// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/ids"
	accessbinding "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Это конечные измерения §8.3, без нового SLO. Client SQL и CommandTag не
// раскрывают работу внутри SQL-функций и сами по себе не доказывают O(delta).
// Время EXPLAIN никогда не включается во время исходного Check.
type fullMeasurementLabel struct{}
type fullMeasurementQueryKey struct{}
type fullMeasurementAcquireKey struct{}
type fullMeasurementAcquire struct {
	Label      string
	PID        uint32
	Start, End time.Time
	Error      string
}
type fullMeasurementQuery struct {
	Batch                            int // Start/End для batch — общий envelope, не per-query duration.
	Label                            string
	SQL                              string
	Args                             []any
	PID                              uint32
	Connection                       int
	TxBefore, TxAfter, CommandTag    string
	Start, End                       time.Time
	RowsAffected                     int64
	Error                            string
	SQLState, Message, Where, Detail string
	conn                             *pgx.Conn
}
type fullMeasurementTrace struct {
	mu          sync.Mutex
	queries     []*fullMeasurementQuery
	acquires    []*fullMeasurementAcquire
	connections map[*pgx.Conn]int
	batches     []*fullMeasurementBatch
}

func (tr *fullMeasurementTrace) TraceAcquireStart(ctx context.Context, _ *pgxpool.Pool, _ pgxpool.TraceAcquireStartData) context.Context {
	label, _ := ctx.Value(fullMeasurementLabel{}).(string)
	if label == "" {
		return ctx
	}
	a := &fullMeasurementAcquire{Label: label, Start: time.Now()}
	tr.mu.Lock()
	tr.acquires = append(tr.acquires, a)
	tr.mu.Unlock()
	return context.WithValue(ctx, fullMeasurementAcquireKey{}, a)
}
func (tr *fullMeasurementTrace) TraceAcquireEnd(ctx context.Context, _ *pgxpool.Pool, d pgxpool.TraceAcquireEndData) {
	a, _ := ctx.Value(fullMeasurementAcquireKey{}).(*fullMeasurementAcquire)
	if a == nil {
		return
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	a.End = time.Now()
	if d.Conn != nil {
		a.PID = d.Conn.PgConn().PID()
	}
	if d.Err != nil {
		a.Error = d.Err.Error()
	}
}
func (tr *fullMeasurementTrace) acquisitions(label string) []fullMeasurementAcquire {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	var out []fullMeasurementAcquire
	for _, a := range tr.acquires {
		if a.Label == label {
			out = append(out, *a)
		}
	}
	return out
}
func (tr *fullMeasurementTrace) TraceQueryStart(ctx context.Context, conn *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	label, _ := ctx.Value(fullMeasurementLabel{}).(string)
	if label == "" {
		return ctx
	}
	args := append([]any(nil), d.Args...)
	for i, arg := range args {
		switch value := arg.(type) {
		case []byte:
			args[i] = append([]byte(nil), value...)
		case []string:
			args[i] = append([]string(nil), value...)
		}
	}
	q := &fullMeasurementQuery{Label: label, SQL: d.SQL, Args: args, PID: conn.PgConn().PID(), Start: time.Now(), conn: conn, TxBefore: string([]byte{conn.PgConn().TxStatus()})}
	tr.mu.Lock()
	if tr.connections == nil {
		tr.connections = map[*pgx.Conn]int{}
	}
	id, ok := tr.connections[conn]
	if !ok {
		id = len(tr.connections) + 1
		tr.connections[conn] = id
	}
	q.Connection = id
	tr.queries = append(tr.queries, q)
	tr.mu.Unlock()
	return context.WithValue(ctx, fullMeasurementQueryKey{}, q)
}
func (tr *fullMeasurementTrace) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, d pgx.TraceQueryEndData) {
	q, _ := ctx.Value(fullMeasurementQueryKey{}).(*fullMeasurementQuery)
	if q == nil {
		return
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	q.End = time.Now()
	q.TxAfter = string([]byte{conn.PgConn().TxStatus()})
	q.CommandTag = d.CommandTag.String()
	// Только прямые DML CommandTag. SELECT n не является числом изменений.
	if d.CommandTag.Insert() || d.CommandTag.Update() || d.CommandTag.Delete() {
		q.RowsAffected = d.CommandTag.RowsAffected()
	}
	if d.Err != nil {
		q.Error = d.Err.Error()
		// QueryEnd видит исходную backend-ошибку ДО repository mapErr.
		var pgErr *pgconn.PgError
		if errors.As(d.Err, &pgErr) {
			q.SQLState, q.Message, q.Where, q.Detail = pgErr.Code, pgErr.Message, pgErr.Where, pgErr.Detail
		}
	}
}
func (tr *fullMeasurementTrace) get(label string) []fullMeasurementQuery {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	var out []fullMeasurementQuery
	for _, q := range tr.queries {
		if q.Label == label {
			out = append(out, *q)
		}
	}
	return out
}
func fullMeasurementContext(base context.Context, label string) (context.Context, context.CancelFunc) {
	return fullMeasurementContextWithin(base, label, 30*time.Second)
}
func fullMeasurementContextWithin(base context.Context, label string, limit time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithValue(context.WithoutCancel(base), fullMeasurementLabel{}, label), limit)
}
func fullMeasurementRigContext(t *testing.T, r protocolRig) protocolRig {
	t.Helper()
	ctx, cancel := fullMeasurementContext(r.ctx, "")
	t.Cleanup(cancel)
	r.ctx = ctx
	return r
}
func fullMeasurementRollback(t *testing.T, ctx context.Context, w interface{ Rollback(context.Context) error }) {
	t.Helper()
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err := w.Rollback(cleanup)
	if !errors.Is(err, pgx.ErrTxClosed) {
		require.NoError(t, err)
	}
}
func fullMeasurementPool(t *testing.T, r protocolRig, trace *fullMeasurementTrace) protocolRig {
	t.Helper()
	r = fullMeasurementRigContext(t, r)
	cfg := r.runtime.Config()
	cfg.MaxConns = 2
	cfg.ConnConfig.Tracer = trace
	r.runtime.Close()
	pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	r.runtime, r.repo = pool, kanamepg.New(pool, nil)
	return r
}
func fullMeasurementLog(t *testing.T, kind string, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	require.NoError(t, err)
	t.Logf("FULL_MEASUREMENT %s %s", kind, body)
}

// Connection — идентичность *pgx.Conn в tracer; Sequence — очередной BEGIN
// на ней. PID отдельно: его повторное использование не склеивает разные TX.
type fullMeasurementEntry struct {
	Query    fullMeasurementQuery
	Mode     string
	Accounts []string
}
type fullMeasurementAttempt struct {
	Connection, Sequence                 int
	PID                                  uint32
	Begin, Terminal                      *fullMeasurementQuery
	Entries                              []fullMeasurementEntry
	Stage                                bool
	Reasons                              []string
	SQLFailures                          []fullMeasurementQuery
	DurationNS, HoldLowerNS, HoldUpperNS *int64
	HoldFrom, HoldTo                     time.Time
	events                               []fullMeasurementQuery
}

func (a *fullMeasurementAttempt) finish() {
	if a.Begin == nil || a.Begin.Error != "" || a.Begin.TxBefore != "I" || a.Begin.TxAfter != "T" {
		a.Reasons = append(a.Reasons, "unproven_begin")
	}
	if a.Terminal == nil {
		a.Reasons = append(a.Reasons, "missing_terminal")
	} else if a.Terminal.Error != "" || a.Terminal.TxBefore != "T" || a.Terminal.TxAfter != "I" || a.Terminal.CommandTag != "COMMIT" {
		a.Reasons = append(a.Reasons, "abort_or_unproven_commit")
	}
	if a.Begin != nil && a.Terminal != nil && !a.Terminal.End.IsZero() {
		duration := a.Terminal.End.Sub(a.Begin.Start).Nanoseconds()
		a.DurationNS = &duration
	}
	firstSuccess := -1
	for i, e := range a.Entries {
		if e.Mode == "" {
			a.Reasons = append(a.Reasons, "unparsed_entry_scope")
		}
		if i > 0 && (e.Mode != a.Entries[0].Mode || !slices.Equal(e.Accounts, a.Entries[0].Accounts)) {
			a.Reasons = append(a.Reasons, "entry_scope_changed")
		}
		if firstSuccess < 0 && e.Query.Error == "" && e.Query.TxBefore == "T" && e.Query.TxAfter == "T" {
			firstSuccess = i
		}
	}
	for _, q := range a.events {
		if q.Error != "" || q.TxBefore == "E" || q.TxAfter == "E" {
			a.SQLFailures = append(a.SQLFailures, q)
			a.Reasons = append(a.Reasons, "sql_error_or_aborted_transaction")
		}
		if q.End.IsZero() {
			a.Reasons = append(a.Reasons, "query_end_missing")
		}
		word := strings.ToLower(strings.TrimSpace(q.SQL))
		if strings.HasPrefix(word, "savepoint") || strings.HasPrefix(word, "release") || strings.HasPrefix(word, "rollback to") {
			a.Reasons = append(a.Reasons, "savepoint_lifetime_unmeasured")
		}
		if firstSuccess >= 0 && q.Start.After(a.Entries[firstSuccess].Query.Start) && (a.Terminal == nil || q.Start.Before(a.Terminal.Start)) && (q.TxBefore != "T" || q.TxAfter != "T") {
			a.Reasons = append(a.Reasons, "interrupted_transaction_lifetime")
		}
	}
	if len(a.Entries) == 0 {
		return
	}
	if firstSuccess < 0 {
		a.Reasons = append(a.Reasons, "no_successful_entry")
	}
	slices.Sort(a.Reasons)
	a.Reasons = slices.Compact(a.Reasons)
	if len(a.Reasons) != 0 {
		return
	}
	// Upper начинается с ПЕРВОГО вызова, lower — с первого успешного
	// ответа. Все entry сохранены; поздний вызов не сдвигает начало hold.
	lower := a.Terminal.Start.Sub(a.Entries[firstSuccess].Query.End).Nanoseconds()
	upper := a.Terminal.End.Sub(a.Entries[0].Query.Start).Nanoseconds()
	if lower < 0 || upper < lower {
		a.Reasons = append(a.Reasons, "invalid_observed_order")
		return
	}
	a.HoldLowerNS, a.HoldUpperNS = &lower, &upper
	a.HoldFrom, a.HoldTo = a.Entries[firstSuccess].Query.End, a.Terminal.Start
}
func fullMeasurementIsEntry(sql string) bool {
	return strings.Contains(sql, "kaname.authority_protocol_enter_") || strings.Contains(sql, "kaname.authority_resource_enter_") || strings.Contains(sql, "kaname.authority_resource_source_enter_")
}

var fullMeasurementDMLTarget = regexp.MustCompile(`(?is)^\s*(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+([a-z_][a-z_0-9.]*)`)
var fullMeasurementFunction = regexp.MustCompile(`(?i)kaname\.([a-z_][a-z_0-9]*)\s*\(`)

type fullMeasurementSQLCost struct {
	SQL                        string
	Calls, Errors, MissingEnds int
	BatchCalls                 int // Индивидуальное время этих SQL не наблюдается.
	ClientNS, DirectRows       int64
}

func fullMeasurementReport(t *testing.T, trace *fullMeasurementTrace, label string, elapsed time.Duration, succeeded bool) []*fullMeasurementAttempt {
	t.Helper()
	qs := trace.get(label)
	current := map[int]*fullMeasurementAttempt{}
	sequence := map[int]int{}
	var attempts []*fullMeasurementAttempt
	var stageRows, domainRows, unknownRows int64
	var stages, entries int
	costs := map[string]*fullMeasurementSQLCost{}
	for _, q := range qs {
		word := strings.ToLower(strings.TrimSpace(q.SQL))
		begin := strings.HasPrefix(word, "begin")
		a := current[q.Connection]
		if begin || a == nil {
			if a != nil {
				a.Reasons = append(a.Reasons, "next_begin_before_terminal")
			}
			sequence[q.Connection]++
			a = &fullMeasurementAttempt{Connection: q.Connection, Sequence: sequence[q.Connection], PID: q.PID}
			if begin {
				copy := q
				a.Begin = &copy
			}
			current[q.Connection] = a
			attempts = append(attempts, a)
		}
		a.events = append(a.events, q)
		if strings.Contains(q.SQL, "CREATE TEMP TABLE kaname_binding_stage") {
			a.Stage = true
			stages++
		}
		if fullMeasurementIsEntry(q.SQL) {
			entries++
			require.Contains(t, q.SQL, "_v3(", "измеряется FULL entry")
			e := fullMeasurementEntry{Query: q}
			if len(q.Args) >= 2 {
				mode, modeOK := q.Args[0].(string)
				accounts, accountsOK := q.Args[1].([]string)
				if modeOK && accountsOK {
					e.Mode = mode
					e.Accounts = append([]string{}, accounts...)
				}
			}
			a.Entries = append(a.Entries, e)
		}
		category := ""
		if target := fullMeasurementDMLTarget.FindStringSubmatch(q.SQL); len(target) > 0 {
			switch {
			case strings.HasPrefix(target[1], "pg_temp."):
				category = "stage_temp_direct_dml"
				stageRows += q.RowsAffected
			case strings.HasPrefix(target[1], "kaname."):
				category = "domain_direct_dml"
				domainRows += q.RowsAffected
			default:
				category = "unclassified_direct_dml"
				unknownRows += q.RowsAffected
			}
		} else if strings.HasPrefix(q.CommandTag, "INSERT") || strings.HasPrefix(q.CommandTag, "UPDATE") || strings.HasPrefix(q.CommandTag, "DELETE") {
			category = "unclassified_direct_dml"
			unknownRows += q.RowsAffected
		}
		if category == "" && fullMeasurementFunction.MatchString(q.SQL) {
			category = "opaque_function_statement"
			for _, name := range []string{"authority_binding_stage_sequence_finalize_v3(", "authority_resource_finalize_v2(", "authority_resource_registration_step_v2(", "authority_resource_registration_body_values_v2("} {
				if strings.Contains(q.SQL, "kaname."+name) {
					category = "actual_finalize_or_apply_boundary"
				}
			}
		}
		if category != "" {
			// Время domain DML включает triggers; время SQL с вызовом функции
			// включает всю statement, а не отдельную внутреннюю функцию.
			key := category + ":" + fmt.Sprintf("%x", sha256.Sum256([]byte(q.SQL)))
			if costs[key] == nil {
				costs[key] = &fullMeasurementSQLCost{SQL: q.SQL}
			}
			c := costs[key]
			c.Calls++
			c.DirectRows += q.RowsAffected
			if q.End.IsZero() {
				c.MissingEnds++
			} else if q.Batch != 0 {
				c.BatchCalls++
			} else {
				c.ClientNS += q.End.Sub(q.Start).Nanoseconds()
			}
			if q.Error != "" {
				c.Errors++
			}
		}
		if word == "commit" || word == "rollback" {
			copy := q
			a.Terminal = &copy
			delete(current, q.Connection)
		}
	}
	var writers []*fullMeasurementAttempt
	for _, a := range attempts {
		a.finish()
		if len(a.Entries) > 0 {
			writers = append(writers, a)
		}
		if a.Stage || len(a.Entries) > 0 || len(a.SQLFailures) > 0 {
			fullMeasurementLog(t, "transaction_attempt", map[string]any{"label": label, "attempt": a})
		}
	}
	fullMeasurementLog(t, "operation", map[string]any{"label": label, "elapsed_ns": elapsed.Nanoseconds(), "client_sql": len(qs), "stage_temp_direct_rows": stageRows, "domain_direct_rows": domainRows, "unclassified_direct_rows": unknownRows, "statement_costs": costs, "stage_create_attempts": stages, "observed_stage_restarts": max(stages-1, 0), "coordinator_entry_calls": entries, "coordinator_tx_attempts": len(writers), "observed_writer_restarts": max(len(writers)-1, 0), "pool_acquire_intervals": trace.acquisitions(label), "private_function_rows_measured": false, "private_function_internal_time_measured": false, "pure_lock_wait_measured": false, "private_row_work_gap": "nested private SQL/trigger rows and churn are not separately observed; actual enclosing SQL cost is measured"})
	fullMeasurementLog(t, "batch_intervals", map[string]any{"label": label, "batches": trace.batchIntervals(label), "individual_statement_time_measured": false, "query_start_end_are_batch_envelope": true})
	// Не скрываем ошибку stage/capture assertion о ещё не достигнутом entry.
	// Успешный run по-прежнему обязан реально вызвать coordinator.
	if succeeded {
		require.Positive(t, entries, "реальный coordinator попал в трассу")
	}
	return writers
}

// fullMeasurementSetupFailure печатает raw QueryEnd.Error перед require/mapErr
// сообщением. Ранний Given без measurement tracer остаётся законным: он только
// сообщает отсутствие raw trace, не открывает новое соединение и не меняет writer.
func fullMeasurementSetupFailure(t *testing.T, r protocolRig, label string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	trace, traced := r.runtime.Config().ConnConfig.Tracer.(*fullMeasurementTrace)
	fullMeasurementLog(t, "setup_error", map[string]any{"label": label, "error": err.Error(), "raw_trace_available": traced && trace != nil})
	if !traced || trace == nil {
		return
	}
	for _, q := range trace.get(label) {
		if q.Error != "" {
			fullMeasurementLog(t, "setup_raw_sql_error", q)
		}
	}
}

func fullMeasurementGroups(t *testing.T, r protocolRig, account string, count int, label string) []string {
	t.Helper()
	setupLabel := fmt.Sprintf("setup_groups_%s_%d_%s", account, count, label)
	ctx, cancel := fullMeasurementContext(r.ctx, setupLabel)
	defer cancel()
	factory, err := kanamepg.NewGroupMembershipParticipant(ctx, r.repo, r.bundle)
	fullMeasurementSetupFailure(t, r, setupLabel, err)
	require.NoError(t, err)
	require.NotNil(t, factory)
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		id := ids.NewID("grp")
		g := domain.Group{ID: domain.GroupID(id), AccountID: domain.AccountID(account), Name: domain.GroupName("measure-" + id), Labels: domain.Labels{"tier": domain.LabelVal(label)}}
		// NEW scope включает потенциальные selectors и recipients других accounts.
		// Штатный lifecycle factory сверяет его до entry и внутри своей транзакции.
		// Один исходный deadline остаётся общим для всего Given; внутри не продлевается.
		err = func() error {
			w, openErr := factory.GroupLifecycleWriter(ctx, kaname.GroupCreate, g)
			if w != nil {
				defer fullMeasurementRollback(t, ctx, w)
			}
			if openErr != nil {
				return openErr
			}
			if w == nil {
				return fmt.Errorf("group lifecycle factory returned nil writer without error")
			}
			if _, insertErr := w.GroupsW().Insert(ctx, g); insertErr != nil {
				return insertErr
			}
			return w.Commit(ctx)
		}()
		fullMeasurementSetupFailure(t, r, setupLabel, err)
		require.NoError(t, err)
		out = append(out, id)
	}
	return out
}
func fullMeasurementLabels(t *testing.T, r protocolRig, account string, objects []string, label string) {
	t.Helper()
	ctx, cancel := fullMeasurementContext(r.ctx, "")
	defer cancel()
	w, err := r.repo.ParticipantAuthorityWriter(ctx, r.intent(account))
	if w != nil {
		defer fullMeasurementRollback(t, ctx, w)
	}
	require.NoError(t, err)
	require.NotNil(t, w)
	for _, id := range objects {
		_, err = w.GroupsW().Update(ctx, domain.Group{ID: domain.GroupID(id), Labels: domain.Labels{"tier": domain.LabelVal(label)}}, []string{"labels"})
		require.NoError(t, err)
	}
	require.NoError(t, w.Commit(ctx))
}

type fullMeasurementEffects struct {
	Members, LedgerObjects, Facts    []string
	MemberRows, LedgerRows, FactRows int64
}

func fullMeasurementSnapshot(t *testing.T, r protocolRig, binding domain.AccessBindingID, inventory []string) fullMeasurementEffects {
	t.Helper()
	ctx, cancel := fullMeasurementContext(r.ctx, "")
	defer cancel()
	var s fullMeasurementEffects
	var subject string
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT subject_type||':'||subject_id FROM kaname.access_bindings WHERE id=$1`, binding).Scan(&subject))
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT object_id ORDER BY object_id),ARRAY[]::text[]),count(*) FROM kaname.access_binding_target_members WHERE binding_id=$1 AND object_type='iam.group' AND verification_status='ACTIVE'`, binding).Scan(&s.Members, &s.MemberRows))
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT split_part(object,':',2) ORDER BY split_part(object,':',2)),ARRAY[]::text[]),count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND object LIKE 'iam_group:%'`, binding).Scan(&s.LedgerObjects, &s.LedgerRows))
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT object_id ORDER BY object_id),ARRAY[]::text[]),count(*) FROM kaname.relation_fact WHERE object_type='iam_group' AND object_id=ANY($1::text[]) AND relation='viewer' AND subject=$2`, inventory, subject).Scan(&s.Facts, &s.FactRows))
	return s
}
func fullMeasurementExpect(t *testing.T, got fullMeasurementEffects, want []string) {
	t.Helper()
	ordered := append([]string{}, want...)
	slices.Sort(ordered)
	require.Equal(t, ordered, got.Members)
	require.Equal(t, ordered, got.LedgerObjects)
	require.Equal(t, ordered, got.Facts)
	require.EqualValues(t, len(want), got.FactRows)
}

func TestFullProtocolReconcileDeltaMeasurements(t *testing.T) {
	for _, size := range []int{257, 513} {
		t.Run(fmt.Sprintf("inventory_%d", size), func(t *testing.T) {
			r := writerProtocolRig(t)
			inventory := fullMeasurementGroups(t, r, r.a, size, "blue")
			r = fullMeasurementRigContext(t, r)
			binding := stageBinding(t, r, r.a, true)
			trace := &fullMeasurementTrace{}
			r = fullMeasurementPool(t, r, trace)
			r.repo, _ = fullContractActivate(t, r)
			engine := bindingStageEngine(t, r, nil)
			run := func(label string) {
				limit := 30 * time.Second
				if size == 513 && (label == "baseline" || label == "delta_257") {
					// Обе большие серии доходили до 30 с до окончания записи.
					// Сохраняем фактическое время и проверяем весь итог каждой серии.
					limit = 45 * time.Second
				}
				ctx, cancel := fullMeasurementContextWithin(r.ctx, label, limit)
				defer cancel()
				start := time.Now()
				err := engine.ReconcileBinding(ctx, binding)
				fullMeasurementReport(t, trace, label, time.Since(start), err == nil)
				require.NoError(t, err)
			}
			run("baseline")
			initial := fullMeasurementSnapshot(t, r, binding, inventory)
			fullMeasurementExpect(t, initial, inventory)
			require.Positive(t, initial.LedgerRows)
			for _, delta := range []int{0, 1, 257} {
				if delta != 0 {
					fullMeasurementLabels(t, r, r.a, inventory[:delta], "red")
				}
				label := fmt.Sprintf("delta_%d", delta)
				run(label)
				after := fullMeasurementSnapshot(t, r, binding, inventory)
				fullMeasurementExpect(t, after, inventory[delta:])
				fullMeasurementLog(t, "reconcile_effects", map[string]any{"inventory": size, "changed_objects": delta, "before": initial, "after": after, "member_rows_delta": after.MemberRows - initial.MemberRows, "ledger_rows_delta": after.LedgerRows - initial.LedgerRows, "fact_rows_delta": after.FactRows - initial.FactRows})
				if delta == 0 {
					require.Equal(t, initial, after)
				}
				if delta == 1 {
					fullMeasurementLabels(t, r, r.a, inventory[:1], "blue")
					run("restore_outside_measurement")
					require.Equal(t, initial, fullMeasurementSnapshot(t, r, binding, inventory))
				}
			}
		})
	}
}

// Законный посев повторяет resourcePublicFixture, но role/binding принадлежат
// account, а selector — чистый anchor. LABELS/NAMES и project scope здесь
// сделали бы whole-binding reconcile global независимо от разных accounts.
func fullMeasurementResourceFixture(t *testing.T, trace *fullMeasurementTrace) resourcePublicFixture {
	t.Helper()
	r := fullMeasurementRigContext(t, writerProtocolRig(t))
	f := resourcePublicFixture{r: r}
	f.scenes = [2]registrationscene.Scene{registrationscene.Seed(t, r.ctx, r.admin), registrationscene.Seed(t, r.ctx, r.admin)}
	var err error
	f.roster, err = moduleidentity.Parse([]string{"modules/kacho-vpc=module-writer"})
	require.NoError(t, err)
	func() {
		ctx, cancel := fullMeasurementContext(r.ctx, "")
		defer cancel()
		w, e := lifecycleOwner(r).Writer(ctx)
		if w != nil {
			defer fullMeasurementRollback(t, ctx, w)
		}
		require.NoError(t, e)
		require.NotNil(t, w)
		_, e = w.ServiceAccountsW().Insert(ctx, domain.ServiceAccount{ID: domain.ServiceAccountID(authzguard.ServiceAccountIDForService("vpc")), AccountID: domain.AccountID(r.a), Name: "kacho-vpc", Description: "FULL throughput module identity"})
		require.NoError(t, e)
		require.NoError(t, w.Commit(ctx))
	}()
	require.NoError(t, seed.ApplyRegistrationAccountWriters(r.ctx, kanamepg.NewRegistrationAccountWriterStore(r.admin), f.roster, f.writerPlan(true)))
	var bootstrapHalves catalog.Halves
	require.NoError(t, json.Unmarshal(r.bundle.CanonicalCatalog(), &bootstrapHalves))
	bootstrapFacts, err := catalog.NewFacts(bootstrapHalves)
	require.NoError(t, err)
	for i, scene := range f.scenes {
		func() {
			ctx, cancel := fullMeasurementContext(r.ctx, "")
			defer cancel()
			f.members[i] = seedMemberUser(t, ctx, r.admin, scene.Account, fmt.Sprintf("full-reader-%d", i))
			_, e := r.admin.Exec(ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, f.members[i])
			require.NoError(t, e)
			rules := domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}}
			projection, e := bootstrapFacts.ProjectGrantRules(rules, domain.TenantPolicy())
			require.NoError(t, e)
			require.NotEmpty(t, projection.Selectors)
			for _, selector := range projection.Selectors {
				require.Equal(t, domain.ArmAnchor, selector.Arm)
				require.Nil(t, selector.Container)
			}
			w, e := lifecycleOwner(r).Writer(ctx)
			if w != nil {
				defer fullMeasurementRollback(t, ctx, w)
			}
			require.NoError(t, e)
			require.NotNil(t, w)
			role, e := w.RolesW().Insert(ctx, domain.Role{ID: domain.RoleID(ids.NewID("rol")), AccountID: domain.AccountID(scene.Account), Name: "full_resource_reader", Rules: rules, Permissions: projection.Permissions})
			require.NoError(t, e)
			require.NoError(t, w.RolesW().ReplaceRuleSelectors(ctx, role.ID, projection.Selectors))
			require.NoError(t, w.RolesW().ReplaceRoleVerbs(ctx, role.ID, projection.Verbs))
			require.NoError(t, w.RolesW().ReplaceRuleRefs(ctx, role.ID, domain.RuleRefsOf(rules)))
			f.bindings[i] = domain.AccessBindingID(ids.NewID("acb"))
			_, e = bindingset.Insert(ctx, w.AccessBindingsW(), domain.AccessBinding{ID: f.bindings[i], RoleID: role.ID, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(f.members[i]), ResourceType: "account", ResourceID: scene.Account, Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true}})
			require.NoError(t, e)
			require.NoError(t, w.Commit(ctx))
		}()
	}
	f.ctx = grpcsrv.WithCertIdentityIn(r.ctx, grpcsrv.NewTrustDomain("kacho.cloud"), "spiffe://kacho.cloud/ns/modules/sa/kacho-vpc", true)

	f.r = fullMeasurementPool(t, f.r, trace)
	f.r.repo, _ = fullContractActivate(t, f.r)
	f.gate = authzguard.NewRelationWriteGate(delegationNativeDoor{f.r}).WithModuleRoster(f.roster)
	ctx, cancel := fullMeasurementContext(f.ctx, "")
	defer cancel()
	for _, scene := range f.scenes {
		require.NoError(t, f.gate.AuthorizeAccount(ctx, scene.Account))
	}
	runner, err := kanamepg.NewResourceDecisionRunner(ctx, f.r.repo, f.r.bundle, f.gate)
	require.NoError(t, err)
	logger := slog.Default()
	f.engine, err = runner.NewObjectReconciler(logger)
	require.NoError(t, err)
	var halves catalog.Halves
	require.NoError(t, json.Unmarshal(f.r.bundle.CanonicalCatalog(), &halves))
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	f.uc = internaliam.NewRegisterResourceUseCase(kanamepg.NewFGAOutboxEmitter(), kanamepg.NewResourceMirrorEmitter(), kanamepg.NewRegistrationTxBeginner(f.r.runtime), kanamepg.NewCatalogTypeReader(), kanamepg.NewPublicReadPublisher(), accessbinding.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), catalog.Fixed{F: facts}), kanamepg.NewRegistrationAudit(), kanamepg.NewRegistrationScopeReader()).WithRegistrationAuthority(f.gate).WithObjectReconciler(f.engine, logger).WithResidualTupleReader(kanamepg.NewResidualTupleReader(f.r.runtime))
	require.NoError(t, f.uc.WithResourceDecisionRunner(runner))
	return f
}

type fullMeasurementOperation struct {
	index, scene int
	register     bool
	id           string
}
type fullMeasurementResult struct {
	Index, Scene       int
	Kind, Label, Error string
	DurationNS         int64
}

func TestFullProtocolPublicThroughputMeasurements(t *testing.T) {
	for _, mode := range []struct {
		name      string
		workers   int
		different bool
	}{{"sequential", 1, false}, {"two_workers_same_account", 2, false}, {"two_workers_different_accounts", 2, true}} {
		t.Run(mode.name, func(t *testing.T) {
			trace := &fullMeasurementTrace{}
			f := fullMeasurementResourceFixture(t, trace)
			f.r = fullMeasurementRigContext(t, f.r)
			engine := bindingStageEngine(t, f.r, nil)
			// Одинаковая смесь: восемь новых Register и восемь no-op reconcile.
			const operations = 16
			results := make(chan fullMeasurementResult, operations)
			var requests []fullMeasurementOperation
			for i := 0; i < operations; i++ {
				scene := 0
				if mode.different {
					scene = i % 2
				}
				job := fullMeasurementOperation{i, scene, (i/2)%2 == 0, ids.NewID("net")}
				requests = append(requests, job)
			}
			var workers sync.WaitGroup
			start := time.Now()
			for worker := 0; worker < mode.workers; worker++ {
				workers.Add(1)
				go func(lane int) {
					defer workers.Done()
					for _, job := range requests {
						if job.index%mode.workers != lane {
							continue
						}
						label := fmt.Sprintf("throughput_%d", job.index)
						ctx, cancel := fullMeasurementContext(f.ctx, label)
						began := time.Now()
						kind := "reconcile"
						var err error
						if job.register {
							kind = "register"
							err = f.uc.Register(ctx, f.request(job.scene, job.id, time.Now()))
						} else {
							err = engine.ReconcileBinding(ctx, f.bindings[job.scene])
						}
						result := fullMeasurementResult{Index: job.index, Scene: job.scene, Kind: kind, Label: label, DurationNS: time.Since(began).Nanoseconds()}
						if err != nil {
							result.Error = err.Error()
						}
						cancel()
						results <- result
					}
				}(worker)
			}
			workers.Wait()
			close(results)
			elapsed := time.Since(start)
			var completed, failed int
			var latencies []int64
			var holds []*fullMeasurementAttempt
			for result := range results {
				if result.Error == "" {
					completed++
				} else {
					failed++
				}
				latencies = append(latencies, result.DurationNS)
				fullMeasurementLog(t, "throughput_result", result)
				for _, attempt := range fullMeasurementReport(t, trace, result.Label, time.Duration(result.DurationNS), result.Error == "") {
					for _, entry := range attempt.Entries {
						require.Equal(t, "accounts", entry.Mode, "измеряем account-scoped FULL workload")
						require.Equal(t, []string{f.scenes[result.Scene].Account}, entry.Accounts)
					}
					if attempt.HoldLowerNS != nil {
						holds = append(holds, attempt)
					}
				}
			}
			// Наблюдаем только доказанные интервалы. Отсутствие пересечения
			// не доказывает сериализацию и не заменяет correctness-тесты fences.
			var overlaps, differentAccountOverlaps int
			for i, a := range holds {
				for _, b := range holds[i+1:] {
					if a.Connection != b.Connection && a.HoldFrom.Before(b.HoldTo) && b.HoldFrom.Before(a.HoldTo) {
						overlaps++
						if !slices.Equal(a.Entries[0].Accounts, b.Entries[0].Accounts) {
							differentAccountOverlaps++
						}
					}
				}
			}
			fullMeasurementLog(t, "throughput_observed_fences", map[string]any{"mode": mode.name, "proven_commit_intervals": len(holds), "overlapping_pairs": overlaps, "different_account_overlapping_pairs": differentAccountOverlaps, "scope_asserted": "accounts with exact requested singleton", "forced_contention": false, "absence_of_overlap_proves_serialization": false})
			slices.Sort(latencies)
			fullMeasurementLog(t, "throughput", map[string]any{"mode": mode.name, "operations": operations, "completed": completed, "errors": failed, "wall_ns": elapsed.Nanoseconds(), "completed_ops_per_second": float64(completed) / elapsed.Seconds(), "latency_ns_sorted": latencies, "pool_max_conns": f.r.runtime.Config().MaxConns, "request_timeout_seconds": 30})
			require.Equal(t, operations, completed)
			require.Zero(t, failed)
			// Каждый новый объект обязан иметь committed mirror и lawful ledger.
			for _, job := range requests {
				if job.register {
					ctx, cancel := fullMeasurementContext(f.ctx, "")
					var mirror, ledger bool
					err := f.r.runtime.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.resource_mirror WHERE object_type='vpc.network' AND object_id=$1 AND parent_account_id=$2),EXISTS(SELECT 1 FROM kaname.access_binding_emitted_tuples WHERE binding_id=$3 AND object=$4)`, job.id, f.scenes[job.scene].Account, f.bindings[job.scene], "vpc_network:"+job.id).Scan(&mirror, &ledger)
					cancel()
					require.NoError(t, err)
					require.True(t, mirror)
					require.True(t, ledger)
				}
			}
			fullMeasurementLog(t, "throughput_committed_effects", map[string]any{"registered_objects": 8, "mirror_and_ledger_verified": true, "mode": mode.name})
		})
	}
}

// Это закрытый реестр повторного EXPLAIN только для данного checker workload.
// SQL прочитаны вместе с pinned producer sources; raw trace сам не approval.
// Любое изменение байтов, даже безопасное, даёт GAP до повторного исполнения.
// Общего SQL parser, regex/function allowlist или разрешения по имени CTE нет.
func fullMeasurementReadonly(sql string) (bool, string) {
	switch fmt.Sprintf("%x", sha256.Sum256([]byte(sql))) {
	case "05bb3146e66ddbf782475d0e7db9657248a5de49dcb956f1dc0fd2438fbc3556":
		return true, "role projection checkpoint: readonly CTE aggregates"
	case "119e3ced2574c25f01ae859f8091de69ca09b977e643d41905fe12bff48b77ae":
		return true, "personmarks: bound user verification marks"
	case "1f8046d42d18207b7023db39210dae6cac7214b015af0354c366d6317fe4448c":
		return true, "catalog type and nesting existence"
	case "33f5c09ef262763d9dcfe33dfca620bb7e2adf2b1bc8236eaa84bae13df2d3ec":
		return true, "native binding subjects page"
	case "358002ea0acc2694daff4084685a08f59b4ee67b11c5738dccc10f9b329ce0a9":
		return true, "producer subject existence: closed subject kinds"
	case "4554cc7fe5a8d3a70a8511afb5dd56df45d4672602840b6f0cc18017b4835429":
		return true, "native current role row"
	case "5e83010cd6d2dfb64c9c38a9a5b44cf844a503be615d846d09e01d7e8d6735a5":
		return true, "iam_group administrative verdict: fixed readonly arms and scope view"
	case "752feef666740ee449d70d58011ce86650e13f2f68908e612ba1ef396e6b34d8":
		return true, "role projection preliminary authored policy"
	case "7b82e64ea9d9babe75d060a453f5c8dfb1daa7005c15f7da4829a20a163d7e52":
		return true, "native current access binding row"
	case "85d03afb155ad226937641aea7a740cfbe195fcc7c22e2c57e6360ffb55c195b":
		return true, "native ledger holder keyset page"
	case "8ab7a98b51f8e04ca35a625ae79b6bbfa94119931a56d41e6033d9983824eb12":
		return true, "iam_group current object projection"
	case "f35649f3138e302afdace76ace9e192087a953374f6e25ea929e3a759111ff89":
		return true, "actor existence: users/service_accounts"
	default:
		return false, "unregistered checker SQL template"
	}
}

func fullMeasurementApprovedBuiltinSQL(sql string) bool {
	switch fmt.Sprintf("%x", sha256.Sum256([]byte(sql))) {
	case "5e83010cd6d2dfb64c9c38a9a5b44cf844a503be615d846d09e01d7e8d6735a5",
		"8ab7a98b51f8e04ca35a625ae79b6bbfa94119931a56d41e6033d9983824eb12":
		return true
	default:
		return false
	}
}

func fullMeasurementBuiltinResolution(ctx context.Context, conn *pgx.Conn) (bool, error) {
	var safe bool
	err := conn.QueryRow(ctx, `SELECT
 (SELECT n.nspname FROM pg_catalog.unnest(pg_catalog.current_schemas(true)) WITH ORDINALITY s(name,pos)
    JOIN pg_catalog.pg_namespace n ON n.nspname=s.name
   WHERE n.oid <> pg_catalog.pg_my_temp_schema() ORDER BY s.pos LIMIT 1) = 'pg_catalog'
 AND EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
              WHERE n.nspname='pg_catalog' AND p.oid=pg_catalog.to_regprocedure('pg_catalog.substr(pg_catalog.text,pg_catalog.int4)'))
 AND EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
              WHERE n.nspname='pg_catalog' AND p.oid=pg_catalog.to_regprocedure('pg_catalog.array_remove(pg_catalog.anycompatiblearray,pg_catalog.anycompatible)'))
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
                  WHERE n.nspname <> 'pg_catalog' AND n.nspname=ANY(pg_catalog.current_schemas(true))
                    AND p.proname IN ('substr','array_remove','length','split_part','min','unnest',
                                      'jsonb_typeof','jsonb_build_array','jsonb_build_object'))`).Scan(&safe)
	return safe, err
}

// Единственный дополнительный callable-набор — агрегаты fixed checkpoint.
// Проверка не расширяет реестр SQL и выполняется после исходного Check/counters.
func fullMeasurementProjectionBuiltinResolution(ctx context.Context, conn *pgx.Conn) (bool, error) {
	var safe bool
	err := conn.QueryRow(ctx, `SELECT
 (SELECT pg_catalog.count(*)=3 FROM pg_catalog.pg_proc p
   JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='pg_catalog' AND p.proowner=n.nspowner AND p.prokind='a'
    AND p.oid IN (pg_catalog.to_regprocedure('pg_catalog.jsonb_agg(pg_catalog.anyelement)'),
                  pg_catalog.to_regprocedure('pg_catalog.count()'),
                  pg_catalog.to_regprocedure('pg_catalog.sum(pg_catalog.int4)')))
 AND EXISTS (SELECT 1 FROM pg_catalog.pg_proc p
   JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   JOIN pg_catalog.pg_language l ON l.oid=p.prolang
  WHERE n.nspname='pg_catalog' AND p.proname='jsonb_build_object'
    AND p.proowner=n.nspowner AND p.prokind='f' AND l.lanname='internal')
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p
   JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   JOIN pg_catalog.pg_language l ON l.oid=p.prolang
  WHERE n.nspname='pg_catalog' AND p.proname='jsonb_build_object'
    AND (p.proowner<>n.nspowner OR p.prokind<>'f' OR l.lanname<>'internal'))
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p
   JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname<>'pg_catalog' AND n.nspname=ANY(pg_catalog.current_schemas(true))
    AND p.proname IN ('jsonb_agg','count','sum','jsonb_build_object'))`).Scan(&safe)
	return safe, err
}

func TestFullMeasurementReadonlyBoundary(t *testing.T) {
	ownerSQL := "SELECT o.id, ARRAY_REMOVE(ARRAY[COALESCE(o.account_id, '')], ''), '', '', o.labels FROM kaname.groups o WHERE o.id = $1"
	require.True(t, fullMeasurementApprovedBuiltinSQL(ownerSQL))
	// Фиксированные bytes всех двенадцати actual templates; ожидаемый hash
	// независим от вычисления в gate. Никакого чтения evidence с runtime-диска.
	positives := []struct{ hash, sql string }{
		{"05bb3146e66ddbf782475d0e7db9657248a5de49dcb956f1dc0fd2438fbc3556", `
WITH module_rows AS (SELECT module,live FROM kaname.catalog_module WHERE module=ANY($2::text[]) LIMIT $3),
 resource_rows AS (SELECT * FROM kaname.catalog_resource WHERE module=ANY($2::text[]) LIMIT $3),
 verb_rows AS (SELECT * FROM kaname.catalog_verb WHERE module=ANY($2::text[]) LIMIT $3),
 selector_rows AS (SELECT * FROM kaname.role_rule_selectors WHERE role_id=$1 LIMIT $3),
 role_verbs AS (SELECT object_type,verb FROM kaname.role_verb WHERE role_id=$1 LIMIT $3),
 create_rows AS (SELECT role_id,rule_fp FROM kaname.role_create_binding_rule WHERE role_id=$1 LIMIT $3),
 bind_rows AS (SELECT role_id,rule_fp,bound_role_id FROM kaname.role_bind_role_rule WHERE role_id=$1 LIMIT $3),
 bind_checks AS (SELECT b.*,t.id AS target_id,t.live AS target_live,
   (r.is_system OR t.is_system OR (coalesce(r.account_id,p.account_id)=coalesce(t.account_id,tp.account_id)
     AND (r.project_id IS NULL OR t.project_id IS NULL OR r.project_id=t.project_id))) AS common_anchor,
   ((t.id IS NOT NULL)::int+(p.id IS NOT NULL)::int+(tp.id IS NOT NULL)::int) AS joined_rows
   FROM bind_rows b JOIN kaname.roles r ON r.id=b.role_id
   LEFT JOIN kaname.roles t ON t.id=b.bound_role_id
   LEFT JOIN kaname.projects p ON p.id=r.project_id LEFT JOIN kaname.projects tp ON tp.id=t.project_id),
 pending_rows AS (SELECT role_id FROM kaname.role_selector_verbs_pending WHERE role_id=$1),
 container_checks AS (SELECT s.container_object_type,c.object_type FROM selector_rows s LEFT JOIN kaname.catalog_resource c ON c.dotted=s.container_type AND c.live WHERE s.container_type IS NOT NULL)
SELECT jsonb_build_object('Permissions',r.permissions,'Rules',r.rules,'IsSystem',r.is_system,'OwnerModule',coalesce(r.owner_module,'')),
jsonb_build_object(
 'Live',jsonb_build_object('Modules',coalesce((SELECT jsonb_agg(module) FROM module_rows WHERE live),'[]'),
 'Resources',coalesce((SELECT jsonb_agg(jsonb_build_object('Module',module,'Resource',resource,'ObjectType',object_type,'ParentTypes',parent_types,'ParentNames',parent_names,'Writes',writes,'PublicReadToChildren',public_read_to_children,'PermanentProject',permanent_project)) FROM resource_rows WHERE live),'[]'),
 'Verbs',coalesce((SELECT jsonb_agg(jsonb_build_object('Module',module,'Resource',resource,'Verb',verb,'PerObject',per_object,'ContainerParent',coalesce(container_parent,''),'ContainerRelation',coalesce(container_relation,''))) FROM verb_rows WHERE live),'[]')),
 'Retired',jsonb_build_object('Modules',coalesce((SELECT jsonb_agg(module) FROM module_rows WHERE NOT live),'[]'),
 'Resources',coalesce((SELECT jsonb_agg(jsonb_build_object('Module',module,'Resource',resource,'ObjectType',object_type,'SupersededBy',coalesce(superseded_by,''))) FROM resource_rows WHERE NOT live),'[]'),
 'Verbs',coalesce((SELECT jsonb_agg(jsonb_build_object('Module',module,'Resource',resource,'Verb',verb,'PerObject',per_object,'ContainerParent',coalesce(container_parent,''),'ContainerRelation',coalesce(container_relation,''))) FROM verb_rows WHERE NOT live),'[]'))),
coalesce((SELECT jsonb_agg(jsonb_build_object('RuleFP',rule_fp,'Arm',CASE arm WHEN 'names' THEN 1 WHEN 'labels' THEN 2 ELSE 0 END,'ObjectTypes',object_types,'ResourceNames',resource_names,'MatchLabels',match_labels,'Grants',verbs_by_type,'CreatedBySubject',created_by_subject,
 'Container',CASE WHEN container_type IS NULL THEN NULL ELSE jsonb_build_object('Type',container_type,'Arm',CASE container_arm WHEN 'names' THEN 1 WHEN 'labels' THEN 2 ELSE 0 END,'ResourceNames',container_resource_names,'MatchLabels',container_match_labels) END)) FROM selector_rows),'[]'),
coalesce((SELECT jsonb_agg(jsonb_build_object('ObjectType',object_type,'Verb',verb)) FROM role_verbs),'[]'),
coalesce((SELECT jsonb_agg(c) FROM (
 SELECT jsonb_build_object('RuleFP',rule_fp,'Kind','create_binding','BoundRoleID','') AS c FROM create_rows
 UNION ALL SELECT jsonb_build_object('RuleFP',rule_fp,'Kind','bind_role','BoundRoleID',bound_role_id) FROM bind_rows) q),'[]'),
(EXISTS(SELECT 1 FROM pending_rows)
 OR EXISTS(SELECT 1 FROM bind_checks WHERE target_live IS DISTINCT FROM true OR common_anchor IS DISTINCT FROM true)
 OR EXISTS(SELECT 1 FROM container_checks WHERE container_object_type IS DISTINCT FROM object_type)),
 (1+(SELECT count(*) FROM module_rows)+(SELECT count(*) FROM resource_rows)
 +(SELECT count(*) FROM verb_rows)+(SELECT count(*) FROM selector_rows)+(SELECT count(*) FROM role_verbs)
 +(SELECT count(*) FROM pending_rows)+(SELECT count(*) FROM container_checks)
 +(SELECT count(*) FROM create_rows)+(SELECT count(*) FROM bind_rows)
 +(SELECT coalesce(sum(1+joined_rows),0) FROM bind_checks))::int
FROM kaname.roles r WHERE r.id=$1 AND r.live`},
		{"119e3ced2574c25f01ae859f8091de69ca09b977e643d41905fe12bff48b77ae", `
	SELECT id, (email_verified_at IS NOT NULL) AS verified
	  FROM kaname.users
	 WHERE id = ANY ($1::text[])`},
		{"1f8046d42d18207b7023db39210dae6cac7214b015af0354c366d6317fe4448c", `SELECT r.dotted,
		        EXISTS (SELECT 1
		                  FROM kaname.role_rule_selectors ns
		                 WHERE ns.container_type IS NOT NULL
		                   AND ns.object_types @> ARRAY[r.dotted])
		   FROM kaname.catalog_resource r
		  WHERE r.object_type = $1::text
		  ORDER BY r.live DESC, r.dotted
		  LIMIT 1`},
		{"33f5c09ef262763d9dcfe33dfca620bb7e2adf2b1bc8236eaa84bae13df2d3ec", `SELECT subject_type,subject_id FROM kaname.access_binding_subjects WHERE binding_id=$1 ORDER BY subject_type,subject_id LIMIT 33`},
		{"358002ea0acc2694daff4084685a08f59b4ee67b11c5738dccc10f9b329ce0a9", `SELECT CASE $1 WHEN 'user' THEN EXISTS(SELECT 1 FROM kaname.users WHERE id=$2) WHEN 'service_account' THEN EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$2) WHEN 'group' THEN EXISTS(SELECT 1 FROM kaname.groups WHERE id=$2) WHEN 'system_class' THEN $2 IN ('anonymous','authenticated') ELSE false END`},
		{"4554cc7fe5a8d3a70a8511afb5dd56df45d4672602840b6f0cc18017b4835429", `SELECT id, cluster_id, account_id, project_id, name, description, permissions, rules, is_system, owner_module, created_at, updated_at, labels,live FROM kaname.roles WHERE id=$1`},
		{"5e83010cd6d2dfb64c9c38a9a5b44cf844a503be615d846d09e01d7e8d6735a5", `
WITH RECURSIVE
-- scope — ОБЛАСТИ, на которые может быть сделана действующая выдача: сам объект
-- и вся его цепь предков.
--
-- ОБХОД, А НЕ ОДНО ЧТЕНИЕ, и это не осторожность. Цепь читается представлением
-- resource_scope_edge, и замыканием не является ни одна из его сторон: ключ
-- (объект, глубина) и проверка глубины 1..4 допускают обе формы, а владельцы
-- ресурсов шлют КОРОТКУЮ цепь — vpc, storage и compute одно звено (проект),
-- реестр два (реестр и проект). Одноразовое чтение схлопнуло бы область до
-- «объект плюс его непосредственный предок»; обход оставляет её открытой вверх.
--
-- ВВЕРХ ЕСТЬ КУДА ИДТИ, и почему — надо сказать здесь, а не подразумевать.
-- Рёбра появляются регистрацией ресурса у владельца прав, а зовут её пять
-- сервисов-соседей только для СВОИХ ресурсов: объектов типа project и account не
-- регистрирует никто, а собственных объектов iam не регистрирует и сам iam.
-- Недостающие звенья ДОСТРАИВАЕТ представление, и у каждого СВОЙ источник — тот,
-- что полон ПО ПОСТРОЕНИЮ именно для ЭТОГО звена:
--
--   проект → его аккаунт    — ПРОЕКЦИЯ ЖУРНАЛА relation_fact: указатель
--                             со-коммитится созданием проекта, а миграции
--                             проекты не сеют (781001, kacho#781);
--   аккаунт → кластер       — СХЕМА, accounts × clusters (синглтон): аккаунты
--                             сеются миграциями, указателя в журнале у них нет
--                             (740001, kacho#740);
--   ЛИЧНОСТЬ → аккаунт     — СХЕМА, таблица kaname.memberships (944001,
--                             kacho#944): принадлежность человека аккаунту
--                             перестала быть колонкой его строки и стала
--                             отдельной связью, которых у него может быть
--                             НЕСКОЛЬКО. Полнота по построению та же, что у
--                             колонки: строка И ЕСТЬ связь (первичный ключ плюс
--                             уникальная пара «человек × аккаунт»), обойти её
--                             нельзя ни через API, ни через посев;
--   четыре собственных типа — СХЕМА, колонка собственной строки объекта:
--   iam → аккаунт либо        groups/service_accounts/roles.account_id,
--   проект                    roles.project_id у проектной роли, пара
--                             access_bindings.resource_type/resource_id для трёх
--                             областных значений закрытого набора. Строка И ЕСТЬ
--                             объект, колонка неизменяема; журнал же полон НЕ по
--                             построению — девять миграций сеют эти строки, и ни
--                             одна не пишет указатель (785001, kacho#785).
--
-- Под представлением лежат kaname.resource_parent_edge (присланное) плюс
-- kaname.relation_fact, kaname.accounts, kaname.clusters,
-- kaname.memberships, kaname.groups, kaname.service_accounts,
-- kaname.roles и kaname.access_bindings (выводимое). Таблица личностей из
-- перечня СНЯТА вместе с ветвью, которая её читала: звено личности берёт аккаунт
-- из членства. Её имя здесь намеренно НЕ ВОСПРОИЗВОДИТСЯ даже в разборе этого
-- снятия — перечень сверяется с телом представления, и имя таблицы, которую цепь
-- не читает, было бы находкой, а не пояснением. Имена названы здесь ЯВНО, и не ради
-- полноты рассказа: отпечаток предмета замера выводит читаемые таблицы ИЗ ТЕКСТА
-- вердикта, поэтому представление, названное одним своим именем, увело бы
-- собственные основания из-под прибора — их правку он перестал бы замечать молча.
--
-- Что из этого следует для формы запроса: выведенные звенья идут ПО ОДНОМУ, как
-- и присланные, поэтому цепь по-прежнему собирается обходом. Ровно этим обходом
-- достижимы верхние уровни security.md §«Три уровня супер-доступа» — выдача на
-- аккаунт и прямой факт администратора облака на кластере; отними его, и оба
-- ответят отказом, НЕОТЛИЧИМЫМ от честного.
--
-- ЦЕНА ОБХОДА ЗАПЛАЧЕНА СОЕДИНЕНИЕМ ВБОК, А НЕ ОБЫЧНЫМ. Рекурсивная ветвь с
-- обычным соединением даёт планировщику право прочитать таблицу рёбер ЦЕЛИКОМ на
-- каждом шаге: измерено 2412 строк за один вердикт при трёх рёбрах у объекта.
-- Соединение вбок с пределом заставляет ходить указателем по ключу.
--
-- Предел числа родителей и глубина пути независимы: первый остаётся 4,
-- второй включает 5 переходов до cluster. Сохранённая цепь имеет до 4 позиций;
-- выведенные ветви resource_scope_edge требуют собственной проверки полноты.
-- Captured writer дочитывает страницы и отвергает graph с fanout>4 либо
-- продолжающийся после предельной глубины; LIMIT сам полноту не доказывает.
-- Та же форма и по той же причине стоит на пути перечисления — одна семантика
-- области на обе точки входа.
scope(s_type, s_id, depth) AS (
    SELECT $2::text, $3::text, 0
  UNION
    SELECT e.parent_type, e.parent_id, s.depth + 1
      FROM scope s
      CROSS JOIN LATERAL (
             SELECT pe.parent_type, pe.parent_id
               FROM kaname.resource_scope_edge pe
              WHERE pe.object_type = s.s_type AND pe.object_id = s.s_id
              ORDER BY pe.depth
              LIMIT $12::int
           ) e
     WHERE s.depth < $7::int
),
-- scope_distinct — ОБЛАСТИ БЕЗ ПОВТОРОВ, и это ЕДИНСТВЕННОЕ, что читают армы.
--
-- Обход выше несёт в кортеже ГЛУБИНУ ШАГА, поэтому UNION не схлопывает предка,
-- достигнутого разными путями. Форма цепи, которую пишет производитель для
-- compute и nlb (ownerregister.ParentChain — проект И аккаунт сразу), даёт
-- аккаунт на глубинах 1 и 2, а стоящий над ним кластер — на 2 и 3: шесть строк
-- при четырёх различных областях.
--
-- Каждая лишняя строка УМНОЖАЕТ ОБА АРМА: ветвь выдач соединена с набором
-- CROSS JOIN, ветвь фактов — по паре колонок. Отбор различных над ОТВЕТОМ
-- прячет это в ответе и не трогает СТОИМОСТЬ, а на отказном вопросе короткого
-- замыкания нет, и цена платится целиком. Измерено пробой
-- scopedistinct_integration_test.go: 6 строк при 4 различных областях.
--
-- ОБХОД СОХРАНЯЕТСЯ ЦЕЛИКОМ — снимается только повтор. Это НЕ переход на одно
-- чтение таблицы рёбер: тот переход опровергнут (таблица хранит присланную
-- цепь, а не замыкание), и здесь его нет.
--
-- Наименьшая глубина БЕЗОПАСНА, и это проверяемо: единственное употребление
-- глубины ниже по запросу — дискриминатор якоря sc.depth = 0, а якорь
-- засевается нулём и по построению остаётся минимумом (выведенная строка даёт
-- s.depth + 1 при s.depth не меньше нуля, то есть нуля дать не может).
scope_distinct(s_type, s_id, depth) AS (
    SELECT s_type, s_id, min(depth) FROM scope GROUP BY s_type, s_id
),
speaker_pair(s_type, s_id, via) AS (
    -- СУБЪЕКТ ВЫДАЧИ — ПАРОЙ КОЛОНОК, а не склейкой.
    --
    -- Склейка subject_type || ':' || subject_id выводит колонки из-под любого
    -- индекса: сравнивать приходится вычисленное значение, а вычисленное
    -- значение отбирает строки только ПОСЛЕ того, как они прочитаны. Пара
    -- колонок сужает набор ДО чтения. Паритет, а не новое устройство: соседнее
    -- соединение того же запроса читает членство парой колонок и обслуживается
    -- индексом (member_type, member_id) с самого начала.
    --
    -- Колонка via называет, ОТКУДА взялась пара, и существует ради текстовой
    -- формы ниже: хвост #member раскрывает ЧЛЕНСТВО, и приписать его группе,
    -- которая сама является вызывающим, значило бы расширить ответ на факты,
    -- которых вызывающему не выдавали.
    SELECT split_part($1::text, ':', 1),
           substr($1::text, length(split_part($1::text, ':', 1)) + 2),
           'self'
  UNION ALL
    SELECT 'group', gm.group_id, 'member'
      FROM kaname.group_members gm
     WHERE gm.member_type = split_part($1::text, ':', 1)
       AND gm.member_id   = substr($1::text, length(split_part($1::text, ':', 1)) + 2)
  UNION ALL
    -- КЛАССЫ ГОВОРЯЩЕГО (Р2) — значением запроса, а не выводом по месту: их
    -- вычисляет ОДИН производитель (domain.SpeakerClasses) для всех трёх форм
    -- вопроса, и разойтись форме перечня с формой вопроса негде. Безусловной
    -- подстановки «любой» здесь больше нет: аноним выданного вошедшим не
    -- получает (SC-10), группа — ничего (SC-11). Классов у говорящего не больше
    -- двух, и они приходят двумя скалярами. Строк здесь от этого становится
    -- больше, и порядок соединения с субъектами выдач держит не оценка числа
    -- строк, а обращение вбок в ветви выдач (довод — там). Пустое имя класса не
    -- совпадает ни с одной строкой: у субъекта выдачи пустого идентификатора нет.
    SELECT 'system_class', $10::text, 'class' WHERE (
           (split_part($1::text, ':', 1) = 'user'
            AND EXISTS (SELECT 1 FROM kaname.users u
                         WHERE u.id = substr($1::text, length(split_part($1::text, ':', 1)) + 2)))
        OR (split_part($1::text, ':', 1) = 'service_account'
            AND EXISTS (SELECT 1 FROM kaname.service_accounts s
                         WHERE s.id = substr($1::text, length(split_part($1::text, ':', 1)) + 2)))
       )
  UNION ALL
    SELECT 'system_class', $11::text, 'class' WHERE (
           (split_part($1::text, ':', 1) = 'user'
            AND EXISTS (SELECT 1 FROM kaname.users u
                         WHERE u.id = substr($1::text, length(split_part($1::text, ':', 1)) + 2)))
        OR (split_part($1::text, ':', 1) = 'service_account'
            AND EXISTS (SELECT 1 FROM kaname.service_accounts s
                         WHERE s.id = substr($1::text, length(split_part($1::text, ':', 1)) + 2)))
       )
),
speaker(subject) AS (
    -- ТЕКСТОВАЯ форма — для прямых фактов: их субъект хранится строкой, и она
    -- не разбирается на пару нигде в дереве. Обе формы имени группы, и это не
    -- перестраховка: канонический производитель кортежей пишет
    -- group:<id>#member (хвост раскрывает членство на стороне модели), а голой
    -- формой group:<id> адресуется сама группа как субъект. Признать одну и
    -- промолчать о другой значит НЕДОотвечать ровно на права, выданные
    -- каноническим путём, — тихо, потому что неполный ответ выглядит как
    -- честное «ничего нет».
    SELECT $1::text
  UNION
    SELECT 'group:' || sp.s_id FROM speaker_pair sp WHERE sp.via = 'member'
  UNION
    SELECT 'group:' || sp.s_id || '#member' FROM speaker_pair sp WHERE sp.via = 'member'
  UNION
    -- Классы — из пары колонок, где они уже прошли предикат существования
    -- говорящего (speakerExistsSQL): второе написание параметров здесь вывело
    -- бы класс учётке, которой нет.
    SELECT 'system_class:' || sp.s_id FROM speaker_pair sp WHERE sp.via = 'class'
),
fact_atom(parent_type, relation) AS (
    -- Источники-факты плана: где искать и что искать. Пустой тип предка означает
    -- «на самом объекте», непустой — «на предке этого типа».
    SELECT * FROM unnest($4::text[], $5::text[])
)
-- РАННИЙ ВЫХОД: ни одного блокирующего узла над союзом.
--
-- Отбор различных, сортировка и оконная функция — все трое БЛОКИРУЮЩИЕ: ни один
-- не отдаёт первой строки, пока не прочитана последняя. Пока стоял хоть один,
-- «строк прочитано» на разрешающем вопросе совпадало с отказным by construction,
-- и короткое замыкание было заявлено, а не наблюдаемо. Измерено: при трёхстах
-- основаниях на области разрешающий вопрос читал 1222 строки против 19 у
-- отказного — то есть был ДОРОЖЕ.
--
-- ПОРЯДОК ВЕТВЕЙ — ЧАСТЬ УСТРОЙСТВА, А НЕ ОФОРМЛЕНИЕ. Ветвь выдач идёт ПЕРВОЙ,
-- потому что каждая её строка безусловна by construction (выдача условия не
-- несёт: роль раздаёт ГЛАГОЛЫ, а условие в модели стоит на отношениях,
-- глаголами не являющихся). Значит первая же её строка отвечает на вопрос, и
-- читатель останавливается на ней. Ветвь фактов идёт второй и несёт СВОЙ отбор
-- различных — внутри себя, где он не мешает первой ветви: узел Append исполняет
-- потомков по очереди, и до второго дело доходит только когда первый пуст.
--
-- Отбор различных над фактами сохранён ДОСЛОВНО, поэтому предел $8 по-прежнему
-- считает РАЗЛИЧНЫЕ условия, а не сырые строки: ПОРОГ усечения не сдвинулся.
--
-- А вот СОСТОЯНИЕ изменилось, и это надо сказать прямо. Прежде проверка
-- усечения стояла ДО поиска безусловного основания: набор из 256+ условий давал
-- отказ, даже если безусловное основание среди них было. Теперь безусловное
-- основание возвращает разрешение из самого цикла чтения, до проверки. Это
-- РАСШИРЕНИЕ: где был отказ, там теперь разрешение. Поведение защитимо —
-- усечение говорит «я не дочитал», а найденное безусловное основание делает
-- недочитанное несущественным, — но выдавать его за «то же состояние» нельзя.
--
-- ПРЕДЕЛ ВЕТВИ ВЫДАЧ — ОДНА СТРОКА, и это не оптимизация, а то самое короткое
-- замыкание. Замыкание обязано случиться НА СЕРВЕРЕ: закрытие курсора раньше
-- времени сберегает разбор у клиента и ничего не сберегает у базы — портал
-- исполняется до конца, потому что предела строк ему не задано. Измерено: с
-- ранним выходом только на стороне клиента разрешающий вопрос читал 1119 строк
-- против 19 у отказного, то есть оставался ДОРОЖЕ.
--
-- Предел ничего не теряет: все строки этой ветви безусловны и на состав ответа
-- влияют одинаково — прежний отбор различных сворачивал их в ОДНУ ровно так же.
-- Разница лишь в том, что отбор различных сначала читал их все.
--
-- Колонка arm отдаётся КАК ЕСТЬ, построчно. Прежде она сворачивалась оконной
-- функцией по всем строкам; свернуть её нечем, пока чтение вправе прекратиться,
-- и накопление по прочитанному было бы ровно тем, от чего эта правка уходит. Что
-- признак теперь означает и чем «не дала основания» отличимо от «до неё не
-- дочитали» — сказано у Grounds.
SELECT src.cond_name, src.cond_params, src.arm, src.object_type, src.object_id, src.relation, src.subject, src.cond_params::text FROM (
  (

    -- ЗАХОД — С ПАРЫ «СУБЪЕКТ + ОБЛАСТЬ», и оба предиката сужают набор ДО
    -- чтения строк. Пока субъект жил на дочерней таблице, а область — на
    -- родительской, одного индекса, обслуживающего оба, не существовало by
    -- construction: заход со стороны области читал ВСЕ выдачи области, заход со
    -- стороны субъекта — ВСЕ выдачи субъекта в облаке. Первое ограничено
    -- размером облака, второе не ограничено ничем. Область перенесена на строку
    -- субъекта (миграция 732001), согласованность держит составной внешний ключ
    -- с каскадом правки, а не синхронизация в коде.
    --
    -- Обращений — не больше, чем произведение мощностей speaker_pair и scope,
    -- и каждое возвращает выдачи ровно этого субъекта ровно в этой области.
    --
    -- Обращение — ВБОК, по паре на строку, и это ДЕРЖИТ обещание абзацем выше,
    -- а не надеется на план. Обычное соединение оставляло порядок планировщику,
    -- и он менял его по оценке числа строк говорящего: при трёх строках
    -- (говорящий и два его системных класса, kaname#829) он предпочитал полный
    -- просмотр субъектов выдач с хэшем, и стоимость вопроса шла за числом выдач
    -- в базе (замер — проба объёма матрицы и сетка масштаба). OFFSET 0 не даёт
    -- подзапросу раствориться в соединении: он и есть ограда порядка.
    SELECT ''::text AS cond_name, '{}'::jsonb AS cond_params, rs.arm AS arm, ''::text AS object_type, ''::text AS object_id, ''::text AS relation, ''::text AS subject
      FROM speaker_pair sp
      CROSS JOIN scope_distinct sc
      CROSS JOIN LATERAL (
             SELECT s.binding_id, s.subject_type, s.subject_id
               FROM kaname.access_binding_subjects s
              WHERE s.subject_type  = sp.s_type AND s.subject_id  = sp.s_id
                AND s.resource_type = sc.s_type AND s.resource_id = sc.s_id
             OFFSET 0
           ) bs
      JOIN kaname.access_bindings b ON b.id = bs.binding_id
      JOIN kaname.role_verb rv
        ON rv.role_id = b.role_id AND rv.object_type = $9::text
       AND rv.verb = ANY ($6::text[])
       AND (bs.subject_type <> 'system_class' OR rv.verb = ANY ('{get,list}'::text[]))
      JOIN kaname.role_rule_selectors rs
        ON rs.role_id = b.role_id AND $9::text = ANY (rs.object_types)
      -- Метки нужны только ветви меток, и лежат они там, где велит ТИП: у чужого
      -- ресурса — в зеркале, у собственного объекта iam — в его таблице.
      -- Соединение ЛЕВОЕ на обеих осях, чтобы объект без меток не выпадал из
      -- ветвей якоря и имён: иначе отсутствие меток читалось бы как отсутствие
      -- права.
      LEFT JOIN kaname.groups m ON m.id = $3::text
     WHERE b.status = 'ACTIVE'
       AND (b.expires_at IS NULL OR b.expires_at > $13::timestamptz)
       AND b.revoked_at IS NULL
       AND (NULLIF(CASE WHEN rs.arm <> 'labels' OR m.labels IS NOT NULL
                  THEN (rs.verbs_by_type -> $9::text) ? rv.verb
                  ELSE false
             END, false) IS NOT NULL
     AND (
             rs.arm = 'anchor'
          OR (rs.arm = 'names'  AND $3::text = ANY (rs.resource_names))
          OR (rs.arm = 'labels' AND m.labels IS NOT NULL
                                AND m.labels @> rs.match_labels)
         )
     AND NULLIF(NOT rs.created_by_subject OR (bs.subject_type = 'service_account' AND EXISTS (
             SELECT 1
               FROM kaname.service_accounts csa
              WHERE $2::text = 'iam_service_account'
                AND csa.id = $3::text
                AND csa.created_by_type = 'service_account'
                AND csa.created_by_id = bs.subject_id)), false) IS NOT NULL
     AND rs.container_type IS NULL
     AND NULLIF(
             (jsonb_typeof(b.target) = 'object' AND NOT (b.target ? 'resources'))
          OR b.target -> 'resources' = '[]'::jsonb
          OR b.target -> 'resources' @> jsonb_build_array(jsonb_build_object(
                 'type', $9::text, 'id', $3::text)),
         false) IS NOT NULL)

    LIMIT 1
  )
  UNION ALL
  (

    -- (1) прямой факт. Условие берётся С САМОЙ ЗАПИСИ: она самоописательна, и
    -- читателю не нужно знать модель, чтобы соблюсти ограничение.
    --
    -- Отбор различных стоит ВНУТРИ этой ветви, а не над союзом: здесь он
    -- обязателен (один и тот же условный источник приходит по нескольким
    -- говорящим и нескольким областям), а над союзом он блокировал бы и ветвь
    -- выдач, у которой дублирования нет — все её строки безусловны и
    -- неразличимы, поэтому читателю довольно первой.
    SELECT DISTINCT f.condition_name AS cond_name, f.condition_params AS cond_params,
           ''::text AS arm, f.object_type, f.object_id, f.relation, f.subject
      FROM kaname.relation_fact f
      JOIN speaker sp ON sp.subject = f.subject
      JOIN scope_distinct sc ON sc.s_type = f.object_type AND sc.s_id = f.object_id
      JOIN fact_atom fa
        ON fa.relation = f.relation
       AND CASE WHEN fa.parent_type = ''
                THEN sc.depth = 0
                ELSE fa.parent_type = sc.s_type
           END

  )
) src
WHERE (src.object_type COLLATE "C",src.object_id COLLATE "C",src.relation COLLATE "C",src.subject COLLATE "C",src.cond_name COLLATE "C",src.cond_params::text COLLATE "C") > ($14::text COLLATE "C",$15::text COLLATE "C",$16::text COLLATE "C",$17::text COLLATE "C",$18::text COLLATE "C",$19::text COLLATE "C")
ORDER BY src.object_type COLLATE "C",src.object_id COLLATE "C",src.relation COLLATE "C",src.subject COLLATE "C",src.cond_name COLLATE "C",src.cond_params::text COLLATE "C"
LIMIT $8::int`},
		{"752feef666740ee449d70d58011ce86650e13f2f68908e612ba1ef396e6b34d8", `SELECT permissions,rules,is_system,coalesce(owner_module,'') FROM kaname.roles WHERE id=$1 AND live`},
		{"7b82e64ea9d9babe75d060a453f5c8dfb1daa7005c15f7da4829a20a163d7e52", `SELECT id, subject_type, subject_id, COALESCE(role_id, '') AS role_id, resource_type, resource_id, status, expires_at, granted_by_user_id, revoked_at, revoked_by_user_id, created_at, scope, deletion_protection, labels, target, granted_relation, is_system, COALESCE(revocation_reason, '') AS revocation_reason, COALESCE(delegation_id, '') AS delegation_id FROM kaname.access_bindings WHERE id=$1`},
		{"85d03afb155ad226937641aea7a740cfbe195fcc7c22e2c57e6360ffb55c195b", `SELECT binding_id,member_object_type,member_object_id FROM kaname.access_binding_emitted_tuples WHERE fga_user=$1 AND relation=$2 AND object=$3 AND (binding_id COLLATE "C",member_object_type COLLATE "C",member_object_id COLLATE "C")>($4::text COLLATE "C",$5::text COLLATE "C",$6::text COLLATE "C") ORDER BY binding_id COLLATE "C",member_object_type COLLATE "C",member_object_id COLLATE "C" LIMIT 256`},
		{"8ab7a98b51f8e04ca35a625ae79b6bbfa94119931a56d41e6033d9983824eb12", `SELECT o.id, ARRAY_REMOVE(ARRAY[COALESCE(o.account_id, '')], ''), '', '', o.labels FROM kaname.groups o WHERE o.id = $1`},
		{"f35649f3138e302afdace76ace9e192087a953374f6e25ea929e3a759111ff89", `SELECT CASE $1 WHEN 'user' THEN EXISTS(SELECT 1 FROM kaname.users WHERE id=$2) WHEN 'service_account' THEN EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$2) ELSE false END`},
	}
	require.Len(t, positives, 12)
	for _, sample := range positives {
		require.Equal(t, sample.hash, fmt.Sprintf("%x", sha256.Sum256([]byte(sample.sql))))
		ok, reason := fullMeasurementReadonly(sample.sql)
		require.True(t, ok, reason)
		ok, reason = fullMeasurementReadonly(sample.sql + " ")
		require.False(t, ok, "даже benign variant требует нового approval: %s", reason)
	}
	for _, sql := range []string{
		"SELECT kaname.substr('x', 1)",
		"SELECT private.array_remove(ARRAY['x'], 'x')",
		"SELECT substr($1::private.subject, 1)",
		"SELECT array_remove($1::private.subject[], $2::private.subject)",
		"SELECT pg_catalog.then(1)",
		"SELECT substr('abc'::text, 2)",
		"SELECT CASE WHEN true THEN (ARRAY_REMOVE(ARRAY['x']::text[], ''::text)) ELSE ARRAY[]::text[] END",
		"SELECT CASE WHEN true THEN (kaname.hidden_write()) ELSE false END",
		"SELECT unknown_function()",
		"SELECT pg_advisory_lock(1)",
		"SELECT nextval('sequence')",
		"SELECT * FROM kaname.groups FOR UPDATE",
		"WITH x AS (DELETE FROM kaname.groups RETURNING *) SELECT * FROM x",
		"SELECT 1; SELECT 2",
		strings.Replace(ownerSQL, "ARRAY_REMOVE", "kaname.ARRAY_REMOVE", 1),
		strings.Replace(ownerSQL, "ARRAY_REMOVE", `"array_remove"`, 1),
		strings.Replace(ownerSQL, "ARRAY_REMOVE", `pg_catalog."array_remove"`, 1),
		`SELECT "unknown_function"()`,
		`SELECT "private"."hidden_write"()`,
		`SELECT private . "hidden_write" ()`,
		`SELECT "private" /* schema */ . "hidden_write" /* call */ ()`,
		`SELECT "private"."hidden""write"()`,
		`SELECT "substr"('abc'::text, 2)`,
		`SELECT unknown_function /* outer /* inner */ tail */ ()`,
		`SELECT '--', unknown_function()`,
		`SELECT array_remove /* outer /* inner */ tail */ (ARRAY[1,2], 1)`,
		`SELECT '--', array_remove(ARRAY[1,2], 1)`,
		`WITH array_remove(x) AS (SELECT 1) SELECT array_remove(ARRAY[1,2], 1)`,
		`WITH unknown_function(x) AS (SELECT 1) SELECT unknown_function()`,
		"SELECT count(*) FROM kaname.groups",
	} {
		ok, reason := fullMeasurementReadonly(sql)
		require.False(t, ok, "%s: %s", sql, reason)
	}
}

func fullMeasurementTupleCount(ctx context.Context, conn *pgx.Conn) (int64, error) {
	var n int64
	err := conn.QueryRow(ctx, `SELECT coalesce(sum(seq_tup_read+coalesce(idx_tup_fetch,0)),0)::bigint FROM pg_stat_xact_all_tables WHERE schemaname='kaname'`).Scan(&n)
	return n, err
}
func fullMeasurementCheck(t *testing.T, r protocolRig, trace *fullMeasurementTrace, actor, target, relation string, want bool, foreign int) {
	t.Helper()
	label := fmt.Sprintf("foreign_%d_%s", foreign, relation)
	ctx, cancel := fullMeasurementContext(r.ctx, label+"_prepare")
	defer cancel()
	in := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityBinding, Bundle: r.bundle, Plan: authorityAccounts(r.a), Owners: []kaname.AuthorityOwnerRef{{Kind: "account", ID: r.a}}}
	read := kaname.SemanticReadIntent{Actor: domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(actor)}, Native: []kaname.SemanticNativeQuestion{{Relation: relation, Object: target}}}
	w, err := r.repo.PreparedAuthorityDecisionWriter(ctx, in, read)
	if w != nil {
		defer fullMeasurementRollback(t, ctx, w)
	}
	require.NoError(t, err)
	require.NotNil(t, w)
	prepared := trace.get(label + "_prepare")
	require.NotEmpty(t, prepared)
	conn := prepared[len(prepared)-1].conn
	require.NotNil(t, conn)
	require.Equal(t, byte('T'), conn.PgConn().TxStatus())
	// Те же deadline и backend. Переключение метки не продлевает запрос.
	statsCtx := context.WithValue(ctx, fullMeasurementLabel{}, label+"_stats")
	before, err := fullMeasurementTupleCount(statsCtx, conn)
	require.NoError(t, err)
	checkCtx := context.WithValue(ctx, fullMeasurementLabel{}, label+"_check")
	started := time.Now()
	got, checkErr := w.SemanticRelationChecker().Check(checkCtx, "user:"+actor, relation, target)
	elapsed := time.Since(started)
	after, err := fullMeasurementTupleCount(statsCtx, conn)
	require.NoError(t, err)
	require.NoError(t, checkErr)
	require.Equal(t, want, got)
	captured := trace.get(label + "_check")
	require.NotEmpty(t, captured)
	require.GreaterOrEqual(t, after, before)
	var explained, gaps int
	for index, q := range captured {
		require.Equal(t, conn.PgConn().PID(), q.PID)
		fullMeasurementLog(t, "checker_actual_sql", map[string]any{"label": label, "index": index, "sql_sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(q.SQL))), "query": q})
		ok, reason := fullMeasurementReadonly(q.SQL)
		if ok {
			resolutionCtx := context.WithValue(ctx, fullMeasurementLabel{}, label+"_builtin_resolution")
			var resolutionErr error
			ok, resolutionErr = fullMeasurementBuiltinResolution(resolutionCtx, conn)
			require.NoError(t, resolutionErr)
			if !ok {
				reason = "unproven pg_catalog resolution or visible user overload"
			}
		}
		if ok && fmt.Sprintf("%x", sha256.Sum256([]byte(q.SQL))) == "05bb3146e66ddbf782475d0e7db9657248a5de49dcb956f1dc0fd2438fbc3556" {
			resolutionCtx := context.WithValue(ctx, fullMeasurementLabel{}, label+"_builtin_resolution")
			var resolutionErr error
			ok, resolutionErr = fullMeasurementProjectionBuiltinResolution(resolutionCtx, conn)
			require.NoError(t, resolutionErr)
			if !ok {
				reason = "unproven pg_catalog aggregate identity or visible user overload"
			}
		}
		if !ok {
			gaps++
			fullMeasurementLog(t, "checker_plan_gap", map[string]any{"label": label, "index": index, "reason": reason})
			continue
		}
		explainCtx := context.WithValue(ctx, fullMeasurementLabel{}, label+"_explain")
		var raw json.RawMessage
		err = conn.QueryRow(explainCtx, "EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON) "+q.SQL, q.Args...).Scan(&raw)
		require.NoError(t, err)
		explained++
		fullMeasurementLog(t, "checker_plan", map[string]any{"label": label, "index": index, "plan": raw})
	}
	fullMeasurementLog(t, "checker", map[string]any{"label": label, "foreign_population": foreign, "actor": actor, "target": target, "relation": relation, "allow": got, "actual_check_ns": elapsed.Nanoseconds(), "server_tuple_reads": after - before, "actual_check_sql": len(captured), "prepared_sql_separate": len(prepared), "explained_sql_separate": explained, "gaps": gaps, "whole_checker_plan_coverage": gaps == 0, "pid": conn.PgConn().PID(), "tuple_counters_exclude_explain": true})
	require.Zero(t, gaps, "полный checker plan measurement требует покрытия каждого actual SQL")
}
func TestFullProtocolCheckerForeignPopulationMeasurements(t *testing.T) {
	r := writerProtocolRig(t)
	local := fullMeasurementGroups(t, r, r.a, 1, "blue")
	foreign := fullMeasurementGroups(t, r, r.b, 257, "blue")
	r = fullMeasurementRigContext(t, r)
	localBinding := stageBinding(t, r, r.a, true)
	r = fullMeasurementRigContext(t, r)
	foreignBinding := stageBinding(t, r, r.b, true)
	var actor string
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT subject_id FROM kaname.access_bindings WHERE id=$1`, localBinding).Scan(&actor))
	trace := &fullMeasurementTrace{}
	r = fullMeasurementPool(t, r, trace)
	r.repo, _ = fullContractActivate(t, r)
	engine := bindingStageEngine(t, r, nil)
	converge := func(binding domain.AccessBindingID) {
		ctx, cancel := fullMeasurementContext(r.ctx, "")
		defer cancel()
		require.NoError(t, engine.ReconcileBinding(ctx, binding))
	}
	converge(localBinding)
	converge(foreignBinding)
	localBefore := fullMeasurementSnapshot(t, r, localBinding, local)
	fullMeasurementExpect(t, localBefore, local)
	for _, population := range []int{257, 513} {
		if population == 513 {
			foreign = append(foreign, fullMeasurementGroups(t, r, r.b, 256, "blue")...)
			converge(foreignBinding)
		}
		fullMeasurementExpect(t, fullMeasurementSnapshot(t, r, foreignBinding, foreign), foreign)
		require.Equal(t, localBefore, fullMeasurementSnapshot(t, r, localBinding, local))
		for _, question := range []struct {
			relation string
			want     bool
		}{{"viewer", true}, {"editor", false}} {
			fullMeasurementCheck(t, r, trace, actor, "iam_group:"+local[0], question.relation, question.want, population)
		}
	}
}
