// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

// Наблюдатель не отменяет worker: corelib Run отделяет его контекст, а
// terminal row не доказывает join. Прежний global Wait остаётся oracle.
// Кольцо ограничено; tracer не исполняет SQL и не читает args.
type operationCausalObserver struct {
	mu           sync.Mutex
	workers      map[<-chan struct{}]string
	rows         [128]string
	n            uint64
	activity     [8]string
	activityN    uint64
	unattributed uint64
	functionCost *operationFunctionCost
}

func (o *operationCausalObserver) record(v string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.rows[o.n%uint64(len(o.rows))] = time.Now().UTC().Format(time.RFC3339Nano) + " " + v
	o.n++
}

// WithValue сохраняет Done исходного worker. Новые cancel/timeout и
// WithoutCancel не получают чужой opID по совпадению deadline, actor или PID.
type operationCausalOwnerKey struct{}

func (o *operationCausalObserver) rememberWorker(ctx context.Context, id string) bool {
	if ctx == nil || ctx.Done() == nil || id == "" {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	owner, exists := o.workers[ctx.Done()]
	if exists {
		if owner == id {
			return true
		}
		// Неоднозначность необратима: реальный чужой claim продолжится,
		// поэтому прежний opID больше нельзя приписывать этому Done.
		// Пустая запись остаётся слотом cap16, а не удаляется ради нового owner.
		o.workers[ctx.Done()] = ""
		return false
	}
	if len(o.workers) >= 16 {
		return false
	}
	o.workers[ctx.Done()] = id
	return true
}
func (o *operationCausalObserver) operation(ctx context.Context) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if ctx != nil {
		// Этот ключ добавляет только wrapper конкретной terminal-записи,
		// которая уже получила opID явным аргументом.
		if op, ok := ctx.Value(operationCausalOwnerKey{}).(string); ok && op != "" {
			return op
		}
		if done := ctx.Done(); done != nil {
			if op := o.workers[done]; op != "" {
				return op
			}
		}
	}
	o.unattributed++
	return ""
}

func (o *operationCausalObserver) dump(t *testing.T, point string) {
	o.mu.Lock()
	start := uint64(0)
	if o.n > uint64(len(o.rows)) {
		start = o.n - uint64(len(o.rows))
	}
	rows := make([]string, 0, o.n-start)
	for i := start; i < o.n; i++ {
		rows = append(rows, o.rows[i%uint64(len(o.rows))])
	}
	activityStart := uint64(0)
	if o.activityN > uint64(len(o.activity)) {
		activityStart = o.activityN - uint64(len(o.activity))
	}
	for i := activityStart; i < o.activityN; i++ {
		rows = append(rows, o.activity[i%uint64(len(o.activity))])
	}
	total, unattributed := o.n, o.unattributed
	o.mu.Unlock()
	t.Logf("OWNED_OPERATION_CAUSAL %s recorded_events=%d unattributed_contexts=%d ring_limit=128 activity_limit=8", point, total, unattributed)
	for _, row := range rows {
		t.Logf("OWNED_OPERATION_CAUSAL %s %s", point, row)
	}
}

type operationCausalQuery struct {
	op    string
	pid   uint32
	start time.Time
}
type operationCausalQueryKey struct{}

func (o *operationCausalObserver) TraceQueryStart(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	op := o.operation(ctx)
	if op == "" {
		return ctx
	}
	sql := d.SQL
	if len(sql) > 600 {
		sql = sql[:600]
	}
	q := operationCausalQuery{op, c.PgConn().PID(), time.Now()}
	o.record(fmt.Sprintf("op=%s pid=%d tx=%c query_start sql=%q", op, q.pid, c.PgConn().TxStatus(), sql))
	return context.WithValue(ctx, operationCausalQueryKey{}, q)
}
func (o *operationCausalObserver) TraceQueryEnd(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryEndData) {
	q, ok := ctx.Value(operationCausalQueryKey{}).(operationCausalQuery)
	if !ok {
		return
	}
	o.record(fmt.Sprintf("op=%s pid=%d tx=%c query_end elapsed=%s tag=%q err=%v", q.op, q.pid, c.PgConn().TxStatus(), time.Since(q.start), d.CommandTag.String(), d.Err))
}
func (o *operationCausalObserver) TraceBatchStart(ctx context.Context, c *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	op := o.operation(ctx)
	if op == "" {
		return ctx
	}
	o.record(fmt.Sprintf("op=%s pid=%d tx=%c batch_start", op, c.PgConn().PID(), c.PgConn().TxStatus()))
	return context.WithValue(ctx, operationCausalQueryKey{}, operationCausalQuery{op: op, pid: c.PgConn().PID()})
}
func (o *operationCausalObserver) TraceBatchQuery(ctx context.Context, _ *pgx.Conn, d pgx.TraceBatchQueryData) {
	q, ok := ctx.Value(operationCausalQueryKey{}).(operationCausalQuery)
	if !ok {
		return
	}
	sql := d.SQL
	if len(sql) > 600 {
		sql = sql[:600]
	}
	// Callback отмечает прочитанный результат, а не серверное время команды.
	o.record(fmt.Sprintf("op=%s pid=%d batch_result sql=%q tag=%q err=%v", q.op, q.pid, sql, d.CommandTag.String(), d.Err))
}
func (o *operationCausalObserver) TraceBatchEnd(ctx context.Context, c *pgx.Conn, d pgx.TraceBatchEndData) {
	q, ok := ctx.Value(operationCausalQueryKey{}).(operationCausalQuery)
	if ok {
		o.record(fmt.Sprintf("op=%s pid=%d tx=%c batch_end err=%v", q.op, q.pid, c.PgConn().TxStatus(), d.Err))
	}
}

type operationCausalRepo struct {
	operations.FullRepo
	observer *operationCausalObserver
	t        *testing.T
	terminal sync.Map
}

type operationCausalTerminal struct {
	done chan struct{}
	once sync.Once
	err  error
}

func (r *operationCausalRepo) terminalFor(id string) *operationCausalTerminal {
	if value, ok := r.terminal.Load(id); ok {
		return value.(*operationCausalTerminal)
	}
	value, _ := r.terminal.LoadOrStore(id, &operationCausalTerminal{done: make(chan struct{})})
	return value.(*operationCausalTerminal)
}

// Сигнал приходит после попытки записи результата в настоящую БД. Повторное
// чтение по ID проверяет сохранённое состояние операции, а не событие очереди.
func (r *operationCausalRepo) awaitOwnOperation(t *testing.T, ctx context.Context, id string) *operations.Operation {
	t.Helper()
	terminal := r.terminalFor(id)
	select {
	case <-ctx.Done():
		r.observer.dump(t, "wait_cancelled op="+id)
		require.NoError(t, ctx.Err())
	case <-terminal.done:
		require.NoError(t, terminal.err, "запись результата операции %s", id)
	}
	got, err := r.Get(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.True(t, got.Done, "операция %s не терминальна", id)
	return got
}

func (r *operationCausalRepo) finishOperation(id string, err error) {
	terminal := r.terminalFor(id)
	terminal.once.Do(func() {
		terminal.err = err
		close(terminal.done)
	})
}

func (r *operationCausalRepo) ClaimForExecution(ctx context.Context, id string) (bool, error) {
	// Сохраняем настоящий optional claim, не превращаем wrapper в обход gate.
	claimer := r.FullRepo.(interface {
		ClaimForExecution(context.Context, string) (bool, error)
	})
	attributed := r.observer.rememberWorker(ctx, id)
	r.observer.record(fmt.Sprintf("op=%s claim_start attributed=%t", id, attributed))
	live, err := claimer.ClaimForExecution(ctx, id)
	r.observer.record(fmt.Sprintf("op=%s claim_end live=%t err=%v", id, live, err))
	return live, err
}
func (r *operationCausalRepo) MarkDone(ctx context.Context, id string, response *anypb.Any) error {
	r.observer.record("op=" + id + " mark_done_start")
	err := r.FullRepo.MarkDone(context.WithValue(ctx, operationCausalOwnerKey{}, id), id, response)
	r.observer.record(fmt.Sprintf("op=%s mark_done_end err=%v", id, err))
	r.finishOperation(id, err)
	return err
}
func (r *operationCausalRepo) MarkError(ctx context.Context, id string, failure *rpcstatus.Status) error {
	r.observer.record(fmt.Sprintf("op=%s mark_error_start code=%d", id, failure.GetCode()))
	err := r.FullRepo.MarkError(context.WithValue(ctx, operationCausalOwnerKey{}, id), id, failure)
	r.observer.record(fmt.Sprintf("op=%s mark_error_end err=%v", id, err))
	r.finishOperation(id, err)
	return err
}
func (r *operationCausalRepo) operationWaitFailed(id string) {
	r.observer.dump(r.t, "global_deadline op="+id)
	if p := r.observer.functionCost; p != nil && !p.baselineAttempted {
		// Соседняя preflight fixture не имеет revoke baseline: её счётчики
		// помогают отличить cascade, но не выдаются за стоимость своей операции.
		p.capture(r.t, "global_deadline_without_baseline", false)
	}
}

// Включается только в трёх исследуемых GD TOP. Отсутствие предыдущего tracer
// проверяется до подмены pool; Query+Batch сохраняют прежний batch-путь.
func operationCausalPool(t *testing.T, r protocolRig) (protocolRig, *operationCausalObserver) {
	t.Helper()
	cfg := r.runtime.Config()
	require.Nil(t, cfg.ConnConfig.Tracer, "нельзя скрывать существующий tracer")
	o := &operationCausalObserver{workers: map[<-chan struct{}]string{}}
	cfg.ConnConfig.Tracer = o
	if operationCostEnabled() {
		// Только LOGIN собственной fixture; права владельца ему не передаются.
		_, err := r.admin.Exec(r.ctx, "GRANT SET ON PARAMETER track_functions TO "+pgx.Identifier{cfg.ConnConfig.User}.Sanitize())
		require.NoError(t, err)
		if cfg.ConnConfig.RuntimeParams == nil {
			cfg.ConnConfig.RuntimeParams = map[string]string{}
		}
		cfg.ConnConfig.RuntimeParams["track_functions"] = "all"
		o.functionCost = &operationFunctionCost{admin: r.admin}
		if os.Getenv("KANAME_GD_SQL_COST_DIAGNOSTIC") == "1" {
			var preload, computeID, adminTracking string
			require.NoError(t, r.admin.QueryRow(r.ctx, "SELECT current_setting('shared_preload_libraries'),current_setting('compute_query_id'),current_setting('pg_stat_statements.track')").Scan(&preload, &computeID, &adminTracking))
			require.Equal(t, "pg_stat_statements", preload, "нужна owned диагностическая копия pgtest")
			require.Equal(t, "on", computeID)
			require.Equal(t, "none", adminTracking, "наблюдатель не должен добавлять свой SQL в статистику")
			_, err = r.admin.Exec(r.ctx, "CREATE SCHEMA gd_sql_cost_diagnostic; REVOKE ALL ON SCHEMA gd_sql_cost_diagnostic FROM PUBLIC; CREATE EXTENSION pg_stat_statements WITH SCHEMA gd_sql_cost_diagnostic")
			require.NoError(t, err, "отсутствующий preload/extension не является нулевой стоимостью")
			_, err = r.admin.Exec(r.ctx, "GRANT SET ON PARAMETER pg_stat_statements.track TO "+pgx.Identifier{cfg.ConnConfig.User}.Sanitize())
			require.NoError(t, err)
			cfg.ConnConfig.RuntimeParams["pg_stat_statements.track"] = "all"
			o.functionCost.sql = &operationSQLCost{admin: r.admin}
		}
	}
	r.runtime.Close()
	pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	// Наблюдаемые фикстуры GD используют общий исполнитель пакета и не идут
	// параллельно. Срок проверки 20 секунд сохраняется, а репозиторий остаётся
	// доступным до завершения terminalWrite даже после отказа этой проверки.
	t.Cleanup(func() { closeOperationPoolAfterDrain(t, operations.Wait, pool.Close) })
	r.runtime, r.repo = pool, kanamepg.New(pool, nil)
	if o.functionCost != nil {
		var effective, session, setting string
		require.NoError(t, pool.QueryRow(r.ctx, "SELECT current_user,session_user,current_setting('track_functions')").Scan(&effective, &session, &setting))
		require.Equal(t, cfg.ConnConfig.User, effective)
		require.Equal(t, cfg.ConnConfig.User, session)
		require.Equal(t, "all", setting)
		t.Logf("GD_FUNCTION_COST runtime_login=%s session_user=%s track_functions=%s", effective, session, setting)
		if o.functionCost.sql != nil {
			var tracking, version string
			require.NoError(t, pool.QueryRow(r.ctx, "SELECT current_setting('pg_stat_statements.track')").Scan(&tracking))
			require.Equal(t, "all", tracking)
			require.NoError(t, r.admin.QueryRow(r.ctx, "SELECT extversion FROM pg_catalog.pg_extension WHERE extname='pg_stat_statements'").Scan(&version))
			t.Logf("GD_SQL_COST mode=DIAGNOSTIC_NOT_PERF_ACCEPTANCE track=%s extension=%s nested_userids=all_owned_database", tracking, version)
		}
		t.Cleanup(func() { o.functionCost.capture(t, "cleanup", false) })
	}
	operationActivityRing(t, r.admin, o)
	t.Cleanup(func() {
		if t.Failed() {
			o.dump(t, "cleanup_before_pool_close")
		}
	})
	return r, o
}

// Счётчики общие для БД и публикуются PostgreSQL с задержкой. Даже пустой
// active-набор не доказывает flush; активные function frames не наблюдаемы.
// Никакого SQL из tracer, принудительного flush или вмешательства в worker TX.
func operationCostEnabled() bool {
	return os.Getenv("KANAME_GD_FUNCTION_COST_DIAGNOSTIC") == "1" || os.Getenv("KANAME_GD_SQL_COST_DIAGNOSTIC") == "1"
}

type operationFunctionCost struct {
	sql               *operationSQLCost
	admin             *pgxpool.Pool
	captures          int
	baselineAttempted bool
	baseline          map[uint32]operationFunctionCounter
}

type operationFunctionCounter struct {
	OID      uint32   `json:"oid"`
	Function string   `json:"function"`
	Calls    *int64   `json:"calls"`
	Total    *float64 `json:"total_ms"`
	Self     *float64 `json:"self_ms"`
}

func (p *operationFunctionCost) capture(t *testing.T, point string, baseline bool) {
	t.Helper()
	if p.captures >= 3 {
		t.Logf("GD_FUNCTION_COST point=%s status=UNKNOWN capture_limit=3", point)
		return
	}
	p.captures++
	if baseline {
		p.baselineAttempted = true
	}
	// Отдельный ограниченный read сохраняет исходный deadline операции.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var raw []byte
	err := p.admin.QueryRow(ctx, `SELECT jsonb_build_object(
 'functions',coalesce((SELECT jsonb_agg(to_jsonb(f) ORDER BY f.oid) FROM (
  SELECT p.oid::bigint AS oid,p.oid::regprocedure::text AS "function",s.calls,s.total_time AS total_ms,s.self_time AS self_ms
  FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
  LEFT JOIN pg_catalog.pg_stat_user_functions s ON s.funcid=p.oid
  WHERE n.nspname='kaname' ORDER BY p.oid LIMIT 2049
 ) f),'[]'::jsonb),
 'active_backends',(SELECT count(*) FROM pg_catalog.pg_stat_activity
  WHERE datname=current_database() AND pid<>pg_backend_pid() AND state='active'),
 'open_transactions',(SELECT count(*) FROM pg_catalog.pg_stat_activity
  WHERE datname=current_database() AND pid<>pg_backend_pid() AND xact_start IS NOT NULL))`).Scan(&raw)
	if p.sql != nil {
		p.sql.capture(t, ctx, point, baseline)
	}
	if err != nil {
		t.Logf("GD_FUNCTION_COST point=%s status=UNKNOWN read_error=%v", point, err)
		return
	}
	var snapshot struct {
		Functions    []operationFunctionCounter `json:"functions"`
		Active       int                        `json:"active_backends"`
		Transactions int                        `json:"open_transactions"`
	}
	if err = json.Unmarshal(raw, &snapshot); err != nil {
		t.Logf("GD_FUNCTION_COST point=%s status=UNKNOWN decode_error=%v", point, err)
		return
	}
	overflow := len(snapshot.Functions) > 2048
	if overflow {
		snapshot.Functions = snapshot.Functions[:2048]
	}
	if baseline && !overflow {
		p.baseline = make(map[uint32]operationFunctionCounter, len(snapshot.Functions))
		for _, row := range snapshot.Functions {
			p.baseline[row.OID] = row
		}
	}
	t.Logf("GD_FUNCTION_COST point=%s at=%s rows=%d overflow=%t active_backends=%d open_transactions=%d flush=UNKNOWN active_frames=UNKNOWN baseline_available=%t scope=database_cumulative_not_operation_attribution", point, time.Now().UTC().Format(time.RFC3339Nano), len(snapshot.Functions), overflow, snapshot.Active, snapshot.Transactions, p.baseline != nil)
	for _, row := range snapshot.Functions {
		value, _ := json.Marshal(row)
		old, known := p.baseline[row.OID]
		if baseline || !known || old.Function != row.Function || old.Calls == nil || row.Calls == nil || old.Total == nil || row.Total == nil || old.Self == nil || row.Self == nil || *row.Calls < *old.Calls || *row.Total < *old.Total || *row.Self < *old.Self {
			t.Logf("GD_FUNCTION_COST point=%s counter=%s delta=UNKNOWN", point, value)
			continue
		}
		t.Logf("GD_FUNCTION_COST point=%s counter=%s observed_delta_calls=%d observed_delta_total_ms=%g observed_delta_self_ms=%g completeness=UNKNOWN", point, value, *row.Calls-*old.Calls, *row.Total-*old.Total, *row.Self-*old.Self)
	}
}

// SQL counters принадлежат только fixture DB, включая SECURITY DEFINER
// userid. Они не являются self-time функции: nested totals нельзя складывать.
// Сбор делит исходный секундный read deadline с function snapshot.
type operationSQLCost struct {
	admin    *pgxpool.Pool
	baseline map[string]operationSQLCounter
	reset    string
	dealloc  int64
}

type operationSQLCounter struct {
	Database  uint32  `json:"dbid"`
	User      uint32  `json:"userid"`
	QueryID   int64   `json:"queryid"`
	TopLevel  bool    `json:"toplevel"`
	Query     string  `json:"query"`
	Truncated bool    `json:"query_truncated"`
	Calls     int64   `json:"calls"`
	Total     float64 `json:"total_exec_ms"`
	Rows      int64   `json:"rows"`
}

func (r operationSQLCounter) key() string {
	return fmt.Sprintf("%d/%d/%d/%t", r.Database, r.User, r.QueryID, r.TopLevel)
}

func (p *operationSQLCost) capture(t *testing.T, ctx context.Context, point string, baseline bool) {
	t.Helper()
	var raw []byte
	err := p.admin.QueryRow(ctx, `SELECT jsonb_build_object(
 'stats_reset',i.stats_reset::text,'dealloc',i.dealloc,
 'queries',coalesce((SELECT jsonb_agg(to_jsonb(q) ORDER BY q.total_exec_ms DESC,q.queryid) FROM (
  SELECT s.dbid::bigint AS dbid,s.userid::bigint AS userid,s.queryid,s.toplevel,
   left(s.query,2000) AS query,length(s.query)>2000 AS query_truncated,
   s.calls,s.total_exec_time AS total_exec_ms,s.rows
  FROM gd_sql_cost_diagnostic.pg_stat_statements s
  WHERE s.dbid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
  ORDER BY s.total_exec_time DESC,s.userid,s.queryid,s.toplevel LIMIT 2049
 ) q),'[]'::jsonb)) FROM gd_sql_cost_diagnostic.pg_stat_statements_info i`).Scan(&raw)
	if err != nil {
		t.Logf("GD_SQL_COST point=%s status=UNKNOWN read_error=%v", point, err)
		return
	}
	var snapshot struct {
		Reset   string                `json:"stats_reset"`
		Dealloc *int64                `json:"dealloc"`
		Queries []operationSQLCounter `json:"queries"`
	}
	if err = json.Unmarshal(raw, &snapshot); err != nil || snapshot.Reset == "" || snapshot.Dealloc == nil {
		t.Logf("GD_SQL_COST point=%s status=UNKNOWN decode_error=%v reset_present=%t dealloc_present=%t", point, err, snapshot.Reset != "", snapshot.Dealloc != nil)
		return
	}
	overflow := len(snapshot.Queries) > 2048
	if overflow {
		snapshot.Queries = snapshot.Queries[:2048]
	}
	if baseline && !overflow {
		p.baseline = make(map[string]operationSQLCounter, len(snapshot.Queries))
		for _, row := range snapshot.Queries {
			p.baseline[row.key()] = row
		}
		p.reset, p.dealloc = snapshot.Reset, *snapshot.Dealloc
	}
	stable := p.baseline != nil && !overflow && p.reset == snapshot.Reset && p.dealloc == *snapshot.Dealloc
	type ranked struct {
		row   operationSQLCounter
		known bool
		calls int64
		total float64
		rows  int64
	}
	values := make([]ranked, 0, len(snapshot.Queries))
	for _, row := range snapshot.Queries {
		v := ranked{row: row}
		old, present := p.baseline[row.key()]
		if !baseline && stable && present && old.Query == row.Query && old.Truncated == row.Truncated && row.Calls >= old.Calls && row.Total >= old.Total && row.Rows >= old.Rows {
			v.known, v.calls, v.total, v.rows = true, row.Calls-old.Calls, row.Total-old.Total, row.Rows-old.Rows
		}
		values = append(values, v)
	}
	// При неизвестном baseline cumulative остаётся cumulative. Top30
	// ранжируется по total; никогда не вычитаем выдуманный нулевой baseline.
	sort.Slice(values, func(i, j int) bool {
		if values[i].row.Total != values[j].row.Total {
			return values[i].row.Total > values[j].row.Total
		}
		return values[i].row.key() < values[j].row.key()
	})
	t.Logf("GD_SQL_COST point=%s at=%s inventory=%d overflow=%t stats_reset=%s dealloc=%d baseline_available=%t reset_dealloc_stable=%t output_limit=30 active_statements=UNKNOWN completeness=UNKNOWN mode=DIAGNOSTIC_NOT_PERF_ACCEPTANCE", point, time.Now().UTC().Format(time.RFC3339Nano), len(snapshot.Queries), overflow, snapshot.Reset, *snapshot.Dealloc, p.baseline != nil, stable)
	for i, v := range values {
		if i == 30 {
			break
		}
		encoded, _ := json.Marshal(v.row)
		if !v.known {
			t.Logf("GD_SQL_COST point=%s rank=%d counter=%s delta=UNKNOWN", point, i+1, encoded)
		} else {
			t.Logf("GD_SQL_COST point=%s rank=%d counter=%s observed_delta_calls=%d observed_delta_exec_ms=%g observed_delta_rows=%d completeness=UNKNOWN", point, i+1, encoded, v.calls, v.total, v.rows)
		}
	}
}

// Baseline снимается после всех 257 carriers непосредственно перед исходным
// revoke. Один deferred снимок срабатывает и при FailNow; повторный вызов после
// успешного await не дублирует его. Cleanup не означает join worker.
func operationFunctionCostBeforeRevoke(t *testing.T, w delegationUCWorld) func() {
	t.Helper()
	if !operationCostEnabled() {
		return func() {}
	}
	r, ok := w.ops.(*operationCausalRepo)
	require.True(t, ok, "для function-cost нужен настоящий observer repo")
	require.NotNil(t, r.observer.functionCost)
	p := r.observer.functionCost
	p.capture(t, "before_revoke", true)
	var once sync.Once
	return func() { once.Do(func() { p.capture(t, "after_wait_or_failure", false) }) }
}

// Только отдельная читающая admin connection. Никаких запросов внутри tracer,
// назначения xid или SQL на наблюдаемой TX. Снимки показывают реальный wait и
// backend_xid; отмена наблюдателя и join принадлежат самой фикстуре.
func operationActivityRing(t *testing.T, admin *pgxpool.Pool, o *operationCausalObserver) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				read, stop := context.WithTimeout(ctx, time.Second)
				var data json.RawMessage
				err := admin.QueryRow(read, `SELECT coalesce(jsonb_agg(to_jsonb(a)),'[]'::jsonb) FROM (
 SELECT pid,backend_xid::text,state,wait_event_type,wait_event,pg_blocking_pids(pid) AS blocker_pids,
 extract(epoch FROM clock_timestamp()-xact_start) AS tx_seconds,
 extract(epoch FROM clock_timestamp()-query_start) AS query_seconds,left(query,600) AS query
 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND state<>'idle'
 ORDER BY pid LIMIT 32) a`).Scan(&data)
				stop()
				row := "activity=" + string(data)
				if err != nil {
					row = fmt.Sprintf("activity err=%v", err)
				}
				o.mu.Lock()
				o.activity[o.activityN%uint64(len(o.activity))] = time.Now().UTC().Format(time.RFC3339Nano) + " " + row
				o.activityN++
				o.mu.Unlock()
			}
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
}

// Только primary expiry TOP включает этот ключ; исторические report calls
// остаются без наблюдателя. Рабочий pool, counter и его batch-выбор неизменны.
type expiryActivityKey struct{}

func expiryActivityPool(t *testing.T, cfg *pgxpool.Config) {
	t.Helper()
	observe := cfg.Copy()
	observe.ConnConfig.Tracer = nil
	observe.MinConns, observe.MaxConns = 0, 1
	observe.AfterConnect = nil
	observe.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	observe.ConnConfig.RuntimeParams["statement_timeout"] = "1000"
	pool, err := pgxpool.NewWithConfig(context.Background(), observe)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	o := &operationCausalObserver{}
	operationActivityRing(t, pool, o)
	t.Cleanup(func() {
		if t.Failed() {
			o.dump(t, "expiry10000_failure")
		}
	})
}

// Проверка использует настоящие деревья context, без синтетических PID или
// приписывания работы по равным deadline. Новые бюджеты здесь не исполняют SQL.
func TestOperationCausalObserverPreservesOnlyKnownCancellationIdentity(t *testing.T) {
	o := &operationCausalObserver{workers: map[<-chan struct{}]string{}}
	worker, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.True(t, o.rememberWorker(worker, "own-op"))
	type valueKey int
	derived := context.WithValue(context.WithValue(worker, valueKey(1), true), valueKey(2), true)
	require.Equal(t, "own-op", o.operation(derived))
	require.False(t, o.rememberWorker(derived, "foreign-op"), "общий Done становится неоднозначным")
	require.Empty(t, o.operation(worker))
	require.Empty(t, o.operation(derived), "WithValue не восстанавливает прежнего владельца после коллизии")
	require.False(t, o.rememberWorker(worker, "own-op"), "повтор прежнего claim не снимает неоднозначность")
	require.Empty(t, o.operation(context.WithValue(derived, valueKey(3), true)))
	require.Len(t, o.workers, 1, "неоднозначный Done продолжает занимать слот cap16")
	child, stop := context.WithCancel(derived)
	defer stop()
	require.Empty(t, o.operation(child))
	timed, stopTimed := context.WithTimeout(derived, time.Hour)
	defer stopTimed()
	require.Empty(t, o.operation(timed))
	detached := context.WithoutCancel(derived)
	require.Empty(t, o.operation(detached))
	require.Empty(t, o.operation(context.Background()))
	require.False(t, o.rememberWorker(context.Background(), "unowned"))
	terminal := context.WithValue(context.Background(), operationCausalOwnerKey{}, "terminal-op")
	require.Equal(t, "terminal-op", o.operation(terminal))
	for i := 1; i < 16; i++ {
		ctx, release := context.WithCancel(context.Background())
		defer release()
		require.True(t, o.rememberWorker(ctx, fmt.Sprintf("op-%d", i)))
	}
	overflow, release := context.WithCancel(context.Background())
	defer release()
	require.False(t, o.rememberWorker(overflow, "overflow"))
	require.Empty(t, o.operation(overflow))
	require.Len(t, o.workers, 16)
}
