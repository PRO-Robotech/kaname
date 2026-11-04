// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Каждая физическая таблица kaname обнаруживается в первичной БД, а не выбранной
// учётной записи или подмножестве только живых строк. Полные канонические строки хешируются в памяти:
// квитанции не должны сохранять материал закрытых ключей/токенов/сессий из таблиц аутентификации.
// Точное разрешённое отделение учёта записывается и не теряется молча.
type ridWholeTable struct {
	Columns []string `json:"columns"`
	Rows    []string `json:"rowSHA256"`
}

// Необработанное представление включает stated_at, все исходные столбцы и полные отпечатки строк.
// Семантическое представление удаляет ТОЛЬКО stated_at; неизвестные будущие поля остаются в дайджесте.
type ridWholeOwnCeilings struct {
	Raw      ridWholeTable        `json:"raw"`
	Semantic map[string]string    `json:"semanticRowSHA256ByKind"`
	StatedAt map[string]time.Time `json:"statedAtByKind"`
}
type ridWholeDeliverySnapshot struct {
	auditSQLRows      [][]byte                 `json:"-"`
	PrimaryStartedAt  time.Time                `json:"primaryStartedAt"`
	PrimaryFinishedAt time.Time                `json:"primaryFinishedAt"`
	OwnCeilings       ridWholeOwnCeilings      `json:"ownCeilings"`
	Delivery          map[string]ridWholeTable `json:"delivery"`
	Bookkeeping       map[string]ridWholeTable `json:"bookkeeping"`
	Separation        map[string]string        `json:"separation"`
}

var ridWholeBookkeeping = map[string]string{
	"audit_outbox":                "audit delivery/retention is not installation domain state",
	"client_assertion_replay":     "normal assertion replay admission",
	"access_tokens":               "normal issued access-token bookkeeping",
	"authorization_codes":         "ordinary O code exchange",
	"refresh_tokens":              "ordinary O refresh issuance",
	"token_families":              "ordinary O token-family bookkeeping",
	"human_sessions":              "normal presented-session activity",
	"human_first_authentications": "normal authentication bookkeeping",
	"login_failures":              "normal authentication refusal bookkeeping",
	"operations":                  "normal Operation ledger; installation Operations checked separately",
}

func ridReadWholeDelivery(t *testing.T, f *installationNativeWorld) ridWholeDeliverySnapshot {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.given.ctx, 20*time.Second)
	defer cancel()
	tx, err := f.given.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() {
		closeCtx, c := context.WithTimeout(context.Background(), time.Second)
		defer c()
		_ = tx.Rollback(closeCtx)
	}()
	var recovery bool
	var started time.Time
	require.NoError(t, tx.QueryRow(ctx, "SELECT pg_is_in_recovery(),clock_timestamp()").Scan(&recovery, &started))
	require.False(t, recovery, "whole-delivery oracle is PRIMARY")
	rs, err := tx.Query(ctx, `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname' AND c.relkind IN ('r','p') ORDER BY c.relname`)
	require.NoError(t, err)
	var tables []string
	for rs.Next() {
		var name string
		require.NoError(t, rs.Scan(&name))
		tables = append(tables, name)
	}
	require.NoError(t, rs.Err())
	rs.Close()
	out := ridWholeDeliverySnapshot{PrimaryStartedAt: started, OwnCeilings: ridWholeOwnCeilings{Semantic: map[string]string{}, StatedAt: map[string]time.Time{}}, Delivery: map[string]ridWholeTable{}, Bookkeeping: map[string]ridWholeTable{}, Separation: map[string]string{}}
	for _, table := range tables {
		col, err := tx.Query(ctx, `SELECT a.attname FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname' AND c.relname=$1 AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`, table)
		require.NoError(t, err)
		entry := ridWholeTable{Columns: []string{}, Rows: []string{}}
		for col.Next() {
			var name string
			require.NoError(t, col.Scan(&name))
			entry.Columns = append(entry.Columns, name)
		}
		require.NoError(t, col.Err())
		col.Close()
		require.NotEmpty(t, entry.Columns)
		// Кавычки идентификаторов определяются настоящими именами каталога; предикат не фильтрует
		// учётную запись, статус, живые/выведенные строки, происхождение посева, создателя или модуль.
		rows, err := tx.Query(ctx, `SELECT to_jsonb(r)::text FROM `+pgx.Identifier{"kaname", table}.Sanitize()+` r ORDER BY to_jsonb(r)::text`)
		require.NoError(t, err)
		for rows.Next() {
			var raw []byte
			require.NoError(t, rows.Scan(&raw))
			if table == "audit_outbox" {
				out.auditSQLRows = append(out.auditSQLRows, append([]byte(nil), raw...))
			}
			sum := sha256.Sum256(raw)
			entry.Rows = append(entry.Rows, hex.EncodeToString(sum[:]))
			if table == "own_ceilings" {
				var fields map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(raw, &fields))
				var kind *string
				var limit *int64
				var stated *time.Time
				require.NoError(t, json.Unmarshal(fields["kind"], &kind))
				require.NotNil(t, kind)
				require.NotEmpty(t, *kind)
				require.NoError(t, json.Unmarshal(fields["limit_value"], &limit))
				require.NotNil(t, limit)
				require.GreaterOrEqual(t, *limit, int64(0))
				require.NoError(t, json.Unmarshal(fields["stated_at"], &stated))
				require.NotNil(t, stated)
				require.False(t, stated.IsZero())
				require.NotContains(t, out.OwnCeilings.Semantic, *kind)
				out.OwnCeilings.StatedAt[*kind] = *stated
				delete(fields, "stated_at") // единственная утверждённая диагностическая временная метка загрузки
				semantic, err := json.Marshal(fields)
				require.NoError(t, err)
				digest := sha256.Sum256(semantic)
				out.OwnCeilings.Semantic[*kind] = hex.EncodeToString(digest[:])
			}
		}
		require.NoError(t, rows.Err())
		rows.Close()
		sort.Strings(entry.Rows)
		if table == "own_ceilings" {
			out.OwnCeilings.Raw = entry
		} else if reason, ok := ridWholeBookkeeping[table]; ok {
			out.Bookkeeping[table] = entry
			out.Separation[table] = reason
		} else {
			out.Delivery[table] = entry
		}
	}
	// Ведомость производителей: catalog_writer, role_repo/withdrawal, module_seed_writer,
	// штатные записи SA/групп/AB/GD/администратора/учётных записей и их журналы проекций.
	// Новые таблицы ВКЛЮЧЕНЫ по умолчанию; удаление обязательной таблицы даёт отказ.
	for _, table := range []string{"catalog_module", "catalog_resource", "catalog_verb", "roles", "role_rule_ref", "role_rule_selectors", "role_selector_verbs_pending", "role_verb", "role_grant_orphan", "role_selector_prune", "service_accounts", "service_account_oauth_clients", "groups", "group_members", "access_bindings", "access_binding_subjects", "access_binding_target_members", "access_binding_emitted_tuples", "grant_delegations", "cluster_admin_grants", "account_admission_rate_limits", "accounts", "users", "memberships", "relation_fact", "resource_mirror", "resource_parent_edge", "resource_journal", "public_read_publication", "fga_outbox", "resource_reconcile_outbox", "subject_change_outbox"} {
		require.Contains(t, out.Delivery, table)
	}
	require.Contains(t, out.Bookkeeping, "operations")
	require.NotEmpty(t, out.OwnCeilings.Semantic, "boot policy must not disappear from the census")
	require.Len(t, out.OwnCeilings.Raw.Rows, len(out.OwnCeilings.Semantic))
	require.Contains(t, out.OwnCeilings.Raw.Columns, "kind")
	require.Contains(t, out.OwnCeilings.Raw.Columns, "limit_value")
	require.Contains(t, out.OwnCeilings.Raw.Columns, "stated_at")
	require.NoError(t, tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&out.PrimaryFinishedAt))
	require.False(t, out.PrimaryFinishedAt.Before(out.PrimaryStartedAt))
	require.NoError(t, tx.Commit(ctx))
	require.NoError(t, ctx.Err())
	return out
}
func ridRequireWholeDeliveryUnchanged(t *testing.T, before, after ridWholeDeliverySnapshot) {
	t.Helper()
	ridRequireOwnCeilingsPreserved(t, before, after)
	require.Equal(t, before.Separation, after.Separation, "bookkeeping partition cannot silently change")
	require.Equal(t, before.Delivery, after.Delivery, "all primary delivery tables/columns/rows, including retired/history rows and every account, must remain exact")
}

// Apply проецирует то же состояние при каждой загрузке, включая отклонённую поставку
// манифеста. Меняется только stated_at. Обе границы — настоящие часы БД PRIMARY,
// охватывающие проверяемый запуск; без часов/допуска хоста или отброшенной строки политики.
func ridRequireOwnCeilingsPreserved(t *testing.T, before, after ridWholeDeliverySnapshot) {
	t.Helper()
	require.Equal(t, before.OwnCeilings.Raw.Columns, after.OwnCeilings.Raw.Columns, "complete boot policy schema remains exact")
	require.Equal(t, before.OwnCeilings.Semantic, after.OwnCeilings.Semantic, "all fields except stated_at, including unknown future columns, remain exact")
	require.NotEmpty(t, before.OwnCeilings.Semantic)
	require.Len(t, after.OwnCeilings.Raw.Rows, len(before.OwnCeilings.Raw.Rows))
	require.Len(t, after.OwnCeilings.StatedAt, len(before.OwnCeilings.StatedAt))
	require.False(t, after.PrimaryStartedAt.Before(before.PrimaryFinishedAt))
	for kind, stated := range after.OwnCeilings.StatedAt {
		require.Contains(t, before.OwnCeilings.Semantic, kind)
		require.False(t, stated.Before(before.PrimaryFinishedAt), "actual after stated_at must follow the stopped-base snapshot for %s", kind)
		require.False(t, stated.After(after.PrimaryStartedAt), "actual after stated_at must precede the post-startup PRIMARY snapshot for %s", kind)
	}
}
func ridWholeDigest(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	if text, ok := v.(string); ok {
		raw = []byte(text)
	} // SHA манифеста покрывает точные байты, а не цитирование JSON
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Десять скобок на режим: отдельные ACT и явные пары VERIFY сюда не входят.
func rid06ReadBracketCase(id string) bool {
	for _, mode := range []string{"S1", "S2"} {
		for _, suffix := range []string{"BEFORE-REVOKE", "AFTER-REVOKE", "SEQUENTIAL-BEFORE-REVOKE", "SEQUENTIAL-AFTER-OVERLAP", "AFTER-SEQUENTIAL-REFUSAL", "NO-REVOKE-BEFORE", "NO-REVOKE-TWIN", "RECOVERY-BEFORE-REVOKE", "RECOVERY-AFTER-REVOKE", "RECOVERY-REAPPLY"} {
			if id == "registry-installation-rid06-"+mode+"-"+suffix {
				return true
			}
		}
	}
	return false
}

func rid06PrimaryBounds(a, b ridWholeDeliverySnapshot) bool {
	return !a.PrimaryStartedAt.IsZero() && !a.PrimaryFinishedAt.Before(a.PrimaryStartedAt) && !b.PrimaryStartedAt.IsZero() && !b.PrimaryFinishedAt.Before(b.PrimaryStartedAt) && !b.PrimaryStartedAt.Before(a.PrimaryFinishedAt)
}

func rid06PreparationEqual(a, b rid03NewmanSnapshot) bool {
	return rid06PrimaryBounds(a.Whole, b.Whole) && rid03SnapshotEqual(a, b) && reflect.DeepEqual(a.Whole.Separation, b.Whole.Separation)
}

type rid06AuditTransportWitness struct {
	Status        string     `json:"status"`
	Attempts      int64      `json:"attempts"`
	NextAttemptAt time.Time  `json:"nextAttemptAt"`
	SentAt        *time.Time `json:"sentAt"`
	ErrorPresent  bool       `json:"errorPresent"`
	ErrorSHA256   string     `json:"errorSHA256"`
}

type rid06AuditRowWitness struct {
	ID                    string                     `json:"id"`
	CreatedAt             time.Time                  `json:"createdAt"`
	BeforeRowSHA256       string                     `json:"beforeRowSHA256"`
	AfterRowSHA256        string                     `json:"afterRowSHA256"`
	BeforeImmutableSHA256 string                     `json:"beforeImmutableSHA256"`
	AfterImmutableSHA256  string                     `json:"afterImmutableSHA256"`
	Before                rid06AuditTransportWitness `json:"before"`
	After                 rid06AuditTransportWitness `json:"after"`
}

type rid06AuditReadProof struct {
	CaseID             string                 `json:"caseId"`
	RunID              string                 `json:"runId"`
	BeforeStartedAt    time.Time              `json:"beforePrimaryStartedAt"`
	BeforeFinishedAt   time.Time              `json:"beforePrimaryFinishedAt"`
	AfterStartedAt     time.Time              `json:"afterPrimaryStartedAt"`
	AfterFinishedAt    time.Time              `json:"afterPrimaryFinishedAt"`
	Columns            []string               `json:"columns"`
	BeforeSQLRowSHA256 []string               `json:"beforeSQLRowSHA256"`
	AfterSQLRowSHA256  []string               `json:"afterSQLRowSHA256"`
	Rows               []rid06AuditRowWitness `json:"rows"`
}

func rid06ByteSHA(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Разбираются только исходные байты того же SQL-чтения, которое дало Whole-дайджест.
// Неизвестные/повторные ключи и расхождение полного мультимножества дают отказ.
func rid06BoundAuditRows(s ridWholeDeliverySnapshot) ([]rid09PrimaryRow, map[string]string, bool) {
	table, exists := s.Bookkeeping["audit_outbox"]
	if !exists || !rid11SameColumns(table.Columns, rid11AuthnColumns["audit_outbox"]) || len(table.Rows) != len(s.auditSQLRows) {
		return nil, nil, false
	}
	rows := []rid09PrimaryRow{}
	hashes := []string{}
	byID := map[string]string{}
	for _, raw := range s.auditSQLRows {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		first, err := decoder.Token()
		if err != nil || first != json.Delim('{') {
			return nil, nil, false
		}
		row := rid09PrimaryRow{}
		for decoder.More() {
			token, err := decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok || row[key] != nil {
				return nil, nil, false
			}
			var value json.RawMessage
			if decoder.Decode(&value) != nil {
				return nil, nil, false
			}
			row[key] = value
		}
		last, err := decoder.Token()
		var extra any
		if err != nil || last != json.Delim('}') || decoder.Decode(&extra) != io.EOF || !rid11AuditRowShape(row, s.PrimaryFinishedAt) {
			return nil, nil, false
		}
		id := rid03S(row, "id")
		if _, duplicate := byID[id]; duplicate {
			return nil, nil, false
		}
		hash := rid06ByteSHA(raw)
		byID[id] = hash
		hashes = append(hashes, hash)
		rows = append(rows, row)
	}
	sort.Strings(hashes)
	if !reflect.DeepEqual(hashes, table.Rows) {
		return nil, nil, false
	}
	return rows, byID, true
}

func rid06TransportWitness(row rid09PrimaryRow) rid06AuditTransportWitness {
	status, _ := rid03Cell[string](row, "status")
	attempts, _ := rid03Cell[int64](row, "attempts")
	next, _ := rid03Cell[time.Time](row, "next_attempt_at")
	sent, _ := rid03Cell[*time.Time](row, "sent_at")
	cause, _ := rid03Cell[*string](row, "last_error")
	out := rid06AuditTransportWitness{Status: status, Attempts: attempts, NextAttemptAt: next, SentAt: sent, ErrorPresent: cause != nil}
	if cause != nil {
		out.ErrorSHA256 = rid06ByteSHA([]byte(*cause))
	}
	return out
}

// Истинность устанавливает неизменённый RID11-предикат по реальным нагрузкам в RAM.
// Наружу выходят только полные хеши строк/неизменяемой части и типизированный транспорт.
func rid06BuildReadBoundary(caseID, runID string, a, b rid03NewmanSnapshot) (rid06AuditReadProof, bool) {
	fail := func() (rid06AuditReadProof, bool) { return rid06AuditReadProof{}, false }
	if !rid06ReadBracketCase(caseID) || !regexp.MustCompile(`^[A-Za-z0-9-]{16,80}$`).MatchString(runID) || !rid06PreparationEqual(a, b) || len(a.Whole.Bookkeeping) != len(ridWholeBookkeeping) || len(b.Whole.Bookkeeping) != len(ridWholeBookkeeping) || !reflect.DeepEqual(a.Whole.Separation, ridWholeBookkeeping) {
		return fail()
	}
	for table, old := range a.Whole.Bookkeeping {
		now, exists := b.Whole.Bookkeeping[table]
		if !exists || (table != "audit_outbox" && !reflect.DeepEqual(old, now)) {
			return fail()
		}
	}
	for table := range ridWholeBookkeeping {
		if _, exists := a.Whole.Bookkeeping[table]; !exists {
			return fail()
		}
	}
	old, oldHashes, ok := rid06BoundAuditRows(a.Whole)
	if !ok {
		return fail()
	}
	now, nowHashes, ok := rid06BoundAuditRows(b.Whole)
	if !ok || !reflect.DeepEqual(a.Whole.Bookkeeping["audit_outbox"].Columns, b.Whole.Bookkeeping["audit_outbox"].Columns) {
		return fail()
	}
	before := rid11AuthnSnapshot{Finished: a.Whole.PrimaryFinishedAt, Raw: map[string][]rid09PrimaryRow{"audit_outbox": old}}
	after := rid11AuthnSnapshot{Finished: b.Whole.PrimaryFinishedAt, Raw: map[string][]rid09PrimaryRow{"audit_outbox": now}}
	if !rid11AuditHistoryValid(before, after) {
		return fail()
	}
	out := rid06AuditReadProof{CaseID: caseID, RunID: runID, BeforeStartedAt: a.Whole.PrimaryStartedAt, BeforeFinishedAt: a.Whole.PrimaryFinishedAt, AfterStartedAt: b.Whole.PrimaryStartedAt, AfterFinishedAt: b.Whole.PrimaryFinishedAt, Columns: append([]string{}, a.Whole.Bookkeeping["audit_outbox"].Columns...), BeforeSQLRowSHA256: append([]string{}, a.Whole.Bookkeeping["audit_outbox"].Rows...), AfterSQLRowSHA256: append([]string{}, b.Whole.Bookkeeping["audit_outbox"].Rows...), Rows: []rid06AuditRowWitness{}}
	oldByID := map[string]rid09PrimaryRow{}
	for _, row := range old {
		oldByID[rid03S(row, "id")] = row
	}
	for _, row := range now {
		id := rid03S(row, "id")
		previous := oldByID[id]
		created, _ := rid03Cell[time.Time](row, "created_at")
		out.Rows = append(out.Rows, rid06AuditRowWitness{ID: id, CreatedAt: created, BeforeRowSHA256: oldHashes[id], AfterRowSHA256: nowHashes[id], BeforeImmutableSHA256: rid03EvidenceHash(rid11AuditImmutable(previous)), AfterImmutableSHA256: rid03EvidenceHash(rid11AuditImmutable(row)), Before: rid06TransportWitness(previous), After: rid06TransportWitness(row)})
	}
	sort.Slice(out.Rows, func(i, j int) bool { return out.Rows[i].ID < out.Rows[j].ID })
	return out, true
}
