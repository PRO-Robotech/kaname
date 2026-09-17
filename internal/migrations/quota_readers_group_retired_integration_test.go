// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// quota_readers_group_retired_integration_test.go — группа `module-quota-readers`
// СНЯТА миграцией вместе с членствами, кортежи членства выведены журналом, след
// оставлен; откат возвращает строку свода, повторный накат сходится (приёмка
// MRW-1, стадия S2б: MRW-16, MRW-24, MRW-17, MRW-25, MRW-18; задача kaname#106).
//
// # Четыре мира, и вакуумную реализацию ловит только первый
//
// На базе миграций дерева членств у группы НЕТ — их сняла `20260909202745`, а
// заводит заново только применитель по вступлениям доставленных манифестов.
// Значит «на каждое снятое членство журнал получил строку снятия» истинно при
// нуле снятых, и миграция, не пишущая в журнал вовсе, проходила бы мир без
// членств. Поэтому дом MRW-16 строится ПОСЕВОМ — применителем с синтетическими
// манифестами модулей платформы, — а близнец с нулём членств (MRW-24) стоит
// рядом, а не вместо: он отличает «снято ноль» от «журнал не пишется».
//
// # Уведомления ловятся СОЕДИНЕНИЕМ, а порог сессии возвращается перед миграцией
//
// Перепись прямого хода — `RAISE NOTICE`; свод объявляет `SET client_min_messages
// = warning` на всю сессию, и без возврата порога сервер гасил бы её раньше, чем
// она уйдёт клиенту. Приём воспроизведён у соседа
// (`account_scope_ceilings_stop_applying_integration_test.go`, `scopeLossChain`).
package migrations_test

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/servicemanifest"
)

const (
	// quotaReadersGroupVersion — версия снимающей миграции. Названа ЧИСЛОМ:
	// положение в каталоге ломается от следующей миграции.
	quotaReadersGroupVersion int64 = 20260916150000
	// Строка свода (`0001_initial.sql`) — идентификаторы системных строк,
	// одинаковые на каждой установке по построению.
	quotaReadersGroupID     = "grp1ed8897b56bb9106f"
	quotaReadersGroupName   = "module-quota-readers"
	quotaReadersSystemAcc   = "acc1a18042d81fb438d6"
	quotaReadersDescription = "Owner-service accounts allowed to read effective resource-count limits (issue #291)"
)

// retiredNoticeSink — приёмник уведомлений соединения.
type retiredNoticeSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *retiredNoticeSink) add(n *pgconn.Notice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, n.Severity+": "+n.Message)
}

func (s *retiredNoticeSink) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, "\n")
}

// retiredChain — пустая база, цепочка до версии `before`, соединение с
// приёмником уведомлений и возвратом порога перед каждой миграцией.
func retiredChain(t *testing.T, before int64) (*sql.DB, string, *retiredNoticeSink) {
	t.Helper()
	if testing.Short() {
		t.Skip("integration")
	}
	dsn := pgtest.NewEmptyDB(t)
	cfg, err := pgx.ParseConfig(dsn)
	require.NoError(t, err)
	sink := &retiredNoticeSink{}
	cfg.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) { sink.add(n) }
	db := stdlib.OpenDB(*cfg, stdlib.OptionResetSession(
		func(ctx context.Context, c *pgx.Conn) error {
			_, resetErr := c.Exec(ctx, "RESET client_min_messages")
			return resetErr
		}))
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	goose.SetLogger(goose.NopLogger())
	require.NoError(t, goose.UpTo(db, ".", before), "цепочка обязана дойти до названной версии — иначе дом не построен")
	return db, dsn, sink
}

func countRow(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(query, args...).Scan(&n))
	return n
}

func groupRows(t *testing.T, db *sql.DB) int {
	return countRow(t, db, `SELECT count(*) FROM kaname.groups WHERE id = $1`, quotaReadersGroupID)
}

func memberRows(t *testing.T, db *sql.DB) int {
	return countRow(t, db, `SELECT count(*) FROM kaname.group_members WHERE group_id = $1`, quotaReadersGroupID)
}

func deleteJournalRows(t *testing.T, db *sql.DB) int {
	return countRow(t, db, `SELECT count(*) FROM kaname.fga_outbox
		 WHERE event_type = 'fga.tuple.delete' AND payload ->> 'object' = $1`, "group:"+quotaReadersGroupID)
}

func journalRows(t *testing.T, db *sql.DB) int {
	return countRow(t, db, `SELECT count(*) FROM kaname.fga_outbox`)
}

func auditRows(t *testing.T, db *sql.DB) int {
	return countRow(t, db, `SELECT count(*) FROM kaname.audit_outbox
		 WHERE event_type = 'iam.group.deleted' AND event_payload ->> 'resource_id' = $1`, quotaReadersGroupID)
}

func allAuditRows(t *testing.T, db *sql.DB) int {
	return countRow(t, db, `SELECT count(*) FROM kaname.audit_outbox`)
}

// syntheticJoiner — доставленный манифест модуля платформы со вступлением в
// снимаемую группу (форма до S2а). Модули — из закрытого набора платформы
// без `iam`; аккаунт назван живым написанием `system`.
func syntheticJoiner(module, group string) string {
	return `
apiVersion: iam/v1
module: ` + module + `
resources: []
seed:
  serviceAccounts:
    - name: kacho-` + module + `
      account: system
      description: "Module SA: kacho-` + module + ` (probe of the group retirement)"
  joins:
    - serviceAccount: {account: system, name: kacho-` + module + `}
      group: {account: system, name: ` + group + `}
      why: "проба снятия группы читателей пределов"
`
}

var platformModulesWithoutIAM = []string{"vpc", "compute", "loadbalancer", "registry", "storage"}

func loadJoiners(t *testing.T, group string) []*manifest.Manifest {
	t.Helper()
	out := make([]*manifest.Manifest, 0, len(platformModulesWithoutIAM))
	for _, module := range platformModulesWithoutIAM {
		m, err := manifest.Load([]byte(syntheticJoiner(module, group)))
		require.NoErrorf(t, err, "синтетический манифест %s не разобран — дом не построен", module)
		out = append(out, m)
	}
	return out
}

func applyDelivered(ctx context.Context, t *testing.T, dsn string, own *manifest.Manifest, delivered []*manifest.Manifest) (moduleseed.Census, error) {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	census, err := moduleseed.NewApplier(kanamepg.NewModuleSeedWriteRepo(pool)).Apply(ctx, own, delivered)
	t.Logf("перепись применения: %s", census)
	return census, err
}

// TestMRW24_GroupWithoutMembersIsRetiredAndTheJournalGetsNothing — база
// миграций без доставки: группа есть, членств ноль; снимается группа, журнал
// не получает ничего, след — одна запись, перепись «членств 0 · группа 1».
func TestMRW24_GroupWithoutMembersIsRetiredAndTheJournalGetsNothing(t *testing.T) {
	db, _, sink := retiredChain(t, quotaReadersGroupVersion-1)

	require.Equal(t, 1, groupRows(t, db), "группы свода нет до прямого хода — дом не построен")
	require.Zero(t, memberRows(t, db), "у группы есть членства на базе без доставки — дом не тот")
	journalBefore, auditBefore := journalRows(t, db), allAuditRows(t, db)

	require.NoError(t, goose.Up(db, "."))

	require.Zero(t, groupRows(t, db), "группа пережила прямой ход")
	require.Equal(t, journalBefore, journalRows(t, db), "журнал прав получил строки — снимать кортежи было не с чего")
	require.Equal(t, auditBefore+1, allAuditRows(t, db))
	require.Equal(t, 1, auditRows(t, db), "записи аудита о снятии группы не ровно одна")
	var tenant, eventType string
	require.NoError(t, db.QueryRow(`SELECT coalesce(tenant_account_id, ''), event_type FROM kaname.audit_outbox
		 WHERE event_payload ->> 'resource_id' = $1`, quotaReadersGroupID).Scan(&tenant, &eventType))
	require.Equal(t, quotaReadersSystemAcc, tenant, "запись аудита не называет арендатора")
	require.Equal(t, "iam.group.deleted", eventType)
	require.Contains(t, sink.text(), "членств 0 · группа 1", "перепись не напечатана числами:\n%s", sink.text())
}

// TestMRW16_MembersFromTheApplierAreRetiredWithTheirTuplesAndATrace — дом
// построен ПОСЕВОМ: N членств от вступлений синтетических манифестов, строки
// записи ещё в очереди. Снимаются группа и членства; на каждое — строка снятия
// позже строки записи; прямого факта не осталось; след — одна запись на группу.
func TestMRW16_MembersFromTheApplierAreRetiredWithTheirTuplesAndATrace(t *testing.T) {
	ctx := context.Background()
	db, dsn, sink := retiredChain(t, quotaReadersGroupVersion-1)

	census, err := applyDelivered(ctx, t, dsn, nil, loadJoiners(t, quotaReadersGroupName))
	require.NoError(t, err, "применитель не построил дом")
	n := 0
	for _, r := range census.Reports {
		n += r.WrittenJoins
	}
	require.Equal(t, len(platformModulesWithoutIAM), n, "вступлений записано не по одному на манифест")
	require.Equal(t, n, memberRows(t, db))
	// Состояние очереди — факт дома: строки записи ещё в журнале.
	writesBefore := countRow(t, db, `SELECT count(*) FROM kaname.fga_outbox
		 WHERE event_type = 'fga.tuple.write' AND payload ->> 'object' = $1`, "group:"+quotaReadersGroupID)
	require.Equal(t, n, writesBefore, "строк записи кортежей членства в очереди не N")
	require.Equal(t, n, countRow(t, db, `SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type = 'group' AND object_id = $1 AND relation = 'member'`, quotaReadersGroupID),
		"прямых фактов членства не N — проекция не следовала журналу")

	require.NoError(t, goose.Up(db, "."))

	require.Zero(t, groupRows(t, db), "группа пережила прямой ход")
	require.Zero(t, memberRows(t, db), "членства пережили прямой ход")
	require.Equal(t, n, deleteJournalRows(t, db), "строк снятия кортежей членства не N")
	// Каждая строка снятия — той же формы, что штатное снятие члена, и ПОЗЖЕ
	// строки записи того же кортежа.
	require.Equal(t, n, countRow(t, db, `
		SELECT count(*) FROM kaname.fga_outbox d
		 WHERE d.event_type = 'fga.tuple.delete' AND d.payload ->> 'object' = $1
		   AND d.payload ->> 'relation' = 'member'
		   AND d.payload ->> 'user' LIKE 'service_account:%'
		   AND EXISTS (SELECT 1 FROM kaname.fga_outbox w
		                WHERE w.event_type = 'fga.tuple.write'
		                  AND w.payload = d.payload
		                  AND w.id < d.id AND w.created_at <= d.created_at)`, "group:"+quotaReadersGroupID),
		"строка снятия не стоит позже строки записи того же кортежа либо несёт другую форму")
	require.Zero(t, countRow(t, db, `SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type = 'group' AND object_id = $1`, quotaReadersGroupID),
		"прямой факт членства пережил снятие")
	require.Equal(t, 1, auditRows(t, db), "записей аудита о снятии группы не одна")
	require.Zero(t, countRow(t, db, `SELECT count(*) FROM kaname.audit_outbox
		 WHERE event_type LIKE 'iam.group.member%'`), "на членства написаны записи аудита — штатное снятие члена их не пишет")
	require.Contains(t, sink.text(), "членств 5 · группа 1", "перепись не напечатана числами:\n%s", sink.text())
}

// TestMRW17_GroupAbsentBeforeTheUpIsACensusNotARefusal — группы нет к моменту
// прямого хода: отказа нет, перепись «членств 0 · группа 0», журнал и аудит
// без строк.
func TestMRW17_GroupAbsentBeforeTheUpIsACensusNotARefusal(t *testing.T) {
	db, _, sink := retiredChain(t, quotaReadersGroupVersion-1)
	res, err := db.Exec(`DELETE FROM kaname.groups WHERE id = $1`, quotaReadersGroupID)
	require.NoError(t, err, "прямому удалению группы что-то помешало — дом не построен")
	affected, _ := res.RowsAffected()
	require.EqualValues(t, 1, affected)
	journalBefore, auditBefore := journalRows(t, db), allAuditRows(t, db)

	require.NoError(t, goose.Up(db, "."), "прямой ход на отсутствующей группе отказал")

	require.Contains(t, sink.text(), "членств 0 · группа 0", "отсутствие группы не названо словом:\n%s", sink.text())
	require.Equal(t, journalBefore, journalRows(t, db))
	require.Equal(t, auditBefore, allAuditRows(t, db), "аудит получил запись о снятии группы, которой не было")
}

// TestMRW25_DownRestoresTheSeedGroupAndTheReapplyConverges — откат до версии
// ниже своей возвращает строку свода дословно, без членств, без строк журнала и
// аудита; повторный накат снимает снова, и записей аудита становится две.
func TestMRW25_DownRestoresTheSeedGroupAndTheReapplyConverges(t *testing.T) {
	db, _, sink := retiredChain(t, quotaReadersGroupVersion-1)
	require.NoError(t, goose.Up(db, "."))
	require.Zero(t, groupRows(t, db))
	journalAfterUp, auditAfterUp := journalRows(t, db), allAuditRows(t, db)
	require.Equal(t, 1, auditRows(t, db))

	steps := 0
	for {
		v, verr := goose.GetDBVersion(db)
		require.NoError(t, verr)
		if v < quotaReadersGroupVersion {
			break
		}
		require.NoError(t, goose.Down(db, "."), "откат обязан проходить")
		steps++
	}
	require.Positive(t, steps, "откат не сделал ни шага — утверждения ниже беспредметны")
	t.Logf("откат: миграций снято %d (до версии ниже %d)", steps, quotaReadersGroupVersion)

	var accountName, description string
	require.NoError(t, db.QueryRow(`SELECT a.name, g.description FROM kaname.groups g
		 JOIN kaname.accounts a ON a.id = g.account_id WHERE g.id = $1`, quotaReadersGroupID).
		Scan(&accountName, &description), "откат не вернул строку группы свода")
	require.Equal(t, "system", accountName)
	require.Equal(t, quotaReadersDescription, description, "назначение возвращённой строки не дословно")
	require.Zero(t, memberRows(t, db), "откат вернул членства — они принадлежат доставке")
	require.Equal(t, journalAfterUp, journalRows(t, db), "откат написал в журнал прав")
	require.Equal(t, auditAfterUp, allAuditRows(t, db), "откат написал в аудит")

	require.NoError(t, goose.Up(db, "."), "повторный накат обязан сходиться")
	require.Zero(t, groupRows(t, db), "повторный накат не снял возвращённую откатом группу")
	require.Equal(t, 2, auditRows(t, db), "записей аудита о снятии группы не две — по одной на каждый прямой ход")
	require.Contains(t, sink.text(), "членств 0 · группа 1")
}

// TestMRW18_DeliveryStillJoiningTheRetiredGroupGetsANamedRefusal — после S2б
// доставка со вступлением в снятую группу получает отказ, называющий пару и
// модуль; та же доставка со вступлением в группу службы применяется.
func TestMRW18_DeliveryStillJoiningTheRetiredGroupGetsANamedRefusal(t *testing.T) {
	ctx := context.Background()
	own, err := servicemanifest.Load()
	require.NoError(t, err)

	t.Run("вступление в снятую группу — названный отказ", func(t *testing.T) {
		_, dsn, _ := retiredChain(t, quotaReadersGroupVersion)
		_, aerr := applyDelivered(ctx, t, dsn, own, loadJoiners(t, quotaReadersGroupName)[:1])
		require.Error(t, aerr, "применитель принял вступление в снятую группу")
		require.Contains(t, aerr.Error(), "system/"+quotaReadersGroupName, "отказ не называет пару (аккаунт, имя)")
		require.Contains(t, aerr.Error(), `"vpc"`, "отказ не называет модуль, чей манифест назвал группу")
		t.Logf("отказ: %v", aerr)
	})
	t.Run("вступление в группу службы — применяется", func(t *testing.T) {
		_, dsn, _ := retiredChain(t, quotaReadersGroupVersion)
		census, aerr := applyDelivered(ctx, t, dsn, own, loadJoiners(t, "module-relation-writers"))
		require.NoError(t, aerr)
		require.Equal(t, len(platformModulesWithoutIAM), census.Seeding)
	})
}
