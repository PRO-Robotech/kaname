// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package listvisibility_test holds the RED-phase probes for
// docs/specs/sub-phase-IAM-645-list-page-is-a-page-of-the-visible-acceptance.md
// (task PRO-Robotech/kacho#645).
//
// # What these probes are about
//
// A list page is a page of what the caller may SEE, not a window over the whole
// table from which the visible is then subtracted. Today every iam list reads a
// page from its own database by cursor and filters it afterwards, so an object
// with more than `page_size` invisible predecessors never reaches the filter at
// all: the caller gets `200` with an empty array while a Get on that same object
// by id answers `200`.
//
// # Почему настоящий Postgres, и почему источник вердикта тоже настоящий
//
// Дефект — это ПОРЯДОК операций между страницей базы и фильтром прав, поэтому ни
// одна из сторон не вправе быть снисходительным дублёром:
//
//   - подставной репозиторий, игнорирующий `PageSize` (тот, которым пользуются
//     обычные юниты пакета), прячет дефект BY CONSTRUCTION — он отдаёт фильтру всю
//     совокупность, то есть ровно то состояние, до которого продукт не доходит;
//   - подставной источник вердикта, отвечающий по списку разрешённых, не прошёл бы
//     ни батчевым путём вопроса, ни разбиением страницы на партии, ни структурными
//     выводами модели (`owner`, `super_admin`, членство в группе), — а приёмка
//     называет их всех путями видимости, которые сужение обязано знать.
//
// Поэтому: `iampgtest.NewTestPostgres` (контейнер, промигрирован) плюс ТА ЖЕ дверь
// решения, которую композиционный корень провязывает стражам в проде —
// `authzcascade.Wrap(relverdict.NewAsker(pool))` поверх той же базы.
//
// Здесь стоял поднятый контейнером внешний движок отношений. Он снят целиком (S6):
// вердикт считает форма поверх собственных таблиц iam, и вопрос о доступе теперь
// читает ТЕ ЖЕ строки, которые пишет фикстура, — выдачу, членство, прямой факт.
// Следствие для фикстуры названо там, где она их пишет: пообъектного глагольного
// кортежа своя база не производит вовсе, право приходит ВЫДАЧЕЙ.
//
// # Creation time is an INPUT of these probes, not an accident
//
// The cursor is `(created_at, id) ASC`, and "the threshold" is defined as "more
// than `page_size` objects the caller cannot see lie BEFORE his own by creation
// time". Rows inserted in one test share a timestamp to the microsecond and the
// tie is then broken by a crockford-random id — that is, by chance. Every seed
// helper here therefore SETS `created_at` explicitly, one second apart, in the
// order the scenario needs. Without it the probes would be measuring the
// generator, not the product.
package listvisibility_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// probePageSize — the page size every threshold probe asks for. It is the
// product's own default (`pkg/validate` DefaultPageSize), which is what the live
// stand was running when the defect was observed.
const probePageSize int32 = 50

// env bundles one test's live Postgres, the live decision door over it and the
// identities every scenario shares.
type env struct {
	pool  *pgxpool.Pool
	repo  *kanamepg.Repository
	gates *authzcascade.Client

	// probeRoles — memo of the system roles this test seeded, keyed by
	// «тип объекта + глагол». Одна роль на пару, а не на выдачу: роль здесь —
	// НОСИТЕЛЬ глагола, и заводить её заново на каждую выдачу значило бы
	// множить строки, за которыми проба не следит.
	probeRoles map[string]string

	// base + seq produce the strictly increasing creation timestamps the cursor
	// orders by. base is placed in the FUTURE so that rows seeded by migrations
	// (the system role catalog) sort ahead of everything a probe creates, which
	// keeps their position in the sequence stated rather than assumed.
	base time.Time
	seq  int

	// callerUser is the principal under test; callerAcc is the account it owns.
	callerUser domain.UserID
	callerAcc  domain.AccountID
	// foreignUser owns foreignAcc — everything the caller must NOT see lives there.
	foreignUser domain.UserID
	foreignAcc  domain.AccountID
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()

	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ, а не `t.Cleanup(pool.Close)`: отложенное закрытие ждёт
	// соединение, которое проба, упавшая внутри открытой транзакции, не вернёт
	// никогда, — и уносит с собой вердикт всего пакета. Здесь это не гипотетика:
	// каждый сценарий берёт reader-TX и половина из них намеренно роняет запрос.
	pgtest.ClosePoolAtEnd(t, pool)

	e := &env{
		pool:       pool,
		repo:       kanamepg.New(pool, nil),
		gates:      authzcascade.Wrap(relverdict.NewAsker(pool)),
		probeRoles: map[string]string{},
		base:       time.Now().UTC().Truncate(time.Second).Add(time.Hour),
	}
	t.Cleanup(e.repo.Close)

	e.callerUser, e.callerAcc = e.seedUserWithAccount(t, "caller")
	e.foreignUser, e.foreignAcc = e.seedUserWithAccount(t, "foreign")
	return e
}

// at returns the next creation timestamp in the sequence. Every seeded row takes
// one, so "created before" is a property the test states, not one it hopes for.
func (e *env) at() time.Time {
	e.seq++
	return e.base.Add(time.Duration(e.seq) * time.Second)
}

func (e *env) ctxAs(id string, typ string) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: typ, ID: id})
}

func (e *env) ctxUser(id domain.UserID) context.Context {
	return e.ctxAs(string(id), "user")
}

// ctxAnonymous mirrors what api-gateway injects for an unauthenticated (or
// un-forwarded) caller.
func (e *env) ctxAnonymous() context.Context {
	return e.ctxAs("anonymous", "system")
}

// ── seeding ──────────────────────────────────────────────────────────────────
//
// All seeding is raw SQL on purpose. The writer path emits outbox rows and audit
// entries that these probes do not exercise, and — decisively — it does not let
// the caller choose `created_at`, which is the very axis under test.

func (e *env) seedUserWithAccount(t *testing.T, suffix string) (domain.UserID, domain.AccountID) {
	t.Helper()
	ctx := context.Background()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))
	uAt, aAt := e.at(), e.at()

	tx, err := e.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status, created_at)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE', $6)`,
		string(uid), string(accID), "ext-"+suffix+"-"+string(uid),
		"u-"+suffix+"-"+lastSix(string(uid))+"@example.com", "User "+suffix, uAt)
	require.NoError(t, err, "seed user %s", suffix)
	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels, created_at)
		VALUES ($1, $2, $3, '{}'::jsonb, $4)`,
		string(accID), "acc-"+suffix+"-"+lastSix(string(accID)), string(uid), aAt)
	require.NoError(t, err, "seed account for %s", suffix)
	require.NoError(t, tx.Commit(ctx))
	return uid, accID
}

func (e *env) seedProject(t *testing.T, acc domain.AccountID, name string) string {
	t.Helper()
	id := ids.NewID(domain.PrefixProject)
	_, err := e.pool.Exec(context.Background(), `
		INSERT INTO projects (id, account_id, name, labels, created_at)
		VALUES ($1, $2, $3, '{}'::jsonb, $4)`,
		id, string(acc), name, e.at())
	require.NoError(t, err, "seed project %s", name)
	return id
}

// seedProjectAt is seedProject with the creation time chosen by the caller —
// used where a probe has to place a row INSIDE an existing sequence rather than
// after it.
func (e *env) seedProjectAt(t *testing.T, acc domain.AccountID, name string, at time.Time) string {
	t.Helper()
	id := ids.NewID(domain.PrefixProject)
	_, err := e.pool.Exec(context.Background(), `
		INSERT INTO projects (id, account_id, name, labels, created_at)
		VALUES ($1, $2, $3, '{}'::jsonb, $4)`,
		id, string(acc), name, at)
	require.NoError(t, err, "seed project %s", name)
	return id
}

// timestampOf reads a row's creation time back from the database, so a probe
// that needs to sit between two rows measures where they are instead of assuming.
func (e *env) timestampOf(t *testing.T, table, id string) time.Time {
	t.Helper()
	var at time.Time
	err := e.pool.QueryRow(context.Background(),
		`SELECT created_at FROM `+table+` WHERE id = $1`, id).Scan(&at)
	require.NoError(t, err, "read created_at of %s.%s", table, id)
	return at
}

func (e *env) seedUser(t *testing.T, acc domain.AccountID, suffix string) string {
	t.Helper()
	id := ids.NewID(domain.PrefixUser)
	_, err := e.pool.Exec(context.Background(), `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status, created_at)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE', $6)`,
		id, string(acc), "ext-"+suffix+"-"+id,
		"u-"+suffix+"-"+lastSix(id)+"@example.com", "User "+suffix, e.at())
	require.NoError(t, err, "seed user %s", suffix)
	return id
}

func (e *env) seedGroup(t *testing.T, acc domain.AccountID, name string) string {
	t.Helper()
	id := ids.NewID(domain.PrefixGroup)
	_, err := e.pool.Exec(context.Background(), `
		INSERT INTO groups (id, account_id, name, labels, created_at)
		VALUES ($1, $2, $3, '{}'::jsonb, $4)`,
		id, string(acc), name, e.at())
	require.NoError(t, err, "seed group %s", name)
	return id
}

func (e *env) seedServiceAccount(t *testing.T, acc domain.AccountID, name string) string {
	t.Helper()
	id := ids.NewID(domain.PrefixServiceAccount)
	_, err := e.pool.Exec(context.Background(), `
		INSERT INTO service_accounts (id, account_id, name, enabled, created_at)
		VALUES ($1, $2, $3, true, $4)`,
		id, string(acc), name, e.at())
	require.NoError(t, err, "seed service account %s", name)
	return id
}

// before returns a timestamp strictly EARLIER than anything the migrations
// seeded, so a probe can place rows AHEAD of the system-role catalog. The
// catalog is written when the migrations run, i.e. "now"; base is an hour ahead
// of that, so a year back is unambiguously before it.
func (e *env) before(i int) time.Time {
	return e.base.Add(-365 * 24 * time.Hour).Add(time.Duration(i) * time.Second)
}

func (e *env) seedCustomRole(t *testing.T, acc domain.AccountID, name string) string {
	t.Helper()
	return e.seedCustomRoleAt(t, acc, name, e.at())
}

func (e *env) seedCustomRoleAt(t *testing.T, acc domain.AccountID, name string, at time.Time) string {
	t.Helper()
	id := ids.NewID(domain.PrefixRole)
	// `is_system` is GENERATED (it follows cluster_id), so it is deliberately
	// absent from the column list: an account-scoped role IS a custom role.
	_, err := e.pool.Exec(context.Background(), `
		INSERT INTO roles (id, account_id, name, permissions, created_at)
		VALUES ($1, $2, $3, '["iam.project.*.get"]'::jsonb, $4)`,
		id, string(acc), name, at)
	require.NoError(t, err, "seed custom role %s", name)
	return id
}

// seedAccount creates an account owned by `owner`. Used for the `account`
// surface, where the objects being listed ARE accounts.
func (e *env) seedAccount(t *testing.T, owner domain.UserID, suffix string) string {
	t.Helper()
	id := ids.NewID(domain.PrefixAccount)
	_, err := e.pool.Exec(context.Background(), `
		INSERT INTO accounts (id, name, owner_user_id, labels, created_at)
		VALUES ($1, $2, $3, '{}'::jsonb, $4)`,
		id, "acc-"+suffix+"-"+lastSix(id), string(owner), e.at())
	require.NoError(t, err, "seed account %s", suffix)
	return id
}

// seedAccessBinding writes a grant row. The subject and role must already exist
// — a BEFORE INSERT trigger probes both (migration 0049), so a fixture that
// invented them would be refused, which is the fixture staying no more lenient
// than the product.
func (e *env) seedAccessBinding(t *testing.T, subject domain.UserID, roleID, resourceType, resourceID string) string {
	t.Helper()
	return e.seedAccessBindingFor(t, "user", string(subject), roleID, resourceType, resourceID)
}

// seedAccessBindingFor is seedAccessBinding for ANY subject kind the schema
// admits ('user' / 'service_account' / 'group').
//
// # A grant exists in TWO places, and a fixture writing one of them is blind
//
// In production a grant is a ROW in iam's own database, and the relation tuple
// is its MATERIALIZATION — the row is the authority, the tuple is the copy the
// model answers from. A probe that writes only the tuple therefore describes a
// state the product never reaches, and it does so in the one direction that
// matters here: the candidate selection of a narrowed page reads the ROWS
// (internal/repo/kaname/visibility), so a grant with no row names no candidate,
// and the probe reports "invisible" for a caller whose grant is live.
//
// That is not the probe's subject. 645-06/07/07b are about the PATHS by which an
// object becomes visible; each of them needs its path to exist on both sides, or
// it is measuring the fixture. Hence this helper, and hence seedGroupMember
// below — the membership leg of path П2 lives in `group_members` and nowhere
// else.
func (e *env) seedAccessBindingFor(t *testing.T, subjectType, subjectID, roleID, resourceType, resourceID string) string {
	t.Helper()
	ctx := context.Background()
	id := ids.NewID(domain.PrefixAccessBinding)
	at := e.at()
	tx, err := e.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO access_bindings
			(id, subject_type, subject_id, role_id, resource_type, resource_id, status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE', $7)`,
		id, subjectType, subjectID, roleID, resourceType, resourceID, at)
	require.NoError(t, err, "seed access binding for %s:%s on %s:%s",
		subjectType, subjectID, resourceType, resourceID)
	_, err = tx.Exec(ctx, `
		INSERT INTO access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
		VALUES ($1, $2, $3, 0)`, id, subjectType, subjectID)
	require.NoError(t, err, "seed access binding subject")
	require.NoError(t, tx.Commit(ctx))
	return id
}

// seedGroupMember writes the membership leg of path П2. `member_type` is
// constrained to 'user' / 'service_account' by the schema, and a BEFORE INSERT
// trigger probes the member's existence — again, no more lenient than the
// product.
func (e *env) seedGroupMember(t *testing.T, groupID, memberType, memberID string) {
	t.Helper()
	_, err := e.pool.Exec(context.Background(), `
		INSERT INTO group_members (group_id, member_type, member_id, added_at)
		VALUES ($1, $2, $3, $4)`, groupID, memberType, memberID, e.at())
	require.NoError(t, err, "seed group member %s:%s in %s", memberType, memberID, groupID)
}

// systemRoleIDs — the catalog rows the migrations seed. They are the `role`
// surface's code floor (`is_system` bypasses the filter entirely), so a probe on
// that surface must expect them in the answer rather than be surprised by them.
func (e *env) systemRoleIDs(t *testing.T) []string {
	t.Helper()
	rows, err := e.pool.Query(context.Background(),
		`SELECT id FROM roles WHERE is_system ORDER BY created_at, id`)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(t, rows.Err())
	return out
}

// anySystemRoleID returns one seeded system role — the role a grant fixture can
// point at without inventing one.
func (e *env) anySystemRoleID(t *testing.T) string {
	t.Helper()
	ids := e.systemRoleIDs(t)
	require.NotEmpty(t, ids, "migrations must seed a system role catalog; without it the grant fixtures have no role to reference")
	return ids[0]
}

func lastSix(s string) string {
	if len(s) <= 6 {
		return s
	}
	return s[len(s)-6:]
}

func projectName(i int) string    { return fmt.Sprintf("prj-seed-%04d", i) }
func groupName(i int) string      { return fmt.Sprintf("grp-seed-%04d", i) }
func svcAccountName(i int) string { return fmt.Sprintf("sva-seed-%04d", i) }

// roleName obeys the custom-role name grammar (`^[a-z][a-z0-9_]{0,40}$`), which
// is NOT the grammar of the other names — a dash is refused there.
func roleName(i int) string { return fmt.Sprintf("rol_seed_%04d", i) }

// ── право и структурный факт: два разных посева, и путать их нельзя ──────────

// grantVerb выдаёт субъекту ГЛАГОЛ на область — тем же, чем это выражено в
// продукте: ролью, проецирующей глагол, и привязкой этой роли на область.
//
// ПОЧЕМУ НЕ ПРЯМАЯ ГЛАГОЛЬНАЯ СТРОКА. Своя база её не производит вовсе: проекция
// журнала глаголы намеренно не переносит (миграция 0098) — их ВЫВОДИТ форма из
// выдачи. Фикстура, писавшая такую строку, описывала бы состояние, до которого
// продукт не доходит, и сужение страницы, читающее ВЫДАЧИ при отборе кандидатов,
// не нашло бы по ней ни одного кандидата: право было бы «видно» вопросу о доступе
// и невидимо отбору. Ровно этот разрыв фикстура здесь и обязана не заводить.
//
// Область — САМ ОБЪЕКТ, а не его предок: пробы этого пакета говорят про ОДИН
// видимый объект среди многих невидимых, и выдача на предка сделала бы видимыми
// всех соседей разом.
func (e *env) grantVerb(t *testing.T, subjectType, subjectID, objectType, objectID, verb string) string {
	t.Helper()
	return e.seedAccessBindingFor(t, subjectType, subjectID,
		e.probeRole(t, objectType, verb), objectType, objectID)
}

// probeRole заводит (и запоминает) СИСТЕМНУЮ роль, проецирующую один глагол на
// один тип.
//
// Системную, а не арендную, и это не удобство: страж назначаемости продукта
// (миграция 0072) отвергает роль одного аккаунта в области другого, а пробы
// `account`-поверхности намеренно выдают право на ЧУЖОЙ аккаунт — там видимость
// обязана приходить от выдачи, а не от владения. Системная роль назначаема где
// угодно, поэтому одна форма посева обслуживает все семь поверхностей; выбирать
// её по поверхности значило бы завести семь разных фикстур на один предмет.
//
// Имя типа берётся ТЕМ ЖЕ переводчиком, каким его читает вопрос о доступе
// (`authzmap.CatalogTypeName`): проекция хранится в точечной форме каталога, и
// строка, написанная именем модели, не была бы найдена — а «не найдено» здесь
// неотличимо от «права нет».
func (e *env) probeRole(t *testing.T, objectType, verb string) string {
	t.Helper()
	key := objectType + "/" + verb
	if id, ok := e.probeRoles[key]; ok {
		return id
	}
	ctx := context.Background()
	id := ids.NewID(domain.PrefixRole)
	name := fmt.Sprintf("probe-%d", len(e.probeRoles)+1)
	catalog := authzmap.CatalogTypeName(objectType)

	// `is_system` — вычисляемая колонка (следует за cluster_id), поэтому не
	// задаётся. Пустые `permissions` законны только при непустых `rules`.
	_, err := e.pool.Exec(ctx, `
		INSERT INTO roles (id, cluster_id, name, permissions, rules)
		VALUES ($1, $2, $3, '[]'::jsonb,
		        jsonb_build_array(jsonb_build_object(
		            'module',    'probe',
		            'resources', jsonb_build_array('*'),
		            'verbs',     jsonb_build_array($4::text))))`,
		id, domain.ClusterSingletonID, name, verb)
	require.NoErrorf(t, err, "seed probe role %s (%s/%s)", name, objectType, verb)

	_, err = e.pool.Exec(ctx,
		`INSERT INTO role_verb (role_id, object_type, verb) VALUES ($1, $2, $3)`,
		id, catalog, verb)
	require.NoError(t, err, "seed role_verb")

	// Без селектора роль не адресует ни одного объекта — и это верно, а не
	// пробел фикстуры. Ветвь ЯКОРНАЯ: она разрешает тип в области независимо от
	// меток, а метки в предмете этих проб не участвуют.
	_, err = e.pool.Exec(ctx, `
		INSERT INTO role_rule_selectors (role_id, rule_fp, arm, object_types, match_labels)
		VALUES ($1, 'fp-probe', 'anchor', ARRAY[$2::text], '{}'::jsonb)`, id, catalog)
	require.NoError(t, err, "seed role_rule_selectors")

	e.probeRoles[key] = id
	return id
}

// factThroughJournal кладёт СТРУКТУРНОЕ отношение (`account`, `cluster`,
// `system_admin`, `member`, `subject`) через журнал — тем же путём, каким его
// кладёт продукт, — и утверждает, что триггер его спроецировал.
//
// Утверждение о проекции несущее: без него «право не сработало» было бы
// неотличимо от «фикстура ничего не посеяла». Глагольное отношение сюда не
// проходит by construction (проекция глаголы не переносит), и это защита от
// того, чтобы посеять право не тем способом.
func (e *env) factThroughJournal(t *testing.T, objectType, objectID, relation, subject string) {
	t.Helper()
	ctx := context.Background()
	_, err := e.pool.Exec(ctx, `
		INSERT INTO fga_outbox (event_type, payload, created_at)
		VALUES ('fga.tuple.write',
		        jsonb_build_object('user', $1::text, 'relation', $2::text,
		                           'object', $3::text || ':' || $4::text),
		        now())`, subject, relation, objectType, objectID)
	require.NoErrorf(t, err, "журнал %s:%s --%s--> %s", objectType, objectID, relation, subject)

	var landed int
	require.NoError(t, e.pool.QueryRow(ctx, `
		SELECT count(*)::int FROM relation_fact
		 WHERE object_type = $1 AND object_id = $2 AND relation = $3 AND subject = $4`,
		objectType, objectID, relation, subject).Scan(&landed))
	require.Equalf(t, 1, landed,
		"строка журнала %s:%s --%s--> %s не спроецировалась в прямой факт — фикстура ничего "+
			"не посеяла, и проба судила бы пустое состояние", objectType, objectID, relation, subject)
}
