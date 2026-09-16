// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package project_test

// delete_nonempty_integration_test.go — непустой проект не удаляется: пробы
// УРОВНЯ ПРИКЛАДНИКА (дом П приёмки `non-empty-project-is-not-deleted.md`,
// §0.2в) — настоящий `DeleteProjectUseCase.Execute` на мигрированной базе,
// чтение операции из хранилища операций, строки базы.
//
// # Что дом П видит, а чего нет — и почему это важно для утверждений
//
// Он видит `Operation.done`, её `error` С ДЕТАЛЯМИ (их ставит `shared.MapRepoErr`
// внутри `shared.DoWithWriteTx`, то есть прикладник) и строки базы. Он НЕ видит
// HTTP-статуса и всего, что производит край, — эти утверждения живут в кейсах
// набора (дом К), и здесь их нет намеренно.
//
// # Как строится «Дано»
//
// Строки зеркала кладутся напрямую: регистрация ресурса — внутренний глагол
// владельца (`:9091`), и по контракту ни один публичный путь такой строки не
// заводит. Роль — ПРОИЗВОДСТВЕННЫМ писателем (`RolesW().Insert`), потому что у
// неё есть свои ограничения схемы, и подделка была бы снисходительнее продукта.
// Синтетические виды каталога заводит сама проба: у посеянного `vpc.network`
// три состояния каталога из пяти схема не строит (`role_rule_ref_verb_fk`,
// приёмка §0.2в, Н8).
//
// # Имена проб
//
// `TestProjectDelete_PNE_<стадия>_<номер>[A|B|V]` — предикат готовности приёмки
// сверяет `--- PASS` ПО ID, а не числом строк (§10).

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
)

// reasonReferenceInUse — машинный признак полосы «на ресурс ещё ссылаются»
// (`internal/apps/kaname/shared/reference_refusal.go`). Приёмка §2.5: второго
// признака у отказа по непустоте не заводится.
const reasonReferenceInUse = "REFERENCE_IN_USE"

// pneEnv — база на пробу, репозиторий и хранилище операций.
type pneEnv struct {
	pool    *pgxpool.Pool
	repo    *kanamepg.Repository
	opsRepo operations.Repo
}

func newPNEEnv(t *testing.T) *pneEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return &pneEnv{
		pool:    pool,
		repo:    kanamepg.New(pool, nil),
		opsRepo: operations.NewRepo(pool, "kaname"),
	}
}

// withPrincipal — контекст аутентифицированного вызывающего: прикладник
// отвергает анонима первым оператором, до чтения проекта.
func withPrincipal(uid domain.UserID) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: string(uid), DisplayName: string(uid)})
}

// seedUserAccountProject кладёт человека, его аккаунт и проект в аккаунте.
func seedUserAccountProject(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) (domain.UserID, domain.AccountID, domain.ProjectID) {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))
	prjID := domain.ProjectID(ids.NewID(domain.PrefixProject))

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		string(uid), string(accID), "ext-"+suffix+"-"+string(uid), "u-"+suffix+"@example.com", "PNE "+suffix)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID), "pne-acc-"+suffix+"-"+string(accID[len(accID)-6:]), string(uid))
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.projects (id, account_id, name, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(prjID), string(accID), "pne-prj-"+suffix)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return uid, accID, prjID
}

// seedExtraProject — второй проект того же аккаунта.
func seedExtraProject(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID domain.AccountID, suffix string) domain.ProjectID {
	t.Helper()
	prjID := domain.ProjectID(ids.NewID(domain.PrefixProject))
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.projects (id, account_id, name, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(prjID), string(accID), "pne-prj-"+suffix)
	require.NoError(t, err)
	return prjID
}

// insertMirrorRow кладёт строку зеркала ПРЯМОЙ ВСТАВКОЙ — так, как её оставляет
// приём регистрации владельца. Возвращает идентификатор объекта.
func insertMirrorRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objectType string, parent domain.ProjectID) string {
	t.Helper()
	objectID := "obj-" + ids.NewID("pne")
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.resource_mirror
		     (object_type, object_id, parent_project_id, parent_account_id, labels)
		 VALUES ($1, $2, $3, '', '{}'::jsonb)`,
		objectType, objectID, string(parent))
	require.NoError(t, err, "строка зеркала %s", objectType)
	return objectID
}

// seedProjectRole кладёт ПРОЕКТНУЮ роль производственным писателем.
func seedProjectRole(t *testing.T, ctx context.Context, repo *kanamepg.Repository, prjID domain.ProjectID, name string) domain.RoleID {
	t.Helper()
	r := domain.Role{
		ID:          domain.RoleID(ids.NewID(domain.PrefixRole)),
		ProjectID:   prjID,
		Name:        domain.RoleName(name),
		Description: domain.Description("project-scoped child of the project under test"),
		Permissions: domain.Permissions{"iam.project.*.get"},
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	inserted, err := w.RolesW().Insert(ctx, r)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return inserted.ID
}

// seedCatalogKind заводит СИНТЕТИЧЕСКИЙ вид: модуль, ресурс и живые глаголы
// `get` и `delete`. Возвращает точечное имя.
func seedCatalogKind(t *testing.T, ctx context.Context, pool *pgxpool.Pool, module, resource string) string {
	t.Helper()
	dotted := module + "." + resource
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx,
		`INSERT INTO kaname.catalog_module (module, live) VALUES ($1, true)
		 ON CONFLICT DO NOTHING`, module)
	require.NoError(t, err, "модуль каталога %s", module)
	_, err = tx.Exec(ctx,
		`INSERT INTO kaname.catalog_resource (module, resource, dotted, live, object_type)
		 VALUES ($1, $2, $3, true, $4)`,
		module, resource, dotted, module+"_"+strings.ToLower(resource))
	require.NoError(t, err, "ресурс каталога %s", dotted)
	for _, verb := range []string{"get", "delete"} {
		_, err = tx.Exec(ctx,
			`INSERT INTO kaname.catalog_verb (module, resource, verb, live, per_object)
			 VALUES ($1, $2, $3, true, true)`, module, resource, verb)
		require.NoError(t, err, "глагол %s.%s", dotted, verb)
	}
	require.NoError(t, tx.Commit(ctx))
	return dotted
}

// retireCatalogVerb снимает глагол ПАРОЙ `live = false, retired_at = now()` —
// той же формой, что писатель `RetireVerb`; одно `live = false` схема отвергает.
func retireCatalogVerb(t *testing.T, ctx context.Context, pool *pgxpool.Pool, module, resource, verb string) int64 {
	t.Helper()
	tag, err := pool.Exec(ctx,
		`UPDATE kaname.catalog_verb SET live = false, retired_at = now()
		  WHERE module = $1 AND resource = $2 AND verb = $3 AND live`,
		module, resource, verb)
	require.NoError(t, err)
	return tag.RowsAffected()
}

// retireCatalogResource снимает ресурс той же парой; successor — точечное имя
// живого преемника либо пустая строка.
func retireCatalogResource(t *testing.T, ctx context.Context, pool *pgxpool.Pool, module, resource, successor string) int64 {
	t.Helper()
	tag, err := pool.Exec(ctx,
		`UPDATE kaname.catalog_resource
		    SET live = false, retired_at = now(), superseded_by = NULLIF($3, '')
		  WHERE module = $1 AND resource = $2 AND live`,
		module, resource, successor)
	require.NoError(t, err)
	return tag.RowsAffected()
}

// runDelete исполняет настоящий прикладник, дожидается воркера и возвращает
// операцию из хранилища.
func runDelete(t *testing.T, env *pneEnv, uid domain.UserID, prjID domain.ProjectID) *operations.Operation {
	t.Helper()
	uc := project.NewDeleteProjectUseCase(env.repo, env.opsRepo)
	op, err := uc.Execute(withPrincipal(uid), prjID)
	require.NoError(t, err, "синхронной ошибки быть не должно: форма и существование уже проверены")
	require.NoError(t, operations.Wait(context.Background()))
	got, err := env.opsRepo.Get(context.Background(), op.ID)
	require.NoError(t, err)
	require.True(t, got.Done, "операция обязана завершиться")
	return got
}

// refusalMessage возвращает текст отказа операции и утверждает пару «код +
// признак»: `FAILED_PRECONDITION` и `ErrorInfo{reason: REFERENCE_IN_USE}` с
// доменом службы.
func refusalMessage(t *testing.T, op *operations.Operation) string {
	t.Helper()
	require.NotNil(t, op.Error, "удаление непустого проекта обязано отвергаться в операции")
	st := grpcstatus.FromProto(op.Error)
	require.Equal(t, codes.FailedPrecondition, st.Code(), "код отказа: %s", st.Message())
	var info *errdetails.ErrorInfo
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			info = ei
		}
	}
	require.NotNil(t, info, "отказ обязан нести ErrorInfo — иначе клиент не отличит полосу")
	require.Equal(t, reasonReferenceInUse, info.GetReason())
	require.Equal(t, refusaldomain.For(refusaldomain.ServiceIAM), info.GetDomain())
	return st.Message()
}

func projectRowExists(t *testing.T, ctx context.Context, pool *pgxpool.Pool, prjID domain.ProjectID) bool {
	t.Helper()
	var exists bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM kaname.projects WHERE id = $1)`, string(prjID)).Scan(&exists))
	return exists
}

func countRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, query, args...).Scan(&n))
	return n
}

// unregisterMirrorRow снимает строку зеркала ТЕМ ЖЕ оператором, которым её
// снимает внутренний глагол владельца `UnregisterResource`
// (`resource_mirror.DeleteTx`). Владельца дом П не зовёт (приёмка §0.2в, Н3).
func unregisterMirrorRow(ctx context.Context, pool *pgxpool.Pool, objectType, objectID string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := resource_mirror.DeleteTx(ctx, tx, objectType, objectID, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ── IAM-PNE-1-02 — объект чужого домена держит проект ───────────────────────

func TestProjectDelete_PNE_1_02(t *testing.T) {
	env := newPNEEnv(t)
	ctx := context.Background()
	uid, _, prj := seedUserAccountProject(t, ctx, env.pool, "1-02")
	insertMirrorRow(t, ctx, env.pool, "vpc.network", prj)

	op := runDelete(t, env, uid, prj)
	msg := refusalMessage(t, op)
	require.Equal(t, fmt.Sprintf("Project %s is not empty (vpc.network: 1)", prj), msg)
	require.True(t, projectRowExists(t, ctx, env.pool, prj),
		"отказ, после которого ресурс всё равно исчез, — потерянная строка, а не запрет")
}

// ── IAM-PNE-1-03 — перечень называет ВСЕ виды, а не первый встреченный ─────

func TestProjectDelete_PNE_1_03(t *testing.T) {
	env := newPNEEnv(t)
	ctx := context.Background()
	uid, _, prj := seedUserAccountProject(t, ctx, env.pool, "1-03")
	// Посев в порядке «Дано» — то есть НЕ по имени; числа по имени (1, 3, 2)
	// не монотонны: мутанты «порядок вставки» и «по числу» дают другой текст.
	insertMirrorRow(t, ctx, env.pool, "vpc.network", prj)
	insertMirrorRow(t, ctx, env.pool, "vpc.network", prj)
	insertMirrorRow(t, ctx, env.pool, "compute.instance", prj)
	insertMirrorRow(t, ctx, env.pool, "storage.volumes", prj)
	insertMirrorRow(t, ctx, env.pool, "storage.volumes", prj)
	insertMirrorRow(t, ctx, env.pool, "storage.volumes", prj)

	want := fmt.Sprintf("Project %s is not empty (compute.instance: 1, storage.volumes: 3, vpc.network: 2)", prj)
	first := refusalMessage(t, runDelete(t, env, uid, prj))
	require.Equal(t, want, first)
	second := refusalMessage(t, runDelete(t, env, uid, prj))
	require.Equal(t, first, second, "порядок видов детерминирован между вызовами")
}

// ── IAM-PNE-1-04 — вид с нулём не печатается, идентификаторы не печатаются ──

func TestProjectDelete_PNE_1_04(t *testing.T) {
	env := newPNEEnv(t)
	ctx := context.Background()
	uid, _, prj := seedUserAccountProject(t, ctx, env.pool, "1-04")
	objectID := insertMirrorRow(t, ctx, env.pool, "vpc.network", prj)

	// Предпосылка «Дано»: в каталоге живо ещё много чужих видов, ни один из
	// которых на проект не зарегистрирован.
	liveForeign := countRows(t, ctx, env.pool,
		`SELECT count(*) FROM kaname.catalog_resource WHERE live AND module <> 'iam'`)
	require.GreaterOrEqual(t, liveForeign, 19, "посев каталога: живых чужих видов")

	msg := refusalMessage(t, runDelete(t, env, uid, prj))
	require.Equal(t, fmt.Sprintf("Project %s is not empty (vpc.network: 1)", prj), msg)
	require.NotContains(t, msg, ": 0", "вид с нулём в перечень не попадает")
	require.NotContains(t, msg, objectID, "идентификаторы дочерних объектов не печатаются")
}

// ── IAM-PNE-1-06 полоса Б — чужой ресурс освобождён оператором владельца ────

func TestProjectDelete_PNE_1_06B(t *testing.T) {
	env := newPNEEnv(t)
	ctx := context.Background()
	uid, _, prj := seedUserAccountProject(t, ctx, env.pool, "1-06b")
	objectID := insertMirrorRow(t, ctx, env.pool, "vpc.network", prj)

	// Положительный близнец внутри сценария: до снятия строки — отказ.
	msg := refusalMessage(t, runDelete(t, env, uid, prj))
	require.Equal(t, fmt.Sprintf("Project %s is not empty (vpc.network: 1)", prj), msg)

	require.NoError(t, unregisterMirrorRow(ctx, env.pool, "vpc.network", objectID))
	require.Equal(t, 0, countRows(t, ctx, env.pool,
		`SELECT count(*) FROM kaname.resource_mirror WHERE object_id = $1`, objectID), "строка снята")

	op := runDelete(t, env, uid, prj)
	require.Nil(t, op.Error, "после освобождения тот же запрос проходит: %v", op.Error)
	require.False(t, projectRowExists(t, ctx, env.pool, prj), "строки проекта нет")
}

// ── IAM-PNE-1-07 полоса В — несуществующий проект отвечает отсутствием СИНХРОННО ──

func TestProjectDelete_PNE_1_07V(t *testing.T) {
	env := newPNEEnv(t)
	ctx := context.Background()
	uid, _, _ := seedUserAccountProject(t, ctx, env.pool, "1-07v")
	ghost := domain.ProjectID(ids.NewID(domain.PrefixProject))
	// Две осиротевшие строки называют несуществующий проект родителем.
	insertMirrorRow(t, ctx, env.pool, "vpc.network", ghost)
	insertMirrorRow(t, ctx, env.pool, "vpc.network", ghost)

	opsBefore := countRows(t, ctx, env.pool, `SELECT count(*) FROM kaname.operations`)
	uc := project.NewDeleteProjectUseCase(env.repo, env.opsRepo)
	op, err := uc.Execute(withPrincipal(uid), ghost)
	require.Error(t, err, "отказ синхронный, а не в операции")
	require.Nil(t, op, "операции не возвращается")
	st, ok := grpcstatus.FromError(err)
	require.True(t, ok, "отказ обязан быть gRPC-статусом: %v", err)
	require.Equal(t, codes.NotFound, st.Code(), "%s", st.Message())
	require.Equal(t, fmt.Sprintf("Project %s not found", ghost), st.Message(),
		"зеркало до чтения проекта не доходит: о том, чего нет, не говорят «не пуст»")
	require.NoError(t, operations.Wait(ctx))
	require.Equal(t, opsBefore, countRows(t, ctx, env.pool, `SELECT count(*) FROM kaname.operations`),
		"операция не создана")
}

// ── IAM-PNE-1-11 полоса Б — отвергнутое удаление не оставляет половинной работы ──

// seedBindingWithLedger кладёт выдачу на проект и ведомость её выпущенных
// кортежей в форме `InsertEmittedTuples`: структурный указатель выдачи на
// область и кортеж отношения субъекта на проект. Кортежи выдачи на снятие
// дренаж берёт ТОЛЬКО из ведомости (приёмка §0.1, Н13).
func seedBindingWithLedger(t *testing.T, ctx context.Context, env *pneEnv, uid domain.UserID, prj domain.ProjectID) (domain.AccessBindingID, int) {
	t.Helper()
	var roleID string
	require.NoError(t, env.pool.QueryRow(ctx,
		`SELECT id FROM kaname.roles WHERE name = 'iam.project.admin' AND cluster_id IS NOT NULL AND live`).
		Scan(&roleID), "посев системной роли iam.project.admin")
	acb := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	_, err := env.pool.Exec(ctx,
		`INSERT INTO kaname.access_bindings
		     (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		 VALUES ($1, 'user', $2, $3, 'project', $4, 'ACTIVE')`,
		string(acb), string(uid), roleID, string(prj))
	require.NoError(t, err)

	w, err := env.repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, acb, []abrepo.RelationTuple{
		{User: "project:" + string(prj), Relation: "project", Object: "iam_access_binding:" + string(acb)},
		{User: "user:" + string(uid), Relation: "v_get", Object: "project:" + string(prj)},
	}))
	require.NoError(t, w.Commit(ctx))
	ledger := countRows(t, ctx, env.pool,
		`SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1 AND source = 'binding'`,
		string(acb))
	require.GreaterOrEqual(t, ledger, 1, "предпосылка: строк ведомости у выдачи не меньше одной")
	return acb, ledger
}

func bindingStatus(t *testing.T, ctx context.Context, pool *pgxpool.Pool, acb domain.AccessBindingID) (string, bool) {
	t.Helper()
	var status string
	err := pool.QueryRow(ctx, `SELECT status FROM kaname.access_bindings WHERE id = $1`, string(acb)).Scan(&status)
	if err != nil {
		return "", false
	}
	return status, true
}

func TestProjectDelete_PNE_1_11B(t *testing.T) {
	env := newPNEEnv(t)
	ctx := context.Background()
	const outboxCount = `SELECT count(*) FROM kaname.fga_outbox`

	// Отвергнутый мир: роль + выдача с ведомостью.
	uid, acc, prj := seedUserAccountProject(t, ctx, env.pool, "1-11b")
	seedProjectRole(t, ctx, env.repo, prj, "pne_1_11b_role")
	acb, _ := seedBindingWithLedger(t, ctx, env, uid, prj)
	before := countRows(t, ctx, env.pool, outboxCount)

	msg := refusalMessage(t, runDelete(t, env, uid, prj))
	require.Equal(t, fmt.Sprintf("Project %s is not empty (iam.role: 1)", prj), msg)
	status, present := bindingStatus(t, ctx, env.pool, acb)
	require.True(t, present, "строка выдачи на месте")
	require.Equal(t, "ACTIVE", status, "и в прежнем состоянии")
	require.Equal(t, before, countRows(t, ctx, env.pool, outboxCount),
		"в очередь намерений не легло ничего — транзакция откатилась целиком")

	// Положительный близнец: тот же мир БЕЗ строки роли — пустой проект.
	twin := seedExtraProject(t, ctx, env.pool, acc, "1-11b-twin")
	twinACB, ledger := seedBindingWithLedger(t, ctx, env, uid, twin)
	before = countRows(t, ctx, env.pool, outboxCount)

	op := runDelete(t, env, uid, twin)
	require.Nil(t, op.Error, "пустой проект удаляется: %v", op.Error)
	_, present = bindingStatus(t, ctx, env.pool, twinACB)
	require.False(t, present, "выдача снята вместе с проектом")
	require.Equal(t, before+ledger+2, countRows(t, ctx, env.pool, outboxCount),
		"намерение снять каждый кортеж ведомости и оба структурных указателя проекта")
}

// ── IAM-PNE-1-12 полоса А — новый вид попадает в перечень без правки кода ────

func TestProjectDelete_PNE_1_12A(t *testing.T) {
	env := newPNEEnv(t)
	ctx := context.Background()
	uid, _, prj := seedUserAccountProject(t, ctx, env.pool, "1-12a")
	fresh := seedCatalogKind(t, ctx, env.pool, "pnn", "fresh")
	insertMirrorRow(t, ctx, env.pool, fresh, prj)
	insertMirrorRow(t, ctx, env.pool, "vpc.network", prj)

	msg := refusalMessage(t, runDelete(t, env, uid, prj))
	require.Equal(t, fmt.Sprintf("Project %s is not empty (pnn.fresh: 1, vpc.network: 1)", prj), msg,
		"новый вид назван наравне с прочими — перечень выводится из данных")
}

// ── IAM-PNE-1-17 — строка зеркала ЛЮБОГО вида семейства iam.* не удерживает ──

func TestProjectDelete_PNE_1_17(t *testing.T) {
	env := newPNEEnv(t)
	ctx := context.Background()
	uid, acc, _ := seedUserAccountProject(t, ctx, env.pool, "1-17")

	// Перебор ВСЕХ семи живых видов семейства — из каталога, а не по памяти.
	rows, err := env.pool.Query(ctx,
		`SELECT dotted FROM kaname.catalog_resource WHERE module = 'iam' AND live ORDER BY dotted`)
	require.NoError(t, err)
	var family []string
	for rows.Next() {
		var d string
		require.NoError(t, rows.Scan(&d))
		family = append(family, d)
	}
	rows.Close()
	require.NoError(t, rows.Err())
	require.Len(t, family, 7, "живых видов семейства iam.* в каталоге: %v", family)

	for i, kind := range family {
		prj := seedExtraProject(t, ctx, env.pool, acc, fmt.Sprintf("1-17-%d", i))
		insertMirrorRow(t, ctx, env.pool, kind, prj)
		op := runDelete(t, env, uid, prj)
		if op.Error != nil {
			st := grpcstatus.FromProto(op.Error)
			require.NotContains(t, st.Message(), "is not empty ()", "пустой скобки не бывает")
			t.Fatalf("строка вида %s удержала проект: %s", kind, st.Message())
		}
		require.False(t, projectRowExists(t, ctx, env.pool, prj), "%s: проект снят", kind)
	}

	// Положительный контроль: чужой вид удерживает — иначе отрицание выше
	// зеленело бы на охране, пропускающей всё.
	control := seedExtraProject(t, ctx, env.pool, acc, "1-17-control")
	insertMirrorRow(t, ctx, env.pool, "vpc.network", control)
	require.Equal(t, fmt.Sprintf("Project %s is not empty (vpc.network: 1)", control),
		refusalMessage(t, runDelete(t, env, uid, control)))

	// Граница семейства: модуль, чьё имя начинается на `iam`, но не `iam.` —
	// приставка семейства берётся С РАЗДЕЛИТЕЛЕМ.
	border := seedExtraProject(t, ctx, env.pool, acc, "1-17-border")
	thing := seedCatalogKind(t, ctx, env.pool, "iamx", "thing")
	insertMirrorRow(t, ctx, env.pool, thing, border)
	require.Equal(t, fmt.Sprintf("Project %s is not empty (iamx.thing: 1)", border),
		refusalMessage(t, runDelete(t, env, uid, border)))
}

// ── IAM-PNE-1-19 — строка чужого вида удерживает в ЛЮБОМ состоянии каталога ──

func TestProjectDelete_PNE_1_19(t *testing.T) {
	env := newPNEEnv(t)
	ctx := context.Background()
	uid, acc, _ := seedUserAccountProject(t, ctx, env.pool, "1-19")
	// Живой преемник для состояния «снят с преемником» — заведён заранее и не
	// меняется.
	successor := seedCatalogKind(t, ctx, env.pool, "pnsx", "live")

	type state struct {
		name    string
		module  string
		apply   func(t *testing.T, module string)
		removes bool // снимает ли строку оператор владельца в этом состоянии
	}
	states := []state{
		{name: "живой ресурс, живой delete", module: "pns1", apply: func(*testing.T, string) {}, removes: true},
		{name: "живой ресурс, delete снят", module: "pns2", apply: func(t *testing.T, m string) {
			require.EqualValues(t, 1, retireCatalogVerb(t, ctx, env.pool, m, "thing", "delete"))
		}, removes: true},
		{name: "снят с преемником", module: "pns3", apply: func(t *testing.T, m string) {
			require.EqualValues(t, 1, retireCatalogVerb(t, ctx, env.pool, m, "thing", "get"))
			require.EqualValues(t, 1, retireCatalogVerb(t, ctx, env.pool, m, "thing", "delete"))
			require.EqualValues(t, 1, retireCatalogResource(t, ctx, env.pool, m, "thing", successor))
		}, removes: true},
		{name: "снят без преемника", module: "pns4", apply: func(t *testing.T, m string) {
			require.EqualValues(t, 1, retireCatalogVerb(t, ctx, env.pool, m, "thing", "get"))
			require.EqualValues(t, 1, retireCatalogVerb(t, ctx, env.pool, m, "thing", "delete"))
			require.EqualValues(t, 1, retireCatalogResource(t, ctx, env.pool, m, "thing", ""))
		}, removes: true},
		{name: "в каталоге нет вовсе", module: "pns5", apply: func(t *testing.T, m string) {
			tag, err := env.pool.Exec(ctx, `DELETE FROM kaname.catalog_verb WHERE module = $1`, m)
			require.NoError(t, err)
			require.EqualValues(t, 2, tag.RowsAffected())
			tag, err = env.pool.Exec(ctx, `DELETE FROM kaname.catalog_resource WHERE module = $1`, m)
			require.NoError(t, err)
			require.EqualValues(t, 1, tag.RowsAffected())
		}, removes: false},
	}

	for _, s := range states {
		t.Run(s.name, func(t *testing.T) {
			kind := seedCatalogKind(t, ctx, env.pool, s.module, "thing")
			// Предпосылка: на заведённый модуль не ссылается ни одно правило роли —
			// иначе смена состояния упёрлась бы в `role_rule_ref_verb_fk`.
			require.Equal(t, 0, countRows(t, ctx, env.pool,
				`SELECT count(*) FROM kaname.role_rule_ref WHERE module = $1`, s.module))
			prj := seedExtraProject(t, ctx, env.pool, acc, s.module)
			objectID := insertMirrorRow(t, ctx, env.pool, kind, prj)
			s.apply(t, s.module)

			require.Equal(t, fmt.Sprintf("Project %s is not empty (%s: 1)", prj, kind),
				refusalMessage(t, runDelete(t, env, uid, prj)),
				"строка удерживает проект независимо от состояния каталога")
			if !s.removes {
				// Пятое состояние — граница, а не близнец: оператор владельца строку
				// не снимает, и продукт это состояние не производит (приёмка §7.6).
				return
			}
			require.NoError(t, unregisterMirrorRow(ctx, env.pool, kind, objectID),
				"оператор владельца снимает строку в этом состоянии")
			op := runDelete(t, env, uid, prj)
			require.Nil(t, op.Error, "после снятия строки удаление проходит: %v", op.Error)
			require.False(t, projectRowExists(t, ctx, env.pool, prj))
		})
	}
}

// ── IAM-PNE-1-20 — перечень называет ровно то, что удерживает ───────────────

func TestProjectDelete_PNE_1_20(t *testing.T) {
	env := newPNEEnv(t)
	ctx := context.Background()
	uid, _, prj := seedUserAccountProject(t, ctx, env.pool, "1-20")

	roleA := seedProjectRole(t, ctx, env.repo, prj, "pne_1_20_a")
	seedProjectRole(t, ctx, env.repo, prj, "pne_1_20_b")
	// Строка зеркала `iam.role` называет ОДНУ из ролей — двойной счёт ловится
	// только здесь, в мире с двумя ролями (мутант «наличие» дал бы iam.role: 1).
	_, err := env.pool.Exec(ctx,
		`INSERT INTO kaname.resource_mirror (object_type, object_id, parent_project_id, parent_account_id, labels)
		 VALUES ('iam.role', $1, $2, '', '{}'::jsonb)`, string(roleA), string(prj))
	require.NoError(t, err)
	insertMirrorRow(t, ctx, env.pool, "iam.group", prj)
	insertMirrorRow(t, ctx, env.pool, seedCatalogKind(t, ctx, env.pool, "iamx", "thing"), prj)
	nodel := seedCatalogKind(t, ctx, env.pool, "pnm", "nodel")
	require.EqualValues(t, 1, retireCatalogVerb(t, ctx, env.pool, "pnm", "nodel", "delete"))
	insertMirrorRow(t, ctx, env.pool, nodel, prj)
	gone := seedCatalogKind(t, ctx, env.pool, "pnm", "gone")
	require.EqualValues(t, 1, retireCatalogVerb(t, ctx, env.pool, "pnm", "gone", "get"))
	require.EqualValues(t, 1, retireCatalogVerb(t, ctx, env.pool, "pnm", "gone", "delete"))
	require.EqualValues(t, 1, retireCatalogResource(t, ctx, env.pool, "pnm", "gone", ""))
	insertMirrorRow(t, ctx, env.pool, gone, prj)
	insertMirrorRow(t, ctx, env.pool, "vpc.network", prj)

	require.Equal(t,
		fmt.Sprintf("Project %s is not empty (iam.role: 2, iamx.thing: 1, pnm.gone: 1, pnm.nodel: 1, vpc.network: 1)", prj),
		refusalMessage(t, runDelete(t, env, uid, prj)))
}
