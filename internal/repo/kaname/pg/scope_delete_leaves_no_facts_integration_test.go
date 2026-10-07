// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// scope_delete_leaves_no_facts_integration_test.go — удаление области не
// оставляет в модели прав фактов, называющих её (kaname#665).
//
// # Предмет
//
// Заведение личных ресурсов (`userapp.BootstrapPersonalResourcesTx`) кладёт
// выдачу на проект по умолчанию и эмитит два её кортежа — самовыдачу
// `user:<U>#admin@project:<P>` и указатель объекта выдачи на предка
// `project:<P>#project@iam_access_binding:<AB>`. Снятие проекта дренирует выдачи
// своей области СИММЕТРИЧНО ПО ВЕДОМОСТИ (`shared.RevokeBindingsInScope` →
// `SelectEmittedTuples`): что записано выпущенным, то и снимается. Ведомость
// этой выдачи заведение не писало, поэтому строка выдачи уходила, а оба факта
// оставались в `kaname.relation_fact` навсегда — снять их штатным путём нечем,
// область удалена.
//
// # Почему проба смотрит на ПРЯМОЙ ФАКТ, а не на намерения журнала
//
// Наблюдаемое — то, из чего вердикт собирает безусловное основание: таблица
// прямого факта, которую наполняет и чистит триггер журнала намерений. Сверка
// намерений «записано / снято» зеленела бы и при факте, оставшемся от другого
// писателя; таблица факта отвечает на сам вопрос приёмки.
//
// # Как строится «Когда»
//
// Настоящее тело заведения (зеркало регистрации), настоящий глагол удаления
// (`DeleteProjectUseCase.Execute` → операция) и настоящий реконсайлер на
// со-коммиченное событие снятия (воркер событий в пробе не поднят, поэтому его
// шаг — `ReconcileObject` по тому же виду и id — исполняется явно).
//
// # Пара
//
// Отрицание («фактов удалённого проекта 0») стоит в паре с положительным
// контролем: до удаления факты есть, а проект соседней личности после удаления
// своих фактов не теряет — иначе проба зеленела бы на реализации, сносящей
// факты без разбора области.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/operations"

	accountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// factsNaming — прямые факты, называющие объект `<typ>:<id>` с любой стороны
// отношения: объектом или субъектом (в том числе субъектом-множеством
// `<typ>:<id>#<rel>`). Возвращает их строками «объект#отношение@субъект», чтобы
// отказ называл остаток, а не число.
func factsNaming(t *testing.T, ctx context.Context, pool *pgxpool.Pool, typ, id string) []string {
	t.Helper()
	ref := typ + ":" + id
	rows, err := pool.Query(ctx, `
		SELECT object_type || ':' || object_id || '#' || relation || '@' || subject
		  FROM kaname.relation_fact
		 WHERE (object_type = $1 AND object_id = $2)
		    OR subject = $3
		    OR subject LIKE $4
		 ORDER BY 1`, typ, id, ref, ref+"#%")
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(t, rows.Err())
	return out
}

// defaultProjectOf — проект по умолчанию личного аккаунта.
func defaultProjectOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID domain.AccountID) domain.ProjectID {
	t.Helper()
	var prj string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kaname.projects WHERE account_id = $1 AND name = 'default'`,
		string(accID)).Scan(&prj))
	return domain.ProjectID(prj)
}

// awaitScopeDeleteOp дожидается операции и возвращает её ошибку текстом (пусто — успех).
func awaitScopeDeleteOp(t *testing.T, ops operations.Repo, op *operations.Operation) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx), "операция не завершилась в срок")
	got, err := ops.Get(context.Background(), op.ID)
	require.NoError(t, err)
	require.True(t, got.Done, "операция не завершилась")
	if got.Error != nil {
		return fmt.Sprintf("code=%d %s", got.Error.GetCode(), got.Error.GetMessage())
	}
	return ""
}

func principalCtx(uid domain.UserID) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: string(uid), DisplayName: string(uid)})
}

type scopeDeleteEnv struct {
	pool *pgxpool.Pool
	repo *kanamepg.Repository
	ops  operations.Repo
}

func newScopeDeleteEnv(t *testing.T) *scopeDeleteEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return &scopeDeleteEnv{pool: pool, repo: kanamepg.New(pool, nil), ops: operations.NewRepo(pool, "kaname")}
}

// runDeleteWorker — шаг воркера событий реконсайла: на КАЖДОЕ со-коммиченное
// событие снятия (`mirror.delete`) — `ReconcileObject` по его виду и id, как
// делает воркер продукта. Берутся все события снятия журнала, а не названные
// пробой: проба не решает за продукт, какие объекты он отозвал.
func (e *scopeDeleteEnv) runDeleteWorker(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	rows, err := e.pool.Query(ctx, `
		SELECT DISTINCT object_type, object_id FROM kaname.resource_reconcile_outbox
		 WHERE event_type = 'mirror.delete' ORDER BY 1, 2`)
	require.NoError(t, err)
	type obj struct{ typ, id string }
	var objs []obj
	for rows.Next() {
		var o obj
		require.NoError(t, rows.Scan(&o.typ, &o.id))
		objs = append(objs, o)
	}
	rows.Close()
	require.NoError(t, rows.Err())
	require.NotEmpty(t, objs, "предпосылка: снятие со-коммитило хотя бы одно событие отзыва")
	rec, _ := newReconciler(e.pool)
	for _, o := range objs {
		require.NoError(t, rec.ReconcileObject(ctx, o.typ, o.id), "отзыв %s:%s", o.typ, o.id)
	}
}

// deleteProject исполняет настоящий глагол удаления и затем шаг воркера.
func (e *scopeDeleteEnv) deleteProject(t *testing.T, uid domain.UserID, prj domain.ProjectID) {
	t.Helper()
	op, err := projectapp.NewDeleteProjectUseCase(e.repo, e.ops).Execute(principalCtx(uid), prj)
	require.NoError(t, err)
	require.Empty(t, awaitScopeDeleteOp(t, e.ops, op), "удаление проекта по умолчанию отказало")
	e.runDeleteWorker(t)
}

// TestProjectDelete_LeavesNoFactsNamingTheProject — после удаления проекта
// фактов, называющих его, 0 (kaname#665, предикат задачи).
func TestProjectDelete_LeavesNoFactsNamingTheProject(t *testing.T) {
	e := newScopeDeleteEnv(t)
	ctx := context.Background()

	uid, accID := bootstrapNewIdentity(t, ctx, e.pool, e.repo, "ext_665_victim", "victim-665@example.com")
	prj := defaultProjectOf(t, ctx, e.pool, accID)
	// Соседняя личность — положительный контроль области.
	_, bystAcc := bootstrapNewIdentity(t, ctx, e.pool, e.repo, "ext_665_byst", "byst-665@example.com")
	bystPrj := defaultProjectOf(t, ctx, e.pool, bystAcc)

	before := factsNaming(t, ctx, e.pool, "project", string(prj))
	require.NotEmpty(t, before,
		"предпосылка: до удаления у проекта есть факты — иначе «0 после» ничего не доказывает")
	bystBefore := factsNaming(t, ctx, e.pool, "project", string(bystPrj))
	require.NotEmpty(t, bystBefore, "предпосылка: у проекта соседа есть факты")

	e.deleteProject(t, uid, prj)

	left := factsNaming(t, ctx, e.pool, "project", string(prj))
	require.Empty(t, left,
		"после удаления проекта в модели прав остались факты, называющие его (%d из %d):\n  %s",
		len(left), len(before), strings.Join(left, "\n  "))
	require.Equal(t, bystBefore, factsNaming(t, ctx, e.pool, "project", string(bystPrj)),
		"удаление чужого проекта изменило факты соседа — снятие не разбирает область")
}

// TestProjectDelete_BootstrapBindingObjectLeavesNoFacts — объект выдачи,
// которую заведение положило на проект, после удаления проекта не несёт ни
// одного факта: указатель на предка — факт ОБ ОБЪЕКТЕ ВЫДАЧИ, и проба по
// проекту видит его лишь субъектом.
func TestProjectDelete_BootstrapBindingObjectLeavesNoFacts(t *testing.T) {
	e := newScopeDeleteEnv(t)
	ctx := context.Background()

	uid, accID := bootstrapNewIdentity(t, ctx, e.pool, e.repo, "ext_665_ab", "ab-665@example.com")
	prj := defaultProjectOf(t, ctx, e.pool, accID)
	var abID string
	require.NoError(t, e.pool.QueryRow(ctx,
		`SELECT id FROM kaname.access_bindings WHERE resource_type = 'project' AND resource_id = $1`,
		string(prj)).Scan(&abID))

	e.deleteProject(t, uid, prj)

	left := factsNaming(t, ctx, e.pool, "iam_access_binding", abID)
	require.Empty(t, left,
		"выдача снята вместе с проектом, а факты её объекта остались (%d):\n  %s",
		len(left), strings.Join(left, "\n  "))
}

// TestAccountDelete_LeavesNoFactsOfItsBindings — тот же класс на снятии
// аккаунта: каждая выдача, дренированная `Account.Delete`, уходит из модели
// прав целиком — ни её объект, ни выдачи на сам аккаунт фактами не остаются.
//
// Аккаунт заводится глаголом создания, а не берётся личный: личный аккаунт
// держит строка его человека, и снять его, не сняв человека, продукт не даёт
// (отказ «resource is still referenced»); проекты, которые заводит создание,
// снимаются первыми — аккаунт с проектами продукт не снимает. Указатель членства
// `account:<A>#account@iam_user:<U>` в предмет не входит — это кортеж жизненного
// цикла ЛИЧНОСТИ, а не выдачи (kaname#946).
func TestAccountDelete_LeavesNoFactsOfItsBindings(t *testing.T) {
	e := newScopeDeleteEnv(t)
	ctx := context.Background()

	uid, _ := bootstrapNewIdentity(t, ctx, e.pool, e.repo, "ext_665_acc", "acc-665@example.com")
	op, err := accountapp.NewCreateAccountUseCase(e.repo, e.ops).Execute(principalCtx(uid),
		domain.Account{Name: domain.AccountName("acc-665-subject"), Labels: domain.Labels{}})
	require.NoError(t, err)
	require.Empty(t, awaitScopeDeleteOp(t, e.ops, op), "создание аккаунта отказало")
	var accID, ownerAB string
	require.NoError(t, e.pool.QueryRow(ctx,
		`SELECT id FROM kaname.accounts WHERE name = 'acc-665-subject'`).Scan(&accID))
	require.NoError(t, e.pool.QueryRow(ctx,
		`SELECT id FROM kaname.access_bindings WHERE resource_type = 'account' AND resource_id = $1`,
		accID).Scan(&ownerAB))
	rec, _ := newReconciler(e.pool)
	require.NoError(t, rec.ReconcileBinding(ctx, domain.AccessBindingID(ownerAB)),
		"материализация собственнической выдачи после фиксации")
	require.NotEmpty(t, factsNaming(t, ctx, e.pool, "iam_access_binding", ownerAB),
		"предпосылка: у собственнической выдачи до удаления есть факты")
	require.NotEmpty(t, accountGrantFacts(t, ctx, e.pool, accID),
		"предпосылка: у аккаунта до удаления есть факты на нём")

	// Аккаунт с проектами не снимается — сначала его проекты, как в продукте.
	var prjs []string
	rows, err := e.pool.Query(ctx, `SELECT id FROM kaname.projects WHERE account_id = $1`, accID)
	require.NoError(t, err)
	for rows.Next() {
		var p string
		require.NoError(t, rows.Scan(&p))
		prjs = append(prjs, p)
	}
	rows.Close()
	require.NoError(t, rows.Err())
	for _, p := range prjs {
		e.deleteProject(t, uid, domain.ProjectID(p))
	}

	op, err = accountapp.NewDeleteAccountUseCase(e.repo, e.ops).Execute(principalCtx(uid), domain.AccountID(accID))
	require.NoError(t, err)
	require.Empty(t, awaitScopeDeleteOp(t, e.ops, op), "удаление аккаунта отказало")
	e.runDeleteWorker(t)

	left := factsNaming(t, ctx, e.pool, "iam_access_binding", ownerAB)
	require.Empty(t, left, "факты объекта собственнической выдачи пережили аккаунт:\n  %s",
		strings.Join(left, "\n  "))
	grants := accountGrantFacts(t, ctx, e.pool, accID)
	require.Empty(t, grants, "на удалённом аккаунте остались факты:\n  %s", strings.Join(grants, "\n  "))
}

// accountGrantFacts — факты, ОБЪЕКТ которых — аккаунт.
func accountGrantFacts(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID string) []string {
	t.Helper()
	var out []string
	for _, f := range factsNaming(t, ctx, pool, "account", accID) {
		if strings.HasPrefix(f, "account:"+accID+"#") {
			out = append(out, f)
		}
	}
	return out
}
