// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// nested_rule_integration_test.go — ВЛОЖЕННОЕ ПРАВИЛО РОЛИ ДОСТАЁТ ДО ПОТОМКОВ
// КОНТЕЙНЕРА, ВЫБРАННОГО ВЫДАЧЕЙ (kaname#874).
//
// Приёмка: docs/engineering/acceptance/nested-rule-reaches-descendants-of-a-named-container.md
// (редакция 2, отпечаток f12395ae242f85e1120346123286318b3027d87e53f6973f4b8a21ac1bd6d9f6),
// сценарии ND-01, 02, 07, 09, 10, 11 и умолчание рецензента R1 (ветвь меток
// правила-владельца) на уровне решения. Глубина (ND-08) — в пакете
// `relverdict/nesteddepth`: ей нужна модель с тремя уровнями родства, а модель
// процесса этого пакета — вшитый канон.
//
// Вход — тот же, что провязывает композиционный корень (`relverdict.NewAsker`),
// посев коммитится. Роль пишется ПРОДУКТОВЫМ писателем (`RolesW().Insert`,
// `ReplaceRuleSelectors`, `ReplaceRoleVerbs` из каталожного факта), а не сырым
// оператором: вложенность едет из домена в строку селектора тем же путём, что у
// `RoleService` и самолечения старта, и фикстура не может оказаться снисходительнее
// продукта. Формы вопроса — все пять, у которых есть ветвь выдач.

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// Объекты: реестры X и Y в prj-1, их репозитории.
const (
	ndRegType  = "registry_registry"
	ndRepoType = "registry_repository"
	ndX        = "reg00000000000000001"
	ndY        = "reg00000000000000002"
	ndXApp     = ndX + "/app"
	ndXMoved   = ndX + "/moved"
	ndXLate    = ndX + "/late"
	ndYApp     = ndY + "/app"
	ndUsrD     = "user:usr-1"
	ndUsrE     = "user:usr-2"
	ndAnon     = "system_class:anonymous"
)

// ndRules — правила ролей таблицы П1 (форма домена).
func ndRules(withChildren bool, ownerNames []string, ownerLabels map[string]string) domain.Rules {
	r := domain.Rule{
		Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get", "list"},
		ResourceNames: ownerNames, MatchLabels: ownerLabels,
	}
	if withChildren {
		r.Children = []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get", "list"}}}
	}
	return domain.Rules{r}
}

// ndFlatRules — прежняя форма `registry.public.read`: одно правило над двумя
// типами (ND-07).
func ndFlatRules() domain.Rules {
	return domain.Rules{{Module: "registry", Resources: []string{"registries", "repositories"}, Verbs: []string{"get", "list"}}}
}

// ndSeedObjects — реестры, репозитории и рёбра цепи предков, как их кладёт
// регистрация владельца (`upsertParentEdges`: каждый предок цепи с глубиной).
func ndSeedObjects(t *testing.T, ctx context.Context, tx pgx.Tx, labelsX, labelsY string) {
	t.Helper()
	seedTenant(t, ctx, tx)
	exec(t, ctx, tx,
		`INSERT INTO kaname.users (id, external_id, email, account_id)
		 VALUES ('usr-2', 'ext-2', 'usr-2@kacho.local', 'acc-1') ON CONFLICT DO NOTHING`)
	reg := catalogFormOf(t, ndRegType)
	for _, o := range []struct{ id, labels string }{{ndX, labelsX}, {ndY, labelsY}} {
		exec(t, ctx, tx,
			`INSERT INTO kaname.resource_mirror (object_type, object_id, parent_project_id, parent_account_id, labels)
			 VALUES ($1, $2, 'prj-1', 'acc-1', $3::jsonb)`, reg, o.id, o.labels)
		ndSeedChain(t, ctx, tx, ndRegType, o.id, "project:prj-1", "account:acc-1")
	}
	for _, id := range []string{ndXApp, ndXMoved, ndYApp} {
		ndSeedRepo(t, ctx, tx, id)
	}
}

// ndSeedRepo — репозиторий под своим реестром (реестр — префикс id).
func ndSeedRepo(t *testing.T, ctx context.Context, tx pgx.Tx, id string) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kaname.resource_mirror (object_type, object_id, parent_project_id, parent_account_id)
		 VALUES ($1, $2, 'prj-1', 'acc-1')`, catalogFormOf(t, ndRepoType), id)
	ndSeedChain(t, ctx, tx, ndRepoType, id, ndRegType+":"+id[:len(ndX)], "project:prj-1", "account:acc-1")
}

// ndSeedChain — рёбра цепи предков объекта.
func ndSeedChain(t *testing.T, ctx context.Context, tx pgx.Tx, objType, objID string, chain ...string) {
	t.Helper()
	exec(t, ctx, tx, `DELETE FROM kaname.resource_parent_edge WHERE object_type = $1 AND object_id = $2`, objType, objID)
	for i, ref := range chain {
		typ, id, _ := cutRef(ref)
		exec(t, ctx, tx,
			`INSERT INTO kaname.resource_parent_edge (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ($1, $2, $3, $4, $5)`, objType, objID, typ, id, i+1)
	}
}

func cutRef(ref string) (string, string, bool) {
	for i := 0; i < len(ref); i++ {
		if ref[i] == ':' {
			return ref[:i], ref[i+1:], true
		}
	}
	return ref, "", false
}

// ndSeedRole — роль аккаунта acc-1, записанная продуктовым писателем.
func ndSeedRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id string, rules domain.Rules) {
	t.Helper()
	repo := kanamepg.New(pool, nil)
	w, err := repo.Writer(ctx)
	if err != nil {
		t.Fatalf("писатель: %v", err)
	}
	defer func() { _ = w.Rollback(ctx) }()
	compiled, err := domain.CompileRules(rules)
	if err != nil {
		t.Fatalf("компиляция правил роли %s: %v", id, err)
	}
	inserted, err := w.RolesW().Insert(ctx, domain.Role{
		ID: domain.RoleID(id), AccountID: "acc-1", Name: domain.RoleName(strings.ReplaceAll(strings.TrimPrefix(id, "rol-"), "-", "_")),
		Description: "nested probe", Rules: rules, Permissions: compiled,
	})
	if err != nil {
		t.Fatalf("роль %s: %v", id, err)
	}
	sels := catalogfixture.Facts().GrantSelectors(inserted.Rules.MaterializingSelectors(), domain.TenantPolicy())
	if err := w.RolesW().ReplaceRuleSelectors(ctx, inserted.ID, sels); err != nil {
		t.Fatalf("селекторы роли %s: %v", id, err)
	}
	pairs := catalogfixture.Facts().RoleVerbsFromSelectors(sels, domain.TenantPolicy())
	if err := w.RolesW().ReplaceRoleVerbs(ctx, inserted.ID, pairs); err != nil {
		t.Fatalf("проекция глаголов роли %s: %v", id, err)
	}
	if err := w.Commit(ctx); err != nil {
		t.Fatalf("коммит роли %s: %v", id, err)
	}
}

// ndBind — выдача роли на проект prj-1 с целью; субъект — пара «вид, id».
func ndBind(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id, subjType, subjID, role, target string) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция выдачи: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec(t, ctx, tx,
		`INSERT INTO kaname.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status, target)
		 VALUES ($1, $2, $3, $4, 'project', 'prj-1', 'ACTIVE', $5::jsonb)`,
		id, subjType, subjID, role, target)
	exec(t, ctx, tx,
		`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ($1, $2, $3)`, id, subjType, subjID)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("коммит выдачи %s: %v", id, err)
	}
}

func ndTarget(id string) string {
	return `{"resources":[{"type":"registry.registries","id":"` + id + `"}]}`
}

// ndAsk — Allowed с отказом пробы на ошибке.
func ndAsk(t *testing.T, ctx context.Context, a *relverdict.Asker, speaker, typ, id string) bool {
	t.Helper()
	got, err := a.Allowed(ctx, speaker, typ, id, "v_get", nil)
	if err != nil {
		t.Fatalf("Allowed(%s, %s:%s): %v", speaker, typ, id, err)
	}
	return got
}

func ndExpect(t *testing.T, ctx context.Context, a *relverdict.Asker, speaker string, want map[[2]string]bool) {
	t.Helper()
	for k, w := range want {
		if got := ndAsk(t, ctx, a, speaker, k[0], k[1]); got != w {
			t.Errorf("Allowed(%s, v_get, %s:%s) = %v, ждали %v", speaker, k[0], k[1], got, w)
		}
	}
}

// ndWorld — посев П1 уровня решения без выдач.
func ndWorld(t *testing.T, labelsX, labelsY string) (*pgxpool.Pool, context.Context, *relverdict.Asker) {
	t.Helper()
	pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
		ndSeedObjects(t, ctx, tx, labelsX, labelsY)
	})
	return pool, ctx, relverdict.NewAsker(pool)
}

// ND-01: роль без children на X — только X; репозитории X не задеты.
func TestNested_ND01_RoleWithoutChildrenGivesOnlyTheContainer(t *testing.T) {
	pool, ctx, a := ndWorld(t, "{}", "{}")
	ndSeedRole(t, ctx, pool, "rol-nd-viewer", ndRules(false, nil, nil))
	ndBind(t, ctx, pool, "acb-nd01", "user", "usr-1", "rol-nd-viewer", ndTarget(ndX))
	ndExpect(t, ctx, a, ndUsrD, map[[2]string]bool{
		{ndRegType, ndX}: true, {ndRepoType, ndXApp}: false,
	})
}

// ND-02: вложенное правило на X — X и его репозитории, включая зарегистрированные
// позже; Y и его репозитории не задеты. Все пять форм вопроса.
func TestNested_ND02_NestedRuleReachesDescendantsInEveryForm(t *testing.T) {
	pool, ctx, a := ndWorld(t, "{}", "{}")
	ndSeedRole(t, ctx, pool, "rol-nd-reader", ndRules(true, nil, nil))
	ndBind(t, ctx, pool, "acb-nd02", "user", "usr-1", "rol-nd-reader", ndTarget(ndX))

	// Будущий потомок: регистрируется ПОСЛЕ выдачи, выдача не меняется.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция: %v", err)
	}
	ndSeedRepo(t, ctx, tx, ndXLate)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("коммит: %v", err)
	}

	ndExpect(t, ctx, a, ndUsrD, map[[2]string]bool{
		{ndRegType, ndX}: true, {ndRepoType, ndXApp}: true, {ndRepoType, ndXLate}: true,
		{ndRegType, ndY}: false, {ndRepoType, ndYApp}: false,
	})
	if got, err := a.Allowed(ctx, ndUsrD, ndRepoType, ndXApp, "v_list", nil); err != nil || !got {
		t.Errorf("Allowed(v_list, …01/app) = %v (%v), ждали true", got, err)
	}

	many, err := a.AllowedMany(ctx, ndUsrD, ndRepoType, []string{ndXApp, ndYApp, ndXLate}, "v_get", nil)
	if err != nil {
		t.Fatalf("AllowedMany: %v", err)
	}
	if want := []bool{true, false, true}; !slices.Equal(many, want) {
		t.Errorf("AllowedMany([…01/app …02/app …01/late]) = %v, ждали %v", many, want)
	}

	ids, complete, err := a.Objects(ctx, ndUsrD, ndRepoType, []string{"v_get"}, 100)
	if err != nil || !complete {
		t.Fatalf("Objects: %v (полнота %v)", err, complete)
	}
	slices.Sort(ids)
	if want := []string{ndXApp, ndXLate, ndXMoved}; !slices.Equal(ids, want) {
		t.Errorf("Objects(registry_repository) = %v, ждали %v", ids, want)
	}

	subs, _, err := a.Subjects(ctx, ndRepoType, ndXApp, "v_get", 100)
	if err != nil {
		t.Fatalf("Subjects: %v", err)
	}
	if !slices.Contains(subs, ndUsrD) {
		t.Errorf("Subjects(…01/app) = %v, не называет %s", subs, ndUsrD)
	}
	src, err := a.Sources(ctx, ndRepoType, ndXApp, "v_get")
	if err != nil {
		t.Fatalf("Sources: %v", err)
	}
	if !slices.Contains(src, ndUsrD) {
		t.Errorf("Sources(…01/app) = %v, не называет основанием выдачу %s", src, ndUsrD)
	}
	if subsY, _, err := a.Subjects(ctx, ndRepoType, ndYApp, "v_get", 100); err != nil || slices.Contains(subsY, ndUsrD) {
		t.Errorf("Subjects(…02/app) = %v (%v): соседний контейнер не назван целью", subsY, err)
	}
}

// ND-07 (б) на уровне решения: правило верхнего уровня над репозиториями
// сравнивает точно — цель [X] репозиториям X не даёт ничего (поведение kaname#857).
func TestNested_ND07_TopLevelRuleStaysExact(t *testing.T) {
	pool, ctx, a := ndWorld(t, "{}", "{}")
	ndSeedRole(t, ctx, pool, "rol-nd-flat", ndFlatRules())
	ndBind(t, ctx, pool, "acb-nd07", "user", "usr-1", "rol-nd-flat", ndTarget(ndX))
	ndExpect(t, ctx, a, ndUsrD, map[[2]string]bool{
		{ndRegType, ndX}: true, {ndRepoType, ndXApp}: false,
	})
}

// ND-09 на уровне решения: решение читает ТЕКУЩИЕ рёбра объекта — замена рёбер
// (её делает применённая регистрация со строго новой версией) переносит право.
// Сама новизна версии — у регистрации, проба пути — в мире П1.
func TestNested_ND09_DecisionFollowsTheCurrentChain(t *testing.T) {
	pool, ctx, a := ndWorld(t, "{}", "{}")
	ndSeedRole(t, ctx, pool, "rol-nd-reader", ndRules(true, nil, nil))
	ndBind(t, ctx, pool, "acb-nd09-d", "user", "usr-1", "rol-nd-reader", ndTarget(ndX))
	ndBind(t, ctx, pool, "acb-nd09-e", "user", "usr-2", "rol-nd-reader", ndTarget(ndY))
	ndExpect(t, ctx, a, ndUsrD, map[[2]string]bool{{ndRepoType, ndXMoved}: true})
	ndExpect(t, ctx, a, ndUsrE, map[[2]string]bool{{ndRepoType, ndXMoved}: false})

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция: %v", err)
	}
	ndSeedChain(t, ctx, tx, ndRepoType, ndXMoved, ndRegType+":"+ndY, "project:prj-1", "account:acc-1")
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("коммит: %v", err)
	}
	ndExpect(t, ctx, a, ndUsrD, map[[2]string]bool{{ndRepoType, ndXMoved}: false})
	ndExpect(t, ctx, a, ndUsrE, map[[2]string]bool{{ndRepoType, ndXMoved}: true})
}

// ND-10 на уровне решения: ветвь выдач вложенное правило к выдаче КЛАССУ не
// применяет — у класса одна дорога к потомкам, `public_reader`. Близнец — та же
// роль и цель у человека.
func TestNested_ND10_ClassDoesNotTakeTheNestedRoad(t *testing.T) {
	pool, ctx, a := ndWorld(t, "{}", "{}")
	ndSeedRole(t, ctx, pool, "rol-nd-reader", ndRules(true, nil, nil))
	ndBind(t, ctx, pool, "acb-nd10-anon", "system_class", "anonymous", "rol-nd-reader", ndTarget(ndX))
	ndBind(t, ctx, pool, "acb-nd10-auth", "system_class", "authenticated", "rol-nd-reader", ndTarget(ndX))
	ndBind(t, ctx, pool, "acb-nd10-usr", "user", "usr-2", "rol-nd-reader", ndTarget(ndX))
	for _, sp := range []string{ndAnon, "system_class:authenticated"} {
		ndExpect(t, ctx, a, sp, map[[2]string]bool{{ndRegType, ndX}: true, {ndRepoType, ndXApp}: false})
	}
	ndExpect(t, ctx, a, ndUsrE, map[[2]string]bool{{ndRegType, ndX}: true, {ndRepoType, ndXApp}: true})
}

// ND-11: вся область (allInScope, `{}`, `{"resources":[]}`) — вложенное правило
// действует внутри ВСЕХ контейнеров области. Близнец — роль без children.
func TestNested_ND11_WholeScopeReachesEveryContainer(t *testing.T) {
	for name, target := range map[string]string{
		"allInScope":      `{"allInScope": true}`,
		"пустая цель":     `{}`,
		"пустой перечень": `{"resources": []}`,
	} {
		t.Run(name, func(t *testing.T) {
			pool, ctx, a := ndWorld(t, "{}", "{}")
			ndSeedRole(t, ctx, pool, "rol-nd-reader", ndRules(true, nil, nil))
			ndSeedRole(t, ctx, pool, "rol-nd-viewer", ndRules(false, nil, nil))
			ndBind(t, ctx, pool, "acb-nd11-e", "user", "usr-2", "rol-nd-reader", target)
			ndBind(t, ctx, pool, "acb-nd11-d", "user", "usr-1", "rol-nd-viewer", target)
			ndExpect(t, ctx, a, ndUsrE, map[[2]string]bool{
				{ndRegType, ndX}: true, {ndRepoType, ndXApp}: true, {ndRegType, ndY}: true, {ndRepoType, ndYApp}: true,
			})
			many, err := a.AllowedMany(ctx, ndUsrE, ndRepoType, []string{ndXApp, ndYApp}, "v_get", nil)
			if err != nil || !slices.Equal(many, []bool{true, true}) {
				t.Errorf("AllowedMany(…01/app …02/app) = %v (%v), ждали [true true]", many, err)
			}
			// Близнец без children: [true, false, true, false].
			ndExpect(t, ctx, a, ndUsrD, map[[2]string]bool{
				{ndRegType, ndX}: true, {ndRepoType, ndXApp}: false, {ndRegType, ndY}: true, {ndRepoType, ndYApp}: false,
			})
		})
	}
}

// R1 (умолчание рецензента): контейнер выбран, если проходит отбор
// правила-владельца в ЛЮБОЙ его ветви, включая метки. Форма ND-08 «И»: цель —
// вся область, ветвь владельца выбирает только X. Близнец — владелец якорем.
func TestNested_ND08_LabelsArmOfTheOwnerSelectsContainers(t *testing.T) {
	pool, ctx, a := ndWorld(t, `{"team":"a"}`, `{"team":"b"}`)
	ndSeedRole(t, ctx, pool, "rol-nd-lbl", ndRules(true, nil, map[string]string{"team": "a"}))
	ndSeedRole(t, ctx, pool, "rol-nd-reader", ndRules(true, nil, nil))
	ndBind(t, ctx, pool, "acb-nd-lbl", "user", "usr-1", "rol-nd-lbl", `{"allInScope": true}`)
	ndBind(t, ctx, pool, "acb-nd-anc", "user", "usr-2", "rol-nd-reader", `{"allInScope": true}`)
	ndExpect(t, ctx, a, ndUsrD, map[[2]string]bool{
		{ndRegType, ndX}: true, {ndRepoType, ndXApp}: true, {ndRegType, ndY}: false, {ndRepoType, ndYApp}: false,
	})
	ndExpect(t, ctx, a, ndUsrE, map[[2]string]bool{{ndRepoType, ndXApp}: true, {ndRepoType, ndYApp}: true})

	// Метка контейнера сменилась — охват следует за ней без правки выдачи.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция: %v", err)
	}
	exec(t, ctx, tx, `UPDATE kaname.resource_mirror SET labels = '{"team":"a"}'::jsonb
	                    WHERE object_type = $1 AND object_id = $2`, catalogFormOf(t, ndRegType), ndY)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("коммит: %v", err)
	}
	ndExpect(t, ctx, a, ndUsrD, map[[2]string]bool{{ndRepoType, ndYApp}: true})
}
