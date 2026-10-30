// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package nesteddepth_test

// nested_depth_integration_test.go — ВЛОЖЕННОЕ ПРАВИЛО ДОСТАЁТ ДО ПОТОМКА НА
// ЛЮБОЙ ГЛУБИНЕ (kaname#874, ND-08 приёмки
// docs/engineering/acceptance/nested-rule-reaches-descendants-of-a-named-container.md,
// редакция 2).
//
// П3: ящики b1, b2 (контейнер; указатель на аккаунт — почему, сказано у
// `probemodManifest`), предметы i1 в b1 и i3 в b2,
// ярлыки t1 в i1 и t3 в i3. Роль `probemod.reader` — `boxes [get, list]` с
// вложенным правилом над ВНУКОМ `tags`; близнец с именами `[b1]` у
// правила-владельца строится здесь же (`p3Rules`): манифест модуля конкретных
// объектов не называет (kaname#965). Каталог применён применителем манифеста, роль
// записана продуктовым писателем, вопросы задаёт `relverdict.NewAsker` — тот же
// вход, что у корня службы. Выдача пишется строкой: вход API цель `probemod` не
// принимает (`ValidTargetType` — закрытый перечень), поэтому здесь
// утверждается решение (материализатор — пробой пакета `reconcile`).

import (
	"context"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
)

type p3 struct {
	t    *testing.T
	ctx  context.Context
	pool *pgxpool.Pool
	a    *relverdict.Asker
}

func (w *p3) exec(sql string, args ...any) {
	w.t.Helper()
	if _, err := w.pool.Exec(w.ctx, sql, args...); err != nil {
		w.t.Fatalf("посев (%s): %v", sql, err)
	}
}

func (w *p3) object(model, dotted, id string, chain ...[2]string) {
	w.t.Helper()
	w.exec(`INSERT INTO kaname.resource_mirror (object_type, object_id, parent_account_id)
	        VALUES ($1, $2, 'acc-1')`, dotted, id)
	for i, c := range chain {
		w.exec(`INSERT INTO kaname.resource_parent_edge (object_type, object_id, parent_type, parent_id, depth)
		        VALUES ($1, $2, $3, $4, $5)`, model, id, c[0], c[1], i+1)
	}
}

// newP3 — мир П3 без выдач.
func newP3(t *testing.T) *p3 {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	if err != nil {
		t.Fatalf("пул: %v", err)
	}
	t.Cleanup(pool.Close)
	w := &p3{t: t, ctx: ctx, pool: pool, a: relverdict.NewAsker(pool)}

	m, err := probemodManifest()
	if err != nil {
		t.Fatalf("фикстура П3: %v", err)
	}
	census, err := modulecatalog.NewApplier(kanamepg.NewCatalogWriteRepo(pool)).ApplyAll(ctx, []*manifest.Manifest{m})
	if err != nil {
		t.Fatalf("применение каталога П3: %v", err)
	}
	if len(census.NotApplied) != 0 {
		t.Fatalf("применение каталога П3: неприменённые модули: %+v", census.NotApplied)
	}

	// Арендная обвязка — ОДНОЙ транзакцией: владелец аккаунта — отложенный
	// внешний ключ, а действующей личности нужен способ входа (kaname#608); оба
	// судятся на фиксации.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция посева: %v", err)
	}
	for _, q := range []string{
		`INSERT INTO kaname.clusters (id, name) VALUES ('cluster_root', 'kacho') ON CONFLICT DO NOTHING`,
		`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ('acc-1', 'acc', 'usr-1')`,
		`INSERT INTO kaname.users (id, external_id, email, account_id) VALUES ('usr-1', 'ext-1', 'usr-1@kacho.local', 'acc-1')`,
		`INSERT INTO kaname.projects (id, account_id, name) VALUES ('prj-1', 'acc-1', 'prj')`,
	} {
		if _, err := tx.Exec(ctx, q); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("посев (%s): %v", q, err)
		}
	}
	activewayin.Seed(t, ctx, tx)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("фиксация посева: %v", err)
	}

	up := [][2]string{{"account", "acc-1"}}
	// Цепь — как её шлёт владелец: ближайший предок первым.
	w.object("probemod_box", "probemod.boxes", "b1", up...)
	w.object("probemod_box", "probemod.boxes", "b2", up...)
	w.object("probemod_item", "probemod.items", "i1", append([][2]string{{"probemod_box", "b1"}}, up...)...)
	w.object("probemod_item", "probemod.items", "i3", append([][2]string{{"probemod_box", "b2"}}, up...)...)
	w.object("probemod_tag", "probemod.tags", "t1", append([][2]string{{"probemod_item", "i1"}, {"probemod_box", "b1"}}, up...)...)
	w.object("probemod_tag", "probemod.tags", "t3", append([][2]string{{"probemod_item", "i3"}, {"probemod_box", "b2"}}, up...)...)
	return w
}

// role — роль аккаунта с правилами, записанная продуктовым писателем; проекция
// глаголов — из каталожного факта живых строк.
func (w *p3) role(id string, rules domain.Rules) {
	w.t.Helper()
	live, err := kanamepg.NewCatalogRepo(w.pool).ReadLiveCatalog(w.ctx)
	if err != nil {
		w.t.Fatalf("живой каталог: %v", err)
	}
	facts, err := catalog.NewFacts(catalog.Halves{Live: live})
	if err != nil {
		w.t.Fatalf("каталожный факт: %v", err)
	}
	wr, err := kanamepg.New(w.pool, nil).Writer(w.ctx)
	if err != nil {
		w.t.Fatalf("писатель: %v", err)
	}
	defer func() { _ = wr.Rollback(w.ctx) }()
	compiled, err := domain.CompileRules(rules)
	if err != nil {
		w.t.Fatalf("компиляция: %v", err)
	}
	r, err := wr.RolesW().Insert(w.ctx, domain.Role{ID: domain.RoleID(id), AccountID: "acc-1",
		Name: domain.RoleName("nd08_" + id[len(id)-2:]), Description: "nd08", Rules: rules, Permissions: compiled})
	if err != nil {
		w.t.Fatalf("роль %s: %v", id, err)
	}
	sels := facts.GrantSelectors(r.Rules.MaterializingSelectors(), domain.TenantPolicy())
	if err := wr.RolesW().ReplaceRuleSelectors(w.ctx, r.ID, sels); err != nil {
		w.t.Fatalf("селекторы %s: %v", id, err)
	}
	pairs := facts.RoleVerbsFromSelectors(sels, domain.TenantPolicy())
	if len(pairs) == 0 {
		w.t.Fatalf("проекция глаголов роли %s пуста — каталог П3 не знает её типов", id)
	}
	if err := wr.RolesW().ReplaceRoleVerbs(w.ctx, r.ID, pairs); err != nil {
		w.t.Fatalf("проекция глаголов %s: %v", id, err)
	}
	if err := wr.Commit(w.ctx); err != nil {
		w.t.Fatalf("коммит роли %s: %v", id, err)
	}
}

func (w *p3) bind(id, role, target string) {
	w.t.Helper()
	// Выдача и строка её набора — одним оператором: отдельные операторы вне
	// транзакции фиксировали бы выдачу без набора, и база её отвергает (kaname#902).
	w.exec(bindingset.With(`INSERT INTO kaname.access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id, status, target)
	        VALUES ($1, 'user', 'usr-1', $2, 'account', 'acc-1', 'ACTIVE', $3::jsonb)`), id, role, target)
}

func (w *p3) allowed(typ, id string) bool {
	w.t.Helper()
	got, err := w.a.Allowed(w.ctx, "user:usr-1", typ, id, "v_get", nil)
	if err != nil {
		w.t.Fatalf("Allowed(%s:%s): %v", typ, id, err)
	}
	return got
}

func p3Rules(names []string) domain.Rules {
	return domain.Rules{{Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get", "list"},
		ResourceNames: names, Children: []domain.Rule{{Resources: []string{"tags"}, Verbs: []string{"get", "list"}}}}}
}

func boxTarget(id string) string {
	return `{"resources":[{"type":"probemod.boxes","id":"` + id + `"}]}`
}

// ND-08: внук t1 (предок b1 на глубине 2) — да; t3 (предок b2) — нет; i1 —
// нет (правила над items нет). Близнец — цель b2.
func TestNestedDepth_ND08_GrandchildOfTheNamedContainer(t *testing.T) {
	for _, c := range []struct {
		box    string
		t1, t3 bool
	}{{"b1", true, false}, {"b2", false, true}} {
		t.Run("цель "+c.box, func(t *testing.T) {
			w := newP3(t)
			w.role("rol-nd08-rd", p3Rules(nil))
			w.bind("acb-nd08", "rol-nd08-rd", boxTarget(c.box))
			if got := w.allowed("probemod_tag", "t1"); got != c.t1 {
				t.Errorf("Allowed(t1) = %v, ждали %v", got, c.t1)
			}
			if got := w.allowed("probemod_tag", "t3"); got != c.t3 {
				t.Errorf("Allowed(t3) = %v, ждали %v", got, c.t3)
			}
			if w.allowed("probemod_item", "i1") {
				t.Errorf("Allowed(i1) = true: правила над items нет")
			}
			many, err := w.a.AllowedMany(w.ctx, "user:usr-1", "probemod_tag", []string{"t1", "t3"}, "v_get", nil)
			if err != nil || !slices.Equal(many, []bool{c.t1, c.t3}) {
				t.Errorf("AllowedMany([t1 t3]) = %v (%v), ждали [%v %v]", many, err, c.t1, c.t3)
			}
		})
	}
}

// ND-08 «И» (B1 = (б)): цель — вся область. Владелец якорем — t1 и t3;
// владелец с именами [b1] — только t1.
func TestNestedDepth_ND08_WholeScopeFollowsTheOwnersArm(t *testing.T) {
	for _, c := range []struct {
		name   string
		names  []string
		t1, t3 bool
	}{{"probemod.reader", nil, true, true}, {"probemod.reader_b1", []string{"b1"}, true, false}} {
		t.Run(c.name, func(t *testing.T) {
			w := newP3(t)
			w.role("rol-nd08-rx", p3Rules(c.names))
			w.bind("acb-nd08", "rol-nd08-rx", `{"allInScope": true}`)
			if got := w.allowed("probemod_tag", "t1"); got != c.t1 {
				t.Errorf("Allowed(t1) = %v, ждали %v", got, c.t1)
			}
			if got := w.allowed("probemod_tag", "t3"); got != c.t3 {
				t.Errorf("Allowed(t3) = %v, ждали %v", got, c.t3)
			}
			ids, complete, err := w.a.Objects(w.ctx, "user:usr-1", "probemod_tag", []string{"v_get"}, 100)
			if err != nil || !complete {
				t.Fatalf("Objects: %v (%v)", err, complete)
			}
			var want []string
			if c.t1 {
				want = append(want, "t1")
			}
			if c.t3 {
				want = append(want, "t3")
			}
			slices.Sort(ids)
			if !slices.Equal(ids, want) {
				t.Errorf("Objects(probemod_tag) = %v, ждали %v", ids, want)
			}
		})
	}
}
