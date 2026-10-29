// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicreadmodule_test

// public_read_module_world_integration_test.go — PM-03 и PM-04 приёмки
// docs/engineering/acceptance/public-read-container-of-a-module-type-is-admitted.md
// (редакция 3, kaname#866): выдача классу `anonymous` на контейнер типа ВНЕ
// канона открывает чтение его детей ровно тогда, когда роль несёт вложенное
// правило над ребёнком.
//
// Мир П2 (раздел «Как строится «Дано»»):
//   - модель процесса — канон плюс П1 с ключом (`TestMain` этого пакета);
//   - каталог `probemod` применён из П1 (`modulecatalog.Applier.ApplyAll`),
//     каталожный факт — из живых строк базы после применения, как на старте;
//   - аккаунт `acc-A` (владелец `usr-A`), проект `prj-A`, путь входа — одной
//     транзакцией;
//   - ящики `b1`, `b2` под `prj-A`, предметы `i1` в `b1` и `i3` в `b2`
//     регистрирует служба-владелец по внутреннему ребру
//     (`internaliam.RegisterResourceUseCase.Register` с `WithObjectReconciler`);
//   - роли ПЧ (`boxes [get, list]` с вложенным `items [get, list]`) и Я (без
//     вложенного) пишет продуктовый писатель: строка, селекторы, проекция глаголов.
//
// «Когда» — путь ND-08 соседа: строка выдачи в `access_bindings` и
// `access_binding_subjects` одним оператором, затем полный проход `reconcile.Reconciler.ReconcileBinding`.
// Вход API выдачи цель `probemod.boxes` не принимает (`domain.ValidTargetType`,
// п. 5 «Вне объёма», kaname#904) и в этих пробах не участвует.
//
// Вопрос `Check` задаёт модуль платформы с внутреннего слушателя (`moduleCtx`)
// через `AuthorizeService.Check`; дверь решения — та же, что у корня службы:
// `authzcascade.WrapAdmitted(relverdict.NewAsker(pool), personmarks.New(pool))`.
// «Материализована» — опрос раз в 200 мс с пределом 30 с. Отзыв —
// `AccessBindingService.Delete` от имени `usr-A`, исход операции читается из
// хранилища операций (его же читает `OperationService.Get`) до `done`.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	authorizeapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/authorize"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/PRO-Robotech/kaname/internal/testsupport/moduleroster"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Объекты и субъект мира П2.
const (
	pmBoxType   = "probemod_box"
	pmItemType  = "probemod_item"
	pmBoxTarget = "probemod.boxes"
	pmAnon      = "system_class:anonymous"
	pmB1, pmB2  = "b1", "b2"
	pmI1, pmI2  = "i1", "i2"
	pmI3        = "i3"

	// pmPollLimit и pmPollStep — окно материализации из раздела «Дано».
	pmPollLimit = 30 * time.Second
	pmPollStep  = 200 * time.Millisecond
	// pmOpLimit — предел ожидания операции отзыва.
	pmOpLimit = 10 * time.Second
)

// pmAction — действие каталога для вопроса по отношению модели.
var pmAction = map[string]string{pmBoxType: "probemod.boxes", pmItemType: "probemod.items"}

// p2 — мир П2 одной базы.
type p2 struct {
	t     *testing.T
	ctx   context.Context
	pool  *pgxpool.Pool
	repo  *kanamepg.Repository
	ops   operations.Repo
	rec   *reconcile.Reconciler
	ab    *accessbindingapp.Handler
	authz *authorizeapp.Handler
	reg   *internaliam.RegisterResourceUseCase
	facts *catalog.Facts

	usrA string
	accA string
	prjA string
}

// newP2 поднимает мир П2 без выдач.
func newP2(t *testing.T) *p2 {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	if err != nil {
		t.Fatalf("пул: %v", err)
	}
	t.Cleanup(pool.Close)
	w := &p2{
		t: t, ctx: ctx, pool: pool,
		repo: kanamepg.New(pool, nil),
		ops:  operations.NewRepo(pool, "kaname"),
		usrA: ids.NewID(domain.PrefixUser),
		accA: ids.NewID(domain.PrefixAccount),
		prjA: ids.NewID(domain.PrefixProject),
	}

	m, err := probemodManifest()
	if err != nil {
		t.Fatalf("фикстура П1: %v", err)
	}
	if _, err := modulecatalog.NewApplier(kanamepg.NewCatalogWriteRepo(pool)).ApplyAll(ctx, []*manifest.Manifest{m}); err != nil {
		t.Fatalf("применение каталога П1: %v", err)
	}
	live, err := kanamepg.NewCatalogRepo(pool).ReadLiveCatalog(ctx)
	if err != nil {
		t.Fatalf("живой каталог: %v", err)
	}
	if w.facts, err = catalog.NewFacts(catalog.Halves{Live: live}); err != nil {
		t.Fatalf("каталожный факт: %v", err)
	}

	w.seedTenant()

	door := authzcascade.WrapAdmitted(relverdict.NewAsker(pool), personmarks.New(pool))
	src := catalog.Fixed{F: w.facts}
	w.rec = reconcile.New(kanamepg.NewReconcileAdapter(pool, src), nil, src)
	create := accessbindingapp.NewCreateAccessBindingUseCase(w.repo, w.ops, src).
		WithRelationStore(door, nil).
		WithReconciler(w.rec)
	get := accessbindingapp.NewGetAccessBindingUseCase(w.repo).WithRelationStore(door, nil)
	// Снятие выдачи судит обработчик вопросом `v_delete` на объекте выдачи
	// (kaname#986, Р1а); в продукте владельцу его материализует авто-выдача роли
	// `owner`, которой посев аккаунта мимо глагола не заводит. Предмет мира —
	// публичное чтение модуля, а не материализация прав владельца, поэтому факт
	// продукта дан портом поверх той же двери (`ownerRemovalOver`).
	del := accessbindingapp.NewDeleteAccessBindingUseCase(w.repo, w.ops).
		WithRelationStore(ownerRemovalOver{inner: door, owner: w.usrA}, nil)
	w.ab = accessbindingapp.NewHandler(create, del, get, nil, nil, nil, nil)
	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations:           door,
		ClusterAdminChecker: door,
	})
	w.authz = authorizeapp.NewHandler(svc, authorizeapp.NewWhoAmIUseCase(nil, nil)).WithModuleRoster(moduleroster.Roster(t))
	w.reg = internaliam.NewRegisterResourceUseCase(
		kanamepg.NewFGAOutboxEmitter(),
		kanamepg.NewResourceMirrorEmitter(),
		kanamepg.NewPoolTxBeginner(pool),
		kanamepg.NewCatalogTypeReader(),
		kanamepg.NewPublicReadPublisher(),
		// Снятие регистрации снимает выдачи объекта (kaname#963) — тем же
		// каталожным источником, что у сверки мира.
		accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), src),
		kanamepg.NewRegistrationAudit(),
	).WithObjectReconciler(w.rec, nil)

	w.box(pmB1)
	w.box(pmB2)
	w.item(pmI1, pmB1)
	w.item(pmI3, pmB2)
	return w
}

// seedTenant — арендная обвязка ОДНОЙ транзакцией: владелец аккаунта —
// отложенный внешний ключ, а действующей личности нужен способ входа
// (kaname#608); оба судятся на фиксации.
func (w *p2) seedTenant() {
	w.t.Helper()
	tx, err := w.pool.Begin(w.ctx)
	if err != nil {
		w.t.Fatalf("транзакция посева: %v", err)
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO kaname.clusters (id, name) VALUES ('cluster_root', 'kacho') ON CONFLICT DO NOTHING`, nil},
		{`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, 'acc-a', $2)`, []any{w.accA, w.usrA}},
		{`INSERT INTO kaname.users (id, external_id, email, account_id, email_verified_at)
		  VALUES ($1, 'ext-a', 'usr-a@kacho.local', $2, now())`, []any{w.usrA, w.accA}},
		{`INSERT INTO kaname.projects (id, account_id, name) VALUES ($1, $2, 'prj-a')`, []any{w.prjA, w.accA}},
	} {
		if _, err := tx.Exec(w.ctx, q.sql, q.args...); err != nil {
			_ = tx.Rollback(w.ctx)
			w.t.Fatalf("посев (%s): %v", q.sql, err)
		}
	}
	activewayin.Seed(w.t, w.ctx, tx)
	if err := tx.Commit(w.ctx); err != nil {
		w.t.Fatalf("фиксация посева: %v", err)
	}
}

// register — регистрация объекта службой-владельцем; цепь предков —
// ближайший первым.
func (w *p2) register(r *iamv1.RegisterResourceRequest) {
	w.t.Helper()
	r.ParentProjectId, r.ParentAccountId = w.prjA, w.accA
	if err := w.reg.Register(w.ctx, r); err != nil {
		w.t.Fatalf("регистрация %s (%s): %v", r.GetObject(), r.GetRelation(), err)
	}
}

func (w *p2) box(id string) {
	w.t.Helper()
	w.register(&iamv1.RegisterResourceRequest{
		SubjectId: "project:" + w.prjA, Relation: "project", Object: pmBoxType + ":" + id,
		ParentChain: []string{"project:" + w.prjA, "account:" + w.accA},
	})
}

func (w *p2) item(id, box string) {
	w.t.Helper()
	w.register(&iamv1.RegisterResourceRequest{
		SubjectId: pmBoxType + ":" + box, Relation: "box", Object: pmItemType + ":" + id,
		ParentChain: []string{pmBoxType + ":" + box, "project:" + w.prjA, "account:" + w.accA},
	})
}

// role — роль аккаунта, записанная продуктовым писателем ТРЕМЯ сторонами
// правила в одной транзакции: строка, селекторы и проекция глаголов из
// каталожного факта. Без проекции ветвь выдач решения роль не видит.
func (w *p2) role(name string, rules domain.Rules) domain.RoleID {
	w.t.Helper()
	compiled, err := domain.CompileRules(rules)
	if err != nil {
		w.t.Fatalf("компиляция роли %s: %v", name, err)
	}
	wr, err := w.repo.Writer(w.ctx)
	if err != nil {
		w.t.Fatalf("писатель: %v", err)
	}
	defer func() { _ = wr.Rollback(w.ctx) }()
	r, err := wr.RolesW().Insert(w.ctx, domain.Role{
		ID: domain.RoleID(ids.NewID(domain.PrefixRole)), AccountID: domain.AccountID(w.accA),
		Name: domain.RoleName(name), Description: "pm", Rules: rules, Permissions: compiled,
	})
	if err != nil {
		w.t.Fatalf("роль %s: %v", name, err)
	}
	// Глаголы каждого правила вычисляет каталог мира (kaname#878), как в
	// продуктовом создании роли: селектор без них писатель отвергает.
	sels := w.facts.GrantSelectors(r.Rules.MaterializingSelectors(), domain.TenantPolicy())
	if err := wr.RolesW().ReplaceRuleSelectors(w.ctx, r.ID, sels); err != nil {
		w.t.Fatalf("селекторы %s: %v", name, err)
	}
	pairs := w.facts.RoleVerbsFromSelectors(sels, domain.TenantPolicy())
	if len(pairs) == 0 {
		w.t.Fatalf("проекция глаголов роли %s пуста — каталог П1 не знает её типов", name)
	}
	if err := wr.RolesW().ReplaceRoleVerbs(w.ctx, r.ID, pairs); err != nil {
		w.t.Fatalf("проекция глаголов %s: %v", name, err)
	}
	if err := wr.Commit(w.ctx); err != nil {
		w.t.Fatalf("фиксация роли %s: %v", name, err)
	}
	return r.ID
}

// grantAnonOnB1 — строка «выдача ПЧ-м» с ролью role и разворачивание по её id;
// отдаёт id выдачи.
//
// Строка выдачи и её набор субъектов ложатся ОДНИМ оператором
// (`bindingset.With`): отложенная проверка `access_bindings_carry_a_subject`
// (kaname#902) отвергает фиксацию, оставившую выдачу без набора, а две
// вставки вне явной транзакции — две фиксации. Так пишет и продукт: набор —
// той же транзакцией, что строка выдачи.
func (w *p2) grantAnonOnB1(role domain.RoleID) domain.AccessBindingID {
	w.t.Helper()
	id := ids.NewID(domain.PrefixAccessBinding)
	if _, err := w.pool.Exec(w.ctx, bindingset.With(`
		INSERT INTO kaname.access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id, status, target)
		VALUES ($1, 'system_class', 'anonymous', $2, 'project', $3, 'ACTIVE', $4::jsonb)`),
		id, string(role), w.prjA, `{"resources":[{"type":"`+pmBoxTarget+`","id":"`+pmB1+`"}]}`); err != nil {
		w.t.Fatalf("строка выдачи и её набор субъектов: %v", err)
	}
	if err := w.rec.ReconcileBinding(w.ctx, domain.AccessBindingID(id)); err != nil {
		w.t.Fatalf("разворачивание выдачи %s завершилось ошибкой: %v", id, err)
	}
	return domain.AccessBindingID(id)
}

// moduleCtx — вызывающий `Check` — проверенный модуль платформы (внутренний
// слушатель).
func moduleCtx() context.Context {
	return grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc", true)
}

// pmQ — вопрос «отношение × объект» от класса `anonymous`.
type pmQ struct{ rel, typ, id string }

func (q pmQ) String() string { return fmt.Sprintf("%s %s:%s", q.rel, q.typ, q.id) }

func (w *p2) ask(q pmQ) bool {
	w.t.Helper()
	resp, err := w.authz.Check(moduleCtx(), &iamv1.AuthorizeCheckRequest{
		Subject:          pmAnon,
		Resource:         &iamv1.ResourceRef{Type: q.typ, Id: q.id},
		Action:           pmAction[q.typ] + "." + q.rel[len("v_"):],
		RequiredRelation: q.rel,
	})
	if err != nil {
		w.t.Fatalf("Check(%s, %s) не ответил: %v", pmAnon, q, err)
	}
	return resp.GetAllowed()
}

// poll — опрос `Check` до want в окне материализации.
func (w *p2) poll(q pmQ, want bool, why string) {
	w.t.Helper()
	deadline := time.Now().Add(pmPollLimit)
	last := !want
	for {
		if last = w.ask(q); last == want {
			return
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(pmPollStep)
	}
	w.t.Fatalf("%s: Check(%s, %s) за %s не дошёл до allowed=%v (последний ответ %v)",
		why, pmAnon, q, pmPollLimit, want, last)
}

// requireDenied — вопрос, который после материализации обязан дать `false`.
func (w *p2) requireDenied(q pmQ, why string) {
	w.t.Helper()
	if w.ask(q) {
		w.t.Errorf("%s: Check(%s, %s) = true, ждали false", why, pmAnon, q)
	}
}

// revoke — «вызов отзыва»: `AccessBindingService.Delete` от имени `usr-A`,
// операция доведена до `done` без `error`.
func (w *p2) revoke(id domain.AccessBindingID) {
	w.t.Helper()
	op, err := w.ab.Delete(operations.WithPrincipal(w.ctx, operations.Principal{Type: "user", ID: w.usrA}),
		&iamv1.DeleteAccessBindingRequest{AccessBindingId: string(id)})
	if err != nil {
		w.t.Fatalf("отзыв выдачи %s: синхронный отказ: %v", id, err)
	}
	deadline := time.Now().Add(pmOpLimit)
	for {
		got, err := w.ops.Get(w.ctx, op.GetId())
		if err != nil {
			w.t.Fatalf("операция отзыва %s: %v", op.GetId(), err)
		}
		if got.Done {
			if got.Error != nil {
				w.t.Fatalf("операция отзыва %s завершилась ошибкой %+v", op.GetId(), got.Error)
			}
			return
		}
		if time.Now().After(deadline) {
			w.t.Fatalf("операция отзыва %s не дошла до done за %s", op.GetId(), pmOpLimit)
		}
		time.Sleep(pmPollStep)
	}
}

// rulesNested — роль ПЧ: ящики с вложенным правилом над предметами.
func rulesNested() domain.Rules {
	return domain.Rules{{Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get", "list"},
		Children: []domain.Rule{{Resources: []string{"items"}, Verbs: []string{"get", "list"}}}}}
}

// rulesBoxOnly — роль Я: ящики без вложенного правила. Отличие от ПЧ — один
// факт.
func rulesBoxOnly() domain.Rules {
	return domain.Rules{{Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get", "list"}}}
}

// PM-03: выдача анониму на названный контейнер открывает чтение его детей,
// будущий ребёнок наследует, отзыв снимает всё открытое.
func TestPM03_AnonymousGrantOnNamedContainerOpensItsChildren(t *testing.T) {
	w := newP2(t)
	id := w.grantAnonOnB1(w.role("pm_read", rulesNested()))

	opened := []pmQ{
		{"v_get", pmItemType, pmI1}, {"v_list", pmItemType, pmI1},
		{"v_get", pmBoxType, pmB1}, {"v_list", pmBoxType, pmB1},
	}
	for _, q := range opened {
		w.poll(q, true, "PM-03: выдача ПЧ-м открывает чтение")
	}
	for _, q := range []pmQ{
		{"v_get", pmItemType, pmI3}, {"v_list", pmItemType, pmI3},
		{"v_update", pmItemType, pmI1}, {"v_delete", pmItemType, pmI1},
		{"v_update", pmBoxType, pmB1}, {"v_delete", pmBoxType, pmB1},
	} {
		w.requireDenied(q, "PM-03: вне контейнера и пишущие глаголы закрыты")
	}

	// И (будущий ребёнок): выдача не меняется.
	w.item(pmI2, pmB1)
	future := pmQ{"v_get", pmItemType, pmI2}
	w.poll(future, true, "PM-03 «И»: будущий ребёнок b1 наследует чтение")

	// И (отзыв): все бывшие true — false.
	w.revoke(id)
	for _, q := range append(opened, future) {
		w.poll(q, false, "PM-03 «И»: отзыв снимает открытое")
	}
}

// PM-04: роль без вложенного правила детей классу не открывает. Близнец PM-03,
// отличие — один факт: вложенное правило над `items`.
func TestPM04_RoleWithoutChildRuleOpensNoChildren(t *testing.T) {
	w := newP2(t)
	w.grantAnonOnB1(w.role("pm_box", rulesBoxOnly()))

	w.poll(pmQ{"v_get", pmBoxType, pmB1}, true, "PM-04: выдача Я открывает сам контейнер")
	for _, q := range []pmQ{{"v_get", pmItemType, pmI1}, {"v_list", pmItemType, pmI1}} {
		w.requireDenied(q, "PM-04: без вложенного правила ребёнок закрыт")
	}
}

// ownerRemovalOver — дверь решения мира с одним фактом продукта сверху: владелец
// аккаунта держит отношение удаления на объектах выдач (в продукте его
// материализует авто-выдача роли `owner`, kaname#986 Р1а). Прочие вопросы —
// настоящей двери.
type ownerRemovalOver struct {
	inner interface {
		Check(ctx context.Context, subject, relation, object string) (bool, error)
	}
	owner string
}

func (o ownerRemovalOver) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	if subject == "user:"+o.owner && relation == accessbindingapp.RemovalRelation &&
		strings.HasPrefix(object, accessbindingapp.RemovalObjectType+":") {
		return true, nil
	}
	return o.inner.Check(ctx, subject, relation, object)
}
