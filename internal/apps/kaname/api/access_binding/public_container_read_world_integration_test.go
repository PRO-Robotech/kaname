// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// public_container_read_world_integration_test.go — посев П6 приёмки
// docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md
// (редакция 10, отпечаток 198db838d0a75b7f5b5bdbd5564bacec23a79cc00550a26e8830f3c6be61aac9;
// стадия S5, задача PRO-Robotech/kaname#856).
//
// П6 = П1 (`newSCWorld`, те же части, что корень службы `cmd/kaname/wiring.go`:
// дверь решения — `relverdict` под допуском `authzcascade.WrapAdmitted`,
// материализация — `reconcile.New`) плюс:
//   - реестры X, Y и репозитории `…/app`, зарегистрированные службой-владельцем
//     по внутреннему ребру (`RegisterResource`, путь проб
//     `register_resource_integration_test.go`);
//   - человек usr-D; роли `rol-reg-get` и `rol-proj-reg-read`; выдача
//     `rol-reg-get` человеку usr-B на X;
//   - доставленный манифест registry ПРЕЖНЕЙ редакции (kacho @a95248464,
//     `registry.prior-edition-fixture.yaml`) — состояние службы сегодня, Р10 шаг 1;
//   - ДОСТАВЛЕННЫЙ манифест registry новой редакции
//     (`internal/manifest/testdata/registry.public-read-fixture.yaml`), применённый
//     теми же глаголами, что путь старта `cmd/kaname/serve.go`: загрузка
//     (`manifest.Load`) → каталог (`modulecatalog.Applier.ApplyAll`) → роли
//     (`moduleroles.Applier.Apply`); каталожный факт для разворачивания выдачи —
//     из ЖИВЫХ строк базы после применения, как у старта.
//
// # Порядок несущий
//
// `newPCRWorld` строит всё, что от предмета S5 НЕ зависит, и доказывает живость
// фикстуры положительным контролем (выдача usr-B материализуется в `v_get` на X).
// Доставка новой редакции — ОТДЕЛЬНЫЙ шаг `deliverNewEdition`, его зовёт проба
// там, где начинается предмет: перед ним — контроль близнецом «без ключа»
// (тот же документ без одной строки загружается). Сломанная фикстура краснеет на
// контроле и не выдаёт себя за отсутствующий ключ, роль или `public_reader`.
//
// Вопрос `Check` задаёт модуль платформы с внутреннего слушателя (`moduleCtx`),
// как в пробах S1: субъект строкой, отношение — именем модели, объект — типом
// модели и id. «Материализована» — опрос раз в 200 мс с пределом 30 с (окно SC-13).

import (
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/manifest/roleexport"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/moduleroster"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Объекты П6. X и Y — реестры одного проекта; `…/app` — их репозитории,
// зарегистрированные до выдачи; `…/late` — после.
const (
	pcrRegType  = "registry_registry"
	pcrRepoType = "registry_repository"
	pcrRegTgt   = "registry.registries"
	pcrX        = "reg00000000000000001"
	pcrY        = "reg00000000000000002"
	pcrXApp     = pcrX + "/app"
	pcrYApp     = pcrY + "/app"
	pcrXLate    = pcrX + "/late"
	pcrYPub     = pcrY + "/pub"
	pcrAnon     = "system_class:anonymous"
)

// pcrWorld — П6 одной базы.
type pcrWorld struct {
	*scWorld
	reg      *internaliam.RegisterResourceUseCase
	internal *internaliam.Handler

	usrD                      domain.UserID
	rolRegGet, rolProjRegRead domain.RoleID
	grantB                    string // выдача rol-reg-get человеку usr-B на X

	facts     *catalog.Facts // каталожный факт из живых строк после последней доставки
	delivered bool
}

// newPCRWorld поднимает П6 БЕЗ доставки новой редакции и доказывает живость
// фикстуры. Доставка — `deliverNewEdition`.
func newPCRWorld(t *testing.T) *pcrWorld {
	t.Helper()
	w := newSCWorld(t)
	p := &pcrWorld{scWorld: w}
	p.usrD = mustSeedUser(t, w.ctx, w.pool, "scd")
	verifyAddresses(t, w.ctx, w.pool)

	p.reg = internaliam.NewRegisterResourceUseCase(
		kanamepg.NewFGAOutboxEmitter(),
		kanamepg.NewResourceMirrorEmitter(),
		kanamepg.NewPoolTxBeginner(w.pool),
		kanamepg.NewCatalogTypeReader(),
		kanamepg.NewPublicReadPublisher(),
		// Снятие регистрации снимает выдачи объекта (kaname#963) — тем же
		// каталожным фактом, что у мира после последней доставки.
		accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), pcrFacts{p}),
		kanamepg.NewRegistrationAudit(),
	).
		// Актор события аудита называет службу формой имени службы перечня — тем
		// же, которым ворота записи признают модуль (kaname#308, kaname#1005).
		WithModuleRoster(moduleroster.Roster(t))
	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations:           w.door,
		ClusterAdminChecker: w.door,
	})
	p.internal = internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), svc)
	p.deliverPriorEdition()

	// Реестры X, Y в prj-A (владелец объекта usr-A) и их репозитории `app`.
	p.registerRegistry(pcrX)
	p.registerRegistry(pcrY)
	p.registerRepository(pcrX, "app")
	p.registerRepository(pcrY, "app")

	p.rolRegGet = p.seedRole("pcr_reg_get",
		domain.Rules{{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"}}})
	p.rolProjRegRead = p.seedRole("pcr_proj_reg_read",
		domain.Rules{
			{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get", "list"}},
			{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get", "list"}},
		})

	// Держатель обычного `registries:get` (SC-61) — и положительный контроль
	// фикстуры: выдача материализуется в `v_get` на X.
	req := p.grantRequest(userSubject(w.usrB), p.rolRegGet, pcrXTarget())
	p.grantB = w.createDone(asUser(w.ctx, w.usrA), req, "П6: выдача rol-reg-get человеку usr-B на X")
	p.pollAsk(fmtSubject("user", string(w.usrB)), "v_get", pcrRegType, pcrX, true,
		"контроль фикстуры П6: выдача rol-reg-get человеку материализуется в v_get на X")
	return p
}

// seedRole — роль аккаунта с правилами, записанная ТРЕМЯ сторонами правила в
// одной транзакции, как у `RoleService.Create` (`internal/apps/kaname/api/role/create.go`):
// строка роли, селекторы (`ReplaceRuleSelectors`) и проекция глаголов
// (`ReplaceRoleVerbs` из каталожного факта). Без проекции глаголов ветвь выдач
// решения (`relverdict`, форма E) не видит роль вовсе, и `v_*` не выводится.
func (p *pcrWorld) seedRole(name string, rules domain.Rules) domain.RoleID {
	p.t.Helper()
	rid := domain.RoleID(ids.NewID(domain.PrefixRole))
	compiled, err := domain.CompileRules(rules)
	require.NoError(p.t, err, "посев роли %s: компиляция правил", name)
	w, err := p.repo.Writer(p.ctx)
	require.NoError(p.t, err)
	defer func() { _ = w.Rollback(p.ctx) }()
	inserted, err := w.RolesW().Insert(p.ctx, domain.Role{
		ID: rid, AccountID: p.accA, Name: domain.RoleName(name),
		Description: domain.Description("rules role " + name),
		Rules:       rules, Permissions: compiled,
	})
	require.NoError(p.t, err, "посев роли %s", name)
	sels := p.facts.GrantSelectors(inserted.Rules.MaterializingSelectors(), domain.TenantPolicy())
	require.NoError(p.t, w.RolesW().ReplaceRuleSelectors(p.ctx, inserted.ID, sels), "посев роли %s: селекторы", name)
	pairs := p.facts.RoleVerbsFromSelectors(sels, domain.TenantPolicy())
	require.NotEmptyf(p.t, pairs, "посев роли %s: проекция глаголов пуста — каталог не знает её типов", name)
	require.NoError(p.t, w.RolesW().ReplaceRoleVerbs(p.ctx, inserted.ID, pairs), "посев роли %s: проекция глаголов", name)
	require.NoError(p.t, w.Commit(p.ctx))
	return rid
}

// registerRegistry — регистрация реестра службой-владельцем: указатель на
// проект и владелец объекта usr-A. Цепь предков владелец называет сам
// (`parent_chain`, форма `pkg/ownerregister.ParentChain`): регистрация без цепи
// СТИРАЕТ предков, и объект выпадал бы из области выдачи.
func (p *pcrWorld) registerRegistry(id string) {
	p.t.Helper()
	obj := pcrRegType + ":" + id
	for _, r := range []*iamv1.RegisterResourceRequest{
		{SubjectId: "project:" + string(p.prjA), Relation: "project", Object: obj},
		{SubjectId: "user:" + string(p.usrA), Relation: "owner", Object: obj},
	} {
		r.ParentProjectId, r.ParentAccountId = string(p.prjA), string(p.accA)
		r.ParentChain = []string{"project:" + string(p.prjA), "account:" + string(p.accA)}
		require.NoErrorf(p.t, p.reg.Register(p.ctx, r), "П6: регистрация реестра %s (%s)", id, r.GetRelation())
	}
}

// registerRepository — регистрация репозитория службой-владельцем: указатель
// `parent` на свой реестр и владелец объекта usr-A.
func (p *pcrWorld) registerRepository(registry, name string) {
	p.t.Helper()
	obj := pcrRepoType + ":" + registry + "/" + name
	for _, r := range []*iamv1.RegisterResourceRequest{
		{SubjectId: pcrRegType + ":" + registry, Relation: "parent", Object: obj},
		{SubjectId: "user:" + string(p.usrA), Relation: "owner", Object: obj},
	} {
		r.ParentProjectId, r.ParentAccountId = string(p.prjA), string(p.accA)
		r.ParentChain = []string{pcrRegType + ":" + registry, "project:" + string(p.prjA), "account:" + string(p.accA)}
		require.NoErrorf(p.t, p.reg.Register(p.ctx, r), "регистрация репозитория %s/%s (%s)", registry, name, r.GetRelation())
	}
}

// pcrXTarget — цель «названные объекты»: только X.
func pcrXTarget() *iamv1.AccessTarget {
	return resourcesTarget(&iamv1.ResourceRef{Type: pcrRegTgt, Id: pcrX})
}

// grantRequest — тело выдачи на prj-A.
func (p *pcrWorld) grantRequest(sub *iamv1.Subject, role domain.RoleID, target *iamv1.AccessTarget) *iamv1.CreateAccessBindingRequest {
	return &iamv1.CreateAccessBindingRequest{
		Subjects:  []*iamv1.Subject{sub},
		RoleId:    string(role),
		ScopeType: "iam.project",
		ScopeId:   string(p.prjA),
		Target:    target,
	}
}

// pchRequest — тело «выдача ПЧ» П6 дословно.
func (p *pcrWorld) pchRequest() *iamv1.CreateAccessBindingRequest {
	return p.grantRequest(classSubject("anonymous"), publicreadfixture.PublicReadRoleID, pcrXTarget())
}

// deliverNewEdition — доставка манифеста registry новой редакции тем же путём,
// что старт. Перед предметом — контроль: тот же документ без строки ключа
// загружается (дельта — одна строка, её сверяет фикстура).
func (p *pcrWorld) deliverNewEdition(sc string) {
	p.t.Helper()
	require.False(p.t, p.delivered, "доставка новой редакции П6 зовётся один раз")
	doc, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	require.NoError(p.t, err, "фикстура П6")
	keyless, err := publicreadfixture.WithoutKey(doc)
	require.NoError(p.t, err, "фикстура П6: близнец без ключа")
	_, err = manifest.Load(keyless)
	require.NoError(p.t, err, "контроль фикстуры П6: новая редакция без ключа обязана загружаться")

	// ── Предмет S5 начинается здесь ──────────────────────────────────────────
	m, err := manifest.Load(doc)
	if err != nil {
		p.t.Fatalf("%s: доставка П6 — загрузчик отверг манифест registry новой редакции (ключ %s; предмета S5 нет): %v",
			sc, publicreadfixture.Key, err)
	}
	p.applyDelivered(sc+": доставка новой редакции", m)
	var n int
	require.NoError(p.t, p.pool.QueryRow(p.ctx, `SELECT count(*) FROM kaname.roles WHERE id = $1`,
		publicreadfixture.PublicReadRoleID).Scan(&n))
	require.Equalf(p.t, 1, n, "%s: доставка П6 — роли %s (%s) в базе нет после применения",
		sc, publicreadfixture.PublicReadRoleName, publicreadfixture.PublicReadRoleID)
	p.delivered = true
}

// deliverPriorEdition — то, что служба видит СЕГОДНЯ: манифест registry прежней
// редакции (kacho @a95248464), доставленный и применённый путём старта (Р10,
// шаг 1). Без него у каталога нет пообъектных действий registry, и выдача
// `rol-reg-get` материализуется лишь ярусом `viewer`, которого `v_get` реестра
// не читает: положительный контроль П6 был бы красным по фикстуре.
func (p *pcrWorld) deliverPriorEdition() {
	p.t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.PriorEditionFile)
	require.NoError(p.t, err, "фикстура П6: прежняя редакция")
	m, err := manifest.Load(doc)
	require.NoError(p.t, err, "фикстура П6: прежняя редакция обязана загружаться")
	p.applyDelivered("фикстура П6: доставка прежней редакции", m)
}

// applyDelivered — применение доставленного манифеста глаголами пути старта
// (`cmd/kaname/serve.go`): каталог → живые строки → роли; затем разворачивание
// выдачи и use-case'ы пересобираются с каталожным фактом из живых строк.
func (p *pcrWorld) applyDelivered(what string, m *manifest.Manifest) {
	p.t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	census, err := modulecatalog.NewApplier(kanamepg.NewCatalogWriteRepo(p.pool)).ApplyAll(p.ctx, []*manifest.Manifest{m})
	require.NoErrorf(p.t, err, "%s — применение каталога (%+v)", what, census)

	live, err := kanamepg.NewCatalogRepo(p.pool).ReadLiveCatalog(p.ctx)
	require.NoErrorf(p.t, err, "%s — живые строки каталога", what)
	facts, err := catalog.NewFacts(catalog.Halves{Live: live})
	require.NoErrorf(p.t, err, "%s — каталожный факт из живых строк", what)

	reg, err := seed.LoadPermissionRegistry(p.ctx, logger)
	require.NoErrorf(p.t, err, "%s — каталог прав", what)
	rows := reg.All()
	entries := make([]roleexport.CatalogEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, roleexport.CatalogEntry{
			FQN: r.FQN, RequiredRelation: r.RequiredRelation, ScopeObjectType: r.ScopeExtractor.ObjectType,
		})
	}
	attributed, _ := roleexport.Attribute(entries)
	rights, err := moduleroles.NewRightsExport(facts, attributed)
	require.NoErrorf(p.t, err, "%s — производитель правил роли", what)
	rep, err := moduleroles.NewApplier(moduleroles.NewRepoTxRunner(p.repo), rights).Apply(p.ctx, m, moduleroles.BootActorID)
	require.NoErrorf(p.t, err, "%s — применение ролей (%s)", what, rep)
	// Самолечение старта (`cmd/kaname/serve.go`): селекторы и проекция глаголов
	// системных ролей — применитель ролей их не пишет (шапка `moduleroles`).
	require.NoErrorf(p.t, seed.SyncAllSystemRoleSelectors(p.ctx, p.pool), "%s — селекторы системных ролей", what)
	_, err = seed.ReseedSystemRoleVerbs(p.ctx, p.repo, p.pool, facts, nil)
	require.NoErrorf(p.t, err, "%s — проекция глаголов системных ролей", what)
	p.facts = facts

	src := catalog.Fixed{F: facts}
	p.rec = reconcile.New(kanamepg.NewReconcileAdapter(p.pool, src), nil, src)
	create := accessbindingapp.NewCreateAccessBindingUseCase(p.repo, p.ops, src).
		WithRelationStore(p.door, nil).
		WithReconciler(p.rec)
	get := accessbindingapp.NewGetAccessBindingUseCase(p.repo).WithRelationStore(p.door, nil)
	del := accessbindingapp.NewDeleteAccessBindingUseCase(p.repo, p.ops).WithRelationStore(p.door, nil)
	p.ab = accessbindingapp.NewHandler(create, del, get, nil, nil, nil, nil)
	if p.reg != nil {
		p.reg = p.reg.WithObjectReconciler(p.rec, nil)
	}
}

// pcrAction — действие каталога для вопроса по отношению модели.
func pcrAction(modelType, relation string) string {
	res := map[string]string{pcrRegType: "registry.registries", pcrRepoType: "registry.repositories"}[modelType]
	return res + "." + relation[len("v_"):]
}

// ask — `AuthorizeService.Check` (публичная дверь решения).
func (p *pcrWorld) ask(subject, relation, modelType, id string) bool {
	p.t.Helper()
	resp, err := p.authz.Check(moduleCtx(), &iamv1.AuthorizeCheckRequest{
		Subject:          subject,
		Resource:         &iamv1.ResourceRef{Type: modelType, Id: id},
		Action:           pcrAction(modelType, relation),
		RequiredRelation: relation,
	})
	require.NoErrorf(p.t, err, "Check(%s, %s, %s:%s) не ответил", subject, relation, modelType, id)
	return resp.GetAllowed()
}

// askInternal — `InternalIAMService.Check` (им спрашивает плоскость данных реестра).
func (p *pcrWorld) askInternal(subject, relation, modelType, id string) bool {
	p.t.Helper()
	resp, err := p.internal.Check(moduleCtx(), &iamv1.CheckRequest{
		SubjectId: subject, Relation: relation, Object: modelType + ":" + id,
	})
	require.NoErrorf(p.t, err, "InternalIAMService.Check(%s, %s, %s:%s) не ответил", subject, relation, modelType, id)
	return resp.GetAllowed()
}

func (p *pcrWorld) requireAsk(subject, relation, modelType, id string, want bool, why string) {
	p.t.Helper()
	require.Equalf(p.t, want, p.ask(subject, relation, modelType, id),
		"%s: Check(%s, %s, %s:%s)", why, subject, relation, modelType, id)
}

// pollAsk — опрос `Check` раз в 200 мс до 30 с (окно материализации SC-13).
func (p *pcrWorld) pollAsk(subject, relation, modelType, id string, want bool, why string) {
	p.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	last := !want
	for {
		if last = p.ask(subject, relation, modelType, id); last == want {
			return
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	p.t.Fatalf("%s: Check(%s, %s, %s:%s) за 30 с не дошёл до allowed=%v (последний ответ %v)",
		why, subject, relation, modelType, id, want, last)
}

// pcrPair — вопрос «отношение × объект».
type pcrPair struct{ relation, modelType, id string }

func (q pcrPair) String() string { return fmt.Sprintf("%s %s:%s", q.relation, q.modelType, q.id) }

// sixPairs — шесть вопросов SC-60: v_get и v_list на X, `…/app`, `…/late`.
func sixPairs() []pcrPair {
	var out []pcrPair
	for _, o := range []pcrPair{{"", pcrRegType, pcrX}, {"", pcrRepoType, pcrXApp}, {"", pcrRepoType, pcrXLate}} {
		for _, rel := range []string{"v_get", "v_list"} {
			out = append(out, pcrPair{rel, o.modelType, o.id})
		}
	}
	return out
}

// pcrFacts — каталожный факт мира П6 после ПОСЛЕДНЕЙ доставки: доставка
// (`applyDelivered`) пересобирает факт, и отзыв по снятию регистрации обязан
// видеть тот же, что разворачивание выдачи.
type pcrFacts struct{ p *pcrWorld }

func (s pcrFacts) Facts() *catalog.Facts { return s.p.facts }
