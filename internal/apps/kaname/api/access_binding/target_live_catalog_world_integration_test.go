// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// target_live_catalog_world_integration_test.go — пробы-держатели S1 (integration)
// приёмки docs/engineering/acceptance/access-target-names-live-catalog-types.md
// (редакция 2, отпечаток 18360285461ee74e59c92a0445fcff9d313e8c2e3ed99bb56b4efce209ff9bd9;
// задача PRO-Robotech/kaname#904): цель выдачи принимает типы ЖИВОГО каталога,
// включая типы модулей; тип судится синхронно по снимку и повторно в транзакции
// записи.
//
// # Мир М2
//
// Части — те же, что у мира П6 (`newPCRWorld`, корень службы `cmd/kaname/wiring.go`):
// аккаунт acc-A с владельцем usr-A, проекты prj-A и prj-B, получатели usr-D и
// usr-E; доставка фикстуры probemod (`probemod.public-read-fixture.yaml`) путём
// старта (`applyDelivered`: каталог → живые строки → роли → ручка на факте из
// живых строк). Объекты `probemod_box` регистрирует служба-владелец по
// внутреннему ребру (`RegisterResource`), когда сценарий это говорит.
//
// Фикстура доставляется БЕЗ ключа `publicReadToChildren` (`publicreadfixture.WithoutKey`),
// и модель процесса собирается из неё же, как на старте (`installComposedModel`;
// здесь — `TestMain`, `installATCModel`):
// типа `probemod_box` сборка не знает, и вопрос `Check` о нём отвечает лишь
// модель, собранная из доставленного манифеста. Допуск модели отвергает ключ
// публичного чтения у модуля вне канона (подстановочная запись субъекта
// `system_class`, находки Д3 — тот же довод у `nesteddepth`), а публичное
// чтение здесь не предмет: его держат пробы материализатора и мира П6.
//
// # М3 — снятие `probemod.items`
//
// Применение той же фикстуры без ресурса `items` применителем пути старта
// (`modulecatalog.NewApplier(...).ApplyAll`). «Снимок не обновлён» — ручка
// остаётся на факте, построенном до снятия (окно отставания снимка, П5).

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const (
	atcBoxType  = "probemod_box"
	atcBoxes    = "probemod.boxes"
	atcItems    = "probemod.items"
	atcB1       = "box0000000000000001"
	atcB2       = "box0000000000000002"
	atcItemsCut = "\n  - name: items\n"
)

// atcT1 / atcT2 — тексты Р3 приёмки дословно.
func atcT1(typ string) string {
	return `Illegal argument target.resources[].type "` + typ +
		`" (not a live entry of the platform resource catalog; grantable types are published by GET /iam/v1/permissionCatalog)`
}

func atcT2(typ string) string {
	return "target type " + typ +
		" is not a live entry of the platform resource catalog; grantable types are published by GET /iam/v1/permissionCatalog"
}

// atcWorld — мир М2 одной базы.
type atcWorld struct {
	*pcrWorld
	usrE domain.UserID
	prjB domain.ProjectID
	doc  []byte // фикстура probemod целиком

	rolBoxGet, rolBoxRead, rolBoxUpd, rolItemGet, rolPoolGet, rolInstGet, rolInstBox domain.RoleID
}

// newATCWorld поднимает М2. Объекты не регистрируются: это делает сценарий.
func newATCWorld(t *testing.T) *atcWorld {
	t.Helper()
	w := newSCWorld(t)
	p := &pcrWorld{scWorld: w}
	p.usrD = mustSeedUser(t, w.ctx, w.pool, "atcd")
	a := &atcWorld{pcrWorld: p}
	a.usrE = mustSeedUser(t, w.ctx, w.pool, "atce")
	verifyAddresses(t, w.ctx, w.pool)
	a.prjB = seedProjectInAccount(t, w.ctx, w.pool, w.accA, "prj-atc-b")

	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations:           w.door,
		ClusterAdminChecker: w.door,
	})
	p.internal = internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), svc)
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
		kanamepg.NewRegistrationScopeReader(),
	)
	doc, err := atcProbemodDoc()
	require.NoError(t, err, "М2: фикстура probemod без ключа публичного чтения")
	a.doc = doc
	p.applyDelivered("М2: доставка probemod", a.manifest(false))

	a.rolBoxGet = p.seedRole("atc_box_get", domain.Rules{{Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get"}}})
	a.rolBoxRead = p.seedRole("atc_box_read", domain.Rules{{Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get", "list"}}})
	a.rolBoxUpd = p.seedRole("atc_box_upd", domain.Rules{{Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get", "update"}}})
	a.rolItemGet = p.seedRole("atc_item_get", domain.Rules{{Module: "probemod", Resources: []string{"items"}, Verbs: []string{"get"}}})
	a.rolPoolGet = p.seedRole("atc_pool_get", domain.Rules{{Module: "vpc", Resources: []string{"addressPool"}, Verbs: []string{"get"}}})
	a.rolInstGet = p.seedRole("atc_inst_get", domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}}})
	a.rolInstBox = p.seedRole("atc_inst_box", domain.Rules{
		{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}},
		{Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get"}},
	})
	return a
}

// manifest — фикстура probemod М2; withoutItems=true — она же без ресурса
// `items` (М3). Дельта сверяется: снята ровно секция `items`, ничего не добавлено.
func (a *atcWorld) manifest(withoutItems bool) *manifest.Manifest {
	a.t.Helper()
	doc := a.doc
	if withoutItems {
		i := strings.Index(string(a.doc), atcItemsCut)
		require.Greater(a.t, i, 0, "М3: секции items в фикстуре нет")
		doc = append([]byte{}, a.doc[:i+1]...)
		removed, added := publicreadfixture.Delta(a.doc, doc)
		require.Empty(a.t, added, "М3: близнец что-то добавил")
		require.NotEmpty(a.t, removed, "М3: близнец ничего не снял")
		for _, l := range removed {
			require.Falsef(a.t, strings.Contains(l, "boxes") || strings.Contains(l, "objectType: probemod_box"),
				"М3: снята строка ресурса boxes: %q", l)
		}
	}
	m, err := manifest.Load(doc)
	require.NoError(a.t, err, "загрузчик отверг фикстуру probemod (без items=%v)", withoutItems)
	return m
}

// atcProbemodDoc — фикстура probemod М2: без ключа `publicReadToChildren` (довод
// — шапка файла). Тот же документ доставляет мир и из него же `TestMain`
// собирает модель процесса (`installATCModel`).
func atcProbemodDoc() ([]byte, error) {
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	if err != nil {
		return nil, err
	}
	return publicreadfixture.WithoutKey(doc)
}

// installATCModel — модель процесса из канона и доставленного probemod теми же
// глаголами, что старт (`cmd/kaname/model_compose.go`, `installComposedModel`):
// композиция → допуск → установка. Зовёт её `TestMain` ДО первой пробы: модель
// глобальна для двери решения и после первого чтения не заменяется
// (`authzmodel.Install`). Собранная из канона и probemod, она — надмножество
// канона, то есть ровно то, что служба видит на старте с доставленным модулем.
func installATCModel() error {
	doc, err := atcProbemodDoc()
	if err != nil {
		return fmt.Errorf("фикстура probemod: %w", err)
	}
	m, err := manifest.Load(doc)
	if err != nil {
		return fmt.Errorf("фикстура probemod: %w", err)
	}
	composed, _, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	if err != nil {
		return fmt.Errorf("композиция модели: %w", err)
	}
	adm, err := authzmodel.Admit(composed)
	if err != nil {
		return fmt.Errorf("допуск модели: %w", err)
	}
	if len(adm.Findings) > 0 {
		return fmt.Errorf("допуск модели отверг её (%s): %v", adm.Census(), adm.Findings)
	}
	return authzmodel.Install(composed)
}

// withdrawItemsInDB — М3 в базе, ручка остаётся на прежнем снимке.
func (a *atcWorld) withdrawItemsInDB() {
	a.t.Helper()
	_, err := modulecatalog.NewApplier(kanamepg.NewCatalogWriteRepo(a.pool)).
		ApplyAll(a.ctx, []*manifest.Manifest{a.manifest(true)})
	require.NoError(a.t, err, "М3: снятие probemod.items")
	require.False(a.t, a.itemsLiveInDB(), "М3: строка probemod.items в базе осталась живой")
}

func (a *atcWorld) itemsLiveInDB() bool {
	a.t.Helper()
	var live bool
	require.NoError(a.t, a.pool.QueryRow(a.ctx,
		`SELECT live FROM kaname.catalog_resource WHERE dotted = $1`, atcItems).Scan(&live))
	return live
}

// registerBox — регистрация `probemod_box:<id>` в prj-A службой-владельцем:
// указатель области. Кортежа `owner` нет: у типа `probemod_box` фикстуры нет
// отношения `owner`, его запись `writes` объявить нечем, и закрытая политика
// записи модуля (kaname#982) такой кортеж отвергает — предмет мира в нём не
// нуждается (выдачи судят цель, а не владельца).
func (a *atcWorld) registerBox(id string) {
	a.t.Helper()
	obj := atcBoxType + ":" + id
	for _, r := range []*iamv1.RegisterResourceRequest{
		{SubjectId: "project:" + string(a.prjA), Relation: "project", Object: obj},
	} {
		r.ParentProjectId, r.ParentAccountId = string(a.prjA), string(a.accA)
		r.ParentChain = []string{"project:" + string(a.prjA), "account:" + string(a.accA)}
		require.NoErrorf(a.t, a.reg.Register(a.ctx, r), "регистрация %s (%s)", obj, r.GetRelation())
	}
}

// req — тело выдачи В(получатель, роль, область-проект, цель).
func (a *atcWorld) req(sub *iamv1.Subject, role domain.RoleID, prj domain.ProjectID, refs ...*iamv1.ResourceRef) *iamv1.CreateAccessBindingRequest {
	return &iamv1.CreateAccessBindingRequest{
		Subjects:  []*iamv1.Subject{sub},
		RoleId:    string(role),
		ScopeType: "iam.project",
		ScopeId:   string(prj),
		Target:    resourcesTarget(refs...),
	}
}

func rr(typ, id string) *iamv1.ResourceRef { return &iamv1.ResourceRef{Type: typ, Id: id} }

// requireSync — синхронный отказ: код и текст дословно.
func (a *atcWorld) requireSync(req *iamv1.CreateAccessBindingRequest, code codes.Code, msg, what string) {
	a.t.Helper()
	op, err := a.ab.Create(asUser(a.ctx, a.usrA), req)
	require.Errorf(a.t, err, "%s: синхронного отказа нет, заведена операция %s", what, op.GetId())
	st, ok := status.FromError(err)
	require.Truef(a.t, ok, "%s: ответ не gRPC-статус: %v", what, err)
	require.Equalf(a.t, code, st.Code(), "%s: код (%q)", what, st.Message())
	require.Equalf(a.t, msg, st.Message(), "%s: текст отказа", what)
}

// opOf — синхронный ответ — `Operation`; отдаёт её id и id выдачи из метаданных.
func (a *atcWorld) opOf(req *iamv1.CreateAccessBindingRequest, what string) (opID, bindingID string) {
	a.t.Helper()
	op, err := a.ab.Create(asUser(a.ctx, a.usrA), req)
	require.NoErrorf(a.t, err, "%s: синхронный отказ создания", what)
	var md iamv1.CreateAccessBindingMetadata
	require.NoError(a.t, op.GetMetadata().UnmarshalTo(&md), "%s: метаданные операции", what)
	return op.GetId(), md.GetAccessBindingId()
}

// requireOpFailed — операция дошла до `done` с ошибкой `code`, текст дословно.
func (a *atcWorld) requireOpFailed(opID string, code codes.Code, msg, what string) {
	a.t.Helper()
	done := awaitOp(a.t, a.ctx, a.ops, opID)
	require.NotNilf(a.t, done.Error, "%s: операция завершилась БЕЗ ошибки — выдача записана", what)
	require.Equalf(a.t, int32(code), done.Error.Code, "%s: код ошибки операции (%q)", what, done.Error.Message)
	require.Equalf(a.t, msg, done.Error.Message, "%s: текст ошибки операции", what)
}

// requireTargetVerbatim — `GET` выдачи отдаёт цель дословно, в присланном
// порядке. Право читать свою выдачу материализуется асинхронно (ban #9), поэтому
// чтение повторяется в ограниченном окне — и только на отказе доступа/отсутствии.
func (a *atcWorld) requireTargetVerbatim(bindingID string, want []*iamv1.ResourceRef, what string) {
	a.t.Helper()
	var (
		got *iamv1.AccessBinding
		err error
	)
	deadline := time.Now().Add(30 * time.Second)
	for {
		got, err = a.ab.Get(asUser(a.ctx, a.usrA), &iamv1.GetAccessBindingRequest{AccessBindingId: bindingID})
		if err == nil || time.Now().After(deadline) {
			break
		}
		if c := status.Code(err); c != codes.NotFound && c != codes.PermissionDenied {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	require.NoErrorf(a.t, err, "%s: GET выдачи %s", what, bindingID)
	res := got.GetTarget().GetResources().GetResources()
	require.Lenf(a.t, res, len(want), "%s: число элементов цели", what)
	for i := range want {
		require.Equalf(a.t, want[i].GetType(), res[i].GetType(), "%s: тип элемента %d", what, i)
		require.Equalf(a.t, want[i].GetId(), res[i].GetId(), "%s: id элемента %d", what, i)
	}
}

// bindingsOf — число строк выдач получателя в проекте (уборка не нужна: база
// пробы своя, снимается вместе с ней).
func (a *atcWorld) bindingsOf(user domain.UserID, prj domain.ProjectID) int {
	a.t.Helper()
	var n int
	require.NoError(a.t, a.pool.QueryRow(a.ctx, `
		SELECT count(*) FROM kaname.access_bindings
		 WHERE subject_id = $1 AND resource_type = 'project' AND resource_id = $2`,
		string(user), string(prj)).Scan(&n))
	return n
}

// listOf — ветвь чтения перечня выдач (`AccessBindings().List`, та, по которой
// `AccessBindingService.List` собирает страницу) с `subject=<user>`: выдачи с
// целью. Видимость страницы ручки судит модель прав по объектам выдач, а в мире
// М2 у владельца нет материализованного права перечислять выдачи — предмет
// ATC-02/-14 не видимость, а то, что чтение цель с каталогом не сверяет (Р5).
func (a *atcWorld) listOf(user domain.UserID) []domain.AccessBinding {
	a.t.Helper()
	rd, err := a.repo.Reader(a.ctx)
	require.NoError(a.t, err)
	defer func() { _ = rd.Rollback(a.ctx) }()
	rows, _, err := rd.AccessBindings().List(a.ctx, repoab.ListFilter{SubjectID: string(user), PageSize: 100})
	require.NoErrorf(a.t, err, "List(subject=%s)", user)
	return rows
}

// requireListed — перечень выдач `user` — ровно выдача `id` с целью `want`.
func (a *atcWorld) requireListed(user domain.UserID, id string, want []*iamv1.ResourceRef, what string) {
	a.t.Helper()
	rows := a.listOf(user)
	require.Lenf(a.t, rows, 1, "%s: List(subject=%s) — выдач %d, ожидалась одна %s", what, user, len(rows), id)
	require.Equalf(a.t, id, string(rows[0].ID), "%s: в перечне не та выдача", what)
	got := rows[0].Target.Resources
	require.Lenf(a.t, got, len(want), "%s: число элементов цели в перечне", what)
	for i := range want {
		require.Equalf(a.t, want[i].GetType(), got[i].Type, "%s: тип элемента %d в перечне", what, i)
		require.Equalf(a.t, want[i].GetId(), got[i].ID, "%s: id элемента %d в перечне", what, i)
	}
}

// askBox — `Check(subject, v_get, probemod_box:<id>)` внутренней двери решения
// (`InternalIAMService.Check`, `askInternal` мира П6): субъект строкой,
// отношение — именем модели, объект — типом модели и id. Публичная дверь
// спрашивает ещё и ДЕЙСТВИЕ из каталога методов, а у модуля пробы методов нет.
func (a *atcWorld) askBox(subject, id string) bool {
	a.t.Helper()
	return a.askInternal(subject, "v_get", atcBoxType, id)
}

// pollBox — опрос `askBox` раз в 200 мс до 30 с до `true`.
func (a *atcWorld) pollBox(subject, id, what string) {
	a.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !a.askBox(subject, id) {
		if time.Now().After(deadline) {
			a.t.Fatalf("%s: Check(%s, v_get, %s:%s) за 30 с не дошёл до allowed=true", what, subject, atcBoxType, id)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ATC-01 + ATC-02 (близнецы одного мира): тип модуля, живой в каталоге,
// принимается целью и читается дословно; тип, которого в каталоге нет, — Т1
// синхронно, операции нет, выдач у usr-D по нему нет.
func TestATC01_ATC02_ModuleTypeLiveInCatalogIsAcceptedUnknownIsRefused(t *testing.T) {
	a := newATCWorld(t)
	target := []*iamv1.ResourceRef{rr(atcBoxes, "b1")}
	op, id := a.opOf(a.req(userSubject(a.usrD), a.rolBoxGet, a.prjA, target...), "ATC-01")
	require.Nilf(t, awaitOp(t, a.ctx, a.ops, op).Error, "ATC-01: операция завершилась ошибкой")
	a.requireTargetVerbatim(id, target, "ATC-01")

	a.requireSync(a.req(userSubject(a.usrD), a.rolBoxGet, a.prjA, rr("probemod.nope", "b1")),
		codes.InvalidArgument, atcT1("probemod.nope"), "ATC-02")
	// «Выдач у usr-D по probemod.nope — 0»: перечень usr-D — ровно выдача ATC-01
	// (положительный контроль того же чтения), строк выдач в prj-A — одна.
	a.requireListed(a.usrD, id, target, "ATC-02")
	require.Equal(t, 1, a.bindingsOf(a.usrD, a.prjA), "ATC-02: в базе у usr-D в prj-A лишняя строка выдачи")
}

// ATC-03: выдача на тип модуля материализуется ровно на названный объект,
// зарегистрированный ПОСЛЕ выдачи.
func TestATC03_ModuleTypeGrantMaterializesOnTheNamedObjectOnly(t *testing.T) {
	a := newATCWorld(t)
	op, _ := a.opOf(a.req(userSubject(a.usrD), a.rolBoxGet, a.prjA, rr(atcBoxes, atcB1)), "ATC-03")
	require.Nilf(t, awaitOp(t, a.ctx, a.ops, op).Error, "ATC-03: операция завершилась ошибкой")
	a.registerBox(atcB1)
	a.registerBox(atcB2)
	a.pollBox("user:"+string(a.usrD), atcB1, "ATC-03 b1")
	require.False(t, a.askBox("user:"+string(a.usrD), atcB2), "ATC-03: доступ к b2, не названному целью")
}

// ATC-04 + близнец, ATC-05: канонические живые типы — вне прежнего перечня и в
// нём — принимаются; другое написание — Т1.
func TestATC04_ATC05_LiveCanonicalTypesAreAccepted(t *testing.T) {
	a := newATCWorld(t)
	pool := []*iamv1.ResourceRef{rr("vpc.addressPool", "ap1")}
	op, id := a.opOf(a.req(userSubject(a.usrD), a.rolPoolGet, a.prjA, pool...), "ATC-04")
	require.Nilf(t, awaitOp(t, a.ctx, a.ops, op).Error, "ATC-04: операция завершилась ошибкой")
	a.requireTargetVerbatim(id, pool, "ATC-04")
	a.requireSync(a.req(userSubject(a.usrE), a.rolPoolGet, a.prjA, rr("vpc.address_pool", "ap1")),
		codes.InvalidArgument, atcT1("vpc.address_pool"), "ATC-04 близнец")

	inst := []*iamv1.ResourceRef{rr("compute.instance", "i1")}
	op, id = a.opOf(a.req(userSubject(a.usrD), a.rolInstGet, a.prjA, inst...), "ATC-05")
	require.Nilf(t, awaitOp(t, a.ctx, a.ops, op).Error, "ATC-05: операция завершилась ошибкой")
	a.requireTargetVerbatim(id, inst, "ATC-05")
}

// ATC-06 (а) и (б): неживая строка посева и снятая строка модуля отвергаются Т1.
func TestATC06_NonLiveTypeIsRefusedWithTheSameText(t *testing.T) {
	a := newATCWorld(t)
	a.requireSync(a.req(userSubject(a.usrD), a.rolInstGet, a.prjA, rr("compute.disk", "d1")),
		codes.InvalidArgument, atcT1("compute.disk"), "ATC-06 (а)")

	// Близнец (б): до снятия тот же вход доходит до done без ошибки.
	op, _ := a.opOf(a.req(userSubject(a.usrE), a.rolItemGet, a.prjA, rr(atcItems, "i1")), "ATC-06 (б) близнец")
	require.Nilf(t, awaitOp(t, a.ctx, a.ops, op).Error, "ATC-06 (б) близнец: операция завершилась ошибкой")

	a.applyDelivered("М3: снятие probemod.items, ручка пересобрана", a.manifest(true))
	require.False(t, a.itemsLiveInDB(), "М3: строка probemod.items осталась живой")
	a.requireSync(a.req(userSubject(a.usrD), a.rolItemGet, a.prjA, rr(atcItems, "i1")),
		codes.InvalidArgument, atcT1(atcItems), "ATC-06 (б)")
}

// ATC-07 и ATC-08 — через полный мир (синхронные исходы на живой ручке).
func TestATC07_ATC08_WildcardUndottedAndMixedListsAreRefused(t *testing.T) {
	a := newATCWorld(t)
	for _, typ := range []string{"*", "probemod.*", "probemod"} {
		a.requireSync(a.req(userSubject(a.usrD), a.rolBoxGet, a.prjA, rr(typ, "b1")),
			codes.InvalidArgument, atcT1(typ), "ATC-07 "+typ)
	}
	a.requireSync(a.req(userSubject(a.usrD), a.rolInstBox, a.prjA, rr("compute.instance", "i1"), rr("probemod.nope", "x")),
		codes.InvalidArgument, atcT1("probemod.nope"), "ATC-08")
	require.Equal(t, 0, a.bindingsOf(a.usrD, a.prjA), "ATC-07/08: выдача записана")

	both := []*iamv1.ResourceRef{rr("compute.instance", "i1"), rr(atcBoxes, atcB1)}
	op, id := a.opOf(a.req(userSubject(a.usrD), a.rolInstBox, a.prjA, both...), "ATC-08 близнец")
	require.Nilf(t, awaitOp(t, a.ctx, a.ops, op).Error, "ATC-08 близнец: операция завершилась ошибкой")
	a.requireTargetVerbatim(id, both, "ATC-08 близнец")
}

// ATC-09: снятие зафиксировано после синхронной проверки (снимок ручки не
// обновлён) — `Operation.error` FAILED_PRECONDITION, Т2, выдачи нет; близнец без
// снятия — выдача есть.
func TestATC09_WithdrawalCommittedAfterTheSyncCheckYieldsNoBinding(t *testing.T) {
	a := newATCWorld(t)
	twin := newATCWorld(t)
	op, _ := twin.opOf(twin.req(userSubject(twin.usrD), twin.rolItemGet, twin.prjA, rr(atcItems, "i1")), "ATC-09 близнец")
	require.Nilf(t, awaitOp(t, twin.ctx, twin.ops, op).Error, "ATC-09 близнец: операция завершилась ошибкой")
	require.Equal(t, 1, twin.bindingsOf(twin.usrD, twin.prjA), "ATC-09 близнец: выдачи нет")

	a.withdrawItemsInDB()
	op, _ = a.opOf(a.req(userSubject(a.usrD), a.rolItemGet, a.prjA, rr(atcItems, "i1")), "ATC-09")
	a.requireOpFailed(op, codes.FailedPrecondition, atcT2(atcItems), "ATC-09")
	require.Equal(t, 0, a.bindingsOf(a.usrD, a.prjA), "ATC-09: выдача записана на снятый тип")
}

// holdingRunner — обёртка порта `modulecatalog.TxRunner`: функция транзакции
// отработала (замки взяты, операторы выполнены), возврат — по сигналу пробы.
type holdingRunner struct {
	inner   modulecatalog.TxRunner
	ran     chan struct{}
	release chan bool // true — фиксировать, false — откатить
}

var errRolledBackByProbe = errors.New("применение откачено пробой")

func (h holdingRunner) RunInWriteTx(ctx context.Context, fn func(context.Context, modulecatalog.CatalogWriter) error) error {
	return h.inner.RunInWriteTx(ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
		if err := fn(ctx, w); err != nil {
			return err
		}
		close(h.ran)
		if commit := <-h.release; !commit {
			return errRolledBackByProbe
		}
		return nil
	})
}

// waitCreateBlockedOnCatalog — запись выдачи стоит на замке строки каталога:
// бэкенд этой базы ждёт замка оператором `FOR KEY SHARE` по `catalog_resource`.
// Без этого наблюдения «запись дождалась исхода снятия» неотличимо от «запись
// пришла после него».
func (a *atcWorld) waitCreateBlockedOnCatalog(what string) {
	a.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var n int
		require.NoError(a.t, a.pool.QueryRow(a.ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND pid <> pg_backend_pid()
			   AND wait_event_type = 'Lock'
			   AND query LIKE '%catalog_resource%' AND query LIKE '%FOR KEY SHARE%'`).Scan(&n))
		if n > 0 {
			return
		}
		if time.Now().After(deadline) {
			a.t.Fatalf("%s: за 10 с запись выдачи не встала на замок строки каталога — транзакция записи каталог не спрашивает", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// atc10Reps — повторов каждого исхода ATC-10 (DoD S1 п. 2).
const atc10Reps = 20

// ATC-10: незафиксированное снятие решает исход записи. Фиксация — Т2, выдачи
// нет; откат — выдача есть и читается дословно. Близнецы отличают запись, ждущую
// исхода, от читающей прежнюю версию (та дала бы выдачу в обоих) и от
// отказывающей на занятой строке сразу (та дала бы отказ в обоих). По 20
// повторов каждого исхода без расхождения.
func TestATC10_UncommittedWithdrawalDecidesTheWrite(t *testing.T) {
	a := newATCWorld(t)
	target := []*iamv1.ResourceRef{rr(atcItems, "i1")}
	withdrawal, revival := a.manifest(true), a.manifest(false)
	for i := 0; i < atc10Reps; i++ {
		for _, commit := range []bool{true, false} {
			what := fmt.Sprintf("ATC-10 повтор %d, снятие %s", i+1, map[bool]string{true: "фиксируется", false: "откатывается"}[commit])
			user := mustSeedUser(t, a.ctx, a.pool, fmt.Sprintf("a10%v%02d", commit, i))
			role := a.seedRole(fmt.Sprintf("atc10_%v_%02d", commit, i),
				domain.Rules{{Module: "probemod", Resources: []string{"items"}, Verbs: []string{"get"}}})

			h := holdingRunner{inner: kanamepg.NewCatalogWriteRepo(a.pool), ran: make(chan struct{}), release: make(chan bool, 1)}
			// На падении пробы удержанное применение откатывается: открытая
			// транзакция не переживает пробу и не держит базу при её снятии.
			t.Cleanup(func() {
				select {
				case h.release <- false:
				default:
				}
			})
			applied := make(chan error, 1)
			go func() {
				_, err := modulecatalog.NewApplier(h).ApplyAll(a.ctx, []*manifest.Manifest{withdrawal})
				applied <- err
			}()
			select {
			case <-h.ran:
			case err := <-applied:
				t.Fatalf("%s: применение завершилось до удержания: %v", what, err)
			case <-time.After(30 * time.Second):
				t.Fatalf("%s: применение не дошло до удержания за 30 с", what)
			}

			op, id := a.opOf(a.req(userSubject(user), role, a.prjA, target...), what)
			a.waitCreateBlockedOnCatalog(what)
			h.release <- commit
			err := <-applied
			if commit {
				require.NoErrorf(t, err, "%s: применение снятия", what)
				a.requireOpFailed(op, codes.FailedPrecondition, atcT2(atcItems), what)
				require.Equalf(t, 0, a.bindingsOf(user, a.prjA), "%s: выдача записана", what)
				// Возврат строки для следующего повтора — тот же путь старта.
				_, rerr := modulecatalog.NewApplier(kanamepg.NewCatalogWriteRepo(a.pool)).
					ApplyAll(a.ctx, []*manifest.Manifest{revival})
				require.NoErrorf(t, rerr, "%s: возврат probemod.items", what)
				require.Truef(t, a.itemsLiveInDB(), "%s: probemod.items не ожил", what)
			} else {
				require.ErrorIsf(t, err, errRolledBackByProbe, "%s: применение не откатилось", what)
				done := awaitOp(t, a.ctx, a.ops, op)
				require.Nilf(t, done.Error, "%s: операция завершилась ошибкой %+v", what, done.Error)
				require.Equalf(t, 1, a.bindingsOf(user, a.prjA), "%s: выдачи нет", what)
				a.requireTargetVerbatim(id, target, what)
			}
		}
	}
}

// ATC-11: ворота роли действуют на тип модуля.
func TestATC11_RoleCoverageGateAppliesToModuleTypes(t *testing.T) {
	a := newATCWorld(t)
	a.requireSync(a.req(userSubject(a.usrD), a.rolInstGet, a.prjA, rr(atcBoxes, atcB1)),
		codes.FailedPrecondition,
		fmt.Sprintf("role %s does not grant verbs on probemod.boxes; target type must be covered by role.rules", a.rolInstGet),
		"ATC-11")
	op, _ := a.opOf(a.req(userSubject(a.usrD), a.rolBoxGet, a.prjA, rr(atcBoxes, atcB1)), "ATC-11 близнец")
	require.Nilf(t, awaitOp(t, a.ctx, a.ops, op).Error, "ATC-11 близнец: операция завершилась ошибкой")
}

// ATC-12: цель вне области выдачи не даёт доступа; контроль — та же выдача с
// областью prj-A другому получателю доходит до `true`.
func TestATC12_TargetOutsideTheScopeGrantsNothing(t *testing.T) {
	a := newATCWorld(t)
	a.registerBox(atcB1)
	op, _ := a.opOf(a.req(userSubject(a.usrD), a.rolBoxGet, a.prjB, rr(atcBoxes, atcB1)), "ATC-12")
	require.Nilf(t, awaitOp(t, a.ctx, a.ops, op).Error, "ATC-12: операция завершилась ошибкой")
	op, _ = a.opOf(a.req(userSubject(a.usrE), a.rolBoxGet, a.prjA, rr(atcBoxes, atcB1)), "ATC-12 контроль")
	require.Nilf(t, awaitOp(t, a.ctx, a.ops, op).Error, "ATC-12 контроль: операция завершилась ошибкой")
	a.pollBox("user:"+string(a.usrE), atcB1, "ATC-12 контроль")
	require.False(t, a.askBox("user:"+string(a.usrD), atcB1), "ATC-12: выдача на prj-B дала доступ к объекту prj-A")
}

// ATC-13: ворота системного класса действуют на тип модуля.
func TestATC13_SystemClassGateAppliesToModuleTypes(t *testing.T) {
	a := newATCWorld(t)
	a.registerBox(atcB1)
	a.registerBox(atcB2)
	a.requireSync(a.req(classSubject("anonymous"), a.rolBoxUpd, a.prjA, rr(atcBoxes, atcB1)),
		codes.FailedPrecondition,
		fmt.Sprintf("Role %s grants verbs beyond get and list; a system class subject accepts read-only roles", a.rolBoxUpd),
		"ATC-13 близнец")
	op, _ := a.opOf(a.req(classSubject("anonymous"), a.rolBoxRead, a.prjA, rr(atcBoxes, atcB1)), "ATC-13")
	require.Nilf(t, awaitOp(t, a.ctx, a.ops, op).Error, "ATC-13: операция завершилась ошибкой")
	a.pollBox(pcrAnon, atcB1, "ATC-13")
	require.False(t, a.askBox(pcrAnon, atcB2), "ATC-13: класс получил доступ к b2, не названному целью")
}

// ATC-14: лежащая выдача читается после снятия её типа — `GET` и `List`.
func TestATC14_StoredBindingReadsAfterItsTypeIsWithdrawn(t *testing.T) {
	a := newATCWorld(t)
	target := []*iamv1.ResourceRef{rr(atcItems, "i1")}
	op, id := a.opOf(a.req(userSubject(a.usrD), a.rolItemGet, a.prjA, target...), "ATC-14")
	require.Nilf(t, awaitOp(t, a.ctx, a.ops, op).Error, "ATC-14: операция завершилась ошибкой")
	a.requireTargetVerbatim(id, target, "ATC-14 близнец: до снятия")

	a.withdrawItemsInDB()
	a.requireTargetVerbatim(id, target, "ATC-14: после снятия")
	a.requireListed(a.usrD, id, target, "ATC-14: List после снятия")
}

// atcPerfReps — прогонов на каждую форму цели (DoD S1 п. 6).
const atcPerfReps = 20

// TestATCPerf_TargetCheckCostInTheWriteTx — цена проверки в транзакции (DoD S1
// п. 6): время `Create` до `done` при цели из 256 элементов разных типов против
// цели из 1 элемента, медиана по 20 прогонам. Утверждение функциональное — обе
// формы доходят до `done` без ошибки (256 различных живых типов в одной цели
// принимаются); число печатается.
func TestATCPerf_TargetCheckCostInTheWriteTx(t *testing.T) {
	a := newATCWorld(t)
	var b strings.Builder
	b.WriteString("apiVersion: iam/v1\nmodule: probeperf\n\nresources:\n")
	for i := 0; i < domain.MaxTargetResourcesPerBinding; i++ {
		fmt.Fprintf(&b, "\n  - name: r%03d\n    objectType: probeperf_r%03d\n    parents: [project]\n    producer: derived\n    verbs: [get]\n", i, i)
	}
	m, err := manifest.Load([]byte(b.String()))
	require.NoError(t, err, "фикстура probeperf")
	a.applyDelivered("доставка probeperf", m)

	var rules domain.Rules
	for r := 0; r < domain.MaxTargetResourcesPerBinding/16; r++ {
		res := make([]string, 0, 16)
		for j := 0; j < 16; j++ {
			res = append(res, fmt.Sprintf("r%03d", r*16+j))
		}
		rules = append(rules, domain.Rule{Module: "probeperf", Resources: res, Verbs: []string{"get"}})
	}
	role := a.seedRole("rol_perf", rules)

	measure := func(n int) time.Duration {
		var ds []time.Duration
		for rep := 0; rep < atcPerfReps; rep++ {
			refs := make([]*iamv1.ResourceRef, 0, n)
			for i := 0; i < n; i++ {
				refs = append(refs, rr(fmt.Sprintf("probeperf.r%03d", i), fmt.Sprintf("o%03d", rep)))
			}
			user := mustSeedUser(t, a.ctx, a.pool, fmt.Sprintf("prf%d%02d", n, rep))
			start := time.Now()
			opID, _ := a.opOf(a.req(userSubject(user), role, a.prjA, refs...), fmt.Sprintf("perf n=%d", n))
			done := awaitOpDoneOnly(t, a.ctx, a.ops, opID)
			ds = append(ds, time.Since(start))
			require.Nilf(t, done.Error, "perf n=%d: операция завершилась ошибкой %+v", n, done.Error)
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return (ds[len(ds)/2-1] + ds[len(ds)/2]) / 2
	}
	one := measure(1)
	full := measure(domain.MaxTargetResourcesPerBinding)
	t.Logf("DoD S1 п. 6: Create до done, медиана по %d прогонам: цель 1 элемент — %.1f мс; цель %d элементов разных типов — %.1f мс",
		atcPerfReps, float64(one.Microseconds())/1000, domain.MaxTargetResourcesPerBinding, float64(full.Microseconds())/1000)
}

// awaitOpDoneOnly — опрос операции раз в 2 мс до `done` (окно 30 с): частый
// опрос, чтобы шаг опроса не стал единицей замера.
func awaitOpDoneOnly(t *testing.T, ctx context.Context, ops operations.Repo, id string) *operations.Operation {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		op, err := ops.Get(ctx, id)
		require.NoError(t, err)
		if op.Done {
			return op
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("операция %s не завершилась за 30 с", id)
	return nil
}
