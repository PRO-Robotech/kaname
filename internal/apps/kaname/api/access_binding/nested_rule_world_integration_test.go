// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// nested_rule_world_integration_test.go — вложенное правило роли манифеста
// модуля на мире П1 (kaname#874).
//
// Приёмка docs/engineering/acceptance/nested-rule-reaches-descendants-of-a-named-container.md
// (редакция 2, отпечаток f12395ae242f85e1120346123286318b3027d87e53f6973f4b8a21ac1bd6d9f6):
// ND-01…07, ND-09…12 сквозь те же части, что корень службы — выдача
// (`AccessBindingService.Create`/`Delete`), разворачивание (`reconcile`),
// регистрация владельца (`InternalIAMService.RegisterResource`), решение
// (`AuthorizeService`, `InternalIAMService.Check`, `relverdict`) и чтение роли
// (`RoleService`).
//
// П1 = П6 соседа (`newPCRWorld`) с доставкой новой редакции манифеста registry
// (`registry.public-read-fixture.yaml` — роли таблицы П1), плюс человек usr-E и
// репозиторий `…01/moved`. «Материализована» — опрос раз в 200 мс до 30 с.

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Роли таблицы П1 (`domain.SystemRoleID` от имени).
const (
	ndRolPublicRead = domain.RoleID("rolb1325b011aa17211d")
	ndRolReader     = domain.RoleID("rolb812261cfaa239694")
	ndRolViewer     = domain.RoleID("rol2375080206e7e5e32")
	ndRolReaderGet  = domain.RoleID("rolc36eeca826b9a8603")
	ndRolReaderName = domain.RoleID("rolc8f851eb7a5da3d9f")

	ndXMoved = pcrX + "/moved"
	ndYTgt   = "reg00000000000000002"
)

// ndWorld — П1.
type ndWorld struct {
	*pcrWorld
	usrE domain.UserID
}

// newNDWorld поднимает П1 с доставкой новой редакции (`doc` пуст — фикстура как
// есть). Контроль фикстуры: роль registry.reader есть в базе.
func newNDWorld(t *testing.T, sc string, doc []byte) *ndWorld {
	t.Helper()
	p := newPCRWorld(t)
	w := &ndWorld{pcrWorld: p}
	w.usrE = mustSeedUser(t, p.ctx, p.pool, "nde")
	// Адрес подтверждён, как у людей мира П6: без него дверь решения отказывает
	// человеку за пределами входа, и проба мерила бы не вложенное правило.
	verifyAddresses(t, p.ctx, p.pool)
	if doc == nil {
		p.deliverNewEdition(sc)
	} else {
		w.deliverDoc(sc, doc)
	}
	var n int
	require.NoError(t, p.pool.QueryRow(p.ctx, `SELECT count(*) FROM kaname.roles WHERE id = $1`, string(ndRolReader)).Scan(&n))
	require.Equalf(t, 1, n, "%s: контроль фикстуры П1 — роли registry.reader нет после доставки", sc)
	return w
}

// deliverDoc — доставка документа тем же путём, что `deliverNewEdition`.
func (w *ndWorld) deliverDoc(sc string, doc []byte) {
	w.t.Helper()
	m, err := manifest.Load(doc)
	require.NoErrorf(w.t, err, "%s: загрузка документа", sc)
	w.applyDelivered(sc+": доставка", m)
	w.delivered = true
}

// ndFlatPublicRead — фикстура П1, у которой `registry.public.read` записана
// ПРЕЖНЕЙ формой: одно правило над `[registries, repositories]` (П2, ND-07).
func ndFlatPublicRead(t *testing.T) []byte {
	t.Helper()
	edition, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	require.NoError(t, err)
	// Запись `writes: owner` — как у мира П6 (kaname#982): доставка заменяет политику
	// записи модуля, и регистрации `owner` мира без неё были бы отказом.
	doc, err := publicreadfixture.WithWrites(edition)
	require.NoError(t, err)
	s := string(doc)
	start := strings.Index(s, "  - id: registry.public.read\n")
	end := strings.Index(s, "  - id: registry.reader\n")
	require.Truef(t, start >= 0 && end > start, "блок registry.public.read фикстуры не найден")
	const nested = "        resources: [registries]\n        classes: [get, list]\n        children:\n          - resources: [repositories]\n            classes: [get, list]\n"
	const flat = "        resources: [registries, repositories]\n        classes: [get, list]\n"
	block := s[start:end]
	require.Equal(t, 1, strings.Count(block, nested), "блок registry.public.read не несёт вложенного правила")
	return []byte(s[:start] + strings.Replace(block, nested, flat, 1) + s[end:])
}

func ndYTarget() *iamv1.AccessTarget {
	return resourcesTarget(&iamv1.ResourceRef{Type: pcrRegTgt, Id: ndYTgt})
}

func ndAllInScope() *iamv1.AccessTarget {
	return &iamv1.AccessTarget{Target: &iamv1.AccessTarget_AllInScope{AllInScope: &iamv1.AccessTargetAllInScope{}}}
}

func (w *ndWorld) usr(id domain.UserID) string { return fmtSubject("user", string(id)) }

// grant — выдача доведена до done и материализована.
func (w *ndWorld) grant(sub *iamv1.Subject, role domain.RoleID, target *iamv1.AccessTarget, why string) string {
	w.t.Helper()
	id := w.createDone(asUser(w.ctx, w.usrA), w.grantRequest(sub, role, target), why)
	w.pollMaterialized(id, why)
	return id
}

// registerRepoAt — регистрация репозитория службой-владельцем: указатель
// `parent` на реестр `registry`, цепь через него; версия источника — `ver`
// (оба вызова).
func (w *ndWorld) registerRepoAt(id, registry string, ver time.Time) {
	w.t.Helper()
	obj := pcrRepoType + ":" + id
	for _, r := range []*iamv1.RegisterResourceRequest{
		{SubjectId: pcrRegType + ":" + registry, Relation: "parent", Object: obj},
		{SubjectId: "user:" + string(w.usrA), Relation: "owner", Object: obj},
	} {
		r.ParentProjectId, r.ParentAccountId = string(w.prjA), string(w.accA)
		r.ParentChain = []string{pcrRegType + ":" + registry, "project:" + string(w.prjA), "account:" + string(w.accA)}
		r.SourceVersion = timestamppb.New(ver)
		require.NoErrorf(w.t, w.reg.Register(w.ctx, r), "регистрация %s в %s (%s)", id, registry, r.GetRelation())
	}
}

// moveRepoAt — перенос репозитория под реестр `registry`: указатель `parent` с
// версией источника `ver`. Кортеж `owner` переносом не переписывается: владелец
// объекта остаётся прежним, а его запись сверяется с ВЫВЕДЕННЫМ родителем объекта
// (kaname#982) — перенос, не принятый как не новее, родителя не меняет, и запись
// `owner` с цепью через новый реестр была бы отказом вывода.
func (w *ndWorld) moveRepoAt(id, registry string, ver time.Time) {
	w.t.Helper()
	r := &iamv1.RegisterResourceRequest{
		SubjectId: pcrRegType + ":" + registry, Relation: "parent", Object: pcrRepoType + ":" + id,
		ParentProjectId: string(w.prjA), ParentAccountId: string(w.accA),
		ParentChain:   []string{pcrRegType + ":" + registry, "project:" + string(w.prjA), "account:" + string(w.accA)},
		SourceVersion: timestamppb.New(ver),
	}
	require.NoErrorf(w.t, w.reg.Register(w.ctx, r), "перенос %s в %s", id, registry)
}

// batch — `AuthorizeService.BatchCheck` по v_get.
func (w *ndWorld) batch(subject string, objs ...pcrPair) []bool {
	w.t.Helper()
	req := &iamv1.BatchAuthorizeCheckRequest{}
	for _, o := range objs {
		req.Checks = append(req.Checks, &iamv1.AuthorizeCheckRequest{
			Subject: subject, Resource: &iamv1.ResourceRef{Type: o.modelType, Id: o.id},
			Action: pcrAction(o.modelType, "v_get"), RequiredRelation: "v_get",
		})
	}
	resp, err := w.authz.BatchCheck(moduleCtx(), req)
	require.NoError(w.t, err, "BatchCheck")
	out := make([]bool, 0, len(resp.GetResponses()))
	for _, r := range resp.GetResponses() {
		out = append(out, r.GetAllowed())
	}
	return out
}

// members — объекты типа `objectType`, на которых у выдачи действующий член.
func (w *ndWorld) members(bindingID, objectType string) []string {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx, `
		SELECT object_id FROM kaname.access_binding_target_members
		 WHERE binding_id = $1 AND object_type = $2 AND verification_status = 'ACTIVE'
		 ORDER BY object_id`, bindingID, objectType)
	require.NoError(w.t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		require.NoError(w.t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(w.t, rows.Err())
	return out
}

// sources — основания права на объекте (`relverdict.Expand`, разбор оснований).
func (w *ndWorld) sources(modelType, id string) []relverdict.Source {
	w.t.Helper()
	tx, err := w.pool.Begin(w.ctx)
	require.NoError(w.t, err)
	defer func() { _ = tx.Rollback(w.ctx) }()
	out, err := relverdict.Expand(w.ctx, tx, modelType, id, "v_get")
	require.NoError(w.t, err, "разбор оснований")
	return out
}

var (
	ndPX     = pcrPair{"v_get", pcrRegType, pcrX}
	ndPY     = pcrPair{"v_get", pcrRegType, ndYTgt}
	ndPXApp  = pcrPair{"v_get", pcrRepoType, pcrXApp}
	ndPYApp  = pcrPair{"v_get", pcrRepoType, pcrYApp}
	ndPXLate = pcrPair{"v_get", pcrRepoType, pcrXLate}
)

// ND-01: человек, registry.viewer на X — только X.
func TestNestedWorld_ND01_ViewerOnXGivesOnlyX(t *testing.T) {
	w := newNDWorld(t, "ND-01", nil)
	w.grant(userSubject(w.usrD), ndRolViewer, pcrXTarget(), "ND-01")
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRegType, pcrX, true, "ND-01: v_get на X")
	for _, rel := range []string{"v_get", "v_list"} {
		w.requireAsk(w.usr(w.usrD), rel, pcrRepoType, pcrXApp, false, "ND-01: "+rel+" на …01/app")
	}
}

// ND-02: человек, registry.reader на X — X и его репозитории, включая будущие; Y
// не задет; все формы вопроса; чтение роли отдаёт вложенное правило.
func TestNestedWorld_ND02_ReaderOnXReachesItsRepositories(t *testing.T) {
	w := newNDWorld(t, "ND-02", nil)
	w.registerRepoAt(ndXMoved, pcrX, time.Now())
	id := w.grant(userSubject(w.usrD), ndRolReader, pcrXTarget(), "ND-02")
	d := w.usr(w.usrD)
	w.pollAsk(d, "v_get", pcrRepoType, pcrXApp, true, "ND-02: v_get на …01/app")
	w.requireAsk(d, "v_list", pcrRepoType, pcrXApp, true, "ND-02: v_list на …01/app")
	w.requireAsk(d, "v_get", pcrRegType, pcrX, true, "ND-02: v_get на X")
	w.requireAsk(d, "v_get", pcrRegType, ndYTgt, false, "ND-02: v_get на Y")
	for _, rel := range []string{"v_get", "v_list"} {
		w.requireAsk(d, rel, pcrRepoType, pcrYApp, false, "ND-02: "+rel+" на …02/app")
	}

	// И: будущий потомок.
	w.registerRepository(pcrX, "late")
	w.pollAsk(d, "v_get", pcrRepoType, pcrXLate, true, "ND-02 «И»: v_get на …01/late")

	// И: формы вопроса.
	require.Equal(t, []bool{true, true, false, false, true}, w.batch(d, ndPX, ndPXApp, ndPY, ndPYApp, ndPXLate), "ND-02: BatchCheck")
	for _, c := range []struct {
		o    pcrPair
		want bool
	}{{ndPX, true}, {ndPXApp, true}, {ndPY, false}, {ndPYApp, false}, {ndPXLate, true}} {
		require.Equalf(t, c.want, w.askInternal(d, "v_get", c.o.modelType, c.o.id), "ND-02: InternalIAMService.Check %s", c.o)
	}
	subs, err := w.authz.ListSubjects(moduleCtx(), &iamv1.ListSubjectsRequest{
		Resource: &iamv1.ResourceRef{Type: pcrRepoType, Id: pcrXApp}, Action: pcrAction(pcrRepoType, "v_get"), PageSize: 100,
	})
	require.NoError(t, err, "ND-02: ListSubjects")
	require.Containsf(t, subs.GetSubjects(), d, "ND-02: ListSubjects(…01/app)")
	var byBinding bool
	for _, s := range w.sources(pcrRepoType, pcrXApp) {
		if s.Kind == "binding" && s.Subject == d && strings.HasPrefix(s.Detail, id+" ") {
			byBinding = true
		}
	}
	require.Truef(t, byBinding, "ND-02: разбор оснований …01/app не называет выдачу %s", id)
	objs, complete, err := relverdict.NewAsker(w.pool).Objects(w.ctx, d, pcrRepoType, []string{"v_get"}, 100)
	require.NoError(t, err)
	require.True(t, complete)
	slices.Sort(objs)
	require.Equal(t, []string{pcrXApp, pcrXLate, ndXMoved}, objs, "ND-02: Objects(registry_repository)")
	deadline := time.Now().Add(30 * time.Second)
	for !slices.Equal(w.members(id, "registry.repositories"), objs) && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	require.Equal(t, objs, w.members(id, "registry.repositories"), "ND-02: материализованные члены = ответ Objects")

	// И: чтение роли.
	pb, err := roleapp.NewHandler(nil, nil, nil, roleapp.NewGetRoleUseCase(w.repo, catalog.Fixed{F: w.facts}), nil).
		Get(asUser(w.ctx, w.usrA), &iamv1.GetRoleRequest{RoleId: string(ndRolReader)})
	require.NoError(t, err, "ND-02: GET роли")
	require.Len(t, pb.GetRules(), 1)
	require.Len(t, pb.GetRules()[0].GetChildren(), 1, "ND-02: rules[0].children")
	ch := pb.GetRules()[0].GetChildren()[0]
	require.Equal(t, []string{"repositories"}, ch.GetResources())
	require.Equal(t, []string{"get", "list"}, ch.GetVerbs())
	require.Empty(t, ch.GetModule(), "ND-02: модуль вложенного правила на чтении пуст")
	require.EqualValues(t, 4, pb.GetDeclaredSegments(), "ND-02: declaredSegments")
}

// ND-03: аноним, registry.public.read на X — X и репозитории через
// `public_reader`, только чтение; материализованных v_* на репозиториях нет.
func TestNestedWorld_ND03_AnonymousReadsDescendantsThroughPublicReader(t *testing.T) {
	w := newNDWorld(t, "ND-03", nil)
	for _, q := range sixPairs()[:4] {
		w.requireAsk(pcrAnon, q.relation, q.modelType, q.id, false, "ND-03 близнец без выдачи")
	}
	id := w.grant(classSubject("anonymous"), ndRolPublicRead, pcrXTarget(), "ND-03")
	for _, rel := range []string{"v_get", "v_list"} {
		w.pollAsk(pcrAnon, rel, pcrRegType, pcrX, true, "ND-03: "+rel+" на X")
		w.pollAsk(pcrAnon, rel, pcrRepoType, pcrXApp, true, "ND-03: "+rel+" на …01/app")
	}
	w.registerRepository(pcrX, "late")
	w.pollAsk(pcrAnon, "v_get", pcrRepoType, pcrXLate, true, "ND-03: …01/late")
	w.requireAsk(pcrAnon, "v_get", pcrRepoType, pcrYApp, false, "ND-03: …02/app")
	for _, q := range []pcrPair{{"v_update", pcrRepoType, pcrXApp}, {"v_delete", pcrRepoType, pcrXApp},
		{"v_update", pcrRegType, pcrX}, {"v_delete", pcrRegType, pcrX}, {"v_create", pcrRegType, pcrX}} {
		w.requireAsk(pcrAnon, q.relation, q.modelType, q.id, false, "ND-03: только чтение")
	}
	var viaPublicReader, viaBinding bool
	for _, s := range w.sources(pcrRepoType, pcrXApp) {
		if s.Kind == "fact" && s.Detail == domain.PublicReaderRelation && s.ScopeID == pcrX {
			viaPublicReader = true
		}
		if s.Kind == "binding" && strings.HasPrefix(s.Detail, id+" ") {
			viaBinding = true
		}
	}
	require.True(t, viaPublicReader, "ND-03: основание — public_reader на X")
	require.False(t, viaBinding, "ND-03: основание — не выдача")
	require.Empty(t, w.members(id, "registry.repositories"), "ND-03: членов v_* на репозиториях у выдачи классу нет")
}

// ND-04 (ж): `RoleService` в этой фазе вложенное правило на входе отвергает с
// именем поля — и `Create`, и `Update` (PATCH). Близнец — то же тело без children.
func TestNestedWorld_ND04_g_RoleServiceRefusesChildrenOnInput(t *testing.T) {
	w := newNDWorld(t, "ND-04 (ж)", nil)
	cat := catalog.Fixed{F: w.facts}
	h := roleapp.NewHandler(roleapp.NewCreateRoleUseCase(w.repo, w.ops, cat), roleapp.NewUpdateRoleUseCase(w.repo, w.ops, cat),
		nil, roleapp.NewGetRoleUseCase(w.repo, cat), nil)
	rules := func(withChildren bool) []*iamv1.Rule {
		r := &iamv1.Rule{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get", "list"}}
		if withChildren {
			r.Children = []*iamv1.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get", "list"}}}
		}
		return []*iamv1.Rule{r}
	}
	refused := func(err error, why string) {
		t.Helper()
		st, ok := status.FromError(err)
		require.Truef(t, ok && err != nil, "%s: ждали синхронный отказ, получено %v", why, err)
		require.Equal(t, codes.InvalidArgument, st.Code(), why)
		require.Equal(t, "Illegal argument children (nested rules are declared by a module manifest)", st.Message(), why)
		var field string
		for _, d := range st.Details() {
			if br, ok := d.(*errdetails.BadRequest); ok && len(br.GetFieldViolations()) > 0 {
				field = br.GetFieldViolations()[0].GetField()
			}
		}
		require.Equal(t, "rules[0].children", field, why)
	}
	create := func(name string, withChildren bool) (*iamv1.Role, error) {
		op, err := h.Create(asUser(w.ctx, w.usrA), &iamv1.CreateRoleRequest{
			AccountId: string(w.accA), Name: name, Description: "nd04g", Rules: rules(withChildren),
		})
		if err != nil {
			return nil, err
		}
		done := awaitOp(t, w.ctx, w.ops, op.GetId())
		require.Nilf(t, done.Error, "ND-04 (ж) близнец %s: операция", name)
		var md iamv1.CreateRoleMetadata
		require.NoError(t, op.GetMetadata().UnmarshalTo(&md))
		return &iamv1.Role{Id: md.GetRoleId()}, nil
	}
	_, err := create("nd04g_nested", true)
	refused(err, "ND-04 (ж): POST с children")
	tenant, err := create("nd04g_plain", false)
	require.NoError(t, err, "ND-04 (ж) близнец: POST без children")

	_, err = h.Update(asUser(w.ctx, w.usrA), &iamv1.UpdateRoleRequest{
		RoleId: tenant.GetId(), Rules: rules(true), UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"rules"}},
	})
	refused(err, "ND-04 (ж): PATCH с children")
	op, err := h.Update(asUser(w.ctx, w.usrA), &iamv1.UpdateRoleRequest{
		RoleId: tenant.GetId(), Rules: rules(false), UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"rules"}},
	})
	require.NoError(t, err, "ND-04 (ж) близнец: PATCH без children")
	require.Nil(t, awaitOp(t, w.ctx, w.ops, op.GetId()).Error, "ND-04 (ж) близнец: PATCH done")
}

// seedNamedReader — строка роли registry.reader_named (у вложенного правила
// `resourceNames: [app]`), положенная применителем НАПРЯМУЮ, минуя загрузчик.
//
// Манифест модуля конкретных объектов не называет (kaname#965), и из фикстуры
// П1 роль снята: загрузчик её отверг бы. Строка такой роли остаётся возможной
// как доставленная до запрета, и ворота класса судят её по-прежнему — ровно это
// утверждает ND-05 (б). Документ строится разобранным, а не текстом: текстом он
// снова прошёл бы через загрузчик.
func (w *ndWorld) seedNamedReader() {
	w.t.Helper()
	edition, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	require.NoError(w.t, err, "ND-05 (б): фикстура П1")
	// Та же запись `writes: owner`, что у мира П6 (kaname#982): доставка заменяет
	// политику записи, и без неё регистрации `owner` мира стали бы отказом.
	doc, err := publicreadfixture.WithWrites(edition)
	require.NoError(w.t, err, "ND-05 (б): фикстура П1 с writes")
	m, err := manifest.Load(doc)
	require.NoError(w.t, err, "ND-05 (б): фикстура П1 обязана загружаться")
	m.Roles = append(m.Roles, manifest.Role{
		ID:          "registry.reader_named",
		Description: "Пробная роль: как registry.reader, но вложенное правило сужено именами.",
		Tier:        &manifest.Tier{TierType: "iam.cluster", TierID: "cluster_root"},
		Rules: []manifest.Rule{{
			Module: "registry", Resources: []string{"registries"}, Classes: []string{"get", "list"},
			Children: []manifest.ChildRule{{
				Resources: []string{"repositories"}, Classes: []string{"get", "list"}, ResourceNames: []string{"app"},
			}},
		}},
	})
	w.applyDelivered("ND-05 (б): строка роли, доставленная до запрета", m)
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.roles WHERE id = $1`, string(ndRolReaderName)).Scan(&n))
	require.Equal(w.t, 1, n, "ND-05 (б): контроль — строки роли registry.reader_named нет после применения")
}

// ND-05: классу не выдаётся вложенное правило, не выполняющее условий Р5.
func TestNestedWorld_ND05_ClassGateRefusesNestedRulesThatDoNotQualify(t *testing.T) {
	w := newNDWorld(t, "ND-05", nil)
	w.seedNamedReader()
	notWhole := func(r domain.RoleID) string {
		return fmt.Sprintf("Role %s nests a rule over registry.repositories that does not read it whole "+
			"(get and list, without resourceNames or matchLabels); a system class reads children only whole", r)
	}
	for _, c := range []struct {
		name string
		role domain.RoleID
	}{{"(а) вложенное get", ndRolReaderGet}, {"(б) вложенное с именами", ndRolReaderName}} {
		op, err := w.ab.Create(asUser(w.ctx, w.usrA), w.grantRequest(classSubject("anonymous"), c.role, pcrXTarget()))
		require.Nilf(t, op, "ND-05 %s: Operation не создаётся", c.name)
		requireSyncRefusal(t, err, codes.FailedPrecondition, notWhole(c.role), "ND-05 "+c.name)
		// И: человеку отказа нет.
		w.createDone(asUser(w.ctx, w.usrA), w.grantRequest(userSubject(w.usrD), c.role, pcrXTarget()), "ND-05 "+c.name+" человеку")
	}
	// Близнец: ND-03.
	w.createDone(asUser(w.ctx, w.usrA), w.pchRequest(), "ND-05 близнец: ND-03")

	// (в) объявление контейнера снято доставкой прежней редакции; роль жива.
	w.deliverPriorEdition()
	op, err := w.ab.Create(asUser(w.ctx, w.usrA), w.grantRequest(classSubject("anonymous"), ndRolReader, pcrXTarget()))
	require.Nil(t, op, "ND-05 (в): Operation не создаётся")
	requireSyncRefusal(t, err, codes.FailedPrecondition,
		"Type registry.registries does not pass public read to its children; role rolb812261cfaa239694 covers its child type registry.repositories",
		"ND-05 (в)")
}

// ND-06: снятие выдачи снимает право со всех потомков.
func TestNestedWorld_ND06_DeleteRemovesTheRightFromAllDescendants(t *testing.T) {
	w := newNDWorld(t, "ND-06", nil)
	idD := w.grant(userSubject(w.usrD), ndRolReader, pcrXTarget(), "ND-06: ND-02")
	idA := w.grant(classSubject("anonymous"), ndRolPublicRead, pcrXTarget(), "ND-06: ND-03")
	w.registerRepository(pcrX, "late")
	d := w.usr(w.usrD)
	for _, sp := range []string{d, pcrAnon} {
		for _, o := range []pcrPair{ndPX, ndPXApp, ndPXLate} {
			w.pollAsk(sp, "v_get", o.modelType, o.id, true, "ND-06 близнец до удаления")
		}
	}
	w.ownerMayRemove("ND-06 Дано", idD, idA)
	for _, id := range []string{idD, idA} {
		op, err := w.ab.Delete(asUser(w.ctx, w.usrA), &iamv1.DeleteAccessBindingRequest{AccessBindingId: id})
		require.NoError(t, err, "ND-06: удаление %s", id)
		require.Nil(t, awaitOp(t, w.ctx, w.ops, op.GetId()).Error, "ND-06: операция удаления")
	}
	for _, sp := range []string{d, pcrAnon} {
		for _, o := range []pcrPair{ndPX, ndPXApp, ndPXLate} {
			w.pollAsk(sp, "v_get", o.modelType, o.id, false, "ND-06: после удаления")
		}
	}
}

// ND-07 (а): роль прежней формы смысла не меняет при «перезапуске» кодом
// изменения. (б): прежняя форма registry.public.read проигрывает в сторону отказа.
func TestNestedWorld_ND07_PriorRoleFormKeepsItsMeaning(t *testing.T) {
	t.Run("(а) перезапуск", func(t *testing.T) {
		doc := ndFlatPublicRead(t)
		w := newNDWorld(t, "ND-07 (а)", doc)
		id := w.grant(userSubject(w.usrD), ndRolPublicRead, pcrXTarget(), "ND-07 (а)")
		d := w.usr(w.usrD)
		w.pollAsk(d, "v_get", pcrRegType, pcrX, true, "ND-07 (а) до перезапуска: X")
		w.requireAsk(d, "v_get", pcrRepoType, pcrXApp, false, "ND-07 (а) до перезапуска: …01/app")
		get := func() (*iamv1.Role, *iamv1.AccessBinding) {
			r, err := roleapp.NewHandler(nil, nil, nil, roleapp.NewGetRoleUseCase(w.repo, catalog.Fixed{F: w.facts}), nil).
				Get(asUser(w.ctx, w.usrA), &iamv1.GetRoleRequest{RoleId: string(ndRolPublicRead)})
			require.NoError(t, err)
			b, err := w.ab.Get(asUser(w.ctx, w.usrA), &iamv1.GetAccessBindingRequest{AccessBindingId: id})
			require.NoError(t, err)
			return r, b
		}
		roleBefore, bindBefore := get()
		m, err := manifest.Load(doc)
		require.NoError(t, err)
		w.applyDelivered("ND-07 (а): перезапуск", m)
		roleAfter, bindAfter := get()
		require.Equal(t, fmt.Sprint(roleBefore.GetRules()), fmt.Sprint(roleAfter.GetRules()), "ND-07 (а): rules роли")
		for _, r := range roleAfter.GetRules() {
			require.Empty(t, r.GetChildren(), "ND-07 (а): у роли прежней формы children нет")
		}
		require.Equal(t, bindBefore.GetMaterializedAt().AsTime(), bindAfter.GetMaterializedAt().AsTime(), "ND-07 (а): materializedAt")
		w.requireAsk(d, "v_get", pcrRegType, pcrX, true, "ND-07 (а) после: X")
		w.requireAsk(d, "v_get", pcrRepoType, pcrXApp, false, "ND-07 (а) после: …01/app")
	})
	t.Run("(б) прежняя форма классу", func(t *testing.T) {
		w := newNDWorld(t, "ND-07 (б)", ndFlatPublicRead(t))
		w.grant(classSubject("anonymous"), ndRolPublicRead, pcrXTarget(), "ND-07 (б)")
		w.pollAsk(pcrAnon, "v_get", pcrRegType, pcrX, true, "ND-07 (б): X")
		for _, rel := range []string{"v_get", "v_list"} {
			w.requireAsk(pcrAnon, rel, pcrRepoType, pcrXApp, false, "ND-07 (б): "+rel+" на …01/app")
		}
		require.Zero(t, w.publicReaderFacts(pcrX), "ND-07 (б): кортежа public_reader на X нет")
	})
}

// ND-09: перенос объекта под другой контейнер переносит право по строго новой
// версии источника; не новее — регистрация не применяется.
func TestNestedWorld_ND09_MoveFollowsAStrictlyNewerSourceVersion(t *testing.T) {
	for _, c := range []struct {
		name  string
		newer bool
	}{{"T2 > T1", true}, {"близнец: T1 повторно", false}} {
		t.Run(c.name, func(t *testing.T) {
			w := newNDWorld(t, "ND-09", nil)
			t1 := time.Now().UTC().Truncate(time.Microsecond)
			w.registerRepoAt(ndXMoved, pcrX, t1)
			w.grant(userSubject(w.usrD), ndRolReader, pcrXTarget(), "ND-09: D на X")
			w.grant(userSubject(w.usrE), ndRolReader, ndYTarget(), "ND-09: E на Y")
			d, e := w.usr(w.usrD), w.usr(w.usrE)
			w.pollAsk(d, "v_get", pcrRepoType, ndXMoved, true, "ND-09 Дано: D")
			w.requireAsk(e, "v_get", pcrRepoType, ndXMoved, false, "ND-09 Дано: E")

			ver := t1
			if c.newer {
				ver = t1.Add(time.Second)
			}
			w.moveRepoAt(ndXMoved, ndYTgt, ver)
			if c.newer {
				w.pollAsk(d, "v_get", pcrRepoType, ndXMoved, false, "ND-09: D после переноса")
				w.pollAsk(e, "v_get", pcrRepoType, ndXMoved, true, "ND-09: E после переноса")
				return
			}
			w.requireAsk(d, "v_get", pcrRepoType, ndXMoved, true, "ND-09 близнец: D")
			w.requireAsk(e, "v_get", pcrRepoType, ndXMoved, false, "ND-09 близнец: E")
		})
	}
}

// ND-10: у класса нет второй дороги к потомкам — снятие объявления
// `publicReadToChildren` снимает чтение классу; человеку вложенное правило
// оставляет право.
func TestNestedWorld_ND10_ClassHasNoSecondRoadToDescendants(t *testing.T) {
	for _, c := range []struct {
		class   string
		speaker func(w *ndWorld) string
	}{
		{"anonymous", func(*ndWorld) string { return pcrAnon }},
		{"authenticated", func(w *ndWorld) string { return w.usr(w.usrE) }},
	} {
		t.Run(c.class, func(t *testing.T) {
			w := newNDWorld(t, "ND-10 "+c.class, nil)
			ids := []string{
				w.grant(classSubject(c.class), ndRolPublicRead, pcrXTarget(), "ND-10: класс"),
				w.grant(userSubject(w.usrD), ndRolPublicRead, pcrXTarget(), "ND-10: usr-D"),
			}
			sp, d := c.speaker(w), w.usr(w.usrD)
			w.pollAsk(sp, "v_get", pcrRepoType, pcrXApp, true, "ND-10 близнец до снятия: класс")
			w.pollAsk(d, "v_get", pcrRepoType, pcrXApp, true, "ND-10 близнец до снятия: usr-D")

			w.deliverPriorEdition()
			for _, id := range ids {
				ctx, cancel := context.WithTimeout(w.ctx, 30*time.Second)
				require.NoError(t, w.rec.ReconcileBinding(ctx, domain.AccessBindingID(id)), "ND-10: полный проход")
				cancel()
			}
			w.requireAsk(sp, "v_get", pcrRepoType, pcrXApp, false, "ND-10: класс после снятия объявления")
			w.requireAsk(d, "v_get", pcrRepoType, pcrXApp, true, "ND-10: usr-D после снятия объявления")
		})
	}
}

// ND-11 (а): вся область — вложенное правило внутри всех контейнеров области.
// Близнец — роль без children.
func TestNestedWorld_ND11_WholeScopeReachesEveryContainer(t *testing.T) {
	w := newNDWorld(t, "ND-11", nil)
	w.grant(userSubject(w.usrE), ndRolReader, ndAllInScope(), "ND-11: reader allInScope")
	w.grant(userSubject(w.usrD), ndRolViewer, ndAllInScope(), "ND-11 близнец: viewer allInScope")
	e, d := w.usr(w.usrE), w.usr(w.usrD)
	w.pollAsk(e, "v_get", pcrRepoType, pcrYApp, true, "ND-11: …02/app")
	require.Equal(t, []bool{true, true, true, true}, w.batch(e, ndPX, ndPXApp, ndPY, ndPYApp), "ND-11: BatchCheck")
	w.registerRepository(pcrX, "late")
	w.pollAsk(e, "v_get", pcrRepoType, pcrXLate, true, "ND-11: …01/late")
	w.pollAsk(d, "v_get", pcrRegType, ndYTgt, true, "ND-11 близнец: Y")
	require.Equal(t, []bool{true, false, true, false}, w.batch(d, ndPX, ndPXApp, ndPY, ndPYApp), "ND-11 близнец: BatchCheck")
}

// ND-12: цель не называет объект типа, покрытого только вложенным правилом.
func TestNestedWorld_ND12_TargetCannotNameATypeCoveredOnlyByANestedRule(t *testing.T) {
	w := newNDWorld(t, "ND-12", nil)
	op, err := w.ab.Create(asUser(w.ctx, w.usrA), w.grantRequest(userSubject(w.usrD), ndRolReader,
		resourcesTarget(&iamv1.ResourceRef{Type: "registry.repositories", Id: pcrXApp})))
	require.Nil(t, op, "ND-12: Operation не создаётся")
	requireSyncRefusal(t, err, codes.FailedPrecondition,
		"role rolb812261cfaa239694 does not grant verbs on registry.repositories; target type must be covered by role.rules", "ND-12")
	w.createDone(asUser(w.ctx, w.usrA), w.grantRequest(userSubject(w.usrD), ndRolReader, pcrXTarget()), "ND-12 близнец: ND-02")
}
