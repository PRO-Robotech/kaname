// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// derive_parent_world_integration_test.go — сценарии DP-01…DP-06, DP-10…DP-17 и
// интеграционная половина DP-20 приёмки
// docs/engineering/acceptance/kaname-derives-the-parent-of-a-registered-object.md
// (отпечаток 1f2991d64d0f8a9b90f8dbcaabeadd8e6af3d2b38e4f573c5d49dfe1a5a1f6e8,
// задача PRO-Robotech/kaname#982): родителя регистрируемого объекта выводит
// kaname, а писать модуль может только объявленное манифестом.
//
// Мир ДР = мир П6 (`newPCRWorld`, после переписи — доставлен документ W:
// прежняя редакция registry плюс `writes: owner`) плюс проекты prj-A2 (в acc-A)
// и prj-C (в acc-B) и обработчик с воротами домена модуля (`hReg`). Все «Когда»,
// кроме DP-06 и DP-20, — `InternalIAMService.RegisterResource` через обработчик,
// то есть через правило проксируемой записи и use-case с политикой и выводом.
//
// «Ничего не записано» утверждается снимком С(obj): строка зеркала, цепь, число
// фактов и число событий перерасчёта объекта — до и после равны.

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Ключи мира ДР. До «Когда» каждый не регистрировался, если «Дано» не говорит
// иного.
const (
	dpQ    = "e12813c6a/abc123"
	dpQ2   = "e12813c6a/q2"
	dpQ3   = "e12813c6a/q3"
	dpK    = "e12813c6a/k"
	dpB    = "e12813c6a/b"
	dpC    = "e12813c6a/c"
	dpD    = "e12813c6a/d"
	dpF    = "e12813c6a/f"
	dpN2   = "enp00000000000000092"
	dpN3   = "enp00000000000000093"
	dpPrjZ = "prj00000000000000099" // форма проекта, которого в kaname нет

	dpNetType = "vpc_network"
)

// dpCatalogType — имя каталога по имени модели для чтений снимка.
var dpCatalogType = map[string]string{
	pcrRegType:  "registry.registries",
	pcrRepoType: "registry.repositories",
	dpNetType:   "vpc.network",
}

// dpWorld — мир ДР одной базы.
type dpWorld struct {
	*pcrWorld
	prjA2, prjC domain.ProjectID
}

// newDPWorld поднимает мир ДР поверх мира П6.
func newDPWorld(t *testing.T) *dpWorld {
	t.Helper()
	p := newPCRWorld(t)
	return &dpWorld{
		pcrWorld: p,
		prjA2:    seedProjectInAccount(t, p.ctx, p.pool, p.accA, "prj-dp-a2"),
		prjC:     seedProjectInAccount(t, p.ctx, p.pool, p.accB, "prj-dp-c"),
	}
}

// dpGate — заглушка порта личности: ворота отвечают доменом модуля.
type dpGate struct{ module string }

func (g dpGate) Authorize(context.Context) (string, error) { return g.module, nil }

// hReg — обработчик с воротами домена module поверх use-case мира.
func (w *dpWorld) hReg(module string) *internaliam.Handler {
	return internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).
		WithResourceRegistrar(w.reg, dpGate{module: module})
}

// register — `RegisterResource` через обработчик модуля.
func (w *dpWorld) register(module string, req *iamv1.RegisterResourceRequest) error {
	_, err := w.hReg(module).RegisterResource(w.ctx, req)
	return err
}

// dpReq — тело регистрации.
//
// Версия владельца — СВОЯ у каждого запроса и монотонная (`dpVersion`): без неё
// повторная регистрация того же объекта (перенос под другой контейнер, правка
// сведений) была бы доставкой без версии, а такая строку зеркала не
// переписывает (`source_version` '-infinity' не новее хранимой), и «Дано» сцены
// не строилось бы.
func dpReq(subject, relation, object, prj, acc string, chain ...string) *iamv1.RegisterResourceRequest {
	return &iamv1.RegisterResourceRequest{
		SubjectId: subject, Relation: relation, Object: object,
		ParentProjectId: prj, ParentAccountId: acc, ParentChain: chain,
		SourceVersion: dpVersion(),
	}
}

// dpClock — счётчик версий запросов мира ДР: каждая следующая новее прежней на
// микросекунду от общего начала, при любом разрешении часов машины.
var dpClock = struct {
	sync.Mutex
	at time.Time
}{at: time.Now()}

// dpVersion — следующая версия владельца.
func dpVersion() *timestamppb.Timestamp {
	dpClock.Lock()
	defer dpClock.Unlock()
	dpClock.at = dpClock.at.Add(time.Microsecond)
	return timestamppb.New(dpClock.at)
}

// regIn — регистрация реестра указателем `project` в проекте prj аккаунта acc.
func (w *dpWorld) regIn(id string, prj domain.ProjectID, acc domain.AccountID) *iamv1.RegisterResourceRequest {
	return dpReq("project:"+string(prj), "project", pcrRegType+":"+id, string(prj), string(acc),
		"project:"+string(prj), "account:"+string(acc))
}

// r0 — базовый запрос R0 группы B для объекта id.
func (w *dpWorld) r0(id string) *iamv1.RegisterResourceRequest { return w.regIn(id, w.prjA, w.accA) }

// r1 — R0 без сведений о родителе.
func (w *dpWorld) r1(id string) *iamv1.RegisterResourceRequest {
	return dpReq("project:"+string(w.prjA), "project", pcrRegType+":"+id, "", "")
}

// r2 — базовый запрос R2 группы C: ребёнок `X/new` под X.
func (w *dpWorld) r2() *iamv1.RegisterResourceRequest {
	return dpReq(pcrRegType+":"+pcrX, "parent", pcrRepoType+":"+pcrX+"/new", string(w.prjA), string(w.accA),
		pcrRegType+":"+pcrX, "project:"+string(w.prjA), "account:"+string(w.accA))
}

// ownerOn — кортеж `owner` субъекта subject на объекте obj с полями области.
func ownerOn(subject, obj, prj, acc string, chain ...string) *iamv1.RegisterResourceRequest {
	return dpReq(subject, "owner", obj, prj, acc, chain...)
}

// requireOK — регистрация принята.
func (w *dpWorld) requireOK(module string, req *iamv1.RegisterResourceRequest, why string) {
	w.t.Helper()
	require.NoErrorf(w.t, w.register(module, req), "%s: регистрация %s %s %s обязана пройти",
		why, req.GetSubjectId(), req.GetRelation(), req.GetObject())
}

// redeliverP0 — передоставка P0 поверх W: строки каталога registry снова несут
// политику «только указатель».
func (w *dpWorld) redeliverP0() {
	w.t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.PriorEditionFile)
	require.NoError(w.t, err, "фикстура P0")
	m, err := manifest.Load(doc)
	require.NoError(w.t, err, "фикстура P0 обязана загружаться")
	w.applyDelivered("передоставка P0", m)
}

// dpSnap — снимок С(obj).
type dpSnap struct {
	mirror string // «проект|аккаунт|метки»; пусто — строки нет
	chain  string
	facts  string // факты объекта «отношение@субъект» через запятую, по порядку
	events int
}

// snap — снимок С(obj) объекта типа модели modelType.
func (w *dpWorld) snap(modelType, id string) dpSnap {
	w.t.Helper()
	dotted := dpCatalogType[modelType]
	require.NotEmptyf(w.t, dotted, "снимок: тип %s мира ДР не известен", modelType)
	var s dpSnap
	err := w.pool.QueryRow(w.ctx, `
		SELECT parent_project_id || '|' || parent_account_id || '|' || labels::text
		  FROM kaname.resource_mirror WHERE object_type = $1 AND object_id = $2`, dotted, id).Scan(&s.mirror)
	if err != nil {
		require.ErrorIsf(w.t, err, pgx.ErrNoRows, "снимок %s:%s: строка зеркала", modelType, id)
	}
	s.chain = strings.Join(w.chain(modelType, id), ",")
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT coalesce(string_agg(relation || '@' || subject, ',' ORDER BY relation, subject), '')
		   FROM kaname.relation_fact WHERE object_type = $1 AND object_id = $2`,
		modelType, id).Scan(&s.facts))
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.resource_reconcile_outbox WHERE object_type IN ($1, $2) AND object_id = $3`,
		modelType, dotted, id).Scan(&s.events))
	return s
}

// chain — цепь предков объекта в порядке глубины.
func (w *dpWorld) chain(modelType, id string) []string {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx, `
		SELECT parent_type || ':' || parent_id FROM kaname.resource_parent_edge
		 WHERE object_type = $1 AND object_id = $2 ORDER BY depth`, modelType, id)
	require.NoError(w.t, err)
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(w.t, err)
	return out
}

// mirrorScope — проект и аккаунт строки зеркала; ok=false — строки нет.
func (w *dpWorld) mirrorScope(modelType, id string) (prj, acc string, ok bool) {
	w.t.Helper()
	err := w.pool.QueryRow(w.ctx, `
		SELECT parent_project_id, parent_account_id FROM kaname.resource_mirror
		 WHERE object_type = $1 AND object_id = $2`, dpCatalogType[modelType], id).Scan(&prj, &acc)
	if err != nil {
		require.ErrorIs(w.t, err, pgx.ErrNoRows)
		return "", "", false
	}
	return prj, acc, true
}

// ownerFacts — число фактов `owner` на объекте; with — есть ли среди них subject.
func (w *dpWorld) ownerFacts(modelType, id, subject string) (n int, with bool) {
	w.t.Helper()
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `
		SELECT count(*), coalesce(bool_or(subject = $3), false) FROM kaname.relation_fact
		 WHERE object_type = $1 AND object_id = $2 AND relation = 'owner'`, modelType, id, subject).Scan(&n, &with))
	return n, with
}

// requirePD — тело отказа политики: `PERMISSION_DENIED`, `permission denied`,
// деталей нет — побайтово как у правила проксируемой записи.
func requirePD(t *testing.T, err error, why string) {
	t.Helper()
	require.Errorf(t, err, "%s: ожидался ПД-отказ, регистрация принята", why)
	st := status.Convert(err)
	require.Equalf(t, codes.PermissionDenied, st.Code(), "%s: код (%v)", why, err)
	require.Equalf(t, "permission denied", st.Message(), "%s: текст", why)
	require.Emptyf(t, st.Details(), "%s: у ПД-отказа деталей нет", why)
}

// requireP8 — тело отказа вывода для объекта obj (`<тип>:<id>`).
func requireP8(t *testing.T, err error, obj, why string) {
	t.Helper()
	require.Errorf(t, err, "%s: ожидался отказ вывода для %s, регистрация принята", why, obj)
	st := status.Convert(err)
	require.Equalf(t, codes.FailedPrecondition, st.Code(), "%s: код (%v)", why, err)
	require.Equalf(t, obj+" parent scope does not match", st.Message(), "%s: текст", why)
	require.Lenf(t, st.Details(), 1, "%s: у отказа вывода ровно одна деталь", why)
	info, ok := st.Details()[0].(*errdetails.ErrorInfo)
	require.Truef(t, ok, "%s: деталь — не ErrorInfo: %T", why, st.Details()[0])
	typ, id, _ := strings.Cut(obj, ":")
	require.Equalf(t, "PARENT_SCOPE_MISMATCH", info.GetReason(), "%s: причина", why)
	require.Equalf(t, refusaldomain.For(refusaldomain.ServiceIAM), info.GetDomain(), "%s: домен", why)
	require.Equalf(t, map[string]string{"resource_type": typ, "resource_id": id}, info.GetMetadata(), "%s: metadata", why)
}

// requireNothing — у объекта нет ни строки зеркала, ни цепи, ни фактов, ни
// событий перерасчёта.
func (w *dpWorld) requireNothing(modelType, id, why string) {
	w.t.Helper()
	require.Equalf(w.t, dpSnap{}, w.snap(modelType, id), "%s: у %s:%s записано", why, modelType, id)
}

// TestDeriveParent_DP01_WriteOutsidePolicyIsRefused — DP-01.
func TestDeriveParent_DP01_WriteOutsidePolicyIsRefused(t *testing.T) {
	w := newDPWorld(t)
	w.redeliverP0()
	prj, acc := string(w.prjA), string(w.accA)
	cases := []struct {
		name string
		req  *iamv1.RegisterResourceRequest
		typ  string
		id   string
	}{
		{"a", ownerOn("user:"+string(w.usrA), pcrRepoType+":"+pcrYApp, prj, acc,
			pcrRegType+":"+pcrY, "project:"+prj, "account:"+acc), pcrRepoType, pcrYApp},
		{"b", ownerOn("user:"+string(w.usrB), pcrRegType+":"+pcrX, prj, acc,
			"project:"+prj, "account:"+acc), pcrRegType, pcrX},
		{"c", dpReq("user:"+string(w.usrA), "project", pcrRegType+":"+dpQ, prj, acc,
			"project:"+prj, "account:"+acc), pcrRegType, dpQ},
		{"d", dpReq(pcrRegType+":"+pcrX, "project", pcrRepoType+":"+pcrX+"/new", prj, acc,
			pcrRegType+":"+pcrX, "project:"+prj, "account:"+acc), pcrRepoType, pcrX + "/new"},
		{"e", dpReq("project:"+prj, "parent", pcrRepoType+":"+pcrX+"/new", prj, acc,
			pcrRegType+":"+pcrX, "project:"+prj, "account:"+acc), pcrRepoType, pcrX + "/new"},
	}
	for _, tc := range cases {
		before := w.snap(tc.typ, tc.id)
		requirePD(t, w.register("registry", tc.req), "DP-01 "+tc.name)
		require.Equalf(t, before, w.snap(tc.typ, tc.id), "DP-01 %s: С(obj) изменился", tc.name)
	}
}

// TestDeriveParent_DP02_PointerWithinPolicyPasses — DP-02.
func TestDeriveParent_DP02_PointerWithinPolicyPasses(t *testing.T) {
	w := newDPWorld(t)
	w.requireOK("registry", w.r0(dpQ), "DP-02 a")
	prj, acc, ok := w.mirrorScope(pcrRegType, dpQ)
	require.True(t, ok, "DP-02 a: строки зеркала Q нет")
	require.Equal(t, []string{string(w.prjA), string(w.accA)}, []string{prj, acc}, "DP-02 a: область строки")
	require.Equal(t, []string{"project:" + string(w.prjA), "account:" + string(w.accA)}, w.chain(pcrRegType, dpQ), "DP-02 a: цепь")

	w.requireOK("registry", w.r2(), "DP-02 b")
	prj, acc, ok = w.mirrorScope(pcrRepoType, pcrX+"/new")
	require.True(t, ok, "DP-02 b: строки зеркала X/new нет")
	require.Equal(t, []string{string(w.prjA), string(w.accA)}, []string{prj, acc}, "DP-02 b: область строки")
	require.Equal(t, []string{pcrRegType + ":" + pcrX, "project:" + string(w.prjA), "account:" + string(w.accA)},
		w.chain(pcrRepoType, pcrX+"/new"), "DP-02 b: цепь")
}

// TestDeriveParent_DP03_DeclaredWritesAdmitsTheCreator — DP-03.
func TestDeriveParent_DP03_DeclaredWritesAdmitsTheCreator(t *testing.T) {
	w := newDPWorld(t)
	prj, acc := string(w.prjA), string(w.accA)
	regChain := []string{"project:" + prj, "account:" + acc}
	before, _ := w.ownerFacts(pcrRegType, pcrX, "")

	w.requireOK("registry", ownerOn("user:"+string(w.usrB), pcrRegType+":"+pcrX, prj, acc, regChain...), "DP-03 a")
	n, with := w.ownerFacts(pcrRegType, pcrX, "user:"+string(w.usrB))
	require.True(t, with, "DP-03 a: факта owner usr-B на X нет")
	require.Equal(t, before+1, n, "DP-03 a: фактов owner на X")

	repoBefore, _ := w.ownerFacts(pcrRepoType, pcrYApp, "")
	w.requireOK("registry", ownerOn("user:"+string(w.usrA), pcrRepoType+":"+pcrYApp, prj, acc,
		pcrRegType+":"+pcrY, "project:"+prj, "account:"+acc), "DP-03 b")
	repoAfter, _ := w.ownerFacts(pcrRepoType, pcrYApp, "")
	require.Equal(t, repoBefore, repoAfter, "DP-03 b: повтор кортежа owner usr-A прибавил факт")

	w.requireOK("registry", ownerOn("service_account:"+w.svaA, pcrRegType+":"+pcrX, prj, acc, regChain...), "DP-03 c")
	n, with = w.ownerFacts(pcrRegType, pcrX, "service_account:"+w.svaA)
	require.True(t, with, "DP-03 c: факта owner sva-A на X нет")
	require.Equal(t, before+2, n, "DP-03 c: фактов owner на X")

	requirePD(t, w.register("registry", ownerOn("group:"+w.grpA, pcrRegType+":"+pcrX, prj, acc, regChain...)), "DP-03 d")
	n, _ = w.ownerFacts(pcrRegType, pcrX, "")
	require.Equal(t, before+2, n, "DP-03 d: отказ прибавил факт owner")
}

// TestDeriveParent_DP04_VpcPolicyFromTheSeededCatalog — DP-04.
func TestDeriveParent_DP04_VpcPolicyFromTheSeededCatalog(t *testing.T) {
	w := newDPWorld(t)
	obj := dpNetType + ":" + dpN2
	req := dpReq("project:"+string(w.prjA), "project", obj, string(w.prjA), "", "project:"+string(w.prjA))

	bad := dpReq("user:"+string(w.usrA), "project", obj, string(w.prjA), "", "project:"+string(w.prjA))
	requirePD(t, w.register("vpc", bad), "DP-04 b")
	w.requireNothing(dpNetType, dpN2, "DP-04 b")

	w.requireOK("vpc", req, "DP-04 a")
	prj, _, ok := w.mirrorScope(dpNetType, dpN2)
	require.True(t, ok, "DP-04 a: строки зеркала vpc.network/N2 нет")
	require.Equal(t, string(w.prjA), prj, "DP-04 a: проект строки")
	require.Equal(t, []string{"project:" + string(w.prjA)}, w.chain(dpNetType, dpN2), "DP-04 a: цепь")
}

// TestDeriveParent_DP05_UnregistrationIsNotJudgedByPolicy — DP-05.
func TestDeriveParent_DP05_UnregistrationIsNotJudgedByPolicy(t *testing.T) {
	w := newDPWorld(t)
	w.redeliverP0()
	owner := "user:" + string(w.usrA)
	obj := pcrRepoType + ":" + pcrYApp
	prj, acc := string(w.prjA), string(w.accA)

	requirePD(t, w.register("registry", ownerOn(owner, obj, prj, acc,
		pcrRegType+":"+pcrY, "project:"+prj, "account:"+acc)), "DP-05 близнец (DP-01 a)")

	_, err := w.hReg("registry").UnregisterResource(w.ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: owner, Relation: "owner", Object: obj,
	})
	require.NoError(t, err, "DP-05: снятие кортежа owner обязано пройти")
	n, _ := w.ownerFacts(pcrRepoType, pcrYApp, "")
	require.Zero(t, n, "DP-05: факты owner на Y/app остались")
}

// TestDeriveParent_DP06_PolicyIsHeldByTheUseCase — DP-06.
func TestDeriveParent_DP06_PolicyIsHeldByTheUseCase(t *testing.T) {
	for _, tc := range []struct {
		name       string
		redeliver  bool
		wantRefuse bool
	}{{"a", true, true}, {"b", false, false}} {
		t.Run(tc.name, func(t *testing.T) {
			w := newDPWorld(t)
			if tc.redeliver {
				w.redeliverP0()
			}
			prj, acc := string(w.prjA), string(w.accA)
			req := ownerOn("user:"+string(w.usrB), pcrRepoType+":"+pcrYApp, prj, acc,
				pcrRegType+":"+pcrY, "project:"+prj, "account:"+acc)
			before := w.snap(pcrRepoType, pcrYApp)
			ownersBefore, _ := w.ownerFacts(pcrRepoType, pcrYApp, "")
			err := w.reg.Register(w.ctx, req)
			if tc.wantRefuse {
				requirePD(t, shared.MapRepoErr(err), "DP-06 a (вход мимо обработчика)")
				require.Equal(t, before, w.snap(pcrRepoType, pcrYApp), "DP-06 a: С(Y/app) изменился")
				return
			}
			require.NoError(t, err, "DP-06 b: use-case обязан принять запись при действующем W")
			n, with := w.ownerFacts(pcrRepoType, pcrYApp, "user:"+string(w.usrB))
			require.True(t, with, "DP-06 b: факта owner usr-B нет")
			require.Equal(t, ownersBefore+1, n, "DP-06 b: фактов owner на Y/app")
		})
	}
}

// TestDeriveParent_DP10_ScopeAgainstHierarchyIsRefused — DP-10.
func TestDeriveParent_DP10_ScopeAgainstHierarchyIsRefused(t *testing.T) {
	w := newDPWorld(t)
	prjA, accA := string(w.prjA), string(w.accA)
	objQ := pcrRegType + ":" + dpQ
	withChain := func(chain ...string) *iamv1.RegisterResourceRequest {
		r := w.r0(dpQ)
		r.ParentChain = chain
		return r
	}
	b := w.r0(dpQ)
	b.ParentAccountId = string(w.accB)
	c := w.r0(dpQ)
	c.ParentProjectId = string(w.prjA2)
	g := w.r1(dpB)
	g.SubjectId = "project:" + dpPrjZ
	cases := []struct {
		name, module string
		req          *iamv1.RegisterResourceRequest
		obj          string
	}{
		{"a", "registry", withChain("project:"+prjA, "account:"+string(w.accB)), objQ},
		{"b", "registry", b, objQ},
		{"c", "registry", c, objQ},
		{"d", "registry", withChain("project:"+string(w.prjA2), "account:"+accA), objQ},
		{"e", "registry", withChain("project:"+prjA, "project:"+string(w.prjA2), "account:"+accA), objQ},
		{"f", "registry", withChain("account:"+accA, "project:"+prjA), objQ},
		{"g", "registry", g, pcrRegType + ":" + dpB},
		{"h", "vpc", dpReq("project:"+prjA, "project", dpNetType+":"+dpN3, prjA, "",
			"project:"+prjA, "account:"+string(w.accB)), dpNetType + ":" + dpN3},
	}
	for _, tc := range cases {
		typ, id, _ := strings.Cut(tc.obj, ":")
		err := w.register(tc.module, tc.req)
		requireP8(t, err, tc.obj, "DP-10 "+tc.name)
		w.requireNothing(typ, id, "DP-10 "+tc.name)
		again := w.register(tc.module, tc.req)
		requireP8(t, again, tc.obj, "DP-10 "+tc.name+" (повтор)")
		require.Equalf(t, status.Convert(err).Proto().String(), status.Convert(again).Proto().String(),
			"DP-10 %s: повтор дал другой ответ", tc.name)
	}
}

// TestDeriveParent_DP11_AgreeingScopePassesOmittedIsNotFilled — DP-11.
func TestDeriveParent_DP11_AgreeingScopePassesOmittedIsNotFilled(t *testing.T) {
	w := newDPWorld(t)
	prjA, accA := string(w.prjA), string(w.accA)

	w.requireOK("registry", w.r0(dpQ), "DP-11 a")
	prj, acc, _ := w.mirrorScope(pcrRegType, dpQ)
	require.Equal(t, []string{prjA, accA}, []string{prj, acc}, "DP-11 a: область строки")
	require.Equal(t, []string{"project:" + prjA, "account:" + accA}, w.chain(pcrRegType, dpQ), "DP-11 a: цепь")

	w.requireOK("registry", w.r1(dpB), "DP-11 b")
	prj, acc, ok := w.mirrorScope(pcrRegType, dpB)
	require.True(t, ok, "DP-11 b: строки зеркала нет")
	require.Equal(t, []string{"", ""}, []string{prj, acc}, "DP-11 b: опущенное дописано")
	require.Empty(t, w.chain(pcrRegType, dpB), "DP-11 b: цепь дописана")

	c := w.r0(dpC)
	c.ParentChain = []string{"project:" + prjA}
	w.requireOK("registry", c, "DP-11 c")
	require.Equal(t, []string{"project:" + prjA}, w.chain(pcrRegType, dpC), "DP-11 c: цепь")

	d := w.r0(dpD)
	d.ParentChain = []string{"account:" + accA}
	w.requireOK("registry", d, "DP-11 d")
	require.Equal(t, []string{"account:" + accA}, w.chain(pcrRegType, dpD), "DP-11 d: цепь")

	w.requireOK("vpc", dpReq("project:"+prjA, "project", dpNetType+":"+dpN3, prjA, "",
		"project:"+prjA, "account:"+accA), "DP-11 e")
	prj, _, _ = w.mirrorScope(dpNetType, dpN3)
	require.Equal(t, prjA, prj, "DP-11 e: проект строки")
	require.Equal(t, []string{"project:" + prjA, "account:" + accA}, w.chain(dpNetType, dpN3), "DP-11 e: цепь")

	f := w.r0(dpF)
	f.ParentProjectId = ""
	w.requireOK("registry", f, "DP-11 f")
	prj, _, _ = w.mirrorScope(pcrRegType, dpF)
	require.Empty(t, prj, "DP-11 f: опущенный проект дописан")
	require.Equal(t, []string{"project:" + prjA, "account:" + accA}, w.chain(pcrRegType, dpF), "DP-11 f: цепь")
}

// TestDeriveParent_DP12_ChildAgainstContainerIsRefused — DP-12.
func TestDeriveParent_DP12_ChildAgainstContainerIsRefused(t *testing.T) {
	w := newDPWorld(t)
	prjA, accA := string(w.prjA), string(w.accA)
	childX := pcrRepoType + ":" + pcrX + "/new"
	containers := []string{pcrX, pcrY}
	// refused — запрос отвергнут отказом вывода, у ребёнка ничего не записано, и
	// снимки контейнеров до и после ИМЕННО ЭТОГО запроса равны.
	refused := func(name string, req *iamv1.RegisterResourceRequest, child string) {
		t.Helper()
		before := make([]dpSnap, len(containers))
		for i, c := range containers {
			before[i] = w.snap(pcrRegType, c)
		}
		requireP8(t, w.register("registry", req), child, "DP-12 "+name)
		_, childID, _ := strings.Cut(child, ":")
		w.requireNothing(pcrRepoType, childID, "DP-12 "+name)
		for i, c := range containers {
			require.Equalf(t, before[i], w.snap(pcrRegType, c), "DP-12 %s: С(%s) изменился", name, c)
		}
	}

	a := w.r2()
	a.ParentChain = []string{pcrRegType + ":" + pcrX, "project:" + string(w.prjA2), "account:" + accA}
	refused("a", a, childX)

	b := w.r2()
	b.ParentProjectId = string(w.prjA2)
	refused("b", b, childX)

	w.requireOK("registry", w.regIn(dpQ, w.prjA, w.accA), "DP-12 c: «Дано»")
	containers = append(containers, dpQ)
	c := dpReq(pcrRegType+":"+dpQ, "parent", pcrRepoType+":"+dpQ+"/new", string(w.prjC), string(w.accB),
		pcrRegType+":"+dpQ, "project:"+string(w.prjC), "account:"+string(w.accB))
	refused("c", c, pcrRepoType+":"+dpQ+"/new")

	d := w.r2()
	d.ParentChain = []string{pcrRegType + ":" + pcrY, "project:" + prjA, "account:" + accA}
	refused("d", d, childX)

	e := dpReq(pcrRegType+":"+dpQ2, "parent", pcrRepoType+":"+dpQ2+"/new", prjA, accA,
		pcrRegType+":"+dpQ2, "project:"+prjA, "account:"+accA)
	refused("e", e, pcrRepoType+":"+dpQ2+"/new")
}

// TestDeriveParent_DP13_ChildAgreeingWithContainerPasses — DP-13.
func TestDeriveParent_DP13_ChildAgreeingWithContainerPasses(t *testing.T) {
	w := newDPWorld(t)
	prjA, accA := string(w.prjA), string(w.accA)

	w.requireOK("registry", w.r2(), "DP-13 a")
	prj, acc, _ := w.mirrorScope(pcrRepoType, pcrX+"/new")
	require.Equal(t, []string{prjA, accA}, []string{prj, acc}, "DP-13 a: область строки ребёнка")
	require.Equal(t, []string{pcrRegType + ":" + pcrX, "project:" + prjA, "account:" + accA},
		w.chain(pcrRepoType, pcrX+"/new"), "DP-13 a: цепь")

	b := w.r2()
	b.ParentProjectId, b.ParentAccountId = "", ""
	b.ParentChain = []string{pcrRegType + ":" + pcrX}
	w.requireOK("registry", b, "DP-13 b")
	prj, acc, _ = w.mirrorScope(pcrRepoType, pcrX+"/new")
	require.Equal(t, []string{"", ""}, []string{prj, acc}, "DP-13 b: опущенное дописано")
	require.Equal(t, []string{pcrRegType + ":" + pcrX}, w.chain(pcrRepoType, pcrX+"/new"), "DP-13 b: цепь")

	w.requireOK("registry", w.regIn(dpQ, w.prjC, w.accB), "DP-13 c: «Дано»")
	prjC, accB := string(w.prjC), string(w.accB)
	w.requireOK("registry", dpReq(pcrRegType+":"+dpQ, "parent", pcrRepoType+":"+dpQ+"/new", prjC, accB,
		pcrRegType+":"+dpQ, "project:"+prjC, "account:"+accB), "DP-13 c")
	prj, acc, _ = w.mirrorScope(pcrRepoType, dpQ+"/new")
	require.Equal(t, []string{prjC, accB}, []string{prj, acc}, "DP-13 c: область строки ребёнка")
	require.Equal(t, []string{pcrRegType + ":" + dpQ, "project:" + prjC, "account:" + accB},
		w.chain(pcrRepoType, dpQ+"/new"), "DP-13 c: цепь")

	w.requireOK("registry", w.regIn(dpQ2, w.prjA, w.accA), "DP-13 d: «Дано»")
	w.requireOK("registry", dpReq(pcrRegType+":"+dpQ2, "parent", pcrRepoType+":"+dpQ2+"/new", prjA, accA,
		pcrRegType+":"+dpQ2, "project:"+prjA, "account:"+accA), "DP-13 d")
	prj, _, _ = w.mirrorScope(pcrRepoType, dpQ2+"/new")
	require.Equal(t, prjA, prj, "DP-13 d: проект строки ребёнка")
	require.Equal(t, []string{pcrRegType + ":" + dpQ2, "project:" + prjA, "account:" + accA},
		w.chain(pcrRepoType, dpQ2+"/new"), "DP-13 d: цепь")
}

// TestDeriveParent_DP14_UnknownContainerProjectIsNotDerived — DP-14.
func TestDeriveParent_DP14_UnknownContainerProjectIsNotDerived(t *testing.T) {
	w := newDPWorld(t)
	w.requireOK("registry", w.r1(dpK), "DP-14 «Дано»")
	child := pcrRepoType + ":" + dpK + "/new"

	a := dpReq(pcrRegType+":"+dpK, "parent", child, "", "", pcrRegType+":"+dpK, "project:"+string(w.prjA))
	requireP8(t, w.register("registry", a), child, "DP-14 a")
	_, _, ok := w.mirrorScope(pcrRepoType, dpK+"/new")
	require.False(t, ok, "DP-14 a: строка зеркала ребёнка записана")

	b := dpReq(pcrRegType+":"+dpK, "parent", child, "", "", pcrRegType+":"+dpK)
	w.requireOK("registry", b, "DP-14 b")
	require.Equal(t, []string{pcrRegType + ":" + dpK}, w.chain(pcrRepoType, dpK+"/new"), "DP-14 b: цепь")
}

// TestDeriveParent_DP15_CreatorIsCheckedAgainstTheDerivedParent — DP-15.
func TestDeriveParent_DP15_CreatorIsCheckedAgainstTheDerivedParent(t *testing.T) {
	w := newDPWorld(t)
	prjA, accA := string(w.prjA), string(w.accA)
	usrB := "user:" + string(w.usrB)

	snapX := w.snap(pcrRegType, pcrX)
	a := ownerOn(usrB, pcrRegType+":"+pcrX, prjA, accA, "project:"+string(w.prjA2), "account:"+accA)
	requireP8(t, w.register("registry", a), pcrRegType+":"+pcrX, "DP-15 a")
	require.Equal(t, snapX, w.snap(pcrRegType, pcrX), "DP-15 a: С(X) изменился")

	b := ownerOn(usrB, pcrRegType+":"+dpQ3, prjA, accA, "project:"+prjA, "account:"+accA)
	requireP8(t, w.register("registry", b), pcrRegType+":"+dpQ3, "DP-15 b")
	w.requireNothing(pcrRegType, dpQ3, "DP-15 b")

	w.requireOK("registry", w.regIn(dpQ3, w.prjA, w.accA), "DP-15 c: «Дано»")
	// Тот же кортеж — новым намерением со своей версией: прежняя версия старше той,
	// с которой Q3 только что зарегистрирован указателем, и такую доставку зеркало
	// законно читает как запоздавшую — кортеж не ставится.
	b.SourceVersion = dpVersion()
	w.requireOK("registry", b, "DP-15 c")
	_, with := w.ownerFacts(pcrRegType, dpQ3, usrB)
	require.True(t, with, "DP-15 c: факта owner usr-B на Q3 нет")
}

// TestDeriveParent_DP16_PolicyComesBeforeDerivation — DP-16.
func TestDeriveParent_DP16_PolicyComesBeforeDerivation(t *testing.T) {
	w := newDPWorld(t)
	snapX := w.snap(pcrRegType, pcrX)
	req := ownerOn("group:"+w.grpA, pcrRegType+":"+pcrX, string(w.prjA), string(w.accA),
		"project:"+string(w.prjA2), "account:"+string(w.accA))
	requirePD(t, w.register("registry", req), "DP-16")
	require.Equal(t, snapX, w.snap(pcrRegType, pcrX), "DP-16: С(X) изменился")
}

// TestDeriveParent_DP17_CreatorAnchorIsTheDerivedParent — DP-17.
func TestDeriveParent_DP17_CreatorAnchorIsTheDerivedParent(t *testing.T) {
	type example struct {
		name   string
		given  func(w *dpWorld) *iamv1.RegisterResourceRequest
		when   func(w *dpWorld) *iamv1.RegisterResourceRequest
		typ    string
		id     string
		refuse bool
		// для принятых — область и цепь строки, как присланы (Р7)
		scoped bool // принятая несёт область prj-A, acc-A; иначе — пустую
		chain  func(w *dpWorld) []string
	}
	usrB := func(w *dpWorld) string { return "user:" + string(w.usrB) }
	givenD := func(w *dpWorld) *iamv1.RegisterResourceRequest {
		r := w.r0(dpD)
		r.ParentChain = []string{"account:" + string(w.accA)}
		return r
	}
	whenA := func(w *dpWorld) *iamv1.RegisterResourceRequest {
		return ownerOn(usrB(w), pcrRegType+":"+dpD, string(w.prjA), string(w.accA), "account:"+string(w.accA))
	}
	givenB := func(w *dpWorld) *iamv1.RegisterResourceRequest { return w.r1(dpB) }
	whenC := func(w *dpWorld) *iamv1.RegisterResourceRequest {
		return ownerOn(usrB(w), pcrRegType+":"+dpB, "", "")
	}
	givenMove := func(w *dpWorld) *iamv1.RegisterResourceRequest {
		return dpReq(pcrRegType+":"+pcrY, "parent", pcrRepoType+":"+pcrXApp, string(w.prjA), string(w.accA),
			pcrRegType+":"+pcrY, "project:"+string(w.prjA), "account:"+string(w.accA))
	}
	whenE := func(w *dpWorld) *iamv1.RegisterResourceRequest {
		return ownerOn(usrB(w), pcrRepoType+":"+pcrXApp, string(w.prjA), string(w.accA),
			pcrRegType+":"+pcrY, "project:"+string(w.prjA), "account:"+string(w.accA))
	}
	cases := []example{
		{name: "a", given: givenD, when: whenA, typ: pcrRegType, id: dpD, scoped: true,
			chain: func(w *dpWorld) []string { return []string{"account:" + string(w.accA)} }},
		{name: "b", given: givenD, when: func(w *dpWorld) *iamv1.RegisterResourceRequest {
			r := whenA(w)
			r.ParentChain = []string{"account:" + string(w.accB)}
			return r
		}, typ: pcrRegType, id: dpD, refuse: true},
		{name: "c", given: givenB, when: whenC, typ: pcrRegType, id: dpB,
			chain: func(*dpWorld) []string { return []string{} }},
		{name: "d", given: givenB, when: func(w *dpWorld) *iamv1.RegisterResourceRequest {
			r := whenC(w)
			r.ParentProjectId = string(w.prjA2)
			return r
		}, typ: pcrRegType, id: dpB, refuse: true},
		{name: "e", given: givenMove, when: whenE, typ: pcrRepoType, id: pcrXApp, scoped: true,
			chain: func(w *dpWorld) []string {
				return []string{pcrRegType + ":" + pcrY, "project:" + string(w.prjA), "account:" + string(w.accA)}
			}},
		{name: "f", given: givenMove, when: func(w *dpWorld) *iamv1.RegisterResourceRequest {
			r := whenE(w)
			r.ParentChain = []string{pcrRegType + ":" + pcrY, "project:" + string(w.prjA2), "account:" + string(w.accA)}
			return r
		}, typ: pcrRepoType, id: pcrXApp, refuse: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newDPWorld(t)
			w.requireOK("registry", tc.given(w), "DP-17 "+tc.name+": «Дано»")
			before := w.snap(tc.typ, tc.id)
			err := w.register("registry", tc.when(w))
			if tc.refuse {
				requireP8(t, err, tc.typ+":"+tc.id, "DP-17 "+tc.name)
				require.Equal(t, before, w.snap(tc.typ, tc.id), "DP-17 %s: С(obj) изменился", tc.name)
				return
			}
			require.NoErrorf(t, err, "DP-17 %s: запись создателя обязана пройти", tc.name)
			_, with := w.ownerFacts(tc.typ, tc.id, usrB(w))
			require.Truef(t, with, "DP-17 %s: факта owner usr-B нет", tc.name)
			wantPrj, wantAcc := "", ""
			if tc.scoped {
				wantPrj, wantAcc = string(w.prjA), string(w.accA)
			}
			prj, acc, _ := w.mirrorScope(tc.typ, tc.id)
			require.Equalf(t, []string{wantPrj, wantAcc}, []string{prj, acc}, "DP-17 %s: область строки дописана", tc.name)
			require.Equalf(t, tc.chain(w), w.chain(tc.typ, tc.id), "DP-17 %s: цепь", tc.name)
		})
	}
}

// dpPolicyReader — читатель политики записи (Р1): тот же порт, которым use-case
// судит регистрацию в её транзакции.
type dpPolicyReader interface {
	WritePolicyTx(ctx context.Context, tx service.Tx, typeName string) (dotted string, policy domain.WritePolicy, live bool, err error)
}

// readPolicy — тройки политики типа модели modelType словами «отношение:тип
// субъекта», в порядке сортировки.
func (w *dpWorld) readPolicy(modelType string) []string {
	w.t.Helper()
	reader, ok := any(kanamepg.NewCatalogTypeReader()).(dpPolicyReader)
	require.True(w.t, ok, "читатель политики записи не заведён (kaname#982)")
	tx, err := kanamepg.NewPoolTxBeginner(w.pool).Begin(w.ctx)
	require.NoError(w.t, err)
	defer func() { _ = tx.Rollback(w.ctx) }()
	_, policy, live, err := reader.WritePolicyTx(w.ctx, tx, modelType)
	require.NoError(w.t, err, "читатель политики: %s", modelType)
	require.Truef(w.t, live, "читатель политики: у типа %s нет живой строки", modelType)
	var out []string
	for _, tr := range policy.Triples() {
		require.Equal(w.t, modelType, tr.ObjectType, "читатель политики: тройка чужого типа")
		out = append(out, tr.Relation+":"+tr.SubjectType)
	}
	sort.Strings(out)
	return out
}

// TestDeriveParent_DP20_ij_PolicyFollowsTheDeliveredManifest — DP-20 i, j.
func TestDeriveParent_DP20_ij_PolicyFollowsTheDeliveredManifest(t *testing.T) {
	w := newDPWorld(t)
	prior, err := publicreadfixture.Read(publicreadfixture.PriorEditionFile)
	require.NoError(t, err)
	doc, err := publicreadfixture.WithWrites(prior)
	require.NoError(t, err)
	m, err := manifest.Load(doc)
	require.NoError(t, err, "DP-20 i: документ W обязан загружаться")
	w.applyDelivered("DP-20 i: повторная доставка W", m)
	require.Equal(t, []string{"owner:service_account", "owner:user", "project:project"},
		w.readPolicy(pcrRegType), "DP-20 i: политика registry_registry")
	require.Equal(t, []string{"owner:service_account", "owner:user", "parent:registry_registry"},
		w.readPolicy(pcrRepoType), "DP-20 i: политика registry_repository")

	w.redeliverP0()
	require.Equal(t, []string{"project:project"}, w.readPolicy(pcrRegType), "DP-20 j: политика registry_registry")
	require.Equal(t, []string{"parent:registry_registry"}, w.readPolicy(pcrRepoType), "DP-20 j: политика registry_repository")
}
