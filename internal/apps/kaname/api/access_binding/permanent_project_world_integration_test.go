// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// permanent_project_world_integration_test.go — сценарии PB-01…PB-13, PB-17…PB-25
// приёмки docs/engineering/acceptance/object-keeps-its-project-after-unregistration.md
// (отпечаток 9bd07e389bdce22cad13b556b4fe78cfda3f878285895282a5580fa211e5122a,
// задача PRO-Robotech/kaname#983): объект модуля остаётся привязан к проекту и
// после снятия регистрации.
//
// Мир ПП = мир ДР (`newDPWorld`: мир П6 плюс prj-A2 в acc-A и prj-C в acc-B) плюс
// версии владельца и доставка D-K — новой редакции registry с `writes: owner` и
// `permanentProject: true` на обоих ресурсах. Регистрация — use-case мира
// (`registerRegistry` мира П6 — тот же вход), отказ читается единственным
// переводчиком `shared.MapRepoErr`, как у обработчика.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Ключи мира ПП сверх ключей мира ДР.
const (
	ppZ        = "93124b19b/abc123"
	ppTeamApp  = "/team/app"
	ppRegCat   = "registry.registries"
	ppBoundFmt = "%s is bound to another project"
)

// ppWorld — мир ПП одной базы.
type ppWorld struct {
	*dpWorld
	ver time.Time
	mu  sync.Mutex
}

// newPPWorld поднимает мир ПП (без доставки D-K) и довязывает use-case
// регистрации тем, что корень службы ставит сверх мира П6 (как мир У): событие
// перерасчёта в той же транзакции, разрешение аккаунта по проекту и читатель
// остатка отношений снимаемого объекта — снятие снимает и кортеж `owner`.
func newPPWorld(t *testing.T) *ppWorld {
	t.Helper()
	w := &ppWorld{dpWorld: newDPWorld(t), ver: time.Now()}
	w.reg = w.reg.
		WithReconcile(kanamepg.NewReconcileEventEmitter()).
		WithAccountResolver(kanamepg.NewProjectAccountResolver()).
		WithResidualTupleReader(kanamepg.NewResidualTupleReader(w.pool))
	return w
}

// withObject — тот же запрос регистрации с другим объектом.
func withObject(r *iamv1.RegisterResourceRequest, obj string) *iamv1.RegisterResourceRequest {
	r.Object = obj
	return r
}

// next — монотонная версия владельца: каждое следующее намерение новее.
func (w *ppWorld) next() *timestamppb.Timestamp {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ver = w.ver.Add(time.Second)
	return timestamppb.New(w.ver)
}

// deliver — доставка документа registry путём старта.
func (w *ppWorld) deliver(what string, doc []byte) {
	w.t.Helper()
	m, err := manifest.Load(doc)
	if err != nil {
		w.t.Fatalf("%s: загрузчик отверг документ (ключ %s; предмета kaname#983 нет): %v",
			what, publicreadfixture.PermanentProjectKey, err)
	}
	w.applyDelivered(what, m)
}

// deliverDK — доставка D-K. Перед ней — контроль: тот же документ без ключа
// загружается, и сломанная фикстура за отсутствующий ключ себя не выдаёт.
func (w *ppWorld) deliverDK() {
	w.t.Helper()
	dk, err := publicreadfixture.PermanentProjectDocument()
	require.NoError(w.t, err, "фикстура D-K")
	keyless, err := publicreadfixture.WithoutPermanentProject(dk)
	require.NoError(w.t, err, "фикстура D-K без ключа")
	_, err = manifest.Load(keyless)
	require.NoError(w.t, err, "контроль фикстуры: D-K без ключа обязан загружаться")
	w.deliver("доставка D-K", dk)
}

// call — регистрация use-case мира; отказ — тем же переводчиком, что у обработчика.
func (w *ppWorld) call(req *iamv1.RegisterResourceRequest) error {
	return shared.MapRepoErr(w.reg.Register(w.ctx, req))
}

// regReq — кортеж `project` регистрации реестра id в проекте prj аккаунта acc со
// следующей версией.
func (w *ppWorld) regReq(id string, prj domain.ProjectID, acc domain.AccountID) *iamv1.RegisterResourceRequest {
	r := w.regIn(id, prj, acc)
	r.SourceVersion = w.next()
	return r
}

// regObj — регистрация реестра: кортеж `project`, затем `owner` usr-A с теми же
// полями области. Возвращает первый отказ.
func (w *ppWorld) regObj(id string, prj domain.ProjectID, acc domain.AccountID) error {
	r := w.regReq(id, prj, acc)
	if err := w.call(r); err != nil {
		return err
	}
	o := ownerOn("user:"+string(w.usrA), r.GetObject(), r.GetParentProjectId(), r.GetParentAccountId(), r.GetParentChain()...)
	o.SourceVersion = w.next()
	return w.call(o)
}

// requireReg — регистрация реестра обязана пройти.
func (w *ppWorld) requireReg(id string, prj domain.ProjectID, acc domain.AccountID, why string) {
	w.t.Helper()
	require.NoErrorf(w.t, w.regObj(id, prj, acc), "%s: регистрация %s в %s обязана пройти", why, id, prj)
}

// repoReq — регистрация ребёнка `<registry><name>` указателем `parent`.
func (w *ppWorld) repoReq(registry, name string, prj domain.ProjectID, acc domain.AccountID) *iamv1.RegisterResourceRequest {
	r := dpReq(pcrRegType+":"+registry, "parent", pcrRepoType+":"+registry+name, string(prj), string(acc),
		pcrRegType+":"+registry, "project:"+string(prj), "account:"+string(acc))
	r.SourceVersion = w.next()
	return r
}

// unreg — снятие регистрации кортежем subject/relation на объекте obj.
func (w *ppWorld) unreg(subject, relation, obj, why string) {
	w.t.Helper()
	require.NoErrorf(w.t, w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: subject, Relation: relation, Object: obj, SourceVersion: w.next(),
	}), "%s: снятие регистрации %s", why, obj)
}

// unregReg — снятие регистрации реестра id указателем `project` проекта prj.
func (w *ppWorld) unregReg(id string, prj domain.ProjectID, why string) {
	w.t.Helper()
	w.unreg("project:"+string(prj), "project", pcrRegType+":"+id, why)
}

// requireP4 — тело отказа привязки для объекта obj; boundProject — проект
// привязки, которого ответ не называет.
func requireP4(t *testing.T, err error, obj string, boundProject domain.ProjectID, why string) {
	t.Helper()
	require.Errorf(t, err, "%s: ожидался отказ привязки для %s, регистрация принята", why, obj)
	st := status.Convert(err)
	require.Equalf(t, codes.FailedPrecondition, st.Code(), "%s: код (%v)", why, err)
	require.Equalf(t, fmt.Sprintf(ppBoundFmt, obj), st.Message(), "%s: текст", why)
	require.Lenf(t, st.Details(), 1, "%s: у отказа привязки ровно одна деталь", why)
	info, ok := st.Details()[0].(*errdetails.ErrorInfo)
	require.Truef(t, ok, "%s: деталь — не ErrorInfo: %T", why, st.Details()[0])
	typ, id, _ := strings.Cut(obj, ":")
	require.Equalf(t, "OBJECT_BOUND_TO_OTHER_PROJECT", info.GetReason(), "%s: причина", why)
	require.Equalf(t, refusaldomain.For(refusaldomain.ServiceIAM), info.GetDomain(), "%s: домен", why)
	require.Equalf(t, map[string]string{"resource_type": typ, "resource_id": id}, info.GetMetadata(), "%s: metadata", why)
	require.NotContainsf(t, st.Message(), string(boundProject), "%s: текст называет проект привязки", why)
}

// requireP2 — отказ формы Р2: `INVALID_ARGUMENT`, поле field, текст msg.
func requireP2(t *testing.T, err error, field, msg, why string) {
	t.Helper()
	require.Errorf(t, err, "%s: ожидался отказ формы, регистрация принята", why)
	st := status.Convert(err)
	require.Equalf(t, codes.InvalidArgument, st.Code(), "%s: код (%v)", why, err)
	require.Equalf(t, msg, st.Message(), "%s: текст", why)
	require.Lenf(t, st.Details(), 1, "%s: деталей", why)
	br, ok := st.Details()[0].(*errdetails.BadRequest)
	require.Truef(t, ok, "%s: деталь — не BadRequest: %T", why, st.Details()[0])
	require.Lenf(t, br.GetFieldViolations(), 1, "%s: нарушений поля", why)
	require.Equalf(t, field, br.GetFieldViolations()[0].GetField(), "%s: поле", why)
	require.Equalf(t, msg, br.GetFieldViolations()[0].GetDescription(), "%s: описание", why)
}

// ppObj — объект реестра id словами провода.
func ppObj(id string) string { return pcrRegType + ":" + id }

// TestPermanentProject_PB01_OtherProjectWhileRegisteredIsRefused — PB-01.
func TestPermanentProject_PB01_OtherProjectWhileRegisteredIsRefused(t *testing.T) {
	w := newPPWorld(t)
	w.deliverDK()
	w.requireReg(dpQ, w.prjA, w.accA, "PB-01 «Дано»")
	before := w.snap(pcrRegType, dpQ)

	r := w.regReq(dpQ, w.prjC, w.accB)
	r.Labels = map[string]string{"env": "prod"}
	requireP4(t, w.call(r), ppObj(dpQ), w.prjA, "PB-01")
	require.Equal(t, before, w.snap(pcrRegType, dpQ), "PB-01: С(Q) изменился")
	r.SourceVersion = w.next()
	requireP4(t, w.call(r), ppObj(dpQ), w.prjA, "PB-01 (повтор)")
	require.Equal(t, before, w.snap(pcrRegType, dpQ), "PB-01 (повтор): С(Q) изменился")
}

// TestPermanentProject_PB02_OtherProjectAfterUnregistrationIsRefused — PB-02.
func TestPermanentProject_PB02_OtherProjectAfterUnregistrationIsRefused(t *testing.T) {
	w := newPPWorld(t)
	w.deliverDK()
	w.requireReg(dpQ, w.prjA, w.accA, "PB-02 «Дано»")
	w.unregReg(dpQ, w.prjA, "PB-02 «Дано»")
	_, _, ok := w.mirrorScope(pcrRegType, dpQ)
	require.False(t, ok, "PB-02 «Дано»: строка зеркала Q осталась после снятия")
	events := w.snap(pcrRegType, dpQ).events

	requireP4(t, w.regObj(dpQ, w.prjC, w.accB), ppObj(dpQ), w.prjA, "PB-02")
	after := w.snap(pcrRegType, dpQ)
	require.Equal(t, dpSnap{events: events}, after, "PB-02: у Q записано")
}

// TestPermanentProject_PB03_SameProjectAfterUnregistrationStartsWithoutGrants — PB-03.
func TestPermanentProject_PB03_SameProjectAfterUnregistrationStartsWithoutGrants(t *testing.T) {
	w := newPPWorld(t)
	w.deliverDK()
	w.requireReg(dpQ, w.prjA, w.accA, "PB-03 «Дано»")
	usrB := fmtSubject("user", string(w.usrB))
	req := w.grantRequest(userSubject(w.usrB), w.rolRegGet,
		resourcesTarget(&iamv1.ResourceRef{Type: ppRegCat, Id: dpQ}))
	w.createDone(asUser(w.ctx, w.usrA), req, "PB-03: выдача rol-reg-get человеку usr-B на Q")
	w.pollAsk(usrB, "v_get", pcrRegType, dpQ, true, "PB-03: выдача действует до снятия")
	w.unregReg(dpQ, w.prjA, "PB-03 «Дано»")

	w.requireReg(dpQ, w.prjA, w.accA, "PB-03")
	prj, _, _ := w.mirrorScope(pcrRegType, dpQ)
	require.Equal(t, string(w.prjA), prj, "PB-03: проект строки")
	require.Equal(t, []string{"project:" + string(w.prjA), "account:" + string(w.accA)}, w.chain(pcrRegType, dpQ), "PB-03: цепь")
	w.pollAsk(usrB, "v_get", pcrRegType, dpQ, false, "PB-03: выдача прежнего объекта не действует на новом")
}

// TestPermanentProject_PB04_SameProjectWhileRegisteredPasses — PB-04.
func TestPermanentProject_PB04_SameProjectWhileRegisteredPasses(t *testing.T) {
	w := newPPWorld(t)
	w.deliverDK()
	w.requireReg(dpQ, w.prjA, w.accA, "PB-04 «Дано»")
	r := w.regReq(dpQ, w.prjA, w.accA)
	r.Labels = map[string]string{"env": "prod"}
	require.NoError(t, w.call(r), "PB-04: регистрация в том же проекте обязана пройти")
	s := w.snap(pcrRegType, dpQ)
	require.Equal(t, string(w.prjA)+"|"+string(w.accA)+`|{"env": "prod"}`, s.mirror, "PB-04: строка зеркала")
}

// TestPermanentProject_PB05_OtherProjectOfTheSameAccountIsRefused — PB-05.
func TestPermanentProject_PB05_OtherProjectOfTheSameAccountIsRefused(t *testing.T) {
	w := newPPWorld(t)
	w.deliverDK()
	w.requireReg(dpQ, w.prjA, w.accA, "PB-05 «Дано»")
	w.unregReg(dpQ, w.prjA, "PB-05 «Дано»")
	requireP4(t, w.regObj(dpQ, w.prjA2, w.accA), ppObj(dpQ), w.prjA, "PB-05")
	_, _, ok := w.mirrorScope(pcrRegType, dpQ)
	require.False(t, ok, "PB-05: строка зеркала Q записана")
}

// TestPermanentProject_PB24_OtherProjectInTheChainIsRefused — PB-24.
func TestPermanentProject_PB24_OtherProjectInTheChainIsRefused(t *testing.T) {
	prjAChain := func(w *ppWorld, chain ...string) *iamv1.RegisterResourceRequest {
		r := w.regReq(dpQ, w.prjA, w.accA)
		r.ParentAccountId = ""
		r.ParentChain = chain
		r.Labels = map[string]string{"env": "prod"}
		return r
	}
	t.Run("a", func(t *testing.T) {
		w := newPPWorld(t)
		w.deliverDK()
		w.requireReg(dpQ, w.prjA, w.accA, "PB-24 a «Дано»")
		before := w.snap(pcrRegType, dpQ)
		requireP4(t, w.call(prjAChain(w, "project:"+string(w.prjC), "account:"+string(w.accB))), ppObj(dpQ), w.prjA, "PB-24 a")
		require.Equal(t, before, w.snap(pcrRegType, dpQ), "PB-24 a: С(Q) изменился")
	})
	t.Run("b", func(t *testing.T) {
		w := newPPWorld(t)
		w.deliverDK()
		w.requireReg(dpQ, w.prjA, w.accA, "PB-24 b «Дано»")
		w.unregReg(dpQ, w.prjA, "PB-24 b «Дано»")
		requireP4(t, w.call(prjAChain(w, "project:"+string(w.prjC), "account:"+string(w.accB))), ppObj(dpQ), w.prjA, "PB-24 b")
		_, _, ok := w.mirrorScope(pcrRegType, dpQ)
		require.False(t, ok, "PB-24 b: строка зеркала Q записана")
		require.Empty(t, w.chain(pcrRegType, dpQ), "PB-24 b: цепь Q записана")
	})
	t.Run("c", func(t *testing.T) {
		w := newPPWorld(t)
		w.deliverDK()
		r := w.regReq(dpQ2, w.prjA, w.accA)
		r.ParentAccountId = ""
		r.ParentChain = []string{"project:" + string(w.prjC), "account:" + string(w.accB)}
		requireP4(t, w.call(r), ppObj(dpQ2), w.prjA, "PB-24 c")
		w.requireNothing(pcrRegType, dpQ2, "PB-24 c")
		w.requireReg(dpQ2, w.prjC, w.accB, "PB-24 c: привязки не заведено")
	})
	t.Run("d", func(t *testing.T) {
		w := newPPWorld(t)
		w.deliverDK()
		w.requireReg(dpQ, w.prjA, w.accA, "PB-24 d «Дано»")
		before := w.snap(pcrRegType, dpQ)
		requireP4(t, w.call(prjAChain(w, "project:"+string(w.prjA), "project:"+string(w.prjC), "account:"+string(w.accA))),
			ppObj(dpQ), w.prjA, "PB-24 d")
		require.Equal(t, before, w.snap(pcrRegType, dpQ), "PB-24 d: С(Q) изменился")
	})
	t.Run("e", func(t *testing.T) {
		w := newPPWorld(t)
		w.deliverDK()
		w.requireReg(dpQ, w.prjA, w.accA, "PB-24 e «Дано»")
		require.NoError(t, w.call(prjAChain(w, "project:"+string(w.prjA), "account:"+string(w.accA))), "PB-24 e")
		s := w.snap(pcrRegType, dpQ)
		require.True(t, strings.HasPrefix(s.mirror, string(w.prjA)+"|") && strings.HasSuffix(s.mirror, `|{"env": "prod"}`),
			"PB-24 e: строка зеркала %q", s.mirror)
		require.Equal(t, []string{"project:" + string(w.prjA), "account:" + string(w.accA)}, w.chain(pcrRegType, dpQ), "PB-24 e: цепь")
	})
}

// TestPermanentProject_PB25_DeclaredTypeWithoutChainProjectIsRefused — PB-25.
func TestPermanentProject_PB25_DeclaredTypeWithoutChainProjectIsRefused(t *testing.T) {
	chainMsg := func(typ string) string {
		return "parent_chain: must name the project for object type " + typ + " with a permanent project"
	}
	accountOnly := func(w *ppWorld) *iamv1.RegisterResourceRequest {
		r := w.regReq(dpQ2, w.prjA, w.accA)
		r.ParentChain = []string{"account:" + string(w.accA)}
		return r
	}
	child := pcrRepoType + ":" + dpQ + ppTeamApp
	childReq := func(w *ppWorld, chain ...string) *iamv1.RegisterResourceRequest {
		r := dpReq(pcrRegType+":"+dpQ, "parent", child, string(w.prjA), string(w.accA), chain...)
		r.SourceVersion = w.next()
		return r
	}
	t.Run("a", func(t *testing.T) {
		w := newPPWorld(t)
		w.deliverDK()
		w.requireReg(dpQ, w.prjA, w.accA, "PB-25 «Дано»")
		requireP2(t, w.call(accountOnly(w)), "parent_chain", chainMsg(pcrRegType), "PB-25 a")
		w.requireNothing(pcrRegType, dpQ2, "PB-25 a")
		w.requireReg(dpQ2, w.prjC, w.accB, "PB-25 a: привязки не заведено")
	})
	t.Run("b", func(t *testing.T) {
		w := newPPWorld(t)
		w.deliverDK()
		w.requireReg(dpQ, w.prjA, w.accA, "PB-25 «Дано»")
		requireP2(t, w.call(childReq(w, pcrRegType+":"+dpQ)), "parent_chain", chainMsg(pcrRepoType), "PB-25 b")
		w.requireNothing(pcrRepoType, dpQ+ppTeamApp, "PB-25 b")
	})
	t.Run("c", func(t *testing.T) {
		w := newPPWorld(t)
		w.deliverDK()
		w.requireReg(dpQ, w.prjA, w.accA, "PB-25 «Дано»")
		r := accountOnly(w)
		r.ParentProjectId = ""
		requireP2(t, w.call(r), "parent_project_id",
			"parent_project_id: required for object type "+pcrRegType+" with a permanent project", "PB-25 c")
	})
	t.Run("d", func(t *testing.T) {
		w := newPPWorld(t)
		w.requireReg(dpQ, w.prjA, w.accA, "PB-25 «Дано»")
		require.NoError(t, w.call(accountOnly(w)), "PB-25 d: без объявления форма прежняя")
		prj, _, _ := w.mirrorScope(pcrRegType, dpQ2)
		require.Equal(t, string(w.prjA), prj, "PB-25 d: проект строки")
		require.Equal(t, []string{"account:" + string(w.accA)}, w.chain(pcrRegType, dpQ2), "PB-25 d: цепь")
	})
	t.Run("e", func(t *testing.T) {
		w := newPPWorld(t)
		w.deliverDK()
		w.requireReg(dpQ, w.prjA, w.accA, "PB-25 «Дано»")
		full := []string{pcrRegType + ":" + dpQ, "project:" + string(w.prjA), "account:" + string(w.accA)}
		require.NoError(t, w.call(childReq(w, full...)), "PB-25 e")
		prj, _, _ := w.mirrorScope(pcrRepoType, dpQ+ppTeamApp)
		require.Equal(t, string(w.prjA), prj, "PB-25 e: проект строки ребёнка")
		require.Equal(t, full, w.chain(pcrRepoType, dpQ+ppTeamApp), "PB-25 e: цепь")
	})
}

// TestPermanentProject_PB06_UndeclaredTypeReRegistersElsewhere — PB-06.
func TestPermanentProject_PB06_UndeclaredTypeReRegistersElsewhere(t *testing.T) {
	w := newPPWorld(t)
	w.requireReg(dpQ, w.prjA, w.accA, "PB-06 «Дано»")
	w.unregReg(dpQ, w.prjA, "PB-06 «Дано»")
	w.requireReg(dpQ, w.prjC, w.accB, "PB-06")
	prj, _, _ := w.mirrorScope(pcrRegType, dpQ)
	require.Equal(t, string(w.prjC), prj, "PB-06: проект строки")
	require.Equal(t, []string{"project:" + string(w.prjC), "account:" + string(w.accB)}, w.chain(pcrRegType, dpQ), "PB-06: цепь")
}

// TestPermanentProject_PB07_UndeclaredTypeReplacesItsProject — PB-07.
func TestPermanentProject_PB07_UndeclaredTypeReplacesItsProject(t *testing.T) {
	w := newPPWorld(t)
	w.requireReg(dpQ, w.prjA, w.accA, "PB-07 «Дано»")
	r := w.regReq(dpQ, w.prjC, w.accB)
	r.Labels = map[string]string{"env": "prod"}
	require.NoError(t, w.call(r), "PB-07")
	prj, _, _ := w.mirrorScope(pcrRegType, dpQ)
	require.Equal(t, string(w.prjC), prj, "PB-07: проект строки")
	require.Equal(t, []string{"project:" + string(w.prjC), "account:" + string(w.accB)}, w.chain(pcrRegType, dpQ), "PB-07: цепь")
}

// TestPermanentProject_PB08_RegisteredBeforeDeclarationIsBoundByDelivery — PB-08.
func TestPermanentProject_PB08_RegisteredBeforeDeclarationIsBoundByDelivery(t *testing.T) {
	t.Run("a", func(t *testing.T) {
		w := newPPWorld(t)
		w.deliverDK()
		requireP4(t, w.regObj(pcrX, w.prjC, w.accB), ppObj(pcrX), w.prjA, "PB-08 a")
		prj, _, _ := w.mirrorScope(pcrRegType, pcrX)
		require.Equal(t, string(w.prjA), prj, "PB-08 a: проект строки X")
	})
	t.Run("b", func(t *testing.T) {
		w := newPPWorld(t)
		w.deliverDK()
		w.unregReg(pcrX, w.prjA, "PB-08 b")
		requireP4(t, w.regObj(pcrX, w.prjC, w.accB), ppObj(pcrX), w.prjA, "PB-08 b")
		_, _, ok := w.mirrorScope(pcrRegType, pcrX)
		require.False(t, ok, "PB-08 b: строка зеркала X записана")
	})
}

// TestPermanentProject_PB09_UnregisteredBeforeDeclarationIsNotBound — PB-09.
func TestPermanentProject_PB09_UnregisteredBeforeDeclarationIsNotBound(t *testing.T) {
	w := newPPWorld(t)
	w.unregReg(pcrX, w.prjA, "PB-09 «Дано»")
	w.deliverDK()
	w.requireReg(pcrX, w.prjC, w.accB, "PB-09")
	prj, _, _ := w.mirrorScope(pcrRegType, pcrX)
	require.Equal(t, string(w.prjC), prj, "PB-09: проект строки X")
	requireP4(t, w.regObj(pcrX, w.prjA, w.accA), ppObj(pcrX), w.prjC, "PB-09: привязка заведена регистрацией")
}

// TestPermanentProject_PB10_ChildUnderOtherProjectContainerIsRefused — PB-10.
func TestPermanentProject_PB10_ChildUnderOtherProjectContainerIsRefused(t *testing.T) {
	for _, unregisterFirst := range []bool{false, true} {
		name := map[bool]string{false: "a", true: "b"}[unregisterFirst]
		t.Run(name, func(t *testing.T) {
			w := newPPWorld(t)
			w.deliverDK()
			w.requireReg(dpQ, w.prjA, w.accA, "PB-10 «Дано»")
			w.requireReg(ppZ, w.prjC, w.accB, "PB-10 «Дано»")
			require.NoError(t, w.call(w.repoReq(dpQ, ppTeamApp, w.prjA, w.accA)), "PB-10 «Дано»: ребёнок под Q")
			child := pcrRepoType + ":" + dpQ + ppTeamApp
			if unregisterFirst {
				w.unreg(pcrRegType+":"+dpQ, "parent", child, "PB-10 b")
			}
			requireP4(t, w.call(withObject(w.repoReq(ppZ, "", w.prjC, w.accB), child)), child, w.prjA, "PB-10 "+name)
			prj, _, ok := w.mirrorScope(pcrRepoType, dpQ+ppTeamApp)
			if unregisterFirst {
				require.False(t, ok, "PB-10 b: строка зеркала ребёнка записана")
				return
			}
			require.Equal(t, string(w.prjA), prj, "PB-10 a: проект строки ребёнка")
			require.Equal(t, []string{pcrRegType + ":" + dpQ, "project:" + string(w.prjA), "account:" + string(w.accA)},
				w.chain(pcrRepoType, dpQ+ppTeamApp), "PB-10 a: цепь ребёнка")
		})
	}
}

// TestPermanentProject_PB11_ChildUnderSameProjectContainerPasses — PB-11.
func TestPermanentProject_PB11_ChildUnderSameProjectContainerPasses(t *testing.T) {
	for _, unregisterFirst := range []bool{false, true} {
		name := map[bool]string{false: "a", true: "b"}[unregisterFirst]
		t.Run(name, func(t *testing.T) {
			w := newPPWorld(t)
			w.deliverDK()
			w.requireReg(dpQ, w.prjA, w.accA, "PB-11 «Дано»")
			require.NoError(t, w.call(w.repoReq(dpQ, ppTeamApp, w.prjA, w.accA)), "PB-11 «Дано»: ребёнок под Q")
			child := pcrRepoType + ":" + dpQ + ppTeamApp
			if unregisterFirst {
				w.unreg(pcrRegType+":"+dpQ, "parent", child, "PB-11 b")
			}
			require.NoError(t, w.call(withObject(w.repoReq(pcrY, "", w.prjA, w.accA), child)), "PB-11 "+name)
			prj, _, _ := w.mirrorScope(pcrRepoType, dpQ+ppTeamApp)
			require.Equal(t, string(w.prjA), prj, "PB-11 %s: проект строки ребёнка", name)
			require.Equal(t, []string{pcrRegType + ":" + pcrY, "project:" + string(w.prjA), "account:" + string(w.accA)},
				w.chain(pcrRepoType, dpQ+ppTeamApp), "PB-11 %s: цепь ребёнка", name)
		})
	}
}

// TestPermanentProject_PB12_DeclaredTypeWithoutProjectIsRefused — PB-12.
func TestPermanentProject_PB12_DeclaredTypeWithoutProjectIsRefused(t *testing.T) {
	w := newPPWorld(t)
	w.deliverDK()
	r := w.regReq(dpQ, w.prjA, w.accA)
	r.ParentProjectId = ""
	requireP2(t, w.call(r), "parent_project_id",
		"parent_project_id: required for object type "+pcrRegType+" with a permanent project", "PB-12")
	w.requireNothing(pcrRegType, dpQ, "PB-12")
	w.requireReg(dpQ, w.prjC, w.accB, "PB-12: привязки не заведено")
}

// TestPermanentProject_PB13_TwinsOfTheFormRefusal — PB-13.
func TestPermanentProject_PB13_TwinsOfTheFormRefusal(t *testing.T) {
	t.Run("a", func(t *testing.T) {
		w := newPPWorld(t)
		r := w.regReq(dpQ, w.prjA, w.accA)
		r.ParentProjectId = ""
		require.NoError(t, w.call(r), "PB-13 a: без объявления проект не обязателен")
		prj, _, ok := w.mirrorScope(pcrRegType, dpQ)
		require.True(t, ok, "PB-13 a: строки зеркала нет")
		require.Empty(t, prj, "PB-13 a: проект строки")
	})
	t.Run("b", func(t *testing.T) {
		w := newPPWorld(t)
		w.deliverDK()
		w.requireReg(dpQ, w.prjA, w.accA, "PB-13 b «Дано»")
		require.NoError(t, w.call(&iamv1.RegisterResourceRequest{
			SubjectId: pcrAnon, Relation: "v_get", Object: ppObj(dpQ), SourceVersion: w.next(),
		}), "PB-13 b: публикация проектом не адресуется")
		w.pollAsk(pcrAnon, "v_get", pcrRegType, dpQ, true, "PB-13 b: публикация действует")
	})
}

// TestPermanentProject_PB17_ConcurrentFirstRegistrationsOneWins — PB-17.
func TestPermanentProject_PB17_ConcurrentFirstRegistrationsOneWins(t *testing.T) {
	w := newPPWorld(t)
	w.deliverDK()
	type outcome struct {
		prj domain.ProjectID
		err error
	}
	race := func(first, last int, second domain.ProjectID, secondAcc domain.AccountID) map[int][2]outcome {
		out := map[int][2]outcome{}
		var mu sync.Mutex
		var wg sync.WaitGroup
		start := make(chan struct{})
		for n := first; n <= last; n++ {
			for side, sp := range []struct {
				prj domain.ProjectID
				acc domain.AccountID
			}{{w.prjA, w.accA}, {second, secondAcc}} {
				req := w.regReq(fmt.Sprintf("race%d/k", n), sp.prj, sp.acc)
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					err := w.call(req)
					mu.Lock()
					pair := out[n]
					pair[side] = outcome{prj: sp.prj, err: err}
					out[n] = pair
					mu.Unlock()
				}()
			}
		}
		close(start)
		wg.Wait()
		return out
	}

	for n, pair := range race(1, 20, w.prjC, w.accB) {
		obj := ppObj(fmt.Sprintf("race%d/k", n))
		var won, lost []outcome
		for _, o := range pair {
			require.NotEqualf(t, codes.Internal, status.Code(o.err), "PB-17 K%d: INTERNAL (%v)", n, o.err)
			require.NotEqualf(t, codes.Unavailable, status.Code(o.err), "PB-17 K%d: UNAVAILABLE (%v)", n, o.err)
			if o.err == nil {
				won = append(won, o)
			} else {
				lost = append(lost, o)
			}
		}
		require.Lenf(t, won, 1, "PB-17 K%d: принят ровно один вызов (%+v)", n, pair)
		requireP4(t, lost[0].err, obj, won[0].prj, fmt.Sprintf("PB-17 K%d: проигравший", n))
		prj, _, _ := w.mirrorScope(pcrRegType, fmt.Sprintf("race%d/k", n))
		require.Equalf(t, string(won[0].prj), prj, "PB-17 K%d: проект строки — выигравшего", n)
		acc := map[domain.ProjectID]domain.AccountID{w.prjA: w.accA, w.prjC: w.accB}
		requireP4(t, w.call(w.regReq(fmt.Sprintf("race%d/k", n), lost[0].prj, acc[lost[0].prj])), obj, won[0].prj,
			fmt.Sprintf("PB-17 K%d: регистрация в проекте проигравшего", n))
		require.NoErrorf(t, w.call(w.regReq(fmt.Sprintf("race%d/k", n), won[0].prj, acc[won[0].prj])),
			"PB-17 K%d: регистрация в проекте выигравшего", n)
	}

	for n, pair := range race(21, 40, w.prjA, w.accA) {
		for side, o := range pair {
			require.NoErrorf(t, o.err, "PB-17 близнец K%d, вызов %d: оба в prj-A обязаны пройти", n, side)
		}
		prj, _, _ := w.mirrorScope(pcrRegType, fmt.Sprintf("race%d/k", n))
		require.Equalf(t, string(w.prjA), prj, "PB-17 близнец K%d: проект строки", n)
	}
}

// waitForLockWaiter — ожидание утверждается СОСТОЯНИЕМ: в базе мира есть сеанс,
// ждущий замок. Пауза измеряла бы скорость машины, а не порядок замков.
func (w *ppWorld) waitForLockWaiter(why string) {
	w.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		var n int
		require.NoError(w.t, w.pool.QueryRow(w.ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&n))
		if n > 0 {
			return
		}
		if time.Now().After(deadline) {
			w.t.Fatalf("%s: за 30 с ни один сеанс не встал в ожидание замка", why)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// declareTx — оператор объявления признака типа `registry.registries` в своей
// транзакции (привязку зарегистрированного делает база тем же оператором, Р8).
func (w *ppWorld) declareTx(ctx context.Context) (service.Tx, error) {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx,
		`UPDATE kaname.catalog_resource SET permanent_project = true WHERE dotted = $1`, ppRegCat); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return tx, nil
}

// mirrorTx — вставка зеркала Q3 в prj-A через `resource_mirror.UpsertTx` в своей
// транзакции, без use-case.
func (w *ppWorld) mirrorTx(ctx context.Context) (service.Tx, error) {
	tx, err := kanamepg.NewPoolTxBeginner(w.pool).Begin(ctx)
	if err != nil {
		return nil, err
	}
	_, _, err = kanamepg.NewResourceMirrorEmitter().UpsertTx(ctx, tx, service.ResourceMirrorRow{
		ObjectType: ppRegCat, ObjectID: dpQ3,
		ParentProjectID: string(w.prjA), ParentAccountID: string(w.accA),
		ParentChain:   []string{"project:" + string(w.prjA), "account:" + string(w.accA)},
		SourceVersion: w.next().AsTime(),
	})
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return tx, nil
}

// TestPermanentProject_PB18_RegistrationDuringDeclarationIsBoundEitherWay — PB-18.
func TestPermanentProject_PB18_RegistrationDuringDeclarationIsBoundEitherWay(t *testing.T) {
	for _, declareFirst := range []bool{true, false} {
		name := map[bool]string{true: "a", false: "b"}[declareFirst]
		t.Run(name, func(t *testing.T) {
			w := newPPWorld(t)
			ctx := w.ctx
			holder, waiter := w.declareTx, w.mirrorTx
			if !declareFirst {
				holder, waiter = w.mirrorTx, w.declareTx
			}
			first, err := holder(ctx)
			require.NoError(t, err, "PB-18 %s: первая транзакция", name)
			type txResult struct {
				tx  service.Tx
				err error
			}
			res := make(chan txResult, 1)
			go func() {
				tx, werr := waiter(ctx)
				res <- txResult{tx: tx, err: werr}
			}()
			// Уборка — ДО первого утверждения: проба, упавшая с открытыми
			// транзакциями, держала бы соединения пула, и снятие базы мира ждало
			// бы их до предела прогона. Откат после коммита ничего не меняет.
			var second txResult
			received := false
			t.Cleanup(func() {
				_ = first.Rollback(context.Background())
				if !received {
					second = <-res
				}
				if second.tx != nil {
					_ = second.tx.Rollback(context.Background())
				}
			})
			w.waitForLockWaiter("PB-18 " + name)
			require.NoError(t, first.Commit(ctx), "PB-18 %s: коммит первой", name)
			second, received = <-res, true
			require.NoError(t, second.err, "PB-18 %s: вторая транзакция", name)
			require.NoError(t, second.tx.Commit(ctx), "PB-18 %s: коммит второй", name)

			requireP4(t, w.call(w.regReq(dpQ3, w.prjC, w.accB)), ppObj(dpQ3), w.prjA, "PB-18 "+name+": prj-C")
			require.NoError(t, w.call(w.regReq(dpQ3, w.prjA, w.accA)), "PB-18 %s: prj-A", name)
		})
	}
}

// TestPermanentProject_PB19_DirectStatementCannotMoveABoundObject — PB-19.
func TestPermanentProject_PB19_DirectStatementCannotMoveABoundObject(t *testing.T) {
	w := newPPWorld(t)
	w.deliverDK()
	w.requireReg(dpQ, w.prjA, w.accA, "PB-19 «Дано»")
	const net = "net00000000000000099"
	w.requireOK("vpc", dpReq("project:"+string(w.prjA), "project", dpNetType+":"+net, string(w.prjA), string(w.accA),
		"project:"+string(w.prjA), "account:"+string(w.accA)), "PB-19 «Дано»: vpc.network")
	requireClass23 := func(err error, why string) {
		t.Helper()
		var pg *pgconn.PgError
		require.ErrorAsf(t, err, &pg, "%s: ожидался отказ базы, получено %v", why, err)
		require.Truef(t, strings.HasPrefix(pg.Code, "23"), "%s: SQLSTATE %s не класса 23", why, pg.Code)
	}
	prjC := string(w.prjC)
	_, err := w.pool.Exec(w.ctx, `UPDATE kaname.resource_mirror SET parent_project_id = $1
		WHERE object_type = 'registry.registries' AND object_id = $2`, prjC, dpQ)
	requireClass23(err, "PB-19 a")
	_, err = w.pool.Exec(w.ctx, `UPDATE kaname.resource_mirror SET parent_project_id = $1
		WHERE object_type = 'vpc.network' AND object_id = $2`, prjC, net)
	require.NoError(t, err, "PB-19 b")
	_, err = w.pool.Exec(w.ctx, `UPDATE kaname.resource_parent_edge SET parent_id = $1
		WHERE object_type = 'registry_registry' AND object_id = $2 AND parent_type = 'project'`, prjC, dpQ)
	requireClass23(err, "PB-19 c")
	_, err = w.pool.Exec(w.ctx, `UPDATE kaname.resource_parent_edge SET parent_id = $1
		WHERE object_type = 'vpc_network' AND object_id = $2 AND parent_type = 'project'`, prjC, net)
	require.NoError(t, err, "PB-19 d")

	prj, _, _ := w.mirrorScope(pcrRegType, dpQ)
	require.Equal(t, string(w.prjA), prj, "PB-19 a: проект строки Q")
	require.Equal(t, []string{"project:" + string(w.prjA), "account:" + string(w.accA)}, w.chain(pcrRegType, dpQ), "PB-19 c: цепь Q")
	prj, _, _ = w.mirrorScope(dpNetType, net)
	require.Equal(t, prjC, prj, "PB-19 b: проект строки сети")
	require.Equal(t, []string{"project:" + prjC, "account:" + string(w.accA)}, w.chain(dpNetType, net), "PB-19 d: цепь сети")
}

// TestPermanentProject_PB20_BindingCannotBeChangedOrRemoved — PB-20.
func TestPermanentProject_PB20_BindingCannotBeChangedOrRemoved(t *testing.T) {
	w := newPPWorld(t)
	w.deliverDK()
	w.requireReg(dpQ, w.prjA, w.accA, "PB-20 «Дано»")
	for _, tc := range []struct{ name, sql string }{
		{"a", `UPDATE kaname.object_project_binding SET project_id = '` + string(w.prjC) +
			`' WHERE object_type = 'registry_registry' AND object_id = '` + dpQ + `'`},
		{"b", `DELETE FROM kaname.object_project_binding WHERE object_type = 'registry_registry' AND object_id = '` + dpQ + `'`},
		{"c", `TRUNCATE kaname.object_project_binding`},
	} {
		_, err := w.pool.Exec(w.ctx, tc.sql)
		var pg *pgconn.PgError
		require.ErrorAsf(t, err, &pg, "PB-20 %s: ожидался отказ базы, получено %v", tc.name, err)
		require.Truef(t, strings.HasPrefix(pg.Code, "23"), "PB-20 %s: SQLSTATE %s не класса 23", tc.name, pg.Code)
	}
	requireP4(t, w.regObj(dpQ, w.prjC, w.accB), ppObj(dpQ), w.prjA, "PB-20: привязка прежняя")
}

// TestPermanentProject_PB21_BindingDoesNotHoldProjectDeletion — PB-21.
func TestPermanentProject_PB21_BindingDoesNotHoldProjectDeletion(t *testing.T) {
	deleteA2 := func(w *ppWorld) error {
		wr, err := w.repo.Writer(w.ctx)
		require.NoError(w.t, err)
		defer func() { _ = wr.Rollback(w.ctx) }()
		if err := wr.ProjectsW().Delete(w.ctx, w.prjA2); err != nil {
			return err
		}
		return wr.Commit(w.ctx)
	}
	projectExists := func(w *ppWorld) bool {
		var n int
		require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.projects WHERE id = $1`, string(w.prjA2)).Scan(&n))
		return n == 1
	}
	t.Run("a", func(t *testing.T) {
		w := newPPWorld(t)
		w.deliverDK()
		w.requireReg(dpQ2, w.prjA2, w.accA, "PB-21 «Дано»")
		w.unregReg(dpQ2, w.prjA2, "PB-21 «Дано»")
		require.NoError(t, deleteA2(w), "PB-21 a: удаление проекта")
		require.False(t, projectExists(w), "PB-21 a: проект на месте")
		requireP4(t, w.regObj(dpQ2, w.prjA, w.accA), ppObj(dpQ2), w.prjA2, "PB-21 a: привязка пережила проект")
	})
	t.Run("b", func(t *testing.T) {
		w := newPPWorld(t)
		w.deliverDK()
		w.requireReg(dpQ2, w.prjA2, w.accA, "PB-21 «Дано»")
		w.unregReg(dpQ2, w.prjA2, "PB-21 «Дано»")
		w.requireReg(dpQ3, w.prjA2, w.accA, "PB-21 b «Дано»")
		err := deleteA2(w)
		require.ErrorIs(t, err, iamerr.ErrReferenceInUse, "PB-21 b")
		require.Equal(t, fmt.Sprintf("Project %s is not empty (registry.registries: 1)", w.prjA2), iamerr.StripSentinel(err), "PB-21 b: текст")
		require.True(t, projectExists(w), "PB-21 b: проект удалён")
	})
}

// TestPermanentProject_PB22_d_DeclarationReachesTheCatalog — PB-22 d,
// интеграционная половина.
func TestPermanentProject_PB22_d_DeclarationReachesTheCatalog(t *testing.T) {
	w := newPPWorld(t)
	w.deliverDK()
	var n int
	require.NoError(t, w.pool.QueryRow(w.ctx, `
		SELECT count(*) FROM kaname.catalog_resource
		 WHERE module = 'registry' AND resource IN ('registries', 'repositories') AND live AND permanent_project`).Scan(&n))
	require.Equal(t, 2, n, "PB-22 d: признак у двух строк каталога")
}

// TestPermanentProject_PB23_WithdrawnDeclarationKeepsBindings — PB-23.
func TestPermanentProject_PB23_WithdrawnDeclarationKeepsBindings(t *testing.T) {
	w := newPPWorld(t)
	w.deliverDK()
	w.requireReg(dpQ, w.prjA, w.accA, "PB-23 «Дано»")
	w.unregReg(dpQ, w.prjA, "PB-23 «Дано»")
	dk, err := publicreadfixture.PermanentProjectDocument()
	require.NoError(t, err)
	keyless, err := publicreadfixture.WithoutPermanentProject(dk)
	require.NoError(t, err)
	w.deliver("PB-23: D-K без ключа", keyless)

	requireP4(t, w.regObj(dpQ, w.prjC, w.accB), ppObj(dpQ), w.prjA, "PB-23 a")

	w.requireReg(dpQ2, w.prjA, w.accA, "PB-23 b")
	w.unregReg(dpQ2, w.prjA, "PB-23 b")
	w.requireReg(dpQ2, w.prjC, w.accB, "PB-23 b")
	prj, _, _ := w.mirrorScope(pcrRegType, dpQ2)
	require.Equal(t, string(w.prjC), prj, "PB-23 b: проект строки Q2")
}
