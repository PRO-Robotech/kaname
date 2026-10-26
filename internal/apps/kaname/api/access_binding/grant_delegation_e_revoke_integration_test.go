// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// grant_delegation_e_revoke_integration_test.go — группа E приёмки делегированных
// выдач (PRO-Robotech/kaname#986): отзыв выданного делегатом, GD-30…GD-32.
//
// GD-30 и GD-31 зовут use-case; что дверь слушателя этот вызов до use-case
// пропускает, держит GD-32 (дверь тем же конструктором, что в корне службы,
// над настоящей дверью решения мира) и сквозной кейс GD-E5.
//
// GD-32 стоит в этом пакете, а не в `internal/authzguard`, по замеру формы
// прогонов: хук отправки гоняет `go test ./... -short`, и проба двери без базы
// исполнялась бы там красной до реализации; пропуск по `-short` в пакете без
// базы не исполнил бы её НИ ОДНО задание конвейера (задание `integration`
// отбирает пакеты по импорту контейнерной базы в пробах, `run-integration.sh`).
// Здесь хранилище отношений — настоящая дверь решения мира Д на Postgres, а не
// дублёр: у учётки sva-iss в ней нет ни одного отношения на объекте выдачи.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/PRO-Robotech/corelib/authz/catalogderive"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// boOf — Bo (GD-30): выдача usr-A роли `registry.puller` учётке sva-A3, область
// prj-A, цель X, обычным путём.
func (w *gdWorld) boOf() string {
	w.t.Helper()
	return w.createDoneX(asUser(w.ctx, w.usrA), w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
		r.RoleId, r.Subjects = string(w.rolPuller), []*iamv1.Subject{svaSubject(w.svaA3)}
	}), "Дано: Bo от usr-A")
}

// gd30World — Дано GD-30: D1, B10 (GD-10 a), B10' (GD-10 b), Bo.
type gd30World struct {
	*gdWorld
	d1, b10, b10p, bo string
}

// newGD30World — мир строки GD-30. withB10p=false — без B10' (строка a, см. её
// комментарий).
func newGD30World(t *testing.T, sc string, withB10p bool) *gd30World {
	t.Helper()
	w := newGDWorld(t)
	g := &gd30World{gdWorld: w}
	g.bo = w.boOf()
	w.requireSubject(sc)
	g.d1 = w.d1()
	g.b10 = requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.v()), sc+" Дано: B10 (GD-10 a)")
	if withB10p {
		g.b10p = requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
			r.ScopeType, r.ScopeId = "iam.account", string(w.accA)
		})), sc+" Дано: B10' (GD-10 b)")
	}
	return g
}

// deleteBinding — `AccessBindingService.Delete` как есть.
func (w *gdWorld) deleteBinding(ctx context.Context, id string) (string, error) {
	op, err := w.abx.Delete(ctx, &iamv1.DeleteAccessBindingRequest{AccessBindingId: id})
	if err != nil {
		return "", err
	}
	return op.GetId(), nil
}

// requireVerbDone — синхронного отказа нет, операция `done` без ошибки.
func (w *gdWorld) requireVerbDone(opID string, err error, why string) {
	w.t.Helper()
	require.NoErrorf(w.t, err, "%s: синхронный отказ", why)
	done := awaitOp(w.t, w.ctx, w.ops, opID)
	require.Nilf(w.t, done.Error, "%s: операция завершилась ошибкой %+v", why, done.Error)
}

// GD-30 — делегат отзывает и удаляет только выданное по своему делегированию.
// Каждая строка — на свежем мире.
func TestGrantDelegation_GD30_DelegateRevokesOnlyWhatItsDelegationGranted(t *testing.T) {
	// Строка a утверждает `pollAsk(sva-A, v_get, X, false)` после отзыва B10. В
	// Дано сценария стоит и B10' — выдача той же роли той же учётке на X областью
	// acc-A, — и с ней v_get у sva-A остаётся законно. Мир строки a поэтому без
	// B10': иначе строка краснела бы и после реализации (вопрос к приёмке в
	// возврате полосы PRO-Robotech/kaname#1009).
	t.Run("a: делегат отзывает B10", func(t *testing.T) {
		g := newGD30World(t, "GD-30 a", false)
		op, err := g.revokeBinding(asSA(g.ctx, g.svaIss), g.b10)
		g.requireVerbDone(op.GetId(), err, "GD-30 a")
		pb := g.getBinding(g.b10)
		assert.Equal(t, iamv1.AccessBinding_REVOKED, pb.GetStatus(), "GD-30 a: status")
		assert.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_REVOKE, pb.GetRevocationReason(), "GD-30 a: причина")
		assert.Equal(t, g.svaIss, pb.GetRevokedByUserId(), "GD-30 a: revokedByUserId — учётка-делегат (§0.10б)")
		g.pollAsk(fmtSubject("service_account", g.svaA), "v_get", pcrRegType, pcrX, false, "GD-30 a: доступ sva-A снят")
	})
	var bText, eText, fText string
	t.Run("b: делегат отзывает Bo", func(t *testing.T) {
		g := newGD30World(t, "GD-30 b", true)
		_, err := g.revokeBinding(asSA(g.ctx, g.svaIss), g.bo)
		bText = statusText(requireRefusal(t, err, codes.PermissionDenied, "permission denied", "GD-30 b"))
		assert.Equal(t, iamv1.AccessBinding_ACTIVE, g.getBinding(g.bo).GetStatus(), "GD-30 b: Bo действует")
	})
	t.Run("c: делегат удаляет B10'", func(t *testing.T) {
		g := newGD30World(t, "GD-30 c", true)
		opID, err := g.deleteBinding(asSA(g.ctx, g.svaIss), g.b10p)
		g.requireVerbDone(opID, err, "GD-30 c")
		_, gerr := g.abx.Get(asUser(g.ctx, g.usrA), &iamv1.GetAccessBindingRequest{AccessBindingId: g.b10p})
		requireRefusal(t, gerr, codes.PermissionDenied, "permission denied", "GD-30 c: Get удалённой")
	})
	t.Run("d: делегат удаляет Bo", func(t *testing.T) {
		g := newGD30World(t, "GD-30 d", true)
		_, err := g.deleteBinding(asSA(g.ctx, g.svaIss), g.bo)
		requireRefusal(t, err, codes.PermissionDenied, "permission denied", "GD-30 d")
		assert.Equal(t, iamv1.AccessBinding_ACTIVE, g.getBinding(g.bo).GetStatus(), "GD-30 d: Bo действует")
	})
	t.Run("e: несуществующая выдача", func(t *testing.T) {
		g := newGD30World(t, "GD-30 e", true)
		_, err := g.revokeBinding(asSA(g.ctx, g.svaIss), "acb00000000000000099")
		eText = statusText(requireRefusal(t, err, codes.PermissionDenied, "permission denied", "GD-30 e"))
	})
	t.Run("f: посторонний", func(t *testing.T) {
		g := newGD30World(t, "GD-30 f", true)
		_, err := g.revokeBinding(asUser(g.ctx, g.usrB), g.b10)
		fText = statusText(requireRefusal(t, err, codes.PermissionDenied, "permission denied", "GD-30 f"))
		assert.Equal(t, iamv1.AccessBinding_ACTIVE, g.getBinding(g.b10).GetStatus(), "GD-30 f: B10 действует")
	})
	t.Run("g: владелец прежним путём", func(t *testing.T) {
		g := newGD30World(t, "GD-30 g", true)
		g.awaitRemovalRight(g.usrA, g.bo, "GD-30 g Дано: у владельца v_delete на Bo")
		op, err := g.revokeBinding(asUser(g.ctx, g.usrA), g.bo)
		g.requireVerbDone(op.GetId(), err, "GD-30 g")
		pb := g.getBinding(g.bo)
		assert.Equal(t, iamv1.AccessBinding_REVOKED, pb.GetStatus(), "GD-30 g: status")
		assert.Equal(t, string(g.usrA), pb.GetRevokedByUserId(), "GD-30 g: revokedByUserId")
	})
	if bText != "" {
		assert.Equal(t, bText, eText, "GD-30: e побайтово равна b")
		assert.Equal(t, bText, fText, "GD-30: f побайтово равна b")
	}
}

// GD-31 — делегат убирает выданное и тогда, когда делегирующий потерял право.
func TestGrantDelegation_GD31_DelegateCleansUpAfterDelegatorLostAuthority(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-31")
	w.createDelegation(asUser(w.ctx, w.usrE), w.d1Body(w.svaIss2), "GD-31 Дано: D-E от usr-E")
	bE := requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss2), w.v()), "GD-31 Дано: B-E")
	op, err := w.revokeBinding(asUser(w.ctx, w.usrA), w.grantE)
	w.requireOpDone(op, err, "GD-31 Дано: usr-A отзывает admin человеку usr-E")
	w.pollRelation("user:"+string(w.usrE), "admin", "account:"+string(w.accA), false,
		"GD-31 Дано: usr-E больше не держит admin на acc-A")

	op, err = w.revokeBinding(asSA(w.ctx, w.svaIss2), bE)
	w.requireVerbDone(op.GetId(), err, "GD-31 a")
	pb := w.getBinding(bE)
	assert.Equal(t, iamv1.AccessBinding_REVOKED, pb.GetStatus(), "GD-31 a: status")
	assert.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_REVOKE, pb.GetRevocationReason(), "GD-31 a: причина")
	assert.Equal(t, w.svaIss2, pb.GetRevokedByUserId(), "GD-31 a: revokedByUserId")

	requireDenied(t, w.tryGrant(asSA(w.ctx, w.svaIss2), w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
		r.Subjects = []*iamv1.Subject{svaSubject(w.svaA2)}
	})), "GD-31 b (близнец): выдача спрашивает права делегирующего")
}

// GD-32 — дверь слушателя пропускает отзыв и удаление к обработчику, правку — нет.
func TestGrantDelegation_GD32_ListenerDoorPassesRevokeAndDeleteButNotUpdate(t *testing.T) {
	w := newGDWorld(t)
	bx := w.boOf() // выдача, на которой у sva-iss нет ни одного отношения
	w.requireRelation("service_account:"+w.svaIss, "v_delete", "iam_access_binding:"+bx, false,
		"GD-32 Дано: у sva-iss нет v_delete на объекте выдачи")
	w.requireRelation("service_account:"+w.svaIss, "v_update", "iam_access_binding:"+bx, false,
		"GD-32 Дано: у sva-iss нет v_update на объекте выдачи")

	ctx := asSA(w.ctx, w.svaIss)
	call := func(method string, req any) (bool, []string, error) {
		door, q := w.ownDoor()
		reached := false
		_, err := door(ctx, req, &grpc.UnaryServerInfo{FullMethod: method},
			func(context.Context, any) (any, error) { reached = true; return &emptypb.Empty{}, nil })
		return reached, q.asked, err
	}
	asked := func(log []string, relation string) bool {
		for _, a := range log {
			if strings.Contains(a, "|"+relation+"|") {
				return true
			}
		}
		return false
	}

	var fails []string
	row := func(name string, ok bool, detail string) {
		mark := "сошлось"
		if !ok {
			mark = "НЕ СОШЛОСЬ"
			fails = append(fails, name)
		}
		t.Logf("GD-32 %s: %s — %s", name, mark, detail)
	}

	// c — близнец a: аннотация `v_update` остаётся (Р1а). Идёт первым: это
	// положительный контроль двери — она в этом мире отказывает по объекту.
	reached, log, err := call("/kaname.cloud.iam.v1.AccessBindingService/Update",
		&iamv1.UpdateAccessBindingRequest{AccessBindingId: bx, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}}})
	wantQ := "service_account:" + w.svaIss + "|v_update|iam_access_binding:" + bx
	cOK := !reached && status.Code(err) == codes.PermissionDenied && contains(log, wantQ)
	require.Truef(t, cOK, "GD-32 c (контроль двери): обработчик достигнут=%v, отказ=%v, вопросы=%v — без этого "+
		"строки a, b, d не различают «дверь пропустила» и «дверь никого не судит»", reached, err, log)
	row("c Update", cOK, fmt.Sprintf("обработчик не достигнут, %v, спрошено %q", status.Code(err), wantQ))

	reached, log, err = call("/kaname.cloud.iam.v1.AccessBindingService/Revoke",
		&iamv1.RevokeAccessBindingRequest{AccessBindingId: bx})
	row("a Revoke", reached && err == nil && !asked(log, "v_delete"),
		fmt.Sprintf("обработчик достигнут=%v, отказ=%v, вопросы двери=%v", reached, err, log))

	reached, log, err = call("/kaname.cloud.iam.v1.AccessBindingService/Delete",
		&iamv1.DeleteAccessBindingRequest{AccessBindingId: bx})
	row("b Delete", reached && err == nil && !asked(log, "v_delete"),
		fmt.Sprintf("обработчик достигнут=%v, отказ=%v, вопросы двери=%v", reached, err, log))

	reached, log, err = call("/"+gdServiceName+"/Revoke", gdRevokeRequest("gdl00000000000000001"))
	row("d GrantDelegationService.Revoke", reached && err == nil,
		fmt.Sprintf("обработчик достигнут=%v, отказ=%v, вопросы двери=%v", reached, err, log))

	// Число методов пакета, освобождённых дверью: база на 5c6b7c078 — 21 в
	// `kaname.cloud.iam.v1` и 2 в `corelib.operation` (разбор классов, CE-21);
	// после реализации — на шесть больше в iam.v1 (Р1а).
	iamExempt, opExempt := exemptCounts(t)
	t.Logf("GD-32: освобождённых дверью методов — kaname.cloud.iam.v1 %d, corelib.operation %d (база 21 и 2)", iamExempt, opExempt)
	row("число освобождённых", iamExempt == 21+6 && opExempt == 2,
		fmt.Sprintf("iam.v1 %d (ожидается 27), operation %d (ожидается 2)", iamExempt, opExempt))

	if len(fails) > 0 {
		t.Fatalf("GD-32: не сошлись строки %v — дверь слушателя судит Revoke/Delete по v_delete либо не знает GrantDelegationService", fails)
	}
}

func contains(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}

// gdRevokeRequest — запрос `GrantDelegationService.Revoke`: сообщение входа из
// дескриптора, если служба объявлена; иначе пустое сообщение — дверь, не
// знающая метода, отвергает его до чтения запроса.
func gdRevokeRequest(id string) proto.Message {
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(gdServiceName)
	if err != nil {
		return &emptypb.Empty{}
	}
	md := d.(protoreflect.ServiceDescriptor).Methods().ByName("Revoke")
	if md == nil {
		return &emptypb.Empty{}
	}
	m := dynamicpb.NewMessage(md.Input())
	if fd := md.Input().Fields().ByJSONName("grantDelegationId"); fd != nil {
		m.Set(fd, protoreflect.ValueOfString(id))
	}
	return m
}

// exemptCounts — освобождённые дверью методы по пакетам двери, выведенные тем
// же `catalogderive.Derive`, что строит карту двери.
func exemptCounts(t *testing.T) (iam, op int) {
	t.Helper()
	m, err := catalogderive.Derive(authzguard.OwnDoorProtoPackages()...)
	require.NoError(t, err, "карта двери не выводится")
	for method, e := range m {
		if !e.Public {
			continue
		}
		switch {
		case strings.HasPrefix(method, "/kaname.cloud.iam.v1."):
			iam++
		case strings.HasPrefix(method, "/corelib.operation."):
			op++
		}
	}
	return iam, op
}

// statusText — код и текст отказа одной строкой (сравнение «побайтово»).
func statusText(st *status.Status) string {
	return fmt.Sprintf("%v|%s", st.Code(), st.Message())
}
