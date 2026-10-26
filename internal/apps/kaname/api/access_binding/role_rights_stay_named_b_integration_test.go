// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// role_rights_stay_named_b_integration_test.go — группа B приёмки
// role-rights-stay-within-what-is-named.md: правка роли не шире права выдавать
// (Р2, Д-2, Д-4…Д-6; задача PRO-Robotech/kaname#1036). Мир — `newEscWorld`.
//
// Строки сценария с разными исходами идут на РАЗНЫХ свежих мирах: правка правил,
// прошедшая в одной строке, меняла бы «Дано» следующей.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/PRO-Robotech/corelib/operations"

	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// escUR — тело правки U-R (§4.1): правила роли — `{registry, [registries], [*]}`.
func escUR(role domain.RoleID) *iamv1.UpdateRoleRequest {
	return &iamv1.UpdateRoleRequest{
		RoleId:     string(role),
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"rules"}},
		Rules:      []*iamv1.Rule{{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"*"}}},
	}
}

// escURText — правила тела U-R в форме сравнения.
const escURText = "registry [registries] [*]"

// rulesText — правила роли в форме сравнения, по порядку.
func rulesText(rules []*iamv1.Rule) string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, fmt.Sprintf("%s %v %v", r.GetModule(), r.GetResources(), r.GetVerbs()))
	}
	return strings.Join(out, "; ")
}

// opOutcome — исход мутации: синхронный отказ либо операция до `done`.
type opOutcome struct {
	syncErr error
	opID    string
	opErr   *status.Status
}

// tryRoleUpdate — `RoleService.Update` через обработчик `h`.
func (w *escWorld) tryRoleUpdate(h *roleapp.Handler, ctx context.Context, req *iamv1.UpdateRoleRequest) opOutcome {
	w.t.Helper()
	op, err := h.Update(ctx, req)
	if err != nil {
		return opOutcome{syncErr: err}
	}
	out := opOutcome{opID: op.GetId()}
	if done := awaitOp(w.t, w.ctx, w.ops, op.GetId()); done.Error != nil {
		out.opErr = status.New(codes.Code(done.Error.Code), done.Error.Message)
	}
	return out
}

// requireOpDoneOutcome — операция `done`, `error` пуст.
func requireOpDoneOutcome(t *testing.T, o opOutcome, why string) {
	t.Helper()
	require.NoErrorf(t, o.syncErr, "%s: синхронный отказ", why)
	require.Nilf(t, o.opErr, "%s: операция завершилась ошибкой", why)
}

// assertSyncRefusalIs — синхронный отказ, равный эталону по коду, сообщению и
// деталям; операции нет. Без остановки пробы: соседние утверждения читаются.
func assertSyncRefusalIs(t *testing.T, o opOutcome, want error, why string) bool {
	t.Helper()
	if !assert.Emptyf(t, o.opID, "%s: синхронного отказа нет, заведена операция (ошибка операции %v)", why, o.opErr) {
		return false
	}
	got, ok := status.FromError(o.syncErr)
	if !assert.Truef(t, ok && o.syncErr != nil, "%s: ожидался синхронный gRPC-отказ, получено %v", why, o.syncErr) {
		return false
	}
	return assert.Truef(t, proto.Equal(status.Convert(want).Proto(), got.Proto()),
		"%s: отказ %v (%q, деталей %d) не равен эталону %v", why, got.Code(), got.Message(), len(got.Details()), want)
}

// roleDescription — описание роли по `RoleService.Get` от владельца.
func (w *escWorld) roleDescription(role domain.RoleID) string {
	w.t.Helper()
	pb, err := w.rolesX.Get(asUser(w.ctx, w.usrA), &iamv1.GetRoleRequest{RoleId: string(role)})
	require.NoErrorf(w.t, err, "RoleService.Get(%s) от usr-A", role)
	return pb.GetDescription()
}

// ESC-10 — правка правил роли с действующей выдачей требует права выдавать на её области.
func TestRoleRightsStayNamed_ESC10_RulesEditNeedsGrantAuthorityOnItsScope(t *testing.T) {
	x := pcrRegType + ":" + pcrX
	// b, c — строки охраны, каждая на своём мире.
	for _, row := range []struct {
		name   string
		caller func(w *escWorld) domain.UserID
	}{
		{"b usr-RP (право выдавать на prj-A)", func(w *escWorld) domain.UserID { return w.usrRoleEdGrant }},
		{"c usr-E (администратор аккаунта)", func(w *escWorld) domain.UserID { return w.usrE }},
	} {
		w := newEscWorld(t)
		requireOpDoneOutcome(t, w.tryRoleUpdate(w.rolesX, asUser(w.ctx, row.caller(w)), escUR(w.rolE1)), "ESC-10 "+row.name)
		assert.Equalf(t, escURText, rulesText(w.rulesOf(w.rolE1)), "ESC-10 %s: правила rol-e1 = U-R", row.name)
		w.pollRelation(escUser(w.usrRoleEd), "v_delete", x, true, "ESC-10 "+row.name+": действующая выдача следует правилам роли")
	}

	// a — правящий без права выдавать.
	w := newEscWorld(t)
	before := rulesText(w.rulesOf(w.rolE1))
	o := w.tryRoleUpdate(w.rolesX, asUser(w.ctx, w.usrRoleEd), escUR(w.rolE1))
	assertSyncRefusalIs(t, o, authzguard.PermissionDenied(), "ESC-10 a usr-R")
	assert.Equal(t, before, rulesText(w.rulesOf(w.rolE1)), "ESC-10 a: правила rol-e1 прежние")
	assert.False(t, w.relation(escUser(w.usrRoleEd), "v_delete", x), "ESC-10 a: usr-R не получил v_delete на X")
}

// ESC-11 — без действующих выдач право выдавать не спрашивается.
func TestRoleRightsStayNamed_ESC11_NoActiveBindingsNoGrantAuthorityAsked(t *testing.T) {
	w := newEscWorld(t)
	for _, row := range []struct {
		name string
		role domain.RoleID
	}{
		{"a rol-e0 (выдач нет)", w.rolE0},
		{"b rol-er (единственная выдача отозвана)", w.rolER},
	} {
		requireOpDoneOutcome(t, w.tryRoleUpdate(w.rolesX, asUser(w.ctx, w.usrRoleEd), escUR(row.role)), "ESC-11 "+row.name)
		assert.Equalf(t, escURText, rulesText(w.rulesOf(row.role)), "ESC-11 %s: правила = U-R", row.name)
	}
}

// ESC-12 — правка не правил права выдавать не требует.
func TestRoleRightsStayNamed_ESC12_NonRulesEditNeedsNoGrantAuthority(t *testing.T) {
	w := newEscWorld(t)
	before := rulesText(w.rulesOf(w.rolE1))
	requireOpDoneOutcome(t, w.tryRoleUpdate(w.rolesX, asUser(w.ctx, w.usrRoleEd), &iamv1.UpdateRoleRequest{
		RoleId:      string(w.rolE1),
		UpdateMask:  &fieldmaskpb.FieldMask{Paths: []string{"description"}},
		Description: "esc-12",
	}), "ESC-12 usr-R правит описание rol-e1")
	assert.Equal(t, "esc-12", w.roleDescription(w.rolE1), "ESC-12: описание")
	assert.Equal(t, before, rulesText(w.rulesOf(w.rolE1)), "ESC-12: правила прежние")
}

// ESC-13 — право нужно на КАЖДОЙ области выдач роли.
func TestRoleRightsStayNamed_ESC13_GrantAuthorityOnEveryScope(t *testing.T) {
	// b — строка охраны.
	wb := newEscWorld(t)
	requireOpDoneOutcome(t, wb.tryRoleUpdate(wb.rolesX, asUser(wb.ctx, wb.usrE), escUR(wb.rolE2)), "ESC-13 b usr-E")
	assert.Equal(t, escURText, rulesText(wb.rulesOf(wb.rolE2)), "ESC-13 b: правила rol-e2 = U-R")

	// a — право выдавать на prj-A есть, на acc-A нет.
	w := newEscWorld(t)
	before := rulesText(w.rulesOf(w.rolE2))
	o := w.tryRoleUpdate(w.rolesX, asUser(w.ctx, w.usrRoleEdGrant), escUR(w.rolE2))
	assertSyncRefusalIs(t, o, authzguard.PermissionDenied(), "ESC-13 a usr-RP")
	assert.Equal(t, before, rulesText(w.rulesOf(w.rolE2)), "ESC-13 a: правила rol-e2 прежние")
}

// ESC-14 — хранилище отношений не отвечает — правка не проходит (fail-closed).
func TestRoleRightsStayNamed_ESC14_RelationStoreOutageRefusesTheEdit(t *testing.T) {
	// Близнец — тот же вызов при отвечающем хранилище.
	twin := newEscWorld(t)
	requireOpDoneOutcome(t, twin.tryRoleUpdate(twin.rolesX, asUser(twin.ctx, twin.usrE), escUR(twin.rolE1)),
		"ESC-14 близнец: хранилище отвечает")

	w := newEscWorld(t)
	before := rulesText(w.rulesOf(w.rolE1))
	fail := &ceFailFor{inner: w.door, subject: escUser(w.usrE)}
	h := roleapp.NewHandler(nil, w.escRoleUpdateOver(fail), nil, nil, nil)
	o := w.tryRoleUpdate(h, asUser(w.ctx, w.usrE), escUR(w.rolE1))
	t.Logf("ESC-14: вопросов о субъекте usr-E к хранилищу — %d", fail.hits)
	assertSyncRefusalIs(t, o, authzguard.AuthzBackendUnavailable(), "ESC-14: неполадка на вопросе о праве выдавать")
	assert.Equal(t, before, rulesText(w.rulesOf(w.rolE1)), "ESC-14: правила rol-e1 прежние")
	assert.Positive(t, fail.hits, "ESC-14 контроль: вопрос о праве выдавать не задан — инъекция вакуумна")
}

// latchedOps — хранилище операций, задерживающее ЗАВЕДЕНИЕ операции до сигнала:
// синхронное решение правки уже принято, запись ещё не началась.
type latchedOps struct {
	operations.Repo
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (l *latchedOps) CreateWithPrincipal(ctx context.Context, op operations.Operation, p operations.Principal) error {
	l.once.Do(func() { close(l.entered) })
	<-l.release
	return l.Repo.CreateWithPrincipal(ctx, op, p)
}

func (l *latchedOps) Create(ctx context.Context, op operations.Operation) error {
	l.once.Do(func() { close(l.entered) })
	<-l.release
	return l.Repo.Create(ctx, op)
}

// Гонка правки правил и выдачи на новой области (DoD S1 п.5). Принудительное
// чередование: решение правки (Р2) принято, пока выдачи на acc-A нет; затем
// выдача rol-e1 на acc-A заведена и доведена до `done`; затем правка пишется.
// Исход обязан совпадать с одним из двух последовательных порядков:
//   - «правка, затем выдача»: правила = U-R, выдача на acc-A действует;
//   - «выдача, затем правка»: правка отвергнута, правила прежние, выдача действует.
func TestRoleRightsStayNamed_RulesEditAndNewScopeGrantSerialize(t *testing.T) {
	w := newEscWorld(t)
	before := rulesText(w.rulesOf(w.rolE1))
	ops := &latchedOps{Repo: w.ops, entered: make(chan struct{}), release: make(chan struct{})}
	u := roleapp.NewHandler(nil, w.escRoleUpdateOn(ops, w.door), nil, nil, nil)

	type res struct {
		op  string
		err error
	}
	done := make(chan res, 1)
	go func() {
		op, err := u.Update(asUser(w.ctx, w.usrRoleEdGrant), escUR(w.rolE1))
		r := res{err: err}
		if op != nil {
			r.op = op.GetId()
		}
		done <- r
	}()

	var r res
	select {
	case <-ops.entered:
		// Решение правки принято: выдача на acc-A заводится до записи правки.
		w.escGrant(svaSubject(w.svaA2), w.rolE1, "iam.account", string(w.accA), "гонка: rol-e1 → sva-A2 на acc-A")
		close(ops.release)
		r = <-done
	case r = <-done:
		// Правка отвергнута синхронно, до заведения операции; выдача — после.
		close(ops.release)
		w.escGrant(svaSubject(w.svaA2), w.rolE1, "iam.account", string(w.accA), "гонка: rol-e1 → sva-A2 на acc-A")
	case <-time.After(30 * time.Second):
		close(ops.release)
		t.Fatal("гонка: правка не дошла ни до решения, ни до заведения операции за 30 с")
	}

	editApplied := false
	if r.err == nil {
		d := awaitOp(t, w.ctx, w.ops, r.op)
		editApplied = d.Error == nil
	}
	after := rulesText(w.rulesOf(w.rolE1))
	t.Logf("гонка: правка применена — %v; правила до %q, после %q", editApplied, before, after)
	if editApplied {
		assert.Equal(t, escURText, after, "порядок «правка, затем выдача»: правила = U-R")
	} else {
		assert.Equal(t, before, after, "порядок «выдача, затем правка»: правила прежние")
	}
	assert.Equal(t, 2, len(w.statusesByRole(w.rolE1)), "выдачи rol-e1: на prj-A и на acc-A")
}
