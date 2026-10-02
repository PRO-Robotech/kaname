// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_gate_integration_test.go — полоса Е приёмки
// `access-beyond-login-needs-a-verified-address.md` (kaname#456, Р3, Р4б, Р4в)
// и условия аудита поверхности о рубеже: вид принципала — строкой людей, а не
// утверждением; обе полосы (однократный вызов и поток); третий исход — отказ
// операции, а не проход.
//
// Рубеж судит над НАСТОЯЩИМ читателем отметок (`personmarks`) и базой; место
// рубежа в цепочках обоих слушателей держит проба композиционного корня
// (`cmd/kaname/address_gate_wiring_test.go`). У каждого отрицания — близнец,
// отличающийся одним фактом: подтверждён ли адрес, о ком действие, кто
// принципал.
package authzguard_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/membership"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const gateRefusalDomain = "iam.kaname.cloud"

// gateWorld — база с человеком и рубеж над её читателем отметок.
type gateWorld struct {
	ctx  context.Context
	pool *pgxpool.Pool
	gate *authzguard.AddressGate
}

func newGateWorld(t *testing.T) *gateWorld {
	t.Helper()
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Postgres) в кратком режиме")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): пул")
	t.Cleanup(pool.Close)
	// Домен отказа — у объявления композиционного корня (`refusaldomain`).
	require.NoError(t, refusaldomain.Declare(refusaldomain.ProductSuffix))
	return &gateWorld{ctx: ctx, pool: pool, gate: authzguard.NewAddressGate(personmarks.New(pool))}
}

// person — строка человека; verified — с отметкой.
func (w *gateWorld) person(t *testing.T, id string, verified bool) {
	t.Helper()
	acc := "acc-" + strings.TrimPrefix(id, "usr-")
	// Аккаунт и его владелец — одной транзакцией: внешние ключи пары отложены.
	tx, err := w.pool.Begin(w.ctx)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): транзакция")
	defer func() { _ = tx.Rollback(w.ctx) }()
	_, err = tx.Exec(w.ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, $1, $2)`, acc, id)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): аккаунт")
	_, err = tx.Exec(w.ctx, `INSERT INTO kaname.users (id, external_id, email, account_id, invite_status)
		VALUES ($1, $1, $1 || '@example.test', $2, 'ACTIVE')`, id, acc)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): человек")
	if verified {
		_, err = tx.Exec(w.ctx, `UPDATE kaname.users SET email_verified_at = now() WHERE id = $1`, id)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): отметка")
	}
	require.NoError(t, tx.Commit(w.ctx), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): фиксация")
}

// call — однократный вызов через рубеж; reached — дошёл ли вызов до обработчика.
func (w *gateWorld) call(t *testing.T, p operations.Principal, method string, req any) (err error, reached bool) {
	t.Helper()
	ctx := operations.WithPrincipal(w.ctx, p)
	_, err = w.gate.Unary()(ctx, req, &grpc.UnaryServerInfo{FullMethod: method}, func(context.Context, any) (any, error) {
		reached = true
		return nil, nil
	})
	return err, reached
}

// requireRefusalR3 — значение отказа положения Р3 дословно.
func requireRefusalR3(t *testing.T, err error, what string) {
	t.Helper()
	st, ok := status.FromError(err)
	require.Truef(t, ok, "%s: отказ — статус gRPC: %v", what, err)
	require.Equalf(t, codes.PermissionDenied, st.Code(), "%s: код", what)
	require.Equalf(t, "email address is not verified", st.Message(), "%s: текст", what)
	var infos []*errdetails.ErrorInfo
	for _, d := range st.Details() {
		if i, ok := d.(*errdetails.ErrorInfo); ok {
			infos = append(infos, i)
		}
	}
	require.Lenf(t, infos, 1, "%s: ровно один ErrorInfo", what)
	require.Equalf(t, "EMAIL_NOT_VERIFIED", infos[0].GetReason(), "%s: признак", what)
	require.Equalf(t, gateRefusalDomain, infos[0].GetDomain(), "%s: домен", what)
}

// publicMethods — перепись методов публичных служб контракта (все службы
// пакета, кроме внутренних): надмножество смонтированного на публичном
// слушателе, по дескрипторам, а не по выборке.
func publicMethods(t *testing.T) []string {
	t.Helper()
	_ = iamv1.File_kaname_cloud_iam_v1_membership_service_proto // дескрипторы пакета в реестре
	var out []string
	protoregistry.GlobalFiles.RangeFilesByPackage("kaname.cloud.iam.v1", func(fd protoreflect.FileDescriptor) bool {
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			s := svcs.Get(i)
			if strings.HasPrefix(string(s.Name()), "Internal") {
				continue
			}
			ms := s.Methods()
			for j := 0; j < ms.Len(); j++ {
				out = append(out, "/"+string(s.FullName())+"/"+string(ms.Get(j).Name()))
			}
		}
		return true
	})
	if len(out) == 0 {
		t.Fatal("НЕ-ВЫПОЛНИЛОСЬ: перепись методов публичных служб пуста — судить нечего")
	}
	return out
}

// internalMethods — методы внутренних служб контракта.
func internalMethods(t *testing.T) []string {
	t.Helper()
	_ = iamv1.File_kaname_cloud_iam_v1_membership_service_proto
	var out []string
	protoregistry.GlobalFiles.RangeFilesByPackage("kaname.cloud.iam.v1", func(fd protoreflect.FileDescriptor) bool {
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			s := svcs.Get(i)
			if !strings.HasPrefix(string(s.Name()), "Internal") {
				continue
			}
			ms := s.Methods()
			for j := 0; j < ms.Len(); j++ {
				out = append(out, "/"+string(s.FullName())+"/"+string(ms.Get(j).Name()))
			}
		}
		return true
	})
	return out
}

// TestEV60_EveryPublicMethodRefusesTheUnverified — EV-60.
func TestEV60_EveryPublicMethodRefusesTheUnverified(t *testing.T) {
	w := newGateWorld(t)
	w.person(t, "usr-ev60a", false)
	w.person(t, "usr-ev60b", true)
	methods := publicMethods(t)
	for _, m := range methods {
		err, reached := w.call(t, operations.Principal{ID: "usr-ev60a", Type: "user"}, m, nil)
		requireRefusalR3(t, err, "EV-60 (а) "+m)
		require.Falsef(t, reached, "EV-60 (а) %s: до обработчика вызов не дошёл", m)
		err, reached = w.call(t, operations.Principal{ID: "usr-ev60b", Type: "user"}, m, nil)
		require.NoErrorf(t, err, "EV-60 (б) %s: подтверждённому рубеж молчит", m)
		require.Truef(t, reached, "EV-60 (б) %s", m)
	}
	t.Logf("EV-60: осмотрено методов публичных служб %d", len(methods))
	require.Contains(t, methods, "/kaname.cloud.iam.v1.MembershipService/ListMine", "перепись несёт самоадресное чтение")
	require.Contains(t, methods, "/kaname.cloud.iam.v1.AuthorizeService/WhoAmI", "перепись несёт «кто я» службы")
}

// TestEV61_AdmissionBeforeArgumentParsing — EV-61: самоадресное ListMine с
// page_size = -1 — у неподтверждённого отказ Р3, у подтверждённого — отказ
// формата производителя.
func TestEV61_AdmissionBeforeArgumentParsing(t *testing.T) {
	w := newGateWorld(t)
	w.person(t, "usr-ev61a", false)
	w.person(t, "usr-ev61b", true)
	h := membership.NewHandler(nil, nil, membership.NewListMyMembershipsUseCase(nil), nil)
	ask := func(id string) error {
		ctx := operations.WithPrincipal(w.ctx, operations.Principal{ID: id, Type: "user"})
		_, err := w.gate.Unary()(ctx, &iamv1.ListMyMembershipsRequest{PageSize: -1},
			&grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.MembershipService/ListMine"},
			func(c context.Context, req any) (any, error) {
				return h.ListMine(c, req.(*iamv1.ListMyMembershipsRequest))
			})
		return err
	}
	requireRefusalR3(t, ask("usr-ev61a"), "EV-61 (а)")
	st, _ := status.FromError(ask("usr-ev61b"))
	require.Equal(t, codes.InvalidArgument, st.Code(), "EV-61 (б): формат судится обработчиком")
	require.Equal(t, "invalid argument", st.Message())
	var found bool
	for _, d := range st.Details() {
		if br, ok := d.(*errdetails.BadRequest); ok {
			for _, v := range br.GetFieldViolations() {
				if v.GetField() == "page_size" {
					found = true
					require.Equal(t, "page_size must be in [0..1000] (0 means default)", v.GetDescription())
				}
			}
		}
	}
	require.True(t, found, "EV-61 (б): нарушение поля page_size")
}

// TestEV62_EdgeCircleOnTheInternalListener — EV-62: 18 методов круга края; 17 —
// отказ Р3, Revoke о себе — своим исходом; контроль вида принципала —
// системный принципал отказа положения не получает. Приёмка называет 19: в
// круг входил глагол обратного вызова прежнего поставщика восстановления,
// снятый вместе с поставщиком (kaname#564).
func TestEV62_EdgeCircleOnTheInternalListener(t *testing.T) {
	w := newGateWorld(t)
	w.person(t, "usr-ev62a", false)
	w.person(t, "usr-ev62b", true)
	circle := authzguard.GatewayFrontedInternalRPCs()
	require.Len(t, circle, 18, "перепись круга края")
	revoke := "/kaname.cloud.iam.v1.InternalSessionRevocationsService/Revoke"
	var refused int
	for _, m := range circle {
		req := any(nil)
		if m == revoke {
			req = &iamv1.RevokeRequest{UserId: "usr-ev62a"}
		}
		err, reached := w.call(t, operations.Principal{ID: "usr-ev62a", Type: "user"}, m, req)
		if m == revoke {
			require.NoError(t, err, "EV-62 (а): Revoke о себе — своим исходом")
			require.True(t, reached)
		} else {
			requireRefusalR3(t, err, "EV-62 (а) "+m)
			require.False(t, reached)
			refused++
		}
		if m == revoke {
			req = &iamv1.RevokeRequest{UserId: "usr-ev62b"}
		}
		err, reached = w.call(t, operations.Principal{ID: "usr-ev62b", Type: "user"}, m, req)
		require.NoErrorf(t, err, "EV-62 (б) %s", m)
		require.True(t, reached)
		err, reached = w.call(t, operations.SystemPrincipal(), m, nil)
		require.NoErrorf(t, err, "EV-62: системный принципал — рубеж судит человека, а не метод (%s)", m)
		require.True(t, reached)
	}
	require.Equal(t, 17, refused, "EV-62 (а): отказ Р3 на 17 методах")
	t.Logf("EV-62: осмотрено методов круга %d, отказов %d", len(circle), refused)
}

// TestEV63_SelfHistoryReadIsRefusedBeforeTheStore — EV-63.
func TestEV63_SelfHistoryReadIsRefusedBeforeTheStore(t *testing.T) {
	w := newGateWorld(t)
	w.person(t, "usr-ev63a", false)
	w.person(t, "usr-ev63b", true)
	m := "/kaname.cloud.iam.v1.InternalSessionRevocationsService/ListByUser"
	err, reached := w.call(t, operations.Principal{ID: "usr-ev63a", Type: "user"}, m, &iamv1.ListByUserRequest{UserId: "usr-ev63a"})
	requireRefusalR3(t, err, "EV-63 (а)")
	require.False(t, reached, "EV-63 (а): до чтения хранилища")
	err, reached = w.call(t, operations.Principal{ID: "usr-ev63b", Type: "user"}, m, &iamv1.ListByUserRequest{UserId: "usr-ev63b"})
	require.NoError(t, err)
	require.True(t, reached, "EV-63 (б): страница истории")
}

// TestEV64_SelfRevokeIsAvailableAndOthersIsNot — EV-64.
func TestEV64_SelfRevokeIsAvailableAndOthersIsNot(t *testing.T) {
	w := newGateWorld(t)
	w.person(t, "usr-ev64h", false)
	w.person(t, "usr-ev64g", true)
	m := "/kaname.cloud.iam.v1.InternalSessionRevocationsService/Revoke"
	err, reached := w.call(t, operations.Principal{ID: "usr-ev64h", Type: "user"}, m, &iamv1.RevokeRequest{UserId: "usr-ev64h"})
	require.NoError(t, err, "EV-64 (а): о себе — доступно")
	require.True(t, reached)
	err, reached = w.call(t, operations.Principal{ID: "usr-ev64h", Type: "user"}, m, &iamv1.RevokeRequest{UserId: "usr-ev64g"})
	requireRefusalR3(t, err, "EV-64 (б): о другом человеке")
	require.False(t, reached)
}

// TestAddressGateJudgesTheKindByThePersonRow — условие аудита поверхности: вид
// принципала не берётся на веру. Удостоверение, называющее человека видом
// служебной учётной записи, всё равно судится; поток — тоже; близнец —
// настоящий идентификатор служебной учётной записи (строки человека нет).
func TestAddressGateJudgesTheKindByThePersonRow(t *testing.T) {
	w := newGateWorld(t)
	w.person(t, "usr-kind0000000000001", false)
	m := "/kaname.cloud.iam.v1.ProjectService/Get"
	err, _ := w.call(t, operations.Principal{ID: "usr-kind0000000000001", Type: "service_account"}, m, nil)
	requireRefusalR3(t, err, "вид из утверждения не спасает")
	err, reached := w.call(t, operations.Principal{ID: "sva-kind0000000000001", Type: "service_account"}, m, nil)
	require.NoError(t, err, "близнец: настоящая служебная учётная запись — рубеж молчит")
	require.True(t, reached)

	ctx := operations.WithPrincipal(w.ctx, operations.Principal{ID: "usr-kind0000000000001", Type: "user"})
	serr := w.gate.Stream()(nil, streamWithContext{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: m},
		func(any, grpc.ServerStream) error { return nil })
	requireRefusalR3(t, serr, "поток неподтверждённого")
}

// TestAddressGateThirdOutcomeIsNotAPass — условие аудита («третий исход»):
// отметку прочесть не смогли — отказ операции, а не проход.
func TestAddressGateThirdOutcomeIsNotAPass(t *testing.T) {
	w := newGateWorld(t)
	w.person(t, "usr-third0000000000001", true)
	m := "/kaname.cloud.iam.v1.ProjectService/Get"
	err, reached := w.call(t, operations.Principal{ID: "usr-third0000000000001", Type: "user"}, m, nil)
	require.NoError(t, err, "близнец: хранилище отвечает")
	require.True(t, reached)

	holder, err := w.pool.Begin(w.ctx)
	require.NoError(t, err)
	defer func() { _ = holder.Rollback(context.Background()) }()
	_, err = holder.Exec(w.ctx, `LOCK TABLE kaname.users IN ACCESS EXCLUSIVE MODE`)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(operations.WithPrincipal(w.ctx, operations.Principal{ID: "usr-third0000000000001", Type: "user"}), time.Second)
	defer cancel()
	called := false
	_, gerr := w.gate.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: m}, func(context.Context, any) (any, error) {
		called = true
		return nil, nil
	})
	require.False(t, called, "третий исход: до обработчика вызов не дошёл")
	st, _ := status.FromError(gerr)
	require.Equal(t, codes.Unavailable, st.Code(), "третий исход — отказ операции: %v", gerr)
	require.False(t, errors.Is(gerr, context.Canceled))
}

// streamWithContext — поток, несущий контекст принципала.
type streamWithContext struct {
	grpc.ServerStream
	ctx context.Context
}

func (s streamWithContext) Context() context.Context { return s.ctx }

// TestInternalAddressGateTablesAreClosed — гейт таблиц Р4в (§9 п. 5): каждый
// метод круга края — строкой круга, каждый прочий метод внутренних служб —
// строкой вне круга, строк без метода нет. Печатает перепись.
func TestInternalAddressGateTablesAreClosed(t *testing.T) {
	circle := authzguard.GatewayFrontedInternalRPCs()
	internal := internalMethods(t)
	table := authzguard.InternalAddressGateTable()
	findings := authzguard.InternalAddressGateFindings(circle, internal, table)
	t.Logf("перепись: круг края %d · методов внутренних служб %d · строк таблиц %d", len(circle), len(internal), len(table))
	require.Empty(t, findings)
	require.Len(t, circle, 18)
	require.Len(t, internal, 31)
}

// TestInternalAddressGateTablesInjection — инъекция в обе стороны: метод круга
// без строки, новый метод внутренней службы без строки и строка без метода
// краснеют с координатой; законный близнец (метод со строкой) молчит; пустой
// обход — находка, а не зелёное.
func TestInternalAddressGateTablesInjection(t *testing.T) {
	circle := authzguard.GatewayFrontedInternalRPCs()
	internal := internalMethods(t)
	table := authzguard.InternalAddressGateTable()

	withCircle := append(append([]string(nil), circle...), "/kaname.cloud.iam.v1.InternalClusterService/Probe")
	withInternal := append(append([]string(nil), internal...), "/kaname.cloud.iam.v1.InternalProbeService/Probe")
	orphan := authzguard.InternalAddressGateTable()
	orphan["/kaname.cloud.iam.v1.InternalGhostService/Ghost"] = authzguard.InternalAddressGateRow{Row: authzguard.GateOutsideCircle, Reason: "ghost"}

	for name, f := range map[string][]string{
		"InternalClusterService/Probe": authzguard.InternalAddressGateFindings(withCircle, append(internal, "/kaname.cloud.iam.v1.InternalClusterService/Probe"), table),
		"InternalProbeService/Probe":   authzguard.InternalAddressGateFindings(circle, withInternal, table),
		"InternalGhostService/Ghost":   authzguard.InternalAddressGateFindings(circle, internal, orphan),
	} {
		require.NotEmptyf(t, f, "инъекция %s не найдена", name)
		require.Containsf(t, strings.Join(f, "\n"), name, "находка называет координату %s", name)
	}
	twin := authzguard.InternalAddressGateTable()
	twin["/kaname.cloud.iam.v1.InternalProbeService/Probe"] = authzguard.InternalAddressGateRow{Row: authzguard.GateOutsideCircle, Reason: "probe"}
	require.Empty(t, authzguard.InternalAddressGateFindings(circle, withInternal, twin), "законный близнец молчит")
	require.NotEmpty(t, authzguard.InternalAddressGateFindings(nil, nil, table), "пустой обход — не вердикт")
}
