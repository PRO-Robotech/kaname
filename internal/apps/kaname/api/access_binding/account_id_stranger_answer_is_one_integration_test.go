// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// account_id_stranger_answer_is_one_integration_test.go — AID-36: посторонний
// получает один ответ на каждом пути, принимающем идентификатор аккаунта
// (задача kaname#1052, приёмка
// `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`, редакция
// 7, sha256 a3dff53e9ae56e3e1fa959d6ee3b43a932aaf09d3918795a62c06377550e3e52;
// Р15, §1.11, находка F1 разбора поверхности до кода).
//
// # Мир
//
// Сервер службы в процессе: собственная дверь (`authzguard.NewOwnDoor`) над той
// же дверью решения, что у корня службы (`authzcascade.WrapAdmitted` над
// `relverdict` и отметками людей), каталог прав, выведенный дверью из аннотаций
// контракта, обработчики и use-case с настоящим хранилищем на базе
// testcontainers. Обработчики собраны теми же частями и в том же порядке
// `With…`, что `cmd/kaname/wiring.go` (`buildServices`, `buildAuthZServices`).
// Каждый вызов идёт ЧЕРЕЗ дверь: проба, зовущая обработчик мимо двери, судила бы
// путь, которого у вызывающего нет.
//
// Люди: O — владелец аккаунтов F (`aid36-foreign`, заданная форма) и Fg (форма
// генератора); H — посторонний в смысле Р15, владелец своего аккаунта Ah с
// проектом Ph; A — администратор облака. Не выданы: `aid36-absent` и Xa (форма
// генератора). В F есть проект Pf; Pa — идентификатор проекта, которого нет.
// F вставлен строкой, которую схема допускает (CHECK формы на `accounts` нет,
// §1.4 приёмки); кортежи модели — владельцы и указатель `cluster` — прямыми
// фактами `relation_fact`, иначе близнец под O и дверь `BatchCheck` под H судили
// бы недосев, а не продукт.
//
// # Строки — по переписи, а не по выбору
//
// Таблица пробы — 34 пути §1.11. Перепись дерева выводит пути тремя предикатами
// §1.11 по `proto/kaname/cloud/iam/v1/*.proto` (по имени поля, по типу поля —
// замыкание до `ResourceRef`, — по полям объекта модели) и записями каталога
// прав с областью `account` из поля `account_id`. Путь, найденный переписью и не
// стоящий ни строкой, ни исключением (4 внутренних пути §1.11), — находка с
// именем пути. Строка таблицы, чьего RPC в дереве головы нет, исполнена быть не
// может и печатается «не выполнилось» с причиной: ветка задачи отходит от ветки
// эпика `942`, которая уступает стволу (§1.0 приёмки), и `GrantDelegationService`
// на ней нет.
//
// # Порядок пробы несущий
//
//  1. мир и его положительные контроли (владелец O проходит дверь на F; H на F
//     прав не имеет; контроль различимости на форме генератора: A видит Fg и не
//     видит Xa) — сломанный посев краснеет здесь, называя контроль;
//  2. перепись путей;
//  3. предмет — один ответ постороннему на каждом пути и каждой форме; затем
//     контроль различимости на заданной форме, неполадка хранилища на создании
//     привязки и близнецы под O (A), разрушающие — последними.
//
// # Чем краснеет до реализации
//
// На заданной форме каждая строка, где форму сегодня судит проверка по
// префиксу (§1.3), отвечает `INVALID_ARGUMENT` — утверждение «ни один ответ не
// INVALID_ARGUMENT» и контроль различимости под A на F красны. На форме
// генератора красна строка `AccessBindingService/Create`: промах области у
// постороннего — `NOT_FOUND`, чужая область — `PERMISSION_DENIED` (F1). Строки,
// которые форму не читают, — фильтры перечня, `AuthorizeService`,
// `ExpandAccess`, — зелёные и сегодня: для них проба держит регрессию.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	accountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	authorizeapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/authorize"
	groupapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	internaloperationsapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_operations"
	membershipapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/membership"
	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	serviceaccountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/service_account"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/servicesan"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const (
	// aid36Foreign — существующий чужой аккаунт заданной формы.
	aid36Foreign = "aid36-foreign"
	// aid36Absent — идентификатор заданной формы, не выданный ни разу.
	aid36Absent = "aid36-absent"
	// aid36Pkg — пакет контракта службы: полное имя метода — «/<пакет>.<служба>/<RPC>».
	aid36Pkg = "kaname.cloud.iam.v1"
	// aid36Mask — метка, которой заменяется присланный идентификатор.
	aid36Mask = "<ID>"
	// aid36RowsInAcceptance — строк переписи §1.11 под Р15.
	aid36RowsInAcceptance = 34
)

// aid36Excluded — закрытый перечень исключений §1.11 с доводом: внутренний
// слушатель и собственный внутренний REST-фронт пускают только модуль по
// проверенному сертификату; постороннего человека там нет.
var aid36Excluded = map[string]string{
	"/" + aid36Pkg + ".InternalIAMService/Check":                  "внутренний слушатель (INTERNAL_LISTENER)",
	"/" + aid36Pkg + ".InternalIAMService/RegisterResource":       "внутренний слушатель (INTERNAL_LISTENER)",
	"/" + aid36Pkg + ".InternalIAMService/UnregisterResource":     "внутренний слушатель (INTERNAL_LISTENER)",
	"/corelib.subscription.InternalSubscriptionService/Subscribe": "ось ids подписки — внутренний слушатель",
}

// Классы путей §1.11: класс решает, КАКОЙ ответ постороннему (Р15).
const (
	aid36ClassDoor      = "дверь службы"
	aid36ClassHandler   = "обработчик (HANDLER_DECIDES)"
	aid36ClassFilter    = "фильтр перечня"
	aid36ClassAdminOnly = "только администратор облака"
	aid36ClassModel     = "только модель прав"
	aid36ClassGrantGate = "ворота права выдачи под сокрытием"
)

// aid36World — мир AID-36 одной базы.
type aid36World struct {
	t    *testing.T
	ctx  context.Context
	pool *pgxpool.Pool
	repo *kanamepg.Repository
	ops  operations.FullRepo
	door grpc.UnaryServerInterceptor

	o, h, a  domain.UserID
	fg, ah   domain.AccountID
	xa       string
	pf, ph   domain.ProjectID
	pa       string
	member   domain.UserID
	seq      int
	acc      *accountapp.Handler
	ab       *accessbindingapp.Handler
	abBroken *accessbindingapp.Handler
	grp      *groupapp.Handler
	mbr      *membershipapp.Handler
	prj      *projectapp.Handler
	rol      *roleapp.Handler
	sa       *serviceaccountapp.Handler
	usr      *userapp.Handler
	iops     *internaloperationsapp.Handler
	authz    *authorizeapp.Handler
}

// brokenRelations — хранилище отношений, отвечающее ошибкой связи на каждый вопрос.
type brokenRelations struct{}

func (brokenRelations) Check(context.Context, string, string, string) (bool, error) {
	return false, errors.New("relation store: connection refused")
}

var _ clients.RelationStore = brokenRelations{}

// fact — прямой факт модели в форме, которую читает `relverdict`.
func (w *aid36World) fact(objectType, objectID, relation, subject string) {
	w.t.Helper()
	_, err := w.pool.Exec(w.ctx, `INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
		VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`, objectType, objectID, relation, subject)
	require.NoErrorf(w.t, err, "мир AID-36: факт %s:%s#%s@%s", objectType, objectID, relation, subject)
}

func (w *aid36World) name(tag string) string {
	w.seq++
	return fmt.Sprintf("aid36-%s-%d", tag, w.seq)
}

// newAID36World поднимает мир и доказывает живость посева.
func newAID36World(t *testing.T) *aid36World {
	t.Helper()
	if testing.Short() {
		t.Skip("нужен Postgres: пропуск в -short")
	}
	ctx := context.Background()
	pool := poolFromDSN(t, setupTestDB(t))
	t.Cleanup(func() { _ = operations.Wait(context.Background()) })
	repo := kanamepg.New(pool, nil)
	ops := operations.NewRepo(pool, "kaname")
	rel := authzcascade.WrapAdmitted(relverdict.NewAsker(pool), personmarks.New(pool))
	own, err := authzguard.NewOwnDoor(authzguard.OwnDoorOptions{SelfCheck: rel, PositiveTTL: time.Second})
	require.NoError(t, err, "мир AID-36: дверь слушателя не собралась")
	w := &aid36World{t: t, ctx: ctx, pool: pool, repo: repo, ops: ops, door: own.Unary()}
	w.buildHandlers(rel)

	// Люди и аккаунты.
	w.o = mustSeedUser(t, ctx, pool, "aid36o")
	w.h = mustSeedUser(t, ctx, pool, "aid36h")
	w.a = mustSeedUser(t, ctx, pool, "aid36a")
	w.member = mustSeedUser(t, ctx, pool, "aid36m")
	_, err = pool.Exec(ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
		VALUES ($1, 'aid36-foreign-name', $2, '{}'::jsonb)`, aid36Foreign, string(w.o))
	require.NoError(t, err, "мир AID-36: аккаунт F заданной формы (схема CHECK формы не держит, §1.4)")
	w.fg = seedAccountByOwner(t, ctx, pool, "aid36-fg", w.o)
	w.ah = seedAccountByOwner(t, ctx, pool, "aid36-ah", w.h)
	w.pf = seedProjectInAccount(t, ctx, pool, aid36Foreign, "aid36-pf")
	w.ph = seedProjectInAccount(t, ctx, pool, w.ah, "aid36-ph")
	w.xa = ids.NewID(domain.PrefixAccount)
	w.pa = ids.NewID(domain.PrefixProject)
	_, err = pool.Exec(ctx, `INSERT INTO kaname.clusters (id, name) VALUES ('cluster_root', 'kacho') ON CONFLICT DO NOTHING`)
	require.NoError(t, err)
	seedClusterAdmin(t, ctx, pool, w.a)
	verifyAddresses(t, ctx, pool)

	// Кортежи модели: владельцы, указатель кластера, проект → аккаунт.
	cluster := "cluster:" + domain.ClusterSingletonID
	w.fact("cluster", domain.ClusterSingletonID, "system_admin", "user:"+string(w.a))
	for acc, owner := range map[string]domain.UserID{aid36Foreign: w.o, string(w.fg): w.o, string(w.ah): w.h} {
		w.fact("account", acc, "owner", "user:"+string(owner))
		w.fact("account", acc, "cluster", cluster)
	}
	for prj, acc := range map[domain.ProjectID]string{w.pf: aid36Foreign, w.ph: string(w.ah)} {
		w.fact("project", string(prj), "account", "account:"+acc)
		w.fact("project", string(prj), "cluster", cluster)
	}

	// ── положительные контроли посева ──────────────────────────────────────
	for _, c := range []struct {
		who  domain.UserID
		obj  string
		want bool
		what string
	}{
		{w.o, "account:" + aid36Foreign, true, "O — владелец F"},
		{w.o, "account:" + string(w.fg), true, "O — владелец Fg"},
		{w.h, "project:" + string(w.ph), true, "H видит свой проект Ph (дверь BatchCheck)"},
		{w.a, "account:" + aid36Foreign, true, "A — администратор облака"},
		{w.h, "account:" + aid36Foreign, false, "H — посторонний на F"},
		{w.h, "account:" + string(w.fg), false, "H — посторонний на Fg"},
	} {
		got, err := rel.Check(ctx, "user:"+string(c.who), "viewer", c.obj)
		require.NoErrorf(t, err, "контроль мира AID-36: %s", c.what)
		require.Equalf(t, c.want, got, "контроль мира AID-36: %s", c.what)
	}
	return w
}

// buildHandlers — обработчики теми же частями, что корень службы.
func (w *aid36World) buildHandlers(rel *authzcascade.Client) {
	repo, ops, pool := w.repo, w.ops, w.pool
	logger := slog.New(slog.NewTextHandler(devNull{}, nil))
	src := catalogfixture.Source()
	rec := reconcile.New(kanamepg.NewReconcileAdapter(pool, src), nil, src)

	w.acc = accountapp.NewHandler(
		accountapp.NewCreateAccountUseCase(repo, ops).WithRelationStore(rel, logger).WithReconciler(rec),
		accountapp.NewUpdateAccountUseCase(repo, ops).WithRelationStore(rel, logger).WithObjectReconciler(rec),
		accountapp.NewDeleteAccountUseCase(repo, ops),
		accountapp.NewGetAccountUseCase(repo).WithRelationStore(rel),
		accountapp.NewListAccountsUseCase(repo).WithRelationStore(rel)).
		WithListOperations(shared.NewListOperationsUseCase(ops)).
		WithListAllOperations(accountapp.NewListAllOperationsUseCase(repo, ops).WithRelationStore(rel, logger))

	w.prj = projectapp.NewHandler(
		projectapp.NewCreateProjectUseCase(repo, ops).WithRelationStore(rel, logger).WithObjectReconciler(rec),
		projectapp.NewUpdateProjectUseCase(repo, ops).WithRelationStore(rel, logger).WithObjectReconciler(rec),
		projectapp.NewDeleteProjectUseCase(repo, ops),
		projectapp.NewGetProjectUseCase(repo).WithRelationStore(rel),
		projectapp.NewListProjectsUseCase(repo).WithRelationStore(rel)).
		WithListOperations(shared.NewListOperationsUseCase(ops))

	limit := outboxtypes.InviteMailRateLimit{MaxPerWindow: 10, Window: time.Hour}
	invite := userapp.NewInviteUserUseCase(repo, ops, rel).
		WithRelationStore(rel, logger).
		WithObjectReconciler(rec).
		WithInviteMailRateLimit(limit, nil)
	w.usr = userapp.NewHandler(
		userapp.NewGetUserUseCase(repo).WithRelationStore(rel),
		userapp.NewListUsersUseCase(repo).WithRelationStore(rel),
		userapp.NewUpdateUserUseCase(repo, ops).WithObjectReconciler(rec, logger),
		userapp.NewDeleteUserUseCase(repo, ops),
		invite,
		userapp.NewBlockUserUseCase(repo, ops),
		userapp.NewUnblockUserUseCase(repo, ops),
		userapp.NewRemoveFromAccountUseCase(repo, ops)).
		WithResendInvite(userapp.NewResendInviteUseCase(repo, ops, rel, limit, nil)).
		WithListOperations(shared.NewListOperationsUseCase(ops))

	w.sa = serviceaccountapp.NewHandler(
		serviceaccountapp.NewCreateServiceAccountUseCase(repo, ops).WithRelationStore(rel, logger).WithObjectReconciler(rec),
		serviceaccountapp.NewUpdateServiceAccountUseCase(repo, ops).WithObjectReconciler(rec, logger),
		serviceaccountapp.NewDeleteServiceAccountUseCase(repo, ops),
		serviceaccountapp.NewGetServiceAccountUseCase(repo).WithRelationStore(rel),
		serviceaccountapp.NewListServiceAccountsUseCase(repo).WithRelationStore(rel),
		serviceaccountapp.NewDisableServiceAccountUseCase(repo, ops),
		serviceaccountapp.NewEnableServiceAccountUseCase(repo, ops)).
		WithListOperations(shared.NewListOperationsUseCase(ops))

	w.grp = groupapp.NewHandler(
		groupapp.NewCreateGroupUseCase(repo, ops).WithRelationStore(rel, logger).WithObjectReconciler(rec),
		groupapp.NewUpdateGroupUseCase(repo, ops).WithObjectReconciler(rec, logger),
		groupapp.NewDeleteGroupUseCase(repo, ops),
		groupapp.NewGetGroupUseCase(repo).WithRelationStore(rel),
		groupapp.NewListGroupsUseCase(repo).WithRelationStore(rel),
		groupapp.NewAddMemberUseCase(repo, ops),
		groupapp.NewRemoveMemberUseCase(repo, ops),
		groupapp.NewListMembersUseCase(repo).WithRelationStore(rel)).
		WithListOperations(shared.NewListOperationsUseCase(ops))

	w.mbr = membershipapp.NewHandler(
		membershipapp.NewGetMembershipUseCase(repo),
		membershipapp.NewListMembershipsUseCase(repo),
		membershipapp.NewListMyMembershipsUseCase(repo),
		invite)

	w.rol = roleapp.NewHandler(
		roleapp.NewCreateRoleUseCase(repo, ops, src).WithRelationStore(rel, logger).WithObjectReconciler(rec),
		roleapp.NewUpdateRoleUseCase(repo, ops, src).
			WithTupleReconciler(accessbindingapp.NewRoleTupleReconciler()).
			WithMembershipFanout(accessbindingapp.NewRoleMembershipFanout(repo, rec)).
			WithObjectReconciler(rec, logger),
		roleapp.NewDeleteRoleUseCase(repo, ops),
		roleapp.NewGetRoleUseCase(repo, src).WithRelationStore(rel),
		roleapp.NewListRolesUseCase(repo, src).WithRelationStore(rel)).
		WithListOperations(shared.NewListOperationsUseCase(ops))

	w.ab = w.accessBindingHandler(rel, rel, rec)
	w.abBroken = w.accessBindingHandler(brokenRelations{}, rel, rec)

	w.iops = internaloperationsapp.NewHandler(internaloperationsapp.NewListIamOperationsUseCase(ops).WithAdminChecker(rel))

	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations:           rel,
		ClusterAdminChecker: rel,
		SessionRecords:      kanamepg.NewHumanSessionRepo(pool),
	})
	w.authz = authorizeapp.NewHandler(svc, authorizeapp.NewWhoAmIUseCase(repo, rel), servicesan.NewForm("kacho-{service}")).
		WithCallerAuthority(rel).
		WithInsecureAnonymousPeer(false)
}

// accessBindingHandler — обработчик выдачи; store — хранилище отношений
// use-case'ов (у мира неполадки — сломанное), queries — запросы к модели.
func (w *aid36World) accessBindingHandler(store clients.RelationStore, rel *authzcascade.Client,
	rec *reconcile.Reconciler) *accessbindingapp.Handler {
	repo, ops, pool := w.repo, w.ops, w.pool
	logger := slog.New(slog.NewTextHandler(devNull{}, nil))
	src := catalogfixture.Source()
	return accessbindingapp.NewHandler(
		accessbindingapp.NewCreateAccessBindingUseCase(repo, ops, src).WithRelationStore(store, logger).WithReconciler(rec),
		accessbindingapp.NewDeleteAccessBindingUseCase(repo, ops).WithRelationStore(store, logger),
		accessbindingapp.NewGetAccessBindingUseCase(repo).WithRelationStore(store, logger).WithRelationQueries(rel),
		accessbindingapp.NewListByScopeUseCase(repo).WithRelationStore(store, logger).WithRelationQueries(rel),
		accessbindingapp.NewListBySubjectUseCase(repo).WithRelationStore(store, logger).WithRelationQueries(rel),
		accessbindingapp.NewListByAccountUseCase(repo).WithRelationStore(store, logger).WithRelationQueries(rel),
		accessbindingapp.NewListSubjectPrivilegesUseCase(repo).WithRelationStore(store, logger).WithRelationQueries(rel)).
		WithUpdate(accessbindingapp.NewUpdateAccessBindingUseCase(repo, ops).WithRelationStore(store, logger).WithObjectReconciler(rec)).
		WithListOperations(shared.NewListOperationsUseCase(ops)).
		WithList(accessbindingapp.NewListUseCase(repo).WithRelationStore(store).WithRelationQueries(rel).
			WithClusterAdmins(kanamepg.NewClusterAdminGrantReader(pool))).
		WithListAssignableRoles(accessbindingapp.NewListAssignableRolesUseCase(repo).WithRelationStore(store, logger)).
		WithListByRole(accessbindingapp.NewListByRoleUseCase(repo).WithRelationStore(store, logger)).
		WithExpandAccess(accessbindingapp.NewExpandAccessUseCase(rel).WithGrantAuthority(repo, store, logger)).
		WithRevoke(accessbindingapp.NewRevokeAccessBindingUseCase(repo, ops).WithRelationStore(store, logger))
}

// devNull — журнал use-case молчит: предмет — ответ, а не строки лога.
type devNull struct{}

func (devNull) Write(p []byte) (int, error) { return len(p), nil }

// via — вызов метода через дверь мира.
func (w *aid36World) via(ctx context.Context, method string, req proto.Message,
	call func(context.Context) (proto.Message, error)) (proto.Message, error) {
	out, err := w.door(ctx, req, &grpc.UnaryServerInfo{FullMethod: method},
		func(ctx context.Context, _ any) (any, error) { return call(ctx) })
	if err != nil {
		return nil, err
	}
	msg, ok := out.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("ответ %s не сообщение (%T)", method, out)
	}
	return msg, nil
}

func asPrincipal(uid domain.UserID) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: string(uid)})
}

// aid36Answer — ответ одной строкой после замены присланного идентификатора меткой:
// пара (код, сообщение) и `details` либо тело ответа.
func aid36Answer(out proto.Message, err error, id string) string {
	mask := func(s string) string { return strings.ReplaceAll(s, id, aid36Mask) }
	if err != nil {
		st := status.Convert(err)
		details, _ := protojson.Marshal(st.Proto())
		return mask(fmt.Sprintf("ERR %s | %s | %s", st.Code(), st.Message(), details))
	}
	body, merr := protojson.Marshal(out)
	if merr != nil {
		return "ERR тело не сериализуется: " + merr.Error()
	}
	return mask("OK " + string(body))
}

// aid36Code — код ответа строки (OK для успешного).
func aid36Code(err error) codes.Code { return status.Code(err) }

// aid36Row — путь переписи §1.11.
type aid36Row struct {
	method string
	class  string
	// call — вызов пути вызывающим who на идентификатор аккаунта id; nil — RPC в
	// дереве головы нет.
	call func(w *aid36World, ctx context.Context, id string) (proto.Message, error)
	// destructive — близнец снимает объекты и исполняется последним.
	destructive bool
}

func m(svc, rpc string) string { return "/" + aid36Pkg + "." + svc + "/" + rpc }

// aid36Rows — 34 пути §1.11 под Р15.
func aid36Rows() []aid36Row {
	labels := map[string]string{"k": "v"}
	return []aid36Row{
		// дверь службы по объекту account:<id> — 16
		{m("AccountService", "Get"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.GetAccountRequest{AccountId: id}
			return w.via(ctx, m("AccountService", "Get"), req, func(c context.Context) (proto.Message, error) { return w.acc.Get(c, req) })
		}, false},
		{m("AccountService", "Update"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.UpdateAccountRequest{AccountId: id, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}}, Labels: labels}
			return w.via(ctx, m("AccountService", "Update"), req, func(c context.Context) (proto.Message, error) { return w.acc.Update(c, req) })
		}, false},
		{m("AccountService", "Delete"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.DeleteAccountRequest{AccountId: id}
			return w.via(ctx, m("AccountService", "Delete"), req, func(c context.Context) (proto.Message, error) { return w.acc.Delete(c, req) })
		}, true},
		{m("AccountService", "ListOperations"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.ListAccountOperationsRequest{AccountId: id}
			return w.via(ctx, m("AccountService", "ListOperations"), req, func(c context.Context) (proto.Message, error) { return w.acc.ListOperations(c, req) })
		}, false},
		{m("AccountService", "ListAllOperations"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.ListAllAccountOperationsRequest{AccountId: id}
			return w.via(ctx, m("AccountService", "ListAllOperations"), req, func(c context.Context) (proto.Message, error) { return w.acc.ListAllOperations(c, req) })
		}, false},
		{m("AccessBindingService", "ListByAccount"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.ListAccessBindingsByAccountRequest{AccountId: id}
			return w.via(ctx, m("AccessBindingService", "ListByAccount"), req, func(c context.Context) (proto.Message, error) { return w.ab.ListByAccount(c, req) })
		}, false},
		{m("GroupService", "Create"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.CreateGroupRequest{AccountId: id, Name: w.name("grp")}
			return w.via(ctx, m("GroupService", "Create"), req, func(c context.Context) (proto.Message, error) { return w.grp.Create(c, req) })
		}, false},
		{m("MembershipService", "Create"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.CreateMembershipRequest{AccountId: id, Email: w.name("mbr") + "@example.invalid"}
			return w.via(ctx, m("MembershipService", "Create"), req, func(c context.Context) (proto.Message, error) { return w.mbr.Create(c, req) })
		}, false},
		{m("MembershipService", "Get"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.GetMembershipRequest{AccountId: id, MembershipId: "mbr-7m3k9q2x5v8b4n6t1"}
			return w.via(ctx, m("MembershipService", "Get"), req, func(c context.Context) (proto.Message, error) { return w.mbr.Get(c, req) })
		}, false},
		{m("MembershipService", "List"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.ListMembershipsRequest{AccountId: id}
			return w.via(ctx, m("MembershipService", "List"), req, func(c context.Context) (proto.Message, error) { return w.mbr.List(c, req) })
		}, false},
		{m("ProjectService", "Create"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.CreateProjectRequest{AccountId: id, Name: w.name("prj")}
			return w.via(ctx, m("ProjectService", "Create"), req, func(c context.Context) (proto.Message, error) { return w.prj.Create(c, req) })
		}, false},
		{m("RoleService", "Create"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.CreateRoleRequest{AccountId: id, Name: strings.ReplaceAll(w.name("rol"), "-", "_"),
				Rules: []*iamv1.Rule{{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}}}}
			return w.via(ctx, m("RoleService", "Create"), req, func(c context.Context) (proto.Message, error) { return w.rol.Create(c, req) })
		}, false},
		{m("ServiceAccountService", "Create"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.CreateServiceAccountRequest{AccountId: id, Name: w.name("sa")}
			return w.via(ctx, m("ServiceAccountService", "Create"), req, func(c context.Context) (proto.Message, error) { return w.sa.Create(c, req) })
		}, false},
		{m("UserService", "Invite"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.InviteUserRequest{AccountId: id, Email: w.name("inv") + "@example.invalid"}
			return w.via(ctx, m("UserService", "Invite"), req, func(c context.Context) (proto.Message, error) { return w.usr.Invite(c, req) })
		}, false},
		{m("UserService", "RemoveFromAccount"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.RemoveUserFromAccountRequest{UserId: string(w.member), AccountId: id}
			return w.via(ctx, m("UserService", "RemoveFromAccount"), req, func(c context.Context) (proto.Message, error) { return w.usr.RemoveFromAccount(c, req) })
		}, true},
		{m("UserService", "ResendInvite"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.ResendInviteRequest{UserId: string(w.member), AccountId: id}
			return w.via(ctx, m("UserService", "ResendInvite"), req, func(c context.Context) (proto.Message, error) { return w.usr.ResendInvite(c, req) })
		}, false},
		// дверь по объекту из resource_type / resource_id — 2
		{m("AccessBindingService", "ListByScope"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.ListAccessBindingsByScopeRequest{ResourceType: "account", ResourceId: id}
			return w.via(ctx, m("AccessBindingService", "ListByScope"), req, func(c context.Context) (proto.Message, error) { return w.ab.ListByScope(c, req) })
		}, false},
		{m("AccessBindingService", "ListAssignableRoles"), aid36ClassDoor, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.ListAssignableRolesRequest{ResourceType: "account", ResourceId: id}
			return w.via(ctx, m("AccessBindingService", "ListAssignableRoles"), req, func(c context.Context) (proto.Message, error) { return w.ab.ListAssignableRoles(c, req) })
		}, false},
		// обработчик — 2 (GrantDelegationService) + 1 (AccessBindingService/Create)
		{m("GrantDelegationService", "Create"), aid36ClassHandler, nil, false},
		{m("GrantDelegationService", "List"), aid36ClassHandler, nil, false},
		{m("AccessBindingService", "Create"), aid36ClassHandler, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			return w.grant(w.ab, ctx, "iam.account", id)
		}, false},
		// фильтр перечня — 6
		{m("AccessBindingService", "List"), aid36ClassFilter, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.ListAccessBindingsRequest{AccountId: id}
			return w.via(ctx, m("AccessBindingService", "List"), req, func(c context.Context) (proto.Message, error) { return w.ab.List(c, req) })
		}, false},
		{m("GroupService", "List"), aid36ClassFilter, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.ListGroupsRequest{AccountId: id}
			return w.via(ctx, m("GroupService", "List"), req, func(c context.Context) (proto.Message, error) { return w.grp.List(c, req) })
		}, false},
		{m("ProjectService", "List"), aid36ClassFilter, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.ListProjectsRequest{AccountId: id}
			return w.via(ctx, m("ProjectService", "List"), req, func(c context.Context) (proto.Message, error) { return w.prj.List(c, req) })
		}, false},
		{m("RoleService", "List"), aid36ClassFilter, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.ListRolesRequest{AccountId: id}
			return w.via(ctx, m("RoleService", "List"), req, func(c context.Context) (proto.Message, error) { return w.rol.List(c, req) })
		}, false},
		{m("ServiceAccountService", "List"), aid36ClassFilter, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.ListServiceAccountsRequest{AccountId: id}
			return w.via(ctx, m("ServiceAccountService", "List"), req, func(c context.Context) (proto.Message, error) { return w.sa.List(c, req) })
		}, false},
		{m("UserService", "List"), aid36ClassFilter, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.ListUsersRequest{AccountId: id}
			return w.via(ctx, m("UserService", "List"), req, func(c context.Context) (proto.Message, error) { return w.usr.List(c, req) })
		}, false},
		// только администратор облака — 2
		{m("InternalOperationsService", "ListIamOperations"), aid36ClassAdminOnly, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.ListIamOperationsRequest{AccountId: id}
			return w.via(ctx, m("InternalOperationsService", "ListIamOperations"), req, func(c context.Context) (proto.Message, error) { return w.iops.ListIamOperations(c, req) })
		}, false},
		{m("AccountService", "Create"), aid36ClassAdminOnly, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.CreateAccountRequest{Id: id, Name: w.name("acc")}
			return w.via(ctx, m("AccountService", "Create"), req, func(c context.Context) (proto.Message, error) { return w.acc.Create(c, req) })
		}, false},
		// только модель прав — 4
		{m("AuthorizeService", "Check"), aid36ClassModel, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := w.checkReq(ctx, id)
			return w.via(ctx, m("AuthorizeService", "Check"), req, func(c context.Context) (proto.Message, error) { return w.authz.Check(c, req) })
		}, false},
		{m("AuthorizeService", "BatchCheck"), aid36ClassModel, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.BatchAuthorizeCheckRequest{ScopeId: w.ownProject(ctx), Checks: []*iamv1.AuthorizeCheckRequest{w.checkReq(ctx, id)}}
			return w.via(ctx, m("AuthorizeService", "BatchCheck"), req, func(c context.Context) (proto.Message, error) { return w.authz.BatchCheck(c, req) })
		}, false},
		{m("AuthorizeService", "ListSubjects"), aid36ClassModel, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.ListSubjectsRequest{Resource: &iamv1.ResourceRef{Type: "account", Id: id}, Action: "iam.account.get"}
			return w.via(ctx, m("AuthorizeService", "ListSubjects"), req, func(c context.Context) (proto.Message, error) { return w.authz.ListSubjects(c, req) })
		}, false},
		{m("AuthorizeService", "ExpandRelations"), aid36ClassModel, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.ExpandRelationsRequest{Resource: &iamv1.ResourceRef{Type: "account", Id: id}, Relation: "viewer"}
			return w.via(ctx, m("AuthorizeService", "ExpandRelations"), req, func(c context.Context) (proto.Message, error) { return w.authz.ExpandRelations(c, req) })
		}, false},
		// ворота права выдачи под сокрытием — 1
		{m("AccessBindingService", "ExpandAccess"), aid36ClassGrantGate, func(w *aid36World, ctx context.Context, id string) (proto.Message, error) {
			req := &iamv1.ExpandAccessRequest{ObjectType: "account", ObjectId: id, Relation: "viewer"}
			return w.via(ctx, m("AccessBindingService", "ExpandAccess"), req, func(c context.Context) (proto.Message, error) { return w.ab.ExpandAccess(c, req) })
		}, false},
	}
}

// ownProject — проект, который вызывающий видит (дверь BatchCheck спрашивает
// `viewer` на проекте из `scope_id`): у H — Ph, у O — Pf. Одно различие близнеца
// — вызывающий, и область вопроса — его собственная.
func (w *aid36World) ownProject(ctx context.Context) string {
	if operations.PrincipalFromContext(ctx).ID == string(w.h) {
		return string(w.ph)
	}
	return string(w.pf)
}

// checkReq — вопрос о САМОМ вызывающем: subject — его принципал.
func (w *aid36World) checkReq(ctx context.Context, id string) *iamv1.AuthorizeCheckRequest {
	p := operations.PrincipalFromContext(ctx)
	return &iamv1.AuthorizeCheckRequest{Subject: "user:" + p.ID, Resource: &iamv1.ResourceRef{Type: "account", Id: id},
		Action: "iam.account.get", RequiredRelation: "viewer"}
}

// grant — создание привязки (системная роль просмотра члену мира) в области
// scopeType на идентификатор id.
func (w *aid36World) grant(h *accessbindingapp.Handler, ctx context.Context, scopeType, id string) (proto.Message, error) {
	req := &iamv1.CreateAccessBindingRequest{SubjectType: "user", SubjectId: string(w.member),
		RoleId: systemViewRole, ScopeType: scopeType, ScopeId: id,
		Target: &iamv1.AccessTarget{Target: &iamv1.AccessTarget_AllInScope{AllInScope: &iamv1.AccessTargetAllInScope{}}}}
	return w.via(ctx, m("AccessBindingService", "Create"), req, func(c context.Context) (proto.Message, error) { return h.Create(c, req) })
}

// ── перепись путей §1.11 ─────────────────────────────────────────────────────

// aid36Census — пути (полные имена методов) по трём предикатам §1.11 над
// `proto/kaname/cloud/iam/v1/*.proto` головы. Второе значение — число
// прочитанных файлов контракта.
func aid36Census(t *testing.T) (map[string]string, int) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "..", ".."))
	require.NoError(t, err)
	files, err := filepath.Glob(filepath.Join(root, "proto", "kaname", "cloud", "iam", "v1", "*.proto"))
	require.NoError(t, err)

	msgRe := regexp.MustCompile(`^message (\S+)`)
	svcRe := regexp.MustCompile(`^service (\S+)`)
	rpcRe := regexp.MustCompile(`^\s*rpc\s+(\w+)\s*\(\s*(stream\s+)?([\w.]+)\s*\)`)
	nameRe := regexp.MustCompile(`^[ \t]*string (account_id|scope_id|resource_id) = `)
	objRe := regexp.MustCompile(`^[ \t]+string (object|object_type|object_id|parent_account_id) = `)
	fieldRe := regexp.MustCompile(`^[ \t]+(repeated )?([A-Za-z.]+) [a-z_]+ = [0-9]+`)

	byName := map[string]string{}         // сообщение → предикат
	edges := map[string]map[string]bool{} // сообщение → типы полей
	rpcs := map[string][]string{}         // сообщение запроса → методы
	for _, f := range files {
		body, rerr := os.ReadFile(f)
		require.NoError(t, rerr)
		var msg, svc string
		for _, line := range strings.Split(string(body), "\n") {
			if mm := msgRe.FindStringSubmatch(line); mm != nil {
				msg = mm[1]
			}
			if sm := svcRe.FindStringSubmatch(line); sm != nil {
				svc = sm[1]
			}
			if rm := rpcRe.FindStringSubmatch(line); rm != nil && svc != "" {
				req := rm[3]
				req = req[strings.LastIndex(req, ".")+1:]
				rpcs[req] = append(rpcs[req], "/"+aid36Pkg+"."+svc+"/"+rm[1])
			}
			if msg == "" {
				continue
			}
			if nameRe.MatchString(line) {
				byName[msg] = "(1) по имени поля"
			}
			if objRe.MatchString(line) {
				byName[msg] = "(3) по полям объекта модели"
			}
			if fm := fieldRe.FindStringSubmatch(line); fm != nil {
				typ := fm[2]
				typ = typ[strings.LastIndex(typ, ".")+1:]
				if edges[msg] == nil {
					edges[msg] = map[string]bool{}
				}
				edges[msg][typ] = true
			}
		}
	}
	// (2) — замыкание до ResourceRef через поля, вложенные сообщения и
	// повторяемые элементы, до неподвижной точки.
	reach := map[string]bool{"ResourceRef": true}
	for changed := true; changed; {
		changed = false
		for from, tos := range edges {
			if reach[from] {
				continue
			}
			for to := range tos {
				if reach[to] {
					reach[from] = true
					changed = true
					break
				}
			}
		}
	}
	for msg := range reach {
		if _, ok := byName[msg]; !ok && msg != "ResourceRef" {
			byName[msg] = "(2) по типу поля"
		}
	}
	out := map[string]string{}
	for msg, pred := range byName {
		if !strings.HasSuffix(msg, "Request") {
			continue
		}
		for _, method := range rpcs[msg] {
			out[method] = pred + ": " + msg
		}
	}
	return out, len(files)
}

// ── проба ────────────────────────────────────────────────────────────────────

// TestAccountID36_EveryPathAnswersAStrangerOnce — AID-36.
func TestAccountID36_EveryPathAnswersAStrangerOnce(t *testing.T) {
	w := newAID36World(t)
	asH, asO, asA := asPrincipal(w.h), asPrincipal(w.o), asPrincipal(w.a)
	rows := aid36Rows()
	require.Len(t, rows, aid36RowsInAcceptance, "таблица пробы — не 34 строки переписи §1.11")

	// Контроль различимости на форме генератора — предпосылка: сравнение способно
	// увидеть разницу (A видит Fg и не видит Xa).
	get := rows[0]
	require.Equal(t, m("AccountService", "Get"), get.method)
	fgOut, fgErr := get.call(w, asA, string(w.fg))
	xaOut, xaErr := get.call(w, asA, w.xa)
	require.NoError(t, fgErr, "контроль мира AID-36: A не читает Fg")
	require.NotEqual(t, aid36Answer(fgOut, fgErr, string(w.fg)), aid36Answer(xaOut, xaErr, w.xa),
		"контроль мира AID-36: под A ответы на Fg и Xa равны — сравнение не видит разницы")

	// Перепись.
	census, files := aid36Census(t)
	require.Positive(t, files, "перепись не прочитала ни одного файла контракта")
	inTable := map[string]bool{}
	for _, r := range rows {
		inTable[r.method] = true
	}
	var unlisted, absent []string
	for method, why := range census {
		if !inTable[method] {
			if _, excluded := aid36Excluded[method]; !excluded {
				unlisted = append(unlisted, method+" ["+why+"]")
			}
		}
	}
	for _, r := range rows {
		if _, found := census[r.method]; !found && r.call == nil {
			absent = append(absent, r.method)
		}
	}
	sort.Strings(unlisted)
	sort.Strings(absent)
	t.Logf("перепись AID-36: файлов контракта %d · путей переписью %d · строк таблицы %d · исключений %d · "+
		"путь без строки %d %v · строк без RPC в дереве головы (не выполнилось) %d %v",
		files, len(census), len(rows), len(aid36Excluded), len(unlisted), unlisted, len(absent), absent)
	require.Empty(t, unlisted, "пути с идентификатором аккаунта без строки AID-36 и без исключения §1.11")

	// Предмет: один ответ постороннему на каждом пути и каждой форме.
	type pair struct{ existing, missing string }
	forms := []struct {
		name string
		ids  pair
	}{
		{"заданная форма", pair{aid36Foreign, aid36Absent}},
		{"форма генератора", pair{string(w.fg), w.xa}},
	}
	var executed, notExecuted int
	for _, r := range rows {
		if r.call == nil {
			notExecuted++
			t.Logf("НЕ ВЫПОЛНИЛОСЬ %s: RPC нет в дереве головы — ветка задачи не сведена со стволом (§1.0 приёмки)", r.method)
			continue
		}
		for _, f := range forms {
			t.Run(strings.TrimPrefix(r.method, "/"+aid36Pkg+".")+"/"+f.name, func(t *testing.T) {
				executed++
				outE, errE := r.call(w, asH, f.ids.existing)
				outM, errM := r.call(w, asH, f.ids.missing)
				ansE, ansM := aid36Answer(outE, errE, f.ids.existing), aid36Answer(outM, errM, f.ids.missing)
				require.NotEqual(t, codes.InvalidArgument, aid36Code(errE), "%s: путь судит форму, а не право: %s", r.method, ansE)
				require.NotEqual(t, codes.InvalidArgument, aid36Code(errM), "%s: путь судит форму, а не право: %s", r.method, ansM)
				require.Equal(t, ansE, ansM, "%s (%s): посторонний отличает «чужое» от «нет такого»", r.method, f.name)
				aid36RequireClassAnswer(t, r, outE, errE, f.ids.existing)
			})
		}
	}

	// Создание привязки в области проекта: Pf (чужой) и Pa (нет такого).
	t.Run("AccessBindingService/Create/область проекта", func(t *testing.T) {
		outE, errE := w.grant(w.ab, asH, "iam.project", string(w.pf))
		outM, errM := w.grant(w.ab, asH, "iam.project", w.pa)
		require.Equal(t, codes.PermissionDenied, aid36Code(errE), "%s", aid36Answer(outE, errE, string(w.pf)))
		require.Equal(t, aid36Answer(outE, errE, string(w.pf)), aid36Answer(outM, errM, w.pa),
			"создание привязки в области проекта отличает чужой проект от несуществующего")
	})

	// Неполадка хранилища отношений на создании привязки — UNAVAILABLE, не отказ права.
	t.Run("AccessBindingService/Create/неполадка хранилища", func(t *testing.T) {
		for _, f := range forms {
			outE, errE := w.grant(w.abBroken, asH, "iam.account", f.ids.existing)
			outM, errM := w.grant(w.abBroken, asH, "iam.account", f.ids.missing)
			for _, e := range []error{errE, errM} {
				st := status.Convert(e)
				require.Equal(t, codes.Unavailable, st.Code(), "%s: %s", f.name, aid36Answer(outE, e, f.ids.existing))
				require.Equal(t, "authz backend unavailable", st.Message())
			}
			require.Equal(t, aid36Answer(outE, errE, f.ids.existing), aid36Answer(outM, errM, f.ids.missing))
		}
	})

	// Контроль различимости на заданной форме: A видит F и не видит aid36-absent.
	t.Run("контроль различимости под A на заданной форме", func(t *testing.T) {
		outF, errF := get.call(w, asA, aid36Foreign)
		outX, errX := get.call(w, asA, aid36Absent)
		require.NoError(t, errF, "A не читает F: %s", aid36Answer(outF, errF, aid36Foreign))
		require.Equal(t, codes.NotFound, aid36Code(errX), "%s", aid36Answer(outX, errX, aid36Absent))
	})

	// Близнецы: тот же вызов на F под O (у путей только администратора — под A);
	// одно различие — вызывающий. Разрушающие — последними.
	var twinsLast []aid36Row
	for _, r := range rows {
		if r.call == nil {
			continue
		}
		if r.destructive {
			twinsLast = append(twinsLast, r)
			continue
		}
		aid36Twin(t, w, r, asO, asA)
	}
	for _, r := range twinsLast {
		aid36Twin(t, w, r, asO, asA)
	}
	t.Logf("AID-36: строк %d · исполнено пар %d · не выполнилось %d (RPC нет в дереве головы)",
		len(rows), executed, notExecuted)
}

// aid36RequireClassAnswer — ответ постороннему, который задаёт класс пути (Р15).
func aid36RequireClassAnswer(t *testing.T, r aid36Row, out proto.Message, err error, id string) {
	t.Helper()
	ans := aid36Answer(out, err, id)
	switch r.class {
	case aid36ClassHandler, aid36ClassGrantGate:
		st := status.Convert(err)
		require.Equal(t, codes.PermissionDenied, st.Code(), "%s: %s", r.method, ans)
		require.Equal(t, "permission denied", st.Message(), "%s", r.method)
	case aid36ClassFilter:
		// Фильтр перечня сужает выдачу построчно: строк присланного аккаунта в
		// ответе нет. Приёмка называет ответ «пустая страница»; `RoleService/List`
		// отдаёт постороннему и системные роли, не принадлежащие ни одному
		// аккаунту, поэтому утверждается отсутствие строк аккаунта, а не пустота.
		require.NoError(t, err, "%s: фильтр перечня ответил отказом: %s", r.method, ans)
		require.NotContains(t, ans, aid36Mask, "%s: посторонний видит строки чужого аккаунта: %s", r.method, ans)
		t.Logf("%s: ответ фильтра постороннему: %.300s", r.method, ans)
	case aid36ClassModel:
		switch r.method {
		case m("AuthorizeService", "Check"):
			require.NoError(t, err, "%s: %s", r.method, ans)
			require.False(t, out.(*iamv1.AuthorizeCheckResponse).GetAllowed(), "%s: посторонний получил allowed", r.method)
		case m("AuthorizeService", "BatchCheck"):
			require.NoError(t, err, "%s: %s", r.method, ans)
			resps := out.(*iamv1.BatchAuthorizeCheckResponse).GetResponses()
			require.Len(t, resps, 1, "%s: ответов не по числу вопросов", r.method)
			for _, res := range resps {
				require.False(t, res.GetAllowed(), "%s: посторонний получил allowed", r.method)
			}
		default:
			st := status.Convert(err)
			require.Equal(t, codes.PermissionDenied, st.Code(), "%s: %s", r.method, ans)
			require.Equal(t, "permission denied", st.Message(), "%s", r.method)
		}
	case aid36ClassDoor:
		if r.method == m("AccountService", "Get") {
			st := status.Convert(err)
			require.Equal(t, codes.NotFound, st.Code(), "%s: %s", r.method, ans)
			require.Equal(t, "Account "+id+" not found", st.Message(), "%s", r.method)
		}
	}
}

// aid36Twin — близнец строки на F: ответ не отказ права и не отсутствие аккаунта.
func aid36Twin(t *testing.T, w *aid36World, r aid36Row, asO, asA context.Context) {
	t.Helper()
	t.Run("близнец/"+strings.TrimPrefix(r.method, "/"+aid36Pkg+"."), func(t *testing.T) {
		ctx := asO
		if r.class == aid36ClassAdminOnly {
			ctx = asA
		}
		out, err := r.call(w, ctx, aid36Foreign)
		ans := aid36Answer(out, err, aid36Foreign)
		t.Logf("%s: ответ близнецу: %.300s", r.method, ans)
		require.NotEqual(t, codes.PermissionDenied, aid36Code(err), "%s: близнец получил отказ права: %s", r.method, ans)
		st := status.Convert(err)
		if st.Code() == codes.NotFound {
			require.NotEqual(t, "Account "+aid36Foreign+" not found", st.Message(), "%s: близнец не видит аккаунт", r.method)
		}
		// Отказ формы — не ответ о праве и существовании: путь, не принявший F,
		// близнецом строки не служит.
		if st.Code() == codes.InvalidArgument {
			require.False(t, strings.HasPrefix(st.Message(), "invalid account id "),
				"%s: близнец отвергнут формой идентификатора аккаунта: %s", r.method, ans)
		}
		switch r.method {
		case m("AuthorizeService", "Check"):
			require.NoError(t, err, "%s: %s", r.method, ans)
			require.True(t, out.(*iamv1.AuthorizeCheckResponse).GetAllowed(), "%s: владелец O не получил allowed о себе", r.method)
		case m("AuthorizeService", "ListSubjects"), m("AuthorizeService", "ExpandRelations"), m("AccessBindingService", "ExpandAccess"):
			require.NoError(t, err, "%s: %s", r.method, ans)
			require.Contains(t, ans, string(w.o), "%s: в ответе близнеца нет владельца O", r.method)
		}
	})
}
