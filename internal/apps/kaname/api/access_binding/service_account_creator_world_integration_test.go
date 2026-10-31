// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// service_account_creator_world_integration_test.go — мир С приёмки
// docs/engineering/acceptance/service-account-creation-is-its-own-right.md
// (редакция 3, отпечаток cd31c47cb19dea4163a70a4e181545c2462e0ef0a62d5f330a23f66fe14bc08f,
// вердикт APPROVED; задача PRO-Robotech/kaname#1003).
//
// # Что здесь лежит
//
// Мир С (§4.1 приёмки) и его глаголы. Пробы групп A…E лежат в соседних файлах
// `service_account_creator_*_integration_test.go`, каждая называется
// `TestServiceAccountCreator_SAC<NN>_…` — один сценарий, одна проба.
//
// # Основа мира — мир Д, а не голый П6, и почему
//
// Приёмка строит мир С поверх П6 (`newPCRWorld`). Мир Д (`newGDWorld`) — тот же
// П6 плюс ровно то «Дано», которое мир С заказывает: аккаунт модуля acc-S с
// учётками sva-iss и sva-iss2, проект prj-A2, авто-выдача владельца usr-A на
// acc-A и положительные контроли посева. Брать его — не второй посев рядом с
// первым, а тот же посев, уже доказанный своими контролями. Сверх него мир С
// заводит только своё: sva-adm, администратора облака usr-R, учётку sva-A2,
// созданную человеком, роль аккаунта rol-own, дверь слушателя с окном 1 с.
//
// # Методы, которые судит ДВЕРЬ, зовутся только через дверь
//
// Глаголы учётки, ключа, проекта, группы и роли решает дверь слушателя
// (аннотации контракта), а не use-case. Мир собирает её тем же конструктором,
// что корень службы (`authzguard.NewOwnDoor`), над той же дверью решения, что
// мир П1 (`authzcascade.WrapAdmitted(relverdict.NewAsker(pool), personmarks.New(pool))`),
// с окном положительного вердикта 1 с. Проба, зовущая обработчик мимо двери,
// судила бы путь, которого у вызывающего нет. Выдачу (`AccessBindingService`)
// судит её обработчик, и её мир зовёт прямо, как мир Д.
//
// # Порядок каждой пробы несущий
//
//  1. мир и его положительные контроли (`newSACWorld`) — сломанный посев
//     краснеет здесь, называя контроль;
//  2. проба возможностей (`requireCreatorRole`): «Дано» с ролью C на стволе до
//     изменения НЕ СТРОИТСЯ, и проба кончается строкой «НЕ ВЫПОЛНИЛОСЬ», а не
//     утверждением о поведении (DoD S1 п.6 приёмки);
//  3. тело сценария.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	groupapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	sakeysapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/sa_keys"
	serviceaccountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/service_account"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest/roleexport"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/servicemanifest"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Координаты предмета приёмки.
const (
	// sacCreatorRoleName — роль создателя C (Р2).
	sacCreatorRoleName = "iam.service_account.creator"
	// sacAdminRoleName — роль SAA, есть до изменения.
	sacAdminRoleName = "iam.service_account.admin"
	// sacCreatorRelation — отношение аккаунта, которое даёт правило 1 роли C (Р1).
	sacCreatorRelation = "service_account_creator"
	// sacDoorTTL — окно положительного вердикта двери мира (§4.1).
	sacDoorTTL = time.Second
	// sacSAModelType — тип учётки в словаре модели прав.
	sacSAModelType = "iam_service_account"
	// sacCreatedByJSON — имя поля правила на крае (Р2а, `Rule.created_by_subject`).
	sacCreatedByJSON = "createdBySubject"
)

// Полные имена методов слушателя — ключ записи каталога, по которой судит дверь.
const (
	sacMethodSACreate  = "/kaname.cloud.iam.v1.ServiceAccountService/Create"
	sacMethodSAGet     = "/kaname.cloud.iam.v1.ServiceAccountService/Get"
	sacMethodSAUpdate  = "/kaname.cloud.iam.v1.ServiceAccountService/Update"
	sacMethodSADelete  = "/kaname.cloud.iam.v1.ServiceAccountService/Delete"
	sacMethodSADisable = "/kaname.cloud.iam.v1.ServiceAccountService/Disable"
	sacMethodSAEnable  = "/kaname.cloud.iam.v1.ServiceAccountService/Enable"
	sacMethodSAList    = "/kaname.cloud.iam.v1.ServiceAccountService/List"
	sacMethodKeyIssue  = "/kaname.cloud.iam.v1.SAKeyService/Issue"
	sacMethodKeyList   = "/kaname.cloud.iam.v1.SAKeyService/List"
	sacMethodKeyRevoke = "/kaname.cloud.iam.v1.SAKeyService/Revoke"
	sacMethodPrjCreate = "/kaname.cloud.iam.v1.ProjectService/Create"
	sacMethodPrjUpdate = "/kaname.cloud.iam.v1.ProjectService/Update"
	sacMethodPrjDelete = "/kaname.cloud.iam.v1.ProjectService/Delete"
	sacMethodGrpCreate = "/kaname.cloud.iam.v1.GroupService/Create"
	sacMethodGrpUpdate = "/kaname.cloud.iam.v1.GroupService/Update"
	sacMethodGrpAdd    = "/kaname.cloud.iam.v1.GroupService/AddMember"
	sacMethodGrpDelete = "/kaname.cloud.iam.v1.GroupService/Delete"
	sacMethodRolCreate = "/kaname.cloud.iam.v1.RoleService/Create"
	sacMethodRolUpdate = "/kaname.cloud.iam.v1.RoleService/Update"
	sacMethodRolDelete = "/kaname.cloud.iam.v1.RoleService/Delete"
	sacMethodRolList   = "/kaname.cloud.iam.v1.RoleService/List"
)

// sacWorld — мир С одной базы.
type sacWorld struct {
	*gdWorld

	// door — дверь слушателя мира: ОДНА на мир, с окном вердикта sacDoorTTL, —
	// как в корне службы, где кеш вердиктов общий для всех вызовов процесса.
	door grpc.UnaryServerInterceptor

	usrR   domain.UserID
	svaAdm string
	// sacA2 — учётка sva-A2 в acc-A, созданная человеком usr-A глаголом (создатель — usr-A).
	sacA2 string
	// rolOwn — роль аккаунта acc-A с правилом {iam, [project], [get]}.
	rolOwn domain.RoleID
	// rolC — роль создателя (ноль, пока её нет в базе); rolSAA — роль SAA; rolView —
	// каноническая `view`.
	rolC, rolSAA, rolView domain.RoleID

	sax   *serviceaccountapp.Handler
	keys  *sakeysapp.Handler
	prjx  *projectapp.Handler
	grpx  *groupapp.Handler
	rolex *roleapp.Handler
}

// newSACWorld поднимает мир С и доказывает живость посева положительными
// контролями. Роль C не трогает: проба возможностей — `requireCreatorRole`.
func newSACWorld(t *testing.T) *sacWorld {
	t.Helper()
	g := newGDWorld(t)
	w := &sacWorld{gdWorld: g}
	ctx, pool := g.ctx, g.pool

	// Дверь слушателя над дверью решения мира, окно вердикта — 1 с (§4.1).
	door, err := authzguard.NewOwnDoor(authzguard.OwnDoorOptions{SelfCheck: g.door, PositiveTTL: sacDoorTTL})
	require.NoError(t, err, "мир С: дверь слушателя не собралась")
	w.door = door.Unary()
	t.Logf("мир С: окно положительного вердикта двери — %s", sacDoorTTL)

	// Учётка sva-adm в аккаунте модуля acc-S.
	w.svaAdm = seedServiceAccount(t, ctx, pool, g.accS, "sva-sac-adm")
	// Администратор облака usr-R и его живая сессия.
	w.usrR = mustSeedUser(t, ctx, pool, "sacr")
	verifyAddresses(t, ctx, pool)
	seedClusterAdmin(t, ctx, pool, w.usrR)
	// Назначение администратора облака держит свой прямой факт
	// `cluster:cluster_root#system_admin` — его кладёт путь назначения строкой
	// журнала; посев мира повторяет оба шага (образец — SD-919-C).
	gdSeedTuple(t, ctx, pool, "user:"+string(w.usrR), "system_admin", "cluster:"+domain.ClusterSingletonID)
	seedLiveHumanSession(t, g.scWorld, w.usrR)

	// Роли своего манифеста службы — тем путём, что старт (`cmd/kaname`,
	// `applyImageModuleRoles`): роль C объявлена встроенным манифестом iam и
	// заводится применителем ролей, а не миграцией (§4.1, «посев ролей модуля при
	// старте»). Затем — самолечение старта: селекторы и проекция глаголов.
	w.applyImageRoles()

	w.buildSACHandlers()

	w.rolSAA = w.roleByName(sacAdminRoleName)
	w.rolView = w.roleByName("view")
	w.rolC = w.roleByNameOrZero(sacCreatorRoleName)

	// Роль аккаунта rol-own — глаголом от usr-A, до `done`.
	w.rolOwn = w.createRoleDone(asUser(ctx, g.usrA), &iamv1.CreateRoleRequest{
		AccountId: string(g.accA),
		Name:      "rol_own_" + ids6(t),
		Rules:     []*iamv1.Rule{{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}}},
	}, "мир С: роль аккаунта rol-own")

	// Учётка sva-A2 — глаголом от usr-A, до `done`; создатель — usr-A (Р4).
	w.sacA2 = w.createSADone(asUser(ctx, g.usrA), string(g.accA), "sva-a2-"+strings.ToLower(ids6(t)),
		"мир С: учётка sva-A2 от usr-A")

	// ── положительные контроли посева ──────────────────────────────────────
	// usr-A — владелец acc-A: ведёт учётки аккаунта и создаёт их (editor).
	w.pollRelation("user:"+string(g.usrA), "editor", "account:"+string(g.accA), true,
		"контроль мира С: usr-A держит editor на acc-A")
	w.pollRelation("user:"+string(g.usrA), "v_update", sacSAModelType+":"+w.sacA2, true,
		"контроль мира С: usr-A держит v_update на sva-A2 (каскад владельца)")
	// usr-R — администратор облака: держит system_admin на кластере.
	w.pollRelation("user:"+string(w.usrR), "system_admin", "cluster:"+domain.ClusterSingletonID, true,
		"контроль мира С: usr-R — администратор облака")
	// Учётки acc-S прав в acc-A не держат.
	for _, sva := range []string{g.svaIss, g.svaIss2, w.svaAdm} {
		w.requireRelation("service_account:"+sva, "editor", "account:"+string(g.accA), false,
			"контроль мира С: учётка acc-S без editor на acc-A")
	}
	return w
}

// ids6 — шесть знаков, различающих имена объектов прогона.
func ids6(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
}

// buildSACHandlers — use-case'ы мира С теми же частями, что корень службы
// (`cmd/kaname/wiring.go`), с каталожным фактом последней доставки мира.
func (w *sacWorld) buildSACHandlers() {
	w.t.Helper()
	src := catalog.Fixed{F: w.facts}
	repo, ops, door := w.repo, w.ops, w.gdWorld.door

	w.sax = serviceaccountapp.NewHandler(
		serviceaccountapp.NewCreateServiceAccountUseCase(repo, ops).
			WithRelationStore(door, nil).WithObjectReconciler(w.rec),
		serviceaccountapp.NewUpdateServiceAccountUseCase(repo, ops).WithObjectReconciler(w.rec, nil),
		serviceaccountapp.NewDeleteServiceAccountUseCase(repo, ops),
		serviceaccountapp.NewGetServiceAccountUseCase(repo).WithRelationStore(door),
		serviceaccountapp.NewListServiceAccountsUseCase(repo).WithRelationStore(door),
		serviceaccountapp.NewDisableServiceAccountUseCase(repo, ops),
		serviceaccountapp.NewEnableServiceAccountUseCase(repo, ops),
	)
	keyRepo := kanamepg.NewSAOAuthClientRepo(w.pool)
	issue := sakeysapp.NewIssueSAKeyUseCase(keyRepo, kanamepg.NewPoolTxBeginner(w.pool), ops).WithOwnIssuance()
	issue.WithAuditEmitter(kanamepg.NewAuditOutboxEmitter(w.pool))
	revoke := sakeysapp.NewRevokeSAKeyUseCase(keyRepo, kanamepg.NewPoolTxBeginner(w.pool), ops)
	revoke.WithAuditEmitter(kanamepg.NewAuditOutboxEmitter(w.pool))
	w.keys = sakeysapp.NewHandler(issue, revoke, sakeysapp.NewListSAKeysUseCase(keyRepo))

	w.prjx = projectapp.NewHandler(
		projectapp.NewCreateProjectUseCase(repo, ops).WithRelationStore(door, nil),
		projectapp.NewUpdateProjectUseCase(repo, ops).WithRelationStore(door, nil),
		projectapp.NewDeleteProjectUseCase(repo, ops), nil, nil)
	w.grpx = groupapp.NewHandler(
		groupapp.NewCreateGroupUseCase(repo, ops).WithRelationStore(door, nil),
		groupapp.NewUpdateGroupUseCase(repo, ops),
		groupapp.NewDeleteGroupUseCase(repo, ops), nil, nil,
		groupapp.NewAddMemberUseCase(repo, ops).
			WithGrantAuthority(accessbindingapp.NewScopeGrantAuthority(repo, door)), nil, nil)
	w.rolex = roleapp.NewHandler(
		roleapp.NewCreateRoleUseCase(repo, ops, src).WithRelationStore(door, nil),
		roleapp.NewUpdateRoleUseCase(repo, ops, src).
			WithGrantAuthority(accessbindingapp.NewScopeGrantAuthority(repo, door)),
		roleapp.NewDeleteRoleUseCase(repo, ops),
		roleapp.NewGetRoleUseCase(repo, src),
		roleapp.NewListRolesUseCase(repo, src).WithRelationStore(door))
}

// roleByNameOrZero — id системной роли по имени либо ноль, если строки нет.
func (w *sacWorld) roleByNameOrZero(name string) domain.RoleID {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.roles WHERE name = $1 AND account_id IS NULL AND project_id IS NULL`, name).Scan(&n))
	if n == 0 {
		return ""
	}
	return w.roleByName(name)
}

// requireCreatorRole — проба возможностей: роль C есть в базе. Без неё «Дано»
// сценария не строится, и проба кончается «НЕ ВЫПОЛНИЛОСЬ», а не красным
// утверждением о поведении (DoD S1 п.6).
func (w *sacWorld) requireCreatorRole(sc string) {
	w.t.Helper()
	if w.rolC == "" {
		w.t.Fatalf("%s: НЕ ВЫПОЛНИЛОСЬ — «Дано» не строится: роли %s нет среди системных ролей базы "+
			"(посев ролей модуля iam её не заводит; ПРЕДМЕТА НЕТ — Р2 приёмки)", sc, sacCreatorRoleName)
	}
}

// ── дверь ─────────────────────────────────────────────────────────────────

// viaSACDoor — вызов метода через дверь слушателя мира; отдаёт ответ обработчика
// либо отказ (двери или обработчика) и признак, достигнут ли обработчик.
func (w *sacWorld) viaSACDoor(ctx context.Context, fullMethod string, req any,
	call func(ctx context.Context) (any, error)) (any, bool, error) {
	w.t.Helper()
	reached := false
	out, err := w.door(ctx, req, &grpc.UnaryServerInfo{FullMethod: fullMethod},
		func(ctx context.Context, _ any) (any, error) {
			reached = true
			return call(ctx)
		})
	return out, reached, err
}

// sacOp — исход мутации через дверь: синхронный отказ либо операция до `done`.
type sacOp struct {
	syncErr error
	reached bool
	opID    string
	done    *operations.Operation
	opErr   *status.Status
}

// mutate — мутация через дверь, доведённая до `done`.
func (w *sacWorld) mutate(ctx context.Context, fullMethod string, req proto.Message,
	call func(ctx context.Context) (*operationpb.Operation, error)) sacOp {
	w.t.Helper()
	out, reached, err := w.viaSACDoor(ctx, fullMethod, req, func(ctx context.Context) (any, error) {
		return call(ctx)
	})
	if err != nil {
		return sacOp{syncErr: err, reached: reached}
	}
	op, ok := out.(*operationpb.Operation)
	require.Truef(w.t, ok, "%s: ответ не Operation (%T)", fullMethod, out)
	res := sacOp{reached: reached, opID: op.GetId()}
	done := awaitOp(w.t, w.ctx, w.ops, op.GetId())
	if done.Error != nil {
		res.opErr = status.New(codes.Code(done.Error.Code), done.Error.Message)
	}
	res.done = done
	return res
}

// requireDone — операция `done` без ошибки.
func requireSACDone(t *testing.T, o sacOp, why string) {
	t.Helper()
	require.NoErrorf(t, o.syncErr, "%s: синхронный отказ", why)
	require.Nilf(t, o.opErr, "%s: операция завершилась ошибкой", why)
}

// requireSACDenied — синхронный `PERMISSION_DENIED` `permission denied`, операции нет.
func requireSACDenied(t *testing.T, o sacOp, why string) {
	t.Helper()
	require.Emptyf(t, o.opID, "%s: синхронного отказа нет, заведена операция (ошибка операции %v)", why, o.opErr)
	requireSyncRefusal(t, o.syncErr, codes.PermissionDenied, "permission denied", why)
}

// ── учётки ────────────────────────────────────────────────────────────────

// saCreate — `ServiceAccountService.Create` через дверь.
func (w *sacWorld) saCreate(ctx context.Context, acc, name string) sacOp {
	req := &iamv1.CreateServiceAccountRequest{AccountId: acc, Name: name}
	return w.mutate(ctx, sacMethodSACreate, req, func(ctx context.Context) (*operationpb.Operation, error) {
		return w.sax.Create(ctx, req)
	})
}

// createdSAID — id учётки из метаданных операции создания.
func (w *sacWorld) createdSAID(o sacOp) string {
	w.t.Helper()
	require.NotNil(w.t, o.done, "операция создания учётки не доведена")
	var md iamv1.CreateServiceAccountMetadata
	require.NoError(w.t, o.done.Metadata.UnmarshalTo(&md), "метаданные операции создания учётки")
	require.NotEmpty(w.t, md.GetServiceAccountId(), "id учётки не назван метаданными")
	return md.GetServiceAccountId()
}

// createSADone — учётка создана до `done` без ошибки; отдаёт её id.
func (w *sacWorld) createSADone(ctx context.Context, acc, name, why string) string {
	w.t.Helper()
	o := w.saCreate(ctx, acc, name)
	requireSACDone(w.t, o, why)
	return w.createdSAID(o)
}

func (w *sacWorld) saGet(ctx context.Context, id string) (*iamv1.ServiceAccount, error) {
	req := &iamv1.GetServiceAccountRequest{ServiceAccountId: id}
	out, _, err := w.viaSACDoor(ctx, sacMethodSAGet, req, func(ctx context.Context) (any, error) {
		return w.sax.Get(ctx, req)
	})
	if err != nil {
		return nil, err
	}
	return out.(*iamv1.ServiceAccount), nil
}

func (w *sacWorld) saUpdateLabels(ctx context.Context, id string, labels map[string]string) sacOp {
	req := &iamv1.UpdateServiceAccountRequest{
		ServiceAccountId: id,
		UpdateMask:       &fieldmaskpb.FieldMask{Paths: []string{"labels"}},
		Labels:           labels,
	}
	return w.mutate(ctx, sacMethodSAUpdate, req, func(ctx context.Context) (*operationpb.Operation, error) {
		return w.sax.Update(ctx, req)
	})
}

func (w *sacWorld) saDisable(ctx context.Context, id string) sacOp {
	req := &iamv1.DisableServiceAccountRequest{ServiceAccountId: id}
	return w.mutate(ctx, sacMethodSADisable, req, func(ctx context.Context) (*operationpb.Operation, error) {
		return w.sax.Disable(ctx, req)
	})
}

func (w *sacWorld) saEnable(ctx context.Context, id string) sacOp {
	req := &iamv1.EnableServiceAccountRequest{ServiceAccountId: id}
	return w.mutate(ctx, sacMethodSAEnable, req, func(ctx context.Context) (*operationpb.Operation, error) {
		return w.sax.Enable(ctx, req)
	})
}

func (w *sacWorld) saDelete(ctx context.Context, id string) sacOp {
	req := &iamv1.DeleteServiceAccountRequest{ServiceAccountId: id}
	return w.mutate(ctx, sacMethodSADelete, req, func(ctx context.Context) (*operationpb.Operation, error) {
		return w.sax.Delete(ctx, req)
	})
}

// saList — все строки `ServiceAccountService.List` по аккаунту через дверь.
func (w *sacWorld) saList(ctx context.Context, acc string) []string {
	w.t.Helper()
	var out []string
	token := ""
	for page := 0; page < 100; page++ {
		req := &iamv1.ListServiceAccountsRequest{AccountId: acc, PageSize: 1000, PageToken: token}
		resp, _, err := w.viaSACDoor(ctx, sacMethodSAList, req, func(ctx context.Context) (any, error) {
			return w.sax.List(ctx, req)
		})
		require.NoErrorf(w.t, err, "List учёток аккаунта %s", acc)
		lr := resp.(*iamv1.ListServiceAccountsResponse)
		for _, sa := range lr.GetServiceAccounts() {
			out = append(out, sa.GetId())
		}
		token = lr.GetNextPageToken()
		if token == "" {
			return out
		}
	}
	w.t.Fatalf("List учёток аккаунта %s: 100 страниц без конца", acc)
	return nil
}

// saCensus — число учёток аккаунта строками базы (перепись «до = после»).
func (w *sacWorld) saCensus(acc domain.AccountID) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.service_accounts WHERE account_id = $1`, string(acc)).Scan(&n))
	return n
}

// ── ключи ─────────────────────────────────────────────────────────────────

func (w *sacWorld) keyIssue(ctx context.Context, sva string) sacOp {
	req := &iamv1.IssueSAKeyRequest{ServiceAccountId: sva}
	return w.mutate(ctx, sacMethodKeyIssue, req, func(ctx context.Context) (*operationpb.Operation, error) {
		return w.keys.Issue(ctx, req)
	})
}

// issuedKeyID — id ключа из метаданных операции выпуска.
func (w *sacWorld) issuedKeyID(o sacOp) string {
	w.t.Helper()
	require.NotNil(w.t, o.done, "операция выпуска ключа не доведена")
	var md iamv1.IssueSAKeyMetadata
	require.NoError(w.t, o.done.Metadata.UnmarshalTo(&md), "метаданные выпуска ключа")
	require.NotEmpty(w.t, md.GetKeyId(), "id ключа не назван метаданными")
	return md.GetKeyId()
}

func (w *sacWorld) keyRevoke(ctx context.Context, sva, key string) sacOp {
	req := &iamv1.RevokeSAKeyRequest{ServiceAccountId: sva, KeyId: key}
	return w.mutate(ctx, sacMethodKeyRevoke, req, func(ctx context.Context) (*operationpb.Operation, error) {
		return w.keys.Revoke(ctx, req)
	})
}

// keyList — действующие ключи учётки через дверь.
func (w *sacWorld) keyList(ctx context.Context, sva string) ([]string, error) {
	req := &iamv1.ListSAKeysRequest{ServiceAccountId: sva, PageSize: 1000}
	out, _, err := w.viaSACDoor(ctx, sacMethodKeyList, req, func(ctx context.Context) (any, error) {
		return w.keys.List(ctx, req)
	})
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, k := range out.(*iamv1.ListSAKeysResponse).GetKeys() {
		ids = append(ids, k.GetId())
	}
	return ids, nil
}

// keyCensus — число ключей учётки строками базы (отзыв строку снимает).
func (w *sacWorld) keyCensus(sva string) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.service_account_oauth_clients WHERE sva_id = $1`,
		sva).Scan(&n))
	return n
}

// ── роли ──────────────────────────────────────────────────────────────────

// createRoleDone — роль создана глаголом до `done`; отдаёт её id.
func (w *sacWorld) createRoleDone(ctx context.Context, req *iamv1.CreateRoleRequest, why string) domain.RoleID {
	w.t.Helper()
	o := w.mutate(ctx, sacMethodRolCreate, req, func(ctx context.Context) (*operationpb.Operation, error) {
		return w.rolex.Create(ctx, req)
	})
	requireSACDone(w.t, o, why)
	var md iamv1.CreateRoleMetadata
	require.NoError(w.t, o.done.Metadata.UnmarshalTo(&md), "%s: метаданные операции", why)
	require.NotEmptyf(w.t, md.GetRoleId(), "%s: id роли не назван", why)
	return domain.RoleID(md.GetRoleId())
}

// roleFromJSON — тело запроса роли из JSON края (`protojson`). Неизвестный
// контракту ключ ОТБРАСЫВАЕТСЯ, а не отвергается: до изменения поля
// `createdBySubject` в контракте нет, и проба обязана исполниться, чтобы показать,
// что вход с ним принят молча — это и есть красное SAC-40 d на стволе.
func roleFromJSON(t *testing.T, body string, into proto.Message) {
	t.Helper()
	require.NoErrorf(t, protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal([]byte(body), into),
		"тело роли не разбирается: %s", body)
}

// roleRulesJSON — правила роли формой края (`protojson`, имена — json_name).
func roleRulesJSON(t *testing.T, r *iamv1.Role) []map[string]any {
	t.Helper()
	raw, err := protojson.Marshal(r)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	var out []map[string]any
	rules, _ := m["rules"].([]any)
	for _, it := range rules {
		rm, ok := it.(map[string]any)
		require.Truef(t, ok, "правило роли — не объект: %v", it)
		out = append(out, rm)
	}
	return out
}

// listRoleByName — роль из `RoleService.List` от вызывающего, по имени.
func (w *sacWorld) listRoleByName(ctx context.Context, name string) *iamv1.Role {
	w.t.Helper()
	token := ""
	for page := 0; page < 100; page++ {
		req := &iamv1.ListRolesRequest{AccountId: string(w.accA), PageSize: 1000, PageToken: token}
		out, _, err := w.viaSACDoor(ctx, sacMethodRolList, req, func(ctx context.Context) (any, error) {
			return w.rolex.List(ctx, req)
		})
		require.NoError(w.t, err, "RoleService.List")
		lr := out.(*iamv1.ListRolesResponse)
		for _, r := range lr.GetRoles() {
			if r.GetName() == name {
				return r
			}
		}
		token = lr.GetNextPageToken()
		if token == "" {
			break
		}
	}
	return nil
}

// roleRules — правила роли строкой базы (для «правила прежние»).
func (w *sacWorld) roleRules(id domain.RoleID) string {
	w.t.Helper()
	var raw string
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT rules::text FROM kaname.roles WHERE id = $1`, string(id)).Scan(&raw))
	return raw
}

// ── выдача роли C ─────────────────────────────────────────────────────────

// gC — тело выдачи G (§4.1): роль C, область `iam.account` acc-A, субъекты, цель allInScope.
func (w *sacWorld) gC(subjects ...string) *iamv1.CreateAccessBindingRequest {
	subs := make([]*iamv1.Subject, 0, len(subjects))
	for _, s := range subjects {
		subs = append(subs, svaSubject(s))
	}
	return &iamv1.CreateAccessBindingRequest{
		Subjects:  subs,
		RoleId:    string(w.rolC),
		ScopeType: "iam.account",
		ScopeId:   string(w.accA),
		Target:    allInScopeTarget(),
	}
}

// grantC — выдача роли C от usr-A до `done`; затем опрос права создавать по
// каждому субъекту (§4.1). Отдаёт id выдачи.
func (w *sacWorld) grantC(why string, subjects ...string) string {
	w.t.Helper()
	id := w.createDoneX(asUser(w.ctx, w.usrA), w.gC(subjects...), why)
	for _, s := range subjects {
		w.pollRelation("service_account:"+s, sacCreatorRelation, "account:"+string(w.accA), true,
			why+": право создавать у "+s)
	}
	return id
}

// creatorBindings — действующих выдач роли C в acc-A (строки базы).
func (w *sacWorld) creatorBindings() int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `
		SELECT count(*) FROM kaname.access_bindings
		 WHERE role_id = $1 AND resource_type = 'account' AND resource_id = $2 AND status = 'ACTIVE'`,
		string(w.rolC), string(w.accA)).Scan(&n))
	return n
}

// awaitDoorWindow — выжидает окно вердикта двери мира: положительный ответ,
// закешированный до конца выдачи, после этого не действует.
func (w *sacWorld) awaitDoorWindow() {
	time.Sleep(sacDoorTTL + 200*time.Millisecond)
}

// reconcileQueueEmpty — очередь событий реконсайла мира пуста (§4.1).
func (w *sacWorld) reconcileQueueEmpty() int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.resource_reconcile_outbox WHERE sent_at IS NULL`).Scan(&n))
	return n
}

// drainReconcile — реконсайлер мира дренирует очередь событий: каждое событие
// проходит полным проходом по объекту, как у работника корня службы, и
// помечается отправленным. Отдаёт число обработанных событий.
func (w *sacWorld) drainReconcile() int {
	w.t.Helper()
	type evt struct {
		id       int64
		typ, oid string
	}
	done := 0
	for round := 0; round < 50; round++ {
		rows, err := w.pool.Query(w.ctx, `
			SELECT id, object_type, object_id FROM kaname.resource_reconcile_outbox
			 WHERE sent_at IS NULL ORDER BY id LIMIT 500`)
		require.NoError(w.t, err)
		var batch []evt
		for rows.Next() {
			var e evt
			require.NoError(w.t, rows.Scan(&e.id, &e.typ, &e.oid))
			batch = append(batch, e)
		}
		rows.Close()
		require.NoError(w.t, rows.Err())
		if len(batch) == 0 {
			return done
		}
		for _, e := range batch {
			require.NoErrorf(w.t, w.rec.ReconcileObject(w.ctx, e.typ, e.oid),
				"дренаж реконсайла: событие %d (%s:%s)", e.id, e.typ, e.oid)
			_, err := w.pool.Exec(w.ctx, `UPDATE kaname.resource_reconcile_outbox SET sent_at = now() WHERE id = $1`, e.id)
			require.NoError(w.t, err)
			done++
		}
	}
	w.t.Fatalf("дренаж реконсайла: 50 кругов без пустой очереди (обработано %d)", done)
	return done
}

// revokeDone — `AccessBindingService.Revoke` от вызывающего до `done`.
func (w *sacWorld) revokeDone(ctx context.Context, id, why string) {
	w.t.Helper()
	op, err := w.revokeBinding(ctx, id)
	w.requireOpDone(op, err, why)
}

// deleteBindingDone — `AccessBindingService.Delete` от вызывающего до `done`.
func (w *sacWorld) deleteBindingDone(ctx context.Context, id, why string) {
	w.t.Helper()
	op, err := w.abx.Delete(ctx, &iamv1.DeleteAccessBindingRequest{AccessBindingId: id})
	w.requireOpDone(op, err, why)
}

// saBody — тело учётки формой края, для «как в приёмке».
func saBody(acc domain.AccountID, name string) string {
	return fmt.Sprintf(`{"accountId":%q,"name":%q}`, string(acc), name)
}

// plans — модель прав мира: какие отношения объявляет тип (SAC-21 спрашивает
// только объявленные).
func (w *sacWorld) plans() *authzmodel.Plans {
	w.t.Helper()
	p, err := authzmodel.New(authzmodel.DSL)
	require.NoError(w.t, err, "модель прав мира")
	return p
}

// applyImageRoles — применение ролей манифеста образа глаголами пути старта
// (`moduleroles.Applier.ApplyImage`) и самолечение селекторов и проекции глаголов
// системных ролей (`seed.SyncAllSystemRoleSelectors`, `seed.ReseedSystemRoleVerbs`)
// — те же шаги, что `applyDelivered` мира П6 делает для доставленного манифеста.
func (w *sacWorld) applyImageRoles() {
	w.t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	own, err := servicemanifest.Load()
	require.NoError(w.t, err, "мир С: встроенный манифест службы")
	reg, err := seed.LoadPermissionRegistry(w.ctx, logger)
	require.NoError(w.t, err, "мир С: каталог прав")
	rows := reg.All()
	entries := make([]roleexport.CatalogEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, roleexport.CatalogEntry{
			FQN: r.FQN, RequiredRelation: r.RequiredRelation, ScopeObjectType: r.ScopeExtractor.ObjectType,
		})
	}
	attributed, _ := roleexport.Attribute(entries)
	rights, err := moduleroles.NewRightsExport(w.facts, attributed)
	require.NoError(w.t, err, "мир С: производитель правил роли")
	rep, err := moduleroles.NewApplier(moduleroles.NewRepoTxRunner(w.repo), rights).
		ApplyImage(w.ctx, own, moduleroles.BootActorID)
	require.NoErrorf(w.t, err, "мир С: применение ролей своего манифеста (%s)", rep)
	w.t.Logf("мир С: роли своего манифеста — %s", rep)
	require.NoError(w.t, seed.SyncAllSystemRoleSelectors(w.ctx, w.pool), "мир С: селекторы системных ролей")
	_, err = seed.ReseedSystemRoleVerbs(w.ctx, w.repo, w.pool, w.facts, nil)
	require.NoError(w.t, err, "мир С: проекция глаголов системных ролей")
}
