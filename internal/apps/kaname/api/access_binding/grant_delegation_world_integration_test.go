// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// grant_delegation_world_integration_test.go — мир Д приёмки
// docs/engineering/acceptance/delegated-grants-stay-within-the-delegation.md
// (редакция 3, отпечаток 7512fd96c7aeb85f352fd55954cfb881fa7c8610169574adb2291155bb690fe6;
// задача PRO-Robotech/kaname#986, полоса красных проб PRO-Robotech/kaname#1009).
//
// # Что здесь лежит
//
// Мир Д (§4.1 приёмки) поверх мира П6 (`newPCRWorld`) и драйвер испытуемого.
// Пробы групп A…I лежат в соседних файлах `grant_delegation_*_integration_test.go`;
// каждая называется `TestGrantDelegation_GD<NN>_…` — один сценарий, одна проба.
//
// # Порядок каждой пробы несущий
//
//  1. мир: посев и его положительные контроли (`newGDWorld`) — сломанный посев
//     краснеет здесь, называя контроль, и за отсутствие предмета себя не выдаёт;
//  2. близнец, не зависящий от предмета, — там, где он есть;
//  3. проба возможностей испытуемого (`requireSubject`) — и только после неё
//     тело сценария. До реализации проба краснеет на шаге 3 строкой
//     «ПРЕДМЕТА НЕТ», перечисляя каждое недостающее звено.
//
// # Испытуемый спрашивается по контракту, а не по коду реализации
//
// Службы `GrantDelegationService` в дереве ещё нет — ни дескрипторов, ни типов
// Go. Проба обязана собираться на сегодняшнем стволе и исполняться, поэтому
// служба спрашивается через влинкованные дескрипторы пакета `kaname.cloud.iam.v1`
// (`protoregistry.GlobalFiles`): тело запроса — JSON края дословно из приёмки,
// разбирается `protojson` в сообщение входа метода, ответ читается обратно в
// JSON. Имена полей сверяются с контрактом самим разбором: ключ, которого нет
// в контракте, — отказ разбора с его именем, а не молчаливое «поле проигнорировано».
//
// Вызов идёт обработчиком из `grpc.ServiceDesc` — тем, что регистрирует
// сгенерированный `Register…Server`, — в этом же процессе, с контекстом
// вызывающего (принципал доходит до use-case, как у прочих проб пакета).
// Провязку службы и четвёртого пути права выдавать в мир делает реализация в
// одном месте — `grant_delegation_seam_world_integration_test.go`; до неё там
// пусто, и проба возможностей называет это отдельным звеном.

import (
	"context"
	"encoding/json"
	"fmt"
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
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	groupapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	serviceaccountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/service_account"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Координаты контракта, которых в стволе ещё нет (Р1, Р4 приёмки). Пишутся
// полным именем proto: Go-типов у них нет, и проба обязана собираться.
const (
	gdServiceName      = "kaname.cloud.iam.v1.GrantDelegationService"
	gdResourceMessage  = "kaname.cloud.iam.v1.GrantDelegation"
	gdBindingMessage   = "kaname.cloud.iam.v1.AccessBinding"
	gdReasonEnum       = "kaname.cloud.iam.v1.AccessBinding.RevocationReason"
	gdReasonRevokedVal = "REVOCATION_REASON_DELEGATION_REVOKED"
	// gdReasonRevokedNum — числовое значение причины (Р4: `= 4`).
	gdReasonRevokedNum = 4
	// gdDelegationIDJSON — имя поля вывода выдачи на крае (`AccessBinding.delegation_id`).
	gdDelegationIDJSON = "delegationId"
)

// Объекты мира Д сверх мира П6 (§4.1): реестр Z в prj-C (цепь prj-C, acc-B) и
// ключ Q, который не регистрируется никогда.
const (
	gdZ        = "reg00000000000000003"
	gdQ        = "reg00000000000000009"
	gdRepoTgt  = "registry.repositories"
	gdFixture  = "registry.delegation-fixture.yaml"
	gdVPCFixt  = "vpc.delegation-fixture.yaml"
	gdIAMRole  = "rol674f6a6d7e4eeb3b6" // iam.project.admin, миграция 0001
	gdIAMName  = "iam.project.admin"
	gdAdminRID = domain.ClusterAdminRoleID // каноническая `admin` каталога ролей
)

// gdWorld — мир Д одной базы.
type gdWorld struct {
	*pcrWorld

	usrS                      domain.UserID
	accS                      domain.AccountID
	svaIss, svaIss2, svaOther string
	svaA2, svaA3              string
	grpB                      string
	usrM, usrP, usrE          domain.UserID
	prjA2, prjC               domain.ProjectID

	rolPuller, rolPusher, rolRegAdmin domain.RoleID
	rolVPCPool                        domain.RoleID

	grantE string // выдача `admin` человеку usr-E на acc-A (usr-E — администратор аккаунта)

	// abx — выдача мира Д со всеми глаголами, которые трогают сценарии.
	abx *accessbindingapp.Handler
	// abCreate/abRevoke/abDelete — те же экземпляры, что в abx: в них
	// реализация провязывает четвёртый путь (`gdWireGrantPath`).
	abCreate *accessbindingapp.CreateAccessBindingUseCase
	abRevoke *accessbindingapp.RevokeAccessBindingUseCase
	abDelete *accessbindingapp.DeleteAccessBindingUseCase

	projects *projectapp.Handler
	groups   *groupapp.Handler
	roles    *roleapp.Handler
	sas      *serviceaccountapp.Handler

	// subject — службы, зарегистрированные провязкой испытуемого.
	subject *gdRegistrar
}

// newGDWorld поднимает мир Д и доказывает живость посева положительными
// контролями. Испытуемого не трогает: проба возможностей — `requireSubject`.
func newGDWorld(t *testing.T) *gdWorld {
	t.Helper()
	p := newPCRWorld(t)
	w := &gdWorld{pcrWorld: p}
	ctx, pool := p.ctx, p.pool

	// Аккаунт службы acc-S и его учётки: делегаты sva-iss, sva-iss2 и посторонняя sva-other.
	w.usrS = mustSeedUser(t, ctx, pool, "gds")
	w.accS = seedAccountByOwner(t, ctx, pool, "acc-gd-s", w.usrS)
	w.svaIss = seedServiceAccount(t, ctx, pool, w.accS, "sva-gd-iss")
	w.svaIss2 = seedServiceAccount(t, ctx, pool, w.accS, "sva-gd-iss2")
	w.svaOther = seedServiceAccount(t, ctx, pool, w.accS, "sva-gd-other")
	// Учётки sva-A2, sva-A3 в acc-A; группа grp-B в acc-B.
	w.svaA2 = seedServiceAccount(t, ctx, pool, w.accA, "sva-gd-a2")
	w.svaA3 = seedServiceAccount(t, ctx, pool, w.accA, "sva-gd-a3")
	w.grpB = seedGroup(t, ctx, pool, w.accB, "grp-gd-b")
	// Люди usr-M (участник acc-A), usr-P (приглашён в acc-A), usr-E (станет администратором acc-A).
	w.usrM = mustSeedUser(t, ctx, pool, "gdm")
	w.usrP = mustSeedUser(t, ctx, pool, "gdp")
	w.usrE = mustSeedUser(t, ctx, pool, "gde")
	verifyAddresses(t, ctx, pool)
	gdSeedMembership(t, ctx, pool, w.usrM, w.accA, "ACTIVE")
	gdSeedMembership(t, ctx, pool, w.usrP, w.accA, "PENDING")
	// Проекты prj-A2 в acc-A и prj-C в acc-B.
	w.prjA2 = seedProjectInAccount(t, ctx, pool, w.accA, "prj-gd-a2")
	w.prjC = seedProjectInAccount(t, ctx, pool, w.accB, "prj-gd-c")

	// Роли модуля registry — новая редакция манифеста registry, доставленная
	// путём старта (Р10 мира П6: загрузка → каталог → роли).
	w.deliverDoc(gdFixture, "мир Д: доставка редакции registry с ролями делегирования")
	// Роль другого модуля — манифест vpc тем же путём.
	w.deliverDoc(gdVPCFixt, "мир Д: доставка манифеста vpc (роль vpc.address_pool_admin)")
	w.rolPuller = w.roleByName("registry.puller")
	w.rolPusher = w.roleByName("registry.pusher")
	w.rolRegAdmin = w.roleByName("registry.admin")
	w.rolVPCPool = w.roleByName("vpc.address_pool_admin")
	require.Equalf(t, domain.RoleID(gdIAMRole), w.roleByName(gdIAMName),
		"контроль мира Д: роль модуля iam %s в базе под своим id", gdIAMName)
	require.Equalf(t, domain.RoleID(gdAdminRID), w.roleByName("admin"),
		"контроль мира Д: каноническая роль admin в базе под своим id")

	// Реестр Z в prj-C (acc-B).
	w.registerRegistryIn(gdZ, w.prjC, w.accB, w.usrC)

	w.buildHandlers()

	// Указатель проекта на аккаунт — строка журнала `project:<p>#account@account:<a>`,
	// которую продукт со-коммитит с проектом (`ProjectService.Create`; образец
	// посева — `internal/repo/kaname/pg/parentedge/rootreach_integration_test.go`).
	// Посев мира кладёт проект строкой таблицы, мимо глагола, и без указателя
	// `project.super_admin = admin from account` не выводится: у владельца нет
	// ни правки проекта (дверь, близнецы GD-25), ни `v_delete` на объекте выдачи
	// проекта (вопрос двери, переезжающий в обработчик, Р1а). Замер: прогон мира Д
	// без указателя — «дверь не пропустила владельца» на правке prj-A2 и контроль
	// `v_update` usr-A за 30 с не дошёл до true.
	for _, pa := range []struct {
		prj domain.ProjectID
		acc domain.AccountID
	}{{w.prjA, w.accA}, {w.prjA2, w.accA}, {w.prjC, w.accB}} {
		gdSeedTuple(t, ctx, pool, "account:"+string(pa.acc), "account", "project:"+string(pa.prj))
	}

	// Авто-выдача владельца: роль `owner` на своём аккаунте, цель — вся область,
	// — как её заводит `AccountService.Create` (`domain.OwnerRoleID`).
	for _, own := range []struct {
		user domain.UserID
		acc  domain.AccountID
	}{{w.usrA, w.accA}, {w.usrC, w.accB}, {w.usrS, w.accS}} {
		w.createDoneX(asUser(ctx, own.user), &iamv1.CreateAccessBindingRequest{
			Subjects:  []*iamv1.Subject{userSubject(own.user)},
			RoleId:    domain.OwnerRoleID,
			ScopeType: "iam.account",
			ScopeId:   string(own.acc),
			Target:    allInScopeTarget(),
		}, "мир Д: авто-выдача владельца "+string(own.user))
	}
	// Авто-выдача владельца acc-A заведена здесь — общий помощник мира П1
	// (`ownerMayRemove`) её второй раз не заводит.
	w.ownerSeeded = true

	// Администратор аккаунта usr-E: выдача канонической `admin` на acc-A от
	// владельца, цель — вся область.
	w.grantE = w.createDoneX(asUser(ctx, w.usrA), &iamv1.CreateAccessBindingRequest{
		Subjects:  []*iamv1.Subject{userSubject(w.usrE)},
		RoleId:    gdAdminRID,
		ScopeType: "iam.account",
		ScopeId:   string(w.accA),
		Target:    allInScopeTarget(),
	}, "мир Д: выдача admin человеку usr-E на acc-A")

	// ── положительные контроли посева ──────────────────────────────────────
	// usr-E проходит Путь 2 (`admin` на области acc-A).
	w.pollRelation("user:"+string(w.usrE), "admin", "account:"+string(w.accA), true,
		"контроль мира Д: usr-E держит admin на acc-A (Путь 2)")
	// Владелец: пообъектные права авто-выдачи материализованы — правка проекта
	// и удаление объекта выдачи.
	w.pollRelation("user:"+string(w.usrA), "v_update", "project:"+string(w.prjA2), true,
		"контроль мира Д: usr-A держит v_update на prj-A2 (авто-выдача владельца)")
	w.pollRelation("user:"+string(w.usrA), "v_delete", "iam_access_binding:"+w.grantE, true,
		"контроль мира Д: usr-A держит v_delete на объекте выдачи (авто-выдача владельца)")
	// Членство: usr-M — ACTIVE, usr-P — PENDING, usr-C — строки нет.
	w.requireMembership(w.usrM, w.accA, domain.MembershipStateActive)
	w.requireMembership(w.usrP, w.accA, domain.MembershipStatePending)
	w.requireNoMembership(w.usrC, w.accA)
	// Учётки делегатов прав не держат ни на acc-A, ни на prj-A.
	for _, sva := range []string{w.svaIss, w.svaIss2, w.svaOther} {
		w.requireRelation("service_account:"+sva, "admin", "account:"+string(w.accA), false,
			"контроль мира Д: учётка делегата без прав на acc-A")
	}
	// Регистрация: X, Y и Z зарегистрированы, Q — нет.
	for _, id := range []string{pcrX, pcrY, gdZ} {
		require.Truef(t, w.mirrorHas(pcrRegType, id), "контроль мира Д: реестр %s зарегистрирован", id)
	}
	require.Falsef(t, w.mirrorHas(pcrRegType, gdQ), "контроль мира Д: ключ Q не зарегистрирован")
	return w
}

// ── посев ─────────────────────────────────────────────────────────────────

// gdSeedMembership — строка членства пары «человек, аккаунт» тем же выражением
// идентификатора, каким её кладут зеркало и бэкфилл (`kaname.membership_mirror_id`;
// образец — `internal/repo/kaname/pg/membership_is_the_account_source_integration_test.go`).
func gdSeedMembership(t *testing.T, ctx context.Context, pool *pgxpool.Pool, user domain.UserID, acc domain.AccountID, state string) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.memberships (id, user_id, account_id, state)
		VALUES (kaname.membership_mirror_id($1, $2), $1, $2, $3)
		ON CONFLICT (user_id, account_id) DO UPDATE SET state = EXCLUDED.state`,
		string(user), string(acc), state)
	require.NoErrorf(t, err, "посев мира Д: членство %s в %s (%s)", user, acc, state)
}

// gdSeedTuple — прямой факт модели строкой журнала (форма посева SC-27,
// `grantAdminOnProject`): триггер складывает строку в факт тем же коммитом.
func gdSeedTuple(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subject, relation, object string) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		VALUES ('fga.tuple.write', jsonb_build_object('user', $1::text, 'relation', $2::text, 'object', $3::text), now())`,
		subject, relation, object)
	require.NoErrorf(t, err, "посев мира Д: факт %s %s %s", subject, relation, object)
}

// deliverDoc — доставка манифеста из фикстур путём старта мира П6.
func (w *gdWorld) deliverDoc(file, what string) {
	w.t.Helper()
	doc, err := publicreadfixture.Read(file)
	require.NoErrorf(w.t, err, "%s: фикстура %s", what, file)
	if file == gdFixture {
		// Редакция registry несёт запись `writes: owner`, как у мира П6 (kaname#982):
		// доставка заменяет политику записи, и регистрации `owner` мира без неё были
		// бы отказом.
		doc, err = publicreadfixture.WithWrites(doc)
		require.NoErrorf(w.t, err, "%s: фикстура %s с writes", what, file)
	}
	m, err := manifest.Load(doc)
	require.NoErrorf(w.t, err, "%s: загрузчик отверг фикстуру %s", what, file)
	w.applyDelivered(what, m)
}

// roleByName — id роли по имени (системные и модульные роли — без аккаунта).
func (w *gdWorld) roleByName(name string) domain.RoleID {
	w.t.Helper()
	var id string
	require.NoErrorf(w.t, w.pool.QueryRow(w.ctx,
		`SELECT id FROM kaname.roles WHERE name = $1 AND account_id IS NULL AND project_id IS NULL`, name).Scan(&id),
		"контроль мира Д: роль %s в базе", name)
	return domain.RoleID(id)
}

// registerRegistryIn — регистрация реестра в названном проекте (вариант глагола
// `registerRegistry` мира П6 с другим проектом и владельцем).
func (w *gdWorld) registerRegistryIn(id string, prj domain.ProjectID, acc domain.AccountID, owner domain.UserID) {
	w.t.Helper()
	obj := pcrRegType + ":" + id
	for _, r := range []*iamv1.RegisterResourceRequest{
		{SubjectId: "project:" + string(prj), Relation: "project", Object: obj},
		{SubjectId: "user:" + string(owner), Relation: "owner", Object: obj},
	} {
		r.ParentProjectId, r.ParentAccountId = string(prj), string(acc)
		r.ParentChain = []string{"project:" + string(prj), "account:" + string(acc)}
		require.NoErrorf(w.t, w.reg.Register(w.ctx, r), "мир Д: регистрация реестра %s (%s)", id, r.GetRelation())
	}
}

// mirrorHas — есть ли строка регистрации объекта. Тип строки зеркала пишется
// именем каталога живой строки (`NewCatalogTypeReader`), а не именем модели,
// поэтому счёт идёт по id объекта: id реестров мира Д различны.
func (w *gdWorld) mirrorHas(_ string, id string) bool {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.resource_mirror WHERE object_id = $1`, id).Scan(&n))
	return n > 0
}

func (w *gdWorld) requireMembership(user domain.UserID, acc domain.AccountID, want domain.MembershipState) {
	w.t.Helper()
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(w.t, err)
	defer func() { _ = rd.Rollback(w.ctx) }()
	m, err := rd.Users().Membership(w.ctx, user, acc)
	require.NoErrorf(w.t, err, "контроль мира Д: членство %s в %s читается", user, acc)
	require.Equalf(w.t, want, m.State, "контроль мира Д: состояние членства %s в %s", user, acc)
}

func (w *gdWorld) requireNoMembership(user domain.UserID, acc domain.AccountID) {
	w.t.Helper()
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(w.t, err)
	defer func() { _ = rd.Rollback(w.ctx) }()
	_, err = rd.Users().Membership(w.ctx, user, acc)
	require.Errorf(w.t, err, "контроль мира Д: у %s нет членства в %s", user, acc)
}

// buildHandlers — use-case'ы мира Д теми же частями, что корень службы
// (`cmd/kaname/wiring.go`), с каталожным фактом последней доставки.
func (w *gdWorld) buildHandlers() {
	w.t.Helper()
	src := catalog.Fixed{F: w.facts}
	w.abCreate, w.abRevoke, w.abDelete = w.newGrantVerbs(w.ops)
	get := accessbindingapp.NewGetAccessBindingUseCase(w.repo).
		WithRelationStore(w.door, nil).WithRelationQueries(w.door)
	listBySubject := accessbindingapp.NewListBySubjectUseCase(w.repo).
		WithRelationStore(w.door, nil).WithRelationQueries(w.door)
	update := accessbindingapp.NewUpdateAccessBindingUseCase(w.repo, w.ops).
		WithRelationStore(w.door, nil).WithObjectReconciler(w.rec)
	w.abx = accessbindingapp.NewHandler(w.abCreate, w.abDelete, get, nil, listBySubject, nil, nil).
		WithUpdate(update).
		WithRevoke(w.abRevoke).
		WithListByRole(accessbindingapp.NewListByRoleUseCase(w.repo).WithRelationStore(w.door, nil)).
		WithExpandAccess(accessbindingapp.NewExpandAccessUseCase(w.door).WithGrantAuthority(w.repo, w.door, nil))

	w.projects = projectapp.NewHandler(
		projectapp.NewCreateProjectUseCase(w.repo, w.ops).WithRelationStore(w.door, nil),
		projectapp.NewUpdateProjectUseCase(w.repo, w.ops).WithRelationStore(w.door, nil),
		projectapp.NewDeleteProjectUseCase(w.repo, w.ops), nil, nil)
	w.groups = groupapp.NewHandler(
		groupapp.NewCreateGroupUseCase(w.repo, w.ops).WithRelationStore(w.door, nil),
		nil, nil, nil, nil, groupapp.NewAddMemberUseCase(w.repo, w.ops).
			WithGrantAuthority(accessbindingapp.NewScopeGrantAuthority(w.repo, w.door)), nil, nil)
	w.roles = roleapp.NewHandler(
		roleapp.NewCreateRoleUseCase(w.repo, w.ops, src).WithRelationStore(w.door, nil), nil, nil, nil, nil)
	w.sas = serviceaccountapp.NewHandler(
		serviceaccountapp.NewCreateServiceAccountUseCase(w.repo, w.ops).WithRelationStore(w.door, nil),
		nil, serviceaccountapp.NewDeleteServiceAccountUseCase(w.repo, w.ops), nil, nil, nil, nil)

	w.subject = newGDRegistrar()
	gdWireSubject(w, w.subject)
}

// newGrantVerbs — Create/Revoke/Delete выдачи над названным хранилищем
// операций, с провязкой четвёртого пути (`gdWireGrantPath`). Отдельная
// функция затем, чтобы детерминированная гонка (CE-09) получила те же глаголы
// над хранилищем с задвижкой, а не вторую сборку руками.
func (w *gdWorld) newGrantVerbs(ops operations.Repo) (*accessbindingapp.CreateAccessBindingUseCase,
	*accessbindingapp.RevokeAccessBindingUseCase, *accessbindingapp.DeleteAccessBindingUseCase) {
	src := catalog.Fixed{F: w.facts}
	create := accessbindingapp.NewCreateAccessBindingUseCase(w.repo, ops, src).
		WithRelationStore(w.door, nil).
		WithReconciler(w.rec)
	revoke := accessbindingapp.NewRevokeAccessBindingUseCase(w.repo, ops).WithRelationStore(w.door, nil)
	del := accessbindingapp.NewDeleteAccessBindingUseCase(w.repo, ops).WithRelationStore(w.door, nil)
	gdWireGrantPath(w, create, revoke, del)
	return create, revoke, del
}

// ── вызывающие ────────────────────────────────────────────────────────────

// asUserID — вызывающий-человек по строковому id.
func asUserID(w *gdWorld, id string) context.Context {
	return asUser(w.ctx, domain.UserID(id))
}

func asSA(ctx context.Context, id string) context.Context {
	return operations.WithPrincipal(ctx, operations.Principal{Type: "service_account", ID: id})
}

func svaSubject(id string) *iamv1.Subject {
	return &iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT, Id: id}
}

func groupSubject(id string) *iamv1.Subject {
	return &iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_GROUP, Id: id}
}

// ── модель прав ───────────────────────────────────────────────────────────

// relation — ответ модели о прямом вопросе (та же дверь решения, что у
// `AuthorizeService.Check`).
func (w *gdWorld) relation(subject, relation, object string) bool {
	w.t.Helper()
	ok, err := w.door.Check(w.ctx, subject, relation, object)
	require.NoErrorf(w.t, err, "модель не ответила: %s %s %s", subject, relation, object)
	return ok
}

func (w *gdWorld) requireRelation(subject, relation, object string, want bool, why string) {
	w.t.Helper()
	require.Equalf(w.t, want, w.relation(subject, relation, object), "%s: Check(%s, %s, %s)", why, subject, relation, object)
}

// pollRelation — опрос раз в 200 мс до 30 с (окно материализации).
func (w *gdWorld) pollRelation(subject, relation, object string, want bool, why string) {
	w.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	last := !want
	for {
		if last = w.relation(subject, relation, object); last == want {
			return
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	w.t.Fatalf("%s: Check(%s, %s, %s) за 30 с не дошёл до %v (последний ответ %v)", why, subject, relation, object, want, last)
}

// ── выдача ────────────────────────────────────────────────────────────────

// v — тело выдачи V (§4.1): sva-iss, область prj-A, роль `registry.pusher`,
// субъект sva-A, цель X. Строки отказов отличаются от V ровно одним полем.
func (w *gdWorld) v() *iamv1.CreateAccessBindingRequest {
	return &iamv1.CreateAccessBindingRequest{
		Subjects:  []*iamv1.Subject{svaSubject(w.svaA)},
		RoleId:    string(w.rolPusher),
		ScopeType: "iam.project",
		ScopeId:   string(w.prjA),
		Target:    pcrXTarget(),
	}
}

// createDoneX — выдача доведена до `done` без `error`; отдаёт её id.
func (w *gdWorld) createDoneX(ctx context.Context, req *iamv1.CreateAccessBindingRequest, what string) string {
	w.t.Helper()
	op, err := w.abx.Create(ctx, req)
	require.NoErrorf(w.t, err, "%s: синхронный отказ создания", what)
	done := awaitOp(w.t, w.ctx, w.ops, op.GetId())
	require.Nilf(w.t, done.Error, "%s: операция завершилась ошибкой %+v", what, done.Error)
	var md iamv1.CreateAccessBindingMetadata
	require.NoError(w.t, op.GetMetadata().UnmarshalTo(&md), "%s: метаданные операции", what)
	require.NotEmptyf(w.t, md.GetAccessBindingId(), "%s: id выдачи не назван", what)
	return md.GetAccessBindingId()
}

// grantOutcome — исход выдачи: синхронный отказ либо операция до `done`.
type grantOutcome struct {
	syncErr   error
	opID      string
	bindingID string
	opErr     *status.Status
}

func (w *gdWorld) tryGrant(ctx context.Context, req *iamv1.CreateAccessBindingRequest) grantOutcome {
	w.t.Helper()
	op, err := w.abx.Create(ctx, req)
	if err != nil {
		return grantOutcome{syncErr: err}
	}
	out := grantOutcome{opID: op.GetId()}
	var md iamv1.CreateAccessBindingMetadata
	if op.GetMetadata() != nil {
		require.NoError(w.t, op.GetMetadata().UnmarshalTo(&md))
		out.bindingID = md.GetAccessBindingId()
	}
	done := awaitOp(w.t, w.ctx, w.ops, op.GetId())
	if done.Error != nil {
		out.opErr = status.New(codes.Code(done.Error.Code), done.Error.Message)
	}
	return out
}

// requireDenied — синхронный `PERMISSION_DENIED` `permission denied`, операции нет.
func requireDenied(t *testing.T, o grantOutcome, why string) {
	t.Helper()
	require.Emptyf(t, o.opID, "%s: синхронного отказа нет, заведена операция (ошибка операции %v)", why, o.opErr)
	requireSyncRefusal(t, o.syncErr, codes.PermissionDenied, "permission denied", why)
}

// requireGranted — операция `done` без ошибки; отдаёт id выдачи.
func requireGranted(t *testing.T, o grantOutcome, why string) string {
	t.Helper()
	require.NoErrorf(t, o.syncErr, "%s: синхронный отказ", why)
	require.Nilf(t, o.opErr, "%s: операция завершилась ошибкой", why)
	require.NotEmptyf(t, o.bindingID, "%s: id выдачи не назван", why)
	return o.bindingID
}

// getBinding — `AccessBindingService.Get` от владельца usr-A.
func (w *gdWorld) getBinding(id string) *iamv1.AccessBinding {
	w.t.Helper()
	pb, err := w.abx.Get(asUser(w.ctx, w.usrA), &iamv1.GetAccessBindingRequest{AccessBindingId: id})
	require.NoErrorf(w.t, err, "Get выдачи %s от usr-A", id)
	return pb
}

// delegationIDOf — `delegationId` выдачи и задан ли он. Поле читается по имени
// контракта: до реализации его в дескрипторе нет, и это звено проба
// возможностей называет отдельно.
func delegationIDOf(t *testing.T, pb *iamv1.AccessBinding) (string, bool) {
	t.Helper()
	m := pb.ProtoReflect()
	fd := m.Descriptor().Fields().ByJSONName(gdDelegationIDJSON)
	require.NotNilf(t, fd, "в контракте выдачи нет поля %s", gdDelegationIDJSON)
	if !m.Has(fd) {
		return "", false
	}
	return m.Get(fd).String(), true
}

// countDelegated — число выдач, несущих ссылку на делегирование `gdl`, по
// строкам выдачи в базе. Колонку называет реализация; поэтому счёт идёт по
// проекции чтения (`Get` каждой выдачи субъектов мира), а не по имени колонки.
func (w *gdWorld) countDelegated(gdl string) int {
	w.t.Helper()
	return w.delegatedBindings(gdl, false)
}

// delegatedBindings — выдач с `delegationId` = gdl (только ACTIVE — при
// activeOnly). Перепись прочитанного отделена от находок: ноль прочитанных
// выдач — отказ, а не «выдач с этой ссылкой ноль» (в мире Д usr-A видит как
// минимум выдачу usr-B мира П6 и выдачу admin человеку usr-E).
func (w *gdWorld) delegatedBindings(gdl string, activeOnly bool) int {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx, `SELECT id FROM kaname.access_bindings`)
	require.NoError(w.t, err)
	var ids []string
	for rows.Next() {
		var id string
		require.NoError(w.t, rows.Scan(&id))
		ids = append(ids, id)
	}
	rows.Close()
	require.NoError(w.t, rows.Err())
	n, read := 0, 0
	for _, id := range ids {
		pb, err := w.abx.Get(asUser(w.ctx, w.usrA), &iamv1.GetAccessBindingRequest{AccessBindingId: id})
		if err != nil {
			continue // выдача вне видимости usr-A (другой аккаунт) к делегированию acc-A не относится
		}
		read++
		if activeOnly && pb.GetStatus() != iamv1.AccessBinding_ACTIVE {
			continue
		}
		if got, ok := delegationIDOf(w.t, pb); ok && got == gdl {
			n++
		}
	}
	require.Positivef(w.t, read, "перепись выдач: строк %d, прочитано Get от usr-A 0 — счёт по ссылке %s вакуумен", len(ids), gdl)
	return n
}

// auditCount — строк аудита данного типа с данным `actor`.
func (w *gdWorld) auditCount(eventType, actor string) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `
		SELECT count(*) FROM kaname.audit_outbox
		 WHERE event_type = $1 AND event_payload->>'actor' = $2`, eventType, actor).Scan(&n))
	return n
}

// ── испытуемый: GrantDelegationService ───────────────────────────────────

// gdRegistrar — `grpc.ServiceRegistrar` мира Д: запоминает зарегистрированные
// службы и ничего не слушает. Вызов идёт обработчиком из `ServiceDesc`.
type gdRegistrar struct {
	svcs map[string]gdRegistered
}

type gdRegistered struct {
	desc *grpc.ServiceDesc
	impl any
}

func newGDRegistrar() *gdRegistrar { return &gdRegistrar{svcs: map[string]gdRegistered{}} }

func (r *gdRegistrar) RegisterService(desc *grpc.ServiceDesc, impl any) {
	r.svcs[desc.ServiceName] = gdRegistered{desc: desc, impl: impl}
}

// subjectGaps — недостающие звенья испытуемого, каждое своей строкой. Пустой
// перечень — испытуемый объявлен и провязан.
func (w *gdWorld) subjectGaps() []string {
	var gaps []string
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(gdServiceName)
	if err != nil {
		gaps = append(gaps, fmt.Sprintf("служба %s не объявлена в контракте (во влинкованном пакете iam.v1 её дескриптора нет)", gdServiceName))
	} else if sd, ok := d.(protoreflect.ServiceDescriptor); !ok {
		gaps = append(gaps, fmt.Sprintf("%s — не служба", gdServiceName))
	} else {
		for _, m := range []protoreflect.Name{"Create", "Get", "List", "Revoke"} {
			if sd.Methods().ByName(m) == nil {
				gaps = append(gaps, fmt.Sprintf("у службы %s нет метода %s (Р1)", gdServiceName, m))
			}
		}
	}
	if _, err := protoregistry.GlobalFiles.FindDescriptorByName(gdResourceMessage); err != nil {
		gaps = append(gaps, fmt.Sprintf("сообщения %s нет (Р1)", gdResourceMessage))
	}
	bd, err := protoregistry.GlobalFiles.FindDescriptorByName(gdBindingMessage)
	if err == nil {
		if bd.(protoreflect.MessageDescriptor).Fields().ByJSONName(gdDelegationIDJSON) == nil {
			gaps = append(gaps, "у AccessBinding нет поля вывода delegation_id (Р1)")
		}
	}
	ed, err := protoregistry.GlobalFiles.FindDescriptorByName(gdReasonEnum)
	if err == nil {
		v := ed.(protoreflect.EnumDescriptor).Values().ByName(gdReasonRevokedVal)
		switch {
		case v == nil:
			gaps = append(gaps, fmt.Sprintf("у причины отзыва нет значения %s (Р4)", gdReasonRevokedVal))
		case v.Number() != gdReasonRevokedNum:
			gaps = append(gaps, fmt.Sprintf("значение %s = %d, а не %d (Р4)", gdReasonRevokedVal, v.Number(), gdReasonRevokedNum))
		}
	}
	if _, ok := w.subject.svcs[gdServiceName]; !ok {
		gaps = append(gaps, "служба не провязана в мир Д: регистратор пуст (gdWireSubject, grant_delegation_seam_world_integration_test.go)")
	}
	return gaps
}

// requireSubject — проба возможностей испытуемого. Стоит ПОСЛЕ проверки мира:
// сломанный посев краснеет раньше, на своём контроле. Отказ печатает каждое
// недостающее звено — это и есть «не сошлась, потому что предмета нет».
func (w *gdWorld) requireSubject(sc string) {
	w.t.Helper()
	if gaps := w.subjectGaps(); len(gaps) > 0 {
		w.t.Fatalf("%s: ПРЕДМЕТА НЕТ — звеньев недостаёт %d:\n  - %s", sc, len(gaps), strings.Join(gaps, "\n  - "))
	}
}

// gdCall — вызов метода испытуемого с телом края (JSON дословно из приёмки).
// Отдаёт ответ в форме JSON края и ошибку вызова как есть.
func (w *gdWorld) gdCall(ctx context.Context, method, body string) (map[string]any, proto.Message, error) {
	w.t.Helper()
	reg := w.subject.svcs[gdServiceName]
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(gdServiceName)
	require.NoError(w.t, err, "служба испытуемого")
	md := d.(protoreflect.ServiceDescriptor).Methods().ByName(protoreflect.Name(method))
	require.NotNilf(w.t, md, "метод %s испытуемого", method)
	in := dynamicpb.NewMessage(md.Input())
	if body == "" {
		body = "{}"
	}
	require.NoErrorf(w.t, protojson.Unmarshal([]byte(body), in),
		"%s: тело приёмки не разбирается входом метода (ключ вне контракта?): %s", method, body)
	var handler grpc.MethodHandler
	for _, m := range reg.desc.Methods {
		if m.MethodName == method {
			handler = m.Handler
		}
	}
	require.NotNilf(w.t, handler, "у зарегистрированной службы нет обработчика %s", method)
	dec := func(v any) error {
		raw, err := proto.Marshal(in)
		if err != nil {
			return err
		}
		return proto.Unmarshal(raw, v.(proto.Message))
	}
	out, err := handler(reg.impl, ctx, dec, nil)
	if err != nil {
		return nil, nil, err
	}
	msg, ok := out.(proto.Message)
	require.Truef(w.t, ok, "%s: ответ не сообщение proto (%T)", method, out)
	return toJSONMap(w.t, msg), msg, nil
}

// toJSONMap — сообщение в форме JSON края (`protojson`, имена — json_name).
func toJSONMap(t *testing.T, m proto.Message) map[string]any {
	t.Helper()
	raw, err := protojson.Marshal(m)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// gdOp — исход асинхронной мутации испытуемого.
type gdOp struct {
	syncErr error
	opID    string
	id      string // id делегирования из метаданных операции либо ответа
	opErr   *status.Status
}

// gdMutate — `Create`/`Revoke` испытуемого до `done`.
func (w *gdWorld) gdMutate(ctx context.Context, method, body string) gdOp {
	w.t.Helper()
	_, msg, err := w.gdCall(ctx, method, body)
	if err != nil {
		return gdOp{syncErr: err}
	}
	op, ok := msg.(*operationpb.Operation)
	require.Truef(w.t, ok, "%s: ответ мутации — не Operation (%T)", method, msg)
	out := gdOp{opID: op.GetId()}
	done := awaitOp(w.t, w.ctx, w.ops, op.GetId())
	if done.Error != nil {
		out.opErr = status.New(codes.Code(done.Error.Code), done.Error.Message)
		return out
	}
	out.id = anyField(w.t, op.GetMetadata(), "grantDelegationId")
	if out.id == "" && done.Response != nil {
		out.id = anyField(w.t, done.Response, "id")
	}
	return out
}

// anyField — строковое поле сообщения в Any по имени JSON края.
func anyField(t *testing.T, a *anypb.Any, jsonName string) string {
	t.Helper()
	if a == nil {
		return ""
	}
	m, err := a.UnmarshalNew()
	require.NoErrorf(t, err, "Any %s не разворачивается", a.GetTypeUrl())
	s, _ := toJSONMap(t, m)[jsonName].(string)
	return s
}

// d1Body — тело делегирования D1 (§4.1) с делегатом и типами цели.
func (w *gdWorld) d1Body(delegate string, targetTypes ...string) string {
	if len(targetTypes) == 0 {
		targetTypes = []string{"registry.registries", "registry.repositories"}
	}
	return w.delegationBody(w.accA, delegate,
		[]domain.RoleID{w.rolPuller, w.rolPusher, w.rolRegAdmin}, targetTypes,
		[]string{"SUBJECT_TYPE_SERVICE_ACCOUNT", "SUBJECT_TYPE_SYSTEM_CLASS"})
}

// delegationBody — тело `Create` делегирования формой края.
func (w *gdWorld) delegationBody(acc domain.AccountID, delegate string, roleIDs []domain.RoleID, targetTypes, subjectTypes []string) string {
	roles := make([]string, 0, len(roleIDs))
	for _, r := range roleIDs {
		roles = append(roles, string(r))
	}
	b, err := json.Marshal(map[string]any{
		"accountId":    string(acc),
		"delegate":     map[string]any{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": delegate},
		"roleIds":      roles,
		"targetTypes":  targetTypes,
		"subjectTypes": subjectTypes,
	})
	require.NoError(w.t, err)
	return string(b)
}

// createDelegation — делегирование доведено до `done` без ошибки; отдаёт id.
func (w *gdWorld) createDelegation(ctx context.Context, body, what string) string {
	w.t.Helper()
	o := w.gdMutate(ctx, "Create", body)
	require.NoErrorf(w.t, o.syncErr, "%s: синхронный отказ заведения делегирования", what)
	require.Nilf(w.t, o.opErr, "%s: операция заведения делегирования завершилась ошибкой", what)
	require.Truef(w.t, strings.HasPrefix(o.id, "gdl"), "%s: id делегирования %q без префикса gdl", what, o.id)
	return o.id
}

// d1 — D1 от usr-A (делегат sva-iss).
func (w *gdWorld) d1() string {
	w.t.Helper()
	return w.createDelegation(asUser(w.ctx, w.usrA), w.d1Body(w.svaIss), "Дано: D1 от usr-A")
}

// revokeDelegation — `Revoke` делегирования до `done` без ошибки.
func (w *gdWorld) revokeDelegation(ctx context.Context, id, what string) {
	w.t.Helper()
	o := w.gdMutate(ctx, "Revoke", fmt.Sprintf(`{"grantDelegationId":%q}`, id))
	require.NoErrorf(w.t, o.syncErr, "%s: синхронный отказ отзыва делегирования", what)
	require.Nilf(w.t, o.opErr, "%s: операция отзыва делегирования завершилась ошибкой", what)
}

// getDelegation — `GrantDelegationService.Get` в форме JSON края.
func (w *gdWorld) getDelegation(ctx context.Context, id string) (map[string]any, error) {
	w.t.Helper()
	body, _, err := w.gdCall(ctx, "Get", fmt.Sprintf(`{"grantDelegationId":%q}`, id))
	return body, err
}

// activeDelegationsOfPair — число действующих делегирований пары «аккаунт,
// делегат», по чтению испытуемого (`List` от владельца, все страницы).
func (w *gdWorld) activeDelegationsOfPair(acc domain.AccountID, delegate string) int {
	w.t.Helper()
	n := 0
	for _, d := range w.listAllDelegations(asUser(w.ctx, w.usrA), acc) {
		del, _ := d["delegate"].(map[string]any)
		if d["status"] == "ACTIVE" && del["id"] == delegate {
			n++
		}
	}
	return n
}

// listAllDelegations — все страницы `List` по аккаунту.
func (w *gdWorld) listAllDelegations(ctx context.Context, acc domain.AccountID) []map[string]any {
	w.t.Helper()
	var all []map[string]any
	token := ""
	for page := 0; page < 100; page++ {
		body, err := json.Marshal(map[string]any{"accountId": string(acc), "pageSize": 1000, "pageToken": token})
		require.NoError(w.t, err)
		resp, _, err := w.gdCall(ctx, "List", string(body))
		require.NoError(w.t, err, "List делегирований")
		all = append(all, listItems(w.t, resp)...)
		token, _ = resp["nextPageToken"].(string)
		if token == "" {
			return all
		}
	}
	w.t.Fatalf("List делегирований: 100 страниц без конца")
	return nil
}

// listItems — элементы страницы `List`: единственное повторяемое поле ответа,
// чьи элементы — объекты (имя поля перечня называет реализация).
func listItems(t *testing.T, resp map[string]any) []map[string]any {
	t.Helper()
	var keys []string
	for k, v := range resp {
		if _, ok := v.([]any); ok {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	sort.Strings(keys)
	require.Lenf(t, keys, 1, "в ответе List больше одного перечня: %v", keys)
	var out []map[string]any
	for _, it := range resp[keys[0]].([]any) {
		m, ok := it.(map[string]any)
		require.Truef(t, ok, "элемент перечня List — не объект: %v", it)
		out = append(out, m)
	}
	return out
}

// requireRefusal — отказ вызова с кодом и ДОСЛОВНЫМ текстом; отдаёт статус.
func requireRefusal(t *testing.T, err error, code codes.Code, text, why string) *status.Status {
	t.Helper()
	require.Errorf(t, err, "%s: отказа нет", why)
	st, ok := status.FromError(err)
	require.Truef(t, ok, "%s: отказ не gRPC-статус: %v", why, err)
	require.Equalf(t, code, st.Code(), "%s: код (текст %q)", why, st.Message())
	require.Equalf(t, text, st.Message(), "%s: текст отказа", why)
	return st
}

// gdQuestionLog — порт отношений, записывающий каждый заданный вопрос. Им
// обёрнута настоящая дверь решения: ответы — её, журнал — пробы.
type gdQuestionLog struct {
	inner clients.RelationStore
	asked []string
}

func (q *gdQuestionLog) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	q.asked = append(q.asked, subject+"|"+relation+"|"+object)
	return q.inner.Check(ctx, subject, relation, object)
}

var _ authzguard.RelationChecker = (*gdQuestionLog)(nil)

// awaitRemovalRight — контроль «Дано» перед отзывом или удалением выдачи прежним
// путём: у держателя права выдавать материализовалось отношение удаления на
// объекте выдачи. С kaname#986 этот вопрос задаёт обработчик (Р1а), а
// пообъектные права на свежий объект выдачи материализуются после коммита —
// окно, которое закрывает ограниченный повтор клиента (ban #9), а не барьер
// операции. Опрос — тем же окном материализации, что `pollRelation`.
func (w *gdWorld) awaitRemovalRight(user domain.UserID, bindingID, why string) {
	w.t.Helper()
	w.pollRelation("user:"+string(user), accessbindingapp.RemovalRelation,
		accessbindingapp.RemovalObjectType+":"+bindingID, true, why)
}
