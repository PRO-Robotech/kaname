// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// system_class_world_integration_test.go — посев П1 приёмки
// docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md
// (отпечаток ae9ba373d26c8f4cc2a3c0036d04ff9e1a20b7cc0a8e43c1fca4690560427f51,
// редакция 4: id объектов `enp…` правильной формы; сессия владельца П1).
//
// Мир собирается ТЕМИ ЖЕ частями, что корень службы (`cmd/kaname/wiring.go`):
// дверь решения — форма `relverdict` под допуском `authzcascade.WrapAdmitted`,
// материализация — `reconcile.New` над адаптером Postgres, use-case'ы выдачи —
// с этой дверью и этим реконсайлером. Дублёра, отвечающего «да» на всё, здесь
// нет: фикстура, снисходительнее продукта, сделала бы невидимым тот самый отказ,
// который пробы обязаны различать.
//
// Порядок каждой пробы несущий: сначала положительный контроль фикстуры (та же
// выдача ЧЕЛОВЕКУ проходит и материализуется), потом предмет. Сломанный посев
// краснеет на контроле и не выдаёт себя за отсутствующий вид субъекта.
//
// Вид субъекта `SUBJECT_TYPE_SYSTEM_CLASS` пишется числом 4 (`scSystemClassType`):
// значения в перечислении ствола нет, и проба обязана исполниться, а не
// не собраться. Открытое перечисление proto3 переносит число без потерь.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	authorizeapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/authorize"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	"github.com/PRO-Robotech/kaname/internal/testsupport/moduleroster"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// scSystemClassType — значение `SUBJECT_TYPE_SYSTEM_CLASS = 4` (Р1 приёмки).
const scSystemClassType = iamv1.SubjectType(4)

// scObjType / scObj1 / scObj2 — объекты П1: `vpc_network` в `prj-A`. Тип цели
// выдачи пишется точечной формой закрытой таблицы (`vpc.network`), тип объекта
// модели — формой модели (`vpc_network`).
const (
	scTargetType = "vpc.network"
	scModelType  = "vpc_network"
	scObj1       = "enp00000000000000001"
	scObj2       = "enp00000000000000002"
)

// scWorld — П1 одной базы.
type scWorld struct {
	t     *testing.T
	ctx   context.Context
	pool  *pgxpool.Pool
	repo  *kanamepg.Repository
	ops   operations.Repo
	door  *authzcascade.Client
	rec   *reconcile.Reconciler
	ab    *accessbindingapp.Handler
	authz *authorizeapp.Handler

	usrA, usrB, usrC domain.UserID
	svaA, svaB       string
	accA, accB       domain.AccountID
	prjA             domain.ProjectID
	grpA             string

	rolRead, rolRead2, rolEdit domain.RoleID

	// ownerSeeded — авто-выдача владельца usr-A и указатель prj-A на acc-A
	// заведены (`ownerMayRemove`): единожды на мир.
	ownerSeeded bool
}

// newSCWorld поднимает П1. Пропуск в -short — по форме пакета.
func newSCWorld(t *testing.T) *scWorld {
	t.Helper()
	if testing.Short() {
		t.Skip("нужен Postgres: пропуск в -short")
	}
	ctx := context.Background()
	return seedSCWorld(t, ctx, wireSCWorld(t, ctx, poolFromDSN(t, setupTestDB(t))))
}

// wireSCWorld собирает части мира над готовой базой — те же, что корень службы
// (`cmd/kaname/wiring.go`), без посева. Вынесено, чтобы мир другой приёмки, которому
// база нужна на версии ДО испытуемой миграции, собирался теми же конструкторами, а
// не своей копией провязки.
func wireSCWorld(t *testing.T, ctx context.Context, pool *pgxpool.Pool) *scWorld {
	t.Helper()
	repo := kanamepg.New(pool, nil)
	ops := operations.NewRepo(pool, "kaname")
	door := authzcascade.WrapAdmitted(relverdict.NewAsker(pool), personmarks.New(pool))
	rec := reconcile.New(kanamepg.NewReconcileAdapter(pool, catalogfixture.Source()), nil, catalogfixture.Source())

	create := accessbindingapp.NewCreateAccessBindingUseCase(repo, ops, catalogfixture.Source()).
		WithRelationStore(door, nil).
		WithReconciler(rec)
	get := accessbindingapp.NewGetAccessBindingUseCase(repo).WithRelationStore(door, nil)
	listBySubject := accessbindingapp.NewListBySubjectUseCase(repo).
		WithRelationStore(door, nil).
		WithRelationQueries(door)
	del := accessbindingapp.NewDeleteAccessBindingUseCase(repo, ops).WithRelationStore(door, nil)
	ab := accessbindingapp.NewHandler(create, del, get, nil, listBySubject, nil, nil).
		WithExpandAccess(accessbindingapp.NewExpandAccessUseCase(door).WithGrantAuthority(repo, door, nil))

	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations:           door,
		ClusterAdminChecker: door,
	})
	authz := authorizeapp.NewHandler(svc, authorizeapp.NewWhoAmIUseCase(nil, nil)).WithModuleRoster(moduleroster.Roster(t))
	return &scWorld{t: t, ctx: ctx, pool: pool, repo: repo, ops: ops, door: door, rec: rec, ab: ab, authz: authz}
}

// seedSCWorld — посев П1 поверх собранного мира.
func seedSCWorld(t *testing.T, ctx context.Context, w *scWorld) *scWorld {
	t.Helper()
	pool, repo := w.pool, w.repo
	// Арендатор acc-A: владелец usr-A, проект prj-A, человек usr-B, учётка sva-A.
	w.usrA = mustSeedUser(t, ctx, pool, "sca")
	w.accA =seedAccountByOwner(t, ctx, pool, "acc-sc-a", w.usrA)
	w.prjA = seedProjectInAccount(t, ctx, pool, w.accA, "prj-sc-a")
	w.usrB = mustSeedUser(t, ctx, pool, "scb")
	w.svaA = seedServiceAccount(t, ctx, pool, w.accA, "sva-sc-a")
	// Второй арендатор acc-B: владелец usr-C, учётка sva-B; выдач в acc-A нет.
	w.usrC = mustSeedUser(t, ctx, pool, "scc")
	w.accB = seedAccountByOwner(t, ctx, pool, "acc-sc-b", w.usrC)
	w.svaB = seedServiceAccount(t, ctx, pool, w.accB, "sva-sc-b")
	w.grpA = seedGroup(t, ctx, pool, w.accA, "grp-sc-a")

	readRules := domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get", "list"}}}
	w.rolRead = seedRulesRoleWithSelectors(t, ctx, repo, w.accA, "sc_read", readRules)
	w.rolRead2 = seedRulesRoleWithSelectors(t, ctx, repo, w.accA, "sc_read2", readRules)
	w.rolEdit = seedRulesRoleWithSelectors(t, ctx, repo, w.accA, "sc_edit",
		domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get", "list", "update"}}})

	verifyAddresses(t, ctx, pool)
	// П1: владелец usr-A вошёл сессией уровня «2», предъявление минуту назад —
	// окно свежести выдачи классу (Р5) судит именно её.
	seedLiveHumanSession(t, w, w.usrA)
	seedMirrorObject(t, ctx, pool, scTargetType, scObj1, string(w.prjA), string(w.accA))
	seedMirrorObject(t, ctx, pool, scTargetType, scObj2, string(w.prjA), string(w.accA))
	return w
}

// verifyAddresses — адреса посеянных людей подтверждены: П1 — обычные вошедшие,
// а допуск двери отвергает человека с неподтверждённым адресом раньше вопроса
// о праве (`email_not_verified`), и без этого каждый вопрос о человеке был бы
// отказом допуска, а не ответом о выдаче.
func verifyAddresses(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx, `UPDATE kaname.users SET email_verified_at = now() WHERE email_verified_at IS NULL`)
	require.NoError(t, err, "посев: адреса людей подтверждены")
}

// seedServiceAccount — строка учётки в аккаунте; id по префиксу домена.
func seedServiceAccount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, acc domain.AccountID, name string) string {
	t.Helper()
	id := ids.NewID(domain.PrefixServiceAccount)
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.service_accounts (id, account_id, name) VALUES ($1, $2, $3)`,
		id, string(acc), name+"-"+id[len(id)-6:])
	require.NoError(t, err, "посев учётки %s", name)
	return id
}

// seedGroup — группа в аккаунте без членов.
func seedGroup(t *testing.T, ctx context.Context, pool *pgxpool.Pool, acc domain.AccountID, name string) string {
	t.Helper()
	id := ids.NewID(domain.PrefixGroup)
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.groups (id, account_id, name) VALUES ($1, $2, $3)`,
		id, string(acc), name+"-"+id[len(id)-6:])
	require.NoError(t, err, "посев группы %s", name)
	return id
}

// classSubject — субъект-класс в форме провода.
func classSubject(name string) *iamv1.Subject {
	return &iamv1.Subject{Type: scSystemClassType, Id: name}
}

// userSubject — субъект-человек в форме провода.
func userSubject(id domain.UserID) *iamv1.Subject {
	return &iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_USER, Id: string(id)}
}

// obj1Target — цель «названные объекты» из одного obj-1.
func obj1Target() *iamv1.AccessTarget {
	return resourcesTarget(&iamv1.ResourceRef{Type: scTargetType, Id: scObj1})
}

// sc01Request — тело SC-01: класс `authenticated`, `rol-read`, проект, obj-1.
func (w *scWorld) sc01Request() *iamv1.CreateAccessBindingRequest {
	return &iamv1.CreateAccessBindingRequest{
		Subjects:  []*iamv1.Subject{classSubject("authenticated")},
		RoleId:    string(w.rolRead),
		ScopeType: "iam.project",
		ScopeId:   string(w.prjA),
		Target:    obj1Target(),
	}
}

// withSubjects — копия тела с другим набором субъектов.
func withSubjects(req *iamv1.CreateAccessBindingRequest, subs ...*iamv1.Subject) *iamv1.CreateAccessBindingRequest {
	out := proto.Clone(req).(*iamv1.CreateAccessBindingRequest)
	out.Subjects = subs
	return out
}

// createDone — выдача доведена до `done` без `error`; отдаёт id выдачи.
func (w *scWorld) createDone(ctx context.Context, req *iamv1.CreateAccessBindingRequest, what string) string {
	w.t.Helper()
	op, err := w.ab.Create(ctx, req)
	require.NoErrorf(w.t, err, "%s: синхронный отказ создания", what)
	done := awaitOp(w.t, w.ctx, w.ops, op.GetId())
	require.Nilf(w.t, done.Error, "%s: операция завершилась ошибкой %+v", what, done.Error)
	var md iamv1.CreateAccessBindingMetadata
	require.NoError(w.t, op.GetMetadata().UnmarshalTo(&md), "%s: метаданные операции", what)
	require.NotEmptyf(w.t, md.GetAccessBindingId(), "%s: id выдачи не назван", what)
	return md.GetAccessBindingId()
}

// controlUserGrant — положительный контроль фикстуры: та же выдача ЧЕЛОВЕКУ
// заводится и материализуется (`Check` от него — `allowed`). Без него отказ
// по классу неотличим от сломанного посева.
func (w *scWorld) controlUserGrant(user domain.UserID, role domain.RoleID) string {
	w.t.Helper()
	req := w.sc01Request()
	req.Subjects = []*iamv1.Subject{userSubject(user)}
	req.RoleId = string(role)
	id := w.createDone(asUser(w.ctx, w.usrA), req, "контроль фикстуры: выдача человеку")
	w.pollCheck("user:"+string(user), "get", scObj1, true,
		"контроль фикстуры: выдача человеку материализуется в право чтения obj-1")
	return id
}

// moduleCtx — вызывающий `Check` — проверенный модуль платформы (внутренний
// слушатель). Вопрос о доступе задаёт решающая сторона, а не арендатор.
func moduleCtx() context.Context {
	return grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc", true)
}

// check — `AuthorizeService.Check` через обработчик, действием `verb`
// (`get` | `update`) и ярусом этого глагола, названным явно.
//
// Ярус назван явно, потому что выдача в этом мире материализуется на объекте
// только ярусным кортежем: замер на `09ec0851e` — `current direct relations:
// [viewer]`, и `v_get` ложен даже после проекции глаголов роли. Вопрос без
// отношения берёт глагол типа (kaname#995), и ответить на него мир не может.
// Вывод отношения из действия судят пробы мира П6 на настоящем решателе
// (`action_only_check_module_verb_integration_test.go`); предмет этого мира —
// классы субъектов, а не вывод отношения.
func (w *scWorld) check(subject, verb, objID string) (*iamv1.AuthorizeCheckResponse, error) {
	return w.authz.Check(moduleCtx(), &iamv1.AuthorizeCheckRequest{
		Subject:          subject,
		Resource:         &iamv1.ResourceRef{Type: scModelType, Id: objID},
		Action:           "vpc.networks." + verb,
		RequiredRelation: scTierOfVerb[verb],
	})
}

// scTierOfVerb — ярус глагола, которым мир спрашивает: тот же, который вопрос
// без отношения получал до kaname#995.
var scTierOfVerb = map[string]string{"get": "viewer", "update": "editor"}

func (w *scWorld) requireCheck(subject, verb, objID string, want bool, why string) {
	w.t.Helper()
	resp, err := w.check(subject, verb, objID)
	require.NoErrorf(w.t, err, "%s: Check(%s, %s, %s) не ответил", why, subject, verb, objID)
	require.Equalf(w.t, want, resp.GetAllowed(), "%s: Check(%s, %s, %s)", why, subject, verb, objID)
}

// pollCheck — опрос `Check` раз в 200 мс до 30 с (окно материализации SC-13).
func (w *scWorld) pollCheck(subject, verb, objID string, want bool, why string) {
	w.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var last bool
	for {
		resp, err := w.check(subject, verb, objID)
		require.NoErrorf(w.t, err, "%s: Check(%s) не ответил", why, subject)
		last = resp.GetAllowed()
		if last == want {
			return
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	w.t.Fatalf("%s: Check(%s, %s, %s) за 30 с не дошёл до allowed=%v (последний ответ %v)",
		why, subject, verb, objID, want, last)
}

// fmtSubject — субъект в форме вопроса к модели.
func fmtSubject(kind, id string) string { return fmt.Sprintf("%s:%s", kind, id) }
