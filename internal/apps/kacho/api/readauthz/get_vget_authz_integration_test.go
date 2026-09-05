// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package readauthz_test

// get_vget_authz_integration_test.go — на НАСТОЯЩЕЙ базе iam: читающие
// use-case'ы (Account/Project/User/Group/ServiceAccount .Get) авторизуются
// глаголоносным отношением `v_get`, а НЕ прежним программным стражем владения
// (authzguard.IsSelf), который и давал живой дефект «приглашённому выдали право →
// 404 на GET /iam/v1/accounts/<id>».
//
// Проверяемый контракт авторизации:
//
//	РАЗРЕШИТЬ если  администратор облака (cluster:cluster_kacho_root#system_admin) — любой объект
//	         ЛИБО   субъект держит v_get на объекте ресурса
//	иначе    NotFound  (скрыть существование — никогда PermissionDenied, никакого перечисления)
//	аноним   NotFound  (fail-closed до любого вопроса о доступе)
//
// ─────────────────────────────────────────────────────────────────────────────
// ГДЕ БЕРЁТСЯ ВЕРДИКТ (изменилось при снятии внешнего движка отношений)
//
// Прежде фикстура поднимала движок контейнером и клала в него по кортежу на
// субъекта. Ни движка, ни харнесса к нему в дереве нет. Вердикт теперь считает
// форма поверх собственной базы iam (`internal/repo/kacho/pg/relverdict`), а
// дверь решения — `internal/authzcascade`, ТО ЖЕ значение, которое композиционный
// корень провязывает стражам в проде.
//
// ПРАВО ВЫРАЖЕНО ТЕМ, ЧЕМ ОНО ВЫРАЖЕНО В ПРОДУКТЕ — ВЫДАЧЕЙ. Прямой глагольный
// кортеж своя база не производит вовсе: проекция журнала глаголы намеренно не
// переносит (миграция 0098), их ВЫВОДИТ форма из выдачи роли. Фикстура, писавшая
// такую строку, описывала бы состояние, которого продукт не достигает, — то есть
// мерила бы себя. Поэтому и владелец, и приглашённый получают здесь настоящую
// выдачу: роль с проекцией глагола + привязка на область; администратор облака —
// прямой факт на кластере, потому что ИМЕННО ТАК он и заводится.
//
// Враждебная половина: выдача на ресурс X не должна удовлетворять Get ресурса Y,
// а посторонний из чужого аккаунта обязан быть скрыт (никакой утечки).
//
// Нужна живая база; под -short пропускается.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	accountapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/account"
	groupapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/group"
	projectapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/project"
	saapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/service_account"
	userapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/user"
	"github.com/PRO-Robotech/kacho-iam/internal/authzcascade"
	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
	"github.com/PRO-Robotech/kacho-iam/internal/testsupport/iampgtest"
)

// readAuthzFixture — живой репозиторий и живая дверь решения над засеянной
// топологией:
//
//	владелец (usr_owner) владеет account:acc_T; аккаунт, проект, пользователь,
//	                     группа и служебная учётка лежат в нём;
//	приглашённый (usr_inv) держит ВЫДАЧУ роли, проецирующей глагол `get`, на
//	                     область аккаунта — это и есть сценарий живого дефекта;
//	администратор облака держит system_admin на кластере (верхний уровень);
//	посторонний (usr_str) не держит на этих объектах ничего.
type readAuthzFixture struct {
	pool  *pgxpool.Pool
	repo  *kachopg.Repository
	gates *authzcascade.Client

	ownerID domain.UserID
	accID   domain.AccountID
	projID  domain.ProjectID
	userID  domain.UserID // второй пользователь внутри acc_T (цель GET'а)
	groupID domain.GroupID
	saID    domain.ServiceAccountID

	inviteeID  domain.UserID
	clusterID  domain.UserID
	strangerID domain.UserID
}

func newReadAuthzFixture(t *testing.T) *readAuthzFixture {
	t.Helper()
	if testing.Short() {
		t.Skip("нужна живая база (-short)")
	}
	ctx := context.Background()

	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := kachopg.New(pool, nil)

	// ТА ЖЕ дверь, что провязывает композиционный корень (cmd/kacho-iam:
	// authzcascade.Wrap(relverdict.NewAsker(pool))). Собрать её здесь иначе
	// значило бы проверять не тот путь, по которому идёт продукт.
	f := &readAuthzFixture{pool: pool, repo: repo, gates: authzcascade.Wrap(relverdict.NewAsker(pool))}

	// владелец + его аккаунт (круговая ссылка owner_user_id разрешается парой
	// строк в одной транзакции).
	f.ownerID = seedUserWithAccount(t, ctx, pool, "owner")
	f.accID = accountOf(t, ctx, pool, f.ownerID)

	// цель GET'а, группа, служебная учётка, проект — всё внутри acc_T.
	f.userID = seedUserInAccount(t, ctx, pool, f.accID, "target")
	f.projID = seedProject(t, ctx, repo, f.accID, "proj-t")
	f.groupID = seedGroup(t, ctx, repo, f.accID, "grp-t")
	f.saID = seedServiceAccount(t, ctx, repo, f.accID, "sa-t")

	// вызывающие — настоящие строки в той же базе.
	f.inviteeID = seedUserInAccount(t, ctx, pool, f.accID, "invitee")
	f.clusterID = seedUserInAccount(t, ctx, pool, f.accID, "clusteradmin")
	f.strangerID = seedUserWithAccount(t, ctx, pool, "stranger") // свой чужой аккаунт

	// ── Посев прав ────────────────────────────────────────────────────────────
	//
	// Проект указывает на свой аккаунт ЧЕРЕЗ ЖУРНАЛ — так его туда кладёт
	// Project.Create, и оттуда же берёт указатель цепь областей. У пользователя,
	// группы и служебной учётки звено выводится из их собственной колонки
	// account_id, поэтому им ничего писать не нужно.
	pointerThroughJournal(t, ctx, pool, "project", string(f.projID), "account", "account:"+string(f.accID))

	// Владелец и приглашённый — ВЫДАЧА на область аккаунта, роль проецирует
	// глагол `get` на каждый из пяти типов, которые здесь читают.
	seedGetGrant(t, ctx, pool, f.accID, "rolownerget", "abnowner", string(f.ownerID))
	seedGetGrant(t, ctx, pool, f.accID, "rolinviteeget", "abninvitee", string(f.inviteeID))

	// Администратор облака — прямой факт на кластере: ровно так его и заводят.
	pointerThroughJournal(t, ctx, pool, "cluster", domain.ClusterSingletonID,
		"system_admin", "user:"+string(f.clusterID))

	return f
}

// readAuthzTypes — типы модели прав, которые читают пять use-case'ов этого файла.
// Перечень выводится не отсюда, а из того, что каждая проба ниже спрашивает; он
// нужен ровно затем, чтобы роль выдачи проецировала глагол на КАЖДЫЙ из них.
var readAuthzTypes = []string{
	"account", "project", "iam_user", "iam_group", "iam_service_account",
}

// seedGetGrant заводит роль, проецирующую глагол `get` на пять читаемых типов, и
// привязывает её к субъекту на область АККАУНТА — тремя строками, какими это
// делает продукт: проекция глаголов роли, якорная ветвь её правила и сама выдача
// со своим субъектом.
//
// Имя типа в проекции берётся ТЕМ ЖЕ переводчиком, каким его берёт запрос
// вердикта (`authzmap.CatalogTypeName`): проекция хранится в точечной форме
// каталога, и фикстура, написавшая имя модели дословно, посеяла бы строку,
// которой запрос не найдёт, — отличить это от «права нет» стало бы нечем.
func seedGetGrant(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	acc domain.AccountID, role, binding, subjectID string) {
	t.Helper()
	mustExec(t, ctx, pool,
		`INSERT INTO kacho_iam.roles (id, account_id, name, permissions)
		 VALUES ($1, $2, $3, '["iam.project.*.get"]'::jsonb)`, role, string(acc), role)
	for _, ty := range readAuthzTypes {
		catalog := authzmap.CatalogTypeName(ty)
		mustExec(t, ctx, pool,
			`INSERT INTO kacho_iam.role_verb (role_id, object_type, verb) VALUES ($1, $2, 'get')`,
			role, catalog)
		mustExec(t, ctx, pool,
			`INSERT INTO kacho_iam.role_rule_selectors
			   (role_id, rule_fp, arm, object_types, match_labels)
			 VALUES ($1, $2, 'anchor', ARRAY[$3::text], '{}'::jsonb)`,
			role, "fp-"+catalog, catalog)
	}
	mustExec(t, ctx, pool,
		`INSERT INTO kacho_iam.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		 VALUES ($1, 'user', $2, $3, 'account', $4, 'ACTIVE')`,
		binding, subjectID, role, string(acc))
	mustExec(t, ctx, pool,
		`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ($1, 'user', $2)`, binding, subjectID)
}

// seedObjectGrant выдаёт глагол `get` на ОДИН названный объект — область выдачи
// есть сам объект. Нужна враждебной пробе: «выдача на X не удовлетворяет Get Y».
func seedObjectGrant(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	acc domain.AccountID, role, binding, subjectID, objectType, objectID string) {
	t.Helper()
	catalog := authzmap.CatalogTypeName(objectType)
	mustExec(t, ctx, pool,
		`INSERT INTO kacho_iam.roles (id, account_id, name, permissions)
		 VALUES ($1, $2, $3, '["iam.project.*.get"]'::jsonb)`, role, string(acc), role)
	mustExec(t, ctx, pool,
		`INSERT INTO kacho_iam.role_verb (role_id, object_type, verb) VALUES ($1, $2, 'get')`,
		role, catalog)
	mustExec(t, ctx, pool,
		`INSERT INTO kacho_iam.role_rule_selectors
		   (role_id, rule_fp, arm, object_types, match_labels)
		 VALUES ($1, 'fp-obj', 'anchor', ARRAY[$2::text], '{}'::jsonb)`, role, catalog)
	mustExec(t, ctx, pool,
		`INSERT INTO kacho_iam.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		 VALUES ($1, 'user', $2, $3, $4, $5, 'ACTIVE')`,
		binding, subjectID, role, objectType, objectID)
	mustExec(t, ctx, pool,
		`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ($1, 'user', $2)`, binding, subjectID)
}

// pointerThroughJournal кладёт отношение ЧЕРЕЗ ЖУРНАЛ — тем же путём, каким его
// кладёт продукт, — и утверждает, что триггер его спроецировал. Без последнего
// «право не сработало» было бы неотличимо от «фикстура ничего не посеяла».
func pointerThroughJournal(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	objectType, objectID, relation, subject string) {
	t.Helper()
	mustExec(t, ctx, pool,
		`INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
		 VALUES ('fga.tuple.write',
		         jsonb_build_object('user', $1::text, 'relation', $2::text,
		                            'object', $3::text || ':' || $4::text),
		         now())`,
		subject, relation, objectType, objectID)
	var landed int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*)::int FROM kacho_iam.relation_fact
		  WHERE object_type = $1 AND object_id = $2 AND relation = $3 AND subject = $4`,
		objectType, objectID, relation, subject).Scan(&landed))
	require.Equalf(t, 1, landed,
		"строка журнала %s:%s --%s--> %s не спроецировалась в прямой факт — фикстура ничего "+
			"не посеяла", objectType, objectID, relation, subject)
}

func mustExec(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	_, err := pool.Exec(ctx, sql, args...)
	require.NoErrorf(t, err, "посев (%s)", sql)
}

// ── контекст вызывающего ──────────────────────────────────────────────────────

func ctxUser(id domain.UserID) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: string(id)})
}

func ctxAnon() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "anonymous"})
}

func requireNotFound(t *testing.T, err error, msg string) {
	t.Helper()
	require.Error(t, err, msg)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.NotFound, st.Code(), "%s — must hide existence (NotFound, not PermissionDenied)", msg)
}

// ── Account.Get ──────────────────────────────────────────────────────────────

func TestReadAuthz_Account_VGet(t *testing.T) {
	f := newReadAuthzFixture(t)
	uc := accountapp.NewGetAccountUseCase(f.repo).WithRelationStore(f.gates)

	t.Run("owner_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.ownerID), f.accID)
		require.NoError(t, err, "owner holds v_get → ALLOW")
		require.Equal(t, f.accID, got.ID)
	})
	t.Run("granted_invitee_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.inviteeID), f.accID)
		require.NoError(t, err, "granted v_get invitee → ALLOW (was 404)")
		require.Equal(t, f.accID, got.ID)
	})
	t.Run("cluster_admin_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.clusterID), f.accID)
		require.NoError(t, err, "cluster-admin short-circuit → ALLOW any object")
		require.Equal(t, f.accID, got.ID)
	})
	t.Run("stranger_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.strangerID), f.accID)
		requireNotFound(t, err, "stranger (no v_get) → hide")
	})
	t.Run("anon_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxAnon(), f.accID)
		requireNotFound(t, err, "anonymous → hide (fail-closed)")
	})
}

// ── Project.Get ──────────────────────────────────────────────────────────────

func TestReadAuthz_Project_VGet(t *testing.T) {
	f := newReadAuthzFixture(t)
	uc := projectapp.NewGetProjectUseCase(f.repo).WithRelationStore(f.gates)

	t.Run("owner_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.ownerID), f.projID)
		require.NoError(t, err)
		require.Equal(t, f.projID, got.ID)
	})
	t.Run("granted_invitee_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.inviteeID), f.projID)
		require.NoError(t, err, "granted v_get invitee → ALLOW")
		require.Equal(t, f.projID, got.ID)
	})
	t.Run("cluster_admin_ALLOW", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.clusterID), f.projID)
		require.NoError(t, err)
	})
	t.Run("stranger_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.strangerID), f.projID)
		requireNotFound(t, err, "stranger → hide (project was over-exposed pre-fix: authenticated-pass-through)")
	})
	t.Run("anon_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxAnon(), f.projID)
		requireNotFound(t, err, "anonymous → hide")
	})
}

// ── User.Get ─────────────────────────────────────────────────────────────────

func TestReadAuthz_User_VGet(t *testing.T) {
	f := newReadAuthzFixture(t)
	ctx := context.Background()
	uc := userapp.NewGetUserUseCase(f.repo).WithRelationStore(f.gates)

	t.Run("owner_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.ownerID), f.userID)
		require.NoError(t, err)
		require.Equal(t, f.userID, got.ID)
	})
	t.Run("self_ALLOW", func(t *testing.T) {
		// Пользователь читает САМ СЕБЯ. Это не выдача, а структурный факт: модель
		// выводит `iam_user.v_get … or subject`, и отношение `subject` на своём
		// объекте кладёт сам продукт при заведении пользователя
		// (apps/kacho/api/user/internal_upsert.go). Сеется тем же журналом, чтобы
		// проба не описывала состояние, которого продукт не производит.
		pointerThroughJournal(t, ctx, f.pool, "iam_user", string(f.userID),
			"subject", "user:"+string(f.userID))
		got, err := uc.Execute(ctxUser(f.userID), f.userID)
		require.NoError(t, err, "self → ALLOW")
		require.Equal(t, f.userID, got.ID)
	})
	t.Run("granted_invitee_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.inviteeID), f.userID)
		require.NoError(t, err, "granted v_get invitee → ALLOW")
		require.Equal(t, f.userID, got.ID)
	})
	t.Run("cluster_admin_ALLOW", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.clusterID), f.userID)
		require.NoError(t, err)
	})
	t.Run("stranger_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.strangerID), f.userID)
		requireNotFound(t, err, "stranger → hide")
	})
	t.Run("anon_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxAnon(), f.userID)
		requireNotFound(t, err, "anonymous → hide")
	})
}

// ── Group.Get ────────────────────────────────────────────────────────────────

func TestReadAuthz_Group_VGet(t *testing.T) {
	f := newReadAuthzFixture(t)
	uc := groupapp.NewGetGroupUseCase(f.repo).WithRelationStore(f.gates)

	t.Run("owner_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.ownerID), f.groupID)
		require.NoError(t, err)
		require.Equal(t, f.groupID, got.ID)
	})
	t.Run("granted_invitee_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.inviteeID), f.groupID)
		require.NoError(t, err, "granted v_get invitee → ALLOW")
		require.Equal(t, f.groupID, got.ID)
	})
	t.Run("cluster_admin_ALLOW", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.clusterID), f.groupID)
		require.NoError(t, err)
	})
	t.Run("stranger_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.strangerID), f.groupID)
		requireNotFound(t, err, "stranger → hide")
	})
	t.Run("anon_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxAnon(), f.groupID)
		requireNotFound(t, err, "anonymous → hide")
	})
}

// ── ServiceAccount.Get ───────────────────────────────────────────────────────

func TestReadAuthz_ServiceAccount_VGet(t *testing.T) {
	f := newReadAuthzFixture(t)
	uc := saapp.NewGetServiceAccountUseCase(f.repo).WithRelationStore(f.gates)

	t.Run("owner_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.ownerID), f.saID)
		require.NoError(t, err)
		require.Equal(t, f.saID, got.ID)
	})
	t.Run("granted_invitee_ALLOW", func(t *testing.T) {
		got, err := uc.Execute(ctxUser(f.inviteeID), f.saID)
		require.NoError(t, err, "granted v_get invitee → ALLOW")
		require.Equal(t, f.saID, got.ID)
	})
	t.Run("cluster_admin_ALLOW", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.clusterID), f.saID)
		require.NoError(t, err)
	})
	t.Run("stranger_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxUser(f.strangerID), f.saID)
		requireNotFound(t, err, "stranger → hide")
	})
	t.Run("anon_hide", func(t *testing.T) {
		_, err := uc.Execute(ctxAnon(), f.saID)
		requireNotFound(t, err, "anonymous → hide")
	})
}

// ── Враждебная: выдача, названная ОДНИМ типом, не открывает другие ───────────
//
// Здесь стояло «v_get на X не удовлетворяет Get на Y (пообъектно)»: вызывающему
// клали прямой глагольный кортеж на аккаунт и требовали, чтобы проект,
// пользователь, группа и учётка внутри него остались скрыты.
//
// Утверждение переформулировано, потому что его прежняя посылка была свойством
// СНЯТОГО механизма, а не контракта. Пообъектный глагольный кортеж своя база не
// производит вовсе; право приходит ВЫДАЧЕЙ, а выдача по построению действует на
// свою область и всё, что под ней, — это её смысл, а не утечка. Требовать от
// выдачи на аккаунт «не доставать до содержимого» значило бы требовать
// поведения, которого контракт не обещает и обещать не должен.
//
// Живое и проверяемое здесь другое, и оно того же рода: выдача ограничена НЕ
// только областью, но и НАБОРОМ ТИПОВ, которые называет её роль. Роль ниже
// проецирует глагол `get` только на `account`, поэтому вызывающий читает аккаунт
// и не читает НИ ОДИН объект внутри него — при том что область выдачи их
// покрывает. Расширение набора типов роли — единственный путь открыть их, и он
// виден в самой выдаче.
func TestReadAuthz_Adversarial_GrantNamingOneTypeDoesNotOpenAnother(t *testing.T) {
	f := newReadAuthzFixture(t)
	ctx := context.Background()

	caller := f.strangerID
	seedObjectGrant(t, ctx, f.pool, f.accID, "rolacconly", "abnacconly",
		string(caller), "account", string(f.accID))

	t.Run("account_ALLOW", func(t *testing.T) {
		uc := accountapp.NewGetAccountUseCase(f.repo).WithRelationStore(f.gates)
		_, err := uc.Execute(ctxUser(caller), f.accID)
		require.NoError(t, err, "выдача, называющая тип account, обязана открыть сам аккаунт")
	})
	t.Run("project_hide", func(t *testing.T) {
		uc := projectapp.NewGetProjectUseCase(f.repo).WithRelationStore(f.gates)
		_, err := uc.Execute(ctxUser(caller), f.projID)
		requireNotFound(t, err, "роль называет только `account` — проект внутри области выдачи "+
			"обязан остаться скрытым")
	})
	t.Run("user_hide", func(t *testing.T) {
		uc := userapp.NewGetUserUseCase(f.repo).WithRelationStore(f.gates)
		_, err := uc.Execute(ctxUser(caller), f.userID)
		requireNotFound(t, err, "роль называет только `account` — пользователь внутри области "+
			"выдачи обязан остаться скрытым")
	})
	t.Run("group_hide", func(t *testing.T) {
		uc := groupapp.NewGetGroupUseCase(f.repo).WithRelationStore(f.gates)
		_, err := uc.Execute(ctxUser(caller), f.groupID)
		requireNotFound(t, err, "роль называет только `account` — группа внутри области выдачи "+
			"обязана остаться скрытой")
	})
	t.Run("sa_hide", func(t *testing.T) {
		uc := saapp.NewGetServiceAccountUseCase(f.repo).WithRelationStore(f.gates)
		_, err := uc.Execute(ctxUser(caller), f.saID)
		requireNotFound(t, err, "роль называет только `account` — служебная учётка внутри области "+
			"выдачи обязана остаться скрытой")
	})
}

// ── seed helpers ─────────────────────────────────────────────────────────────

func seedUserWithAccount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) domain.UserID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		string(uid), string(accID), "ext-"+suffix+"-"+string(uid),
		"u-"+suffix+"@example.com", "User "+suffix)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID), "acc-"+suffix+"-"+string(accID)[len(accID)-6:], string(uid))
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return uid
}

func accountOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, owner domain.UserID) domain.AccountID {
	t.Helper()
	var accID string
	err := pool.QueryRow(ctx, `SELECT id FROM accounts WHERE owner_user_id = $1`, string(owner)).Scan(&accID)
	require.NoError(t, err)
	return domain.AccountID(accID)
}

func seedUserInAccount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID domain.AccountID, suffix string) domain.UserID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err := pool.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		string(uid), string(accID), "ext-"+suffix+"-"+string(uid),
		"u-"+suffix+"-"+string(uid)[len(uid)-6:]+"@example.com", "User "+suffix)
	require.NoError(t, err)
	return uid
}

func seedProject(t *testing.T, ctx context.Context, repo *kachopg.Repository, accID domain.AccountID, name string) domain.ProjectID {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, err := w.ProjectsW().Insert(ctx, domain.Project{
		ID:        domain.ProjectID(ids.NewID(domain.PrefixProject)),
		AccountID: accID,
		Name:      domain.ProjectName(name),
		Labels:    domain.Labels{},
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return out.ID
}

func seedGroup(t *testing.T, ctx context.Context, repo *kachopg.Repository, accID domain.AccountID, name string) domain.GroupID {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, err := w.GroupsW().Insert(ctx, domain.Group{
		ID:        domain.GroupID(ids.NewID(domain.PrefixGroup)),
		AccountID: accID,
		Name:      domain.GroupName(name),
		Labels:    domain.Labels{},
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return out.ID
}

func seedServiceAccount(t *testing.T, ctx context.Context, repo *kachopg.Repository, accID domain.AccountID, name string) domain.ServiceAccountID {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, err := w.ServiceAccountsW().Insert(ctx, domain.ServiceAccount{
		ID:        domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount)),
		AccountID: accID,
		Name:      domain.SvcAccountName(name),
		Enabled:   true,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return out.ID
}
