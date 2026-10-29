// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// fga_symmetric_test.go — регрессионная проба симметрии выдачи и отзыва.
//
// Контракт: прод-путь заявляет кортежи через EmitRelationWrite /
// EmitRelationDelete В ТРАНЗАКЦИИ ПИСАТЕЛЯ. Create и Delete заявляют одинаковые
// наборы кортежей, так что выдача и отзыв побайтно симметричны: отзыв, снявший не
// тот набор, что добавила выдача, оставил бы доступ либо отнял бы невыданный.
//
// # Что теперь значит «в транзакции писателя» и почему файл лишился второй половины
//
// Журнал `kaname.fga_outbox` прежде был очередью «хотя бы раз» к ВНЕШНЕМУ движку
// отношений и дренировался асинхронно. Дренаж отставал, поэтому use-case вдобавок
// СИНХРОННО снимал тот же набор с движка после фиксации — через
// clients.RelationStore.DeleteTuples, и этот файл утверждал обе
// половины.
//
// Этап S6 снял движок. Журнал остался и сменил роль: триггер базы
// (`relation_fact_follows_journal`, миграции 0098/0100) сворачивает каждую строку
// журнала в `kaname.relation_fact` — таблицу, из которой читается вердикт, — В ТОЙ
// ЖЕ ТРАНЗАКЦИИ, что INSERT. Значит, отзыв действует с фиксации, а это раньше и
// строже, чем «синхронно, сразу после фиксации»; а порт, через который
// утверждалась вторая половина, DeleteTuples больше не несёт вовсе.
//
// Оставленные, те утверждения стали бы истинны по устройству самого типа дублёра:
// без метода, который можно позвать, «набор не снят» никогда не покраснел бы по
// причине в продукте. Они сняты, причина записана здесь, а не стёрта, и осталась
// та половина, у которой есть производитель, — набор, заявленный в транзакции писателя.
//
// Проба НЕ использует testcontainers (Postgres не нужен). Она провязывает дублёры
// в памяти для Repository и operations.Repo, проводит полный круг Create→Delete
// через оба use-case и утверждает:
//
//  1. Create заявляет ≥2 кортежей (отношение роли + иерархия для привязки к проекту).
//  2. Delete заявляет ровно тот же набор (выдача отозвана целиком).
//  3. Для привязки к аккаунту: Create заявляет 2 кортежа (отношение роли +
//     иерархия родителя-аккаунта), Delete — тот же набор.

import (
	"context"
	stderrors "errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab_repo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	acct_repo "github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	gdrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/grant_delegation"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	proj_repo "github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
	role_repo "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	sa_repo "github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
	user_repo "github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// ─── Симметрия выдачи и отзыва FGA ─────────────────────────────────────────

// TestFGASymmetric_CreateWritesTuples_DeleteRevokesSameSet утверждает контракт
// эмиссии в транзакции: набор кортежей, заявленный Create (EmitRelationWrite),
// побайтно совпадает с набором, заявленным Delete (EmitRelationDelete). Проекцию
// этих строк в таблицу фактов, из которой читается вердикт, проверяет на
// настоящем Postgres интеграционный набор relverdict.
func TestFGASymmetric_CreateWritesTuples_DeleteRevokesSameSet(t *testing.T) {
	const (
		roleID     = "rol_viewer_test_001-"
		roleName   = "kaname.view" // прежнее имя оставлено для контекста; сопоставление идёт по permissions
		subjectID  = "usr_test_subject----"
		resourceID = "prj_test_project----"
		ownerID    = "usr_test_owner------"
		accountID  = "acc_test_account----"
	)

	// Permissions класса наблюдателя → отношение "viewer" через PermissionsToRelations.
	perms := domain.Permissions{"iam.access_bindings.get", "iam.access_bindings.list"}
	repo := newABFakeRepo(ownerID, accountID, resourceID, roleID, roleName, perms)
	opsRepo := newFakeOpsRepo()
	fga := newRecordingFGA() // провязан через WithRelationStore: сторона ЧТЕНИЯ (полномочие выдачи)

	// Контекст с владельцем аккаунта как принципалом → requireGrantAuthority пропускает.
	ctx := newOwnerContext(ownerID)

	// ── Create ────────────────────────────────────────────────────────────────
	createUC := NewCreateAccessBindingUseCase(repo, opsRepo, catalogfixture.Source()).
		WithRelationStore(fga, nil)

	binding := domain.AccessBinding{
		SubjectType:  "user",
		SubjectID:    domain.SubjectID(subjectID),
		RoleID:       domain.RoleID(roleID),
		ResourceType: "project",
		ResourceID:   resourceID,
	}
	opCreate, err := createUC.Execute(ctx, binding)
	require.NoError(t, err, "Create.Execute must succeed")
	require.NotNil(t, opCreate)

	// Ожидание асинхронного исполнителя.
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx), "async Create worker must complete")

	// Строки журнала, захваченные дублёром интерфейса писателя.
	writtenTuples := repo.drainFGAWritten()
	require.GreaterOrEqual(t, len(writtenTuples), 2,
		"Create must state ≥2 journal tuples (role-relation + hierarchy)")

	// Проверка кортежа отношения роли.
	assert.Contains(t, writtenTuples, ab_repo.RelationTuple{
		User:     "user:" + subjectID,
		Relation: "viewer",
		Object:   "project:" + resourceID,
	}, "Create must state the role-relation tuple in the journal")

	// Проверка кортежа иерархии (нужен каскаду authz для Get/Delete).
	abID := repo.lastInsertedID()
	require.NotEmpty(t, abID, "repo must record the inserted AB id")
	assert.Contains(t, writtenTuples, ab_repo.RelationTuple{
		User:     "project:" + resourceID,
		Relation: "project",
		Object:   "iam_access_binding:" + string(abID),
	}, "Create must state the hierarchy tuple in the journal")

	// ── Delete ────────────────────────────────────────────────────────────────
	deleteUC := NewDeleteAccessBindingUseCase(repo, opsRepo).
		WithRelationStore(fga, nil)

	subjectCtx := newOwnerContext(subjectID)
	opDelete, err := deleteUC.Execute(subjectCtx, abID)
	require.NoError(t, err, "Delete.Execute must succeed")
	require.NotNil(t, opDelete)

	waitCtx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	require.NoError(t, operations.Wait(waitCtx2), "async Delete worker must complete")

	deletedTuples := repo.drainFGADeleted()

	require.Equal(t, len(writtenTuples), len(deletedTuples),
		"Delete must state the same number of journal tuples as Create did")

	for _, w := range writtenTuples {
		assert.Contains(t, deletedTuples, w,
			"Delete must state revoke tuple {User:%q Relation:%q Object:%q}",
			w.User, w.Relation, w.Object)
	}
}

// TestFGASymmetric_AccountBinding_RoleRelationAndHierarchyTuple —
// привязки к аккаунту заявляют в журнале кортеж отношения роли ПЛЮС кортеж
// иерархии с родителем `account`, чтобы каскад модели `viewer from account`
// делал объект привязки читаемым для владельца аккаунта (Get/List/Delete). Без
// кортежа иерархии каждая привязка к аккаунту отвечала на чтение 403 (каскад
// iam-access-binding в newman-e2e).
func TestFGASymmetric_AccountBinding_RoleRelationAndHierarchyTuple(t *testing.T) {
	const (
		roleID    = "rol_admin_test_002--"
		roleName  = "admin"
		subjectID = "usr_test_admin------"
		resID     = "acc_target_account--"
		ownerID   = "usr_test_owner------"
		accountID = "acc_test_account----"
	)

	// Permissions класса администратора → отношение "admin". Permission НАЗЫВАЕТ
	// аккаунт намеренно: уровень 3 на якоре-аккаунте эмитируется, лишь когда роль
	// покрывает iam.account, потому что account:<A>#admin — источник каскада (см.
	// tuples.go::capSynthesizedAccountAdmin). Предмет пробы — симметрия
	// эмитированного набора при создании и удалении, поэтому ей нужен сильнейший
	// ярус — записанный автором, а не синтезированный.
	perms := domain.Permissions{"iam.account.admin"}
	repo := newABFakeRepo(ownerID, accountID, resID, roleID, roleName, perms)
	opsRepo := newFakeOpsRepo()
	fga := newRecordingFGA()
	ctx := newOwnerContext(ownerID)

	createUC := NewCreateAccessBindingUseCase(repo, opsRepo, catalogfixture.Source()).WithRelationStore(fga, nil)
	binding := domain.AccessBinding{
		SubjectType:  "user",
		SubjectID:    domain.SubjectID(subjectID),
		RoleID:       domain.RoleID(roleID),
		ResourceType: "account", // якорь-аккаунт — заявляет собственный указатель на родителя `account`
		ResourceID:   resID,
	}
	_, err := createUC.Execute(ctx, binding)
	require.NoError(t, err)
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx))

	written := repo.drainFGAWritten()
	require.Len(t, written, 2,
		"account-scoped binding: role-relation tuple + account-parent hierarchy tuple")
	assert.Contains(t, written, ab_repo.RelationTuple{
		User:     "user:" + subjectID,
		Relation: "admin",
		Object:   "account:" + resID,
	}, "must state the role-relation tuple")
	assert.Contains(t, written, ab_repo.RelationTuple{
		User:     "account:" + resID,
		Relation: "account",
		Object:   "iam_access_binding:" + string(repo.lastInsertedID()),
	}, "must state the account-parent hierarchy tuple (cascade readability)")

	deleteUC := NewDeleteAccessBindingUseCase(repo, opsRepo).WithRelationStore(fga, nil)
	subjectCtx := newOwnerContext(subjectID)
	_, err = deleteUC.Execute(subjectCtx, repo.lastInsertedID())
	require.NoError(t, err)
	waitCtx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	require.NoError(t, operations.Wait(waitCtx2))

	deleted := repo.drainFGADeleted()
	require.Equal(t, written, deleted, "Delete must state the same single tuple Create stated")
}

// ─── заглушка хранилища отношений ────────────────────────────────────────────

// recordingFGA — clients.RelationStore для стороны ЧТЕНИЯ этих use-case:
// requireGrantAuthority спрашивает его, вправе ли вызывающий выдать это право, и
// он отвечает «да», чтобы фикстура прошла ворота и дошла до предмета пробы.
//
// # Он больше ничего не записывает, а имя расходится с этим, и это изменение его не меняло
//
// Он нёс WriteTuples/DeleteTuples с переданными наборами, потому что их объявлял
// clients.RelationStore: порт стоял за ЧУЖИМ хранилищем, и отзыв доходил до этого
// хранилища через него. Этап S6 снял внешний движок; у порта остался лишь вопрос
// (Check). Писать больше некуда: выдача становится ответом в ТОЙ ЖЕ ФИКСАЦИИ, что
// её записывает (журнал → триггер `relation_fact_follows_journal` → `relation_fact`).
//
// Записывающая сторона снята, а не оставлена. Метод, стоящий за несуществующим
// больше методом порта, некому звать: исполнить его нечем, значит, никакое
// утверждение о нём не покраснеет по причине в продукте, а дублёр, который его
// предлагает, выглядит стоящим за более широкой поверхностью, чем на деле.
//
// ИМЯ осталось, потому что этот тип или его конструктор называют восемь файлов
// пакета, и они не предмет этого изменения; переименование здесь правило бы их.
// Ложным было то, что тип ДЕЛАЛ, — это и исправлено, а расхождение записано, а не
// оставлено на открытие следующему читателю.
type recordingFGA struct{}

func newRecordingFGA() *recordingFGA { return &recordingFGA{} }

func (r *recordingFGA) Check(_ context.Context, _, _, _ string) (bool, error) { return true, nil }

var _ clients.RelationStore = (*recordingFGA)(nil)

// ─── поддельный Repository в памяти ──────────────────────────────────────────

type abFakeRepo struct {
	mu              sync.Mutex
	ownerUserID     string
	accountID       string
	projectID       string
	roleID          string
	roleName        string
	rolePermissions domain.Permissions
	// roleRules — если задано, поддельный Roles().Get отдаёт роль ПРАВИЛ (модель
	// правил RBAC), чтобы создание и сверка шли путём эмиссии scope_grant по
	// типу (rulesBindingTuples), а не прежним схлопыванием всей роли в якорь.
	// Пусто ⇒ прежняя роль из одних permissions.
	roleRules domain.Rules
	ab        *domain.AccessBinding // последняя вставленная
	// Захваченные кортежи журнала (`kaname.fga_outbox`), эмитированные в
	// транзакции, — строки, которые триггер сворачивает в `kaname.relation_fact`
	// в той же транзакции.
	fgaWritten []ab_repo.RelationTuple
	fgaDeleted []ab_repo.RelationTuple
	// Захваченные события соответствия audit_outbox, эмитированные в транзакции писателя.
	auditEvents []ab_repo.AuditEvent
	// groupMembers — хранилище за адаптером IsMember.
	// Ключ карты: "<groupID>|<memberType>|<memberID>". Наличие ⇒ членство.
	// Меняют его помощники проб AddGroupMember / removeGroupMember.
	groupMembers map[string]struct{}
	// lbaRows — фикстурные строки ListByAccount. Засеваются
	// seedABListByAccount; используются unit-пробами ListByAccountUseCase.
	lbaRows []domain.AccessBinding
	// lbrRows — фикстурные строки ListByRole. Засевается seedABListByRole;
	// используется пробами стоимости страницы (kacho#2054). Пусто ⇒ читается
	// одиночная `ab`, как было, поэтому существующие пробы не задеты.
	lbrRows []domain.AccessBinding
	// lbsRows — фикстурные строки ListByScope. Засеваются seedABListByScope;
	// используются unit-пробами нижней границы объединения viewer ∪ v_list. Они же —
	// исходные строки дублёра единого List.
	lbsRows []domain.AccessBinding
	// lbsubRows — фикстурные строки чтения ListBySubject. Засеваются
	// seedABListBySubject. До kacho#1352 это чтение отдавало пустоту всегда, и дублёр
	// отвечал тем же — на пустом ответе сужение утверждать нечем: «чужого нет»
	// зеленело бы на полностью сломанной полосе.
	lbsubRows []domain.AccessBinding
	// lastListFilter — ListFilter, последним полученный единым List (пробы F11
	// утверждают спуск VisibleIDs из use-case и сопоставление предиката).
	lastListFilter ab_repo.ListFilter
	// projectAccounts — проект → аккаунт, которому он принадлежит. Питает фан-аут
	// `List(account_id)` в дублёре (rowInAccountScope). Пусто ⇒ ни один проект
	// ни в каком аккаунте, и это намеренно строгое умолчание.
	projectAccounts map[string]string
	// materializedAt — фикстура ведомости сверщика, на которой стоит
	// ListMaterializedAtForBindings (AccessBinding.materialized_at). Засевается
	// seedMaterializedAt; о незасеянной привязке не сообщается ничего (= ещё не действует).
	materializedAt map[domain.AccessBindingID]time.Time
	// lastByScopeType / lastByScopeID — якорь области, последним полученный ListByScope.
	// Обработчик сводит канонический `scope_type` с точкой (или прежний голый
	// `resource_type`) к голому виду внутри службы ДО use-case, и эти поля
	// закрепляют это сведение (scope_coordinate_test.go).
	lastByScopeType domain.ResourceType
	lastByScopeID   string
	// reconcileObjs — id объектов, для которых в транзакции писателя эмитировано
	// событие сверки (совместная фиксация меток). Выбираются drainReconcileObjects.
	reconcileObjs []string
	// users / serviceAccounts / groups — хранилище id→accountID за поддельными
	// читателями Users()/ServiceAccounts()/Groups() (существование и
	// домашний аккаунт для ListSubjectPrivileges). Нет записи ⇒ ErrNotFound.
	users           map[string]string
	serviceAccounts map[string]string
	groups          map[string]string
	// spRows — фикстурные строки AccessBindings().ListSubjectPrivileges.
	// Засеваются seedSubjectPrivileges; используются пробами ListSubjectPrivilegesUseCase.
	spRows []domain.SubjectPrivilege
	// roleIsCustom — при true поддельный Roles().Get отдаёт ПОЛЬЗОВАТЕЛЬСКУЮ роль
	// (IsSystem=false, AccountID=accountID), чтобы ворота Role.Update — полномочие
	// владельца аккаунта и назначаемость — пропускали (пробы веера сверки).
	roleIsCustom bool
	// roleSegmentsAnswered — дублёр отвечает на вопрос о сегментах роли «держится
	// всё» (kaname#76). Ставят его ТОЛЬКО пробы, зовущие эхо правки роли: эхо
	// несёт признак превью и спрашивает его в транзакции правки. Прочим пробам
	// вопрос не предмет, и дублёр по умолчанию отказывает.
	roleSegmentsAnswered bool
	// abSubjects — хранилище access_binding_subjects с ключом
	// id привязки → упорядоченные субъекты. Меняют его InsertSubjects/DeleteSubject.
	abSubjects map[domain.AccessBindingID][]domain.Subject
	// forceGetErr — если задано, fakeABRdr.Get безусловно отдаёт эту ошибку
	// вместо обычного поиска «найдено / не найдено». Использует его
	// get_error_mapping_test.go, чтобы имитировать преходящий (не «не найдено»)
	// отказ Reader на Get проверки существования в Update/Delete.
	forceGetErr error
	// membersOfGroupsErr — отказ чтения состава групп. Ручка нужна, потому что
	// «полнота перечисления» держится ТОЛЬКО тем, что отказ соседа отказывает
	// запросу: проглоченный отказ даёт тихо усечённый ответ, неотличимый от
	// честного «в группах никого» (kacho#914).
	membersOfGroupsErr error
	// groupsReaderNil — непровязанный читатель групп. Отдельная полоса от
	// отказа: «мне нечем ответить» и «ответ пуст» — разные факты, и второй не
	// вправе производиться первым.
	groupsReaderNil bool
	// incompleteGroups — перечень групп, чей состав дублёр объявляет неполным.
	// Настоящий читатель объявляет это, упершись в предел выборки; дублёру
	// предел ни к чему, а признак нужен — иначе путь его переноса не проверен.
	incompleteGroups []domain.GroupID
	// emittedTuples — хранимый точный эмитированный набор каждой привязки
	// (access_binding_emitted_tuples) с ключом id привязки. Совместная фиксация
	// кортежей выдачи здесь позволяет отзыву и Role.Update брать хранимый набор
	// (а не выводить заново из изменчивой роли). У кортежа семантика множества
	// (без повторов), но ПОРЯДОК ВСТАВКИ при чтении сохраняется: настоящий repo
	// на pg отдаёт детерминированный `ORDER BY relation, object, fga_user`, и
	// контракт симметричного отзыва — по множеству (проекция журнала применяет
	// множество), однако TestFGASymmetric утверждает побайтное равенство набора
	// записи и набора удаления. Порядок вставки делает SelectEmittedTuples
	// детерминированным И равным порядку, захваченному EmitRelationWrite (create.go
	// подаёт ОДИН И ТОТ ЖЕ срез `tuples` в EmitRelationWrite и InsertEmittedTuples),
	// так что круг устойчив по порядку без перемешивания неупорядоченной карты Go.
	// Голый `map[tuple]struct{}` обходится в случайном порядке ⇒ require.Equal
	// мерцает или падает.
	emittedTuples map[domain.AccessBindingID]*orderedTupleSet
	// txOps — упорядоченный след вызовов порта транзакции писателя, несущих
	// контракт сериализации на уровне базы (advisory-lock / чтение ведомости /
	// CAS статуса). Позволяет unit-пробе закрепить ПОРЯДОК этих операторов — именно
	// он делает критическую секцию отзыва свободной от гонок (ban #10), см. revoke_test.go.
	txOps []string
}

// recordTxOp дописывает один вызов порта транзакции писателя в упорядоченный след.
func (r *abFakeRepo) recordTxOp(op string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.txOps = append(r.txOps, op)
}

// resetTxOpTrace сбрасывает записанные до сих пор отметки, чтобы проба, чей
// предмет — ОДНА транзакция, не читала чужую. Без него фикстура, выдающая до
// отзыва, не различит двух транзакций в одном плоском следе.
func (r *abFakeRepo) resetTxOpTrace() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.txOps = nil
}

// txOpTrace отдаёт копию записанного порядка вызовов порта транзакции писателя.
func (r *abFakeRepo) txOpTrace() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.txOps))
	copy(out, r.txOps)
	return out
}

// AddUser — помощник проб. Регистрирует id пользователя с его домашним
// аккаунтом, чтобы поддельный читатель Users() его находил (существование и
// account_id для ворот authz 1.3).
func (r *abFakeRepo) AddUser(userID, accountID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.users == nil {
		r.users = map[string]string{}
	}
	r.users[userID] = accountID
}

// AddServiceAccount — помощник проб. Регистрирует id сервисной учётки с её
// домашним аккаунтом, чтобы поддельный читатель ServiceAccounts() её находил.
func (r *abFakeRepo) AddServiceAccount(saID, accountID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.serviceAccounts == nil {
		r.serviceAccounts = map[string]string{}
	}
	r.serviceAccounts[saID] = accountID
}

// AddGroup — помощник проб. Регистрирует id группы с её домашним аккаунтом,
// чтобы поддельный читатель Groups() её находил (существование и account_id для
// ворот authz 1.3b при subject_type=group).
func (r *abFakeRepo) AddGroup(groupID, accountID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.groups == nil {
		r.groups = map[string]string{}
	}
	r.groups[groupID] = accountID
}

// seedSubjectPrivileges — помощник проб. Заменяет фикстурные строки, которые
// отдаёт поддельный AccessBindings().ListSubjectPrivileges.
func (r *abFakeRepo) seedSubjectPrivileges(rows []domain.SubjectPrivilege) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.spRows = append(r.spRows[:0], rows...)
}

// seedMaterializedAt — помощник проб. Записывает момент, когда пообъектный доступ
// привязки начал действовать, как это сделала бы ведомость сверщика.
func (r *abFakeRepo) seedMaterializedAt(id domain.AccessBindingID, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.materializedAt == nil {
		r.materializedAt = map[domain.AccessBindingID]time.Time{}
	}
	r.materializedAt[id] = at
}

// seedABListByAccount — помощник проб. Заменяет фикстурные строки, которые
// отдаёт поддельный fakeABRdr.ListByAccount.
// seedABListBySubject заменяет фикстурные строки, которые отдаёт поддельный
// ListBySubject.
func seedABListBySubject(r *abFakeRepo, rows []domain.AccessBinding) {
	r.mu.Lock()
	r.lbsubRows = rows
	r.mu.Unlock()
}

func (r *abFakeRepo) seedABListByAccount(rows []domain.AccessBinding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lbaRows = append(r.lbaRows[:0], rows...)
}

// AddGroupMember — помощник проб. Хранит тройку членства, чтобы поиск
// requireGroupMembership в use-case отвечал для этого вызывающего true.
func (r *abFakeRepo) AddGroupMember(groupID, memberType, memberID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.groupMembers == nil {
		r.groupMembers = map[string]struct{}{}
	}
	r.groupMembers[groupID+"|"+memberType+"|"+memberID] = struct{}{}
}

func newABFakeRepo(ownerUserID, accountID, projectID, roleID, roleName string, perms domain.Permissions) *abFakeRepo {
	return &abFakeRepo{
		ownerUserID:     ownerUserID,
		accountID:       accountID,
		projectID:       projectID,
		roleID:          roleID,
		roleName:        roleName,
		rolePermissions: perms,
	}
}

// rowInAccountScope — «эта строка лежит в области названного аккаунта»: либо
// привязана к самому аккаунту, либо к одному из его проектов. Форма ответа —
// та же, что у SQL-предиката настоящего репозитория (accountScopePredicate).
//
// Принадлежность проекта аккаунту берётся из projectAccounts (засевается
// seedProjectAccount). Незасеянный проект НЕ считается принадлежащим аккаунту:
// умолчание «раз не знаю — значит наш» отдало бы строку, которой в ответе быть
// не должно, и проба на исключение чужого зеленела бы по построению.
func (r *abFakeRepo) rowInAccountScope(b domain.AccessBinding, accountID string) bool {
	switch b.ResourceType {
	case "account":
		return b.ResourceID == accountID
	case "project":
		return r.projectAccounts[b.ResourceID] == accountID
	default:
		return false
	}
}

// seedProjectAccount объявляет, какому аккаунту принадлежит проект (фан-аут
// List по account_id). Вызывать ДО чтения: карта читается под тем же mutex.
func seedProjectAccount(repo *abFakeRepo, projectID, accountID string) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.projectAccounts == nil {
		repo.projectAccounts = map[string]string{}
	}
	repo.projectAccounts[projectID] = accountID
}

// drainFGAWritten — захваченные эмиссии выдачи в fga_outbox с прошлой выборки.
func (r *abFakeRepo) drainFGAWritten() []ab_repo.RelationTuple {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ab_repo.RelationTuple, len(r.fgaWritten))
	copy(out, r.fgaWritten)
	r.fgaWritten = nil
	return out
}

// drainFGADeleted — захваченные эмиссии отзыва в fga_outbox с прошлой выборки.
func (r *abFakeRepo) drainFGADeleted() []ab_repo.RelationTuple {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ab_repo.RelationTuple, len(r.fgaDeleted))
	copy(out, r.fgaDeleted)
	r.fgaDeleted = nil
	return out
}

// drainAuditEvents — захваченные события соответствия audit_outbox с прошлой выборки.
func (r *abFakeRepo) drainAuditEvents() []ab_repo.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ab_repo.AuditEvent, len(r.auditEvents))
	copy(out, r.auditEvents)
	r.auditEvents = nil
	return out
}

func (r *abFakeRepo) lastInsertedID() domain.AccessBindingID {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ab == nil {
		return ""
	}
	return r.ab.ID
}

func (r *abFakeRepo) Reader(_ context.Context) (kanamerepo.Reader, error) {
	return &abFakeReader{repo: r}, nil
}
func (r *abFakeRepo) Writer(_ context.Context) (kanamerepo.Writer, error) {
	return &abFakeWriter{abFakeReader: abFakeReader{repo: r}}, nil
}
func (r *abFakeRepo) Close() {}

var _ kanamerepo.Repository = (*abFakeRepo)(nil)

// abFakeReader реализует kanamerepo.Reader.
type abFakeReader struct{ repo *abFakeRepo }

func (rd *abFakeReader) Accounts() acct_repo.ReaderIface      { return &fakeAcctRdr{repo: rd.repo} }
func (rd *abFakeReader) Projects() proj_repo.ReaderIface      { return &fakeProjRdr{repo: rd.repo} }
func (rd *abFakeReader) Users() user_repo.ReaderIface         { return &fakeUserRdr{repo: rd.repo} }
func (rd *abFakeReader) ServiceAccounts() sa_repo.ReaderIface { return &fakeSARdr{repo: rd.repo} }
func (rd *abFakeReader) Groups() group.ReaderIface {
	rd.repo.mu.Lock()
	nilReader := rd.repo.groupsReaderNil
	rd.repo.mu.Unlock()
	if nilReader {
		return nil
	}
	return &fakeGroupRdr{repo: rd.repo}
}
func (rd *abFakeReader) Roles() role_repo.ReaderIface        { return &fakeRoleRdr{repo: rd.repo} }
func (rd *abFakeReader) AccessBindings() ab_repo.ReaderIface { return &fakeABRdr{repo: rd.repo} }
func (rd *abFakeReader) Commit(_ context.Context) error      { return nil }
func (rd *abFakeReader) Rollback(_ context.Context) error    { return nil }

// abFakeWriter реализует kanamerepo.Writer.
type abFakeWriter struct {
	abFakeReader
}

func (w *abFakeWriter) AccountsW() acct_repo.WriterIface                         { return nil }
func (w *abFakeWriter) ProjectsW() proj_repo.WriterIface                         { return nil }
func (w *abFakeWriter) UsersW() user_repo.WriterIface                            { return nil }
func (w *abFakeWriter) ServiceAccountsW() sa_repo.WriterIface                    { return nil }
func (w *abFakeWriter) GroupsW() group.WriterIface                               { return nil }
func (w *abFakeWriter) RolesW() role_repo.WriterIface                            { return &fakeRoleWtr{repo: w.repo} }
func (w *abFakeWriter) AccessBindingsW() ab_repo.WriterIface                     { return &fakeABWtr{repo: w.repo} }
func (w *abFakeWriter) EmitAuditEvent(context.Context, service.AuditEvent) error { return nil }
func (w *abFakeWriter) EmitFGARelationWrite(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *abFakeWriter) EmitFGARelationDelete(context.Context, []service.RelationTuple) error {
	return nil
}
func (w *abFakeWriter) AdvisoryXactLock(_ context.Context, key string) error {
	w.repo.recordTxOp("advisory_xact_lock:" + key)
	return nil
}

// Commit закрывает транзакцию писателя и ставит отметку в след, чтобы проба
// отличала заявленное ВНУТРИ транзакции от случившегося после неё.
// abFakeReader.Commit перекрыт намеренно: фиксация читателя — не та граница, о
// которой здесь что-либо утверждается.
func (w *abFakeWriter) Commit(_ context.Context) error {
	w.repo.recordTxOp("commit")
	return nil
}

// fakeAcctRdr — читатель аккаунтов; отдаёт Account с заданным владельцем.
type fakeAcctRdr struct{ repo *abFakeRepo }

func (a *fakeAcctRdr) Get(_ context.Context, id domain.AccountID) (domain.Account, error) {
	return domain.Account{
		ID:          id,
		OwnerUserID: domain.UserID(a.repo.ownerUserID),
	}, nil
}
func (a *fakeAcctRdr) List(_ context.Context, _ acct_repo.ListFilter) ([]domain.Account, string, error) {
	return nil, "", nil
}
func (a *fakeAcctRdr) ExistsByName(_ context.Context, _ domain.AccountName) (bool, error) {
	return false, nil
}
func (a *fakeAcctRdr) CountAccountsByOwner(_ context.Context, _ domain.UserID) (int, error) {
	return 0, nil
}

// fakeProjRdr — читатель проектов; отдаёт Project, указывающий на поддельный аккаунт.
type fakeProjRdr struct{ repo *abFakeRepo }

func (p *fakeProjRdr) Get(_ context.Context, id domain.ProjectID) (domain.Project, error) {
	return domain.Project{
		ID:        id,
		AccountID: domain.AccountID(p.repo.accountID),
	}, nil
}
func (p *fakeProjRdr) List(_ context.Context, _ proj_repo.ListFilter) ([]domain.Project, string, error) {
	return nil, "", nil
}
func (p *fakeProjRdr) CountByAccount(_ context.Context, _ domain.AccountID) (int64, error) {
	return 0, nil
}

// fakeRoleRdr — читатель ролей; отдаёт заданную роль по заданному id.
type fakeRoleRdr struct{ repo *abFakeRepo }

func (r *fakeRoleRdr) Get(_ context.Context, id domain.RoleID) (domain.Role, error) {
	r.repo.mu.Lock()
	defer r.repo.mu.Unlock()
	if string(id) == r.repo.roleID {
		// Сопоставление по permissions. Permissions[] заполняется,
		// чтобы PermissionsToRelations мог вывести ярус FGA.
		if r.repo.roleIsCustom {
			// ПОЛЬЗОВАТЕЛЬСКАЯ роль: ею владеет аккаунт, чтобы ворота Role.Update —
			// полномочие владельца аккаунта и назначаемость — пропускали; веер
			// сверки работает с действующими permissions.
			return domain.Role{
				ID:          id,
				Name:        domain.RoleName(r.repo.roleName),
				AccountID:   domain.AccountID(r.repo.accountID),
				IsSystem:    false,
				Permissions: r.repo.rolePermissions,
				Rules:       r.repo.roleRules,
			}, nil
		}
		// По умолчанию — IsSystem, чтобы проверка области
		// (domain.IsRoleAssignable) считала роль назначаемой на любой ресурс:
		// набор о симметрии проверяет симметрию кортежей FGA, а не область роли.
		return domain.Role{
			ID:          id,
			Name:        domain.RoleName(r.repo.roleName),
			ClusterID:   domain.ClusterID(domain.ClusterSingletonID),
			IsSystem:    true,
			Permissions: r.repo.rolePermissions,
			Rules:       r.repo.roleRules,
		}, nil
	}
	// Верность настоящему repo ролей на pg (role_repo.go): отсутствующая роль — это
	// канонический обёрнутый ErrNotFound с текстом контракта, так что ворота
	// use-case, ветвящиеся по iamerr.ErrNotFound, ведут себя как в проде.
	return domain.Role{}, iamerr.Wrapf(iamerr.ErrNotFound, "Role %s not found", id)
}
func (r *fakeRoleRdr) GetWithVersion(ctx context.Context, id domain.RoleID) (domain.Role, string, error) {
	role, err := r.Get(ctx, id)
	return role, "v-fake", err
}
func (r *fakeRoleRdr) List(_ context.Context, _ role_repo.ListFilter) ([]domain.Role, string, error) {
	return nil, "", nil
}
func (r *fakeRoleRdr) ListAssignable(_ context.Context, _, _ string, _ role_repo.ListFilter) ([]domain.Role, string, error) {
	return nil, "", nil
}

// fakeABRdr — читатель access_binding; отдаёт по id последнюю вставленную привязку.
type fakeABRdr struct{ repo *abFakeRepo }

// ListActiveHoldingMembership — предмета этой пробы не касается: она не исключает
// человека из аккаунта. Пустой перечень — ЗАКОННЫЙ ответ (мешающих выдач нет), а
// не заглушка «ответить нечем»: дублёр обязан выполнять контракт настоящего, и
// молчаливо шире его не отвечать.
func (a *fakeABRdr) ListActiveHoldingMembership(context.Context, domain.UserID, domain.AccountID, int) ([]string, int, error) {
	return nil, 0, nil
}

func (a *fakeABRdr) Get(_ context.Context, id domain.AccessBindingID) (domain.AccessBinding, error) {
	a.repo.mu.Lock()
	defer a.repo.mu.Unlock()
	if a.repo.forceGetErr != nil {
		return domain.AccessBinding{}, a.repo.forceGetErr
	}
	if a.repo.ab != nil && a.repo.ab.ID == id {
		return *a.repo.ab, nil
	}
	return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
}
func (a *fakeABRdr) List(_ context.Context, f ab_repo.ListFilter) ([]domain.AccessBinding, string, error) {
	a.repo.mu.Lock()
	defer a.repo.mu.Unlock()
	a.repo.lastListFilter = f
	// Предиката видимости нет: видимость чтения применяет use-case к отданным
	// здесь строкам (internal/authzfilter), как и у repo на pg.
	var out []domain.AccessBinding
	for _, b := range a.repo.lbsRows {
		// AccountID — фан-аут «аккаунт плюс каждый его проект», ровно как в
		// настоящем репозитории. Дублёр обязан выполнять контракт настоящего:
		// пропусти он это поле, проба «поле применено» зеленела бы на
		// реализации, которая его выбрасывает, — то есть подделка была бы
		// снисходительнее продукта ровно там, ради чего её и подставляют.
		if f.AccountID != "" && !a.repo.rowInAccountScope(b, f.AccountID) {
			continue
		}
		if f.SubjectID != "" && string(b.SubjectID) != f.SubjectID {
			continue
		}
		if f.RoleID != "" && string(b.RoleID) != f.RoleID {
			continue
		}
		if f.ScopeType != "" && string(b.ResourceType) != f.ScopeType {
			continue
		}
		if f.ScopeID != "" && b.ResourceID != f.ScopeID {
			continue
		}
		out = append(out, b)
	}
	return out, "", nil
}
func (a *fakeABRdr) ListByScope(_ context.Context, resourceType domain.ResourceType, resourceID string, _ ab_repo.PageFilter) ([]domain.AccessBinding, string, error) {
	a.repo.mu.Lock()
	defer a.repo.mu.Unlock()
	a.repo.lastByScopeType = resourceType
	a.repo.lastByScopeID = resourceID
	if a.repo.lbsRows == nil {
		return nil, "", nil
	}
	out := make([]domain.AccessBinding, len(a.repo.lbsRows))
	copy(out, a.repo.lbsRows)
	return out, "", nil
}
func (a *fakeABRdr) ListBySubject(_ context.Context, _ domain.SubjectType, _ domain.SubjectID, _ ab_repo.PageFilter) ([]domain.AccessBinding, string, error) {
	a.repo.mu.Lock()
	defer a.repo.mu.Unlock()
	if a.repo.lbsubRows == nil {
		return nil, "", nil
	}
	out := make([]domain.AccessBinding, len(a.repo.lbsubRows))
	copy(out, a.repo.lbsubRows)
	return out, "", nil
}
func (a *fakeABRdr) ListByAccount(_ context.Context, _ domain.AccountID, _ ab_repo.AccountPageFilter) ([]domain.AccessBinding, string, error) {
	a.repo.mu.Lock()
	defer a.repo.mu.Unlock()
	if a.repo.lbaRows == nil {
		return nil, "", nil
	}
	out := make([]domain.AccessBinding, len(a.repo.lbaRows))
	copy(out, a.repo.lbaRows)
	return out, "", nil
}

func (a *fakeABRdr) ListSubjectPrivileges(_ context.Context, _ domain.SubjectType, _ domain.SubjectID, _ ab_repo.PageFilter) ([]domain.SubjectPrivilege, string, error) {
	a.repo.mu.Lock()
	defer a.repo.mu.Unlock()
	if len(a.repo.spRows) == 0 {
		return nil, "", nil
	}
	out := make([]domain.SubjectPrivilege, len(a.repo.spRows))
	copy(out, a.repo.spRows)
	return out, "", nil
}

// fakeUserRdr — наименьший user.ReaderIface для ListSubjectPrivileges:
// существование и домашний аккаунт. Исполняется только Get.
type fakeUserRdr struct{ repo *abFakeRepo }

func (u *fakeUserRdr) Get(_ context.Context, id domain.UserID) (domain.User, error) {
	u.repo.mu.Lock()
	defer u.repo.mu.Unlock()
	acc, ok := u.repo.users[string(id)]
	if !ok {
		return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", id)
	}
	return domain.User{ID: id, AccountID: domain.AccountID(acc)}, nil
}
func (u *fakeUserRdr) GetByEmail(_ context.Context, _ domain.Email) (domain.User, error) {
	return domain.User{}, stderrors.New("not implemented in fake")
}
func (u *fakeUserRdr) List(_ context.Context, _ user_repo.ListFilter) ([]domain.User, string, error) {
	return nil, "", nil
}
func (u *fakeUserRdr) GetByAccountEmail(_ context.Context, _ domain.AccountID, _ domain.Email) (domain.User, error) {
	return domain.User{}, stderrors.New("not implemented in fake")
}
func (u *fakeUserRdr) FindPendingByEmail(_ context.Context, _ domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (u *fakeUserRdr) FindByExternalIDInStatuses(_ context.Context, _ domain.ExternalSubject, _ []domain.InviteStatus) ([]domain.User, error) {
	return nil, nil
}
func (u *fakeUserRdr) FindActiveByEmail(_ context.Context, _ domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (u *fakeUserRdr) ListAccountsForUser(_ context.Context, _ domain.UserID) ([]domain.AccountID, error) {
	return nil, nil
}

// fakeSARdr — наименьший service_account.ReaderIface для ListSubjectPrivileges.
type fakeSARdr struct{ repo *abFakeRepo }

func (s *fakeSARdr) Get(_ context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	s.repo.mu.Lock()
	defer s.repo.mu.Unlock()
	acc, ok := s.repo.serviceAccounts[string(id)]
	if !ok {
		return domain.ServiceAccount{}, iamerr.Wrapf(iamerr.ErrNotFound, "ServiceAccount %s not found", id)
	}
	return domain.ServiceAccount{ID: id, AccountID: domain.AccountID(acc)}, nil
}
func (s *fakeSARdr) List(_ context.Context, _ sa_repo.ListFilter) ([]domain.ServiceAccount, string, error) {
	return nil, "", nil
}

// fakeGroupRdr — поддельный читатель групп с поиском IsMember.
// Наименьшая реализация group.ReaderIface, на которой стоит авторизация по
// IsMember в ListAccessBindingsBySubject. Прочие методы не используются.
type fakeGroupRdr struct{ repo *abFakeRepo }

func (g *fakeGroupRdr) Get(_ context.Context, id domain.GroupID) (domain.Group, error) {
	g.repo.mu.Lock()
	defer g.repo.mu.Unlock()
	acc, ok := g.repo.groups[string(id)]
	if !ok {
		return domain.Group{}, iamerr.Wrapf(iamerr.ErrNotFound, "Group %s not found", id)
	}
	return domain.Group{ID: id, AccountID: domain.AccountID(acc)}, nil
}
func (g *fakeGroupRdr) List(_ context.Context, _ group.ListFilter) ([]domain.Group, string, error) {
	return nil, "", nil
}
func (g *fakeGroupRdr) ListMembers(_ context.Context, _ domain.GroupID, _ group.MemberPage) ([]domain.GroupMember, string, error) {
	return nil, "", nil
}

// MembersOfGroups — дублёр отвечает ИЗ ТОГО ЖЕ хранилища, что и IsMember.
// Дублёр, отвечающий пусто там, где настоящий отвечает составом, сделал бы
// невидимым ровно тот недоответ, ради которого пробу и пишут.
func (g *fakeGroupRdr) MembersOfGroups(_ context.Context, groupIDs []domain.GroupID) ([]domain.GroupMember, []domain.GroupID, error) {
	g.repo.mu.Lock()
	defer g.repo.mu.Unlock()
	if g.repo.membersOfGroupsErr != nil {
		return nil, nil, g.repo.membersOfGroupsErr
	}
	want := make(map[string]struct{}, len(groupIDs))
	for _, id := range groupIDs {
		want[string(id)] = struct{}{}
	}
	keys := make([]string, 0, len(g.repo.groupMembers))
	for k := range g.repo.groupMembers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []domain.GroupMember
	for _, k := range keys {
		parts := strings.SplitN(k, "|", 3)
		if len(parts) != 3 {
			continue
		}
		if _, ok := want[parts[0]]; !ok {
			continue
		}
		out = append(out, domain.GroupMember{
			GroupID:    domain.GroupID(parts[0]),
			MemberType: domain.SubjectType(parts[1]),
			MemberID:   domain.SubjectID(parts[2]),
		})
	}
	// Дублёр отдаёт состав целиком и говорит об этом пустым перечнем неполных:
	// снисходительнее настоящего он быть не вправе, но и усечения, которого не
	// было, объявлять не должен.
	return out, g.repo.incompleteGroups, nil
}
func (g *fakeGroupRdr) IsMember(_ context.Context, groupID domain.GroupID, memberType domain.SubjectType, memberID domain.SubjectID) (bool, error) {
	g.repo.mu.Lock()
	defer g.repo.mu.Unlock()
	if g.repo.groupMembers == nil {
		return false, nil
	}
	_, ok := g.repo.groupMembers[string(groupID)+"|"+string(memberType)+"|"+string(memberID)]
	return ok, nil
}

// fakeABWtr — писатель access_binding; хранит итог Insert, очищает на Delete.
type fakeABWtr struct{ repo *abFakeRepo }

// GetForDeactivation — то же чтение, что у фейка читателя: замка строки у фейка нет,
// предмет пробы здесь — набор снимаемых кортежей, а не порядок замков.
func (w *fakeABWtr) GetForDeactivation(ctx context.Context, id domain.AccessBindingID) (domain.AccessBinding, error) {
	return (&fakeABRdr{repo: w.repo}).Get(ctx, id)
}

// LockLiveTargetTypes — дублёр выполняет контракт настоящего тем же источником,
// что синхронная половина проверки: живые строки каталога фикстуры.
func (w *fakeABWtr) LockLiveTargetTypes(_ context.Context, types []string) ([]string, error) {
	return fixtureLiveTargetTypes(types), nil
}

func (w *fakeABWtr) Insert(_ context.Context, b domain.AccessBinding) (domain.AccessBinding, error) {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if b.ID == "" {
		b.ID = "acbc_fake_ab_test01-"
	}
	cp := b
	w.repo.ab = &cp
	return b, nil
}

func (w *fakeABWtr) Delete(_ context.Context, id domain.AccessBindingID) error {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if w.repo.ab != nil && w.repo.ab.ID == id {
		w.repo.ab = nil
		return nil
	}
	return stderrors.New("access binding not found for delete in fake")
}

func (w *fakeABWtr) DeleteGuarded(_ context.Context, id domain.AccessBindingID) error {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if w.repo.ab != nil && w.repo.ab.ID == id {
		if w.repo.ab.DeletionProtection {
			return iamerr.Wrapf(iamerr.ErrFailedPrecondition,
				"access binding %s has deletion_protection enabled; clear it via Update before Delete", id)
		}
		w.repo.ab = nil
		return nil
	}
	return iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
}

func (w *fakeABWtr) RevokeGuarded(_ context.Context, id domain.AccessBindingID, revokedBy domain.UserID) (domain.AccessBinding, error) {
	w.repo.recordTxOp("revoke_guarded:" + string(id))
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if w.repo.ab == nil || w.repo.ab.ID != id {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
	}
	if w.repo.ab.DeletionProtection {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"access binding %s has deletion_protection enabled; clear it via Update before revoke", id)
	}
	if w.repo.ab.Status != domain.AccessBindingStatusActive {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"access binding %s is not active (status %s); cannot revoke", id, w.repo.ab.Status)
	}
	now := time.Now().UTC()
	rb := revokedBy
	w.repo.ab.Status = domain.AccessBindingStatusRevoked
	w.repo.ab.RevokedAt = &now
	w.repo.ab.RevokedByUserID = &rb
	return *w.repo.ab, nil
}

func (w *fakeABWtr) SetDeletionProtection(_ context.Context, id domain.AccessBindingID, protected bool) (domain.AccessBinding, error) {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if w.repo.ab != nil && w.repo.ab.ID == id {
		w.repo.ab.DeletionProtection = protected
		return *w.repo.ab, nil
	}
	return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
}

func (w *fakeABWtr) UpdateLabels(_ context.Context, id domain.AccessBindingID, labels domain.Labels) (domain.AccessBinding, error) {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	if w.repo.ab != nil && w.repo.ab.ID == id {
		w.repo.ab.Labels = labels
		return *w.repo.ab, nil
	}
	return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
}

func (w *fakeABWtr) EmitSubjectChangeEvent(_ context.Context, _ ab_repo.SubjectChangeEvent) error {
	return nil
}

// Захват эмитированных кортежей FGA для пробы симметрии выше.
func (w *fakeABWtr) EmitRelationWrite(_ context.Context, tuples []ab_repo.RelationTuple) error {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	w.repo.fgaWritten = append(w.repo.fgaWritten, tuples...)
	return nil
}

// EmitRelationDelete вдобавок оставляет отметку в следе транзакции писателя.
//
// Отметка позволяет пробе утверждать, КОГДА заявлен набор отзыва, а «когда»
// теперь и есть всё свойство: триггер на журнале применяет строку к таблице
// фактов в той же транзакции, так что набор, заявленный ДО фиксации, отказывает
// В МОМЕНТ фиксации, — тогда как набор, заявленный после неё, был бы второй,
// отдельной записью, которая может потеряться между ними. Без отметки порядок
// невидим всем пробам пакета, и вынос эмиссии из транзакции оставил бы зелёными
// все утверждения о равенстве наборов.
func (w *fakeABWtr) EmitRelationDelete(_ context.Context, tuples []ab_repo.RelationTuple) error {
	w.repo.recordTxOp("emit_relation_delete")
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	w.repo.fgaDeleted = append(w.repo.fgaDeleted, tuples...)
	return nil
}

// EmitAuditEvent захватывает событие соответствия audit_outbox для утверждений.
func (w *fakeABWtr) EmitAuditEvent(_ context.Context, ev ab_repo.AuditEvent) error {
	w.repo.mu.Lock()
	defer w.repo.mu.Unlock()
	w.repo.auditEvents = append(w.repo.auditEvents, ev)
	return nil
}

func (w *fakeABWtr) TransitionStatus(
	_ context.Context,
	_ domain.AccessBindingID,
	_ []domain.AccessBindingStatus,
	_ domain.AccessBindingStatus,
	_ *domain.UserID,
) (domain.AccessBinding, error) {
	return domain.AccessBinding{}, stderrors.New("TransitionStatus: not implemented in fake")
}

// ─── поддельный operations.Repo ─────────────────────────────────────────────

type fakeOpsRepo struct {
	mu  sync.Mutex
	ops map[string]*operations.Operation
}

func newFakeOpsRepo() *fakeOpsRepo {
	return &fakeOpsRepo{ops: map[string]*operations.Operation{}}
}

func (r *fakeOpsRepo) Create(_ context.Context, op operations.Operation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := op
	r.ops[op.ID] = &cp
	return nil
}

func (r *fakeOpsRepo) CreateWithPrincipal(_ context.Context, op operations.Operation, _ operations.Principal) error {
	return r.Create(context.Background(), op)
}

func (r *fakeOpsRepo) Get(_ context.Context, id string) (*operations.Operation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	op, ok := r.ops[id]
	if !ok {
		return nil, operations.ErrNotFound
	}
	cp := *op
	return &cp, nil
}

func (r *fakeOpsRepo) List(_ context.Context, _ operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}

func (r *fakeOpsRepo) MarkDone(_ context.Context, id string, resp *anypb.Any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Response = resp
	}
	return nil
}

func (r *fakeOpsRepo) MarkError(_ context.Context, id string, st *gstatus.Status) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
		op.Error = st
	}
	return nil
}

func (r *fakeOpsRepo) Cancel(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
	}
	return nil
}

var _ operations.Repo = (*fakeOpsRepo)(nil)

// ─── помощник контекста ──────────────────────────────────────────────────────

// newOwnerContext отдаёт контекст, несущий пользователя-владельца как
// подлинный принципал (проходит проверку IsSelf/владельца в requireGrantAuthority).
func newOwnerContext(ownerID string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{
		ID:   ownerID,
		Type: "user",
	})
}

// EmitReconcileEvent — записывает (objectType, objectID), чтобы можно было
// утверждать совместную фиксацию меток (событие сверки iam.accessBinding на
// смене метки).
func (w *abFakeWriter) EmitReconcileEvent(_ context.Context, _, objectType, objectID string) error {
	if objectType == "iam.accessBinding" {
		w.repo.mu.Lock()
		w.repo.reconcileObjs = append(w.repo.reconcileObjs, objectID)
		w.repo.mu.Unlock()
	}
	return nil
}

// drainReconcileObjects отдаёт id объектов, для которых в транзакции писателя
// эмитировано событие сверки (утверждение о совместной фиксации меток).
func (r *abFakeRepo) drainReconcileObjects() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.reconcileObjs))
	copy(out, r.reconcileObjs)
	r.reconcileObjs = nil
	return out
}

// Visibility — структурные факты о вызывающем, объявленные НЕСУЖЁННЫМИ.
//
// Это НАМЕРЕННО снисходительнее продукта, и цена названа вслух, а не умолчана:
// строк выдачи у этой фикстуры нет вовсе (её гранты живут только в дублёре стора
// отношений), поэтому назвать кандидатов она не может — а сузив набор до пустого,
// она вернула бы пустую страницу везде и стёрла бы ровно то, о чём эти пробы
// спрашивают.
//
// Отсюда граница: предмет проб этого пакета — ВЕРДИКТ (каким отношением судится
// строка страницы, ведёт ли сверх-гейт администратора облака к нефильтрованной
// выдаче, что происходит на отказе стора). ОТБОР кандидатов они не проверяют и
// проверять не могут; он проверяется на настоящем Postgres и настоящей модели
// прав — services/iam/internal/apps/kaname/api/listvisibility, где снисходительного
// дублёра нет ни с одной стороны именно потому, что предмет там — ПОРЯДОК между
// страницей и сужением.
//
// Прежде здесь стоял nil с комментарием «списочный use-case обязан ОТКАЗАТЬ».
// Он и отказывает — ровно поэтому дублёру пришлось начать отвечать: nil означает
// «сузить нечем», а эта фикстура сузить может (ничем не сужая), и это разные
// утверждения.
func (rd *abFakeReader) Visibility() visibility.ReaderIface { return unrestrictedVisibility{} }

// unrestrictedVisibility — «кандидаты не сужаются». Ровно то, что означает
// visibility.Scope{Unrestricted: true}: Candidates(...) вернёт nil, и репозиторий
// не получит ни одного предиката отбора.
type unrestrictedVisibility struct{}

func (unrestrictedVisibility) ScopeOf(_ context.Context, _ visibility.Subject) (visibility.Scope, error) {
	return visibility.Scope{Unrestricted: true, GrantedObjects: map[string][]string{}}, nil
}

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kaname/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (r *abFakeWriter) Visibility() visibility.ReaderIface { return nil }

// MembershipExists — дублёр не отвечает на вопрос о членстве: предмет этой
// пробы другой, и подставной ответ был бы утверждением, которого никто не
// делал. Единственный прод-вызывающий — разрешение осиротевшей операции
// исключения из аккаунта (kacho#1127).
func (*fakeUserRdr) MembershipExists(context.Context, domain.UserID, domain.AccountID) (bool, error) {
	return false, nil
}

// Membership — дублёр членства ПАРОЙ не читает: предмет этих проб другой, и
// подставная строка была бы утверждением, которого никто не делал (kaname#181).
func (*fakeUserRdr) Membership(context.Context, domain.UserID, domain.AccountID) (domain.Membership, error) {
	return domain.Membership{}, iamerr.ErrNotFound
}

// EmitInviteMail — порт со-коммита намерения отправить письмо приглашения.
// Дублёр не глотает того, что настоящий отвергает: пустой адресат и пустой ключ
// партиции отвергаются здесь так же, как ограничением миграции, — иначе фикстура
// была бы снисходительнее продукта и скрыла бы ровно тот дефект, ради которого её
// подставляют.
func (w *abFakeWriter) EmitInviteMail(_ context.Context, intent outboxtypes.InviteMailIntent) (bool, error) {
	if intent.To == "" {
		return false, fmt.Errorf("invite mail: recipient required")
	}
	if intent.UserID == "" {
		return false, fmt.Errorf("invite mail: user id required")
	}
	if intent.Limit.MaxPerWindow <= 0 || intent.Limit.Window <= 0 {
		return false, fmt.Errorf("invite mail: rate limit must be positive — there is no «unlimited»")
	}
	return true, nil
}

// UnresolvedSegments — дублёр ОТКАЗЫВАЕТ, а не отвечает «неразрешённых нет»:
// заглушка, возвращающая пустое, была бы снисходительнее продукта и молча
// зеленила бы утверждения о деградации роли. Целость в этих пробах не предмет,
// поэтому её путь здесь исполняться не должен — а если исполнится, проба упадёт.
// WithdrawnGrants — дублёр ОТКАЗЫВАЕТ, а не отвечает «отобранного нет»:
// заглушка, возвращающая пустое, была бы снисходительнее продукта. Ведомость
// в этих пробах не предмет, поэтому её путь исполняться не должен — а если
// исполнится, проба упадёт.
func (r *fakeRoleRdr) WithdrawnGrants(context.Context, []domain.RoleID) (map[domain.RoleID][]domain.WithdrawnGrant, error) {
	return nil, stderrors.New("WithdrawnGrants не предмет этих проб")
}

// PrunedSelectorTypes — дублёр ОТКАЗЫВАЕТ по тому же доводу, что и сосед выше:
// заглушка, возвращающая пустое, была бы снисходительнее продукта и молча
// прятала бы лишний вопрос к ведомости.
func (r *fakeRoleRdr) PrunedSelectorTypes(context.Context, []domain.RoleID) (map[domain.RoleID][]domain.PrunedSelectorType, error) {
	return nil, stderrors.New("PrunedSelectorTypes не предмет этих проб")
}

func (r *fakeRoleRdr) UnresolvedSegments(context.Context, []domain.RoleSegment) (map[domain.RoleID][]domain.RoleSegment, error) {
	r.repo.mu.Lock()
	defer r.repo.mu.Unlock()
	if r.repo.roleSegmentsAnswered {
		return map[domain.RoleID][]domain.RoleSegment{}, nil
	}
	return nil, stderrors.New("UnresolvedSegments не предмет этих проб")
}

// Lifecycles — дублёр: жизненное состояние ролей этот путь не спрашивает.
// Пустая карта означает «не вычислено», и вызывающий оставляет нулевое
// состояние — ровно то, что дублёр обязан отдавать о величине, которой не
// владеет.
func (*fakeRoleRdr) Lifecycles(_ context.Context, _ []domain.RoleID) (
	map[domain.RoleID]domain.RoleLifecycle, error) {
	return nil, nil
}

// BoundToSystemClass — системный класс субъекта (kaname#829) этим дублёром не судится.
func (_ *fakeRoleRdr) BoundToSystemClass(context.Context, domain.RoleID) (bool, error) {
	return false, nil
}

// GrantDelegationsW — делегирований этот дублёр не несёт (kaname#986): пробы файла
// делегированного пути права выдавать не касаются.
func (w *fakeABWtr) GrantDelegationsW() gdrepo.WriterIface { return nil }
