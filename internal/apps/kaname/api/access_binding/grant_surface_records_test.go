// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// grant_surface_records_test.go — ПЕРЕЧИСЛЕНИЕ ВЫДАЧ ВОЗВРАЩАЕТ ВСЕ ТРИ ВИДА И
// НАЗЫВАЕТ ВИД КАЖДОЙ ЗАПИСИ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (#914, решение 2)
//
// Поверхностей выдачи три: выдача, состав группы, кластерный администратор.
// Раздельными они остаются — у членства нет ни роли, ни области, ни срока, а у
// кластерного администратора свой порядок выдачи. Но ЧТЕНИЕ у них было тоже
// раздельным, а две поверхности об одном предмете расходятся МОЛЧА:
// спрашивающий «кто имеет доступ» получает ответ с одной из них и считает его
// полным.
//
// Признак нарушения решения назван в
// `services/iam/docs/engineering/architecture/grant-surface-boundaries.md`:
// перечисление вернуло запись БЕЗ ВИДА либо вид, которого нет в перечне. Оба
// утверждаются здесь дословно.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ СТОИТ ОТРИЦАТЕЛЬНЫМ ПЛЕЧОМ И ПОЧЕМУ ИМЕННО ОНО
//
// Верхний ярус супер-доступа перечисляется ТОМУ, КТО ИМ РАСПОРЯЖАЕТСЯ. Проба
// без отрицания зеленела бы на перечислении, отдающем имена администраторов
// облака всякому арендатору, — то есть ровно на том, чего делать нельзя.

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// stubClusterAdmins — соседняя поверхность верхнего яруса.
type stubClusterAdmins struct {
	rows  []domain.ClusterAdminEntry
	err   error
	calls int
}

func (s *stubClusterAdmins) ListActive(context.Context) ([]domain.ClusterAdminEntry, error) {
	s.calls++
	return s.rows, s.err
}

const (
	// Три группы, и каждая проверяет СВОЙ путь до состава.
	//
	// Форм субъекта у выдачи ДВЕ, и они не совпадают: канонический набор
	// `subjects[]` и плоская пара строки, в которую путь создания кладёт ТОЛЬКО
	// `subjects[0]` (`create.go`). Выдача на две группы поэтому хранит вторую
	// исключительно в наборе — и достаёт её единственная ветвь `groupSubjectsOf`.
	//
	// Фикстура обязана делать НАГРУЖЕННЫМИ обе ветви, иначе снятие одной из них
	// проходит зелёным: групповая выдача с одним субъектом достаётся и той, и
	// другой, и проба перестаёт различать их вовсе.
	gsGroupFlat  = "grp0000000000000wrt1" // только в плоской паре — ветвь пары
	gsGroupBoth  = "grp0000000000000wrt2" // и в паре, и в наборе — перекрытие
	gsGroupMulti = "grp0000000000000wrt3" // только в наборе — ветвь набора

	gsBindGrp   = "acb00000000000grp001" // выдача одной группе, набора нет
	gsBindMulti = "acb00000000000grp002" // многосубъектная: пара + вторая группа
	gsBindUser  = "acb00000000000usr001" // выдача человеку — групп не даёт
	gsAccount   = "acc_gs_914"
)

// gsExpectedGroups — группы, чей состав перечисление обязано вернуть, и путь,
// которым каждая туда попадает. Проба утверждает СОСТАВ множества, а не его
// мощность: потеря ветви обязана называть ПРОПАВШУЮ группу, иначе разбирающий
// отказ видит «было 5, стало 3» и не знает, какая из форм субъекта отвалилась.
var gsExpectedGroups = map[string]string{
	gsGroupFlat:  "плоская пара выдачи",
	gsGroupBoth:  "обе формы сразу",
	gsGroupMulti: "канонический набор subjects[] (в плоскую пару НЕ попадает)",
}

// newGrantSurfaceFixture — страница с ТРЕМЯ выдачами: одна группе одной формой,
// одна МНОГОСУБЪЕКТНАЯ (две группы), одна человеку.
//
// Многосубъектная — не украшение: `subjects` публичное повторяющееся поле
// запроса создания, выдача на две группы законна и достижима арендатором. Без
// неё ветвь набора в `groupSubjectsOf` не исполняется НИ РАЗУ, и её снятие
// проходит зелёным по всему пакету.
func newGrantSurfaceFixture(t *testing.T) (*abFakeRepo, *abQueriesStub) {
	t.Helper()
	repo := newABFakeRepo("usr_o", gsAccount, "", "rol_v", "kacho.view", nil)
	seedABListByScope(repo, []domain.AccessBinding{
		// Плоская пара без строк набора: так выглядит выдача, у которой
		// канонический набор не спроецирован. Единственный путь к её группе —
		// ветвь пары.
		{ID: gsBindGrp, ResourceType: "account", ResourceID: gsAccount,
			SubjectType: domain.SubjectTypeGroup, SubjectID: gsGroupFlat},
		// Многосубъектная: пара несёт ПЕРВЫЙ субъект (так её кладёт путь
		// создания), вторая группа живёт только в наборе.
		{ID: gsBindMulti, ResourceType: "account", ResourceID: gsAccount,
			SubjectType: domain.SubjectTypeGroup, SubjectID: gsGroupBoth},
		{ID: gsBindUser, ResourceType: "account", ResourceID: gsAccount,
			SubjectType: domain.SubjectTypeUser, SubjectID: "usr_a"},
	})
	seedABSubjects(repo, gsBindMulti, []domain.Subject{
		{Type: domain.SubjectTypeGroup, ID: gsGroupBoth},
		{Type: domain.SubjectTypeGroup, ID: gsGroupMulti},
	})
	repo.AddGroupMember(gsGroupFlat, "service_account", "sva0000000000000one1")
	repo.AddGroupMember(gsGroupFlat, "service_account", "sva0000000000000two2")
	repo.AddGroupMember(gsGroupBoth, "service_account", "sva000000000000three")
	repo.AddGroupMember(gsGroupMulti, "service_account", "sva0000000000000four")
	repo.AddGroupMember(gsGroupMulti, "user", "usr0000000000000five")

	fga := newABQueriesStub()
	fga.set("v_get", "user:usr_caller", []string{gsBindGrp, gsBindMulti, gsBindUser})
	return repo, fga
}

// seedABSubjects — канонический набор субъектов выдачи в дублёре
// `access_binding_subjects`. Тот же путь, которым его наполняет запись.
func seedABSubjects(repo *abFakeRepo, id domain.AccessBindingID, subs []domain.Subject) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.abSubjects == nil {
		repo.abSubjects = map[domain.AccessBindingID][]domain.Subject{}
	}
	repo.abSubjects[id] = append([]domain.Subject(nil), subs...)
}

// groupsOfMemberships — группы, чей состав вернуло перечисление.
func groupsOfMemberships(records []*iamv1.GrantSurfaceRecord) map[string]int {
	out := map[string]int{}
	for _, r := range records {
		if m := r.GetGroupMembership(); m != nil {
			out[m.GetGroupId()]++
		}
	}
	return out
}

// kindOfArm — вид, который называет ВЕТВЬ записи. Отдельно от поля `kind`
// намеренно: согласие двух прочтений — предмет утверждения, а не допущение.
func kindOfArm(r *iamv1.GrantSurfaceRecord) iamv1.GrantSurfaceKind {
	switch r.GetRecord().(type) {
	case *iamv1.GrantSurfaceRecord_Binding:
		return iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_ACCESS_BINDING
	case *iamv1.GrantSurfaceRecord_GroupMembership:
		return iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_GROUP_MEMBERSHIP
	case *iamv1.GrantSurfaceRecord_ClusterAdmin:
		return iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_CLUSTER_ADMIN
	default:
		return iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_UNSPECIFIED
	}
}

func kindCounts(t *testing.T, records []*iamv1.GrantSurfaceRecord) map[iamv1.GrantSurfaceKind]int {
	t.Helper()
	out := map[iamv1.GrantSurfaceKind]int{}
	for i, r := range records {
		require.NotEqualf(t, iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_UNSPECIFIED, r.GetKind(),
			"запись %d вернулась БЕЗ ВИДА — перечисление отдало то, что само назвать не может", i)
		require.Equalf(t, r.GetKind(), kindOfArm(r),
			"запись %d: поле вида и ветвь называют РАЗНОЕ — два прочтения одной записи "+
				"расходятся, и разные вызывающие прочтут её по-разному", i)
		out[r.GetKind()]++
	}
	return out
}

// TestABList_R914_EnumerationReturnsAllThreeKinds — кластерный администратор
// получает ПОЛНОЕ перечисление: выдачи, состав названных ими групп и верхний
// ярус супер-доступа.
func TestABList_R914_EnumerationReturnsAllThreeKinds(t *testing.T) {
	repo, fga := newGrantSurfaceFixture(t)
	admins := &stubClusterAdmins{rows: []domain.ClusterAdminEntry{{
		ClusterAdminGrantID: "cag_00000000000000001",
		SubjectType:         "user",
		SubjectID:           "usr_root",
		GrantedAt:           time.Now().UTC(),
	}}}
	var rs clients.RelationStore = onlyClusterAdmin()

	h := (&Handler{}).WithList(NewListUseCase(repo).
		WithRelationStore(rs).
		WithRelationQueries(fga).
		WithClusterAdmins(admins))

	resp, err := h.List(clusterAdminCtx("usr_caller"), &iamv1.ListAccessBindingsRequest{PageSize: 100})
	require.NoError(t, err)

	counts := kindCounts(t, resp.GetRecords())
	assert.Equal(t, 3, counts[iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_ACCESS_BINDING],
		"выдачи страницы обязаны быть в перечислении: без них оно не перечисление, а довесок")
	assert.Equal(t, 5, counts[iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_GROUP_MEMBERSHIP],
		"состав группы, названной субъектом выдачи, — второй вид: без него «выдано группе» "+
			"не отвечает на вопрос, КОМУ выдано")

	// СОСТАВ множества групп, а не его мощность. Обе формы субъекта обязаны
	// доводить до состава, и потеря любой из них называет пропавшую группу
	// поимённо — иначе разбирающий видит упавшее число и не знает, что отвалилось.
	got := groupsOfMemberships(resp.GetRecords())
	for gid, how := range gsExpectedGroups {
		assert.Containsf(t, got, gid,
			"состав группы %s не вернулся: её достаёт %s — значит эта форма субъекта "+
				"перестала доходить до перечисления, и неполнота выглядит как «в группе никого»",
			gid, how)
	}
	assert.Equal(t, 1, counts[iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_CLUSTER_ADMIN],
		"верхний ярус супер-доступа — третий вид: своя поверхность у него остаётся, "+
			"но чтение обязано быть одно")

	// Поле выдач остаётся тем же: перечисление ДОБАВЛЯЕТ вид, а не подменяет
	// прежний ответ.
	assert.Len(t, resp.GetAccessBindings(), 3)
}

// TestABList_R914_TenantSeesNoClusterAdmins — отрицательное плечо: арендатору
// имена администраторов облака не адресованы, а состав групп его выдач — да.
func TestABList_R914_TenantSeesNoClusterAdmins(t *testing.T) {
	repo, fga := newGrantSurfaceFixture(t)
	admins := &stubClusterAdmins{rows: []domain.ClusterAdminEntry{{
		ClusterAdminGrantID: "cag_00000000000000001",
		SubjectType:         "user",
		SubjectID:           "usr_root",
	}}}
	// Кластерным администратором вызывающий НЕ является: короткое замыкание
	// D-9 не срабатывает, и страница сужается вердиктом.
	var rs clients.RelationStore = &scopedFGA{allow: map[string]bool{}}

	h := (&Handler{}).WithList(NewListUseCase(repo).
		WithRelationStore(rs).
		WithRelationQueries(fga).
		WithClusterAdmins(admins))

	resp, err := h.List(clusterAdminCtx("usr_caller"), &iamv1.ListAccessBindingsRequest{PageSize: 100})
	require.NoError(t, err)

	counts := kindCounts(t, resp.GetRecords())
	assert.Zero(t, counts[iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_CLUSTER_ADMIN],
		"арендатор не вправе перечислить администраторов облака: перечисление верхнего "+
			"яруса адресовано тому, кто им распоряжается")
	assert.Zero(t, admins.calls,
		"поверхность верхнего яруса не должна быть даже СПРОШЕНА за арендатора — "+
			"иначе «не показали» держится на фильтре после чтения, а не на решении до него")

	// Положительный контроль рядом. Без него ноль выше зеленел бы и на
	// перечислении, которое не заполняется вовсе.
	assert.Equal(t, 3, counts[iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_ACCESS_BINDING])
	assert.Equal(t, 5, counts[iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_GROUP_MEMBERSHIP])
	assert.Len(t, groupsOfMemberships(resp.GetRecords()), len(gsExpectedGroups),
		"арендатору состав групп его же выдач возвращается целиком — обеими формами субъекта")
}

// TestABList_R914_LegacyProjectionLeavesTheFieldEmptyAndSaysSo — устаревшее
// семейство (ListByScope/ListBySubject/ListByRole/ListByAccount) делит с
// каноническим чтением ОДНО сообщение ответа и поле полного перечисления НЕ
// заполняет.
//
// Проба стоит здесь не ради самого нуля, а ради того, чтобы расхождение двух
// проекций одного сообщения было ЗАФИКСИРОВАНО: молчаливое «иногда пусто»
// читается вызывающим как «ничего не найдено», а не как «это чтение поля не
// заполняет» (api-conventions.md §«Проекция, которая поле НЕ заполняет, обязана
// это сказать»). Утверждается сама проекция — та функция, через которую идут
// все четыре устаревших чтения, — а не один из её вызывающих: иначе три
// остальных остались бы неутверждёнными.
func TestABList_R914_LegacyProjectionLeavesTheFieldEmptyAndSaysSo(t *testing.T) {
	rows := []domain.AccessBinding{
		{ID: gsBindGrp, ResourceType: "account", ResourceID: gsAccount,
			SubjectType: domain.SubjectTypeGroup, SubjectID: gsGroupFlat},
	}
	legacy, err := listToProto(rows, "")
	require.NoError(t, err)
	assert.Empty(t, legacy.GetRecords(),
		"устаревшее чтение полного перечисления не производит — у него нет ни вопроса о "+
			"верхнем ярусе, ни своего вердикта для соседних видов")

	// Положительный контроль той же формы: каноническая проекция поле
	// заполняет. Без него ноль выше зеленел бы и на сообщении, у которого этого
	// поля нет вовсе.
	canonical, err := listPageToProto(ListPage{Bindings: rows})
	require.NoError(t, err)
	assert.Len(t, canonical.GetRecords(), 1)
}

// TestABList_R914_NeighbourReadFailureRefusesTheRequest — ОТКАЗ ЧТЕНИЯ СОСЕДА
// ОТКАЗЫВАЕТ ЗАПРОСУ, а не усекает перечисление молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО ОТДЕЛЬНАЯ ПРОБА, А НЕ СВОЙСТВО, ВИДНОЕ В КОДЕ
//
// Единственный предмет поля `records` — ПОЛНОТА. Проглоченный отказ соседа даёт
// ответ, который выглядит полным и им не является: «состава нет» неотличимо от
// «состав не удалось прочитать», а вызывающий записывает это к себе как факт о
// доступе. Написать `return nil` вместо `return err` — правка на одну строку,
// и без пробы её ничто не остановит.
//
// Полос ТРИ, и они разные: отказ чтения состава, непровязанный читатель групп
// («мне нечем ответить» — не то же, что «пусто»), отказ чтения верхнего яруса.
// Каждая проверяется отдельно, потому что закрыть одну и оставить две — ровно
// тот исход, ради которого проба и пишется.
func TestABList_R914_NeighbourReadFailureRefusesTheRequest(t *testing.T) {
	newHandler := func(repo *abFakeRepo, fga *abQueriesStub, admins *stubClusterAdmins) *Handler {
		return (&Handler{}).WithList(NewListUseCase(repo).
			WithRelationStore(onlyClusterAdmin()).
			WithRelationQueries(fga).
			WithClusterAdmins(admins))
	}

	t.Run("отказ чтения состава групп", func(t *testing.T) {
		repo, fga := newGrantSurfaceFixture(t)
		repo.membersOfGroupsErr = stderrors.New("состав недоступен")
		h := newHandler(repo, fga, &stubClusterAdmins{})

		_, err := h.List(clusterAdminCtx("usr_caller"), &iamv1.ListAccessBindingsRequest{PageSize: 100})
		require.Error(t, err, "проглоченный отказ отдал бы 200 с усечённым перечислением — "+
			"полнота и есть предмет этого поля")
		st, _ := status.FromError(err)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("читатель групп не провязан", func(t *testing.T) {
		repo, fga := newGrantSurfaceFixture(t)
		repo.groupsReaderNil = true
		h := newHandler(repo, fga, &stubClusterAdmins{})

		_, err := h.List(clusterAdminCtx("usr_caller"), &iamv1.ListAccessBindingsRequest{PageSize: 100})
		require.Error(t, err, "«мне нечем ответить» не вправе производить «состава нет»")
		st, _ := status.FromError(err)
		assert.Equal(t, codes.Unavailable, st.Code())
	})

	t.Run("отказ чтения верхнего яруса", func(t *testing.T) {
		repo, fga := newGrantSurfaceFixture(t)
		admins := &stubClusterAdmins{err: stderrors.New("поверхность недоступна")}
		h := newHandler(repo, fga, admins)

		_, err := h.List(clusterAdminCtx("usr_caller"), &iamv1.ListAccessBindingsRequest{PageSize: 100})
		require.Error(t, err, "перечисление без верхнего яруса читается как «администраторов нет»")
		st, _ := status.FromError(err)
		assert.Equal(t, codes.Unavailable, st.Code())
		assert.Equal(t, 1, admins.calls, "поверхность обязана быть спрошена — иначе отказ нечем получить")
	})

	// Положительный контроль всех трёх полос сразу: без отказов тот же запрос
	// проходит. Без него три отрицания зеленели бы и на перечислении, которое
	// отказывает всегда.
	t.Run("положительный контроль: без отказов запрос проходит", func(t *testing.T) {
		repo, fga := newGrantSurfaceFixture(t)
		h := newHandler(repo, fga, &stubClusterAdmins{})
		resp, err := h.List(clusterAdminCtx("usr_caller"), &iamv1.ListAccessBindingsRequest{PageSize: 100})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.GetRecords())
	})
}

// TestABList_R914_IncompleteMembershipIsNamedInTheAnswer — усечение состава
// ДОЕЗЖАЕТ до вызывающего, а не остаётся в репозитории.
//
// Предел состава законен: членство неограниченно by construction, и у него есть
// свой пагинированный глагол. Незаконно — промолчать: усечённый состав читается
// как факт о доступе, «в группе больше никого». Признак усечения потому и часть
// ОТВЕТА, а не журнала — путь его переноса обязан быть проверен, иначе честная
// граница в репозитории оканчивается молчанием на проводе.
func TestABList_R914_IncompleteMembershipIsNamedInTheAnswer(t *testing.T) {
	repo, fga := newGrantSurfaceFixture(t)
	repo.incompleteGroups = []domain.GroupID{gsGroupMulti}
	h := (&Handler{}).WithList(NewListUseCase(repo).
		WithRelationStore(onlyClusterAdmin()).
		WithRelationQueries(fga).
		WithClusterAdmins(&stubClusterAdmins{}))

	resp, err := h.List(clusterAdminCtx("usr_caller"), &iamv1.ListAccessBindingsRequest{PageSize: 100})
	require.NoError(t, err)
	assert.Equal(t, []string{gsGroupMulti}, resp.GetIncompleteMembershipGroupIds(),
		"группа с усечённым составом обязана быть НАЗВАНА в ответе: без имени вызывающий "+
			"не знает ни того, что состав неполон, ни к какой группе идти за остатком")

	// Отрицание рядом: без усечения перечень пуст. Пустой перечень — это
	// утверждение «состав полон», и оно обязано быть отличимо от «не заполняли».
	clean, fga2 := newGrantSurfaceFixture(t)
	h2 := (&Handler{}).WithList(NewListUseCase(clean).
		WithRelationStore(onlyClusterAdmin()).
		WithRelationQueries(fga2).
		WithClusterAdmins(&stubClusterAdmins{}))
	resp2, err := h2.List(clusterAdminCtx("usr_caller"), &iamv1.ListAccessBindingsRequest{PageSize: 100})
	require.NoError(t, err)
	assert.Empty(t, resp2.GetIncompleteMembershipGroupIds(),
		"состав всех названных групп возвращён целиком — объявлять усечение не о чем")
	assert.NotEmpty(t, resp2.GetRecords(), "положительный контроль: перечисление не пусто")
}
