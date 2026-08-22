// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
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
	gsGroupID  = "grp0000000000000wrt1"
	gsBindGrp  = "acb00000000000grp001"
	gsBindUser = "acb00000000000usr001"
	gsAccount  = "acc_gs_914"
)

// newGrantSurfaceFixture — страница с ДВУМЯ выдачами: одна выдана группе (её
// состав и есть предмет второго вида), другая — человеку.
func newGrantSurfaceFixture(t *testing.T) (*abFakeRepo, *abQueriesStub) {
	t.Helper()
	repo := newABFakeRepo("usr_o", gsAccount, "", "rol_v", "kacho.view", nil)
	seedABListByScope(repo, []domain.AccessBinding{
		{ID: gsBindGrp, ResourceType: "account", ResourceID: gsAccount,
			SubjectType: domain.SubjectTypeGroup, SubjectID: gsGroupID},
		{ID: gsBindUser, ResourceType: "account", ResourceID: gsAccount,
			SubjectType: domain.SubjectTypeUser, SubjectID: "usr_a"},
	})
	repo.AddGroupMember(gsGroupID, "service_account", "sva0000000000000one1")
	repo.AddGroupMember(gsGroupID, "service_account", "sva0000000000000two2")

	fga := newABQueriesStub()
	fga.set("v_get", "user:usr_caller", []string{gsBindGrp, gsBindUser})
	return repo, fga
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
	assert.Equal(t, 2, counts[iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_ACCESS_BINDING],
		"выдачи страницы обязаны быть в перечислении: без них оно не перечисление, а довесок")
	assert.Equal(t, 2, counts[iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_GROUP_MEMBERSHIP],
		"состав группы, названной субъектом выдачи, — второй вид: без него «выдано группе» "+
			"не отвечает на вопрос, КОМУ выдано")
	assert.Equal(t, 1, counts[iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_CLUSTER_ADMIN],
		"верхний ярус супер-доступа — третий вид: своя поверхность у него остаётся, "+
			"но чтение обязано быть одно")

	// Поле выдач остаётся тем же: перечисление ДОБАВЛЯЕТ вид, а не подменяет
	// прежний ответ.
	assert.Len(t, resp.GetAccessBindings(), 2)
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
	assert.Equal(t, 2, counts[iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_ACCESS_BINDING])
	assert.Equal(t, 2, counts[iamv1.GrantSurfaceKind_GRANT_SURFACE_KIND_GROUP_MEMBERSHIP])
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
			SubjectType: domain.SubjectTypeGroup, SubjectID: gsGroupID},
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
