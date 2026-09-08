// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// list_account_scope_test.go — приёмка «выдачи субъекта в названном аккаунте
// одним вызовом» (задача #1737, док
// docs/engineering/acceptance/subject-grants-within-an-account.md).
//
// Предмет: поле `account_id` у `ListAccessBindingsRequest` сужает страницу до
// области ОДНОГО аккаунта — выдачи на самом аккаунте плюс выдачи на каждом его
// проекте, — и композируется с `filter` и `include_revoked`.
//
// ПОЧЕМУ ЭТИ ПРОБЫ ЖИВУТ НА УРОВНЕ USE-CASE, А НЕ ТОЛЬКО В SQL. Дублёр
// видимости этого пакета отвечает `Unrestricted: true`, то есть `Candidates`
// равен nil — ровно та полоса, на которой реализация «дописать аккаунт в
// сужение кандидатов» не исполнилась бы ВОВСЕ (приёмка §2.3). Проба здесь
// поэтому не дублирует SQL-пробу, а утверждает то, чего та не видит: что поле
// доезжает до репозитория и действует независимо от сужения кандидатов.

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// Идентификаторы фикстуры. Форма — ровно та, которую принимает
// shared.ValidateResourceID: префикс плюс тело до domain.ShortIDLen.
const (
	siaAccountHome    = "acc00000000000home01"
	siaAccountForeign = "acc00000000000frgn01"
	siaAccountAbsent  = "acc00000000000absnt1"
	siaProjectHome    = "prj00000000000home01"
	siaSubject        = "usr000000000000subj1"
	siaSubjectOther   = "usr000000000000othr1"
)

// siaRows — три выдачи одного субъекта: на домашнем аккаунте, на проекте
// домашнего аккаунта и на ЧУЖОМ аккаунте.
//
// Третья строка — не украшение. Без неё «ни одной строки вне аккаунта» верно by
// construction, и кейс зеленел бы на реализации, которая поле выбрасывает
// (e2e-flow.md §11: отрицание на пустом множестве).
func siaRows() []domain.AccessBinding {
	return []domain.AccessBinding{
		{ID: "acb0000000000000sia1", ResourceType: "account", ResourceID: siaAccountHome, SubjectID: siaSubject},
		{ID: "acb0000000000000sia2", ResourceType: "project", ResourceID: siaProjectHome, SubjectID: siaSubject},
		{ID: "acb0000000000000sia3", ResourceType: "account", ResourceID: siaAccountForeign, SubjectID: siaSubject},
	}
}

// newSIARepo — репозиторий с тремя строками выше и объявленной принадлежностью
// проекта домашнему аккаунту.
func newSIARepo() *abFakeRepo {
	repo := newABFakeRepo("usr_o", siaAccountHome, siaProjectHome, "rol_v", "kacho.view", nil)
	seedABListByScope(repo, siaRows())
	seedProjectAccount(repo, siaProjectHome, siaAccountHome)
	return repo
}

// siaVisibleToAll — вердикт «видно всё»: предмет этих проб — сужение ПОЛЕМ, а
// не вердиктом, поэтому вердикт не должен убирать ни одной строки. Иначе
// «строк чужого аккаунта нет» было бы неотличимо от «их убрал вердикт».
func siaVisibleToAll() *abQueriesStub {
	fga := newABQueriesStub()
	ids := make([]string, 0, 3)
	for _, b := range siaRows() {
		ids = append(ids, string(b.ID))
	}
	fga.set("v_get", "user:"+siaSubject, ids)
	return fga
}

func siaIDs(resp *iamv1.ListAccessBindingsResponse) []string {
	out := make([]string, 0, len(resp.GetAccessBindings()))
	for _, b := range resp.GetAccessBindings() {
		out = append(out, b.GetId())
	}
	return out
}

// IAM-AB-SIA-01 — фан-аут покрывает аккаунт И его проекты, и НЕ покрывает чужой.
func TestABList_SIA01_AccountFanoutCoversAccountAndItsProjects(t *testing.T) {
	repo := newSIARepo()
	h := newListHandler(repo, siaVisibleToAll())

	resp, err := h.List(newOwnerContext(siaSubject), &iamv1.ListAccessBindingsRequest{
		PageSize:  100,
		Filter:    `subject="` + siaSubject + `"`,
		AccountId: siaAccountHome,
	})
	require.NoError(t, err)
	assert.ElementsMatch(t,
		[]string{"acb0000000000000sia1", "acb0000000000000sia2"}, siaIDs(resp),
		"страница обязана нести выдачу на самом аккаунте И выдачу на его проекте")
	assert.NotContains(t, siaIDs(resp), "acb0000000000000sia3",
		"выдача в чужом аккаунте на этой странице появиться не может")
}

// IAM-AB-SIA-06 — РАЗЛИЧАЮЩИЙ: поле применено, а не принято и выброшено.
//
// Единственная проба набора, чей исход отличает работающее поле от прочитанного
// и не применённого: два ответа на один и тот же вход, различающиеся ТОЛЬКО
// наличием поля, обязаны различаться составом.
func TestABList_SIA06_FieldChangesTheAnswer(t *testing.T) {
	repo := newSIARepo()
	h := newListHandler(repo, siaVisibleToAll())
	ctx := newOwnerContext(siaSubject)

	withField, err := h.List(ctx, &iamv1.ListAccessBindingsRequest{
		PageSize: 100, Filter: `subject="` + siaSubject + `"`, AccountId: siaAccountHome,
	})
	require.NoError(t, err)
	withoutField, err := h.List(ctx, &iamv1.ListAccessBindingsRequest{
		PageSize: 100, Filter: `subject="` + siaSubject + `"`,
	})
	require.NoError(t, err)

	assert.Len(t, siaIDs(withField), 2)
	assert.Len(t, siaIDs(withoutField), 3)
	assert.NotEqual(t, siaIDs(withoutField), siaIDs(withField),
		"поле обязано МЕНЯТЬ ответ: совпадение означало бы, что его прочитали и выбросили")
}

// IAM-AB-SIA-02 — поле композируется с фильтром субъекта.
func TestABList_SIA02_ComposesWithSubjectFilter(t *testing.T) {
	repo := newSIARepo()
	rows := append(siaRows(), domain.AccessBinding{
		ID: "acb0000000000000sia4", ResourceType: "account",
		ResourceID: siaAccountHome, SubjectID: siaSubjectOther,
	})
	seedABListByScope(repo, rows)

	fga := newABQueriesStub()
	fga.set("v_get", "user:"+siaSubject, []string{
		"acb0000000000000sia1", "acb0000000000000sia2", "acb0000000000000sia3", "acb0000000000000sia4",
	})
	h := newListHandler(repo, fga)

	resp, err := h.List(newOwnerContext(siaSubject), &iamv1.ListAccessBindingsRequest{
		PageSize: 100, Filter: `subject="` + siaSubject + `"`, AccountId: siaAccountHome,
	})
	require.NoError(t, err)
	assert.NotContains(t, siaIDs(resp), "acb0000000000000sia4",
		"строка другого субъекта в том же аккаунте не проходит: предикаты конъюнктивны")
	assert.ElementsMatch(t, []string{"acb0000000000000sia1", "acb0000000000000sia2"}, siaIDs(resp))
}

// IAM-AB-SIA-04 — без поля ответ прежний (положительный контроль обратной
// совместимости). Без него все утверждения выше зеленели бы на реализации,
// которая сужает всегда.
func TestABList_SIA04_WithoutFieldTheAnswerIsUnchanged(t *testing.T) {
	repo := newSIARepo()
	h := newListHandler(repo, siaVisibleToAll())

	resp, err := h.List(newOwnerContext(siaSubject), &iamv1.ListAccessBindingsRequest{
		PageSize: 100, Filter: `subject="` + siaSubject + `"`,
	})
	require.NoError(t, err)
	assert.Len(t, siaIDs(resp), 3, "без поля видны выдачи во всех аккаунтах — поведение до изменения")
	assert.Empty(t, repo.lastListFilter.AccountID, "незаданное поле не превращается в предикат")
}

// IAM-AB-SIA-13 — пустая строка означает «не сужать», а не «аккаунт с пустым id».
func TestABList_SIA13_EmptyMeansDoNotNarrow(t *testing.T) {
	repo := newSIARepo()
	h := newListHandler(repo, siaVisibleToAll())

	resp, err := h.List(newOwnerContext(siaSubject), &iamv1.ListAccessBindingsRequest{
		PageSize: 100, Filter: `subject="` + siaSubject + `"`, AccountId: "",
	})
	require.NoError(t, err, "пустое значение — законный вход, а не негодный id")
	assert.Len(t, siaIDs(resp), 3, "ответ равен ответу без поля")
}

// IAM-AB-SIA-07 — полоса АДМИНИСТРАТОРА ОБЛАКА: поле сужает и его ответ.
//
// На этой полосе страница отдаётся `unfiltered` — пообъектный вердикт
// пропускается вовсе, — поэтому единственное, что может убрать чужие строки,
// это само поле.
func TestABList_SIA07_ClusterAdminLaneIsNarrowedToo(t *testing.T) {
	repo := newSIARepo()
	h := newListHandlerWithStore(repo, newABQueriesStub(), onlyClusterAdmin())

	resp, err := h.List(clusterAdminCtx("usr_root"), &iamv1.ListAccessBindingsRequest{
		PageSize: 100, AccountId: siaAccountHome,
	})
	require.NoError(t, err)
	assert.ElementsMatch(t,
		[]string{"acb0000000000000sia1", "acb0000000000000sia2"}, siaIDs(resp),
		"администратор облака получает суженную страницу, а не всю таблицу")
}

// IAM-AB-SIA-08 — полоса ДЕРЖАТЕЛЯ CLUSTER-SCOPED ВЫДАЧИ: поле не становится
// no-op. Сужения кандидатов на ней тоже нет (Candidates nil), но пообъектный
// вердикт применяется.
func TestABList_SIA08_UnrestrictedCandidatesLaneIsNarrowed(t *testing.T) {
	repo := newSIARepo()
	h := newListHandler(repo, siaVisibleToAll())

	resp, err := h.List(newOwnerContext(siaSubject), &iamv1.ListAccessBindingsRequest{
		PageSize: 100, AccountId: siaAccountHome,
	})
	require.NoError(t, err)
	assert.NotContains(t, siaIDs(resp), "acb0000000000000sia3")
	assert.Len(t, siaIDs(resp), 2)
}

// IAM-AB-SIA-10/11 — чужой и НЕСУЩЕСТВУЮЩИЙ аккаунт отвечают ОДИНАКОВО: пустая
// страница, не отказ. Утверждается равенство ТЕЛ, а не только кодов: различимый
// ответ здесь есть оракул существования аккаунта.
func TestABList_SIA10_11_ForeignAndAbsentAccountAreIndistinguishable(t *testing.T) {
	repo := newSIARepo()
	// Строк ЧУЖОГО аккаунта у субъекта нет вовсе: вопрос пробы — что видит
	// вызывающий, которому этот аккаунт не принадлежит.
	seedABListByScope(repo, siaRows()[:2])
	h := newListHandler(repo, siaVisibleToAll())
	ctx := newOwnerContext(siaSubject)

	foreign, err := h.List(ctx, &iamv1.ListAccessBindingsRequest{PageSize: 100, AccountId: siaAccountForeign})
	require.NoError(t, err, "чужой аккаунт отвечает пустой страницей, а не 403/404")
	absent, err := h.List(ctx, &iamv1.ListAccessBindingsRequest{
		PageSize: 100, AccountId: siaAccountAbsent,
	})
	require.NoError(t, err)

	assert.Empty(t, foreign.GetAccessBindings())
	assert.Empty(t, absent.GetAccessBindings())
	assert.Equal(t, foreign.String(), absent.String(),
		"ответы обязаны совпадать: различие называет, существует ли аккаунт")
}

// IAM-AB-SIA-12 — негодный формат отвергается синхронно, ТЕМ ЖЕ производителем,
// что у ListByAccount на этом же поле. Утверждается ПАРА: код и текст.
func TestABList_SIA12_MalformedAccountIDRejectedByTheSameProducer(t *testing.T) {
	repo := newSIARepo()
	h := newListHandler(repo, siaVisibleToAll())

	_, err := h.List(newOwnerContext(siaSubject), &iamv1.ListAccessBindingsRequest{
		PageSize: 100, AccountId: "not-an-id",
	})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Equal(t, "invalid account id 'not-an-id'", st.Message())

	// Тот же вход у снимаемого глагола — то же тело. Оба ответа берутся у
	// НАСТОЯЩИХ производителей, а не сверяются с выписанной строкой: выписанная
	// разошлась бы с обоими молча.
	_, _, byAccountErr := NewListByAccountUseCase(repo).Execute(
		newOwnerContext(siaSubject), "not-an-id", repoab.AccountPageFilter{PageSize: 100})
	require.Error(t, byAccountErr)
	byAccountSt, _ := status.FromError(byAccountErr)
	assert.Equal(t, byAccountSt.Code(), st.Code())
	assert.Equal(t, byAccountSt.Message(), st.Message(),
		"два глагола на одном поле при одном входе обязаны отвечать одинаково")
	assert.Empty(t, st.Details(), "плоское сообщение, без field_violations")
}

// IAM-AB-SIA-16 — годная форма, но id ЧУЖОГО типа — ТОЖЕ отказ, и тем же телом.
//
// Полоса СТРОГАЯ (префикс сверяется) по практике сервиса, а не по платформенной
// конвенции: паритет с ListByAccount на этом же поле требует IAM-AB-SIA-05.
// Расхождение самого iam с конвенцией — отдельная находка (приёмка §9 п. 2).
func TestABList_SIA16_WellFormedIDOfAnotherTypeIsRejected(t *testing.T) {
	repo := newSIARepo()
	h := newListHandler(repo, siaVisibleToAll())
	wrongType := siaProjectHome // крокфордова форма годна, префикс не тот

	_, err := h.List(newOwnerContext(siaSubject), &iamv1.ListAccessBindingsRequest{
		PageSize: 100, AccountId: wrongType,
	})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.True(t, strings.HasPrefix(st.Message(), "invalid account id "),
		"сообщение называет поле по имени ресурса: %q", st.Message())

	_, _, byAccountErr := NewListByAccountUseCase(repo).Execute(
		newOwnerContext(siaSubject), wrongType, repoab.AccountPageFilter{PageSize: 100})
	require.Error(t, byAccountErr)
	byAccountSt, _ := status.FromError(byAccountErr)
	assert.Equal(t, byAccountSt.Message(), st.Message())
}

// IAM-AB-SIA-14 — проверка формата стоит ДО замыкания на пустом гранте.
//
// Вызывающий не назван вовсе (анонимный контекст) — то есть замыкание сработало
// бы первым и вернуло пустую страницу. Утверждается, что первым срабатывает
// проверка формата: иначе ответ на один и тот же негодный ввод зависел бы от
// того, что вызывающему выдано.
func TestABList_SIA14_FormatCheckedBeforeIdentityShortCircuit(t *testing.T) {
	repo := newSIARepo()
	fga := siaVisibleToAll()
	h := newListHandler(repo, fga)

	t.Run("negodnyj account_id", func(t *testing.T) {
		_, err := h.List(context.Background(), &iamv1.ListAccessBindingsRequest{
			PageSize: 100, AccountId: "not-an-id",
		})
		require.Error(t, err, "пустой грант не вправе превратить 400 в 200 []")
		st, _ := status.FromError(err)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	// Положительный контроль: законный вход при том же пустом гранте проходит и
	// даёт пустую страницу. Без него отрицание выше зеленело бы на реализации,
	// отвергающей всё подряд.
	t.Run("godnyj account_id prohodit", func(t *testing.T) {
		resp, err := h.List(context.Background(), &iamv1.ListAccessBindingsRequest{
			PageSize: 100, AccountId: siaAccountHome,
		})
		require.NoError(t, err)
		assert.Empty(t, resp.GetAccessBindings())
	})
}
