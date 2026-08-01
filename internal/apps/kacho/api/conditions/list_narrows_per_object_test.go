// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package conditions

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// Страница условий сужается до объектов, которые вызывающему видны, — а не до
// его проекта.
//
// ПОЧЕМУ ЭТО ДЕФЕКТ, А НЕ ФОРМА. `iam_condition` — полноценный объект прав: у
// него объявлен весь набор глаголов (v_get/v_list/v_create/v_update/v_delete,
// прямые usersets), и запись каталога гейтит Get/Update/Delete именно по нему,
// per-object. List же спрашивал ОДИН вопрос про проект (`viewer @ project`) и
// отдавал всю его страницу. Ровно эту асимметрию — «Get требует per-object
// грант, а List отдаёт всё, что есть в проекте» — платформа уже назвала дефектом
// на storage, и ради неё существует гейт audit-list-filter.
//
// Сужение безопасно и ничего не отнимает у законного читателя: проектная
// привязка материализуется реконсайлером в per-object tuple на каждое условие
// проекта (containment транзитивен), поэтому у участника проекта эти tuple есть.
// Именно на этом допущении уже работают девять остальных ресурсов iam.

// visibilityStub — подставной ObjectChecker: отвечает «видно» только по явному
// списку. Отказы повторяет так же, как настоящий, — дублёр не снисходительнее.
type visibilityStub struct {
	visible map[string]bool
	err     error
	asked   int
}

func (s *visibilityStub) CheckWithContext(_ context.Context, _, _, object string, _ map[string]any) (bool, error) {
	s.asked++
	if s.err != nil {
		return false, s.err
	}
	return s.visible[object], nil
}

// Вызывающий видит ДВА условия проекта из трёх — страница обязана отдать два.
func TestFilterVisibleConditions_NarrowsPageToVisibleObjects(t *testing.T) {
	chk := &visibilityStub{visible: map[string]bool{
		"iam_condition:cnd-1": true,
		"iam_condition:cnd-3": true,
	}}

	got, err := filterVisibleConditionIDs(context.Background(), chk, "user:usr-1",
		[]string{"cnd-1", "cnd-2", "cnd-3"})

	require.NoError(t, err)
	require.True(t, got["cnd-1"])
	require.False(t, got["cnd-2"], "условие без гранта обязано выпасть из страницы")
	require.True(t, got["cnd-3"])
}

// ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ: сужение не отнимает у того, кому всё видно. Без него
// «выпало» неотличимо от «выпадает всегда».
func TestFilterVisibleConditions_KeepsEverythingTheCallerMaySee(t *testing.T) {
	chk := &visibilityStub{visible: map[string]bool{
		"iam_condition:cnd-1": true,
		"iam_condition:cnd-2": true,
	}}

	got, err := filterVisibleConditionIDs(context.Background(), chk, "user:usr-1",
		[]string{"cnd-1", "cnd-2"})

	require.NoError(t, err)
	require.True(t, got["cnd-1"])
	require.True(t, got["cnd-2"])
}

// Недоступное хранилище прав — НЕ «не видно»: ошибка обязана дойти до
// вызывающего, иначе авария соседа превращается в тихую пустую страницу,
// которую вызывающий прочтёт как «условий нет».
func TestFilterVisibleConditions_StoreErrorPropagates(t *testing.T) {
	chk := &visibilityStub{err: context.DeadlineExceeded}

	_, err := filterVisibleConditionIDs(context.Background(), chk, "user:usr-1", []string{"cnd-1"})

	require.Error(t, err, "ошибка хранилища прав не может читаться как отсутствие доступа")
}

// Неопознанный вызывающий отсекается БЕЗУСЛОВНО, а не «когда фильтр подключён»:
// пустой subject не есть разрешение.
func TestFilterVisibleConditions_EmptySubjectSeesNothing(t *testing.T) {
	chk := &visibilityStub{visible: map[string]bool{"iam_condition:cnd-1": true}}

	got, err := filterVisibleConditionIDs(context.Background(), chk, "", []string{"cnd-1"})

	require.NoError(t, err)
	require.False(t, got["cnd-1"], "пустой subject не может видеть ничего")
	require.Zero(t, chk.asked, "у хранилища прав не спрашивают за неопознанного вызывающего")
}

// Недоступное хранилище прав отвечает UNAVAILABLE, а не INTERNAL.
//
// Разница не косметическая: INTERNAL означает «у нас сломалось, повторять
// бессмысленно», UNAVAILABLE — «сосед недоступен, повтори». Локальный mapErr
// ветви для этого sentinel'а не имел, поэтому недоступность хранилища прав
// доезжала до вызывающего как внутренняя ошибка. Полоса существовала и до
// сужения страницы — её отдаёт проверка проектной области
// (service.ConditionsCRUDService.List), просто ею никто не ходил; сужение
// добавило второго отправителя того же sentinel'а.
//
// Общий shared.MapRepoErr эту ветвь имеет — расходился именно локальный.
func TestMapErr_UnavailableIsNotInternal(t *testing.T) {
	err := mapErr(iamerr.Wrapf(iamerr.ErrUnavailable, "authorization store unavailable"))

	require.Equal(t, codes.Unavailable, status.Code(err),
		"недоступность соседа обязана быть повторяемой, а не выглядеть внутренней поломкой")
}
