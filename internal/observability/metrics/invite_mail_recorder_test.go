// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// invite_mail_recorder_test.go — наблюдаемость НАШЕЙ отправки письма
// приглашения (приёмка ID-MAIL-1, сценарий MAIL-31).
//
// # ГДЕ ЖИВЁТ КАЖДАЯ ИЗ ТРЁХ ВЕЛИЧИН MAIL-31 — НАЗВАНО ЗДЕСЬ, А НЕ ВЫВОДИТСЯ
//
// Сценарий требует ТРЁХ величин сразу, и держат их пробы в трёх пакетах:
//
//	число сданных писем              Test_InviteMailRecorder_AllCellsExistBeforeTheFirstLetter
//	                                 (здесь; утверждается ПРИСУТСТВИЕ ряда, а не значение)
//	число отказов ПО ВИДАМ           Test_InviteMailRecorder_CountsIntoTheNamedCell (здесь)
//	                                 + clients: Test_InviteMailOutcomes_IsAClosedSet и
//	                                 Test_InviteMailApplier_ClassifiesRefusalIntoItsOwnCell
//	возраст СТАРЕЙШЕГО неотправленного  MAIL-50 на живой базе:
//	                                 services/iam/internal/clients/invite_mail_integration_test.go,
//	                                 Test_InviteMailQueue_OldestPendingAgeGrowsAndReturnsToZero
//
// # ПОЧЕМУ ЭТОТ АБЗАЦ ВООБЩЕ НАПИСАН
//
// Ни одна из проб имени MAIL-31 не называла, и поиск по нему давал НОЛЬ при трёх
// живых производителях. Читатель, проверяющий предикат задачи #1776 по имени
// сценария, заключал «производителя нет» — и это ровно тот случай, когда
// предикат меряет СОГЛАШЕНИЕ ОБ ИМЕНАХ, а не предмет. Стоимость ошибки
// односторонняя: работу заводят заново, а существующие пробы остаются
// неизвестными следующему.
//
// Собирать три величины в ОДНУ пробу при этом нельзя: третья наблюдаема только
// на живой базе (её ставит периодический скан очереди), а первые две — в
// процессе без базы вовсе. Проба, требующая базы ради счётчика, перестала бы
// исполняться там, где он живёт.
package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/clients"
)

// Test_InviteMailRecorder_AllCellsExistBeforeTheFirstLetter — «ноль писем за всю
// жизнь» обязано быть ОТЛИЧИМО от «сюда никто не приходил».
//
// Ряд, которого нет вовсе, отвечает на «провязан ли механизм»; ряд со значением
// ноль — на «приходили ли». Без предварительной инициализации оба состояния
// выглядят одинаково: сборщик не видит ничего. Утверждается ПРИСУТСТВИЕ, а не
// значение: отсутствующий ряд читается как ноль и был бы неотличим.
func Test_InviteMailRecorder_AllCellsExistBeforeTheFirstLetter(t *testing.T) {
	r := NewRegistry()
	require.NotNil(t, r.InviteMailRecorder())

	for _, outcome := range clients.InviteMailOutcomes {
		v, present := labelledCounter(t, r, InviteMailOutcomesMetric,
			map[string]string{"outcome": outcome})
		assert.True(t, present,
			"клетка %q обязана существовать ДО первого письма: без неё «отказов не было» "+
				"неотличимо от «отказ ни разу не классифицировали»", outcome)
		assert.Equal(t, float64(0), v, "до первой отправки клетка %q обязана быть нулём", outcome)
	}
}

// Test_InviteMailRecorder_CountsIntoTheNamedCell — исход попадает в СВОЮ клетку,
// и соседние не растут.
//
// Без второй половины проба зеленела бы на счётчике, который увеличивает всё
// подряд, и «настройка отделена от сбоя» ничего не означало бы.
func Test_InviteMailRecorder_CountsIntoTheNamedCell(t *testing.T) {
	r := NewRegistry()
	rec := r.InviteMailRecorder()

	rec.IncInviteMailOutcome(clients.InviteMailOutcomeMisconfigured)

	got, _ := labelledCounter(t, r, InviteMailOutcomesMetric,
		map[string]string{"outcome": clients.InviteMailOutcomeMisconfigured})
	assert.Equal(t, float64(1), got, "названная клетка обязана вырасти")

	for _, other := range []string{
		clients.InviteMailOutcomeSent, clients.InviteMailOutcomeTransient,
	} {
		v, _ := labelledCounter(t, r, InviteMailOutcomesMetric, map[string]string{"outcome": other})
		assert.Equal(t, float64(0), v,
			"клетка %q не вправе расти от чужого исхода: настройка отделена от сбоя "+
				"собственной клеткой, а не комментарием", other)
	}
}

// Test_InviteMailRecorder_IsASingleInstance — два конструктора уронили бы старт
// на повторной регистрации ровно тогда, когда механизм провязали целиком.
func Test_InviteMailRecorder_IsASingleInstance(t *testing.T) {
	r := NewRegistry()
	assert.Same(t, r.InviteMailRecorder(), r.InviteMailRecorder(),
		"счётчик обязан быть единственным экземпляром реестра")
}
