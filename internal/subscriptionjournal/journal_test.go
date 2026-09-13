// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package subscriptionjournal

// journal_test.go — объявление владельца СВЯЗАНО С ДЕРЕВОМ, а не выписано рядом.
//
// Перечень видов, слова рода изменения и предикат сужения объявлены здесь
// значениями; без этих проб каждое из трёх устарело бы МОЛЧА — переименовали бы
// тип модели, поправили ограничение миграции, сузили предикат видимости, и
// объявление продолжало бы выглядеть исправным.
//
// Пробы выводят ожидаемое ИЗ ДЕРЕВА (канонической модели и текста миграции), а
// не повторяют его вторым списком: второй список разошёлся бы с первым так же
// молча, только позже.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/subscription"

	"github.com/PRO-Robotech/kaname/internal/authzfilter"
)

// journalMigration — миграция, заводящая журнал. Ограничение в ней и есть
// закрытый словарь, который объявление обязано повторять.
const journalMigration = "../migrations/20260914090000_resource_journal_serves_the_subscription.sql"

// canonicalModel — каноническая модель прав службы.
const canonicalModel = "../authzmodel/fga_model.fga"

func TestJournalDeclarationIsValid(t *testing.T) {
	require.NoError(t, Journal().Validate(),
		"объявление владельца обязано проходить суждение механизма: "+
			"иначе процесс не поднимется, и узнает об этом бой, а не прогон")
}

// TestProjectGateCarriesTheOwnersNotFoundForm — страж оси отвечает формой
// ПРОИЗВОДИТЕЛЯ, и обе величины пары читаются.
func TestProjectGateCarriesTheOwnersNotFoundForm(t *testing.T) {
	gate, err := ProjectGate()
	require.NoError(t, err)

	assert.Equal(t, "Project %s not found", gate.NotFoundFormat,
		"форма отсутствия обязана совпасть с промахом владельца ДОСЛОВНО: "+
			"различимый текст выдаёт существование чужого проекта")
	assert.Equal(t, authzfilter.RelationsFor("project"), gate.Relations,
		"отношения берутся у единственного объявления предиката видимости, "+
			"а не выписываются рядом")
	assert.NotEmpty(t, gate.Relations,
		"пустой перечень отношений оставил бы ось без стража")
}

// TestKindDictionaryAgreesWithTheMigration — словарь видов объявления и словарь,
// закрытый ограничением миграции, суть ОДИН словарь.
func TestKindDictionaryAgreesWithTheMigration(t *testing.T) {
	src, err := os.ReadFile(filepath.Clean(journalMigration))
	require.NoError(t, err, "миграция журнала обязана лежать по названному пути")

	declared := kindsIn(t, src, "resource_journal_resource_kind_check")
	require.NotEmpty(t, declared,
		"перепись пуста: ограничение не найдено или прочитано не то — "+
			"на пустой переписи сверка ниже зеленеет, ничего не проверив")

	var own []string
	for kind := range Journal().Mapping.Kinds {
		own = append(own, kind)
	}
	sort.Strings(own)

	assert.Equal(t, declared, own,
		"вид, закрытый базой и не объявленный владельцем, недоставляем; "+
			"объявленный и не закрытый базой — строка, которой не будет")
}

// TestChangeDictionaryAgreesWithTheMigration — то же для рода изменения.
func TestChangeDictionaryAgreesWithTheMigration(t *testing.T) {
	src, err := os.ReadFile(filepath.Clean(journalMigration))
	require.NoError(t, err)

	declared := kindsIn(t, src, "resource_journal_event_type_check")
	require.NotEmpty(t, declared, "перепись пуста: ограничение прочитано не то")

	var own []string
	for word := range Journal().Mapping.Changes {
		own = append(own, word)
	}
	sort.Strings(own)

	assert.Equal(t, declared, own,
		"род изменения обязан быть назван словарём, а не выведен из слова владельца")
}

// TestEveryKindIsALiveTypeOfTheModel — вид журнала обязан быть ТИПОМ МОДЕЛИ ПРАВ.
//
// Это и есть условие, по которому домен вообще может служить подписку: у вида без
// типа модели вопрос «вправе ли вызывающий видеть эту строку» задать НЕЧЕМ.
func TestEveryKindIsALiveTypeOfTheModel(t *testing.T) {
	src, err := os.ReadFile(filepath.Clean(canonicalModel))
	require.NoError(t, err, "каноническая модель обязана лежать по названному пути")

	live := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^type ([a-z][a-z0-9_]*)$`).
		FindAllStringSubmatch(string(src), -1) {
		live[m[1]] = true
	}
	require.NotEmpty(t, live, "перепись типов пуста: модель прочитана не та")

	for kind, binding := range Journal().Mapping.Kinds {
		assert.True(t, live[binding.ObjectType],
			"вид %q объявлен типом %q, которого в модели прав НЕТ: "+
				"строка такого вида не доставляется, а поток по нему молчит, "+
				"оставаясь «зелёным»", kind, binding.ObjectType)
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ на том же чтении: тип, которого в модели нет,
	// перепись не признаёт. Без него утверждение выше зеленело бы на карте,
	// признающей всё.
	assert.False(t, live["iam_widget"],
		"перепись обязана отвергать несуществующий тип — иначе она признаёт любой")
}

// TestStateIsNotProducedAndSaysSo — состояние не производится, причина названа.
func TestStateIsNotProducedAndSaysSo(t *testing.T) {
	for kind := range Journal().Mapping.Kinds {
		st, absence, err := state(subscription.Row{Kind: kind})
		assert.NoError(t, err, "вид %q словарю принадлежит: ошибки быть не должно", kind)
		assert.Nil(t, st, "состояние этот журнал не производит ни по одному виду")
		assert.Equal(t, subscription.StateNotProduced, absence,
			"причина обязана быть НАЗВАНА: неназванную сервер отдаёт как "+
				"REASON_UNSPECIFIED, и подписчик не отличит свойство журнала от сбоя")
	}

	// Вид вне словаря — ОШИБКА, а не молчаливое отсутствие: молчаливый nil
	// означал бы «предмет снят», и подписчик убрал бы живую строку.
	_, absence, err := state(subscription.Row{Kind: "iam_widget"})
	assert.Error(t, err)
	assert.Equal(t, subscription.StateAbsenceUnnamed, absence)
}

// kindsIn — значения закрытого словаря из НАЗВАННОГО ограничения миграции.
//
// Читается ограничение поимённо, а не все строковые литералы файла: второй путь
// подобрал бы слова соседних словарей и сверял бы объявление с шумом.
func kindsIn(t *testing.T, src []byte, constraint string) []string {
	t.Helper()
	text := string(src)
	at := strings.Index(text, "CONSTRAINT "+constraint)
	require.GreaterOrEqual(t, at, 0,
		"ограничение %q в миграции не найдено: переименовали — сверять нечего",
		constraint)
	tail := text[at:]
	if end := strings.Index(tail, "))"); end >= 0 {
		tail = tail[:end]
	}
	var out []string
	// Класс знаков ОБА: словарь видов записан строчными, словарь рода изменения —
	// заглавными. Узкий класс дал бы пустую перепись на втором, и проба честно
	// упала бы на собственной предпосылке — что и произошло при заведении.
	for _, m := range regexp.MustCompile(`'([A-Za-z_]+)'::text`).
		FindAllStringSubmatch(tail, -1) {
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}
