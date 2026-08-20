// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package verdictsource_test

// switchboard_test.go — РУБИЛЬНИК ИСТОЧНИКА ВЕРДИКТА: одно значение на процесс.
//
// Предмет проб — не «поле существует», а ИСХОД: что рубильник отвечает на
// вопрос «кто решает по этому типу». Тот же приём, что у круга доверенных
// отправителей (`grpcsrv.NewTrustedForwarders`): нормализация живёт в
// конструкторе, а все три читателя — путь решения, страж старта и самоотчёт —
// спрашивают ОДИН объект и ОДИН предикат. Тогда «страж прошёл» ⟺ «источник
// действительно переключён» по построению, а не потому, что три отдельно
// написанных тела совпали.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/verdictsource"
)

// Пустой рубильник НЕ переключает ничего. Умолчание названо явно и проверяется
// исходом: «как получится» здесь означало бы, что источник вердикта зависит от
// того, чего оператор не написал.
func TestEmptySwitchboardDecidesNothing(t *testing.T) {
	sb := verdictsource.New()

	require.False(t, sb.Decides("vpc_network"),
		"пустой рубильник обязан оставить решение движку по КАЖДОМУ типу")
	require.Empty(t, sb.Declared())
	require.True(t, sb.IsEmpty())
}

// Названный тип решает форма; НЕ названный — по-прежнему движок. Отрицание
// стоит в паре с положительным: без второй половины проба зеленела бы на
// рубильнике, переключающем всё разом.
func TestDeclaredTypeDecidesByForm_UndeclaredDoesNot(t *testing.T) {
	sb := verdictsource.New("vpc_network")

	require.True(t, sb.Decides("vpc_network"), "названный тип решает форма")
	require.False(t, sb.Decides("vpc_subnet"), "не названный тип остаётся за движком")
}

// Нормализация — В КОНСТРУКТОРЕ, как у круга отправителей: пустые записи и
// пробелы приходят из плоской переменной окружения («a, ,b»), и разбирать их
// у каждого читателя значило бы завести три места об одном предмете.
func TestConstructorNormalisesBlanksWhitespaceAndDuplicates(t *testing.T) {
	sb := verdictsource.New(" vpc_network ", "", "   ", "vpc_network", "project")

	require.Equal(t, []string{"project", "vpc_network"}, sb.Declared(),
		"перечень объявлен в устойчивом порядке, без пустых и без повторов")
	require.True(t, sb.Decides("vpc_network"))
	require.True(t, sb.Decides("project"))
}

// Рубильник из ОДНИХ пустых записей — это пустой рубильник, а не «переключено».
//
// Ровно тот класс, что у пустого круга доверенных отправителей: длина сырой
// строки не ноль, а записей, которые доедут до пути решения, — ноль. Страж,
// меряющий сырую строку, объявил бы источник переключённым, а путь решения
// продолжал бы спрашивать движок.
func TestSwitchboardOfBlanksIsEmpty(t *testing.T) {
	require.True(t, verdictsource.New("", " ").IsEmpty(),
		"перечень, у которого ноль пригодных записей, обязан быть пустым для ВСЕХ читателей")

	// Одинокая запятая — канонический вырожденный вход этого класса: длина
	// сырого значения единица, пригодных записей ноль. Читатель, меряющий
	// длину строки, объявил бы источник переключённым.
	require.True(t, verdictsource.Parse(",").IsEmpty(),
		"одинокая запятая даёт ноль записей — рубильник обязан быть пустым")

	require.False(t, verdictsource.New("vpc_network").Decides(""),
		"пустое имя типа не переключает ничего")
}

// Плоская строка разбирается ОДНИМ местом — тем же, что нормализует.
func TestParseSplitsFlatEnvValue(t *testing.T) {
	sb := verdictsource.Parse("vpc_network, project ,,vpc_subnet")

	require.Equal(t, []string{"project", "vpc_network", "vpc_subnet"}, sb.Declared())
}

// Пустое имя типа НИКОГДА не совпадает — даже когда рубильник непуст.
//
// Вопрос без разобранного типа приходит на путь решения (объект не разобран,
// область не названа), и совпадение с пустой записью означало бы переключение
// источника для вопроса, тип которого неизвестен.
func TestEmptyObjectTypeNeverMatches(t *testing.T) {
	sb := verdictsource.New("vpc_network")

	require.False(t, sb.Decides(""))
}
