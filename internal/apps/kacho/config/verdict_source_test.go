// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config_test

// verdict_source_test.go — РУЧКИ ИСТОЧНИКА ВЕРДИКТА: проверяется ИСХОД
// загрузки, а не наличие поля.
//
// Имена ENV этого сервиса не встречаются в дереве литералами — их выводит viper
// из пути ключа. Значит переименование ключа молча отвязывает документированную
// ручку, и ни сборка, ни пробы этого не замечают. Поэтому здесь стоит ровно та
// строка, которую увидит оператор, и требуется, чтобы она меняла загруженное
// значение.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// УМОЛЧАНИЕ НАЗВАНО ЯВНО: не переключено ничего, сверка включена.
//
// «Как получится» здесь означало бы, что источник вердикта о доступе зависит от
// того, чего оператор не написал.
func TestVerdictSourceDefaults(t *testing.T) {
	cfg, err := config.Load("")
	require.NoError(t, err)

	require.True(t, cfg.AuthZ.VerdictSwitchboard().IsEmpty(),
		"по умолчанию решение остаётся за движком по каждому типу")
	require.True(t, cfg.AuthZ.ShadowCompare,
		"по умолчанию сверка форм включена — выключенная сверка это осознанное действие")
}

// Ручка перечня типов меняет ИСХОД загрузки, и её имя — то самое, что
// напечатано оператору.
func TestDocumentedEnvName_VerdictFormTypes(t *testing.T) {
	t.Setenv("KACHO_IAM_AUTHZ__VERDICT_FORM_TYPES", "iam_group, iam_role")

	cfg, err := config.Load("")
	require.NoError(t, err)

	sb := cfg.AuthZ.VerdictSwitchboard()
	require.Equal(t, []string{"iam_group", "iam_role"}, sb.Declared())
	require.True(t, sb.Decides("iam_group"))
	require.False(t, sb.Decides("iam_user"))
}

// Положительный контроль отрицания: плоское имя (без `__`) ручкой НЕ является.
// Без этой половины проба зеленела бы на любом имени и ничего не сужала.
func TestFlatEnvName_VerdictFormTypes_IsNotAKnob(t *testing.T) {
	t.Setenv("KACHO_IAM_VERDICT_FORM_TYPES", "iam_group")

	cfg, err := config.Load("")
	require.NoError(t, err)

	require.True(t, cfg.AuthZ.VerdictSwitchboard().IsEmpty(),
		"плоское имя ручкой не является: у значения ровно один вход")
}

// Выключатель сверки (#763) — ОТДЕЛЬНОЕ значение, а не «позиция рубильника».
//
// Это разные предметы: «кто решает» и «сверяем ли вообще». Слить их значило бы
// сделать выключение сверки невыразимым, пока не переключён хоть один тип.
func TestDocumentedEnvName_ShadowCompareCanBeTurnedOff(t *testing.T) {
	t.Setenv("KACHO_IAM_AUTHZ__SHADOW_COMPARE", "false")

	cfg, err := config.Load("")
	require.NoError(t, err)

	require.False(t, cfg.AuthZ.ShadowCompare)
	require.True(t, cfg.AuthZ.VerdictSwitchboard().IsEmpty(),
		"выключение сверки не переключает ничего — предметы разные")
}

// Перечень из одних пустых записей — ПУСТОЙ рубильник для всех читателей.
//
// Канонический вырожденный вход: длина сырого значения не ноль, пригодных
// записей ноль. Читатель, меряющий длину строки, объявил бы источник
// переключённым, а путь решения продолжал бы спрашивать движок.
func TestBlankListIsAnEmptySwitchboard(t *testing.T) {
	t.Setenv("KACHO_IAM_AUTHZ__VERDICT_FORM_TYPES", " , ,")

	cfg, err := config.Load("")
	require.NoError(t, err)

	require.True(t, cfg.AuthZ.VerdictSwitchboard().IsEmpty())
}
