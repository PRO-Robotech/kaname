// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// Инъекция гейта описи настроек. Вход СИНТЕТИЧЕСКИЙ, и это решение: фикстура,
// привязанная к живой строке описи, истекла бы вместе с ней — ровно в тот день,
// когда опись снимут, а способность гейта падать станет недоказанной.
//
// Ключи производителя тоже синтетические и минимальные: инъекция утверждает
// РАБОТУ СУДЬИ, а не сегодняшний состав настройки.

// injKeys — множество ключей «производителя» для инъекции.
var injKeys = map[string]bool{
	"authn":                true,
	"authn.session-ttl":    true,
	"repository":           true,
	"repository.postgres":  true,
	"jobs":                 true,
	"jobs.target-drain":    true,
	"jobs.target-drain.on": true,
}

// injTable — опись с одной строкой: `key` попадает в колонку ключа настройки.
func injTable(key string) string {
	return strings.Join([]string{
		"## Конфигурация",
		"",
		"| Env var | YAML key | Default | Описание |",
		"|---|---|---|---|",
		"| `KANAME_X` | `" + key + "` | — | что-то |",
		"",
	}, "\n")
}

// TestDocumentedSettingKeyInjection_AbsentKeyIsFoundWithItsCoordinate — ДЕФЕКТ
// ловится, и находка называет ПРИЧИНУ (какой ключ), а не симптом.
func TestDocumentedSettingKeyInjection_AbsentKeyIsFoundWithItsCoordinate(t *testing.T) {
	t.Parallel()

	corpus := check.TreeCorpus{"docs/engineering/components/99-inj.md": injTable("extapi.provider.admin-token")}
	findings, census, err := check.JudgeDocumentedSettingKeys(corpus, injKeys)
	require.NoError(t, err)
	require.Len(t, findings, 1, "перепись: %s", census)
	require.Equal(t, "extapi.provider.admin-token", findings[0].Key)
	require.Equal(t, "docs/engineering/components/99-inj.md", findings[0].File)
	require.Equal(t, 5, findings[0].Line)
	require.Contains(t, findings[0].String(), "которого в дереве настроек НЕТ")
	require.Equal(t, 1, census.Tables)
	require.Equal(t, 1, census.Rows)
}

// TestDocumentedSettingKeyInjection_LawfulTwinIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ той
// же формы молчит. Отличие от дефекта — РОВНО ОДИН факт: существует ли ключ.
func TestDocumentedSettingKeyInjection_LawfulTwinIsSilent(t *testing.T) {
	t.Parallel()

	corpus := check.TreeCorpus{"docs/engineering/components/99-inj.md": injTable("authn.session-ttl")}
	findings, census, err := check.JudgeDocumentedSettingKeys(corpus, injKeys)
	require.NoError(t, err)
	require.Empty(t, findings, "законный ключ объявлен находкой; перепись: %s", census)
	require.Equal(t, 1, census.Matched)
	require.Equal(t, 1, census.Tables)
}

// TestDocumentedSettingKeyInjection_EmptyLedgerIsTheGoalNotAFailure — проза без
// единой описи ПРОХОДИТ и объявляет «описей 0». Гейт не имеет права падать на
// достижении своей цели.
func TestDocumentedSettingKeyInjection_EmptyLedgerIsTheGoalNotAFailure(t *testing.T) {
	t.Parallel()

	corpus := check.TreeCorpus{"docs/engineering/components/99-inj.md": "# Заголовок\n\nпроза без описи.\n"}
	findings, census, err := check.JudgeDocumentedSettingKeys(corpus, injKeys)
	require.NoError(t, err)
	require.Empty(t, findings)
	require.Equal(t, 0, census.Tables)
	require.Equal(t, 1, census.Files)
}

// TestDocumentedSettingKeyInjection_EmptyWalkIsNotAVerdict — обход, не принёсший
// ни одного документа, ОТКАЗЫВАЕТ: «находок ноль» здесь означало бы «прочитано
// ноль».
func TestDocumentedSettingKeyInjection_EmptyWalkIsNotAVerdict(t *testing.T) {
	t.Parallel()

	_, _, err := check.JudgeDocumentedSettingKeys(check.TreeCorpus{}, injKeys)
	require.ErrorIs(t, err, check.ErrEmptyTraversal)
}

// TestDocumentedSettingKeyInjection_EmptyKeySetIsRefused — предпосылка: пустое
// множество ключей означает «судить не по чему», и это ОТКАЗ, а не «находок
// много».
func TestDocumentedSettingKeyInjection_EmptyKeySetIsRefused(t *testing.T) {
	t.Parallel()

	corpus := check.TreeCorpus{"docs/engineering/components/99-inj.md": injTable("authn.session-ttl")}
	_, _, err := check.JudgeDocumentedSettingKeys(corpus, map[string]bool{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "предпосылка не выполнена")
}

// TestDocumentedSettingKeyInjection_RowWithoutAKeyIsABoundaryNotAFinding —
// ячейка без токена ключевой формы — граница, и она СЧИТАЕТСЯ отдельно, а не
// растворяется в зелёном.
func TestDocumentedSettingKeyInjection_RowWithoutAKeyIsABoundaryNotAFinding(t *testing.T) {
	t.Parallel()

	corpus := check.TreeCorpus{"docs/engineering/components/99-inj.md": injTable("—")}
	findings, census, err := check.JudgeDocumentedSettingKeys(corpus, injKeys)
	require.NoError(t, err)
	require.Empty(t, findings)
	require.Equal(t, 1, census.Rows)
	require.Equal(t, 1, census.RowsWithoutKey)
}

// TestDocumentedSettingKeyInjection_UnknownColumnSpellingIsCounted — написание
// колонки, словарём НЕ опознанное, даёт не молчание, а число переписи с
// координатой.
func TestDocumentedSettingKeyInjection_UnknownColumnSpellingIsCounted(t *testing.T) {
	t.Parallel()

	body := strings.Replace(injTable("extapi.provider.admin-token"), "YAML key", "YAML-путь", 1)
	findings, census, err := check.JudgeDocumentedSettingKeys(
		check.TreeCorpus{"docs/engineering/components/99-inj.md": body}, injKeys)
	require.NoError(t, err)
	require.Empty(t, findings, "колонка не опознана — судить нечего")
	require.Equal(t, 0, census.Tables)
	require.Len(t, census.UnnamedYAMLHeaders, 1,
		"промах словаря обязан быть виден числом, а не молчанием; перепись: %s", census)
	require.Contains(t, census.UnnamedYAMLHeaders[0], "yaml-путь")
}
