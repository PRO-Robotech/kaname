// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// directory_name_injection_test.go — доказательство того, что проверка имён
// каталогов СПОСОБНА упасть, и того, что она молчит на законных близнецах.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СИНТЕТИЧЕСКИЙ КОРЕНЬ, А НЕ ПРАВКА ДЕРЕВА
//
// Проверка читает дерево службы, которое читают и соседние сессии. Внести в
// него дефект ради доказательства значило бы править общее состояние. Поэтому
// разбор вынесен в чистую функцию над ПРОИЗВОЛЬНЫМ корнем, а сюда подаётся
// корень, собранный в каталоге прогона.
//
// ─────────────────────────────────────────────────────────────────────────────
// КАЖДАЯ ИНЪЕКЦИЯ МЕНЯЕТ РОВНО ОДИН ФАКТ ПРОТИВ КОНТРОЛЯ
//
// Контроль стоит первым и обязан МОЛЧАТЬ. Дальше по одной оси меняется ровно
// один факт: иначе красное могло бы прийти от соседа, а проверка осталась бы
// вакуумной, не показав этого ничем.
//
// Осей «краснеет» — три (сегмент пути · ссылка на `apps` · ссылка на `repo`).
// Осей «молчит» — семь, и они несущие: без них проверка ловила бы СЛОВО, а не
// каталог, и первый же ложный срабат на пути модуля, на пакете контракта или на
// каталоге соседней службы её бы отключил.
//
// У каждой пропущенной полосы стоит ПАРА: «в полосе — молчит» и «та же проза вне
// полосы — находка». Без второй половины пропуск был бы маской, а не полосой.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// dirRootWith собирает корень из перечисленных файлов с заданным содержимым.
// Файлов ровно столько, сколько подано: перепись тогда прямо называет, что
// прочитано ровно то, что подано.
func dirRootWith(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o750))
		require.NoError(t, os.WriteFile(full, []byte(body), 0o600))
	}
	return root
}

// soundTree — законный близнец: каталог зовётся каноническим именем, и ссылка
// на него в содержимом тоже каноническая. Проверка обязана молчать.
func soundTree() map[string]string {
	return map[string]string{
		"internal/apps/kaname/api/sample.go": "// use-case живёт в `internal/apps/kaname/api/`\n" +
			"package api\n",
		"internal/repo/kaname/iface.go": "// порт объявлен в `repo/kaname`\npackage kaname\n",
	}
}

// ── Контроль: годный корень молчит ──────────────────────────────────────────

func TestDirNameInjectionControl_CanonicalRootIsSilent(t *testing.T) {
	census, findings, err := scanDirectoryNames(syntheticCorpus(t, dirRootWith(t, soundTree())))
	require.NoError(t, err)
	require.Empty(t, findings, "годный корень объявлен нарушением: проверка ловит форму, а не существо")
	require.Equal(t, 2, census.filesRead, "контроль беспредметен: прочитано не то число файлов")
	require.NotZero(t, census.canonicalSegments, "контроль беспредметен: канонического сегмента не распознано")
	require.NotZero(t, census.canonicalRefs, "контроль беспредметен: канонической ссылки не распознано")
	require.Zero(t, census.retiredSegments)
	require.Zero(t, census.retiredRefs)
}

// ── Ось 1: сегмент пути — НАХОДКА, и она называет координату ────────────────

func TestDirNameInjection_RetiredPathSegmentIsFound(t *testing.T) {
	files := soundTree()
	files["internal/repo/kacho/iface.go"] = "package kacho\n"
	census, findings, err := scanDirectoryNames(syntheticCorpus(t, dirRootWith(t, files)))
	require.NoError(t, err)
	require.NotEmpty(t, findings, "каталог с отставленным именем не найден — проверка вакуумна")
	require.Equal(t, 1, census.retiredSegments)
	require.Contains(t, findings[0].String(), "internal/repo/kacho/iface.go",
		"находка не называет координату: читатель ищет её глазами")
}

// ── Ось 2 и 3: ссылка в содержимом — НАХОДКА по каждому родителю ────────────

func TestDirNameInjection_RetiredAppsReferenceIsFound(t *testing.T) {
	files := soundTree()
	files["docs/overview.md"] = "use-case живут в `internal/apps/kacho/api/`\n"
	census, findings, err := scanDirectoryNames(syntheticCorpus(t, dirRootWith(t, files)))
	require.NoError(t, err)
	require.Equal(t, 1, census.retiredRefs)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0].String(), "docs/overview.md:1")
}

func TestDirNameInjection_RetiredRepoReferenceIsFound(t *testing.T) {
	files := soundTree()
	files["docs/overview.md"] = "порт объявлен в `repo/kacho`\n"
	census, findings, err := scanDirectoryNames(syntheticCorpus(t, dirRootWith(t, files)))
	require.NoError(t, err)
	require.Equal(t, 1, census.retiredRefs)
	require.Len(t, findings, 1)
}

// ── Молчит: каталог СОСЕДНЕЙ службы ─────────────────────────────────────────
//
// У соседа своего имени продукта нет, его каталог законно зовётся именем
// платформы. Проверка, роняющая прогон на такой ссылке, требовала бы
// переименования чужого дерева.

func TestDirNameInjection_ForeignServiceDirectoryStaysSilent(t *testing.T) {
	files := soundTree()
	files["docs/overview.md"] = "по образцу `services/nlb/internal/repo/kacho/pg/dto/`\n" +
		"и `kacho-vpc/internal/apps/kacho/shared`\n"
	census, findings, err := scanDirectoryNames(syntheticCorpus(t, dirRootWith(t, files)))
	require.NoError(t, err)
	require.Empty(t, findings, "каталог соседней службы объявлен нарушением")
	require.Equal(t, 2, census.skippedForeign, "пропуск соседей не сосчитан: полоса не отличима от «не рассматривалась»")
}

func TestDirNameInjection_TheSameFormWithoutAForeignAnchorIsFound(t *testing.T) {
	files := soundTree()
	files["docs/overview.md"] = "по образцу `internal/repo/kacho/pg/dto/`\n"
	_, findings, err := scanDirectoryNames(syntheticCorpus(t, dirRootWith(t, files)))
	require.NoError(t, err)
	require.Len(t, findings, 1, "без анкера соседа та же форма обязана быть находкой — иначе пропуск есть маска")
}

// ── Молчит: путь модуля, пакет контракта и прочие соседи по СЛОВУ ───────────

func TestDirNameInjection_ModuleAndContractNamesStaySilent(t *testing.T) {
	files := soundTree()
	files["internal/apps/kaname/api/wire.go"] = "" +
		"import \"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role\"\n" +
		"// пакет контракта — kaname.cloud.iam.v1; метрика — kacho_quota_refuse; якорь — cluster_root\n" +
		"// ручка KACHO_MONOREPO и общий слой tests/newman/kacholib/ тоже несут это слово\n"
	census, findings, err := scanDirectoryNames(syntheticCorpus(t, dirRootWith(t, files)))
	require.NoError(t, err)
	require.Empty(t, findings,
		"слово `kacho` вне двусоставной формы объявлено нарушением: проверка судит слово, а не каталог")
	require.Zero(t, census.retiredRefs)
	require.Zero(t, census.skippedForeign, "пропуск соседей сработал там, где соседей нет")
}

// ── Молчит: сегмент, продолжающийся дальше ──────────────────────────────────

func TestDirNameInjection_LongerSegmentStaysSilent(t *testing.T) {
	files := soundTree()
	files["docs/overview.md"] = "алиас `apps/kachopg` каталогом предмета не является\n"
	_, findings, err := scanDirectoryNames(syntheticCorpus(t, dirRootWith(t, files)))
	require.NoError(t, err)
	require.Empty(t, findings, "`apps/kachopg` объявлен нарушением: правая граница сегмента не проверяется")
}

// ── Полоса применённых миграций: молчит В полосе, находка ВНЕ неё ───────────

func TestDirNameInjection_AppliedMigrationStaysSilent(t *testing.T) {
	files := soundTree()
	files["internal/migrations/0001_initial.sql"] = "-- go test ./services/iam/internal/repo/kacho/pg/\n"
	census, findings, err := scanDirectoryNames(syntheticCorpus(t, dirRootWith(t, files)))
	require.NoError(t, err)
	require.Empty(t, findings, "применённая миграция объявлена нарушением: её править запрещает ban #5")
	require.Equal(t, 1, census.filesMigration)
	require.Equal(t, 1, census.skippedMigration, "пропуск миграции не сосчитан")
}

func TestDirNameInjection_TheSameProseOutsideMigrationsIsFound(t *testing.T) {
	files := soundTree()
	files["internal/notmigrations/0001_initial.sql"] = "-- go test ./services/iam/internal/repo/kacho/pg/\n"
	_, findings, err := scanDirectoryNames(syntheticCorpus(t, dirRootWith(t, files)))
	require.NoError(t, err)
	require.Len(t, findings, 1, "вне каталога миграций та же проза обязана быть находкой")
}

// ── Полоса захваченных отчётов: молчит В полосе, находка ВНЕ неё ────────────

func TestDirNameInjection_CapturedReportStaysSilent(t *testing.T) {
	files := soundTree()
	files["internal/repo/kaname/pg/scalegrid/REPORT-R7-1.txt"] = "ok services/iam/internal/repo/kacho/pg 1.2s\n"
	census, findings, err := scanDirectoryNames(syntheticCorpus(t, dirRootWith(t, files)))
	require.NoError(t, err)
	require.Empty(t, findings, "захваченный отчёт объявлен нарушением: он свидетельствует о том, что было")
	require.Equal(t, 1, census.filesReport)
	require.Equal(t, 1, census.skippedReport)
}

func TestDirNameInjection_TheSameLineOutsideAReportIsFound(t *testing.T) {
	files := soundTree()
	files["internal/repo/kaname/pg/scalegrid/notes.txt"] = "ok services/iam/internal/repo/kacho/pg 1.2s\n"
	_, findings, err := scanDirectoryNames(syntheticCorpus(t, dirRootWith(t, files)))
	require.NoError(t, err)
	require.Len(t, findings, 1, "вне отчёта та же строка обязана быть находкой")
}

// ── Полоса самой проверки: молчит В перечне, находка ВНЕ него ──────────────

func TestDirNameInjection_TheCheckDoesNotJudgeItsOwnDeclaration(t *testing.T) {
	files := soundTree()
	files["internal/supplyhygiene/directory_name_test.go"] = "// запрещено: `apps/kacho` и `repo/kacho`\n"
	census, findings, err := scanDirectoryNames(syntheticCorpus(t, dirRootWith(t, files)))
	require.NoError(t, err)
	require.Empty(t, findings, "проверка краснеет на собственном объяснении")
	require.Equal(t, 1, census.filesOwn)
	require.Equal(t, 2, census.skippedOwn)
}

func TestDirNameInjection_TheSameDeclarationOutsideTheListIsFound(t *testing.T) {
	files := soundTree()
	files["internal/supplyhygiene/other_test.go"] = "// запрещено: `apps/kacho` и `repo/kacho`\n"
	census, findings, err := scanDirectoryNames(syntheticCorpus(t, dirRootWith(t, files)))
	require.NoError(t, err)
	// Находка одна — по строке, а ссылок в ней две: перепись считает ссылки,
	// перечень находок адресует читателя к строке.
	require.Len(t, findings, 1, "файл вне перечня обязан судиться как любой другой")
	require.Equal(t, 2, census.retiredRefs, "обе ссылки строки обязаны быть сосчитаны")
	require.Zero(t, census.skippedOwn, "файл вне перечня зачтён в полосу самой проверки")
}

// ── Пустой обход отличим от нуля находок ───────────────────────────────────

func TestDirNameInjection_EmptyWalkIsDistinguishableFromZeroFindings(t *testing.T) {
	_, _, err := scanDirectoryNames(syntheticCorpus(t, t.TempDir()))
	require.Error(t, err, "пустой обход выдан за зелёный прогон")
	require.Contains(t, err.Error(), "обход пуст")
}

// ── Положительный контроль не выполняется чем попало ───────────────────────

func TestDirNameInjection_CanonicalInsideALongerSegmentDoesNotSatisfyTheControl(t *testing.T) {
	census, _, err := scanDirectoryNames(syntheticCorpus(t, dirRootWith(t, map[string]string{
		"internal/apps/kanamex/sample.go": "// ссылка на `apps/kanamex` каталогом предмета не является\n",
	})))
	require.NoError(t, err)
	require.Zero(t, census.canonicalSegments,
		"`kanamex` засчитан каноническим сегментом: контроль выполнился чем угодно")
	require.Zero(t, census.canonicalRefs,
		"`apps/kanamex` засчитан канонической ссылкой: правая граница не проверяется")
}
