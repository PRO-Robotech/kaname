// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// migration_not_a_writer_of_module_role_test.go — ГЕЙТ КЛАССА: ДОБАВЛЕННАЯ
// миграция не вставляет роль модуля, у которого есть манифест (задача #17, порт
// семейства `migrationnotawriterofmodulerole`).
//
// # Гейт судит ДОБАВЛЕННЫЕ миграции, а не всё дерево
//
// Роли модулей пишут ПРИМЕНЁННЫЕ миграции, а применённую миграцию не правят
// (ban #5): «починка» здесь означала бы правку того, что уже стоит в боевой
// базе, и мигратор её не заметил бы вовсе. Требовать её значило бы держать ствол
// красным за прошлое, которого правкой не изменить.
//
// Исторический остаток при этом не молчание, а ЧИСЛО: перепись печатает его на
// каждом прогоне.
//
// # Ведомость исторических строк рассмотрена и отвергнута
//
// Ведомость ТОЧНЫМ числом краснела бы на каждом шаге переезда, то есть на
// движении К СОБСТВЕННОЙ ЦЕЛИ, а ПОТОЛКОМ не краснела бы никогда и потому не
// истекла бы. Плюс она стала бы вторым местом об одном предмете.
//
// # Перепись идёт по ВСЕМУ дереву, а находки — только по добавленному
//
// Разделение обязательно. Порог стережёт РАЗБОР: сменится форма записи имени — и
// гейт замолчит, не находя предмета. Считай перепись по добавленному, и ветка
// без миграций роняла бы порог, то есть гейт падал бы на достижении собственной
// цели.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// migration_not_a_writer_of_module_role_injection_test.go.
package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/gitenv"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// migrationRoleCensusFloor — блоков вставки роли, ниже которого обход
// беспредметен: обвал переписи означает, что разбор перестал видеть предмет.
const migrationRoleCensusFloor = 5

// TestMODRD23MigrationDoesNotWriteARoleOfAManifestBearingModule — имя сохранено
// дословно с монорепо.
func TestMODRD23MigrationDoesNotWriteARoleOfAManifestBearingModule(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	tree := gateTree(t, root)

	bearing, yamlScanned := manifestBearingModules(t, root, tree)

	var (
		rels                      []string
		blocks, names, unreadable int
		sites                     []check.MigrationRoleSite
		parsedMigrated            int
	)
	for rel := range tree.files {
		if strings.HasPrefix(rel, check.MigrationsDirRel+"/") && strings.HasSuffix(rel, ".sql") {
			rels = append(rels, rel)
		}
	}
	sort.Strings(rels)
	for _, rel := range rels {
		src, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if rerr != nil {
			t.Errorf("%s не прочитан: %v — файл НЕ осмотрен", rel, rerr)
			continue
		}
		parsedMigrated++
		s, census := check.ScanMigrationRoleInserts(rel, src)
		blocks += census.Blocks
		names += census.Names
		unreadable += census.Unreadable
		sites = append(sites, s...)
	}

	// Перепись ДЕРЕВА и проверки РАЗБОРА идут ДО разрешения ствола: иначе клон
	// без ствола уходил бы в пропуск, не сказав ни числа, и «ноль находок» снова
	// стало бы неотличимо от «ноль прочитанного».
	t.Logf("перепись: файлов YAML осмотрено %d, манифестов модулей найдено %d %v; "+
		"миграций прочитано %d, блоков вставки роли %d, имён ролей извлечено %d, "+
		"блоков с НЕПРОЧИТАННЫМ именем %d",
		yamlScanned, len(bearing), manifestModuleNames(bearing), parsedMigrated,
		blocks, names, unreadable)

	if parsedMigrated == 0 {
		t.Fatalf("миграций прочитано ноль — каталог %s переехал, и гейт стережёт "+
			"координату, которой больше нет", check.MigrationsDirRel)
	}
	if blocks < migrationRoleCensusFloor {
		t.Fatalf("блоков вставки роли прочитано %d при пороге %d — разбор перестал видеть "+
			"предмет, и его молчание сказано ни о чём", blocks, migrationRoleCensusFloor)
	}
	if names == 0 {
		t.Fatalf("имён ролей извлечено ноль при %d блоках — форма записи имени сменилась, "+
			"и разбор МОЛЧИТ вместо того чтобы находить", blocks)
	}
	// Блок, вставляющий роль, у которого имя прочитать не удалось, — НЕВИДИМОСТЬ,
	// а не находка и не молчание: роль вставлена, а гейт о ней не судил. Порог
	// «имён ноль» ловит только ПОЛНУЮ слепоту: смени форму один блок из сорока
	// восьми — сорок семь имён скрыли бы сорок восьмое.
	if unreadable > 0 {
		t.Fatalf("блоков вставки роли, из которых имя прочитать НЕ УДАЛОСЬ, %d при %d "+
			"прочитанных именах. Роль вставлена, а гейт о ней не судил: это не находка и "+
			"не молчание, а невидимость. Неизвестную форму надо ЗАВЕСТИ в разбор, "+
			"а не пропустить", unreadable, names)
	}

	if len(bearing) == 0 {
		// Популяция пуста — и это НАЗВАНО, а не выдано за проверенное. Молчание
		// гейта здесь означает «сверять не с чем», а не «расхождений нет».
		t.Log("манифестов модулей в дереве НОЛЬ — популяция гейта пуста: миграция " +
			"остаётся законным писателем КАЖДОЙ роли. Это не «проверено», это «сверять не с " +
			"чем»: разбор прочитал дерево и не опознал в нём ни одного манифеста")
		return
	}

	// Состав ДОБАВЛЕННОГО — предмет находок. Ствол разрешается ЗДЕСЬ, после
	// переписи дерева и проверок разбора: его недостижимость есть отказ
	// ПРЕДПОСЫЛКИ, и он обязан прийти отдельно от них, а не вместо них.
	base, ok := trunkRef(root)
	if !ok {
		t.Skipf("УСЛОВИЕ НЕ СОЗДАНО (не находка): ствол %s в этом клоне не разрешается — "+
			"состав ДОБАВЛЕННОГО установить нечем. Перепись дерева выше снята и остаётся "+
			"верной; о находках вердикта НЕТ ни зелёного, ни красного", trunkRefName)
	}
	added := addedMigrationFiles(t, root, base)
	addedSites := sitesInFiles(sites, added)

	// Исторический остаток — ЧИСЛО на каждом прогоне, а не молчание. Находкой он
	// быть не может: применённую миграцию не правят (ban #5).
	t.Logf("добавлено относительно %s миграций %d, из них вставок роли %d; "+
		"исторический остаток: вставок роли модуля с манифестом в УЖЕ ПРИМЕНЁННЫХ "+
		"миграциях %d — правке не подлежат (ban #5), их переезд к применителю есть "+
		"отдельный предмет",
		base, len(added), len(addedSites),
		len(migrationRoleFindings(sites, bearing))-len(migrationRoleFindings(addedSites, bearing)))

	if findings := migrationRoleFindings(addedSites, bearing); len(findings) > 0 {
		t.Fatalf("ДОБАВЛЕННАЯ миграция вставляет роль модуля, у которого ЕСТЬ манифест — "+
			"%d место(а):\n  %s\n\n"+
			"Это второй писатель одного предмета: правка манифеста до строки не доедет, "+
			"потому что строку держит миграция, и перепись применителя об этом промолчит.\n"+
			"Снятие: роль объявляется манифестом, а миграция её не вставляет.",
			len(findings), strings.Join(findings, "\n  "))
	}
}

// trunkRefName — ствол, относительно которого считается ДОБАВЛЕННОЕ.
//
// Имя объявлено ОДНО: релизная линия — точка интеграции, а не ствол, и
// «добавленное относительно неё» означало бы «добавленное этой полосой», то есть
// другой предмет. Гейт судит то, что уезжает в ствол.
const trunkRefName = "origin/main"

// trunkRef — разрешается ли ствол в этом клоне.
//
// Отсутствие ствола — ТРЕТИЙ ИСХОД, а не находка и не зелёное: у свежего клона
// без выборки истории его нет by construction.
func trunkRef(root string) (string, bool) {
	if err := gitenv.Command(root, "rev-parse", "--verify", "--quiet", trunkRefName).Run(); err != nil {
		return "", false
	}
	return trunkRefName, true
}

// manifestBearingModules — модули, у которых манифест в дереве ЕСТЬ. Перечень
// выводится обходом, а не выписывается.
func manifestBearingModules(t *testing.T, root string, tree gateFileTree) (map[string]string, int) {
	t.Helper()
	out := map[string]string{}
	var scanned int
	for rel := range tree.files {
		if !strings.HasSuffix(rel, ".yaml") && !strings.HasSuffix(rel, ".yml") {
			continue
		}
		// Фикстуры проб исключены по каталогу: они объявляют чужой модуль и
		// сделали бы каждую его миграцию находкой. Это единственное исключение.
		if strings.Contains(rel, "/testdata/") || strings.Contains(rel, "_test") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		scanned++
		if site, ok := check.ScanModuleManifest(rel, src); ok {
			out[site.Module] = site.File
		}
	}
	return out, scanned
}

// sitesInFiles — сайты, чей файл назван перечнем.
//
// Вынесена ЧИСТОЙ функцией намеренно: ось «судятся только добавленные»
// доказывается инъекцией на синтетическом входе, не трогая живое дерево.
func sitesInFiles(sites []check.MigrationRoleSite, files map[string]bool) []check.MigrationRoleSite {
	var out []check.MigrationRoleSite
	for _, s := range sites {
		if files[s.File] {
			out = append(out, s)
		}
	}
	return out
}

// addedMigrationFiles — миграции, ДОБАВЛЕННЫЕ относительно ствола.
func addedMigrationFiles(t *testing.T, root, base string) map[string]bool {
	t.Helper()
	out, err := gitenv.Command(root, "diff", "--name-only", "--diff-filter=A",
		base+"...HEAD").Output()
	if err != nil {
		t.Fatalf("состав добавленного относительно %s не прочитан: %v — это отказ "+
			"ПРЕДПОСЫЛКИ, а не пустой список: без него гейт судил бы дерево, а не изменение",
			base, err)
	}
	files := map[string]bool{}
	for _, rel := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		rel = strings.TrimSpace(rel)
		if rel == "" || !strings.HasSuffix(rel, ".sql") || !strings.Contains(rel, "/migrations/") {
			continue
		}
		files[rel] = true
	}
	return files
}

// migrationRoleFindings — предикат находки. Тот же зовёт инъекция.
func migrationRoleFindings(sites []check.MigrationRoleSite, bearing map[string]string) []string {
	var out []string
	for _, s := range sites {
		if s.Owner == "" {
			continue
		}
		if manifestFile, ok := bearing[s.Owner]; ok {
			out = append(out, fmt.Sprintf("%s: роль %q модуля %q, чей манифест лежит в %s",
				s.File, s.Name, s.Owner, manifestFile))
		}
	}
	sort.Strings(out)
	return out
}

// manifestModuleNames — имена модулей в устойчивом порядке для переписи.
func manifestModuleNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
