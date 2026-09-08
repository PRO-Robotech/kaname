// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/treeposture"
)

// ОТПЕЧАТОК НЕ ЗАВИСИТ ОТ ПОСАДКИ (задача продукта #2273)
//
// # Предмет
//
// Прибор объявляет себя неподвижным при переезде каталога: строковая лексема,
// называющая координату собственного дерева, замещается постоянной меткой.
// Обещание держалось внутри одной посадки и терялось между посадками: словарь
// координат выводился из состава КОРНЯ, а корень в монорепо и в самостоятельном
// клоне модуля разный. Один и тот же код давал разные отпечатки.
//
// Цена измерена, а не предположена: `git archive HEAD:services/iam` в каталог
// вне репозитория, тот же состав, различие только в посадке — отпечаток состава
// совпадал, отпечаток СОДЕРЖИМОГО расходился (`b40f95a9…` против `06e3b406…`),
// и виноваты были два файла из девятнадцати. Следствие: четыре гейта свежести у
// арендатора не исполнялись вовсе, хотя оба их операнда с модулем едут.
//
// # Что здесь утверждается, а что нет
//
// Утверждается свойство ПОСТАВКИ: отпечаток есть функция содержимого модуля, а
// не того, что лежит рядом с ним. Не утверждается ничего о каталоге, которого в
// поставке нет и который завёлся в рабочей копии: словарь читается с файловой
// системы, и такой каталог его расширит — граница названа в шапке `fingerprint.go`.
//
// # Чем доказана способность упасть
//
// Инъекция здесь ДВУХСЛОЙНАЯ, и обе половины обязательны.
//
//	(а) фикстура собрана так, что ПРЕЖНЯЯ редакция распознавателя на ней
//	    расходится: литералы называют каталог, лежащий только у корня фикстуры
//	    платформы (`pkg/…`), каталог, лежащий только в поставке модуля
//	    (`internal/…`), и координату модуля в дереве платформы
//	    (`services/iam/…`). Верни распознавателю чтение состава корня — и
//	    сравнение краснеет, называя файл (проверено: `вердикт/query.go`);
//	(б) само сравнение обязано УМЕТЬ краснеть: одно-фактное расхождение деревьев
//	    (один оператор запроса) даёт красное с координатой, а тот же оператор,
//	    правленный в ОБОИХ, — молчание при СДВИНУВШЕМСЯ отпечатке. Без (б)
//	    «совпало» было бы неотличимо от «прибор перестал что-либо различать».
//
// # ОСЬ, КОТОРУЮ ДЕРЖИТ НЕ ЭТОТ ГЕЙТ — сказано, чтобы её не искали здесь
//
// Снятие ОДНОЙ ветви — той, что принимает координату модуля в дереве платформы,
// — этот гейт НЕ роняет: словарь поставки одинаков в обеих посадках, поэтому
// литерал `services/iam/…` становится значащим сразу у обеих, и равенство
// сохраняется. Ось держит сосед `TestSignificantContent_ProvenByInjection`
// (случай «каталог переехал в пути отчёта — НЕ сдвинулся»): при снятой ветви он
// краснеет. Проверено инъекцией обеих ветвей порознь.

// postureModuleDirs — каталоги верхнего уровня ПОСТАВКИ модуля.
//
// Они одни в обеих посадках — в этом всё дело: в монорепо они лежат под
// `services/iam/`, в клоне от корня.
var postureModuleDirs = []string{"cmd", "docs", "schema"}

// posturePlatformOnlyDirs — каталоги, которые есть только у КОРНЯ монорепо.
//
// Они и делали словари разными. Фикстура несёт их намеренно: без них прежняя
// редакция сошлась бы, и инъекция (а) ничего не доказывала бы.
var posturePlatformOnlyDirs = []string{"pkg", "proto", "gateway", "terraform"}

// postureVerdictSource — код вердикта фикстуры.
//
// Литералы подобраны так, чтобы задеть ВСЕ три ветви распознавателя и ещё одну,
// координатой не являющуюся:
//
//	путь импорта своего модуля      узнаётся по `module` из go.mod
//	координата модуля в платформе   `services/iam/…` — каталога `services` в клоне НЕТ
//	каталог верхнего уровня модуля  `internal/…` — каталога `internal` у корня монорепо ЕСТЬ,
//	                                но решает теперь поставка, а не корень
//	каталог, поставке НЕ принадлежащий `pkg/…` — значащ в ОБЕИХ посадках
//	литерал с косой чертой          `kaname.roles/updated_at` — положительный контроль
const postureVerdictSource = `// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

import "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"

const reportPath = "services/iam/internal/repo/kaname/pg/scalegrid/REPORT-R7-2-strength.txt"
const askerPath = "internal/repo/kaname/pg/relverdict/asker.go"
const foreignPath = "pkg/ids/ids.go"
const sameSubject = "kaname.roles/updated_at"

func askVerdict() string {
	_ = resource_mirror.Nothing
	_, _, _, _ = reportPath, askerPath, foreignPath, sameSubject
	return "SELECT id FROM kaname.access_bindings WHERE scope_id = $1"
}
`

// moduleCoord — координата модуля в дереве платформы.
//
// Берётся у `treeposture`, а не выписывается: выписанная разошлась бы с той, по
// которой прибор резолвит посадку, и фикстура молча перестала бы быть той формой,
// о которой гейт утверждает.
var moduleCoord = treeposture.ModuleDirInPlatform()

// posturePair — два дерева ОДНОЙ поставки в двух посадках.
type posturePair struct {
	platform   string
	standalone string
}

// buildPostureTree — дерево модуля в названной посадке.
//
// standalone=false: содержимое модуля лежит под `services/iam/`, а у корня есть
// собственные каталоги платформы и СВОЙ go.mod другого модуля — ровно та форма,
// в которой отчёты и снимались.
//
// standalone=true: то же содержимое лежит ОТ КОРНЯ, каталога `services` нет
// вовсе — ровно то, что даёт `git archive HEAD:services/iam`.
func buildPostureTree(t *testing.T, standalone bool, verdictSource string) string {
	t.Helper()
	root := t.TempDir()

	// Приставка модуля в этом дереве. Пустая в клоне — модуль там сам себе дерево.
	prefix := ""
	if !standalone {
		prefix = moduleCoord
		for _, d := range posturePlatformOnlyDirs {
			if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
				t.Fatalf("создание каталога платформы %s: %v", d, err)
			}
		}
		// Корневой go.mod платформы: другой модуль, и подъём обязан его НЕ брать.
		writeFile(t, filepath.Join(root, "go.mod"), "module github.com/PRO-Robotech/kacho\n\ngo 1.26.0\n")
	}

	// Каталоги ПОСТАВКИ — одни и те же в обеих посадках.
	for _, d := range postureModuleDirs {
		if err := os.MkdirAll(filepath.Join(root, prefix, d), 0o750); err != nil {
			t.Fatalf("создание каталога модуля %s: %v", d, err)
		}
	}

	// Предмет отпечатка. Координаты прибора записаны от корня ПЛАТФОРМЫ; здесь
	// они приводятся к посадке ровно так же, как их приводит сам прибор, —
	// снятием приставки модуля в самостоятельном клоне.
	inside := func(rel string) string {
		if standalone {
			rel = strings.TrimPrefix(strings.TrimPrefix(rel, moduleCoord), "/")
		}
		return filepath.Join(root, filepath.FromSlash(rel))
	}

	for _, dir := range []string{verdictDir, gridDir, migrateDir, reconcileDir} {
		if err := os.MkdirAll(inside(dir), 0o750); err != nil {
			t.Fatalf("создание %s: %v", dir, err)
		}
	}
	writeFile(t, filepath.Join(inside(verdictDir), "query.go"), verdictSource)
	writeFile(t, filepath.Join(inside(gridDir), "fingerprint.go"), "package scalegrid\n\nfunc fp() int { return 1 }\n")
	writeFile(t, filepath.Join(inside(gridDir), "report.go"), "package scalegrid\n\nfunc rep() int { return 2 }\n")
	writeFile(t, filepath.Join(inside(gridDir), "grid.go"),
		"package scalegrid\n\nconst gridReport = \"services/iam/internal/repo/kaname/pg/scalegrid/REPORT-R7-1-S1-scale-grid.txt\"\n\nfunc grid() string { return gridReport }\n")
	writeFile(t, filepath.Join(inside(migrateDir), "0001_initial.sql"),
		"-- +goose Up\nCREATE TABLE kaname.access_bindings (id text PRIMARY KEY);\n")

	// Предмет ВТОРОГО прибора — материализатор. Он тоже несёт координату
	// собственного дерева, и она тоже обязана узнаваться в обеих посадках.
	writeFile(t, filepath.Join(inside(reconcileDir), "forward.go"),
		"package reconcile\n\nconst home = \"services/iam/internal/apps/kaname/api/access_binding/reconcile\"\n\n"+
			"func forward() string { return \"INSERT INTO kaname.access_bindings (id) VALUES ($1)\" + home }\n")

	// go.mod МОДУЛЯ. В обеих посадках объявляет один и тот же путь — иначе
	// расхождение объяснялось бы разными модулями, а не посадкой.
	writeFile(t, filepath.Join(root, prefix, "go.mod"), "module github.com/PRO-Robotech/kaname\n\ngo 1.26.0\n")
	return root
}

func buildPosturePair(t *testing.T, verdictSource string) posturePair {
	t.Helper()
	return posturePair{
		platform:   buildPostureTree(t, false, verdictSource),
		standalone: buildPostureTree(t, true, verdictSource),
	}
}

// perFileDiff — тождества, чьё значащее содержимое разошлось между посадками.
//
// Гейт обязан НАЗЫВАТЬ виновника: «отпечатки разошлись» без координаты посылает
// читателя искать по девятнадцати файлам.
func perFileDiff(t *testing.T, p posturePair) []string {
	t.Helper()
	a, err := ComputeFingerprint(p.platform)
	if err != nil {
		t.Fatalf("отпечаток в посадке платформы: %v", err)
	}
	b, err := ComputeFingerprint(p.standalone)
	if err != nil {
		t.Fatalf("отпечаток в самостоятельном клоне: %v", err)
	}
	if len(a.Files) == 0 || len(b.Files) == 0 {
		t.Fatalf("пустой обход (%d и %d файлов): «совпало» означало бы «не с чем сравнивать»",
			len(a.Files), len(b.Files))
	}
	byID := map[string]string{}
	for i, id := range a.Identities {
		byID[id] = ContentOf(p.platform, a.Files[i])
	}
	var moved []string
	for i, id := range b.Identities {
		was, seen := byID[id]
		if !seen {
			moved = append(moved, id+" (в посадке платформы такого тождества нет)")
			continue
		}
		if now := ContentOf(p.standalone, b.Files[i]); now != was {
			moved = append(moved, id+": платформа "+was+", клон "+now)
		}
	}
	sort.Strings(moved)
	return moved
}

// TestFingerprintIsTheSameInBothPostures — ГЕЙТ.
func TestFingerprintIsTheSameInBothPostures(t *testing.T) {
	p := buildPosturePair(t, postureVerdictSource)

	platform, err := ComputeFingerprint(p.platform)
	if err != nil {
		t.Fatalf("отпечаток в посадке платформы не вычислен: %v", err)
	}
	standalone, err := ComputeFingerprint(p.standalone)
	if err != nil {
		t.Fatalf("отпечаток в самостоятельном клоне не вычислен: %v", err)
	}

	if len(platform.Files) == 0 || len(platform.Tables) == 0 {
		t.Fatalf("пустой обход: файлов %d, таблиц %d — совпадение отпечатков ничего не "+
			"доказывает, потому что сравнивать нечего", len(platform.Files), len(platform.Tables))
	}

	if platform.Composition != standalone.Composition {
		t.Fatalf("отпечаток СОСТАВА зависит от посадки: платформа %s, клон %s\n"+
			"  тождество обязано быть «роль каталога/имя файла», а не путём",
			platform.Composition, standalone.Composition)
	}
	if platform.Content != standalone.Content {
		t.Fatalf("отпечаток СОДЕРЖИМОГО зависит от посадки: платформа %s, клон %s\n"+
			"  разошлись: %s\n"+
			"  словарь координат обязан выводиться из ПОСТАВКИ модуля, а не из состава корня:\n"+
			"  корень монорепо несёт %v, а модуль — %v, и словарь из корня делает отпечаток\n"+
			"  функцией посадки (задача продукта #2273)",
			platform.Content, standalone.Content, strings.Join(perFileDiff(t, p), "; "),
			posturePlatformOnlyDirs, postureModuleDirs)
	}

	// ВТОРОЙ ПРИБОР — тем же правилом. Расхождение здесь означало бы вторую
	// реализацию распознавателя, разошедшуюся с первой молча.
	wdPlatform, err := ComputeWriteDeleteFingerprint(p.platform)
	if err != nil {
		t.Fatalf("отпечаток записи в посадке платформы: %v", err)
	}
	wdStandalone, err := ComputeWriteDeleteFingerprint(p.standalone)
	if err != nil {
		t.Fatalf("отпечаток записи в самостоятельном клоне: %v", err)
	}
	if wdPlatform.Content != wdStandalone.Content || wdPlatform.Composition != wdStandalone.Composition {
		t.Fatalf("отпечаток МАТЕРИАЛИЗАТОРА зависит от посадки: платформа %s/%s, клон %s/%s",
			wdPlatform.Composition, wdPlatform.Content, wdStandalone.Composition, wdStandalone.Content)
	}

	// СЛОВАРЬ — прямое утверждение о механизме, а не о его следствии.
	dictPlatform := topLevelOf(t, p.platform)
	dictStandalone := topLevelOf(t, p.standalone)
	if strings.Join(dictPlatform, ",") != strings.Join(dictStandalone, ",") {
		t.Fatalf("словарь координат зависит от посадки: платформа %v, клон %v",
			dictPlatform, dictStandalone)
	}

	t.Logf("перепись: файлов под отпечатком %d, тождеств сверено %d, таблиц выведено %d, "+
		"каталогов в словаре %d (%v); каталогов, лежащих только у корня платформы, %d (%v); "+
		"приборов сверено 2",
		len(platform.Files), len(platform.Identities), len(platform.Tables),
		len(dictPlatform), dictPlatform, len(posturePlatformOnlyDirs), posturePlatformOnlyDirs)
}

// topLevelOf — словарь распознавателя, отсортированный, для сравнения посадок.
func topLevelOf(t *testing.T, root string) []string {
	t.Helper()
	coords, err := newRepoCoordinates(root)
	if err != nil {
		t.Fatalf("распознаватель координат по %s не построен: %v", root, err)
	}
	if len(coords.topLevel) == 0 {
		t.Fatalf("словарь координат ПУСТ: распознаватель не узнал бы ни одной координаты")
	}
	out := make([]string, 0, len(coords.topLevel))
	for name := range coords.topLevel {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// TestPostureComparisonCanFailAndStaysSilentOnItsTwin — ИНЪЕКЦИЯ.
//
// Половина (б) доказательства: сравнение обязано уметь краснеть, а законный
// близнец — молчать, причём молчать НЕ оттого, что прибор перестал различать.
func TestPostureComparisonCanFailAndStaysSilentOnItsTwin(t *testing.T) {
	base := buildPosturePair(t, postureVerdictSource)
	baseFp, err := ComputeFingerprint(base.platform)
	if err != nil {
		t.Fatalf("отпечаток исходной пары: %v", err)
	}

	// (1) ОДНО-ФАКТНОЕ расхождение деревьев: оператор правлен ТОЛЬКО в клоне.
	edited := strings.Replace(postureVerdictSource,
		"WHERE scope_id = $1", "WHERE scope_id = $1 AND role_id = $2", 1)
	if edited == postureVerdictSource {
		t.Fatal("фикстура не изменилась: инъекция беспредметна")
	}
	split := posturePair{
		platform:   buildPostureTree(t, false, postureVerdictSource),
		standalone: buildPostureTree(t, true, edited),
	}
	moved := perFileDiff(t, split)
	if len(moved) == 0 {
		t.Fatal("одно-фактное расхождение деревьев отпечаток НЕ сдвинуло: сравнение " +
			"вырождено, и его молчание на настоящей паре ничего не значит")
	}
	if !strings.Contains(strings.Join(moved, ";"), "query.go") {
		t.Fatalf("расхождение названо БЕЗ координаты виновника: %v", moved)
	}

	// (2) ЗАКОННЫЙ БЛИЗНЕЦ: тот же оператор правлен в ОБЕИХ посадках.
	twin := buildPosturePair(t, edited)
	twinPlatform, err := ComputeFingerprint(twin.platform)
	if err != nil {
		t.Fatalf("отпечаток близнеца в посадке платформы: %v", err)
	}
	twinStandalone, err := ComputeFingerprint(twin.standalone)
	if err != nil {
		t.Fatalf("отпечаток близнеца в клоне: %v", err)
	}
	if twinPlatform.Content != twinStandalone.Content {
		t.Fatalf("близнец разошёлся по посадкам: платформа %s, клон %s\n  разошлись: %s",
			twinPlatform.Content, twinStandalone.Content, strings.Join(perFileDiff(t, twin), "; "))
	}
	if twinPlatform.Content == baseFp.Content {
		t.Fatalf("правка оператора отпечаток НЕ сдвинула (%s): «совпало в обеих посадках» "+
			"куплено тем, что прибор перестал различать код", twinPlatform.Content)
	}

	// (3) ПУСТОЙ ПРЕДМЕТ — отказ, а не зелёное.
	if _, err := ComputeFingerprint(t.TempDir()); err == nil {
		t.Fatal("дерево без предмета отпечаток ВЫЧИСЛИЛО: пустой обход обязан быть отказом, " +
			"иначе «совпало» означает «не с чем сравнивать»")
	}

	t.Logf("перепись инъекции: осей 3 (одно-фактное расхождение · законный близнец · "+
		"пустой предмет), расхождений названо %d, отпечаток базы %s, отпечаток близнеца %s",
		len(moved), baseFp.Content, twinPlatform.Content)
}
