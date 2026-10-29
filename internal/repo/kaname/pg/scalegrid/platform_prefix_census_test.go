// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid_test

// platform_prefix_census_test.go — В ДЕРЕВЕ ХРАНИЛИЩА НЕ ОСТАЁТСЯ КООРДИНАТ С
// ПРИСТАВКОЙ МОНОРЕПО ПЛАТФОРМЫ (kaname#141).
//
// # Предмет
//
// Служба вынесена из монорепо собственным репозиторием; каталога, которым
// монорепо её адресовал (`treeposture.ModuleDirInPlatform`), здесь нет. Всякая
// координата с этой приставкой — в коде, в комментарии, в отчёте — называет
// читателю место, которого нет: команда пересъёма отвечает «нет такого
// каталога», ссылка на приёмку никуда не ведёт, перечень файлов в шапке отчёта
// не совпадает с выводом git.
//
// Гейт ТЕКСТОВЫЙ намеренно: предмет — что прочтёт человек, а читает он и прозу,
// и отчёты. Приставка спрашивается у её единственного дома, а не выписывается:
// литерал в этом файле сделал бы гейт находкой самого себя.
//
// # Исключение — одно, и оно истекает само
//
// Базовый замер R7-1 снят до правок S2 в дереве ПЛАТФОРМЫ, на ревизии, которой в
// этом репозитории нет. Его координаты — координаты того дерева на момент
// замера, и переписать их значило бы подделать провенанс артефакта, а не
// исправить его. Запись исключения истекает, когда исключать нечего: файла нет
// либо приставки в нём больше нет — то и другое находка, а не тишина.
//
// Предикат снятия исключения — внешний факт: прибор R7-1 перестал сравниваться с
// базовым замером (константа его координаты снята из `relverdict`), и файл
// уходит вместе с ней.

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
	"github.com/PRO-Robotech/kaname/internal/treeposture"
)

// storageTree — обходимое дерево: всё хранилище, а не два каталога прибора.
// Предикат kaname#141 сформулирован над ним целиком.
const storageTree = "internal/repo/kaname/pg"

// prefixExemptions — файл → причина. Перечень закрытый; запись без предмета —
// находка (см. шапку).
var prefixExemptions = map[string]string{
	storageTree + "/scalegrid/REPORT-R7-1-S1-scale-grid-before-S2.txt": "базовый замер R7-1, снятый в дереве " +
		"платформы на ревизии, которой здесь нет: координаты — того дерева на момент замера",
}

// prefixCensus — объём осмотренного. «Ноль находок» отличим от «ноль прочитанного».
type prefixCensus struct {
	Files, Lines, Exempted int
	ByExt                  map[string]int
}

// platformPrefixFindings — строки, несущие приставку, по всем файлам под absRoot.
//
// Путь находки — от relRoot, тем же видом, каким записаны исключения.
func platformPrefixFindings(absRoot, relRoot string, exempt map[string]string) ([]string, prefixCensus, []string, error) {
	census := prefixCensus{ByExt: map[string]int{}}
	needle := []byte(treeposture.ModuleDirInPlatform())
	var findings []string
	exemptSeen := map[string]bool{}

	err := filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, rerr := filepath.Rel(absRoot, path)
		if rerr != nil {
			return rerr
		}
		rel = relRoot + "/" + filepath.ToSlash(rel)
		body, err := os.ReadFile(path) // #nosec G304 -- обход СОБСТВЕННОГО дерева хранилища, путь не из запроса
		if err != nil {
			return fmt.Errorf("чтение %s: %w", rel, err)
		}
		census.Files++
		census.ByExt[filepath.Ext(rel)]++
		sc := bufio.NewScanner(bytes.NewReader(body))
		sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		hits := 0
		for n := 1; sc.Scan(); n++ {
			census.Lines++
			if bytes.Contains(sc.Bytes(), needle) {
				hits++
				if _, ok := exempt[rel]; !ok {
					findings = append(findings, fmt.Sprintf("%s:%d", rel, n))
				}
			}
		}
		if serr := sc.Err(); serr != nil {
			return fmt.Errorf("разбор строк %s: %w", rel, serr)
		}
		if _, ok := exempt[rel]; ok {
			exemptSeen[rel] = hits > 0
			if hits > 0 {
				census.Exempted++
			}
		}
		return nil
	})
	if err != nil {
		return nil, census, nil, err
	}

	// Исключение без предмета — находка: файла нет либо приставки в нём нет.
	var expired []string
	for rel := range exempt {
		if !exemptSeen[rel] {
			expired = append(expired, rel)
		}
	}
	sort.Strings(expired)
	return findings, census, expired, nil
}

// TestStorageTreeNamesNoPlatformPrefixedCoordinate — гейт по дереву хранилища.
func TestStorageTreeNamesNoPlatformPrefixedCoordinate(t *testing.T) {
	t.Parallel()
	abs := platformtree.RequirePath(t, storageTree)

	findings, census, expired, err := platformPrefixFindings(abs, storageTree, prefixExemptions)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: обход %s: %v", storageTree, err)
	}
	t.Logf("перепись: файлов %d (по расширениям %v), строк %d, исключённых файлов с приставкой %d, находок %d",
		census.Files, census.ByExt, census.Lines, census.Exempted, len(findings))

	// Предпосылка: предмет на месте — и код, и отчёты.
	if census.ByExt[".go"] == 0 || census.ByExt[".txt"] == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: в %s прочитано .go %d, .txt %d — у гейта исчез "+
			"предмет, и его молчание не значило бы «приставки нет»",
			storageTree, census.ByExt[".go"], census.ByExt[".txt"])
	}
	for _, rel := range expired {
		t.Errorf("исключение %s истекло — исключать нечего (файла нет либо приставки в нём нет); "+
			"запись снимается вместе с предметом", rel)
	}
	if len(findings) > 0 {
		t.Fatalf("строк с приставкой монорепо платформы %q: %d; первые:\n  %s\n"+
			"Такой координаты в этом дереве нет: читатель получает адрес, который никуда не ведёт. "+
			"Форма — от корня ЭТОГО дерева (internal/…, docs/…, tools/…)",
			treeposture.ModuleDirInPlatform(), len(findings),
			strings.Join(findings[:min(len(findings), 10)], "\n  "))
	}
}

// TestPlatformPrefixCensusCanFailAndStaySilent — способность гейта упасть,
// смолчать и истечь, на синтетике: живую ведомость проба не трогает.
func TestPlatformPrefixCensusCanFailAndStaySilent(t *testing.T) {
	t.Parallel()
	prefix := treeposture.ModuleDirInPlatform()
	write := func(dir, name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("синтетика %s: %v", name, err)
		}
	}

	// Дефект и близнец различаются РОВНО ОДНИМ: приставкой перед координатой.
	dir := t.TempDir()
	write(dir, "stale.go", "package p\n\n// Приёмка `"+prefix+"/docs/x.md`.\n")
	write(dir, "moved.go", "package p\n\n// Приёмка `docs/x.md`.\n")
	findings, census, expired, err := platformPrefixFindings(dir, "синт", nil)
	if err != nil {
		t.Fatalf("обход синтетики: %v", err)
	}
	if census.Files != 2 {
		t.Fatalf("прочитано файлов %d, ожидалось 2", census.Files)
	}
	if len(findings) != 1 || findings[0] != "синт/stale.go:3" {
		t.Errorf("находки %v, ожидалась ровно одна с координатой синт/stale.go:3", findings)
	}
	if len(expired) != 0 {
		t.Errorf("без исключений истёкших быть не может: %v", expired)
	}

	// Исключение с предметом молчит; без предмета — находка.
	findings, _, expired, err = platformPrefixFindings(dir, "синт", map[string]string{
		"синт/stale.go": "проба", "синт/moved.go": "проба: приставки в файле нет",
	})
	if err != nil {
		t.Fatalf("обход синтетики: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("исключённый файл подан находкой: %v", findings)
	}
	if len(expired) != 1 || expired[0] != "синт/moved.go" {
		t.Errorf("исключение без предмета не названо истёкшим: %v", expired)
	}

	// Пустой обход — ноль прочитанного, и перепись это показывает.
	_, census, _, err = platformPrefixFindings(t.TempDir(), "пусто", nil)
	if err != nil {
		t.Fatalf("обход пустого: %v", err)
	}
	if census.Files != 0 || census.ByExt[".go"] != 0 {
		t.Errorf("пустой обход насчитал файлы: %+v", census)
	}
}
