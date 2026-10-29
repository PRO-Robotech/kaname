// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid_test

// coordinates_verbatim_test.go — КООРДИНАТА, КОТОРУЮ ПРИБОР ПЕЧАТАЕТ, ВЕРНА В
// ЭТОМ ДЕРЕВЕ ДОСЛОВНО (kaname#141).
//
// # Предмет
//
// Каталоги предмета замера и пути отчётов были записаны от корня монорепо
// платформы — с приставкой, которой в этом дереве нет. Разрешитель её снимал,
// поэтому файлы находились; но та же координата уходила наружу КАК ЕСТЬ:
//
//	в шапку отчёта      перечень «файлы под отпечатком» называл пути, которых нет;
//	в предикат          «все не-тестовые .go каталогов …» — каталогов, которых нет;
//	в сверку чистоты    перечень под отпечатком сравнивается с выводом
//	                    `git status --porcelain` ДОСЛОВНО, а git пишет пути от корня
//	                    ЭТОГО дерева. Ни одна пара не совпадала, и правка файла
//	                    предмета классифицировалась «вне предмета» — шапка
//	                    объявляла дерево «чистым по предмету замера», когда предмет
//	                    был грязным.
//
// Последнее — не косметика: это ложный вердикт о воспроизводимости отчёта.
//
// # Что держит проба
//
// Исход, а не объявление: каждая координата, которую прибор печатает, ищется на
// диске склейкой с корнем — так, как её прочтёт человек и как её сравнивает
// сверка чистоты. Разрешитель с его снятием приставки здесь НЕ зовётся: он и
// прятал расхождение.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestPrintedCoordinatesExistVerbatimInThisTree — пути отчётов и файлы под
// обоими отпечатками существуют от корня дерева дословно.
func TestPrintedCoordinatesExistVerbatimInThisTree(t *testing.T) {
	t.Parallel()
	root := platformtree.Require(t)

	read, err := scalegrid.ComputeFingerprint(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: отпечаток чтения не снят: %v", err)
	}
	write, err := scalegrid.ComputeWriteDeleteFingerprint(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: отпечаток записи не снят: %v", err)
	}

	printed := []string{scalegrid.ReportPath, scalegrid.StrengthReportPath, scalegrid.WriteDeleteReportPath}
	printed = append(printed, read.Files...)
	printed = append(printed, write.Files...)
	if len(read.Files) == 0 || len(write.Files) == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: под отпечатками файлов %d и %d — сверять нечего",
			len(read.Files), len(write.Files))
	}

	var missing []string
	for _, rel := range printed {
		if _, serr := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); serr != nil {
			missing = append(missing, rel)
		}
	}
	t.Logf("перепись: координат проверено %d (путей отчётов 3, файлов под отпечатком чтения %d, записи %d)",
		len(printed), len(read.Files), len(write.Files))
	if len(missing) > 0 {
		t.Fatalf("координат, которых в этом дереве НЕТ дословно: %d из %d; первые:\n  %s\n"+
			"Шапка отчёта печатает их читателю, а сверка чистоты сравнивает с выводом git — "+
			"ни то, ни другое разрешителя не зовёт", len(missing), len(printed),
			strings.Join(missing[:min(len(missing), 5)], "\n  "))
	}
}

// TestDirtyFileUnderTheFingerprintIsNamedSo — правка файла предмета, названная
// git'ом так, как git её называет, классифицируется «под отпечатком».
//
// Законный близнец — правка файла ВНЕ предмета: она обязана остаться «вне»,
// иначе проба краснела бы на любой правке.
func TestDirtyFileUnderTheFingerprintIsNamedSo(t *testing.T) {
	t.Parallel()
	prov := scalegrid.TakeProvenance("make scale-grid-full", nil)
	if len(prov.Fingerprint.Files) == 0 {
		t.Fatal("проверка НЕ ИСПОЛНЯЛАСЬ: отпечаток предмета не снят в дереве модуля")
	}

	// Вывод git — настоящей формы: путь от корня ЭТОГО дерева.
	const subjectFile = "internal/repo/kaname/pg/relverdict/query.go"
	const outsideFile = "README.md"
	prov.DirtyPathList = scalegrid.ParsePorcelainPaths([]byte(" M " + subjectFile + "\n M " + outsideFile + "\n"))
	prov.DirtyPaths, prov.TreeDirty = len(prov.DirtyPathList), true

	header, err := prov.Header("проба")
	if err != nil {
		t.Fatalf("шапка не собрана: %v", err)
	}
	if !strings.Contains(header, "ГРЯЗНОЕ ПО ПРЕДМЕТУ ЗАМЕРА") || !strings.Contains(header, "ПОД ОТПЕЧАТКОМ 1") {
		t.Fatalf("правка %s (файл предмета, путь — как его пишет git) не признана правкой "+
			"предмета; шапка:\n%s", subjectFile, header)
	}
	if !strings.Contains(header, "под отпечатком  "+subjectFile) {
		t.Errorf("шапка не называет грязный файл предмета поимённо:\n%s", header)
	}
	if strings.Contains(header, "под отпечатком  "+outsideFile) {
		t.Errorf("файл вне предмета %s записан «под отпечаток»:\n%s", outsideFile, header)
	}
}
