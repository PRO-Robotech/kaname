// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// checklimit_test.go — СКОЛЬКО читает обход дерева.
//
// Читатель, у которого предела нет, кладёт в память ровно столько, сколько ему
// подали. Обход дерева подаёт то, что в дереве лежит, а не то, что мы
// задумали, — и файл с именем манифеста бывает порождён сборкой, слит из
// журнала, склеен по ошибке. Проверка, легшая на таком файле, не даёт вердикта
// НИ ПО ОДНОМУ манифесту дерева, включая прочитанные до него.
//
// Свойство: чтение ограничено по размеру, а превышение есть НАХОДКА С
// ВЕЛИЧИНОЙ — не отказ проверки и не молчание. Величина в тексте обязательна:
// без неё читателю нечем решить, чинить ли файл или поднять предел.
//
// Граница проверяется С ОБЕИХ СТОРОН: ровно предел проходит, предел плюс байт —
// находка. Одностороннее утверждение зеленело бы на читателе, отвергающем всё.
package manifest

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// manifestOfSize — годный манифест, дополненный комментарием до РОВНО size байт.
//
// Дополняется именно годный, а не произвольный мусор: негодный дал бы находку и
// без всякого предела, и проба зеленела бы на отказе разбора, ничего не сказав о
// размере.
func manifestOfSize(t *testing.T, size int) string {
	t.Helper()
	good := goodManifest(t)
	pad := size - len(good)
	if pad < 2 {
		t.Fatalf("предел %d не больше фикстуры (%d байт) хотя бы на два байта — "+
			"вход не произвести", size, len(good))
	}
	body := good + "\n" + strings.Repeat("#", pad-1)
	if len(body) != size {
		t.Fatalf("вход НЕ ПРОИЗВЕДЁН: получено %d байт при заказанных %d", len(body), size)
	}
	return body
}

// TestCheckTreeRefusesAManifestOverTheLimitAndNamesTheValue — файл сверх предела
// есть находка, называющая место и обе величины; годный рядом читается.
func TestCheckTreeRefusesAManifestOverTheLimitAndNamesTheValue(t *testing.T) {
	oversized := manifestOfSize(t, manifestSizeLimit+1)

	root := writeTree(t, map[string]string{
		"services/vpc/manifest.yaml":  goodManifest(t),
		"services/huge/manifest.yaml": oversized,
	})

	report := CheckTree(root)

	if report.ExitCode() != CheckFailed {
		t.Fatalf("манифест сверх предела дал код %d, ожидался %d — предела нет: "+
			"перепись %s", report.ExitCode(), CheckFailed, report.Summary())
	}
	if report.ManifestsRead != 1 {
		t.Errorf("прочитано манифестов %d, положен 1 — превысивший предел не прочитан "+
			"и в число прочитанных не входит: %v", report.ManifestsRead, report.Paths)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("находок %d, ожидалась 1: %v", len(report.Findings), report.Findings)
	}
	fault := report.Findings[0]
	if !strings.Contains(fault, "services/huge/manifest.yaml") {
		t.Errorf("находка не называет места: %q", fault)
	}
	for _, want := range []string{strconv.Itoa(len(oversized)), strconv.Itoa(manifestSizeLimit)} {
		if !strings.Contains(fault, want) {
			t.Errorf("находка не называет величины %s — читателю нечем решить, "+
				"чинить файл или поднимать предел: %q", want, fault)
		}
	}
	t.Logf("находка: %s", fault)
}

// TestCheckTreeReadsAManifestExactlyAtTheLimit — законный близнец: ровно предел
// проходит МОЛЧА.
//
// Граница принадлежит годной стороне намеренно: предел есть верхняя допустимая
// величина, а не первая запрещённая, и «не больше предела» читается однозначно.
func TestCheckTreeReadsAManifestExactlyAtTheLimit(t *testing.T) {
	root := writeTree(t, map[string]string{
		"services/vpc/manifest.yaml": manifestOfSize(t, manifestSizeLimit),
	})

	report := CheckTree(root)

	if report.ExitCode() != CheckOK {
		t.Fatalf("манифест РОВНО в предел дал код %d, ожидался %d: %v",
			report.ExitCode(), CheckOK, report.Findings)
	}
	if report.ManifestsRead != 1 {
		t.Errorf("прочитано манифестов %d, положен 1: %v", report.ManifestsRead, report.Paths)
	}
	t.Logf("перепись: %s (предел %d байт)", report.Summary(), manifestSizeLimit)
}

// treeRootFromPackage — корень дерева относительно каталога пакета. Пробы Go
// исполняются из каталога своего пакета, поэтому путь относительный.
const treeRootFromPackage = "../../../.."

// manifestHeadroomDivisor — во сколько раз предел обязан превосходить САМЫЙ
// БОЛЬШОЙ манифест дерева.
//
// Величина выбрана так, чтобы предупреждение пришло ЗА ТРИ ЧЕТВЕРТИ до отказа:
// решение «двигать предел или чинить документ» принимается заранее, а не в
// минуту, когда проверка перестала читать манифест. Порог, срабатывающий в
// момент отказа, решения не готовит — он о нём сообщает.
const manifestHeadroomDivisor = 4

// TestManifestSizeLimitOutgrowsTheBiggestManifestOfThisTree — обоснование
// предела ВЫВОДИТСЯ из дерева, а не выписывается рядом с константой
// (задача PRO-Robotech/kacho#1908).
//
// # Почему проба, а не число в комментарии
//
// Комментарий у константы называл максимум «vpc, 42 626 байт» и запас «в 24
// раза». Число было снято с черновика в ДРУГОМ дереве и пережило свой предмет:
// самый большой манифест этого дерева — другой файл и другая величина. Само по
// себе это безобидно, а читает его тот, кто решает, двигать предел или чинить
// документ, — то есть неверно ровно то, ради чего комментарий и написан.
//
// Здесь величина берётся у дерева на каждом прогоне и ПЕЧАТАЕТСЯ: второго места
// об одном предмете не заводится, и устареть ему нечем.
//
// # Обход — ПРОД-ПУТЬ
//
// `CheckTree` — тот самый исполнитель, которым судит
// `make -C services/iam module-manifest-check`. Свой обходчик рядом разошёлся бы
// с ним молча на первом же новом месте манифеста.
//
// # Пустой обход — НАХОДКА
//
// Иначе «запас достаточен» стало бы неотличимо от «манифестов не нашлось»:
// у пустого множества максимума нет, и утверждение о нём тривиально истинно.
func TestManifestSizeLimitOutgrowsTheBiggestManifestOfThisTree(t *testing.T) {
	rep := CheckTree(treeRootFromPackage)
	if len(rep.Findings) > 0 {
		t.Fatalf("дерево не прочитано целиком, вердикта о размере нет ни по одному "+
			"манифесту: %v", rep.Findings)
	}
	if rep.ManifestsRead == 0 {
		t.Fatalf("манифестов не найдено ни одного — обход пуст (%s): у пустого множества "+
			"максимума нет, и утверждение о запасе было бы тривиально истинным", rep.Summary())
	}

	biggest, biggestPath := 0, ""
	for _, p := range rep.Paths {
		size, err := treeFileSize(t, p)
		if err != nil {
			t.Fatalf("размер %s не прочитан: %v", p, err)
		}
		if size > biggest {
			biggest, biggestPath = size, p
		}
	}

	bound := manifestSizeLimit / manifestHeadroomDivisor
	if biggest > bound {
		t.Errorf("самый большой манифест дерева — %s, %d байт; предел %d, и запас упал "+
			"ниже объявленного (%d-кратного): решение «двигать предел или чинить документ» "+
			"пора принять СЕЙЧАС, а не в минуту, когда чтение упрётся в предел",
			biggestPath, biggest, manifestSizeLimit, manifestHeadroomDivisor)
	}

	t.Logf("перепись: %s · самый большой %s = %d байт · предел %d · запас %.1f-кратный "+
		"(объявленный минимум — %d-кратный)",
		rep.Summary(), biggestPath, biggest, manifestSizeLimit,
		float64(manifestSizeLimit)/float64(biggest), manifestHeadroomDivisor)
}

// treeFileSize — размер файла, найденного обходом. Путь приходит от CheckTree
// относительно корня обхода, поэтому корень возвращается к нему здесь.
func treeFileSize(t *testing.T, rel string) (int, error) {
	t.Helper()
	fi, err := os.Stat(filepath.Join(treeRootFromPackage, rel))
	if err != nil {
		return 0, err
	}
	return int(fi.Size()), nil
}
