// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelrender_test

// unparsedcause_test.go — находка о негодном манифесте несёт САМУ ошибку, а не
// подставленную причину (задача #1905).
//
// # Предмет
//
// Обход сваливал три РАЗНЫЕ причины в одну корзину и ВЫБРАСЫВАЛ ошибку каждой:
// путь не приведён к корню · файл не прочитан · документ не разобран. Печаталось
// по ним одно сообщение, и оно утверждало ОДНУ КОНКРЕТНУЮ причину — «модуля не
// объявил», — которая в общем случае неверна.
//
// Цена не в опрятности: читатель идёт искать отсутствующий ключ `module:`,
// который стоит на месте, и не получает ни строки, ни поля, ни слова о настоящем
// отказе. Класс «находка называет симптом вместо причины»: на неё тратят прогон,
// а потом снимают гейт как непонятный.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/modelrender"
)

// unparsedFindings — находки обхода на дереве, где у одного модуля лежит
// негодный манифест, а остальные прощены ведомостью.
func unparsedFindings(t *testing.T, write func(t *testing.T, root, module string)) []modelrender.Finding {
	t.Helper()
	root := helperTree(t, twoBlockCanon)
	module := "vpc"
	write(t, root, module)
	_, findings, code := modelrender.Sweep(seed.LiteralRows().Resources, root, allWaivers(module))
	if code != modelrender.SweepFinding {
		t.Fatalf("исход %d, ожидалась находка (%d): негодный манифест обязан быть находкой",
			code, modelrender.SweepFinding)
	}
	if len(authzmap.CatalogSeedModules()) == 0 {
		t.Fatal("обход пуст: закрытый набор модулей пуст — сверять нечего")
	}
	return findings
}

// detailOfUnparsed — текст находки о негодном документе. Отбор по признаку
// «называет путь манифеста», а не по позиции: перечень находок несёт и соседние.
func detailOfUnparsed(t *testing.T, findings []modelrender.Finding) string {
	t.Helper()
	for _, f := range findings {
		if strings.Contains(f.Detail, "manifest.yaml") && strings.Contains(f.Detail, "манифест") {
			return f.Detail
		}
	}
	t.Fatalf("находки о негодном манифесте нет вовсе: %v", findings)
	return ""
}

// TestUnparsedManifestFindingCarriesTheParseError — причина «документ не
// разобран» несёт САМУ ошибку разбора.
func TestUnparsedManifestFindingCarriesTheParseError(t *testing.T) {
	detail := detailOfUnparsed(t, unparsedFindings(t, func(t *testing.T, root, module string) {
		t.Helper()
		// Модуль объявлен строкой, а класс действия из имени не выводится:
		// документ разбирается загрузчиком и ОТВЕРГАЕТСЯ им — ровно вход,
		// на котором прежнее сообщение лгало.
		writeManifest(t, root, module, "apiVersion: iam/v1\nmodule: vpc\nresources:\n"+
			"  - name: network\n    objectType: vpc_network\n    parents: [project]\n"+
			"    producer: derived\n    verbs:\n      - addCidrBlocks\n")
	}))

	if strings.Contains(detail, "модуля не объявил") {
		t.Errorf("находка утверждает «модуля не объявил», а `module: vpc` стоит строкой и "+
			"загрузчик его читает — подставленная причина вместо настоящей:\n  %s", detail)
	}
	for _, want := range []string{"addCidrBlocks", "verbs"} {
		if !strings.Contains(detail, want) {
			t.Errorf("находка не несёт %q — сама ошибка разбора выброшена, и читателю нечем "+
				"установить отказ:\n  %s", want, detail)
		}
	}
}

// TestUnreadableManifestFindingSaysItWasNotRead — причина «файл не прочитан»
// ОТЛИЧИМА в тексте от «не разобран».
//
// Вход — висячая символическая ссылка: документ по имени манифеста есть, а
// прочитать его нельзя.
func TestUnreadableManifestFindingSaysItWasNotRead(t *testing.T) {
	detail := detailOfUnparsed(t, unparsedFindings(t, func(t *testing.T, root, module string) {
		t.Helper()
		dir := filepath.Join(root, "modules", module)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("каталог модуля: %v", err)
		}
		if err := os.Symlink(filepath.Join(dir, "нет-такого.yaml"), filepath.Join(dir, "manifest.yaml")); err != nil {
			t.Skipf("символические ссылки недоступны: %v", err)
		}
	}))

	if strings.Contains(detail, "не разобран") {
		t.Errorf("непрочитанный документ назван неразобранным — две причины неотличимы, "+
			"и читатель ищет ошибку в тексте документа, которого не существует:\n  %s", detail)
	}
	if !strings.Contains(detail, "не прочитан") {
		t.Errorf("находка не называет причину «не прочитан»:\n  %s", detail)
	}
}

// TestGoodManifestStaysSilent — законный близнец: годный манифест находки о
// негодности НЕ даёт.
//
// Без него всякое красное выше могло бы приходить от самого обхода.
func TestGoodManifestStaysSilent(t *testing.T) {
	root := helperTree(t, twoBlockCanon)
	writeManifest(t, root, "vpc", manifestFor("vpc", "vpc_network", "vpc_subnet"))

	_, findings, _ := modelrender.Sweep(seed.LiteralRows().Resources, root, allWaivers("vpc"))
	for _, f := range findings {
		if strings.Contains(f.Detail, "не разобран") || strings.Contains(f.Detail, "не прочитан") {
			t.Errorf("годный манифест объявлен негодным — первое же ложное срабатывание "+
				"снимает гейт:\n  %s", f.Detail)
		}
	}
}
