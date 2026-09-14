// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// request_field_has_a_reader_test.go — ГЕЙТ КЛАССА: у каждого поля сообщения
// запроса есть читатель в прод-коде своей службы (задача kacho#1351).
//
// Предмет, довод в пользу разбора узлов вместо поиска имени геттера и граница
// «запрос, ушедший в вызов целиком» — в шапке `request_field_has_a_reader.go`;
// здесь они не пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// request_field_has_a_reader_injection_test.go.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// contractDir — СВОЙ контракт службы. Копии чужих контрактов (`proto/corelib`,
// `proto/kacho`, `proto/google`) сюда не входят: их поля читает их владелец, и
// требовать читателя здесь значило бы судить чужое дерево.
const contractDir = "proto/kaname/cloud/iam/v1"

// generatedDir — сгенерированные стабы. Читателем НЕ считаются (геттер там есть
// у каждого поля by construction); нужны как ПРОВЕРКА ПРЕДПОСЫЛКИ: имя геттера
// гейт вычисляет, и вычисленное обязано совпасть с порождённым.
const generatedDir = "pkg/api/kaname/cloud/iam/v1"

// moduleRoot — корень СВОЕГО модуля.
//
// Взят вместо `platformtree.Require`: тот пропускает прогон, когда рядом нет
// дерева платформы, — а предмет этого гейта целиком свой (контракт службы и её
// прод-код), и в самостоятельном клоне он обязан исполняться, а не молчать.
// Пропуск здесь был бы третьей категорией, поданной как успех.
func moduleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	return root
}

func TestPublicRequestFieldHasAReaderInProductionCode(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)

	protoFiles, err := treecorpus.UnderWithSuffix(filepath.Join(root, contractDir), ".proto")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав контракта (%s): %v", contractDir, err)
	}
	var surfaces []check.ProtoSurface
	for _, abs := range protoFiles {
		body, rerr := os.ReadFile(abs) // #nosec G304 -- путь из индекса git своего дерева
		if rerr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s: %v", abs, rerr)
		}
		rel, _ := filepath.Rel(root, abs)
		s, perr := check.ProtoSurfaceIn(filepath.ToSlash(rel), string(body))
		if perr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", perr)
		}
		surfaces = append(surfaces, s)
	}
	if len(protoFiles) == 0 {
		t.Fatalf("обход не прочитал НИ ОДНОГО файла контракта (%s) — вердикт "+
			"беспредметен: «находок ноль» неотличимо от «прочитано ноль»", contractDir)
	}

	messages := map[string]bool{}
	for _, s := range surfaces {
		for _, u := range s.Requests {
			messages[u.Message] = true
		}
	}
	if len(messages) == 0 {
		t.Fatalf("предпосылка гейта не выполнена: в %s не найдено ни одного "+
			"сообщения запроса — форма объявления глаголов изменилась, "+
			"и гейт судит пустоту", contractDir)
	}

	goFiles, err := treecorpus.UnderWithSuffix(root, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева Go: %v", err)
	}
	var (
		reads   []check.RequestFieldRead
		whole   []string
		scanned int
	)
	for _, abs := range goFiles {
		rel, _ := filepath.Rel(root, abs)
		rel = filepath.ToSlash(rel)
		if strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(rel, generatedDir) {
			continue
		}
		body, rerr := os.ReadFile(abs) // #nosec G304 -- путь из индекса git своего дерева
		if rerr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s: %v", abs, rerr)
		}
		r, w, perr := check.RequestFieldReadsIn(rel, string(body), messages)
		if perr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", perr)
		}
		scanned++
		reads = append(reads, r...)
		whole = append(whole, w...)
	}
	if scanned == 0 {
		t.Fatalf("обход не разобрал НИ ОДНОГО прод-файла Go — вердикт беспредметен: " +
			"«находок ноль» неотличимо от «прочитано ноль»")
	}

	census := check.JudgeRequestFieldReaders(surfaces, reads, whole, len(protoFiles), scanned)
	t.Logf("перепись: %s", census.Summary())
	if census.Fields == 0 {
		t.Fatalf("предпосылка гейта не выполнена: у сообщений запроса не найдено " +
			"ни одного поля — разбор перестал их видеть, и гейт судит пустоту")
	}

	if len(census.Findings) > 0 {
		t.Fatalf("полей сообщений запроса без читателя в прод-коде: %d\n  %s",
			len(census.Findings), strings.Join(census.Findings, "\n  "))
	}
}

// TestComputedGetterNameAgreesWithTheGenerator — ПРЕДПОСЫЛКА гейта выше.
//
// Имя геттера гейт ВЫЧИСЛЯЕТ из имени поля контракта. Разойдись правило
// именования с генератором — гейт спрашивал бы имя, которого в дереве нет, и
// объявил бы находкой КАЖДОЕ поле; либо, что тише, спрашивал бы имя чужого поля
// и молчал бы на мёртвом. Поэтому вычисленное сверяется с ПОРОЖДЁННЫМ.
func TestComputedGetterNameAgreesWithTheGenerator(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)

	protoFiles, err := treecorpus.UnderWithSuffix(filepath.Join(root, contractDir), ".proto")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав контракта: %v", err)
	}
	var surfaces []check.ProtoSurface
	for _, abs := range protoFiles {
		body, rerr := os.ReadFile(abs) // #nosec G304 -- путь из индекса git своего дерева
		if rerr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s: %v", abs, rerr)
		}
		rel, _ := filepath.Rel(root, abs)
		s, perr := check.ProtoSurfaceIn(filepath.ToSlash(rel), string(body))
		if perr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", perr)
		}
		surfaces = append(surfaces, s)
	}

	genFiles, err := treecorpus.UnderWithSuffix(filepath.Join(root, generatedDir), ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав сгенерированного (%s): %v", generatedDir, err)
	}
	generated := map[string]bool{} // "<Сообщение>|<Геттер>"
	for _, abs := range genFiles {
		body, rerr := os.ReadFile(abs) // #nosec G304 -- путь из индекса git своего дерева
		if rerr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s: %v", abs, rerr)
		}
		for _, m := range check.GeneratedGettersIn(string(body)) {
			generated[m] = true
		}
	}
	if len(generated) == 0 {
		t.Fatalf("предпосылка не выполнена: в %s не найдено ни одного геттера — "+
			"сверять вычисленное не с чем", generatedDir)
	}

	requested := map[string]bool{}
	for _, s := range surfaces {
		for _, u := range s.Requests {
			requested[u.Message] = true
		}
	}

	var (
		checked int
		bad     []string
	)
	for _, s := range surfaces {
		for _, m := range s.Messages {
			if !requested[m.Name] {
				continue
			}
			for _, f := range m.Fields {
				checked++
				if !generated[m.Name+"|"+f.Getter] {
					bad = append(bad, m.Name+"."+f.Name+" → вычислено "+f.Getter+
						", порождённого такого нет")
				}
			}
		}
	}
	if checked == 0 {
		t.Fatalf("предпосылка не выполнена: сверено ноль полей — разбор контракта " +
			"перестал их видеть")
	}
	t.Logf("перепись: сверено полей %d, порождённых геттеров %d", checked, len(generated))
	if len(bad) > 0 {
		t.Fatalf("правило именования геттера разошлось с генератором: %d\n  %s",
			len(bad), strings.Join(bad, "\n  "))
	}
}
