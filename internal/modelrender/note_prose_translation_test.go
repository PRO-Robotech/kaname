// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelrender_test

// note_prose_translation_test.go — переходный перевод ПРОЗЫ примечаний
// публичного чтения (kaname#855, пара — kacho#3272).
//
// # Предмет
//
// Канон модели переносит примечания манифестов платформы побайтово. После
// классов субъектов (kaname#829) публичное чтение описывается классом
// `system_class`, но проза примечаний registry и nlb ствола kacho называла его
// словом `user:*`. Проза меняется только парой «канон kaname + манифест kacho»,
// а сверка kaname судит ствол kacho, и kacho закрепляет kaname пином: переход
// одной стороны раньше другой красил бы сверку (так же, как слово записи
// субъекта — `subjectWords` в render.go).
//
// # Что судится
//
// Перевод ДВУСТОРОННИЙ: манифест прежней прозы и манифест новой прозы
// порождают один и тот же блок канона. Переводится строка, равная прежней
// ЦЕЛИКОМ; любая иная форма строки воспроизводится дословно, как и раньше.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelrender"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// renderForCanon — блок единственного ресурса документа в виде, в котором его
// судят против канона (обе стороны сверки зовут именно эту форму).
func renderForCanon(t *testing.T, doc string) string {
	t.Helper()
	m, err := manifest.Load([]byte(doc))
	if err != nil {
		t.Fatalf("загрузчик отверг вход:\n%v\nвход:\n%s", err, doc)
	}
	if len(m.Resources) != 1 {
		t.Fatalf("ресурсов в манифесте %d, ожидался один", len(m.Resources))
	}
	got, err := modelrender.RenderForCanon(m.Resources[0])
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	return string(got)
}

const registryProseHead = `apiVersion: iam/v1
module: registry
resources:
  - name: repositories
    objectType: registry_repository
    parents:
      - {name: parent, type: registry_registry}
    producer: authored
    notes:
      - before: v_get
        text: |
`

const registryProseTail = `    relations:
      - name: owner
        definition: '[user, service_account]'
        position: beforeTiers
    verbs:
      - {name: get, subjects: [system_class, user, service_account, 'group#member'], from: [owner, super_admin]}
      - {name: list, from: [owner, super_admin]}
      - {name: update, from: [owner, super_admin]}
      - {name: delete, from: [owner, super_admin]}
`

// registryPriorProse — проза ствола kacho до kacho#3272, построчно.
var registryPriorProse = []string{
	"# RG-1 D-7: `user:*` public-read wildcard — anonymous pull of a PUBLIC repo.",
	"# The wildcard grants v_get ONLY on repos that ALSO carry an explicit",
	"# `user:* v_get` tuple emitted by the registry overlay (visibility=PUBLIC);",
	"# absent that tuple `user:*` has no access → uniform 404. ONLY v_get gains",
	"# the wildcard — no write relation does (anon is a read-only floor, B14).",
	"# #64 Defect A: v_* derive from `owner` (repo creator/pusher owner-tuple) so",
	"# the repo owner fully manages their own repository; `user:*` wildcard stays",
	"# on v_get ONLY (anonymous public-read floor, B14).",
}

// registryNewProse — та же проза после перевода на класс субъекта.
var registryNewProse = []string{
	"# RG-1 D-7: `system_class:anonymous` public-read subject — anonymous pull of a PUBLIC repo.",
	"# The class grants v_get ONLY on repos that ALSO carry an explicit",
	"# `system_class:anonymous v_get` tuple emitted by the registry overlay (visibility=PUBLIC);",
	"# absent that tuple the class has no access → uniform 404. ONLY v_get gains",
	"# the class — no write relation does (anon is a read-only floor, B14).",
	"# #64 Defect A: v_* derive from `owner` (repo creator/pusher owner-tuple) so",
	"# the repo owner fully manages their own repository; the `system_class` subject stays",
	"# on v_get ONLY (anonymous public-read floor, B14).",
}

func registryManifestWithProse(lines []string) string {
	var b strings.Builder
	b.WriteString(registryProseHead)
	for _, l := range lines {
		b.WriteString("          " + l + "\n")
	}
	b.WriteString(registryProseTail)
	return b.String()
}

func indented(lines []string) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString("    " + l + "\n")
	}
	return b.String()
}

// TestNoteProseOfPublicReadIsTranslatedBothWays — манифест прежней прозы и
// манифест новой прозы порождают ОДИН блок, равный новой прозе канона.
func TestNoteProseOfPublicReadIsTranslatedBothWays(t *testing.T) {
	fromPrior := renderForCanon(t, registryManifestWithProse(registryPriorProse))
	fromNew := renderForCanon(t, registryManifestWithProse(registryNewProse))

	if fromPrior != fromNew {
		t.Fatalf("манифест прежней прозы порождает иной блок, чем манифест новой:\nпрежний:\n%s\nновый:\n%s", fromPrior, fromNew)
	}
	mustContainLine(t, fromPrior, indented(registryNewProse))
	if strings.Contains(fromPrior, "user:*") {
		t.Errorf("в порождённом блоке осталось слово `user:*`:\n%s", fromPrior)
	}
}

// TestNoteProseTranslationTouchesOnlyAWholeLine — близнец: строка, отличная от
// прежней хоть на слово, воспроизводится дословно и перевода не получает.
func TestNoteProseTranslationTouchesOnlyAWholeLine(t *testing.T) {
	other := append([]string{}, registryPriorProse...)
	other[0] = "# RG-1 D-7: `user:*` public-read wildcard — a line nobody translated."
	other[3] = "# absent that tuple `user:*` has no access → uniform 404."

	got := renderForCanon(t, registryManifestWithProse(other))

	mustContainLine(t, got, "    "+other[0]+"\n")
	mustContainLine(t, got, "    "+other[3]+"\n")
	// Соседние строки, равные прежним целиком, переведены.
	mustContainLine(t, got, "    "+registryNewProse[1]+"\n")
	mustContainLine(t, got, "    "+registryNewProse[6]+"\n")
}

// TestNoteProseOfBearerRelationIsTranslated — nlb: перечень субъектов
// отношения называет класс, а не слово.
func TestNoteProseOfBearerRelationIsTranslated(t *testing.T) {
	doc := func(line string) string {
		return `apiVersion: iam/v1
module: loadbalancer
resources:
  - name: networkLoadBalancers
    objectType: nlb_network_load_balancer
    parents: [project]
    producer: derived
    notes:
      - before: announce_writer
        text: |
          ` + line + `
    relations:
      - name: announce_writer
        definition: '[service_account]'
        position: afterVerbs
    verbs:
      - get
`
	}
	prior := "#   * `[service_account]` ONLY — no `user`, no `group#member`, no `user:*`."
	now := "#   * `[service_account]` ONLY — no `user`, no `group#member`, no `system_class`."

	fromPrior := renderForCanon(t, doc(prior))
	fromNew := renderForCanon(t, doc(now))
	if fromPrior != fromNew {
		t.Fatalf("прежняя и новая проза порождают разные блоки:\n%s\n---\n%s", fromPrior, fromNew)
	}
	mustContainLine(t, fromPrior, "    "+now+"\n")
}

// TestPriorEditionStaysRecognisedAfterTheProseTranslation — Р10: манифест
// прежней редакции registry (с прежней прозой либо с новой) по-прежнему узнаётся
// как прежняя редакция, а блок с чужой прозой — нет. Закреплённые Р10 байты не
// пересчитаны: узнавание ведёт [modelrender.IsPriorEdition].
func TestPriorEditionStaysRecognisedAfterTheProseTranslation(t *testing.T) {
	doc, err := publicreadfixture.Read(publicreadfixture.PriorEditionFile)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	m, err := manifest.Load(doc)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	seen := 0
	for _, r := range m.Resources {
		raw, err := modelrender.Render(r)
		if err != nil {
			t.Fatalf("рендер %s: %v", r.ObjectType, err)
		}
		translated := modelrender.TranslateNoteProse(raw)
		if r.ObjectType == "registry_repository" && string(raw) == string(translated) {
			t.Fatalf("фикстура не несёт прежней прозы: перевод её не тронул, пробе нечего судить")
		}
		if !modelrender.IsPriorEdition(r.ObjectType, raw) {
			t.Errorf("%s: прежняя редакция с прежней прозой не узнана", r.ObjectType)
		}
		if !modelrender.IsPriorEdition(r.ObjectType, translated) {
			t.Errorf("%s: прежняя редакция с переведённой прозой не узнана", r.ObjectType)
		}
		changed := []byte(strings.Replace(string(translated), "define", "defin", 1))
		if modelrender.IsPriorEdition(r.ObjectType, changed) {
			t.Errorf("%s: блок, отличный от прежней редакции, узнан", r.ObjectType)
		}
		seen++
	}
	if seen == 0 {
		t.Fatal("в фикстуре прежней редакции нет ни одного ресурса")
	}
}

// TestCanonCarriesNoPublicReadWildcardWord — канон не называет публичное чтение
// словом `user:*`: ни записью, ни прозой.
//
// Предпосылка обхода: файл канона прочитан, не пуст и несёт блок, чья проза
// переведена, — иначе «ноль вхождений» было бы нолём прочитанного.
func TestCanonCarriesNoPublicReadWildcardWord(t *testing.T) {
	root := platformtree.Require(t)
	path := filepath.Join(root, "proto", "kaname", "cloud", "iam", "v1", "fga_model.fga")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("чтение канона: %v", err)
	}
	lines := strings.Split(string(b), "\n")
	var hits []string
	sawRepository := false
	for _, l := range lines {
		if strings.HasPrefix(l, "type registry_repository") {
			sawRepository = true
		}
		if strings.Contains(l, "user:*") {
			hits = append(hits, strings.TrimSpace(l))
		}
	}
	t.Logf("строк канона прочитано %d · вхождений `user:*` %d", len(lines), len(hits))
	if len(lines) < 100 || !sawRepository {
		t.Fatalf("канон не прочитан целиком: строк %d, блок registry_repository найден %v", len(lines), sawRepository)
	}
	if len(hits) != 0 {
		t.Errorf("канон называет публичное чтение словом `user:*`:\n  %s", strings.Join(hits, "\n  "))
	}
}
