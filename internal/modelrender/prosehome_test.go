// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package modelrender_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/authzplan"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/modelrender"
)

// prosehome_test.go — у прозы блока есть дом, и её место проверяется в обе
// стороны (приёмка `model-block-prose-has-a-home.md`, нормы Н-06 и Н-08,
// инъекции C-05 … C-08).

// blocksWithTrailingProse — блоки, чья проза стоит ПОСЛЕ последнего `define`.
//
// Такая проза якоря не имеет by construction: примечание ставится ПЕРЕД
// отношением, и отношения за ней уже нет. Возвращается перечень имён, а не
// булево: находка обязана называть блок, иначе читатель ищет его глазами.
func blocksWithTrailingProse(dsl []byte) []string {
	var out []string
	for _, b := range modelrender.SplitCanon(dsl) {
		trailing := false
		for _, line := range strings.Split(strings.TrimRight(string(b.Body), "\n"), "\n") {
			body := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(body, "#"):
				trailing = true
			case strings.HasPrefix(body, "define "):
				trailing = false
			}
		}
		if trailing {
			out = append(out, b.Type)
		}
	}
	return out
}

// TestN06ProseAtTheEndOfABlockHasNoHome — САМОИСТЕКАЮЩИЙ гейт.
//
// Формы под прозу в конце блока НЕТ, и это решение, а не пропуск: ни один блок
// канона её сегодня не несёт. Послабление истекает ОТ ПОЯВЛЕНИЯ ПРЕДМЕТА, а не
// от чьей-то памяти: первая такая строка роняет гейт с именем блока.
func TestN06ProseAtTheEndOfABlockHasNoHome(t *testing.T) {
	path, dsl, err := authzplan.ResolveCanonicalModel()
	if err != nil {
		t.Fatalf("канон не резолвится: %v", err)
	}
	blocks := modelrender.SplitCanon(dsl)
	if len(blocks) == 0 {
		t.Fatalf("блоков канона 0 — обход пуст, вердикт беспредметен (%s)", path)
	}
	found := blocksWithTrailingProse(dsl)
	for _, name := range found {
		t.Errorf("блок %s: прозе в конце блока дома нет; заведите форму, а не подвиньте строку", name)
	}
	t.Logf("перепись: блоков канона %d · с прозой в конце %d", len(blocks), len(found))
}

// TestC07InjectionTrailingProseIsSeenAndItsTwinIsNot — инъекция C-07 в ОБЕ
// стороны: та же строка после последнего `define` — находка, перед ним — тишина.
//
// Без близнеца гейт ловил бы форму, а не существо: проверка, краснеющая на всякой
// строке комментария, отключается первым же ложным срабатом.
func TestC07InjectionTrailingProseIsSeenAndItsTwinIsNot(t *testing.T) {
	const head = "model\n  schema 1.1\n\ntype vpc_gateway\n  relations\n" +
		"    define project: [project]\n"
	const tail = "    define super_admin: super_admin from project\n"

	injected := head + tail + "    # дописано после последнего define\n"
	if got := blocksWithTrailingProse([]byte(injected)); len(got) != 1 || got[0] != "vpc_gateway" {
		t.Fatalf("проза после последнего define не найдена: %v", got)
	}

	twin := head + "    # дописано ПЕРЕД define\n" + tail
	if got := blocksWithTrailingProse([]byte(twin)); len(got) != 0 {
		t.Fatalf("законный близнец объявлен находкой: %v", got)
	}
}

// TestC05InjectionReorderingTheNoteTextIsSeen — инъекция C-05: перестановка двух
// строк текста даёт побайтовое расхождение.
//
// Проза несёт самоистекающие маркеры и ссылки на задачи; порядок её строк есть
// часть текста, а не оформление.
func TestC05InjectionReorderingTheNoteTextIsSeen(t *testing.T) {
	straight := gatewayResource()
	straight.Notes = []manifest.Note{{Before: "project", Text: "# первая\n# вторая"}}
	reordered := gatewayResource()
	reordered.Notes = []manifest.Note{{Before: "project", Text: "# вторая\n# первая"}}

	a, err := modelrender.Render(straight)
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	b, err := modelrender.Render(reordered)
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	if string(a) == string(b) {
		t.Fatalf("перестановка строк текста рендер не изменила — порядок не воспроизводится:\n%s", a)
	}
	// Законный близнец: тот же текст в исходном порядке равен сам себе.
	again, err := modelrender.Render(straight)
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	if string(again) != string(a) {
		t.Fatalf("рендер недетерминирован на одном и том же входе")
	}
}

// TestC06InjectionMovingTheAnchorIsSeen — инъекция C-06: тот же текст на другом
// якоре даёт побайтовое расхождение.
//
// Якорь есть часть примечания, а не подсказка: переехавшая проза уносит с собой
// ссылку на задачу и причину снятия к чужой строке.
func TestC06InjectionMovingTheAnchorIsSeen(t *testing.T) {
	atGet := gatewayResource()
	atGet.Notes = []manifest.Note{{Before: "v_get", Text: "# разбор"}}
	atList := gatewayResource()
	atList.Notes = []manifest.Note{{Before: "v_list", Text: "# разбор"}}

	a, err := modelrender.Render(atGet)
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	b, err := modelrender.Render(atList)
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	if string(a) == string(b) {
		t.Fatalf("перестановка якоря рендер не изменила — якорь не читается:\n%s", a)
	}
	if !strings.Contains(string(a), "    # разбор\n    define v_get:") {
		t.Fatalf("примечание не стоит перед своим якорем:\n%s", a)
	}
	if !strings.Contains(string(b), "    # разбор\n    define v_list:") {
		t.Fatalf("примечание не переехало вместе с якорем:\n%s", b)
	}
}

// TestN01EveryModularBlockOfTheCanonRoundTrips — несущее утверждение линии: у
// КАЖДОГО модульного блока канона есть вход манифеста, дающий его байты.
//
// Отдельно от переписи: перепись печатает числа и НЕ РОНЯЕТ на именах, а здесь
// падение называет блок, чью форму дерево перестало выражать.
func TestN01EveryModularBlockOfTheCanonRoundTrips(t *testing.T) {
	_, dsl, err := authzplan.ResolveCanonicalModel()
	if err != nil {
		t.Fatalf("канон не резолвится: %v", err)
	}
	owned := map[string]bool{}
	for _, e := range authzmap.Catalog() {
		if typ, ok := authzmap.ObjectType(e.Module, e.Resource); ok {
			owned[typ] = true
		}
	}
	seen := 0
	for _, b := range modelrender.SplitCanon(dsl) {
		if !owned[b.Type] {
			continue
		}
		seen++
		if reproduces(b) != verdictReached {
			t.Errorf("блок %s не воспроизводится из манифеста побайтово", b.Type)
		}
	}
	if seen == 0 {
		t.Fatal("модульных блоков 0 — обход пуст, вердикт беспредметен")
	}
	t.Logf("перепись: модульных блоков осмотрено %d", seen)
}
