// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package modelrender_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/authzplan"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/modelrender"
)

// render_test.go — порождение блока типа из ресурса манифеста (Н-01; сценарии
// B-01…B-05; инъекции C-01…C-06).

// canonBlock — тело блока канона по имени типа. Второй операнд берётся ИЗ ДЕРЕВА,
// а не из литерала рядом с пробой: литерал есть снимок, и снимок каноном не является.
func canonBlock(t *testing.T, typ string) string {
	t.Helper()
	_, dsl, err := authzplan.ResolveCanonicalModel()
	if err != nil {
		t.Fatalf("канон не резолвится: %v", err)
	}
	for _, b := range modelrender.SplitCanon(dsl) {
		if b.Type == typ {
			return string(b.Body)
		}
	}
	t.Fatalf("типа %s в каноне нет", typ)
	return ""
}

// gatewayResource — ресурс, порождающий блок vpc_gateway: четыре глагола,
// умолчательные субъекты и ярусы.
func gatewayResource() manifest.Resource {
	return manifest.Resource{
		Name: "gateway", ObjectType: "vpc_gateway", Parents: []manifest.Parent{{Name: "project", Type: "project"}}, Producer: "derived",
		Verbs: []manifest.Verb{{Name: "get"}, {Name: "list"}, {Name: "update"}, {Name: "delete"}},
	}
}

// TestB01RenderOfARealResourceIsByteEqualToTheCanonBlock — побайтовое равенство
// на блоке, который канон несёт СЕГОДНЯ.
//
// Это несущая проба Н-01: равенство «по смыслу» измеряло бы согласие двух
// разборщиков, а не согласие текстов.
func TestB01RenderOfARealResourceIsByteEqualToTheCanonBlock(t *testing.T) {
	got, err := modelrender.Render(gatewayResource())
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	want := canonBlock(t, "vpc_gateway")
	if string(got) != want {
		t.Fatalf("рендер не равен канону побайтово.\nпорождено:\n%s\nканон:\n%s", got, want)
	}
}

// TestB05TheTrailingNewlineIsAByteToo — хвостовой перевод строки есть байт, а не
// косметика.
func TestB05TheTrailingNewlineIsAByteToo(t *testing.T) {
	got, err := modelrender.Render(gatewayResource())
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	if !strings.HasSuffix(string(got), "\n") {
		t.Fatalf("рендер не оканчивается переводом строки")
	}
	if strings.HasSuffix(string(got), "\n\n") {
		t.Fatalf("рендер несёт разделитель блоков — он принадлежит файлу, а не блоку")
	}
}

// TestB02TheRetiredRelationDoesNotComeBack — снятое отношение не воскресает.
//
// Названо поимённо, потому что это ИЗМЕРЕННАЯ регрессия, а не гипотеза: черновик
// генератора эмитил `define use` у vpc_subnet, тогда как канон несёт его НОЛЬ раз
// (снято #1115). Черновик был зелен ровно потому, что сверялся со снимком.
func TestB02TheRetiredRelationDoesNotComeBack(t *testing.T) {
	got, err := modelrender.Render(manifest.Resource{
		Name: "subnet", ObjectType: "vpc_subnet", Parents: []manifest.Parent{{Name: "project", Type: "project"}}, Producer: "derived",
		Verbs: []manifest.Verb{{Name: "get"}, {Name: "list"}, {Name: "update"}, {Name: "delete"}},
	})
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	if strings.Contains(string(got), "define use:") {
		t.Fatalf("порождено снятое отношение `use`:\n%s", got)
	}
	if _, _, err := authzplan.ResolveCanonicalModel(); err != nil {
		t.Fatalf("канон не резолвится: %v", err)
	}
}

// TestB03TheNoteIsReproducedVerbatim — авторское примечание стоит внутри блока
// дословно, с тем же отступом и тем же порядком строк.
//
// Внутриблочный комментарий канона несёт самоистекающие маркеры и ссылки на
// задачи. Потерять его перегенерацией значило бы снять условие, о котором никто
// не решал. Знак комментария ставит РЕНДЕР: автор пишет прозу, у которой
// грамматики нет.
func TestB03TheNoteIsReproducedVerbatim(t *testing.T) {
	r := gatewayResource()
	r.Notes = []manifest.Note{{
		Before: "project",
		Text:   "# первая строка разбора\n#\n# третья строка, со ссылкой #1089",
	}}
	got, err := modelrender.Render(r)
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	for _, want := range []string{
		"    # первая строка разбора\n",
		"    #\n",
		"    # третья строка, со ссылкой #1089\n",
	} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("строка %q не воспроизведена дословно:\n%s", want, got)
		}
	}
	if strings.Index(string(got), "# первая") > strings.Index(string(got), "# третья") {
		t.Fatalf("порядок строк комментария изменён:\n%s", got)
	}
}

// TestC04RemovingTheNoteIsSeenByTheComparison — инъекция C-04 приёмки о доме
// прозы: снятое примечание даёт побайтовое расхождение.
//
// Заменяет собой инъекцию C-01 задачи #1089, снимавшую ключ `doc`. Ключа больше
// нет, и старая инъекция ПОТЕРЯЛА БЫ СВОЙ ПРЕДМЕТ: вход, на котором она находит
// нарушение, перестал быть представимым, а проверка при этом молчала бы и
// выглядела исправной (`testing.md` §«Гейт на класс», п. 9). Поэтому она не
// оставлена «на всякий случай», а переведена на примечание — тем же изменением,
// каким снят ключ.
func TestC04RemovingTheNoteIsSeenByTheComparison(t *testing.T) {
	withDoc := gatewayResource()
	withDoc.Notes = []manifest.Note{{Before: "project", Text: "# разбор, который сняли"}}
	full, err := modelrender.Render(withDoc)
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	stripped, err := modelrender.Render(gatewayResource())
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	if string(full) == string(stripped) {
		t.Fatalf("снятие примечания рендер не изменило — комментарий не порождается вовсе")
	}
}

// TestC04ReorderingTheManifestDoesNotChangeTheRender — законный близнец: порядок
// ГЛАГОЛОВ в манифесте рендер не меняет, потому что порядок задаёт канон.
//
// Обязателен вместе с C-03: без него гейт краснел бы на любой перестановке, а без
// C-03 — молчал бы на возвращённом праве.
func TestC04ReorderingTheManifestDoesNotChangeTheRender(t *testing.T) {
	straight := gatewayResource()
	shuffled := gatewayResource()
	shuffled.Verbs = []manifest.Verb{{Name: "delete"}, {Name: "get"}, {Name: "update"}, {Name: "list"}}

	a, err := modelrender.Render(straight)
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	b, err := modelrender.Render(shuffled)
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("перестановка глаголов изменила рендер:\n%s\n---\n%s", a, b)
	}
}

// TestC03ReturningARetiredTierIsRenderedAndThusDiverges — инъекция C-03:
// возвращённый ярус попадает в рендер, то есть сверка его УВИДИТ.
func TestC03ReturningARetiredTierIsRenderedAndThusDiverges(t *testing.T) {
	r := gatewayResource()
	r.Relations = []manifest.Relation{{Name: "use", Definition: "[user, service_account] or editor"}}
	got, err := modelrender.Render(r)
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	if !strings.Contains(string(got), "    define use: [user, service_account] or editor\n") {
		t.Fatalf("возвращённое отношение не попало в рендер — сверка его не увидит:\n%s", got)
	}
	if string(got) == canonBlock(t, "vpc_gateway") {
		t.Fatalf("рендер с лишним отношением равен канону — сверка слепа")
	}
}

// TestTiersNarrowTiersAndNeverTheVerbs — сужение субъектов трогает ЯРУСЫ и не
// трогает глаголы.
//
// Замер: у vpc_address_pool ярусы несут [user, service_account], а его же v_get —
// полный набор с group#member. Сузив заодно глаголы, рендер отнял бы живое право
// у групп молча.
func TestTiersNarrowTiersAndNeverTheVerbs(t *testing.T) {
	got, err := modelrender.Render(manifest.Resource{
		Name: "addressPool", ObjectType: "vpc_address_pool", Parents: []manifest.Parent{{Name: "cluster", Type: "cluster"}}, Producer: "authored",
		Subjects: []string{"user", "service_account"},
		Tiers:    []manifest.ResourceTier{{Name: "admin"}, {Name: "viewer"}},
		Verbs:    []manifest.Verb{{Name: "get"}, {Name: "list"}, {Name: "update"}, {Name: "delete"}},
	})
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	s := string(got)
	if !strings.Contains(s, "    define admin: [user, service_account] or super_admin\n") {
		t.Fatalf("ярус admin не сужен субъектами:\n%s", s)
	}
	if !strings.Contains(s, "    define viewer: [user, service_account] or admin\n") {
		t.Fatalf("ярус viewer выведен не от предыдущего яруса:\n%s", s)
	}
	if strings.Contains(s, "define editor:") {
		t.Fatalf("порождён ярус, которого ресурс не объявлял:\n%s", s)
	}
	if !strings.Contains(s, "    define v_get: [user, service_account, group#member] or super_admin\n") {
		t.Fatalf("сужение ярусов отняло право у групп на глаголе:\n%s", s)
	}
}

// TestRenderRefusesAResourceWithoutAnObjectType — рендерить нечего: отказ, а не
// блок с пустым именем типа.
func TestRenderRefusesAResourceWithoutAnObjectType(t *testing.T) {
	if _, err := modelrender.Render(manifest.Resource{Name: "x", Parents: []manifest.Parent{{Name: "project", Type: "project"}}}); err == nil {
		t.Fatalf("ресурс без типа объекта отрендерен")
	}
	if _, err := modelrender.Render(manifest.Resource{Name: "x", ObjectType: "vpc_network"}); err == nil {
		t.Fatalf("ресурс без якоря отрендерен")
	}
}

// TestCanonicalVerbOrderAgreesWithTheClassRule — набор глаголов, чей ПОРЯДОК
// объявляет рендер, совпадает с набором, чей КЛАСС объявляет загрузчик.
//
// Объявления два намеренно: загрузчик объявляет ЧЛЕНСТВО (из каких имён выводится
// класс), рендер — ПОРЯДОК (в каком порядке канон ставит отношения). Это разные
// предметы, и связывать их одним литералом значило бы, что перестановка ради
// текста отказа молча меняет порядок строк модели.
//
// Но и разойтись молча они не вправе: шестой канонический глагол, добавленный
// загрузчику и неизвестный рендеру, уехал бы у рендера в хвост «прочих» — то есть
// блок разошёлся бы с каноном на ресурсе, который этот глагол несёт. Поэтому
// согласие УТВЕРЖДАЕТСЯ, а не предполагается.
func TestCanonicalVerbOrderAgreesWithTheClassRule(t *testing.T) {
	fromLoader := manifest.CanonicalVerbs()
	if len(fromLoader) == 0 {
		t.Fatalf("загрузчик объявляет 0 канонических глаголов — сверять нечего")
	}
	for _, verb := range fromLoader {
		if _, ok := modelrender.CanonicalVerbOrder()[verb]; !ok {
			t.Errorf("глагол %q известен загрузчику и неизвестен рендеру: он уехал бы "+
				"в хвост «прочих», и блок разошёлся бы с каноном", verb)
		}
	}
	for verb := range modelrender.CanonicalVerbOrder() {
		if _, ok := manifest.ClassOfCanonicalVerb(verb); !ok {
			t.Errorf("глагол %q известен рендеру и неизвестен загрузчику: рендер ставил бы "+
				"в каноническую позицию имя, которого манифест не примет", verb)
		}
	}
	t.Logf("перепись: канонических глаголов у загрузчика %d · у рендера %d",
		len(fromLoader), len(modelrender.CanonicalVerbOrder()))
}
