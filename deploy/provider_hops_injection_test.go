// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_hops_injection_test.go — доказательство того, что перепись полос
// поставщика СПОСОБНА упасть, и падает на своём предмете (#2479).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ЭТОТ ФАЙЛ
//
// Перепись полос — ЕДИНСТВЕННЫЙ держатель оси «адрес объявлен И его якорь
// объявлен вместе с ним»: без неё отказ старта боевой службы обнаруживается
// установкой в кластер. При этом её способность упасть не была доказана ничем —
// у 13 из 20 проб этого каталога файл инъекции есть, у неё не было, — то есть
// свойство держалось вниманием. Гейт, потерявший способность краснеть, на
// чистом дереве выглядит РОВНО ТАК ЖЕ, как исправный.
//
// ─────────────────────────────────────────────────────────────────────────────
// ИНЪЕКЦИЯ РОНЯЕТ ТОЛЬКО ПРОВЕРЯЕМОЕ
//
// Ни один профиль дерева не правится: суждение вынесено функцией
// (`auditProviderHopsStack`), поэтому синтетический стек подаётся ДОВОДОМ. Каждый
// мир отличается от своего законного близнеца ОДНИМ фактом — одним значением в
// карте, — поэтому соседние пробы каталога не задеваются вовсе.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОСИ
//
//  1. АДРЕС НЕ ОБЪЯВЛЕН — находка называет ОБА написания, которыми его задают.
//  2. HTTPS БЕЗ ЯКОРЯ — находка; с якорем — молчание. Это несущая ось: адрес
//     читается как защищённый, а каждый вызов по нему отказывает.
//  3. ОТКРЫТЫЙ ТЕКСТ ВНЕ ВЕДОМОСТИ — находка; полоса из ведомости у источника,
//     который её несёт, — молчание И отметка в переписи открытого текста.
//  4. ВЕДОМОСТЬ ПРИВЯЗАНА К ИСТОЧНИКУ — та же полоса открытым текстом у
//     источника, ведомости НЕ несущего, остаётся находкой.
//  5. НЕ-АБСОЛЮТНЫЙ АДРЕС и ЧУЖАЯ СХЕМА — находки со своим текстом.
//  6. ПРЕФИКС ИСТОЧНИКА — значения читаются под псевдонимом подчарта, а не из
//     корня документа.
//  7. ОТБОР БОЕВОГО СТЕКА — канонический ключ и прежний; стек, не объявивший
//     посадки, боевым не считается. Ось названа ЗАМЕРОМ: когда адрес посадки
//     свели к одному написанию, а отбор остался на прежнем, боевым не опознался
//     НИ ОДИН стек, перепись прочитала ноль и проверка отчиталась бы успехом при
//     любом содержимом профилей.
package deploy_test

import (
	"strings"
	"testing"
)

// injectedSource — источник профилей, каким его видит суждение. Дерева не
// касается: у него нет ни каталога, ни цепочек.
func injectedSource(label string, prefix []string, carriesRegister bool) profileSource {
	return profileSource{label: label, prefix: prefix, carriesPlaintextRegister: carriesRegister}
}

// hopStack — синтетический стек: по полосе адрес и (необязательно) якорь.
//
// Карта строится ПО ИМЕНАМ ПОЛОС из `providerHops`, а не выписывается: перечень
// полос растёт, и выписанный разошёлся бы с ним молча — ровно тот класс, ради
// которого перепись и заведена.
func hopStack(prefix []string, addrs, anchors map[string]string) map[string]any {
	tree := map[string]any{}
	set := func(path []string, value string) {
		cur := tree
		for _, seg := range path[:len(path)-1] {
			next, ok := cur[seg].(map[string]any)
			if !ok {
				next = map[string]any{}
				cur[seg] = next
			}
			cur = next
		}
		cur[path[len(path)-1]] = value
	}
	for _, h := range providerHops {
		if v, ok := addrs[h.name]; ok && v != "" {
			set(under(prefix, h.knob...), v)
		}
		if v, ok := anchors[h.name]; ok && v != "" {
			set(under(prefix, h.anchor...), v)
		}
	}
	return tree
}

// allHops — одно значение на каждую полосу.
func allHops(value string) map[string]string {
	out := map[string]string{}
	for _, h := range providerHops {
		out[h.name] = value
	}
	return out
}

// lawfulStack — стек, на котором суждение обязано молчать: все полосы по https
// со своим якорем.
func lawfulStack(prefix []string) map[string]any {
	return hopStack(prefix, allHops("https://provider.internal:4445"), allHops("/etc/kaname/tls/ca.crt"))
}

// requirePremise — предпосылка инъекции: полос в перечне не ноль. Без неё
// «находок нет» означало бы «судить было нечего».
func requirePremise(t *testing.T) {
	t.Helper()
	if len(providerHops) == 0 {
		t.Fatal("инъекция беспредметна: перечень полос поставщика пуст")
	}
}

// TestProviderHopsInjection_LawfulTwinStaysSilent — ЗАКОННЫЙ БЛИЗНЕЦ.
//
// Стоит первым намеренно: без него всякое красное ниже приходило бы от чего
// угодно — например от суждения, объявляющего находкой любой стек.
func TestProviderHopsInjection_LawfulTwinStaysSilent(t *testing.T) {
	requirePremise(t)
	findings, plaintext, hops := auditProviderHopsStack(
		injectedSource("chart", nil, false), "prod", lawfulStack(nil))
	if len(findings) != 0 {
		t.Fatalf("законный стек объявлен находками: %v", findings)
	}
	if len(plaintext) != 0 {
		t.Fatalf("на стеке без открытого текста отмечены полосы: %v", plaintext)
	}
	if hops != len(providerHops) {
		t.Fatalf("осмотрено полос %d, объявлено %d — перепись судит не весь перечень", hops, len(providerHops))
	}
}

// TestProviderHopsInjection_UndeclaredAddressIsCaught — адрес не объявлен;
// находка называет ОБА написания, которыми его задают.
func TestProviderHopsInjection_UndeclaredAddressIsCaught(t *testing.T) {
	requirePremise(t)
	missing := providerHops[0]
	addrs := allHops("https://provider.internal:4445")
	delete(addrs, missing.name)

	findings, _, _ := auditProviderHopsStack(injectedSource("chart", nil, false), "prod",
		hopStack(nil, addrs, allHops("/etc/kaname/tls/ca.crt")))
	if len(findings) != 1 {
		t.Fatalf("необъявленный адрес дал находок %d, ожидалась 1: %v", len(findings), findings)
	}
	for _, want := range []string{missing.name, strings.Join(missing.knob, "."), missing.env} {
		if !strings.Contains(findings[0], want) {
			t.Errorf("находка не называет %q — оператору не сказано, ЧТО задавать: %s", want, findings[0])
		}
	}
}

// TestProviderHopsInjection_EnvSpellingCountsAsDeclared — законный близнец
// предыдущей: тот же адрес, объявленный СЫРЫМ написанием окружения, находкой не
// является. Это объявленное свойство переписи («iam читает оба»), и без пробы
// оно неотличимо от недосмотра.
func TestProviderHopsInjection_EnvSpellingCountsAsDeclared(t *testing.T) {
	requirePremise(t)
	h := providerHops[0]
	tree := hopStack(nil, allHops("https://provider.internal:4445"), allHops("/etc/kaname/tls/ca.crt"))
	// снимаем ручку и объявляем ту же полосу через `env`
	delete(tree["platform"].(map[string]any)["iam"].(map[string]any), h.knob[len(h.knob)-1])
	tree["env"] = map[string]any{h.env: "https://provider.internal:4445"}

	findings, _, _ := auditProviderHopsStack(injectedSource("chart", nil, false), "prod", tree)
	if len(findings) != 0 {
		t.Fatalf("адрес, объявленный написанием окружения, объявлен необъявленным: %v", findings)
	}
}

// TestProviderHopsInjection_HTTPSWithoutAnchorIsCaught — https без якоря.
func TestProviderHopsInjection_HTTPSWithoutAnchorIsCaught(t *testing.T) {
	requirePremise(t)
	bare := providerHops[0]
	anchors := allHops("/etc/kaname/tls/ca.crt")
	delete(anchors, bare.name)

	findings, _, _ := auditProviderHopsStack(injectedSource("chart", nil, false), "prod",
		hopStack(nil, allHops("https://provider.internal:4445"), anchors))
	if len(findings) != 1 {
		t.Fatalf("https без якоря дал находок %d, ожидалась 1: %v", len(findings), findings)
	}
	for _, want := range []string{bare.name, strings.Join(bare.anchor, "."), bare.anchorEnv} {
		if !strings.Contains(findings[0], want) {
			t.Errorf("находка не называет %q: %s", want, findings[0])
		}
	}
}

// TestProviderHopsInjection_PlaintextOutsideTheRegisterIsCaught — открытый текст
// на полосе, которой ведомость не прощает.
func TestProviderHopsInjection_PlaintextOutsideTheRegisterIsCaught(t *testing.T) {
	requirePremise(t)
	var unlisted *hop
	for i := range providerHops {
		if _, listed := plaintextPendingProviderTLS[providerHops[i].name]; !listed {
			unlisted = &providerHops[i]
			break
		}
	}
	if unlisted == nil {
		t.Skip("предпосылки нет: ведомость прощает открытый текст на КАЖДОЙ полосе — " +
			"эта ось перестала быть выразимой, и её надо пересобрать вместе с ведомостью")
	}
	addrs := allHops("https://provider.internal:4445")
	addrs[unlisted.name] = "http://provider.internal:4444"

	findings, _, _ := auditProviderHopsStack(injectedSource("umbrella", nil, true), "prod",
		hopStack(nil, addrs, allHops("/etc/kaname/tls/ca.crt")))
	if len(findings) != 1 {
		t.Fatalf("открытый текст вне ведомости дал находок %d, ожидалась 1: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0], unlisted.name) {
		t.Errorf("находка не называет полосы: %s", findings[0])
	}
}

// TestProviderHopsInjection_RegisteredPlaintextIsSilentAndCounted — законный
// близнец: прощённая полоса молчит И попадает в перепись открытого текста.
//
// Вторая половина несущая: именно ею ведомость истекает сама. Отметки нет —
// запись, которой больше нечего прощать, не покраснела бы.
func TestProviderHopsInjection_RegisteredPlaintextIsSilentAndCounted(t *testing.T) {
	requirePremise(t)
	var listed string
	for name := range plaintextPendingProviderTLS {
		listed = name
		break
	}
	if listed == "" {
		t.Skip("ведомость пуста — прощать нечего, и это ЦЕЛЬ, а не поломка")
	}
	addrs := allHops("https://provider.internal:4445")
	addrs[listed] = "http://provider.internal:4444"

	findings, plaintext, _ := auditProviderHopsStack(injectedSource("umbrella", nil, true), "prod",
		hopStack(nil, addrs, allHops("/etc/kaname/tls/ca.crt")))
	if len(findings) != 0 {
		t.Fatalf("прощённая ведомостью полоса объявлена находкой: %v", findings)
	}
	if len(plaintext) != 1 || plaintext[0] != listed {
		t.Fatalf("полоса открытого текста не попала в перепись: %v", plaintext)
	}
}

// TestProviderHopsInjection_RegisterIsBoundToItsSource — та же прощённая полоса
// у источника, ведомости НЕ несущего, остаётся находкой.
//
// Ведомость описывает НАШ стенд; поставляемый чарт поставщика не несёт вовсе.
// Прощение, действующее у всякого источника, прощало бы то, о чём никто не
// решал.
func TestProviderHopsInjection_RegisterIsBoundToItsSource(t *testing.T) {
	requirePremise(t)
	var listed string
	for name := range plaintextPendingProviderTLS {
		listed = name
		break
	}
	if listed == "" {
		t.Skip("ведомость пуста — прощать нечего")
	}
	addrs := allHops("https://provider.internal:4445")
	addrs[listed] = "http://provider.internal:4444"

	findings, plaintext, _ := auditProviderHopsStack(injectedSource("chart", nil, false), "prod",
		hopStack(nil, addrs, allHops("/etc/kaname/tls/ca.crt")))
	if len(findings) != 1 {
		t.Fatalf("открытый текст у источника без ведомости дал находок %d, ожидалась 1: %v",
			len(findings), findings)
	}
	if len(plaintext) != 0 {
		t.Fatalf("источник без ведомости отметил полосы открытого текста: %v — запись истекала бы "+
			"по чужому стеку", plaintext)
	}
}

// TestProviderHopsInjection_MalformedAndForeignSchemesAreCaught — не-абсолютный
// адрес и чужая схема называются СВОИМИ текстами, а не общим «неверно».
func TestProviderHopsInjection_MalformedAndForeignSchemesAreCaught(t *testing.T) {
	requirePremise(t)
	for _, c := range []struct{ value, want string }{
		{"provider.internal:4445", "not an absolute http(s) URL"},
		{"ftp://provider.internal", `scheme "ftp"`},
	} {
		addrs := allHops("https://provider.internal:4445")
		addrs[providerHops[0].name] = c.value
		findings, _, _ := auditProviderHopsStack(injectedSource("chart", nil, false), "prod",
			hopStack(nil, addrs, allHops("/etc/kaname/tls/ca.crt")))
		if len(findings) != 1 {
			t.Fatalf("адрес %q дал находок %d, ожидалась 1: %v", c.value, len(findings), findings)
		}
		if !strings.Contains(findings[0], c.want) {
			t.Errorf("находка по %q не называет причины (%q): %s", c.value, c.want, findings[0])
		}
	}
}

// TestProviderHopsInjection_PrefixIsRead — источник с псевдонимом подчарта
// читается ПОД ним: тот же документ без префикса объявляется необъявленным.
func TestProviderHopsInjection_PrefixIsRead(t *testing.T) {
	requirePremise(t)
	prefix := []string{"kaname"}
	src := injectedSource("umbrella", prefix, true)

	if findings, _, _ := auditProviderHopsStack(src, "prod", lawfulStack(prefix)); len(findings) != 0 {
		t.Fatalf("стек под псевдонимом объявлен находками: %v", findings)
	}
	findings, _, _ := auditProviderHopsStack(src, "prod", lawfulStack(nil))
	if len(findings) != len(providerHops) {
		t.Fatalf("документ БЕЗ псевдонима прочитан источником С псевдонимом: находок %d, "+
			"ожидалось %d — суждение читало бы корень чужого документа", len(findings), len(providerHops))
	}
}

// TestProviderHopsInjection_ProductionClassSelection — отбор боевого стека.
//
// Замер, из которого ось: отбор по ключу, который ПЕРЕЕХАЛ, не краснеет — он
// тихо перестаёт находить предмет, и перепись читает ноль при любом содержимом
// профилей.
func TestProviderHopsInjection_ProductionClassSelection(t *testing.T) {
	for _, c := range []struct {
		name string
		tree map[string]any
		want bool
	}{
		{"канонический ключ", map[string]any{"authMode": "production"}, true},
		{"прежний ключ", map[string]any{"config": map[string]any{"authn": map[string]any{"mode": "production"}}}, true},
		{"канонический перебивает прежний", map[string]any{
			"authMode": "dev",
			"config":   map[string]any{"authn": map[string]any{"mode": "production"}},
		}, false},
		{"посадка не объявлена", map[string]any{}, false},
		{"дев-посадка", map[string]any{"authMode": "dev"}, false},
	} {
		if got := isProductionClass(c.tree, nil); got != c.want {
			t.Errorf("%s: боевым опознан %v, ожидалось %v", c.name, got, c.want)
		}
	}
	if !isProductionClass(map[string]any{"kaname": map[string]any{"authMode": "production"}}, []string{"kaname"}) {
		t.Error("посадка под псевдонимом подчарта не прочитана — все стеки зонтичного источника " +
			"ушли бы в пропуск, а перепись прочитала бы ноль")
	}
}
