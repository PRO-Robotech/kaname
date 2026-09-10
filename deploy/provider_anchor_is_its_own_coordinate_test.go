// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_anchor_is_its_own_coordinate_test.go — ЯКОРЬ ПОСТАВЩИКА ЛИЧНОСТИ И
// КРУГ КЛИЕНТСКИХ ЛИСТОВ СЛУЖБЫ — РАЗНЫЕ ВЕЛИЧИНЫ, И РАЗНЫМИ ИХ ДЕЛАЕТ ПРОФИЛЬ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (#2487)
//
// Это два разных вопроса, и путать их дорого:
//
//	«чьим сертификатам сервера я верю У СОСЕДА»  — якорь поставщика личности;
//	«кто вправе прийти КО МНЕ клиентом»          — круг клиентских листов.
//
// Боевой профиль называл обоим ОДНУ координату — `ca.crt` серверного секрета, —
// и комментарий самого секрета описывал её как якорь ВНУТРЕННЕГО центра
// установки. Совпадение двух центров есть свойство НАШЕЙ установки, а не
// свойство мира: оператор, чей поставщик выпущен публичным центром или другим
// внутренним, развести их не мог, не расширив (или не сузив) заодно круг тех,
// кому позволено прийти клиентом.
//
// Механизм развести существовал и до этого гейта — секрет заводит оператор, и
// монтируются все его ключи, — но на него ничто не указывало, а существующая
// проба проверяла только ДОСЯГАЕМОСТЬ файла, не его смысл. Досягаемость обе
// величины проходят и склеенными: файл-то один и он на месте.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ГЕЙТ СУДИТ И ЧЕГО НЕ СУДИТ
//
// Судит РАЗЛИЧИЕ КООРДИНАТ, а не различие содержимого. Оператор вправе положить
// в оба объекта один и тот же материал — если его поставщик выпущен тем же
// центром, это верный выбор. Гейт требует лишь, чтобы выбор БЫЛ ВЫРАЗИМ: две
// величины — две координаты.
//
// НЕ судит, объявлен ли якорь вообще и по какой схеме адресован хоп: это
// предмет соседней переписи (`provider_hops_test.go`), и второе место о нём
// разошлось бы с первым молча. Перечень хопов берётся ОТТУДА же, а не
// выписывается здесь.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПОПУЛЯЦИЯ ВЫВОДИТСЯ
//
// Круги клиентских листов находятся по ФОРМЕ ИМЕНИ переменной, которой их
// объявляет профиль (`KANAME_<ребро>_MTLS_CLIENTCAFILES`), а не перечисляются:
// выписанный перечень слушателей разошёлся бы с профилем на первом же новом
// ребре — и разошёлся бы молча, потому что новое ребро в перечень не попало бы.
//
// ЗАКОННЫЙ БЛИЗНЕЦ НАЗВАН: круги МЕЖДУ СОБОЙ координату делить ВПРАВЕ — у
// установки один внутренний центр, и требовать от каждого слушателя своего
// объекта значило бы решать за оператора то, чего он не решал. Находка — только
// пересечение якоря поставщика с любым из кругов.
package deploy_test

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// clientCircleEnvSuffix — форма имени переменной, которой профиль объявляет круг
// клиентских листов слушателя.
const clientCircleEnvSuffix = "_MTLS_CLIENTCAFILES"

// splitAnchorList — координаты из значения ручки. Обе стороны принимают
// перечень через запятую, поэтому и сравнивать надо ПОЭЛЕМЕНТНО: склейка,
// спрятанная в перечне из двух путей, иначе прошла бы незамеченной.
func splitAnchorList(v string) []string {
	out := []string{}
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// clientCircles читает круги клиентских листов, объявленные картой `env`
// профиля: имя ребра → координаты его круга.
func clientCircles(tree map[string]any, prefix []string) map[string][]string {
	out := map[string][]string{}
	var cur any = tree
	for _, key := range append(append([]string{}, prefix...), "env") {
		m, ok := cur.(map[string]any)
		if !ok {
			return out
		}
		if cur, ok = m[key]; !ok {
			return out
		}
	}
	envs, ok := cur.(map[string]any)
	if !ok {
		return out
	}
	for k, v := range envs {
		if !strings.HasSuffix(k, clientCircleEnvSuffix) {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		if paths := splitAnchorList(s); len(paths) > 0 {
			out[strings.TrimSuffix(strings.TrimPrefix(k, "KANAME_"), clientCircleEnvSuffix)] = paths
		}
	}
	return out
}

// TestProviderAnchorIsNotTheClientCircleCoordinate — несущая проба.
func TestProviderAnchorIsNotTheClientCircleCoordinate(t *testing.T) {
	findings, census := auditProviderAnchorCoordinates(t, chartChains)
	t.Logf("перепись: %s", census)
	require.Empty(t, findings,
		"якорь поставщика и круг клиентских листов делят координату:\n%s",
		strings.Join(findings, "\n"))
}

// judgeProviderAnchorCoordinates — ЧИСТОЕ ТЕЛО ВЕРДИКТА над одним разобранным
// стеком. Вынесено отдельно РАДИ ИНЪЕКЦИИ: доказать способность гейта упасть
// можно только подачей ему стека, в котором координата склеена, — а такого
// стека в дереве нет и быть не должно.
//
// Возвращает находки и число осмотренных кругов: «ноль находок» обязано быть
// отличимо от «ноль прочитанного» и на этом уровне тоже.
func judgeProviderAnchorCoordinates(label string, merged map[string]any, prefix []string) (findings []string, circlesSeen, anchorsSeen int) {
	circles := clientCircles(merged, prefix)
	circlesSeen = len(circles)
	// Координаты кругов — множество, потому что круги МЕЖДУ СОБОЙ делить
	// координату ВПРАВЕ: у установки один внутренний центр, и требовать от
	// каждого слушателя своего объекта значило бы решать за оператора то, чего
	// он не решал.
	circleOf := map[string][]string{}
	for edge, paths := range circles {
		for _, p := range paths {
			circleOf[p] = append(circleOf[p], edge)
		}
	}
	for _, h := range providerHops {
		raw, ok := declaredAnchor(merged, prefix, h)
		if !ok {
			// Объявлен ли якорь вообще — предмет соседней переписи
			// (`provider_hops_test.go`); второе место о нём разошлось бы молча.
			continue
		}
		anchorsSeen++
		for _, p := range splitAnchorList(raw) {
			edges, clash := circleOf[p]
			if !clash {
				continue
			}
			sort.Strings(edges)
			findings = append(findings, "  "+label+": якорь хопа «"+h.name+"» и круг клиентских листов "+
				"слушателей ["+strings.Join(edges, ", ")+"] названы ОДНОЙ координатой "+p+
				" — это два разных вопроса («чьим сертификатам сервера я верю у соседа» против «кто вправе "+
				"прийти ко мне клиентом»), и оператор, чей поставщик выпущен другим центром, развести их "+
				"не может, не тронув заодно круг тех, кому позволено говорить с этой службой. Назовите якорю "+
				"поставщика СВОЮ координату: у чарта для этого есть ручка `tls.providerSecretName` и своё "+
				"монтирование `<tls.mountPath>/provider`.")
		}
	}
	return findings, circlesSeen, anchorsSeen
}

// auditProviderAnchorCoordinates читает цепочки чарта с диска и судит каждую
// боевую тем же телом, что и инъекция.
func auditProviderAnchorCoordinates(t *testing.T, chains map[string][]string) ([]string, string) {
	t.Helper()
	src := profileSource{
		label:  "chart",
		dir:    filepath.Join(serviceRoot(t), "deploy"),
		chains: chains,
	}

	names := make([]string, 0, len(chains))
	for name := range chains {
		names = append(names, name)
	}
	sort.Strings(names)

	findings := []string{}
	stacks, anchorsSeen, circlesSeen := 0, 0, 0
	for _, name := range names {
		merged := mergeProfiles(t, src, chains[name])
		if !isProductionClass(merged, src.prefix) {
			continue
		}
		stacks++
		f, circles, anchors := judgeProviderAnchorCoordinates(name, merged, src.prefix)
		findings = append(findings, f...)
		circlesSeen += circles
		anchorsSeen += anchors
	}

	census := "цепочек чарта " + strconv.Itoa(len(chains)) + " · из них боевых " + strconv.Itoa(stacks) +
		" · хопов поставщика " + strconv.Itoa(len(providerHops)) + " · объявленных якорей " + strconv.Itoa(anchorsSeen) +
		" · кругов клиентских листов " + strconv.Itoa(circlesSeen) + " · находок " + strconv.Itoa(len(findings))

	// «Ноль находок» обязано быть отличимо от «ноль прочитанного».
	require.NotZero(t, stacks, "обход пуст: боевых цепочек 0 — вердикт беспредметен")
	require.NotZero(t, anchorsSeen, "обход пуст: объявленных якорей 0 — сравнивать нечего")
	require.NotZero(t, circlesSeen, "обход пуст: кругов клиентских листов 0 — сравнивать не с чем")
	return findings, census
}
