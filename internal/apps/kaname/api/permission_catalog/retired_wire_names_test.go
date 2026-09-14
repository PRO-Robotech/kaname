// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_wire_names_test.go — ИМЕНА полей снятого на проводе: `retiredResources`
// и `supersededBy`, camelCase, как у всех соседей витрины (kacho#1814).
//
// # Что эта проба доказывает, а чего НЕ доказывает — сказано первым
//
// Она НЕ доказывает `IAM-SUC-10` и его не подменяет. `IAM-SUC-10` утверждает,
// что поле доезжает до клиента ЧЕРЕЗ КРАЙ на поднятом стенде, и производитель у
// него один — кейс чёрного ящика `CONF-G-03-catalog-retired-successor`. Мимо
// этой пробы проходит всё, что делает край: маршрут, перекодирование и, главное,
// пересборка потребителя — неизвестное ему поле он отбрасывает МОЛЧА.
//
// Доказывает она одно и узкое: имена, которые ПОРОЖДАЕТ контракт, — те самые,
// что названы в кейсе края и на странице арендатора
// (`docs/content/api/authorize.mdx`). Ошибись мы в них, кейс края покраснел бы
// на поднятом стенде — то есть через полный цикл выкатки, — а страница лгала бы
// до тех пор. Здесь то же расхождение стоит секунды.
package permission_catalog

import (
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
)

// TestRetiredFieldsTravelInCamelCase — имена полей снятого в теле JSON.
func TestRetiredFieldsTravelInCamelCase(t *testing.T) {
	resp := catalogOverHalves(t, retiredHalves())
	// Положительный контроль: снятое в ответе ЕСТЬ. Без него утверждения об
	// именах выполнялись бы на теле, где полей нет вовсе.
	if len(resp.GetRetiredResources()) == 0 {
		t.Fatalf("перечень снятого пуст — утверждения об именах стали бы вакуумными")
	}

	raw, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatalf("проекция ответа в JSON: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("разбор тела: %v", err)
	}

	list, ok := body["retiredResources"].([]any)
	if !ok {
		t.Fatalf("в теле нет ключа `retiredResources`; ключи верхнего уровня: %v\n"+
			"страница арендатора и кейс края называют именно это имя", keysOf(body))
	}
	if len(list) == 0 {
		t.Fatalf("`retiredResources` пуст при непустом перечне в ответе")
	}
	first, ok := list[0].(map[string]any)
	if !ok {
		t.Fatalf("запись снятого не объект: %T", list[0])
	}
	if _, ok := first["resource"]; !ok {
		t.Errorf("у записи снятого нет ключа `resource`; ключи: %v", keysOf(first))
	}
	if _, ok := first["supersededBy"]; !ok {
		t.Errorf("у записи снятого нет ключа `supersededBy`; ключи: %v — "+
			"змеиная форма `superseded_by` на проводе разошлась бы с соседями витрины "+
			"и со страницей арендатора", keysOf(first))
	}

	// Контроль в обратную сторону: змеиных форм на проводе НЕТ ни у одного из
	// двух ключей. Без него ответ, несущий ОБЕ формы, прошёл бы утверждения выше.
	if _, ok := body["retired_resources"]; ok {
		t.Errorf("на проводе есть змеиная форма `retired_resources` — контракт даёт " +
			"два имени одному полю")
	}
	if _, ok := first["superseded_by"]; ok {
		t.Errorf("на проводе есть змеиная форма `superseded_by` — контракт даёт " +
			"два имени одному полю")
	}
	t.Logf("перепись: ключей верхнего уровня %d, записей снятого %d",
		len(body), len(list))
}

// keysOf — ключи объекта, для текстов отказа.
func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
