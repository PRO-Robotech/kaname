// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// schemarolesform_internal_test.go — держатель Г10 приёмки
// `services/iam/docs/engineering/acceptance/roles-come-as-data-not-migrations.md`
// (§3.2.1, §6, §7; сценарий MOD-RD-25).
//
// # Предмет: СОГЛАСИЕ ЗНАЧЕНИЙ, а не множеств ключей
//
// Опубликованная схема — публичный контракт модуля, и её образец имени роли
// НЕ ИСПОЛНЯЕТСЯ никем: единственная строка прод-дерева, знающая файл схемы,
// стоит в пробе. Значит расхождение между схемой и разбором тихое by
// construction: оба отвечают «валидно» на валидном входе и расходятся только на
// невалидном.
//
// Замер, из-за которого гейт заведён: образец схемы требовал ровно ДВУХ
// сегментов и допускал заглавные, а живые имена — `<модуль>.<ресурс>.<ярус>`;
// прогон образца по сорока восьми живым именам давал выразимо ТРИ. То есть
// флагманский вход `vpc.network.admin` контракт отвергал двумя своими
// значениями сразу.
//
// # Почему это НЕ расширение `schemaagreement_internal_test.go`
//
// Та проба сверяет МНОЖЕСТВА КЛЮЧЕЙ схемы и структур, а `pattern` и `enum`
// стоят у неё в `annotationKeywords` — то есть значения вне её наблюдения by
// construction. Расширять её значило бы завести второе место об одном предмете:
// она про равенство ключей, этот гейт — про равенство значений.
package manifest

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// schemaRolesItemProps достаёт `properties.roles.items.properties` из
// опубликованной схемы. Падает на любом расхождении формы: схема без раздела
// `roles` есть НАХОДКА, а не молчание — иначе гейт зеленел бы на дереве, где
// предмета нет вовсе.
func schemaRolesItemProps(t *testing.T) (props map[string]any, census int) {
	t.Helper()
	raw, err := os.ReadFile(publishedSchemaPath)
	if err != nil {
		t.Fatalf("опубликованная схема не читается (%s): %v", publishedSchemaPath, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("опубликованная схема не разбирается: %v", err)
	}
	step := func(m map[string]any, key string) map[string]any {
		v, ok := m[key]
		if !ok {
			t.Fatalf("в опубликованной схеме нет ключа %q — гейт беспредметен: он молчал бы "+
				"и тогда, когда предмет исчез, и тогда, когда сломался он сам", key)
		}
		mm, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("ключ %q опубликованной схемы не объект: %T", key, v)
		}
		return mm
	}
	items := step(step(step(doc, "properties"), "roles"), "items")
	props = step(items, "properties")
	return props, len(props)
}

// TestMODRD25SchemaAndTheDeclaredFormSayTheSame — сам гейт Г10.
func TestMODRD25SchemaAndTheDeclaredFormSayTheSame(t *testing.T) {
	props, census := schemaRolesItemProps(t)
	t.Logf("перепись: свойств роли в опубликованной схеме прочитано %d", census)
	if census == 0 {
		t.Fatalf("прочитано ноль свойств роли — обход пуст, и его молчание сказано ни о чём")
	}

	// (1) Образец идентификатора равен ЕДИНСТВЕННОМУ объявлению формы.
	id, ok := props["id"].(map[string]any)
	if !ok {
		t.Fatalf("у роли нет свойства `id`: %v", props)
	}
	got, _ := id["pattern"].(string)
	if got != RoleIDForm {
		t.Errorf("схема и разбор говорят о форме идентификатора РАЗНОЕ:\n"+
			"  ключ схемы : properties.roles.items.properties.id.pattern\n"+
			"  объявлено  : %s\n"+
			"  найдено    : %s\n\n"+
			"Схема не исполняется никем, поэтому расхождение тихое: оба правила отвечают "+
			"«валидно» на валидном входе и расходятся только на невалидном. Автор манифеста "+
			"получил бы от редактора «годно» на имени, которое разбор отвергнет, — либо "+
			"наоборот, отказ на имени, которое платформа принимает.", RoleIDForm, got)
	}

	// (2) Перечень ярусов равен ЕДИНСТВЕННОМУ объявлению набора.
	tier, ok := props["tier"].(map[string]any)
	if !ok {
		t.Fatalf("у роли нет свойства `tier`: %v", props)
	}
	tierProps, ok := tier["properties"].(map[string]any)
	if !ok {
		t.Fatalf("у яруса нет `properties`: %v", tier)
	}
	tierType, ok := tierProps["tierType"].(map[string]any)
	if !ok {
		t.Fatalf("у яруса нет `tierType`: %v", tierProps)
	}
	rawEnum, ok := tierType["enum"].([]any)
	if !ok {
		t.Fatalf("`tierType` без перечня значений (`enum`): %v", tierType)
	}
	gotEnum := make([]string, 0, len(rawEnum))
	for _, v := range rawEnum {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("значение перечня `tierType` не строка: %T", v)
		}
		gotEnum = append(gotEnum, s)
	}
	if !reflect.DeepEqual(gotEnum, RoleTierTypes) {
		t.Errorf("схема и разбор говорят о наборе ярусов РАЗНОЕ:\n"+
			"  ключ схемы : properties.roles.items.properties.tier.properties.tierType.enum\n"+
			"  объявлено  : %v\n"+
			"  найдено    : %v\n\n"+
			"Все живые системные роли — кластерные. Перечень без `iam.cluster` означает, что "+
			"контракт отвергает единственный ярус, на котором роли продукта существуют.",
			RoleTierTypes, gotEnum)
	}

	// (3) ТРЕТЬЯ копия той же формы — образец ссылки выдачи на роль. Она живёт в
	// другом разделе схемы и разошлась бы с двумя первыми молча: выдача просто
	// не смогла бы сослаться на роль вида `<модуль>.<ресурс>.<ярус>`.
	if got := schemaSeedRoleIDPattern(t); got != RoleIDForm {
		t.Errorf("ссылка выдачи на роль объявляет форму, отличную от объявления:\n"+
			"  ключ схемы : properties.seed.properties.accessBindings.items.properties.roleId.pattern\n"+
			"  объявлено  : %s\n"+
			"  найдено    : %s\n\n"+
			"Раздел `roles` принял бы имя, на которое раздел `seed` сослаться не может.",
			RoleIDForm, got)
	}

	// (4) Флагманский вход обязан быть выразим ОБОИМИ значениями сразу.
	// Без этой стороны гейт зеленел бы на паре, согласованной между собой и
	// неисполнимой: расхождения нет, а объявить роль по-прежнему нельзя.
	for _, name := range []string{"vpc.network.admin", "iam.access_binding.view"} {
		if !roleIDRe.MatchString(name) {
			t.Errorf("объявленная форма отвергает живое имя %q — согласие схемы и разбора "+
				"достигнуто на правиле, которого продукт не исполняет", name)
		}
	}
}

// schemaSeedRoleIDPattern — образец ссылки выдачи на роль. Отдельным
// помощником, а не третьим повторением обхода: место в документе другое, а
// предмет тот же.
func schemaSeedRoleIDPattern(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(publishedSchemaPath)
	if err != nil {
		t.Fatalf("опубликованная схема не читается (%s): %v", publishedSchemaPath, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("опубликованная схема не разбирается: %v", err)
	}
	cur := any(doc)
	for _, step := range []string{
		"properties", "seed", "properties", "accessBindings", "items", "properties", "roleId",
	} {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("путь до ссылки выдачи на роль оборвался на %q: %T", step, cur)
		}
		cur, ok = m[step]
		if !ok {
			t.Fatalf("в опубликованной схеме нет ключа %q на пути до ссылки выдачи — "+
				"гейт беспредметен", step)
		}
	}
	m, ok := cur.(map[string]any)
	if !ok {
		t.Fatalf("ссылка выдачи на роль не объект: %T", cur)
	}
	p, _ := m["pattern"].(string)
	return p
}
