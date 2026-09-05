// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// baseroles_test.go — два признака раздела `resources`, которых требует приёмка
// `#1090` (задача PRO-Robotech/kacho#1843): `baseRoles` у ресурса (§3.3) и
// `internal` у действия (§3.8).
//
// # Почему признаки заводятся ВМЕСТЕ и проверяются здесь ОДНОЙ пробой
//
// Порознь каждый — просто поле. Вместе они дают утверждение, которое можно
// проверить сегодня: базовые ярусные роли выдаются АРЕНДАТОРУ, а внутренняя
// плоскость арендатору недоступна by construction (ban #6). Значит ресурс, у
// которого внутренние ВСЕ действия, базовых ролей порождать не вправе — такая
// роль выдавалась бы и не давала НИЧЕГО, оставаясь на вид действующей.
//
// Это не изобретённое правило: оно следует из ban #6 и из §3.3 («отсутствие
// признака означает „ярусов нет"»), и оно же — читатель обоих полей в
// прод-коде. Поле без читателя не заводится: норма эпика.
package manifest_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

// baseRolesDoc — оболочка с одним ресурсом; %s подставляет тело ресурса.
const baseRolesDoc = "apiVersion: iam/v1\nmodule: vpc\nresources:\n%s"

// TestBaseRolesOnAnAllInternalResourceIsRefused — ресурс, все действия которого
// внутренние, базовых ролей не порождает.
//
// Отрицание идёт В ПАРЕ с положительным: без него проба зеленела бы на
// загрузчике, отвергающем любой ресурс, и утверждала бы о нём ничего.
func TestBaseRolesOnAnAllInternalResourceIsRefused(t *testing.T) {
	allInternal := "  - name: addressPool\n    objectType: vpc_address_pool\n" +
		"    parents: [cluster]\n    producer: derived\n    baseRoles: true\n" +
		"    verbs:\n" +
		"      - {name: internalGetAddressPool,  class: get,  internal: true}\n" +
		"      - {name: internalListAddressPool, class: list, internal: true}\n"

	_, err := manifest.Load([]byte(strings.Replace(baseRolesDoc, "%s", allInternal, 1)))
	if err == nil {
		t.Fatal("ресурс с одними внутренними действиями объявил базовые ярусы и принят: " +
			"роль на него выдавалась бы арендатору и не давала бы НИ ОДНОГО права")
	}
	if !errors.Is(err, manifest.ErrBaseRolesWithoutTenantVerb) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	for _, needle := range []string{"baseRoles", "addressPool"} {
		if !strings.Contains(err.Error(), needle) {
			t.Errorf("отказ не назвал %q — читатель пойдёт искать место вручную: %v", needle, err)
		}
	}

	// Положительный близнец: ровно одно действие доступно арендатору — ярусы
	// становятся выдаваемыми, и отказа быть не должно.
	oneTenant := strings.Replace(allInternal,
		"      - {name: internalListAddressPool, class: list, internal: true}\n",
		"      - {name: list, class: list}\n", 1)
	if _, err := manifest.Load([]byte(strings.Replace(baseRolesDoc, "%s", oneTenant, 1))); err != nil {
		t.Fatalf("законный близнец отвергнут: %v — отрицание выше тогда ничего не утверждает", err)
	}

	// Второй близнец: те же одни внутренние действия, но БЕЗ признака —
	// отсутствие признака означает «ярусов нет», и запрещать тут нечего.
	noFlag := strings.Replace(allInternal, "    baseRoles: true\n", "", 1)
	if _, err := manifest.Load([]byte(strings.Replace(baseRolesDoc, "%s", noFlag, 1))); err != nil {
		t.Fatalf("ресурс без признака отвергнут: %v — правило судит объявленное, а не всякий "+
			"ресурс с внутренними действиями", err)
	}
}

// TestBaseRoleTiersAreDerivedOnlyFromTheDeclaredFlag — три состояния вывода
// ярусов, и все три названы: признака нет · есть · есть при суженном наборе.
func TestBaseRoleTiersAreDerivedOnlyFromTheDeclaredFlag(t *testing.T) {
	cases := []struct {
		name string
		res  manifest.Resource
		want []string
	}{
		{
			name: "признака нет — ярусов нет, а не «ярусы по умолчанию»",
			res:  manifest.Resource{Name: "network"},
			want: nil,
		},
		{
			name: "признак есть, сужения нет — весь набор",
			res:  manifest.Resource{Name: "network", BaseRoles: true},
			want: []string{"viewer", "editor", "admin"},
		},
		{
			name: "авторский набор СУЖАЕТ выводимое",
			res: manifest.Resource{Name: "addressPool", BaseRoles: true,
				Tiers: []manifest.ResourceTier{{Name: "admin"}, {Name: "viewer"}}},
			want: []string{"admin", "viewer"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.res.BaseRoleTiers()
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("выведено %v, ожидалось %v", got, c.want)
			}
		})
	}
}

// TestInternalVerbKeyIsAcceptedInTheLongFormOnly — признак плоскости
// объявляется только длинной формой действия.
//
// Короткая форма — имя канонического действия, и канонические действия
// тенантские: внутренняя плоскость у них не встречается. Проба утверждает ОБЕ
// стороны, иначе «принимается» было бы неотличимо от «принимается что угодно».
func TestInternalVerbKeyIsAcceptedInTheLongFormOnly(t *testing.T) {
	body := "  - name: network\n    objectType: vpc_network\n    parents: [project]\n" +
		"    producer: derived\n    verbs:\n      - {name: internalGetNetwork, class: get, internal: true}\n"
	m, err := manifest.Load([]byte(strings.Replace(baseRolesDoc, "%s", body, 1)))
	if err != nil {
		t.Fatalf("длинная форма с признаком плоскости отвергнута: %v", err)
	}
	if !m.Resources[0].Verbs[0].Internal {
		t.Error("признак прочитан как ложь: поле принято и не применено — запрещённый исход")
	}

	unknown := strings.Replace(body, "internal: true", "internalPlane: true", 1)
	if _, err := manifest.Load([]byte(strings.Replace(baseRolesDoc, "%s", unknown, 1))); err == nil {
		t.Error("неизвестный ключ действия принят: форма перестала быть закрытой")
	}
}
