// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// executionplane_test.go — действие ПЛОСКОСТИ ИСПОЛНЕНИЯ не едет в роль классом.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (задача продукта #1835)
//
// Черновик манифеста объявляет запрет прямо: действие плоскости исполнения не
// попадает в роль автоматически ни при каком способе перечисления прав. Пока
// формы «выдать по классу» в контракте не было, запрет был БЕСПРЕДМЕТЕН —
// раздел `roles` перечислял действия поимённо, и раскрывать было нечему.
//
// Форма появилась (ключ `classes`, задача продукта #1090), и вместе с ней
// появился предмет: покрытие класса собиралось по ВСЕМ действиям ресурса, а
// признак плоскости (`Action.Internal`, выведенный из приставки `Internal` у
// имени службы) в нём не читался вовсе. Значит класс объявлялся «пригодным» на
// одном лишь основании внутреннего действия, и выдача по классу зачитывала его
// в покрытие наравне с обычным чтением.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ ИЗМЕРЕН, А НЕ ПРЕДПОЛОЖЕН
//
// Перепись встроенного каталога прав (единица — запись каталога; 350 записей):
// внутренней плоскости — 102. Пар «отношение + объект», встречающихся ТОЛЬКО у
// внутренней плоскости, — 10, и пять из них производимы классом через ярус
// (`editor` у storage_volume и vpc_network_interface, `viewer` у storage_image
// и storage_volume, `admin` у registry_registry). То есть класс, покрывающий
// одни лишь внутренние действия, — состояние дерева, а не выдумка пробы.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ — ПАРОЙ, а не одной стороной
//
//	находка          внутреннее действие в покрытие НЕ входит, и отказ его НАЗЫВАЕТ
//	законный близнец арендаторское действие той же формы покрывается по-прежнему
//
// Без второй половины проверка зеленела бы на реализации, у которой класс не
// покрывает НИЧЕГО, — то есть на сломанной выдаче.
package roleexport_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/manifest/roleexport"
	"github.com/PRO-Robotech/kacho-iam/internal/testsupport/catalogfixture"
)

// planeTwins — два действия, различающиеся РОВНО ОДНИМ фактом: плоскостью.
//
// Один факт — условие годности пары: изменив второй, проба перестала бы
// говорить о плоскости и заговорила бы о чём придётся.
func planeTwins() (tenant, internal roleexport.Action) {
	tenant = roleexport.Action{
		Module:   "vpc",
		Resource: "address",
		Verb:     "get",
		FQN:      "kacho.cloud.vpc.v1.AddressService/GetAddress",
		Relation: "v_get",
		Object:   "vpc_address",
	}
	internal = tenant
	internal.FQN = "kacho.cloud.vpc.v1.InternalAddressService/GetAddress"
	internal.Internal = true
	return tenant, internal
}

func TestClassNeverCoversAnExecutionPlaneAction(t *testing.T) {
	facts := catalogfixture.Facts()
	tenant, internal := planeTwins()

	// Законный близнец: арендаторское действие покрывается — иначе утверждение
	// ниже было бы вакуумным (покрытие пусто при любом входе).
	if got := roleexport.Covers(facts, []roleexport.Action{tenant}, "vpc_address", "get"); len(got) != 1 {
		t.Fatalf("положительный контроль провален: класс get не покрыл АРЕНДАТОРСКОЕ действие "+
			"%s (%s@%s) — значит проверка ниже не говорит ни о чём",
			tenant.FQN, tenant.Relation, tenant.Object)
	}

	// Находка: то же действие на ВНУТРЕННЕЙ плоскости в покрытие не входит.
	if got := roleexport.Covers(facts, []roleexport.Action{internal}, "vpc_address", "get"); len(got) != 0 {
		t.Errorf("класс get покрыл действие ПЛОСКОСТИ ИСПОЛНЕНИЯ %s: выдача по классу отдаёт "+
			"наблюдателю действие внутреннего слушателя вместе с обычным чтением. "+
			"Признак плоскости объявлен и разделом resources (ключ internal), и записью "+
			"каталога (приставка Internal у имени службы) — и не читается покрытием",
			internal.FQN)
	}

	// Обе плоскости вместе: покрытие несёт РОВНО арендаторское.
	both := roleexport.Covers(facts, []roleexport.Action{tenant, internal}, "vpc_address", "get")
	if len(both) != 1 || both[0].Internal {
		t.Errorf("на смешанном наборе покрытие вышло %d действий (внутреннее среди них: %v) — "+
			"ожидалось ровно одно арендаторское", len(both), len(both) > 0 && both[0].Internal)
	}
}

// TestRefusalNamesTheExecutionPlaneActionItSkipped — отказ обязан НАЗВАТЬ
// пропущенное.
//
// Без имени автор прочтёт «класс ничего не покрывает» как опечатку в манифесте и
// пойдёт искать её у себя — при том что действия у ресурса есть, и они просто не
// его плоскости.
func TestRefusalNamesTheExecutionPlaneActionItSkipped(t *testing.T) {
	m := mustFixture(t)
	_, internal := planeTwins()

	// Состав действий подаёт проба: у ресурса `vpc.address` есть ровно одно
	// действие, и оно внутреннее. Роль `vpc.internal_consumer` фикстуры называет
	// этот ресурс классами get/list — значит класс `get` обязан стать находкой.
	faults, _ := roleexport.CheckRoleRules(catalogfixture.Facts(), m, []roleexport.Action{internal})

	var refusal string
	for _, f := range faults {
		var got roleexport.Finding
		if errors.As(f, &got) && errors.Is(f, roleexport.ErrClassCoversNoSuitableAction) &&
			got.Role == "vpc.internal_consumer" && got.Resource == "address" && got.Class == "get" {
			refusal = f.Error()
			break
		}
	}
	if refusal == "" {
		t.Fatalf("класс get на ресурсе address не стал находкой, хотя единственное действие "+
			"ресурса — внутреннее (%s). Находки: %v", internal.FQN, faults)
	}
	// Регистр слова не значим: отказ пишет «ПЛОСКОСТИ ИСПОЛНЕНИЯ» заглавными,
	// и утверждение о РЕГИСТРЕ было бы утверждением не о том.
	lowered := strings.ToLower(refusal)
	for _, want := range []string{strings.ToLower(internal.FQN), "плоскост"} {
		if !strings.Contains(lowered, want) {
			t.Errorf("отказ не называет %q — читатель не узнает, что действия у ресурса ЕСТЬ, "+
				"но они не его плоскости; отказ: %s", want, refusal)
		}
	}
}
