// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// openmoduleset_test.go — набор модулей РАЗОМКНУТ: оператор чужого облака
// объявляет свой модуль доставкой, а не пересборкой образа.
//
// # Предмет
//
// До этой полосы имя модуля судилось перечнем, ПОРОЖДЁННЫМ СБОРКОЙ из манифестов
// нашего дерева (`authzmap.CatalogSeedModules()`). Перечень вкомпилирован в
// бинарь, поэтому модуль, которого в нашем дереве нет, был невыразим НИ ПРИ КАКОМ
// входе — ни файлом, ни глаголом: круг замыкался так же, как замыкался он у
// таблицы типов (`typereferent.go`), только вокруг имени модуля.
//
// # Чем судится имя ТЕПЕРЬ, и почему отказ не исчез
//
//	форма имени        грамматика модуля, ОДНА на дерево (`domain.IsWellFormedModuleName`)
//	членство в наборе  собственные объявления ЭТОГО ЖЕ обхода плюс набор,
//	                   внесённый вызывающим (`WithModuleSet`)
//	столкновение       имя, объявленное дважды одним обходом, — находка,
//	                   называющая ОБА места
//
// Отказ остаётся возможен — но по ПРИЧИНЕ, названной автору манифеста, а не по
// канону образа, о котором автор ничего не знает и повлиять на который не может.
//
// # Отрицания стоят В ПАРЕ с положительным, и близнец отличается ОДНИМ фактом
//
// Без пары «отказ есть» неотличимо от «загрузчик отвергает всё», а близнец,
// отличающийся двумя фактами, не говорит, который из них дал красное.

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// acmeEnvelope — оболочка модуля, которого нет в порождённой сборкой таблице.
//
// Разделов у неё нет намеренно: предмет проб формы и столкновения — ИМЯ, и
// лишний раздел добавил бы второй факт к дельте близнеца.
const acmeEnvelope = "apiVersion: iam/v1\nmodule: acme\n"

// acmeWithRole — тот же модуль, объявляющий роль на своём ресурсе.
//
// Раздела `resources` здесь НЕТ, и это измеренная граница, а не упущение: имя
// ТИПА ОБЪЕКТА судит закрытая таблица, порождённая сборкой, и её размыкание —
// отдельный предмет (см. [manifest.TypeReferent]). Правило роли называет ресурс
// грамматикой, поэтому роль модуля оператора выразима уже сегодня.
const acmeWithRole = acmeEnvelope + `roles:
  - id: acme.widget.admin
    description: "Полный доступ к виджетам acme в проекте оператора"
    tier:
      tierType: iam.cluster
      tierId: cluster_root
    rules:
      - module: acme
        resources: [widget]
        classes: ["*"]
`

// refuteVacuity — `acme` обязан ОТСУТСТВОВАТЬ в порождённой сборкой таблице,
// иначе всё ниже утверждает о члене набора и не проверяет ничего.
func refuteVacuity(t *testing.T) {
	t.Helper()
	canon := authzmap.CatalogSeedModules()
	if len(canon) == 0 {
		t.Fatal("порождённая таблица пуста — сверка беспредметна: «принят» здесь " +
			"неотличимо от «набор ничего не знает»")
	}
	if slices.Contains(canon, "acme") {
		t.Fatalf("`acme` состоит в порождённой таблице (%s) — проба утверждала бы "+
			"о ЧЛЕНЕ набора и была бы зелёной при закрытом наборе",
			strings.Join(canon, ", "))
	}
	t.Logf("перепись: в порождённой сборкой таблице модулей %d (%s); `acme` вне её",
		len(canon), strings.Join(canon, ", "))
}

// TestLoadAdmitsAModuleTheShippedTableDoesNotKnow — модуль вне порождённой
// таблицы принимается загрузчиком.
func TestLoadAdmitsAModuleTheShippedTableDoesNotKnow(t *testing.T) {
	refuteVacuity(t)

	if _, err := manifest.Load([]byte(acmeEnvelope)); err != nil {
		t.Fatalf("оболочка модуля оператора отвергнута: %v", err)
	}
	if _, err := manifest.Load([]byte(acmeWithRole)); err != nil {
		t.Fatalf("модуль оператора со своей ролью отвергнут: %v", err)
	}
}

// TestDeliveryAdmitsAModuleTheShippedTableDoesNotKnow — то же на ДОСТАВКЕ: это
// та полоса, которой пользуется оператор чужого облака.
func TestDeliveryAdmitsAModuleTheShippedTableDoesNotKnow(t *testing.T) {
	refuteVacuity(t)

	root := deliveryDir(t, map[string]string{
		"vpc/manifest.yaml":  compactManifest,
		"acme/manifest.yaml": acmeWithRole,
	})

	report, err := manifest.LoadDelivered(root)
	if err != nil {
		t.Fatalf("доставка с модулем оператора отвергнута: %v", err)
	}
	if report.ManifestsRead != 2 {
		t.Fatalf("манифестов прочитано %d, ожидалось 2 (осмотрено файлов %d) — "+
			"«ноль находок» обязано быть отличимо от «ноль прочитанного»",
			report.ManifestsRead, report.PathsSeen)
	}
	if !slices.Contains(report.Modules(), "acme") {
		t.Fatalf("перепись модулей %v не называет доставленного оператором",
			report.Modules())
	}
}

// TestLoadRefusesAModuleNameByItsFormAndNamesTheRule — отказ по ФОРМЕ имени,
// с названной причиной. Близнец отличается ОДНИМ фактом — регистром буквы.
func TestLoadRefusesAModuleNameByItsFormAndNamesTheRule(t *testing.T) {
	broken := strings.Replace(acmeEnvelope, "module: acme", "module: Acme", 1)

	_, err := manifest.Load([]byte(broken))
	if err == nil {
		t.Fatal("имя модуля не той формы принято молча")
	}
	if !errors.Is(err, manifest.ErrMalformedModule) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	if !strings.Contains(err.Error(), "Acme") {
		t.Errorf("отказ не называет полученного токена — чинить придётся угадыванием: %v", err)
	}
	if !strings.Contains(err.Error(), domain.ModuleNameGrammar()) {
		t.Errorf("отказ не называет ПРАВИЛА (%s) — автор не узнает, чем имя негодно: %v",
			domain.ModuleNameGrammar(), err)
	}

	// Близнец: та же оболочка, имя годной формы.
	if _, err := manifest.Load([]byte(acmeEnvelope)); err != nil {
		t.Fatalf("парный положительный (acme) отвергнут: %v", err)
	}
}

// TestDeliveryRefusesAModuleNameThatCollidesWithAnAlreadyDeclaredOne —
// столкновение имён внутри одной доставки: у модуля один манифест и один
// владелец. Близнец отличается ОДНИМ фактом — именем второго модуля.
func TestDeliveryRefusesAModuleNameThatCollidesWithAnAlreadyDeclaredOne(t *testing.T) {
	root := deliveryDir(t, map[string]string{
		"first/manifest.yaml":  acmeEnvelope,
		"second/manifest.yaml": acmeEnvelope,
	})

	report, err := manifest.LoadDelivered(root)
	if err == nil {
		t.Fatal("два манифеста одного модуля приняты — второй молча переопределил бы первый")
	}
	if report.ManifestsRead != 2 {
		t.Errorf("перепись при отказе называет %d прочитанных, ожидалось 2", report.ManifestsRead)
	}
	msg := err.Error()
	for _, where := range []string{"first/manifest.yaml", "second/manifest.yaml"} {
		if !strings.Contains(msg, where) {
			t.Errorf("отказ не называет места %q — чинить придётся перебором: %s", where, msg)
		}
	}

	// Близнец: второй манифест назван ДРУГИМ модулем — тот же обход, один факт.
	twin := deliveryDir(t, map[string]string{
		"first/manifest.yaml":  acmeEnvelope,
		"second/manifest.yaml": strings.Replace(acmeEnvelope, "module: acme", "module: acme-two", 1),
	})
	if _, err := manifest.LoadDelivered(twin); err != nil {
		t.Fatalf("парный положительный (два РАЗНЫХ модуля) отвергнут: %v", err)
	}
}

// TestDeliveryDiagnosesARuleModuleByWhatTheDeliveryDeclares — модуль, названный
// ПРАВИЛОМ роли, судится объявлениями ЭТОЙ ЖЕ доставки, и от этого зависит, КАКОЙ
// отказ получит автор.
//
// # Здесь опровергнута моя же посылка, и опровержение улучшило предмет
//
// Полоса заводилась в расчёте на то, что правило вправе назвать модуль соседа по
// доставке. Это неверно: `validateRuleOwnership` (roles.go) отвергает такое
// правило ВСЕГДА — междоменная роль принадлежит платформе, а не модулю. Значит
// набор решает не «принять или отвергнуть», а ЧТО ИМЕННО сказать автору:
//
//	модуля нет в установке   отказ ДОМЕНА «unknown module» — такого модуля нет
//	                         вовсе, и правило чинится сменой имени;
//	модуль в установке есть  отказ ВЛАДЕНИЯ, называющий ОБА значения — модуль
//	                         существует, но он не твой, и правило чинится
//	                         переносом роли к его владельцу.
//
// Починки разные, поэтому и отказы разные. Отличие двух прогонов ниже — ОДИН
// факт: лежит ли в доставке манифест соседа.
func TestDeliveryDiagnosesARuleModuleByWhatTheDeliveryDeclares(t *testing.T) {
	refuteVacuity(t)

	crossed := strings.Replace(acmeWithRole, "      - module: acme", "      - module: vpc", 1)

	alone := deliveryDir(t, map[string]string{"acme/manifest.yaml": crossed})
	_, err := manifest.LoadDelivered(alone)
	if err == nil {
		t.Fatal("правило над чужим модулем принято — междоменная роль принадлежит платформе")
	}
	if !strings.Contains(err.Error(), "unknown module") {
		t.Errorf("доставка НЕ объявляла `vpc`, а отказ не говорит, что модуля нет вовсе: %v", err)
	}

	// Один факт: сосед лежит в той же доставке — и диагноз меняется.
	withNeighbour := deliveryDir(t, map[string]string{
		"acme/manifest.yaml": crossed,
		"vpc/manifest.yaml":  compactManifest,
	})
	_, err = manifest.LoadDelivered(withNeighbour)
	if err == nil {
		t.Fatal("правило над чужим модулем принято при объявленном соседе")
	}
	if strings.Contains(err.Error(), "unknown module") {
		t.Errorf("доставка объявила `vpc` манифестом, а отказ утверждает, что модуля нет: %v", err)
	}
	for _, want := range []string{"roles[0].rules[0].module", "acme", "vpc"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ владения не называет %q — автор чинит не то поле: %v", want, err)
		}
	}
}

// TestLoadJudgesRuleModulesByTheSetTheCallerSupplies — набор вносит ВЫЗЫВАЮЩИЙ:
// живые строки каталога доезжают до загрузчика этим портом, а не своей копией
// перечня. Отличие двух прогонов — ОДИН факт: внесён набор или нет.
func TestLoadJudgesRuleModulesByTheSetTheCallerSupplies(t *testing.T) {
	crossed := strings.Replace(acmeWithRole, "      - module: acme", "      - module: vpc", 1)

	_, err := manifest.Load([]byte(crossed))
	if err == nil {
		t.Fatal("правило над чужим модулем принято без внесённого набора")
	}
	if !strings.Contains(err.Error(), "unknown module") {
		t.Errorf("набор не внесён, а отказ не говорит, что модуля нет вовсе: %v", err)
	}

	_, err = manifest.Load([]byte(crossed), manifest.WithModuleSet(domain.ModuleSetOf("vpc")))
	if err == nil {
		t.Fatal("правило над чужим модулем принято при внесённом наборе")
	}
	if strings.Contains(err.Error(), "unknown module") {
		t.Errorf("набор внесён и знает `vpc`, а отказ утверждает, что модуля нет: %v", err)
	}
}

// TestDeliveryStillRefusesAnEmptyWalkAndPrintsTheCensus — размыкание набора не
// трогает третьего исхода: пустой обход остаётся отказом, перепись печатается.
func TestDeliveryStillRefusesAnEmptyWalkAndPrintsTheCensus(t *testing.T) {
	root := configMapMount(t, nil)

	report, err := manifest.LoadDelivered(root)
	if err == nil {
		t.Fatal("пустой обход принят — сорванное монтирование стало бы неотличимо " +
			"от снятия всех модулей разом")
	}
	if report.PathsSeen == 0 {
		t.Fatal("перепись не названа — отказ неотличим от нечитаемого каталога")
	}
	if !strings.Contains(report.Summary(), "манифестов прочитано 0") {
		t.Errorf("перепись не говорит числа прочитанного: %s", report.Summary())
	}
}
