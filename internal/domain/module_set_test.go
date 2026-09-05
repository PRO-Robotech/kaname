// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

// module_set_test.go — ПОРТ членства: домен читает ПОДАННЫЙ набор и не имеет
// своего (задача продукта #1927).
//
// # Что здесь проверялось раньше и почему проверка сменила предмет
//
// Прежняя редакция утверждала, что домен ВЛАДЕЕТ закрытым набором: она брала
// `domain.KnownModules()` и требовала, чтобы `domain.IsKnownModule` признавал
// каждое его имя. Оба символа сняты вместе с литералом, и утверждение о них
// исчезло бы молча — негативная половина («banana не модуль») продолжала бы
// зеленеть на любом наборе, потому что её вход перестал бы быть представимым
// (`testing.md` §«Гейт на класс», п. 9). Поэтому проба не ослаблена, а
// ПЕРЕВЕДЕНА на признак, который дерево производит: набор приходит параметром,
// и домен обязан читать именно его.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// fixtureModules — набор для проб ВНЕШНЕГО пакета. Довод против равенства
// платформенному набору — в `module_set_fixture_test.go`.
func fixtureModules() domain.ModuleSet {
	return domain.ModuleSetOf("iam", "vpc", "compute", "loadbalancer", "registry", "storage", "probe")
}

// TestModuleSetOf_ReadsWhatItWasGiven — обе стороны членства на ОДНОМ наборе.
//
// Положительная половина берёт имя, которого в каноне платформы нет
// (`probe`): будь у домена свой перечень, оно было бы отвергнуто. Отрицательная
// берёт имена, соседние с настоящими, — и `nlb`, который есть короткое имя
// службы балансировщика и НЕ есть имя её модуля каталога.
func TestModuleSetOf_ReadsWhatItWasGiven(t *testing.T) {
	set := fixtureModules()

	known := []string{"iam", "vpc", "compute", "loadbalancer", "registry", "storage", "probe"}
	for _, m := range known {
		if !set.IsKnownModule(m) {
			t.Errorf("IsKnownModule(%q) = false, want true (имя подано набору)", m)
		}
	}
	t.Logf("перепись: подано имён %d (%s)", len(known), strings.Join(known, ", "))

	unknown := []string{"banana", "geo", "nlb", "loadbalancers", "iAm", "", "*", "vpc "}
	for _, m := range unknown {
		if set.IsKnownModule(m) {
			t.Errorf("IsKnownModule(%q) = true, want false (имя набору не подавалось)", m)
		}
	}
}

// TestModuleSetOf_EmptyRecognisesNothing — пустой перечень даёт набор, не
// признающий ничего. Утверждение положительное по форме и отрицательное по
// смыслу, поэтому рядом стоит контроль: то же имя на НЕПУСТОМ наборе признаётся,
// иначе проба зеленела бы на реализации, отвергающей всё.
func TestModuleSetOf_EmptyRecognisesNothing(t *testing.T) {
	if domain.ModuleSetOf().IsKnownModule("vpc") {
		t.Error("пустой набор признал vpc — «перечень пуст» не есть «принимаем любой»")
	}
	if !domain.ModuleSetOf("vpc").IsKnownModule("vpc") {
		t.Error("контроль: непустой набор не признал vpc — проба выше зеленела бы даром")
	}
}

// TestValidateModule_MissingSetIsRefusedByItsOwnText — набор НЕ ПРОВЯЗАН.
//
// Отказ обязан отличаться текстом от «unknown module»: последний говорит
// арендатору, что виноват его вход, тогда как виновата провязка, и следующий шаг
// у этих двух разный. Рядом — контроль: то же правило на поданном наборе
// проходит.
func TestValidateModule_MissingSetIsRefusedByItsOwnText(t *testing.T) {
	r := domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}

	err := r.Validate(domain.TenantPolicy(), nil)
	if err == nil {
		t.Fatal("правило принято без набора модулей — «не знаю» не есть «можно»")
	}
	if !strings.Contains(err.Error(), "platform module set was not supplied") {
		t.Errorf("отказ = %v; хотел текст, называющий непровязанный набор, а не вход вызывающего", err)
	}
	if strings.Contains(err.Error(), "unknown module") {
		t.Errorf("отказ = %v; текст «unknown module» обвиняет вход, а виновата провязка", err)
	}

	if verr := r.Validate(domain.TenantPolicy(), fixtureModules()); verr != nil {
		t.Errorf("контроль: то же правило на поданном наборе отвергнуто: %v", verr)
	}
}

// TestValidateModule_UnknownNamesTheModule — членство читается у поданного
// набора, и отказ называет имя. Контроль — то же имя в наборе, где оно есть.
func TestValidateModule_UnknownNamesTheModule(t *testing.T) {
	r := domain.Rule{Module: "probe", Resources: []string{"network"}, Verbs: []string{"get"}}

	err := r.Validate(domain.TenantPolicy(), domain.ModuleSetOf("vpc"))
	if err == nil {
		t.Fatal("модуль вне поданного набора принят")
	}
	if !strings.Contains(err.Error(), "unknown module 'probe'") {
		t.Errorf("отказ = %v; хотел контракт-тон «unknown module 'probe'»", err)
	}

	if verr := r.Validate(domain.TenantPolicy(), fixtureModules()); verr != nil {
		t.Errorf("контроль: `probe` есть в фикстуре, но правило отвергнуто: %v", verr)
	}
}
