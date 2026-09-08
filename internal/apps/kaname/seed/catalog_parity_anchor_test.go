// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_parity_anchor_test.go — ОПОРА стража паритета есть «образ ∪ ДОСТАВКА»,
// а не один образ (задача продукта #1861, вторая её половина).
//
// # Что здесь предмет, а что уже закрыто соседним набором
//
// Соседний набор (`catalog_parity_test.go`) утверждает, что опора судит как
// ВЕРХНЯЯ ГРАНИЦА: живых строк вправе быть меньше, если о пропавшей есть снятая.
// Это закрыло полосу СНЯТИЯ. Осталась встречная полоса — ДОБАВЛЕНИЕ: живая
// строка, которой образ не несёт, отвергалась при любом входе, потому что опорой
// был перечень, вшитый сборкой.
//
// Цена этого снаружи: установка в чужом облаке объявляет свой модуль манифестом,
// применитель строку пишет, а следующий пуск отказан — то есть объявить модуль
// данными нельзя, и требуется пересборка образа. При этом ВТОРАЯ половина того
// же старта — композиция модели прав — новый тип уже принимает
// (`composed-model-admits-only-what-it-owns.md`): две половины одного старта
// противоречили друг другу.
//
// # Дисциплина взята у близнеца, а не выдумана
//
// Модель допускает доставку МОНОТОННО и ПОДВЕШЕННО: вправе добавить своё, не
// вправе изменить ни одного объявления, которое образ уже несёт. Каталог
// получает ту же пару:
//
//	доставка объявила строку, которой образ не несёт   опора расширяется
//	доставка объявила строку образа ДОСЛОВНО           опора не меняется (обычный
//	                                                   случай: манифесты дерева и
//	                                                   есть источник образа)
//	доставка ПЕРЕОПРЕДЕЛЯЕТ форму строки образа        ОТКАЗ, и ДО применения
//
// # Что обязано уцелеть, и почему это половина предмета
//
// Живая строка, которой не объявляют НИ образ, НИ доставка, остаётся отказом
// старта. Ослабь это — и отзыв модуля перестал бы доезжать: снятая доставкой
// строка осталась бы жить в базе, а страж молчал бы, потому что сравнивать стало
// не с чем. Поэтому каждое утверждение о допуске стоит здесь В ПАРЕ с
// утверждением об отказе на том же входе при неизменённой опоре.
package seed_test

import (
	"context"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
)

// Имена строки, которую объявляет ДОСТАВКА и не несёт образ. Взяты заведомо
// вне словаря платформы: совпади они с живым модулем — набор проверял бы
// оживление снятой строки, а не расширение опоры.
const (
	deliveredModule   = "tenantops"
	deliveredResource = "runbook"
	deliveredType     = "tenantops_runbook"
	deliveredVerb     = "get"
)

// ownRows — строки, которые объявляет ТОЛЬКО доставка.
func ownRows() catalog.Rows {
	return catalog.Rows{
		Modules: []string{deliveredModule},
		Resources: []catalog.ResourceRow{{
			Module: deliveredModule, Resource: deliveredResource, ObjectType: deliveredType,
		}},
		Verbs: []catalog.VerbRow{{
			Module: deliveredModule, Resource: deliveredResource,
			Verb: deliveredVerb, PerObject: true,
		}},
	}
}

// mergeRows — объединение двух множеств. Доставка в этом дереве объявляет ОБЕ
// половины: манифесты, из которых порождён образ, и своё сверх них.
func mergeRows(a, b catalog.Rows) catalog.Rows {
	out := catalog.Rows{
		Modules:   append(append([]string{}, a.Modules...), b.Modules...),
		Resources: append(append([]catalog.ResourceRow{}, a.Resources...), b.Resources...),
		Verbs:     append(append([]catalog.VerbRow{}, a.Verbs...), b.Verbs...),
	}
	return out
}

// requireNonEmptyImage — ПРЕДПОСЫЛКА набора: производитель образа непуст.
// На пустом образе «доставка ничего не переопределяет» выполнялось бы
// тривиально, а «расширение опоры» было бы неотличимо от опоры целиком.
func requireNonEmptyImage(t *testing.T) catalog.Rows {
	t.Helper()
	image := seed.LiteralRows()
	if len(image.Modules) == 0 || len(image.Resources) == 0 || len(image.Verbs) == 0 {
		t.Fatalf("производитель образа пуст: модулей/ресурсов/глаголов %d/%d/%d — "+
			"набор беспредметен, и его молчание неотличимо от исправной работы",
			len(image.Modules), len(image.Resources), len(image.Verbs))
	}
	t.Logf("перепись образа: модулей %d, ресурсов %d, глаголов %d",
		len(image.Modules), len(image.Resources), len(image.Verbs))
	return image
}

// TestAnchorAdmitsDeliveryThatOnlyAddsItsOwn — ДОПУСК доставки: три входа,
// у каждого назван законный близнец.
func TestAnchorAdmitsDeliveryThatOnlyAddsItsOwn(t *testing.T) {
	image := requireNonEmptyImage(t)

	t.Run("доставка повторяет образ ДОСЛОВНО — опора не расширяется", func(t *testing.T) {
		a, err := seed.NewAnchor(image)
		if err != nil {
			t.Fatalf("доставка, дословно совпадающая с образом, отвергнута: %v. "+
				"Это ОБЫЧНЫЙ случай: манифесты дерева и есть источник образа, "+
				"и отказ на них сделал бы доставку неисполнимой by construction", err)
		}
		if n := len(a.AddedRows()); n != 0 {
			t.Fatalf("опора расширена на %d строк дословным повтором образа: %v",
				n, a.AddedRows())
		}
	})

	t.Run("доставка объявила СВОЁ — опора расширяется ровно на него", func(t *testing.T) {
		a, err := seed.NewAnchor(mergeRows(image, ownRows()))
		if err != nil {
			t.Fatalf("доставка, добавляющая своё, отвергнута: %v", err)
		}
		added := a.AddedRows()
		if len(added) != 3 {
			t.Fatalf("опора расширена на %d строк, ожидалось 3 (модуль, ресурс, глагол): %v",
				len(added), added)
		}
		for _, want := range []string{deliveredModule, deliveredResource, deliveredVerb} {
			if !strings.Contains(strings.Join(added, " | "), want) {
				t.Fatalf("перепись расширения не называет %q: %v", want, added)
			}
		}
	})

	t.Run("доставка ПЕРЕОПРЕДЕЛЯЕТ строку образа — отказ, и он называет строку", func(t *testing.T) {
		tampered := catalog.Rows{
			Modules:   append([]string{}, image.Modules...),
			Resources: append([]catalog.ResourceRow{}, image.Resources...),
			Verbs:     append([]catalog.VerbRow{}, image.Verbs...),
		}
		victim := tampered.Resources[0]
		tampered.Resources[0].ObjectType = deliveredType

		a, err := seed.NewAnchor(tampered)
		if err == nil {
			t.Fatalf("доставка переопределила имя типа строки образа %s.%s (%s → %s), "+
				"а опора это приняла: расширение перестало быть монотонным, и "+
				"доставка получила власть переписывать объявления образа. Перепись: %v",
				victim.Module, victim.Resource, victim.ObjectType, deliveredType, a.AddedRows())
		}
		for _, want := range []string{victim.Module + "." + victim.Resource, deliveredType} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("отказ не называет %q: %v", want, err)
			}
		}
	})
}

// TestCatalogParityGuardJudgesAgainstDeliveredAnchor — СТРАЖ над той же опорой.
// Четыре входа, и каждый допуск стоит в паре с отказом на том же живом
// множестве при неизменённой опоре.
func TestCatalogParityGuardJudgesAgainstDeliveredAnchor(t *testing.T) {
	image := requireNonEmptyImage(t)
	own := ownRows()
	delivered, derr := seed.NewAnchor(mergeRows(image, own))
	if derr != nil {
		t.Fatalf("опора «образ ∪ доставка» не собралась: %v", derr)
	}

	t.Run("строка доставки жива, доставка её объявила — страж молчит", func(t *testing.T) {
		src := &stubRowSource{rows: mergeRows(image, own)}
		census, err := seed.AssertCatalogParity(context.Background(), src, delivered)
		if err != nil {
			t.Fatalf("страж отказал в пуске на строке, ОБЪЯВЛЕННОЙ доставкой: %v. "+
				"Нет строкой %v; нет в опоре %v", err, census.MissingRows, census.ExtraRows)
		}
		if len(census.ExtraRows) != 0 || len(census.MissingRows) != 0 {
			t.Fatalf("перепись назвала расхождение при молчащем страже: "+
				"нет строкой %v; нет в опоре %v", census.MissingRows, census.ExtraRows)
		}
	})

	t.Run("та же живая строка, доставка её НЕ объявляла — отказ, и он её называет", func(t *testing.T) {
		src := &stubRowSource{rows: mergeRows(image, own)}
		census, err := seed.AssertCatalogParity(context.Background(), src, seed.ImageAnchor())
		if err == nil {
			t.Fatalf("живая строка %s.%s не объявлена ни образом, ни доставкой, "+
				"а страж пустил: отзыв модуля перестал бы доезжать — снятая доставкой "+
				"строка осталась бы жить, и сравнивать стало бы не с чем",
				deliveredModule, deliveredResource)
		}
		if !strings.Contains(err.Error(), deliveredModule+"."+deliveredResource) {
			t.Fatalf("отказ не называет лишнюю строку поимённо: %v (перепись: %v)",
				err, census.ExtraRows)
		}
	})

	t.Run("доставка объявила строку, а каталог её НЕ несёт — отказ", func(t *testing.T) {
		src := &stubRowSource{rows: image}
		census, err := seed.AssertCatalogParity(context.Background(), src, delivered)
		if err == nil {
			t.Fatalf("опора называет строку %s.%s, живой её нет и снятой нет, "+
				"а страж пустил: непроехавшее применение прошло бы молча",
				deliveredModule, deliveredResource)
		}
		if !strings.Contains(err.Error(), deliveredModule+"."+deliveredResource) {
			t.Fatalf("отказ не называет недостающую строку поимённо: %v (перепись: %v)",
				err, census.MissingRows)
		}
	})

	t.Run("строка доставки СНЯТА решением — страж молчит и называет снятое", func(t *testing.T) {
		src := &stubRowSource{rows: image, retired: own}
		census, err := seed.AssertCatalogParity(context.Background(), src, delivered)
		if err != nil {
			t.Fatalf("страж отказал на строке, СНЯТОЙ решением: %v. "+
				"Снятие и есть та операция, ради которой заведены retired_at/live", err)
		}
		if len(census.WithdrawnRows) != 3 {
			t.Fatalf("снятыми названо %d строк, ожидалось 3: %v",
				len(census.WithdrawnRows), census.WithdrawnRows)
		}
	})
}
