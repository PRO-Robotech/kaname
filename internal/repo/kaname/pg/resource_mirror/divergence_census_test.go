// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resource_mirror_test

// divergence_census_test.go — ПЕРЕПИСЬ РАЗНОСТИ ПЕЧАТАЕТ ОБА ЧИСЛА (kacho#1828).
//
// # Предмет
//
// Читатель разности в дереве есть, а на поднятом стенде его не спрашивает
// НИКТО: величина, от которой зависит решение владельца об отзыве, не
// производится ни на одном подъёме. Механизм без вызывающего не работает, и
// отличить его от отсутствующего нельзя ничем.
//
// Вызывающий заводится в композиционном корне, и печатать он обязан ПЕРЕПИСЬ, а
// не находки: «разности нет» и «зеркало пусто» дают одинаковое число находок —
// ноль — и совершенно разные утверждения о стенде.
//
// # Почему проба чистая, а не интеграционная
//
// Предмет здесь — ТЕКСТ переписи, а не запрос. Соседний интеграционный прогон
// уже держит чтение против настоящей схемы; повторять его значило бы завести
// второе место об одном предмете и заплатить контейнером за утверждение о
// форматировании.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
)

// TestDivergenceCensusNamesBothNumbers — несущее: перепись называет и
// осмотренное, и найденное.
func TestDivergenceCensusNamesBothNumbers(t *testing.T) {
	rows := []resource_mirror.DivergenceRow{
		{ObjectType: "compute.disk", Rows: 3, State: resource_mirror.CatalogRetiredSucceeded,
			SupersededBy: "storage.volumes"},
		{ObjectType: "legacy.thing", Rows: 7, State: resource_mirror.CatalogAbsent},
	}

	got := resource_mirror.DivergenceCensus(rows, 9)

	for _, want := range []string{"9", "2", "1"} {
		if !strings.Contains(got, want) {
			t.Fatalf("перепись %q не называет числа %q", got, want)
		}
	}
	if !strings.Contains(got, "legacy.thing") {
		t.Fatalf("перепись %q не называет неразрешимую строку по имени", got)
	}
	if !strings.Contains(got, "storage.volumes") {
		t.Fatalf("перепись %q не называет преемника, хотя каталог его назвал", got)
	}
}

// TestDivergenceCensusDistinguishesCleanFromEmpty — «разности нет» и «зеркало
// пусто» обязаны читаться РАЗНЫМИ строками.
//
// Обе дают ноль находок, и без этого различения ноль «не спрашивали» уезжал бы
// в отчёт как ноль «спросили и чисто» — тот самый класс, ради которого перепись
// и печатается.
func TestDivergenceCensusDistinguishesCleanFromEmpty(t *testing.T) {
	clean := resource_mirror.DivergenceCensus(nil, 12)
	empty := resource_mirror.DivergenceCensus(nil, 0)

	if clean == empty {
		t.Fatalf("чистая разность и пустое зеркало читаются одной строкой: %q", clean)
	}
	if !strings.Contains(clean, "12") {
		t.Fatalf("чистая перепись %q не называет объёма осмотренного", clean)
	}
}

// TestDivergenceCensusCountsTheResolvableApart — снятое С ПРЕЕМНИКОМ считается
// отдельно от неразрешимого.
//
// Схлопнуть их значило бы объявить дефектом то, что дерево делает намеренно:
// переживание снятия — объявленное свойство, а не находка.
func TestDivergenceCensusCountsTheResolvableApart(t *testing.T) {
	rows := []resource_mirror.DivergenceRow{
		{ObjectType: "compute.disk", Rows: 3, State: resource_mirror.CatalogRetiredSucceeded,
			SupersededBy: "storage.volumes"},
	}

	got := resource_mirror.DivergenceCensus(rows, 4)

	if strings.Contains(got, "legacy") {
		t.Fatalf("перепись назвала строку, которой в разности нет: %q", got)
	}
	if !strings.Contains(got, "неразрешимых 0") {
		t.Fatalf("перепись %q не называет НУЛЬ неразрешимых — тогда «их нет» "+
			"неотличимо от «их не считали»", got)
	}
}
