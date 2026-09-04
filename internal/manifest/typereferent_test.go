// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package manifest_test

// typereferent_test.go — существование типа объекта судит РЕФЕРЕНТ, названный
// вызывающим (задача продукта #1930).
//
// # Что здесь утверждается — обе стороны, и вторая несущая
//
//	новый тип, референт «закрытая таблица»  → ОТКАЗ  (потребление: таблица уже произведена)
//	новый тип, референт «канон»             → ПРОХОД (порождение: таблица есть продукт прохода)
//	пустой тип, любой референт              → ОТКАЗ  (форма судится всегда)
//	известный тип, любой референт           → ПРОХОД (законный близнец)
//
// Без второй строки круг остаётся замкнутым: новый тип не проходит ни одной из
// двух дверей — загрузчик отвергает его, потому что таблица о нём не знает, а
// таблица не узнаёт, потому что перегенерация начинается с загрузки.
//
// Без четвёртой отрицание зеленело бы на загрузчике, отвергающем ВСЯКИЙ тип.

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// typeReferentFixture — минимально-полный манифест модуля с ОДНИМ ресурсом;
// тип объекта подставляется.
const typeReferentFixture = `apiVersion: iam/v1
module: vpc
resources:
  - name: probe
    objectType: %s
    parents: [project]
    producer: derived
    verbs:
      - get
`

func manifestWithObjectType(objectType string) []byte {
	return []byte(strings.Replace(typeReferentFixture, "%s", objectType, 1))
}

// TestObjectTypeOutsideTheShippedTableIsRefusedWhenTheTableJudges — полоса
// ПОТРЕБЛЕНИЯ: доставленный манифест, назвавший тип вне таблицы, не работает
// никак, и отказ обязан прийти.
func TestObjectTypeOutsideTheShippedTableIsRefusedWhenTheTableJudges(t *testing.T) {
	const fresh = "vpc_probe_resource"
	if _, ok := authzmap.DottedType(fresh); ok {
		t.Fatalf("тип %q завели в закрытую таблицу — проба потеряла предмет: она утверждает "+
			"про тип, которого таблица НЕ знает", fresh)
	}

	_, err := manifest.LoadWithReferent(manifestWithObjectType(fresh), manifest.ReferentShippedTable)
	if err == nil {
		t.Fatal("тип вне закрытой таблицы принят полосой потребления — селектор роли адресовал " +
			"бы несуществующий тип и не дал бы ни одного пообъектного права, молча")
	}
	if !errors.Is(err, manifest.ErrObjectTypeUnknown) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}

	// Умолчание — потребление: забытый референт обязан давать СТРОГИЙ разбор.
	if _, derr := manifest.Load(manifestWithObjectType(fresh)); !errors.Is(derr, manifest.ErrObjectTypeUnknown) {
		t.Errorf("умолчание оказалось мягким — забытый референт открывал бы полосу молча: %v", derr)
	}
}

// TestObjectTypeOutsideTheShippedTablePassesWhenTheCanonJudges — НЕСУЩАЯ
// половина: в проходе, ПОРОЖДАЮЩЕМ таблицу, загрузчик о существовании не
// спрашивает.
//
// Это и есть разрыв круга: до него новый тип не проходил ни одной из двух
// дверей, и `authzmapgen.Collect` отказывал, а продукт не обновлялся вовсе.
func TestObjectTypeOutsideTheShippedTablePassesWhenTheCanonJudges(t *testing.T) {
	const fresh = "vpc_probe_resource"
	m, err := manifest.LoadWithReferent(manifestWithObjectType(fresh), manifest.ReferentCanon)
	if err != nil {
		t.Fatalf("новый тип отвергнут в ПОРОЖДАЮЩЕМ проходе — круг «производитель спрашивает "+
			"у своего продукта» не разорван: %v", err)
	}
	if len(m.Resources) != 1 || m.Resources[0].ObjectType != fresh {
		t.Fatalf("тип не доехал до разобранного документа: %+v", m.Resources)
	}
}

// TestObjectTypeFormIsJudgedByEveryReferent — форма судится ВСЕГДА.
//
// Смена референта снимает вопрос о СУЩЕСТВОВАНИИ, а не о форме: тип, не
// названный вовсе, негоден в обоих проходах, и пропустить его значило бы
// сменить предмет проверки под видом смены её референта.
func TestObjectTypeFormIsJudgedByEveryReferent(t *testing.T) {
	for _, referent := range []manifest.TypeReferent{
		manifest.ReferentShippedTable, manifest.ReferentCanon,
	} {
		_, err := manifest.LoadWithReferent(manifestWithObjectType(`""`), referent)
		if !errors.Is(err, manifest.ErrObjectTypeRequired) {
			t.Errorf("референт %v: пустой тип принят — форма перестала судиться: %v", referent, err)
		}
	}
}

// TestKnownObjectTypePassesUnderEveryReferent — законный близнец обеих полос.
//
// Без него отрицания выше зеленели бы на загрузчике, отвергающем ВСЯКИЙ тип.
func TestKnownObjectTypePassesUnderEveryReferent(t *testing.T) {
	const known = "vpc_network"
	if _, ok := authzmap.DottedType(known); !ok {
		t.Fatalf("тип %q выбыл из закрытой таблицы — законного близнеца построить не из чего", known)
	}
	for _, referent := range []manifest.TypeReferent{
		manifest.ReferentShippedTable, manifest.ReferentCanon,
	} {
		if _, err := manifest.LoadWithReferent(manifestWithObjectType(known), referent); err != nil {
			t.Errorf("референт %v отверг ИЗВЕСТНЫЙ тип: %v", referent, err)
		}
	}
}
