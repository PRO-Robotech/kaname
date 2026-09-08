// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// typereferent_test.go — что различает референт, названный вызывающим.
//
// # Предмет СМЕНИЛСЯ, и старые утверждения сняты вместе со своим (задача #2015)
//
// Файл заводился задачей #1930 и утверждал: «существование типа судит РЕФЕРЕНТ»
// — на полосе потребления таблица, в порождающем проходе канон. Первая половина
// снята целиком: существование типа не спрашивается больше ни у кого, потому что
// ресурс, объявивший тип, тем самым его и заводит (`objecttype.go`). Проба
// `TestObjectTypeOutsideTheShippedTableIsRefusedWhenTheTableJudges` утверждала
// ровно снятый предикат и потому удалена, а не ослаблена: оставь я её с
// подправленным ожиданием — она бы утверждала о механизме, которого нет.
//
// # Что референт различает ТЕПЕРЬ — ВЛАДЕНИЕ
//
//	тип образа у ЧУЖОЙ строки, референт «образ»       → ОТКАЗ  (доставка есть ДАННЫЕ оператора)
//	тип образа у ЧУЖОЙ строки, референт «порождение»  → ПРОХОД (образа ещё нет; перенос типа
//	                                                           между строками ДЕРЕВА законен)
//	новый тип, любой референт                         → ПРОХОД (это и есть размыкание)
//	пустой тип, любой референт                        → ОТКАЗ  (форма судится всегда)
//	негодная форма, любой референт                    → ОТКАЗ  (то же)
//	тип образа у СВОЕЙ строки, любой референт         → ПРОХОД (законный близнец)
//
// Без второй строки круг остаётся замкнутым с другой стороны: законный перенос
// типа с одной строки дерева на другую отвергался бы своей же будущей таблицей,
// и перегенерация не проходила бы.
//
// Без последней отрицания зеленели бы на загрузчике, отвергающем ВСЯКИЙ тип.

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// typeReferentFixture — минимально-полный манифест модуля с ОДНИМ ресурсом; имя
// ресурса и тип объекта подставляются.
const typeReferentFixture = `apiVersion: iam/v1
module: vpc
resources:
  - name: %[1]s
    objectType: %[2]s
    parents: [project]
    producer: derived
    verbs:
      - get
`

func manifestWithResourceType(resource, objectType string) []byte {
	return []byte(fmt.Sprintf(typeReferentFixture, resource, objectType))
}

// allReferents — оба вызывающих. Перечислены здесь один раз: выписанный у каждой
// пробы, он разошёлся бы с объявлением молча при заведении третьего.
var allReferents = []manifest.TypeReferent{
	manifest.ReferentShippedTable, manifest.ReferentCanon,
}

// TestImageTypeOnAForeignRowIsRefusedWhenTheImageIsGuarded — полоса ПОТРЕБЛЕНИЯ:
// тип, который несёт образ, доставка не вправе присвоить другой строке.
func TestImageTypeOnAForeignRowIsRefusedWhenTheImageIsGuarded(t *testing.T) {
	const known = "vpc_network"
	dotted, shipped := authzmap.DottedType(known)
	if !shipped {
		t.Fatalf("тип %q выбыл из порождённой таблицы — проба утверждала бы про тип, "+
			"которого образ НЕ несёт, и была бы зелёной при снятой охране", known)
	}
	if dotted == "vpc.probe" {
		t.Fatalf("образ адресует %q строкой vpc.probe — фикстура совпала с образом, "+
			"и присвоения в ней нет", known)
	}

	_, err := manifest.LoadWithReferent(manifestWithResourceType("probe", known),
		manifest.ReferentShippedTable)
	if err == nil {
		t.Fatal("чужой тип образа присвоен строкой доставки — правило её роли выдало бы " +
			"пообъектные права на объекты, которых этот модуль не создавал")
	}
	if !errors.Is(err, manifest.ErrObjectTypeRedefinesImage) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	// Отказ называет ОБЕ стороны: без второй автор не знает, у кого тип занят.
	for _, want := range []string{known, dotted, "vpc.probe"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}

	// Умолчание — потребление: забытый референт обязан охранять, а не открывать.
	if _, derr := manifest.Load(manifestWithResourceType("probe", known)); !errors.Is(
		derr, manifest.ErrObjectTypeRedefinesImage) {
		t.Errorf("умолчание оказалось мягким — забытый референт снимал бы охрану молча: %v", derr)
	}
}

// TestImageTypeOnAForeignRowPassesWhenTheTableIsBeingGenerated — НЕСУЩАЯ
// половина: в проходе, ПОРОЖДАЮЩЕМ таблицу, охранять нечего.
//
// Это и есть вторая сторона круга «производитель спрашивает у своего продукта»:
// перенос типа с одной строки дерева на другую — законная правка, ради которой
// перегенерация и запускается, — отвергался бы своей же будущей таблицей.
func TestImageTypeOnAForeignRowPassesWhenTheTableIsBeingGenerated(t *testing.T) {
	const known = "vpc_network"
	m, err := manifest.LoadWithReferent(manifestWithResourceType("probe", known),
		manifest.ReferentCanon)
	if err != nil {
		t.Fatalf("перенос типа отвергнут в ПОРОЖДАЮЩЕМ проходе: %v", err)
	}
	if len(m.Resources) != 1 || m.Resources[0].ObjectType != known {
		t.Fatalf("тип не доехал до разобранного документа: %+v", m.Resources)
	}
}

// TestFreshObjectTypePassesUnderEveryReferent — размыкание: тип, которого образ
// не несёт, принимается ОБЕИМИ полосами.
func TestFreshObjectTypePassesUnderEveryReferent(t *testing.T) {
	const fresh = "vpc_probe_resource"
	if _, shipped := authzmap.DottedType(fresh); shipped {
		t.Fatalf("тип %q завели в порождённую таблицу — проба потеряла предмет: она "+
			"утверждает про тип, которого образ НЕ несёт", fresh)
	}
	for _, referent := range allReferents {
		if _, err := manifest.LoadWithReferent(manifestWithResourceType("probe", fresh),
			referent); err != nil {
			t.Errorf("референт %v отверг НОВЫЙ тип — таблица не разомкнулась: %v", referent, err)
		}
	}
}

// TestObjectTypeFormIsJudgedByEveryReferent — форма судится ВСЕГДА.
//
// Смена референта снимает вопрос о ВЛАДЕНИИ, а не о форме: имя, не названное
// вовсе либо негодное, отвергнет колонка каталога ключом и допуск собранной
// модели, поэтому пропустить его здесь значило бы отдать отказ чужой полосе.
func TestObjectTypeFormIsJudgedByEveryReferent(t *testing.T) {
	for _, referent := range allReferents {
		_, err := manifest.LoadWithReferent(manifestWithResourceType("probe", `""`), referent)
		if !errors.Is(err, manifest.ErrObjectTypeRequired) {
			t.Errorf("референт %v: пустой тип принят — форма перестала судиться: %v", referent, err)
		}
		_, err = manifest.LoadWithReferent(manifestWithResourceType("probe", `"vpc probe"`), referent)
		if !errors.Is(err, manifest.ErrObjectTypeMalformed) {
			t.Errorf("референт %v: негодная форма принята: %v", referent, err)
		}
	}
}

// TestImageTypeOnItsOwnRowPassesUnderEveryReferent — законный близнец обеих полос.
//
// Без него отрицания выше зеленели бы на загрузчике, отвергающем ВСЯКИЙ тип
// образа.
func TestImageTypeOnItsOwnRowPassesUnderEveryReferent(t *testing.T) {
	const known = "vpc_network"
	dotted, shipped := authzmap.DottedType(known)
	if !shipped {
		t.Fatalf("тип %q выбыл из порождённой таблицы — законного близнеца построить не из чего", known)
	}
	// Имя строки берётся У ОБРАЗА, а не выписывается: выписанное разошлось бы с
	// таблицей молча при первом же переименовании ресурса.
	_, resource, ok := authzmap.SplitObjectType(dotted)
	if !ok {
		t.Fatalf("точечный ключ %q не разбирается — близнеца не собрать", dotted)
	}
	for _, referent := range allReferents {
		if _, err := manifest.LoadWithReferent(manifestWithResourceType(resource, known),
			referent); err != nil {
			t.Errorf("референт %v отверг тип образа у ЕГО ЖЕ строки (%s): %v", referent, dotted, err)
		}
	}
}
