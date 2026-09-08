// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// opentypetable_test.go — таблица ТИПОВ ОБЪЕКТА разомкнута: оператор чужого
// облака объявляет свой РЕСУРС доставкой, а не пересборкой образа.
//
// # Предмет
//
// Соседняя полоса разомкнула набор МОДУЛЕЙ, и её проба это прямо оговаривала:
// «раздела `resources` здесь НЕТ… имя ТИПА ОБЪЕКТА судит закрытая таблица,
// порождённая сборкой, и её размыкание — отдельный предмет». Это он.
//
// До полосы продукт принимал модуль и отвергал то, ради чего модуль объявляют:
// манифест `acme` с `resources[0].objectType: acme_widget` отвергался словами
// «типа "acme_widget" нет в закрытой таблице типов iam».
//
// # Чем судится тип ТЕПЕРЬ, и почему отказ не исчез
//
//	форма имени     грамматика типа, ОДНА на дерево (`domain.IsWellFormedObjectTypeName`),
//	                та же, что держит колонка каталога `catalog_resource_object_type_form`
//	владение        тип, который ОБРАЗ уже несёт, доставка не вправе присвоить
//	                другой строке: монотонность взята у близнеца — допуска
//	                собранной модели прав
//	столкновение    один тип, объявленный двумя ресурсами (одного документа либо
//	                одного обхода), — находка, называющая ОБА места
//
// # Отрицания стоят В ПАРЕ с положительным, и близнец отличается ОДНИМ фактом
//
// Без пары «отказ есть» неотличимо от «загрузчик отвергает всё», а близнец,
// отличающийся двумя фактами, не говорит, который из них дал красное.
//
// # Чему этот файл СЛУЖИТ ДЕРЖАТЕЛЕМ
//
// Сценарий `IAM-MB-1-05` приёмки композиции
// (`docs/engineering/acceptance/model-composes-at-boot-from-delivered-manifests.md`)
// требует, чтобы манифест, задевающий ЧЕТЫРЕ судьи ступеней 1–4 разом, читался
// без единой находки. Ступени 1 и 4 — имя модуля и модуль правила роли — закрыты
// соседней полосой (`openmoduleset_test.go`); ступени 2 и 3 — тип объекта и тип
// указателя — закрыты здесь, вместе с четырьмя положительными контролями,
// отрицанием формы и переписью, называющей, охранялось ли владение.

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// acmeWidgetType — тип, которого порождённая сборкой таблица не несёт.
const acmeWidgetType = "acme_widget"

// acmeResourceManifest — манифест оператора: свой модуль И свой ресурс.
const acmeResourceManifest = `apiVersion: iam/v1
module: acme
resources:
  - name: widget
    objectType: acme_widget
    parents: [project]
    producer: derived
    verbs: [get, list, create, update, delete]
`

// acmeOwnParentManifest — тот же модуль, где ВТОРОЙ ресурс подвешен под ПЕРВЫЙ:
// оператор вправе подвесить свой тип под свой же.
const acmeOwnParentManifest = `apiVersion: iam/v1
module: acme
resources:
  - name: widget
    objectType: acme_widget
    parents: [project]
    producer: derived
    verbs: [get, list, create, update, delete]
  - name: widgetPart
    objectType: acme_widget_part
    parents:
      - {name: parent, type: acme_widget}
    producer: derived
    verbs: [get, list]
`

// refuteOpenTypeVacuity — `acme_widget` обязан ОТСУТСТВОВАТЬ в порождённой
// сборкой таблице, иначе всё ниже утверждает о её ЧЛЕНЕ и не проверяет ничего.
func refuteOpenTypeVacuity(t *testing.T) {
	t.Helper()
	catalog := authzmap.CatalogKeys()
	if len(catalog) == 0 {
		t.Fatal("порождённая таблица пуста — сверка беспредметна: «принят» здесь " +
			"неотличимо от «таблица ничего не знает»")
	}
	for _, typ := range []string{acmeWidgetType, "acme_widget_part"} {
		if _, known := authzmap.DottedType(typ); known {
			t.Fatalf("тип %q состоит в порождённой таблице — проба утверждала бы о ЧЛЕНЕ "+
				"набора и была бы зелёной при закрытой таблице", typ)
		}
	}
	if _, known := authzmap.DottedType("vpc_network"); !known {
		t.Fatal("`vpc_network` выбыл из порождённой таблицы — законного близнеца " +
			"и предмета монотонности построить не из чего")
	}
	t.Logf("перепись: в порождённой сборкой таблице пар %d; `acme_widget` и "+
		"`acme_widget_part` вне её, `vpc_network` в ней", len(catalog))
}

// TestLoadAdmitsAResourceTypeTheShippedTableDoesNotKnow — тип оператора
// принимается загрузчиком.
func TestLoadAdmitsAResourceTypeTheShippedTableDoesNotKnow(t *testing.T) {
	refuteOpenTypeVacuity(t)

	m, err := manifest.Load([]byte(acmeResourceManifest))
	if err != nil {
		t.Fatalf("ресурс оператора отвергнут: %v", err)
	}
	if len(m.Resources) != 1 || m.Resources[0].ObjectType != acmeWidgetType {
		t.Fatalf("тип не доехал до разобранного документа: %+v", m.Resources)
	}
}

// TestLoadAdmitsAParentThatIsATypeOfTheSameManifest — родитель типа может быть
// типом ТОГО ЖЕ манифеста: оператор вправе подвесить свой тип под свой же.
func TestLoadAdmitsAParentThatIsATypeOfTheSameManifest(t *testing.T) {
	refuteOpenTypeVacuity(t)

	if _, err := manifest.Load([]byte(acmeOwnParentManifest)); err != nil {
		t.Fatalf("указатель на тип того же манифеста отвергнут: %v", err)
	}
}

// TestDeliveryAdmitsAnOperatorResourceType — то же на ДОСТАВКЕ: это та полоса,
// которой пользуется оператор чужого облака.
func TestDeliveryAdmitsAnOperatorResourceType(t *testing.T) {
	refuteOpenTypeVacuity(t)

	root := deliveryDir(t, map[string]string{
		"vpc/manifest.yaml":  compactManifest,
		"acme/manifest.yaml": acmeOwnParentManifest,
	})
	report, err := manifest.LoadDelivered(root)
	if err != nil {
		t.Fatalf("доставка с ресурсом оператора отвергнута: %v", err)
	}
	if report.ManifestsRead != 2 {
		t.Fatalf("манифестов прочитано %d, ожидалось 2 (осмотрено файлов %d) — "+
			"«ноль находок» обязано быть отличимо от «ноль прочитанного»",
			report.ManifestsRead, report.PathsSeen)
	}
}

// TestTypeRedefiningAnImageDeclarationIsRefused — МОНОТОННОСТЬ: тип, который
// образ уже несёт, доставка не вправе присвоить другой строке.
//
// Отказ здесь не косметический. Строка каталога несёт имя типа модели прав, и
// отношение `v_<глагол>` адресуется именно им: присвоив чужой тип своей строке,
// оператор данными выдал бы права на объекты, которых его модуль не создавал.
func TestTypeRedefiningAnImageDeclarationIsRefused(t *testing.T) {
	refuteOpenTypeVacuity(t)

	const hijack = `apiVersion: iam/v1
module: acme
resources:
  - name: widget
    objectType: vpc_network
    parents: [project]
    producer: derived
    verbs: [get]
`
	_, err := manifest.Load([]byte(hijack))
	if err == nil {
		t.Fatal("чужой тип образа присвоен строкой оператора и это прошло — правами, " +
			"выданными на такую строку, оператор адресовал бы объекты чужого модуля")
	}
	if !errors.Is(err, manifest.ErrObjectTypeRedefinesImage) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	// Отказ обязан назвать ОБЕ стороны: чем строка образа адресуется и чем —
	// строка доставки. Одна сторона не говорит, что чинить.
	for _, want := range []string{"vpc_network", "vpc.network", "acme.widget"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}

	// Законный близнец, отличающийся ОДНИМ фактом: тот же тип объявляет ТА ЖЕ
	// строка, что и в образе.
	const own = `apiVersion: iam/v1
module: vpc
resources:
  - name: network
    objectType: vpc_network
    parents: [project]
    producer: derived
    verbs: [get]
`
	if _, err := manifest.Load([]byte(own)); err != nil {
		t.Fatalf("законный близнец отвергнут — образ повторён дословно: %v", err)
	}
}

// TestMalformedObjectTypeNameIsRefused — ФОРМА имени судится всегда, и той же
// грамматикой, что держит колонка каталога.
func TestMalformedObjectTypeNameIsRefused(t *testing.T) {
	base := `apiVersion: iam/v1
module: acme
resources:
  - name: widget
    objectType: %s
    parents: [project]
    producer: derived
    verbs: [get]
`
	for _, bad := range []string{`"Acme Widget"`, `AcmeWidget`, `acme-widget`, `"9widget"`, `"acme.widget"`} {
		doc := strings.Replace(base, "%s", bad, 1)
		_, err := manifest.Load([]byte(doc))
		if err == nil {
			t.Errorf("негодное по форме имя %s принято", bad)
			continue
		}
		if !errors.Is(err, manifest.ErrObjectTypeMalformed) {
			t.Errorf("имя %s: отказ не отнесён к своей причине: %v", bad, err)
		}
	}
	// Парный положительный: годная форма нового типа проходит.
	if _, err := manifest.Load([]byte(strings.Replace(base, "%s", "acme_widget", 1))); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
}

// TestMalformedParentTypeIsRefused — та же грамматика судит и тип УКАЗАТЕЛЯ:
// иначе размыкание таблицы открыло бы вторую дверь мимо первой.
func TestMalformedParentTypeIsRefused(t *testing.T) {
	base := `apiVersion: iam/v1
module: acme
resources:
  - name: widget
    objectType: acme_widget
    parents: [project]
    producer: derived
    verbs: [get]
  - name: part
    objectType: acme_widget_part
    parents:
      - {name: parent, type: %s}
    producer: derived
    verbs: [get]
`
	_, err := manifest.Load([]byte(strings.Replace(base, "%s", `"Acme Widget"`, 1)))
	if err == nil {
		t.Fatal("негодный по форме тип указателя принят")
	}
	if !errors.Is(err, manifest.ErrParentUnknown) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}

	// Близнец первый: указатель на тип ТОГО ЖЕ манифеста — проходит.
	if _, err := manifest.Load([]byte(strings.Replace(base, "%s", "acme_widget", 1))); err != nil {
		t.Fatalf("указатель на тип того же манифеста отвергнут: %v", err)
	}
	// Близнец второй: годная форма, но тип не объявлен НИКЕМ — отказ остаётся.
	_, err = manifest.Load([]byte(strings.Replace(base, "%s", "acme_nobody", 1)))
	if !errors.Is(err, manifest.ErrParentUnknown) {
		t.Errorf("указатель на неизвестный никому тип принят — отношение объявили бы "+
			"по адресу, которого нет: %v", err)
	}
}

// TestTwoResourcesOfOneManifestSharingATypeAreRefused — СТОЛКНОВЕНИЕ внутри
// документа: отказ называет ОБА места.
func TestTwoResourcesOfOneManifestSharingATypeAreRefused(t *testing.T) {
	const collide = `apiVersion: iam/v1
module: acme
resources:
  - name: widget
    objectType: acme_widget
    parents: [project]
    producer: derived
    verbs: [get]
  - name: gadget
    objectType: acme_widget
    parents: [project]
    producer: derived
    verbs: [get]
`
	_, err := manifest.Load([]byte(collide))
	if err == nil {
		t.Fatal("два ресурса под одним типом приняты — права, выданные на один, " +
			"материализовались бы на объектах другого")
	}
	if !errors.Is(err, manifest.ErrObjectTypeCollision) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	for _, want := range []string{"resources[0]", "resources[1]", acmeWidgetType} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}

	// Законный близнец, отличающийся ОДНИМ фактом: тот же документ, но типы
	// разные.
	const distinct = `apiVersion: iam/v1
module: acme
resources:
  - name: widget
    objectType: acme_widget
    parents: [project]
    producer: derived
    verbs: [get]
  - name: gadget
    objectType: acme_gadget
    parents: [project]
    producer: derived
    verbs: [get]
`
	if _, err := manifest.Load([]byte(distinct)); err != nil {
		t.Fatalf("законный близнец отвергнут — типы разные: %v", err)
	}
}

// TestTwoManifestsOfOneDeliverySharingATypeAreRefused — СТОЛКНОВЕНИЕ через
// обход: два манифеста доставки под одним типом.
//
// Одного документа для этого вопроса мало by construction, поэтому судит его
// обход, а не [manifest.Load].
func TestTwoManifestsOfOneDeliverySharingATypeAreRefused(t *testing.T) {
	refuteOpenTypeVacuity(t)

	const beta = `apiVersion: iam/v1
module: beta
resources:
  - name: thing
    objectType: acme_widget
    parents: [project]
    producer: derived
    verbs: [get]
`
	root := deliveryDir(t, map[string]string{
		"acme/manifest.yaml": acmeResourceManifest,
		"beta/manifest.yaml": beta,
	})
	_, err := manifest.LoadDelivered(root)
	if err == nil {
		t.Fatal("два манифеста доставки под одним типом приняты — чья строка каталога " +
			"доедет до применителя, решал бы порядок обхода")
	}
	// Отказ обхода приходит СТРОКОЙ находки, а не обёрнутой ошибкой (перечень
	// находок у обхода один на все документы), поэтому причина сверяется её
	// текстом — тем же, что у столкновения имён модулей.
	for _, want := range []string{
		manifest.ErrObjectTypeCollision.Error(),
		acmeWidgetType, "acme/manifest.yaml", "beta/manifest.yaml",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}

	// Законный близнец: те же два манифеста под РАЗНЫМИ типами.
	okRoot := deliveryDir(t, map[string]string{
		"acme/manifest.yaml": acmeResourceManifest,
		"beta/manifest.yaml": strings.Replace(beta, "acme_widget", "beta_thing", 1),
	})
	if _, err := manifest.LoadDelivered(okRoot); err != nil {
		t.Fatalf("законный близнец отвергнут — типы разные: %v", err)
	}
}

// TestDeliveryCensusSaysWhetherOwnershipWasGuarded — перепись обхода называет,
// ЧЕМ была таблица типов.
//
// Требование стоит в приёмке композиции (`IAM-MB-1-05`) и держится здесь:
// «находок ноль» и «владение не охранялось» суть разные утверждения о доставке,
// и различить их оператору нечем, если перепись об этом молчит.
//
// Утверждается РАЗЛИЧИЕ двух текстов, а не их содержимое: закрепи проба слова
// дословно — она бы краснела на всякой правке формулировки, ничего не говоря о
// свойстве. А совпади два текста, перепись перестала бы различать полосы, оставаясь
// на вид полноценной.
func TestDeliveryCensusSaysWhetherOwnershipWasGuarded(t *testing.T) {
	root := deliveryDir(t, map[string]string{"acme/manifest.yaml": acmeResourceManifest})

	guarded := manifest.CheckDelivery(root).Summary()
	generating := manifest.CheckSyntheticTreeForGeneration(root).Summary()

	if guarded == generating {
		t.Fatalf("перепись обеих полос совпала дословно — она не различает, "+
			"охранялось ли владение:\n%s", guarded)
	}
	for name, got := range map[string]string{"доставка": guarded, "порождение": generating} {
		if !strings.Contains(got, "таблица типов:") {
			t.Errorf("перепись полосы %s не называет таблицу типов вовсе: %s", name, got)
		}
		if !strings.Contains(got, "манифестов прочитано") {
			t.Errorf("перепись полосы %s потеряла объём осмотренного: %s", name, got)
		}
	}
	t.Logf("перепись доставки:   %s", guarded)
	t.Logf("перепись порождения: %s", generating)
}
