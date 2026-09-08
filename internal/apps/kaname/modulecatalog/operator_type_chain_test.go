// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog_test

// operator_type_chain_test.go — СКВОЗНОЙ замок: манифест оператора со СВОИМ
// модулем и СВОИМ типом ресурса проходит всю последовательность старта, и
// СЛЕДУЮЩИЙ старт после применения тоже проходит (задача продукта #2015).
//
// # Почему проба здесь, а не у владельцев звеньев
//
// Замок не принадлежал ни одному звену по отдельности, и каждое звено было
// исправно:
//
//	загрузчик манифеста        отвергал тип вне порождённой сборкой таблицы (#2015 — снято)
//	композиция и допуск модели уже умели добавлять поддерево нового типа (#1969, #1971)
//	опора паритета каталога    уже складывалась «образ ∪ доставка» (#1861)
//	набор модулей              уже был разомкнут (#1927)
//
// То есть продукт ПРИНИМАЛ модуль оператора и ОТВЕРГАЛ то, ради чего модуль
// объявляют. Такой класс ловится только сквозным вызовом: половины по отдельности
// зелены (`multi-agent-flow.md` §14, столкновение смыслов).
//
// # Что здесь НЕ утверждается
//
// Запись строк в базу (`Applier`) — она требует живой Postgres и живёт в своих
// интеграционных пробах. Здесь утверждается всё, что от базы не зависит: разбор
// доставки, деривация строк, сборка опоры, перепись паритета и допуск собранной
// модели прав.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
)

// operatorManifest — манифест ЧУЖОГО облака: свой модуль, свой тип ресурса и
// СВОЙ ЖЕ тип в указателе второго ресурса.
//
// Все три вещи по отдельности были невыразимы до полос #1927 и #2015.
const operatorManifest = `apiVersion: iam/v1
module: tenantops
resources:
  - name: runbook
    objectType: tenantops_runbook
    parents: [project]
    producer: derived
    verbs:
      - get
      - list
      - create
      - update
      - delete
  - name: runbookStep
    objectType: tenantops_runbook_step
    parents:
      - {name: parent, type: tenantops_runbook}
    producer: derived
    verbs:
      - get
      - list
`

// refuteChainVacuity — образ НЕ несёт ни одного типа оператора и НЕ знает его
// модуля, иначе вся цепочка ниже утверждает о члене набора.
func refuteChainVacuity(t *testing.T) {
	t.Helper()
	image := seed.LiteralRows()
	require.NotEmpty(t, image.Resources, "образ пуст: цепочка беспредметна")
	for _, typ := range []string{"tenantops_runbook", "tenantops_runbook_step"} {
		_, shipped := authzmap.DottedType(typ)
		require.Falsef(t, shipped, "тип %q несёт образ — проба утверждала бы о ЧЛЕНЕ "+
			"порождённой таблицы и была бы зелёной при закрытой", typ)
	}
	require.NotContains(t, image.Modules, "tenantops",
		"модуль оператора несёт образ — предмет размыкания отсутствует")
	t.Logf("перепись образа: модулей %d, ресурсов %d, глаголов %d; "+
		"типов оператора среди них 0", len(image.Modules), len(image.Resources), len(image.Verbs))
}

// deliveryOf — каталог доставки с одним манифестом оператора.
func deliveryOf(t *testing.T, doc string) string {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "tenantops.yaml"), []byte(doc), 0o600))
	return root
}

// TestOperatorOwnResourceTypePassesTheWholeBootChain — вся последовательность:
// доставка → строки каталога → опора → перепись паритета → допуск модели.
func TestOperatorOwnResourceTypePassesTheWholeBootChain(t *testing.T) {
	refuteChainVacuity(t)

	// ── звено 1: ДОСТАВКА читается тем же путём, что и на старте ─────────────
	report, err := manifest.LoadDelivered(deliveryOf(t, operatorManifest))
	require.NoErrorf(t, err, "манифест оператора отвергнут доставкой — продукт принимает "+
		"модуль и отвергает то, ради чего модуль объявляют")
	require.Equalf(t, 1, report.ManifestsRead,
		"манифестов прочитано %d при осмотренных %d файлах — «ноль находок» обязано быть "+
			"отличимо от «ноль прочитанного»", report.ManifestsRead, report.PathsSeen)
	require.Len(t, report.Manifests, 1)

	// ── звено 2: СТРОКИ КАТАЛОГА выводятся из манифеста ──────────────────────
	declared, derr := modulecatalog.RowsOf(report.Manifests[0])
	require.NoError(t, derr, "строки каталога не выведены из манифеста оператора")
	byType := map[string]string{}
	for _, r := range declared.Resources {
		byType[r.ObjectType] = r.Module + "." + r.Resource
	}
	require.Equal(t, "tenantops.runbook", byType["tenantops_runbook"],
		"имя типа не доехало до строки каталога — читатель спрашивал бы его у словаря, "+
			"порождённого СБОРКОЙ, и получал бы «не найдено»")
	require.Equal(t, "tenantops.runbookStep", byType["tenantops_runbook_step"])

	// ── звено 3: ОПОРА «образ ∪ доставка» собирается без переопределения ─────
	deliveredRows := mergeRows(seed.LiteralRows(), catalog.Rows{
		Modules: []string{declared.Module}, Resources: declared.Resources, Verbs: declared.Verbs,
	})
	anchor, aerr := seed.NewAnchor(deliveredRows)
	require.NoError(t, aerr, "опора не собралась: доставка признана переопределяющей образ")
	require.NotEmpty(t, anchor.AddedRows(), "расширение опоры не названо поимённо — "+
		"«расхождений ноль» стало бы неотличимо от «доставка расширила опору молча»")

	// ── звено 4: СЛЕДУЮЩИЙ СТАРТ. Каталог после применения равен опоре ───────
	//
	// Это и есть предикат «применение не сделало пуск невозможным»: страж
	// паритета судит живые строки той же опорой, которой судил их применитель.
	state := catalogAfterApply{live: deliveredRows}
	census, cerr := seed.MeasureCatalogParity(context.Background(), state, anchor)
	require.NoError(t, cerr)
	require.NoErrorf(t, census.BootRefusal(),
		"страж отказал бы в пуске после применения манифеста оператора: недостающие %v, "+
			"лишние %v", census.MissingRows, census.ExtraRows)
	t.Logf("перепись паритета: опора — модулей %d, ресурсов %d, глаголов %d; "+
		"расширение доставкой %d строк(и)",
		census.AnchorModules, census.AnchorResources, census.AnchorVerbs, len(census.AnchorAdded))

	// ── звено 5: МОДЕЛЬ ПРАВ собирается и допускается ────────────────────────
	composed, rep, merr := modelcompose.Compose(authzmodel.DSL, report.Manifests)
	require.NoErrorf(t, merr, "модель прав не собралась вокруг типа оператора")
	require.Equal(t, 2, rep.ResourcesSeen, "композиция осмотрела не оба ресурса оператора")
	admission, aderr := authzmodel.Admit(composed)
	require.NoErrorf(t, aderr, "собранная модель не допущена: %s", admission.Census())
	require.Truef(t, admission.Admitted(), "модель отвергнута допуском: %s", admission.Census())
	for _, typ := range []string{"tenantops_runbook", "tenantops_runbook_step"} {
		require.Containsf(t, composed, "type "+typ+"\n",
			"тип %q объявлен ТОЛЬКО манифестом и до собранной модели не доехал", typ)
	}
	t.Logf("перепись допуска: %s", admission.Census())
}

// TestOperatorTypeTakenFromTheImageBreaksTheChainAtItsFirstLink — отрицание в
// паре: тот же манифест, отличающийся ОДНИМ фактом — тип взят у образа.
//
// Без него зелёная цепочка выше означала бы лишь «загрузчик принимает всё».
func TestOperatorTypeTakenFromTheImageBreaksTheChainAtItsFirstLink(t *testing.T) {
	refuteChainVacuity(t)

	const shipped = "vpc_network"
	dotted, known := authzmap.DottedType(shipped)
	require.Truef(t, known, "тип %q выбыл из образа — отрицание беспредметно", shipped)

	hijack := strings.Replace(operatorManifest, "tenantops_runbook\n", shipped+"\n", 1)
	_, err := manifest.LoadDelivered(deliveryOf(t, hijack))
	require.Errorf(t, err, "строка оператора присвоила тип образа %q и это прошло — "+
		"правило её роли выдало бы пообъектные права на объекты чужого модуля", shipped)
	require.Contains(t, err.Error(), manifest.ErrObjectTypeRedefinesImage.Error())
	require.Contains(t, err.Error(), dotted, "отказ не называет строку ОБРАЗА")
	require.Contains(t, err.Error(), "tenantops.runbook", "отказ не называет строку ДОСТАВКИ")
}

// catalogAfterApply — состояние каталога ПОСЛЕ применения манифеста оператора:
// живые строки равны опоре, снятых нет.
//
// Свой носитель, а не `modulecatalog.CatalogState`: страж старта спрашивает порт
// `seed.CatalogSource` (живое И снятое), и состояние применителя его не
// реализует — предметы у них разные, и сводить их одним типом значило бы
// объявить, что «что применитель видит» и «чем судит страж» суть одно.
type catalogAfterApply struct{ live catalog.Rows }

func (c catalogAfterApply) ReadLiveCatalog(context.Context) (catalog.Rows, error) {
	return c.live, nil
}

func (c catalogAfterApply) ReadRetiredCatalog(context.Context) (catalog.Rows, error) {
	return catalog.Rows{}, nil
}

// mergeRows — образ ПЛЮС доставка, тем же сложением, каким его делает опора.
func mergeRows(image, delivered catalog.Rows) catalog.Rows {
	return catalog.Rows{
		Modules:   append(append([]string{}, image.Modules...), delivered.Modules...),
		Resources: append(append([]catalog.ResourceRow{}, image.Resources...), delivered.Resources...),
		Verbs:     append(append([]catalog.VerbRow{}, image.Verbs...), delivered.Verbs...),
	}
}
