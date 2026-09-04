// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package modulecatalog_test

// prune_test.go — снятие строки каталога приводит ТРЕТЬЮ проекцию правила к
// каталожному факту (задача продукта #1942).
//
// # Предмет
//
// Проекций у правила три. У двух референт держится КЛЮЧОМ, поэтому снятие их
// роняет — и применитель обязан переселить их тем же оператором. У третьей —
// массива точечных типов в строке селекторов — ключа нет и быть не может:
// внешний ключ на элемент массива в Postgres невыразим. Её референт держит
// триггер НА ВХОДЕ; снятие строки каталога он не судит, и селектор оставался
// называть снятый тип МОЛЧА.
//
// # Что здесь утверждается
//
// Применитель, снявший строку ресурса, тем же оператором вырезает её из
// `object_types` селекторов АРЕНДАТОРСКИХ ролей и отдаёт ТРИ величины: строк
// укорочено, строк снято целиком, элементов вырезано. Одной не хватает: «тронута
// одна строка» не говорит, вырезан из неё один элемент или пять; «вырезано пять»
// не говорит, у одной роли или у пяти; а строка, оставшаяся без единого живого
// типа, снимается целиком — пустой массив запрещён ограничением схемы, — и это
// событие иного рода, чем укорочение.
//
// О базе эти пробы не говорят ничего — писатель подставной. Порядок относительно
// снятия, атомарность и поведение триггера доказаны против живой Postgres
// (`selector_loses_its_referent_integration_test.go`).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/modulecatalog"
	"github.com/PRO-Robotech/kacho/services/iam/internal/catalog"
)

// pruningWriter — писатель, ведущий журнал вызовов и отдающий перепись
// вырезанного.
type pruningWriter struct {
	recordingWriter
	live   catalog.Rows
	pruned modulecatalog.Pruned
	// prunedFor — ресурсы, с которыми звали вырезание. Журнал, а не счётчик:
	// предмет пробы в том, ЧТО вырезалось, и счётчик об этом молчит.
	prunedFor []string
	// appliedBy — автор, с которым звали вырезание (#2005).
	appliedBy string
}

func (w *pruningWriter) ReadModule(_ context.Context, module string) (catalog.Rows, error) {
	w.calls = append(w.calls, "read:"+module)
	return w.live, nil
}

func (w *pruningWriter) PruneRetiredSelectorTypes(_ context.Context,
	resources []catalog.ResourceRow, appliedBy string) (modulecatalog.Pruned, error) {
	w.calls = append(w.calls, "prune")
	w.appliedBy = appliedBy
	for _, r := range resources {
		w.prunedFor = append(w.prunedFor, r.Module+"."+r.Resource)
	}
	return w.pruned, nil
}

type pruningTx struct{ w *pruningWriter }

func (r *pruningTx) RunInWriteTx(ctx context.Context,
	fn func(context.Context, modulecatalog.CatalogWriter) error) error {
	return fn(ctx, r.w)
}

func liveTwo() catalog.Rows {
	return catalog.Rows{
		Modules: []string{"vpc"},
		Resources: []catalog.ResourceRow{
			{Module: "vpc", Resource: "network", ObjectType: "vpc_network"},
			{Module: "vpc", Resource: "gone", ObjectType: "vpc_gone"},
		},
		Verbs: []catalog.VerbRow{
			{Module: "vpc", Resource: "network", Verb: "get"},
			{Module: "vpc", Resource: "gone", Verb: "get"},
		},
	}
}

// TestRetiringAResourcePrunesTheThirdProjection — снятие вырезает тип из
// селекторов, и перепись несёт ОБЕ величины.
func TestRetiringAResourcePrunesTheThirdProjection(t *testing.T) {
	w := &pruningWriter{live: liveTwo(),
		pruned: modulecatalog.Pruned{Rows: 2, Dropped: 1, Elements: 3}}
	applier := modulecatalog.NewApplier(&pruningTx{w: w})

	rep, err := applier.Apply(context.Background(), fixtureManifest("vpc", "network"))
	require.NoError(t, err)
	require.Positivef(t, rep.RetiredResources, "вход не произведён: снятия нет (%s)", rep)

	require.Equal(t, []string{"vpc.gone"}, w.prunedFor,
		"вырезание звали не с теми ресурсами: предмет — РОВНО те строки, что сняты")
	require.Equal(t, 2, rep.PrunedSelectorRows)
	require.Equal(t, 1, rep.PrunedSelectorRowsDropped,
		"строка, оставшаяся без единого живого типа, снимается целиком — пустой массив "+
			"запрещён ограничением схемы, и событие это иного рода, чем укорочение")
	require.Equal(t, 3, rep.PrunedSelectorTypes,
		"третья величина обязательна: «тронута строка» не говорит, вырезан из неё "+
			"один элемент или пять")
	require.True(t, rep.Changed(), "вырезание есть изменение состояния: %s", rep)
}

// TestPruneRunsAfterTheRowIsRetired — ПОРЯДОК, и он несущий.
//
// Вырезание оставляет в массиве только элементы, называющие ЖИВУЮ строку
// каталога. Поставь его ПЕРЕД снятием — и снимаемая строка ещё жива, то есть
// уцелеет ровно та, ради которой вырезание и делается. Порядок утверждается
// ЖУРНАЛОМ: число вызовов о нём не говорит ничего.
func TestPruneRunsAfterTheRowIsRetired(t *testing.T) {
	w := &pruningWriter{live: liveTwo()}
	applier := modulecatalog.NewApplier(&pruningTx{w: w})

	_, err := applier.Apply(context.Background(), fixtureManifest("vpc", "network"))
	require.NoError(t, err)

	var retiredAt, prunedAt = -1, -1
	for i, c := range w.calls {
		switch c {
		case "retire_resource:vpc.gone":
			retiredAt = i
		case "prune":
			prunedAt = i
		}
	}
	require.NotEqual(t, -1, retiredAt, "снятие ресурса не звалось: %v", w.calls)
	require.NotEqual(t, -1, prunedAt, "вырезание не звалось: %v", w.calls)
	require.Greaterf(t, prunedAt, retiredAt,
		"вырезание стоит ПЕРЕД снятием: снимаемая строка ещё жива, и уцелеет ровно "+
			"тот элемент, ради которого вырезание и делается. Журнал: %v", w.calls)
}

// TestNothingRetiredNothingPruned — ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него «вырезание позвано» было бы неотличимо от применителя, зовущего его
// на КАЖДОМ применении, — то есть от правки, трогающей селекторы всех
// арендаторов при каждом подъёме службы.
func TestNothingRetiredNothingPruned(t *testing.T) {
	w := &pruningWriter{live: catalog.Rows{Modules: []string{"vpc"}}}
	applier := modulecatalog.NewApplier(&pruningTx{w: w})

	rep, err := applier.Apply(context.Background(), fixtureManifest("vpc", "network"))
	require.NoError(t, err)
	require.Zero(t, rep.RetiredResources, "предпосылка нарушена: снятие произошло")
	require.NotContains(t, w.calls, "prune",
		"вырезание позвано без снятия — применитель трогает селекторы арендаторов "+
			"на каждом подъёме: %v", w.calls)
	require.Zero(t, rep.PrunedSelectorRows)
	require.Zero(t, rep.PrunedSelectorRowsDropped)
	require.Zero(t, rep.PrunedSelectorTypes)
}
