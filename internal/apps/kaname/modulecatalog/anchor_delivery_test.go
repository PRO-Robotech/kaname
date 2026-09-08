// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog_test

// anchor_delivery_test.go — ВТОРОЙ потребитель опоры: вердикт полосы ГЛАГОЛА
// (задача продукта #1861).
//
// # Зачем отдельно от стража
//
// Страж и вердикт опоры спрашивают у одной переписи РАЗНОЕ («поднимать ли
// службу» против «вывело ли применение каталог за опору»), но опора у них обязана
// быть ОДНА. Оставь глаголу образ — и `iamctl module apply` отвергал бы ровно тот
// модуль, который старт этого же процесса принимает: два ответа об одном
// предмете, расходящиеся молча.
//
// # Каждое утверждение — в паре
//
// Ни одна строка ниже не говорит «опора расширилась» без соседней, говорящей
// «при неизменённой опоре тот же вход отвергнут». Односторонний набор зеленел бы
// на вердикте, который перестал смотреть вовсе.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
)

// Строка, которой образ не несёт. Имена заведомо вне словаря платформы: совпади
// они с живым модулем — набор проверял бы оживление снятой строки.
const (
	deliveredOnlyModule   = "tenantops"
	deliveredOnlyResource = "runbook"
	deliveredOnlyType     = "tenantops_runbook"
)

func deliveredOnlyRows() catalog.Rows {
	return catalog.Rows{
		Modules: []string{deliveredOnlyModule},
		Resources: []catalog.ResourceRow{{
			Module: deliveredOnlyModule, Resource: deliveredOnlyResource,
			ObjectType: deliveredOnlyType,
		}},
		Verbs: []catalog.VerbRow{{
			Module: deliveredOnlyModule, Resource: deliveredOnlyResource,
			Verb: "get", PerObject: true,
		}},
	}
}

func withDeliveredOnly(base catalog.Rows) catalog.Rows {
	own := deliveredOnlyRows()
	return catalog.Rows{
		Modules:   append(append([]string{}, base.Modules...), own.Modules...),
		Resources: append(append([]catalog.ResourceRow{}, base.Resources...), own.Resources...),
		Verbs:     append(append([]catalog.VerbRow{}, base.Verbs...), own.Verbs...),
	}
}

// TestAnchorVerdictJudgesAgainstTheDeliveredAnchor — вердикт полосы глагола над
// той же опорой, что судит старт.
func TestAnchorVerdictJudgesAgainstTheDeliveredAnchor(t *testing.T) {
	image := seed.LiteralRows()
	// ПРЕДПОСЫЛКА: образ непуст, иначе «расширение опоры» неотличимо от опоры
	// целиком, а всякий вердикт ниже тривиален.
	require.NotEmpty(t, image.Resources, "образ пуст: набор беспредметен")
	t.Logf("перепись образа: модулей %d, ресурсов %d, глаголов %d",
		len(image.Modules), len(image.Resources), len(image.Verbs))

	// Живое состояние: образ ПЛЮС строка, объявленная только доставкой, — то,
	// что оставит после себя применение манифеста оператора.
	state := modulecatalog.NewCatalogState(withDeliveredOnly(image), catalog.Rows{})

	delivered, err := seed.NewAnchor(withDeliveredOnly(image))
	require.NoError(t, err, "опора «образ ∪ доставка» не собралась")

	t.Run("опора несёт доставку — применение объявлено проходимым", func(t *testing.T) {
		plan, perr := modulecatalog.AnchorVerdictOf(context.Background(), state, delivered)
		require.NoError(t, perr)
		require.Equalf(t, modulecatalog.VerdictWouldApply, plan.Verdict,
			"глагол отверг строку, ОБЪЯВЛЕННУЮ доставкой: лишние %v, недостающие %v — "+
				"iamctl отказывал бы ровно на том модуле, который старт этого же "+
				"процесса принимает", plan.BeyondAnchorExtra, plan.BeyondAnchorMissing)
	})

	t.Run("та же строка при опоре ОДНОГО ОБРАЗА — вердикт отказа", func(t *testing.T) {
		plan, perr := modulecatalog.AnchorVerdictOf(context.Background(), state, seed.ImageAnchor())
		require.NoError(t, perr)
		require.Equalf(t, modulecatalog.VerdictWouldBeRefusedBeyondAnchor, plan.Verdict,
			"строка, которой не объявляют ни образ, ни доставка, признана проходимой: "+
				"следующий пуск отказал бы страж, а починить это можно было бы только "+
				"прямым SQL")
		require.NotEmpty(t, plan.BeyondAnchorExtra, "вердикт отказа не назвал строку поимённо")
	})

	t.Run("опора несёт доставку, а каталог строки НЕ несёт — вердикт отказа", func(t *testing.T) {
		bare := modulecatalog.NewCatalogState(image, catalog.Rows{})
		plan, perr := modulecatalog.AnchorVerdictOf(context.Background(), bare, delivered)
		require.NoError(t, perr)
		require.Equalf(t, modulecatalog.VerdictWouldBeRefusedBeyondAnchor, plan.Verdict,
			"опора называет строку, живой её нет и снятой нет, а вердикт проходной: "+
				"непроехавшее применение прошло бы молча")
		require.NotEmpty(t, plan.BeyondAnchorMissing, "вердикт не назвал недостающую строку")
	})
}
