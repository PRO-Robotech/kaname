// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// own_gate_wiring_guard_test.go — the refusal to start, exercised in both directions.
//
// The guard it covers exists because losing a piece of the wiring is silent: iam's own gates
// would keep answering, from delivered relations only, and disagree with the gate the
// api-gateway asks about the same subject and the same object. Nothing else in the process
// would say so.
//
// A guard nobody can exercise is one nobody knows works, so this asserts both directions —
// the complete wiring passes, and each missing piece produces a complaint that NAMES what is
// missing. The message text is checked because it is what an operator sees when the stand will
// not come up; a refusal that does not say what to fix cannot be acted on.

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_iam/shadowverdict"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzcascade"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/verdictsource"
)

// openSnapshot — a snapshot opener that is never called. The guard asks only whether one is
// present, and nothing here reads a row.
func openSnapshot(context.Context) (authzcascade.StructuralSnapshot, error) { return nil, nil }

func TestOwnGateWiringGuard(t *testing.T) {
	transport := &clients.OpenFGAHTTPClient{Endpoint: "127.0.0.1:1", StoreID: "s"}
	complete := authzcascade.New(nil).WithBatch(authzcascade.BatchSourceFunc(openSnapshot))
	// Сравнитель с nil-формой: страж спрашивает лишь, ПРОВЯЗАН ли он, и ни одной
	// строки здесь не читается. Настоящий тип, а не дублёр, — иначе проба
	// утверждала бы о значении, которого композиционный корень не собирает.
	comparator := shadowverdict.New(nil, nil)

	require.Empty(t,
		ownGateWiringComplaint(authzcascade.Wrap(transport, complete).WithComparator(comparator), complete, verdictsource.Switchboard{}, true),
		"the wiring the composition root builds must satisfy its own guard — otherwise the "+
			"guard is either wrong or unreachable, and both look identical from outside")

	// Piece one missing: the gates would answer from delivered relations only.
	require.Contains(t,
		ownGateWiringComplaint(authzcascade.Wrap(transport, nil).WithComparator(comparator), complete, verdictsource.Switchboard{}, true),
		"delivered relations only",
		"a relation store without a fact source must be refused, and the refusal must say why")

	// Piece two missing: correct answers, at a cost a contract-sized page cannot pay.
	noBatch := authzcascade.New(nil)
	require.False(t, noBatch.BatchReachable(), "premise: this resolver cannot batch")
	require.Contains(t,
		ownGateWiringComplaint(authzcascade.Wrap(transport, noBatch).WithComparator(comparator), noBatch, verdictsource.Switchboard{}, true),
		"one object at a time",
		"a resolver without the page read must be refused, and the refusal must name the cost")

	// Piece three missing: РЕШЕНИЯ УХОДЯТ ДВИЖКУ НЕ ПРЕДЪЯВЛЕННЫМИ СРАВНЕНИЮ.
	//
	// Это отказ не про корректность ответа — ответ остаётся прежним, — а про
	// НАБЛЮДАЕМОСТЬ перед переключением источника вердикта. Без сравнения обе
	// формы живы, расходятся молча, и первое, что об этом скажет, — арендатор.
	// Провязка в пустоту выглядит исполненной, поэтому её и проверяет отказ в
	// старте, а не память ревьюера.
	require.Contains(t,
		ownGateWiringComplaint(authzcascade.Wrap(transport, complete), complete, verdictsource.Switchboard{}, true),
		"не предъявляя их сравнению",
		"обёртка без сравнения обязана быть отвергнута, и отказ обязан назвать, чего не хватает")
}
