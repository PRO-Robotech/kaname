// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"fmt"
	"sort"
)

// CheckNarrowingWitness содержит только результат для зарегистрированного
// InternalIAMService.Check. Свидетель не служит отчётом о покрытии дерева.
type CheckNarrowingWitness struct {
	Reads    []CallerIdentityRead
	Findings []string
}

func CheckNarrowingWitnessForTest(ctx context.Context, root string, declared []CallerReadDeclaration) (CheckNarrowingWitness, error) {
	const rpc = "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1/InternalIAMService/Check"
	l, err := bindingPairListingFor(ctx, root, []string{"cmd/kaname"})
	if err != nil {
		return CheckNarrowingWitness{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	p, err := l.program(nil)
	if err != nil {
		return CheckNarrowingWitness{}, err
	}
	d := newFinalCauseProbe(p)
	scope := callerRegisteredWalk{rpc: rpc, finalProbe: d}
	r := scope.collect(ctx, p, callerExternalLeafProof(l), nil)
	if r.Invalid != "" || scope.readSet == nil {
		return CheckNarrowingWitness{}, fmt.Errorf("обход Check не завершён: %s %v", r.Invalid, r.Findings)
	}

	narrow, err := callerRuntimeNarrowing(p)
	if err != nil {
		return CheckNarrowingWitness{}, err
	}
	d.print(p, r.Findings, rpc, narrow[rpc])
	selected := map[string]bool{}
	if narrow[rpc] {
		selected[rpc] = true
	}
	var declarations []CallerReadDeclaration
	for _, row := range declared {
		if row.RPC == rpc {
			declarations = append(declarations, row)
		}
	}
	evidence := callerDeclarationEvidence{readSet: scope.readSet, narrow: selected, appliedNarrow: scope.appliedNarrow}
	findings := append(r.Findings, evidence.findings(r.Reads, declarations)...)
	sort.Strings(findings)
	if err := ctx.Err(); err != nil {
		return CheckNarrowingWitness{}, err
	}
	return CheckNarrowingWitness{Reads: r.Reads, Findings: findings}, nil
}
