// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"fmt"
	"sort"
)

const checkNarrowingRPC = "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1/InternalIAMService/Check"

// CheckNarrowingWitness содержит только результат для зарегистрированного
// InternalIAMService.Check. Свидетель не служит отчётом о покрытии дерева.
type CheckNarrowingWitness struct {
	Reads    []CallerIdentityRead
	Findings []string
}

func CheckNarrowingWitnessForTest(ctx context.Context, root string, declared []CallerReadDeclaration) (CheckNarrowingWitness, error) {
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
	facts, err := collectCheckNarrowingFacts(ctx, p, l)
	if err != nil {
		return CheckNarrowingWitness{}, err
	}

	narrow, err := callerRuntimeNarrowing(p)
	if err != nil {
		return CheckNarrowingWitness{}, err
	}
	witness := facts.witness(narrow, declared)
	if err := ctx.Err(); err != nil {
		return CheckNarrowingWitness{}, err
	}
	return witness, nil
}

type checkNarrowingFacts struct {
	report CallerIdentityReport
	scope  callerRegisteredWalk
}

func collectCheckNarrowingFacts(ctx context.Context, p *surfaceProgram, listing *surfaceListing) (checkNarrowingFacts, error) {
	scope := callerRegisteredWalk{rpc: checkNarrowingRPC}
	report := scope.collect(ctx, p, callerExternalLeafProof(listing), nil)
	if report.Invalid != "" || scope.readSet == nil {
		return checkNarrowingFacts{}, fmt.Errorf("обход Check не завершён: %s %v", report.Invalid, report.Findings)
	}
	return checkNarrowingFacts{report: report, scope: scope}, nil
}

func (facts checkNarrowingFacts) witness(narrow map[string]bool, declared []CallerReadDeclaration) CheckNarrowingWitness {
	selected := map[string]bool{}
	if narrow[checkNarrowingRPC] {
		selected[checkNarrowingRPC] = true
	}
	var declarations []CallerReadDeclaration
	for _, row := range declared {
		if row.RPC == checkNarrowingRPC {
			declarations = append(declarations, row)
		}
	}
	evidence := callerDeclarationEvidence{readSet: facts.scope.readSet, narrow: selected, appliedNarrow: facts.scope.appliedNarrow}
	findings := append(evidence.findings(facts.report.Reads, declarations), facts.report.Findings...)
	sort.Strings(findings)
	return CheckNarrowingWitness{Reads: facts.report.Reads, Findings: findings}
}
