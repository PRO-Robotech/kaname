// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"fmt"
	"sort"
)

const checkNarrowingAPI = "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
const checkNarrowingRPC = checkNarrowingAPI + "/InternalIAMService/Check"

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
	reads                  []CallerIdentityRead
	findings               []string
	readSet, appliedNarrow map[string]bool
}

func collectCheckNarrowingFacts(ctx context.Context, p *surfaceProgram, listing *surfaceListing) (checkNarrowingFacts, error) {
	scope := callerRegisteredWalk{rpc: checkNarrowingRPC}
	report := scope.collect(ctx, p, callerExternalLeafProof(listing), nil)
	if report.Invalid != "" || scope.readSet == nil {
		return checkNarrowingFacts{}, fmt.Errorf("обход Check не завершён: %s %v", report.Invalid, report.Findings)
	}
	return checkNarrowingFacts{
		reads: report.Reads, findings: report.Findings, readSet: scope.readSet, appliedNarrow: scope.appliedNarrow,
	}, nil
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
	evidence := callerDeclarationEvidence{readSet: facts.readSet, narrow: selected, appliedNarrow: facts.appliedNarrow}
	findings := append(evidence.findings(facts.reads, declarations), facts.findings...)
	sort.Strings(findings)
	return CheckNarrowingWitness{Reads: facts.reads, Findings: findings}
}
