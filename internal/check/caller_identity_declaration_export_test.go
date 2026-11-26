// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import "fmt"

// DeclarationFindingsForTest меняет только список описаний законного дерева.
func (r CallerIdentityReport) DeclarationFindingsForTest(declared []CallerReadDeclaration) ([]string, error) {
	if r.Invalid != "" || r.declarationEvidence == nil || len(r.Findings) != 0 {
		return nil, fmt.Errorf("нет завершённого законного обхода: invalid=%q findings=%v", r.Invalid, r.Findings)
	}
	return r.declarationEvidence.findings(r.Reads, declared), nil
}
