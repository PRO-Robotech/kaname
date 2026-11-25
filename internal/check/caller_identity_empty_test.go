// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import "testing"

func TestCallerIdentityEmptyInputIsNotGreen(t *testing.T) {
	r := judgeCallerIdentity(&surfaceProgram{}, nil)
	if len(r.Findings) == 0 {
		t.Fatal("пустой обход ошибочно принят")
	}
}
