// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"fmt"
	"regexp"
)

// AccessBindingConditionID — format `cond_<...>` (migration 0012 CHECK
// `^cond_[a-z0-9_]{1,40}$`). Used as the nullable
// AccessBinding.ConditionID overlay link; the standalone
// AccessBindingCondition entity/repo was removed in prod-cleanup (no live
// consumer — the RBAC-v2 overlay is served by domain.Condition /
// ConditionsService).
type AccessBindingConditionID string

var condIDRe = regexp.MustCompile(`^cond_[a-z0-9_]{1,40}$`)

func (id AccessBindingConditionID) Validate() error {
	if id == "" {
		return nil
	}
	if !condIDRe.MatchString(string(id)) {
		return fmt.Errorf("Illegal argument id: must match ^cond_[a-z0-9_]{1,40}$")
	}
	return nil
}
