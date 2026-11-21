// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import "github.com/PRO-Robotech/kaname/internal/domain"

// Эти чистые порты возвращают тот же план обхода, который использует live
// reconciler. Они не удостоверяют полноту capture и не разрешают DB mutation.
func CapturedObjectDependencyShape(binding BindingScope, changedType string) (wholeBinding, ancestors bool) {
	return nestsUnder(binding, changedType), hasNestedSelector(binding)
}

func CapturedNestedOwnerSelector(selector domain.RuleSelector) (domain.RuleSelector, error) {
	if selector.Container == nil {
		return domain.RuleSelector{}, ErrIncompleteObjectDiff
	}
	return ownerSelectorOf(selector), nil
}

func CapturedNestedContainerSelected(selector domain.RuleSelector, binding BindingScope, object domain.MirrorObject) (bool, error) {
	if selector.Container == nil {
		return false, ErrIncompleteObjectDiff
	}
	return containerSelected(selector, binding, object), nil
}
