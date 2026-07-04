// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// feed_registry_materializable_test.go — unified IAM visibility model.
//
// Прежде два набора были РАЗДЕЛЕНЫ (O-4): labelSelectableTypes исключал iam
// content-типы (user/serviceAccount/group/role/accessBinding) — они были
// materializable только через ARM_ANCHOR/ARM_NAMES, но НЕ через ARM_LABELS.
//
// Единая модель (owner direction — единая модель для всех iam-типов): КАЖДЫЙ
// iam-native тип label-selectable наравне с account/project. Следствие:
//   - labelSelectableTypes содержит все 7 iam-native типов;
//   - AllMaterializableTypes() ⊇ labelSelectableTypes — материализуемое множество
//     есть strict superset label-selectable, отличается ровно на
//     registry.repositories (materializable, но НЕ label-selectable; проверяется в
//     feed_registry_repositories_test.go). Для iam-типов множества совпадают.
// iam content-типы по-прежнему materializable через ARM_ANCHOR/ARM_NAMES И
// дополнительно через ARM_LABELS (own-table labels @> matchLabels, same-DB).

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// iamContentTypes — iam-native content-типы (помимо иерархических project/account).
var iamContentTypes = []string{
	"iam.role", "iam.group", "iam.serviceAccount", "iam.user", "iam.accessBinding",
}

// allIAMTypes — полный набор iam-native типов (иерархия + content).
var allIAMTypes = append([]string{"iam.project", "iam.account"}, iamContentTypes...)

// TestLabelSelectable_IncludesEveryIAMType — единая модель: КАЖДЫЙ iam-native тип
// label-selectable (match_labels-правило на iam.user/serviceAccount/group/role/
// accessBinding валидно так же, как на iam.project/iam.account).
func TestLabelSelectable_IncludesEveryIAMType(t *testing.T) {
	for _, ty := range allIAMTypes {
		assert.True(t, IsLabelSelectableType(ty),
			"iam type %s must be label-selectable (unified visibility model)", ty)
	}
}

// TestLabelSelectable_KeepsConsumerTypes — расширение iam-набора не уронило
// mirror-fed consumer-типы (vpc/compute/loadbalancer остаются label-selectable).
func TestLabelSelectable_KeepsConsumerTypes(t *testing.T) {
	for _, ty := range []string{
		"compute.instance", "vpc.network", "vpc.subnet",
		"loadbalancer.networkLoadBalancers",
	} {
		assert.True(t, IsLabelSelectableType(ty),
			"consumer mirror-fed type %s must stay label-selectable", ty)
	}
}

// TestAllMaterializableTypes_IncludesIamContent — `*.*` wildcard-expansion набор
// по-прежнему включает iam content-типы (bounded owner `*.*` материализует
// per-object admin на Role/Group/SA/User/AccessBinding, forward-mat).
func TestAllMaterializableTypes_IncludesIamContent(t *testing.T) {
	seen := map[string]struct{}{}
	for _, ty := range AllMaterializableTypes() {
		seen[ty] = struct{}{}
	}
	for _, want := range allIAMTypes {
		_, ok := seen[want]
		assert.True(t, ok, "AllMaterializableTypes must include iam type %s", want)
	}
	for _, want := range []string{"vpc.network", "compute.instance"} {
		_, ok := seen[want]
		assert.True(t, ok, "AllMaterializableTypes must keep consumer type %s", want)
	}
}
