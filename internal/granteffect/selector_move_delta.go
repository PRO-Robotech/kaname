// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"maps"
	"slices"
)

// CompileSelectorMoveDelta специализирует эффекты одной привязки на удержанной
// координате. Писатель подтверждает точный перенос предикатов роли, полноту
// привязок и совместный результат всех копий на существующих объектах.
// Условия на остальных узлах пути, в том числе на будущих детях, символические.
func (b *Bundle) CompileSelectorMoveDelta(before, after Binding, old, next MetadataObject) MetadataDelta {
	if b.Validate() != nil {
		return MetadataDelta{}
	}
	fail := func(detail string) MetadataDelta {
		s := Set{identity: b.Identity(), obligations: []Obligation{{Code: "selector_move_input", Detail: detail,
			Provenance: Provenance{SourceID: before.SourceID, RoleID: before.Role.ID}}}}
		return MetadataDelta{Before: s, After: s}
	}
	if before.SourceID != after.SourceID || before.Scope != after.Scope || before.Recipient != after.Recipient ||
		before.CapabilityVersion != after.CapabilityVersion || before.Target.AllInScope != after.Target.AllInScope ||
		!slices.Equal(before.Target.Resources, after.Target.Resources) ||
		len(before.Subjects) == 0 || !slices.Equal(before.Subjects, after.Subjects) {
		return fail("same binding and complete recipients required")
	}
	oldRole, newRole := before.Role, after.Role
	if oldRole.ID == "" || oldRole.ID != newRole.ID || oldRole.IsSystem != newRole.IsSystem || oldRole.OwnerModule != newRole.OwnerModule ||
		oldRole.ClusterID != newRole.ClusterID || oldRole.AccountID != newRole.AccountID || oldRole.ProjectID != newRole.ProjectID ||
		!slices.Equal(oldRole.Permissions, newRole.Permissions) || len(oldRole.Rules) != len(newRole.Rules) {
		return fail("same role identity, definition tier and permissions required")
	}
	if !maps.Equal(old.Labels, next.Labels) {
		return fail("ordinary labels changed")
	}
	for key, value := range old.AccessLabels {
		if v, ok := next.AccessLabels[key]; !ok || v != value {
			return fail("existing access label changed")
		}
	}
	for key, value := range next.AccessLabels {
		if _, exists := old.AccessLabels[key]; !exists {
			if v, ok := old.Labels[key]; !ok || v != value {
				return fail("new access label does not match the ordinary label")
			}
		}
	}
	return b.compiler.compileMetadataImages(before, after, old, next)
}
