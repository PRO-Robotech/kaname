// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

import (
	"fmt"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
)

// ValidateGrantVerbs судит и decoded, и построенный в памяти манифест. kaname#1034.
func ValidateGrantVerbs(m *Manifest) []error {
	var faults []error
	for i, r := range m.Resources {
		seen := map[string]bool{}
		for _, v := range r.GrantVerbs {
			if !slices.Contains(authzmap.GrantAuthoringVerbs(m.Module, r.Name), v) || seen[v] {
				faults = append(faults, fmt.Errorf("resources[%d].grantVerbs: unsupported or duplicate grant axis %q", i, v))
			}
			seen[v] = true
			for _, ordinary := range r.Verbs {
				if ordinary.Name == v {
					faults = append(faults, fmt.Errorf("resources[%d].grantVerbs: axis %q is also a leaf verb", i, v))
				}
			}
			for _, container := range r.ContainerVerbs {
				if container.Name == v {
					faults = append(faults, fmt.Errorf("resources[%d].grantVerbs: axis %q is also a container verb", i, v))
				}
			}
		}
	}
	return faults
}
