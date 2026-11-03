// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

import (
	"errors"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"gopkg.in/yaml.v3"
)

// GrantDelegation is the closed installation declaration. Identity, creator,
// status and account IDs are resolved by the authenticated installation stage.
type GrantDelegation struct {
	Delegate     SubjectRef `yaml:"delegate"`
	RoleIDs      []string   `yaml:"roleIds"`
	TargetTypes  []string   `yaml:"targetTypes"`
	SubjectTypes []string   `yaml:"subjectTypes"`
}

var ErrGrantDelegation = errors.New("manifest: invalid seed grant delegation")

func validateGrantDelegations(m *Manifest, doc *yaml.Node) []error {
	var faults []error
	for i, d := range m.Seed.GrantDelegations {
		fail := func(field, reason string) {
			faults = append(faults, linkFault{kind: ErrGrantDelegation, coord: locate(doc, "seed", "grantDelegations", i, field), detail: fmt.Sprintf("seed.grantDelegations[%d].%s: %s", i, field, reason)})
		}
		found := false
		for _, sa := range m.Seed.ServiceAccounts {
			if sa.Name == d.Delegate.Name && sa.Account == d.Delegate.Account {
				found = true
			}
		}
		if !found || d.Delegate.Account != domain.SystemAccountName {
			fail("delegate", "must name a service account declared by this seed in system")
		}
		for _, axis := range []struct {
			name string
			xs   []string
			max  int
		}{
			{"roleIds", d.RoleIDs, domain.MaxGrantDelegationRoles},
			{"targetTypes", d.TargetTypes, domain.MaxGrantDelegationTargetTypes},
			{"subjectTypes", d.SubjectTypes, domain.MaxGrantDelegationSubjectTypes},
		} {
			if len(axis.xs) < 1 || len(axis.xs) > axis.max {
				fail(axis.name, fmt.Sprintf("requires 1..%d entries", axis.max))
			}
			seen := map[string]bool{}
			for _, x := range axis.xs {
				if seen[x] {
					fail(axis.name, fmt.Sprintf("duplicate %q", x))
				}
				seen[x] = true
			}
		}
		for _, id := range d.RoleIDs {
			found := false
			for _, r := range m.Roles {
				if r.ID == id {
					found = true
				}
			}
			if !found || m.Module == "iam" || !strings.HasPrefix(id, m.Module+".") {
				fail("roleIds", fmt.Sprintf("role %q must be declared by module %q", id, m.Module))
			}
		}
		for _, typ := range d.TargetTypes {
			found := false
			for _, r := range m.Resources {
				if m.Module+"."+r.Name == typ {
					found = true
				}
			}
			if !found || m.Module == "iam" {
				fail("targetTypes", fmt.Sprintf("type %q must belong to this module catalog", typ))
			}
		}
		for _, typ := range d.SubjectTypes {
			switch typ {
			case "SUBJECT_TYPE_USER", "SUBJECT_TYPE_SERVICE_ACCOUNT", "SUBJECT_TYPE_GROUP", "SUBJECT_TYPE_SYSTEM_CLASS":
			default:
				fail("subjectTypes", fmt.Sprintf("unknown subject type %q", typ))
			}
		}
	}
	return faults
}

// A declared null list is not the closed array input (omission and [] are legal).
func refuseNullDelegations(doc *yaml.Node) error {
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value != "seed" {
			continue
		}
		seed := doc.Content[i+1]
		for j := 0; j+1 < len(seed.Content); j += 2 {
			if seed.Content[j].Value == "grantDelegations" && seed.Content[j+1].Kind != yaml.SequenceNode {
				return linkFault{kind: ErrShape, coord: locate(doc, "seed", "grantDelegations"), detail: "grantDelegations must be an array"}
			}
		}
	}
	return nil
}

// Refuse unknown fields and wrong node kinds so callers receive structural coordinates,
// independently of yaml.Decoder's human-readable error formatting.
func refuseUnknownDelegationFields(doc *yaml.Node) error {
	entries := mapValue(mapValue(doc, "seed"), "grantDelegations")
	if entries == nil || entries.Kind != yaml.SequenceNode {
		return nil
	}
	for i, entry := range entries.Content {
		entry, err := delegationNodeKind(doc, entry, yaml.MappingNode, "seed", "grantDelegations", i)
		if err != nil {
			return err
		}
		for j := 0; j+1 < len(entry.Content); j += 2 {
			key, value := entry.Content[j].Value, entry.Content[j+1]
			switch key {
			case "roleIds", "targetTypes", "subjectTypes":
				axis, err := delegationNodeKind(doc, value, yaml.SequenceNode, "seed", "grantDelegations", i, key)
				if err != nil {
					return err
				}
				for k, item := range axis.Content {
					if _, err := delegationNodeKind(doc, item, yaml.ScalarNode, "seed", "grantDelegations", i, key, k); err != nil {
						return err
					}
				}
			case "delegate":
				value, err = delegationNodeKind(doc, value, yaml.MappingNode, "seed", "grantDelegations", i, "delegate")
				if err != nil {
					return err
				}
				for k := 0; k+1 < len(value.Content); k += 2 {
					field := value.Content[k].Value
					if field != "account" && field != "name" {
						return linkFault{kind: ErrShape, coord: locate(doc, "seed", "grantDelegations", i, "delegate", field), detail: "unknown field"}
					}
					if _, err := delegationNodeKind(doc, value.Content[k+1], yaml.ScalarNode, "seed", "grantDelegations", i, "delegate", field); err != nil {
						return err
					}
				}
			default:
				return linkFault{kind: ErrShape, coord: locate(doc, "seed", "grantDelegations", i, key), detail: "unknown field"}
			}
		}
	}
	return nil
}

// Check the resolved kind without embedding input values in a shape failure.
// Scalar tags and allowed values remain the strict decoder's and semantic
// validator's responsibility; valid YAML aliases keep their normal meaning.
func delegationNodeKind(doc, node *yaml.Node, want yaml.Kind, steps ...any) (*yaml.Node, error) {
	resolved, err := resolveAlias(node)
	if err != nil || resolved.Kind != want {
		return nil, linkFault{kind: ErrShape, coord: locate(doc, steps...), detail: "expected " + nodeKindName(want)}
	}
	return resolved, nil
}
