// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelrender_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/modelrender"
)

func TestNativeGrantCapabilityProducerMatchesCanonicalBlocks(t *testing.T) {
	if err := modelrender.ValidateNativeGrantCapabilityBlocks([]byte(authzmodel.DSL)); err != nil {
		t.Fatal(err)
	}
	blocks := modelrender.NativeGrantCapabilityBlocks()
	want := []string{grantcapability.ScopeObjectType, grantcapability.RoleObjectType, grantcapability.AccessLabelObjectType}
	if len(blocks) != len(want) {
		t.Fatalf("native block census: %d", len(blocks))
	}
	for i, block := range blocks {
		if block.Type != want[i] {
			t.Fatalf("native coordinate order: %v", blocks)
		}
		for _, forbidden := range []string{" from ", "define admin:", "define editor:", "define viewer:", "define v_", "user:*", " with "} {
			if bytes.Contains(block.Body, []byte(forbidden)) {
				t.Fatalf("native block grew ordinary authority: %s", block.Body)
			}
		}
	}
	blocks[0].Body[0] = 'X'
	if modelrender.NativeGrantCapabilityBlocks()[0].Body[0] != 't' {
		t.Fatal("native producer shares mutable template bytes")
	}
}

func TestNativeGrantCapabilityValidatorRejectsMissingDuplicateAndWidenedBlocks(t *testing.T) {
	for _, block := range modelrender.NativeGrantCapabilityBlocks() {
		body := string(block.Body)
		for name, changed := range map[string]string{
			"missing":   strings.Replace(authzmodel.DSL, body, "", 1),
			"duplicate": authzmodel.DSL + "\n" + body,
			"wildcard":  strings.Replace(authzmodel.DSL, body, strings.Replace(body, "group#member]", "group#member, user:*]", 1), 1),
			"narrowed":  strings.Replace(authzmodel.DSL, body, strings.Replace(body, "user, service_account, group#member", "user", 1), 1),
			"parent":    strings.Replace(authzmodel.DSL, body, body+"    define parent: [account]\n", 1),
			"tier":      strings.Replace(authzmodel.DSL, body, body+"    define admin: [user]\n", 1),
		} {
			t.Run(block.Type+"/"+name, func(t *testing.T) {
				if err := modelrender.ValidateNativeGrantCapabilityBlocks([]byte(changed)); err == nil {
					t.Fatal("noncanonical native block accepted")
				}
			})
		}
	}
	if err := modelrender.ValidateNativeGrantCapabilityBlocks(nil); err == nil {
		t.Fatal("empty product canon accepted")
	}
}

func TestNativeGrantCapabilityCatalogRowIsOutsideManifestResources(t *testing.T) {
	var dsl []byte
	for _, block := range modelrender.NativeGrantCapabilityBlocks() {
		dsl = append(dsl, block.Body...)
		dsl = append(dsl, '\n')
	}
	// Authoring-only строка каталога принадлежит IAM, но её блок не становится
	// ordinary manifest resource и не получает parent/tier по умолчанию.
	resources := []catalog.ResourceRow{{Module: "iam", Resource: "accessLabel", ObjectType: grantcapability.AccessLabelObjectType}}
	if owned := modelrender.OwnedTypes(resources, dsl, "iam"); len(owned) != 0 {
		t.Fatalf("native block assigned to ordinary manifest producer: %v", owned)
	}
	outside := modelrender.TypesOutsideModules(resources, dsl)
	want := []string{grantcapability.AccessLabelObjectType, grantcapability.RoleObjectType, grantcapability.ScopeObjectType}
	if strings.Join(outside, ",") != strings.Join(want, ",") {
		t.Fatalf("native census outside manifest resources: %v", outside)
	}
}
