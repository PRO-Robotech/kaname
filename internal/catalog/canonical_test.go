// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
)

func canonicalFixture() Halves {
	return Halves{
		Live: Rows{
			Modules: []string{"z", "a", "z"},
			Resources: []ResourceRow{
				{Module: "z", Resource: "items", ObjectType: "z_item", ParentTypes: []string{"account", "project"}, ParentNames: []string{"account", "project"}, Writes: []string{"owner:user", "owner:service_account"}},
				{Module: "a", Resource: "items", ObjectType: "a_item"},
			},
			Verbs: []VerbRow{{Module: "z", Resource: "items", Verb: "get", PerObject: true}, {Module: "a", Resource: "items", Verb: "create", ContainerParent: "account", ContainerRelation: "item_creator"}},
		},
		Retired: Rows{
			Modules:   []string{"old_z", "old_a"},
			Resources: []ResourceRow{{Module: "old_z", Resource: "items", ObjectType: "old_z_item", SupersededBy: "z.items"}, {Module: "old_a", Resource: "items", ObjectType: "old_a_item"}},
			Verbs:     []VerbRow{{Module: "old_z", Resource: "items", Verb: "get", PerObject: true}, {Module: "old_a", Resource: "items", Verb: "update", PerObject: true}},
		},
	}
}

func mustCanonical(t *testing.T, h Halves) []byte {
	t.Helper()
	b, err := CanonicalJSON(h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCanonicalCatalogIgnoresSQLRowOrderWithoutChangingInput(t *testing.T) {
	h := canonicalFixture()
	before, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	canonical := mustCanonical(t, h)
	after, err := json.Marshal(h)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("канонизация изменила исходные строки", err)
	}
	other := canonicalFixture()
	for _, r := range []*Rows{&other.Live, &other.Retired} {
		slices.Reverse(r.Modules)
		slices.Reverse(r.Resources)
		slices.Reverse(r.Verbs)
	}
	if !bytes.Equal(canonical, mustCanonical(t, other)) {
		t.Fatal("перестановка строк SQL изменила значение каталога")
	}
	// nil и пустой массив не различаются в SameForm и не должны менять identity.
	other = canonicalFixture()
	other.Live.Resources[1].ParentTypes = []string{}
	other.Live.Resources[1].ParentNames = []string{}
	other.Live.Resources[1].Writes = []string{}
	other.Retired.Resources[1].Writes = []string{}
	if !bytes.Equal(canonical, mustCanonical(t, other)) {
		t.Fatal("пустые массивы изменили значение каталога")
	}
	if !bytes.Equal(mustCanonical(t, Halves{}), mustCanonical(t, Halves{Live: Rows{Modules: []string{}, Resources: []ResourceRow{}, Verbs: []VerbRow{}}, Retired: Rows{Resources: []ResourceRow{}}})) {
		t.Fatal("пустые половины должны иметь одну форму")
	}
}

func TestCanonicalCatalogRetainsEveryRowFieldAndManifestOrder(t *testing.T) {
	base := mustCanonical(t, canonicalFixture())
	changes := map[string]func(*Halves){
		"module_membership":  func(h *Halves) { h.Live.Modules = append(h.Live.Modules, "new") },
		"resource_module":    func(h *Halves) { h.Live.Resources[0].Module = "other" },
		"resource_name":      func(h *Halves) { h.Live.Resources[0].Resource = "other" },
		"object_type":        func(h *Halves) { h.Live.Resources[0].ObjectType = "other" },
		"successor":          func(h *Halves) { h.Retired.Resources[0].SupersededBy = "a.items" },
		"parent_type":        func(h *Halves) { h.Live.Resources[0].ParentTypes[0] = "cluster" },
		"parent_name":        func(h *Halves) { h.Live.Resources[0].ParentNames[0] = "parent" },
		"writes":             func(h *Halves) { h.Live.Resources[0].Writes[0] = "viewer:user" },
		"public_children":    func(h *Halves) { h.Live.Resources[0].PublicReadToChildren = true },
		"permanent_project":  func(h *Halves) { h.Live.Resources[0].PermanentProject = true },
		"verb_module":        func(h *Halves) { h.Live.Verbs[0].Module = "other" },
		"verb_resource":      func(h *Halves) { h.Live.Verbs[0].Resource = "other" },
		"verb_name":          func(h *Halves) { h.Live.Verbs[0].Verb = "update" },
		"per_object":         func(h *Halves) { h.Live.Verbs[0].PerObject = false },
		"container_parent":   func(h *Halves) { h.Live.Verbs[1].ContainerParent = "project" },
		"container_relation": func(h *Halves) { h.Live.Verbs[1].ContainerRelation = "other_creator" },
		"retired_membership": func(h *Halves) { h.Retired.Modules = append(h.Retired.Modules, "new") },
		"retired_verb":       func(h *Halves) { h.Retired.Verbs[0].PerObject = false },
		"manifest_order": func(h *Halves) {
			slices.Reverse(h.Live.Resources[0].ParentTypes)
			slices.Reverse(h.Live.Resources[0].ParentNames)
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			h := canonicalFixture()
			change(&h)
			if bytes.Equal(base, mustCanonical(t, h)) {
				t.Fatal("изменённое поле потеряно из канонической формы")
			}
		})
	}
}

func TestCanonicalCatalogRejectsAmbiguousRowKeys(t *testing.T) {
	for _, half := range []string{"live", "retired"} {
		for _, kind := range []string{"resource", "verb"} {
			for _, different := range []bool{false, true} {
				name := half + "/" + kind + "/equal"
				if different {
					name = half + "/" + kind + "/conflicting"
				}
				t.Run(name, func(t *testing.T) {
					h := canonicalFixture()
					r := &h.Live
					if half == "retired" {
						r = &h.Retired
					}
					if kind == "resource" {
						dup := r.Resources[0]
						if different {
							dup.ObjectType = "other_type"
						}
						r.Resources = append(r.Resources, dup)
					} else {
						dup := r.Verbs[0]
						if different {
							dup.PerObject = !dup.PerObject
						}
						r.Verbs = append(r.Verbs, dup)
					}
					if b, err := CanonicalJSON(h); err == nil || b != nil {
						t.Fatal("повтор ключа не должен давать каноническую authority", err)
					}
				})
			}
		}
	}
}
