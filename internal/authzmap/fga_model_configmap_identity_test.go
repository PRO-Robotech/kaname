// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// fga_model_configmap_identity_test.go — "one source of truth" gate for the
// authorization model.
//
// The canonical model is `proto/kacho/cloud/iam/v1/fga_model.fga` (see
// fga_model_drift_test.go). The openfga-bootstrap ConfigMap is GENERATED from it
// by `deploy/scripts/gen-openfga-model-configmap.py` (`make openfga-model-json`)
// and carries two derived blocks:
//
//	model.fga   — a byte-for-byte, 4-space-indented copy of the canonical DSL.
//	model.json  — the pre-transformed OpenFGA-JSON. THIS is what the bootstrap
//	              Job actually sends to WriteAuthorizationModel, i.e. the model
//	              OpenFGA really enforces on the stand.
//
// Without this gate the repository has TWO models that can silently disagree:
// the Go drift-gate would keep verifying the canonical file while the cluster
// enforces a stale `model.json`. Gate C-2 below is the one that matters
// operationally — it pins the APPLIED artifact to the canonical source.
//
//	C-1  the ConfigMap `model.fga` block, de-indented, is byte-identical to the
//	     canonical file (the DSL copy is generated, never hand-edited).
//	C-2  the ConfigMap `model.json` block declares EXACTLY the same types, the
//	     same per-type relation names and the same conditions as the canonical
//	     DSL — so a DSL edit that was never re-transformed (`make
//	     openfga-model-json` forgotten) cannot ship.
//
// C-2 compares the parsed structure rather than re-running `fga model transform`
// (the OpenFGA CLI is a Docker-only, distroless binary — unavailable in a unit
// test). Structure is what authorization depends on: a type or relation present
// in one artifact and absent from the other is precisely the dangling-relation
// class this suite exists to prevent.
package authzmap_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// configMapRelPath — the generated openfga-bootstrap model ConfigMap.
const configMapRelPath = "deploy/helm/umbrella/charts/openfga-bootstrap/templates/openfga-model-stub-configmap.yaml"

// configMapPath resolves the generated ConfigMap. Like the canonical model, a
// missing artifact is a hard failure, never a skip: the gate exists to prove the
// two copies agree, and it cannot do that if one of them is not there.
func configMapPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join(monorepoRoot(t), configMapRelPath)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("openfga-bootstrap model ConfigMap %s is MISSING (%v) — cannot prove the "+
			"applied authorization model still matches the canonical %s", configMapRelPath, err, canonicalModelRelPath)
	}
	return p
}

// configMapBlock extracts one `  <key>: |-` YAML block-scalar body from the
// ConfigMap template, de-indented by the 4 spaces the generator adds. It stops
// at the first line that is neither empty nor 4-space-indented (the next key or
// the generator's `model.json` comment header).
func configMapBlock(t *testing.T, key string) string {
	t.Helper()
	raw, err := os.ReadFile(configMapPath(t))
	require.NoError(t, err)

	header := "  " + key + ": |-"
	var out []string
	inBlock := false
	for _, l := range strings.Split(string(raw), "\n") {
		if !inBlock {
			if strings.TrimRight(l, " ") == header {
				inBlock = true
			}
			continue
		}
		switch {
		case strings.TrimSpace(l) == "":
			out = append(out, "")
		case strings.HasPrefix(l, "    "):
			out = append(out, l[4:])
		default:
			// next key / comment header — block ends.
			return strings.Join(out, "\n")
		}
	}
	require.Truef(t, inBlock, "ConfigMap %s has no `%s` block", configMapRelPath, key)
	return strings.Join(out, "\n")
}

// C-1: the ConfigMap DSL copy is byte-identical to the canonical model.
func TestModelConfigMap_DSLBlockIsByteIdenticalToCanonical(t *testing.T) {
	canonical, err := os.ReadFile(canonicalModelPath(t))
	require.NoError(t, err)

	// The generator normalises the canonical text to exactly one trailing
	// newline before indenting it, so compare on the same normalisation.
	want := strings.TrimRight(string(canonical), "\n")
	got := strings.TrimRight(configMapBlock(t, "model.fga"), "\n")

	require.Equalf(t, want, got,
		"the openfga-bootstrap ConfigMap `model.fga` block has DRIFTED from the canonical %s. "+
			"The ConfigMap is a GENERATED artifact — never hand-edit its DSL. Edit the canonical "+
			"file and re-run `make openfga-model-json` (in deploy/), then commit both.",
		canonicalModelRelPath)
}

// jsonModel is the subset of the OpenFGA-JSON authorization model this gate
// compares: type names, their relation names, and the condition names.
type jsonModel struct {
	SchemaVersion   string `json:"schema_version"`
	TypeDefinitions []struct {
		Type      string                     `json:"type"`
		Relations map[string]json.RawMessage `json:"relations"`
	} `json:"type_definitions"`
	Conditions map[string]json.RawMessage `json:"conditions"`
}

var reCondition = regexp.MustCompile(`^condition (\w+)\(`)

// C-2: the APPLIED model.json declares exactly the canonical DSL's types,
// relations and conditions.
func TestModelConfigMap_AppliedJSONMatchesCanonicalStructure(t *testing.T) {
	canonicalRaw, err := os.ReadFile(canonicalModelPath(t))
	require.NoError(t, err)
	dsl := parseModelDSL(string(canonicalRaw))

	var jm jsonModel
	require.NoErrorf(t, json.Unmarshal([]byte(strings.TrimSpace(configMapBlock(t, "model.json"))), &jm),
		"ConfigMap `model.json` block is not valid JSON")
	require.NotEmpty(t, jm.TypeDefinitions, "ConfigMap `model.json` declares no types")

	// --- types ---
	jsonTypes := make([]string, 0, len(jm.TypeDefinitions))
	jsonRelations := map[string][]string{}
	for _, td := range jm.TypeDefinitions {
		jsonTypes = append(jsonTypes, td.Type)
		rels := make([]string, 0, len(td.Relations))
		for r := range td.Relations {
			rels = append(rels, r)
		}
		sort.Strings(rels)
		jsonRelations[td.Type] = rels
	}
	sort.Strings(jsonTypes)

	dslTypes := make([]string, 0, len(dsl.types))
	for ty := range dsl.types {
		dslTypes = append(dslTypes, ty)
	}
	sort.Strings(dslTypes)

	require.Equalf(t, dslTypes, jsonTypes,
		"the APPLIED model.json declares a different set of types than the canonical %s — the "+
			"pre-transformed JSON is STALE (or hand-edited). Re-run `make openfga-model-json` in deploy/.",
		canonicalModelRelPath)

	// --- per-type relations ---
	for _, ty := range dslTypes {
		want := make([]string, 0, len(dsl.relations[ty]))
		for r := range dsl.relations[ty] {
			want = append(want, r)
		}
		sort.Strings(want)
		got := jsonRelations[ty]
		if len(want) == 0 && len(got) == 0 {
			continue
		}
		require.Equalf(t, want, got,
			"type %q: the APPLIED model.json relations differ from the canonical DSL — the "+
				"pre-transformed JSON is STALE. Re-run `make openfga-model-json` in deploy/.", ty)
	}

	// --- conditions ---
	var dslConditions []string
	for _, line := range strings.Split(string(canonicalRaw), "\n") {
		if m := reCondition.FindStringSubmatch(line); m != nil {
			dslConditions = append(dslConditions, m[1])
		}
	}
	sort.Strings(dslConditions)
	jsonConditions := make([]string, 0, len(jm.Conditions))
	for c := range jm.Conditions {
		jsonConditions = append(jsonConditions, c)
	}
	sort.Strings(jsonConditions)
	require.Equalf(t, dslConditions, jsonConditions,
		"the APPLIED model.json declares a different set of CEL conditions than the canonical %s "+
			"— re-run `make openfga-model-json` in deploy/.", canonicalModelRelPath)
}
