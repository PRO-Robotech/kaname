// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzmap_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// registry_owner_derivation_test.go — regression lock for #64 Defect A.
//
// The registry owner-registration edge (registry→iam RegisterResource) writes a
// structural `owner` tuple on registry_registry / registry_repository. In the flat
// Contract-A model the per-verb `v_*` relations are DIRECT (`[user, ...]`) and are
// materialized per-object by the iam reconciler from AccessBindings. The `owner`
// relation was DANGLING — nothing derived from it — so a registry's CREATOR/OWNER
// (who holds `owner` + editor-tier v_get/v_list/v_update/v_delete via their edit
// binding, but never `v_create`, since the `edit` role authors no `create` verb)
// could NOT CreateRepository in their OWN registry: the handler's per-object
// `v_create@registry_registry` Check denied → uniform 404 (existence-hiding).
// Only an account/project ADMIN (admin role → all v_*) could create repos, which
// contradicts RG-1 acceptance A01 ("any v_create-principal, incl. non-admin").
//
// Fix: every `v_*` on registry_registry / registry_repository now derives from
// `owner` (a per-OBJECT computed relation, NOT a hierarchy cascade — no O(mirror)
// recompute, consistent with the flat model's `editor: this or admin`). This test
// parses the deployed model DSL (the openfga-bootstrap ConfigMap `model.fga` block,
// which is the source of truth after the polyrepo→monorepo migration lost the
// canonical fga_model.fga) and asserts the derivation exists, so a future edit that
// re-dangles `owner` fails here rather than silently 404-ing every registry owner.

// findConfigMap walks up from CWD to the repo root and returns the openfga-bootstrap
// model-stub ConfigMap path.
func findConfigMap(t *testing.T) string {
	t.Helper()
	const rel = "deploy/helm/umbrella/charts/openfga-bootstrap/templates/openfga-model-stub-configmap.yaml"
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		cand := filepath.Join(dir, rel)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skipf("openfga model-stub ConfigMap not found walking up from CWD (rel=%s) — cannot run registry owner-derivation lock", rel)
		}
		dir = parent
	}
}

// registryModelBlock returns the `model.fga` DSL block, de-indented, from the
// ConfigMap.
func registryModelBlock(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(findConfigMap(t))
	require.NoError(t, err)
	lines := strings.Split(string(raw), "\n")
	var out []string
	inBlock := false
	for _, l := range lines {
		if strings.TrimRight(l, " ") == "  model.fga: |-" {
			inBlock = true
			continue
		}
		if inBlock {
			if strings.TrimRight(l, " ") == "  model.json: |-" ||
				strings.HasPrefix(strings.TrimSpace(l), "# Pre-transformed") {
				break
			}
			if strings.TrimSpace(l) == "" {
				out = append(out, "")
				continue
			}
			if strings.HasPrefix(l, "    ") {
				out = append(out, l[4:])
				continue
			}
			break
		}
	}
	return strings.Join(out, "\n")
}

// typeRelations returns the DSL body (`relations` section) of `type <name>` up to
// the next top-level `type `/`condition ` keyword.
func typeBody(t *testing.T, dsl, typeName string) string {
	t.Helper()
	re := regexp.MustCompile(`(?ms)^type ` + regexp.QuoteMeta(typeName) + `\b.*?(?:\n(?:type |condition )|\z)`)
	m := re.FindString(dsl)
	require.NotEmptyf(t, m, "type %q not found in model.fga block", typeName)
	return m
}

// TestRegistryModel_OwnerDerivesVerbs asserts every closed v_* relation on the two
// registry object-types derives from `owner`, so the registry owner/creator holds
// the full CRUD verb-set (esp. v_create → CreateRepository) on their own resource.
func TestRegistryModel_OwnerDerivesVerbs(t *testing.T) {
	dsl := registryModelBlock(t)
	verbs := []string{"v_get", "v_list", "v_create", "v_update", "v_delete"}
	for _, ty := range []string{"registry_registry", "registry_repository"} {
		body := typeBody(t, dsl, ty)
		for _, v := range verbs {
			// match e.g. `define v_create: [user, service_account, group#member] or owner`
			re := regexp.MustCompile(`(?m)^\s*define ` + v + `:.*\bor owner\b`)
			require.Truef(t, re.MatchString(body),
				"%s.%s must derive from `owner` (`… or owner`) so the registry owner "+
					"holds it — else the owner cannot manage their own registry (#64 Defect A). body:\n%s",
				ty, v, body)
		}
	}
}
