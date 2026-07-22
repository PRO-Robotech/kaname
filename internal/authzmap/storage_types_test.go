// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzmap_test

import (
	"context"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
)

// storageDottedToFGA — the dotted closed-table key (resource_mirror.object_type,
// derived by RegisterResource via DottedType) → FGA object_type. The dotted
// segments mirror the plural catalog permission form (storage.volumes.*).
var storageDottedToFGA = map[string]string{
	"storage.volumes":   "storage_volume",
	"storage.snapshots": "storage_snapshot",
	"storage.images":    "storage_image",
}

// TestStorageTypes_WiredForReconciler locks the Go-side wiring that the owner-
// materialization path depends on. The model type alone is INSUFFICIENT: storage
// RegisterResource sends `Object="storage_volume:<id>"`; iam's tupleIntent.objectType
// maps the FGA prefix back to the dotted mirror key via authzmap.DottedType, stores
// it in resource_mirror.object_type, and the reconciler resolves it FORWARD via
// authzmap.FGAObjectType before gating v_* emission on TypeHasVerbRelations. If any
// of ObjectType / DottedType (round-trip) / TypeHasVerbRelations is missing for a
// storage type, ReconcileObjectForward drops the object (fgaObjectType ok=false) or
// emits no verbs → the owner's per-object v_get never materializes → owner-GET 403
// (the exact #71 fail-closed gap). This test would have caught the gap the model
// change alone leaves open.
func TestStorageTypes_WiredForReconciler(t *testing.T) {
	for dotted, fga := range storageDottedToFGA {
		// forward: dotted → FGA (reconciler's fgaObjectType)
		got, ok := authzmap.FGAObjectType(dotted)
		require.Truef(t, ok, "FGAObjectType(%q) ok=false — reconciler drops the mirror object → no owner v_* (#71)", dotted)
		require.Equal(t, fga, got, "FGAObjectType(%q) mismatch", dotted)

		// reverse: FGA → dotted (RegisterResource's DottedType, feeding the mirror key)
		back, ok := authzmap.DottedType(fga)
		require.Truef(t, ok, "DottedType(%q) ok=false — mirror stores the FGA prefix verbatim (no dot) → FGAObjectType fails → no materialization (#71)", fga)
		require.Equalf(t, dotted, back, "DottedType(%q) must round-trip to %q so the mirror key resolves forward", fga, dotted)

		// verb-bearing: gate the reconciler emits v_* through
		require.Truef(t, authzmap.TypeHasVerbRelations(fga),
			"%s must be verb-bearing (TypeHasVerbRelations) so the reconciler materializes per-object v_* for the owner (#71)", fga)
	}
}

// storage_types_test.go — regression lock for #71.
//
// kacho-storage's owner-registration edge (storage→iam RegisterResource, SEC-D /
// CS-1 GAP-D) emits a `storage_<t>:<id> #project @project:<proj>` owner-hierarchy
// tuple for every Volume / Snapshot / Image (services/storage/.../fgaregister.go,
// relationProject) — exactly like nlb emits it for nlb_network_load_balancer /
// nlb_listener. But the FGA model defined NO `storage_volume` / `storage_image` /
// `storage_snapshot` TYPE AT ALL. OpenFGA therefore REJECTED every storage
// owner-tuple ("type 'storage_volume' not found") → the iam fga_outbox drainer
// dead-lettered it (permanent-poison, no retry) → the resource's project hierarchy
// never materialized → the reconciler could not materialize per-object v_* for the
// creator → the gateway anti-BOLA scope_extractor `{storage_volume, volume_id}` on
// Volume/Snapshot/Image Get/Update/Delete could not resolve target→project → the
// per-object Check `storage_volume:<id>#viewer@user` errored → production fail-closed
// → **403 for the OWNER on their OWN just-created volume** (verified live: owner-GET
// 403 "no authorization path", cross-GET 403 — fail-CLOSED over-denial, not BOLA).
//
// Same defect class as #68 (nlb_listener missing `project` relation) and #64
// Defect A (registry dangling `owner`): an emitter↔model mismatch. Fix = add the
// three storage types with `project: [project]` + DIRECT v_* (Contract-A), parity
// with nlb_network_load_balancer / nlb_target_group. Storage emits ONLY the
// `project` tuple (no `owner` tuple — unlike registry), so the verbs are DIRECT and
// the reconciler materializes them per-object from the creator's project binding;
// an `or owner` derivation would be an inert dead relation here (LEAN / ban #11).

var storageTypes = []string{"storage_volume", "storage_image", "storage_snapshot"}

// TestStorageModel_DefinesTypesAndProjectRelation asserts the three storage FGA
// object-types exist and each carries a `project: [project]` relation plus the
// DIRECT v_* verb-set — so the storage-emitted project owner-tuple is a valid FGA
// write (no dead-letter poison) and the reconciler can materialize owner access.
func TestStorageModel_DefinesTypesAndProjectRelation(t *testing.T) {
	dsl := registryModelBlock(t) // whole model.fga DSL block (helper name is historical)
	proj := regexp.MustCompile(`(?m)^\s*define project:\s*\[project\]`)
	verbs := []string{"v_get", "v_list", "v_create", "v_update", "v_delete"}

	for _, ty := range storageTypes {
		body := typeBody(t, dsl, ty) // fails loudly if the type is absent
		require.Truef(t, proj.MatchString(body),
			"%s must define `project: [project]` so the storage-emitted project owner-hierarchy "+
				"tuple is a valid FGA write (no dead-letter poison), parity with "+
				"nlb_network_load_balancer / nlb_listener (#71). body:\n%s", ty, body)
		for _, v := range verbs {
			// DIRECT verb (matches `define v_get: [user, service_account, group#member]`);
			// storage emits no `owner` tuple, so verbs must NOT hang off a dangling `owner`.
			re := regexp.MustCompile(`(?m)^\s*define ` + v + `:\s*\[`)
			require.Truef(t, re.MatchString(body),
				"%s must define a DIRECT `%s: [...]` verb (reconciler materializes it per-object "+
					"from the creator's project binding). body:\n%s", ty, v, body)
			// (в) NO `or owner` dead branch: storage never emits an owner tuple, so an
			//     `… or owner` derivation would be an inert, misleading dead relation
			//     (LEAN / ban #11). Lock it out — parity with nlb, NOT registry.
			deadOwner := regexp.MustCompile(`(?m)^\s*define ` + v + `:.*\bor owner\b`)
			require.Falsef(t, deadOwner.MatchString(body),
				"%s.%s must NOT derive from `owner` — storage emits no owner tuple, so `or owner` "+
					"is an inert dead relation (parity with nlb, not registry; LEAN/ban#11). body:\n%s",
				ty, v, body)
		}
		// The `owner` relation itself must be absent from the storage type (nothing
		// emits or derives from it).
		require.Falsef(t, regexp.MustCompile(`(?m)^\s*define owner:`).MatchString(body),
			"%s must NOT declare an `owner` relation (storage emits project-only; no owner). body:\n%s", ty, body)
	}
}

// TestStorageModel_ProjectTuple_OpenFGACheck loads the DEPLOYED model into a real
// OpenFGA and proves #71 end-to-end for each storage type: (1) the storage-emitted
// `storage_<t> #project @project` tuple is a VALID write (pre-fix OpenFGA rejected
// it → drainer poison), (2) a materialized owner resolves the resource's v_* verbs
// (the anti-BOLA object-self path the gateway takes for Get/Update/Delete), and
// (3) a cross-account subject is denied (the project link leaks no access — the
// live 403 for the owner was a fail-CLOSED gap, never an over-grant). Real OpenFGA
// container; skipped under -short.
func TestStorageModel_ProjectTuple_OpenFGACheck(t *testing.T) {
	h := fgatest.NewFromModelJSON(t, readConfigMapModelJSON(t))
	ctx := context.Background()

	for _, ty := range storageTypes {
		ty := ty
		t.Run(ty, func(t *testing.T) {
			obj := ty + ":res-71test"

			// (1) The project owner-hierarchy tuple storage emits is now a valid FGA
			//     write. h.Write t.Fatalf's on an OpenFGA reject — pre-#71 this failed
			//     with "type '" + ty + "' not found".
			h.Write(t, "project:prj-71test", "project", obj)

			// (2) Owner's materialized DIRECT v_* resolves (the object-self scope the
			//     gateway Checks for Get/Update/Delete).
			h.Write(t, "service_account:sva-owner71", "v_get", obj)
			h.Write(t, "service_account:sva-owner71", "v_update", obj)
			h.Write(t, "service_account:sva-owner71", "v_delete", obj)
			for _, rel := range []string{"v_get", "v_update", "v_delete"} {
				ok, err := h.Client.CheckWithContextConsistent(ctx, "service_account:sva-owner71", rel, obj, nil)
				require.NoError(t, err)
				require.Truef(t, ok, "%s owner must resolve %s (object-self anti-BOLA path)", ty, rel)
			}

			// (3) A cross-account SA with no tuple on this object is DENIED — the
			//     project relation is a structural hierarchy link, not a grant.
			for _, rel := range []string{"v_get", "v_update", "v_delete"} {
				ok, err := h.Client.CheckWithContextConsistent(ctx, "service_account:sva-cross71", rel, obj, nil)
				require.NoError(t, err)
				require.Falsef(t, ok, "cross-account SA must NOT resolve %s on %s", rel, ty)
			}
		})
	}
}
