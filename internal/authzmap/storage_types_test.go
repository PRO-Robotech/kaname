// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap_test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
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
	dsl := modelDSL(t) // canonical model DSL (single source of truth)
	proj := regexp.MustCompile(`(?m)^\s*define project:\s*\[project\]`)

	for _, ty := range storageTypes {
		// Набор берётся У ТИПА, а не выписывается. Литерал, стоявший здесь, называл
		// `v_create`; хранилище его больше не объявляет — создание тома/снимка/образа
		// авторизуется ярусом записи на проекте, а не пообъектным глаголом на самом
		// томе, которого в момент решения ещё нет.
		verbs := authzmap.VerbRelationsOfType(ty)
		require.NotEmptyf(t, verbs, "тип %q не объявляет ни одного глагольного отношения", ty)
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

// Здесь стояла TestStorageModel_ProjectTuple_OpenFGACheck: она грузила заготовку
// модели из карты чарта загрузки движка отношений в поднятый контейнером движок и
// утверждала три вещи — что указатель на проект есть ВАЛИДНАЯ запись, что владелец
// разрешает глаголы объекта, и что субъект соседнего аккаунта их не разрешает.
//
// Первое снято ВМЕСТЕ СО СВОИМ ПРЕДМЕТОМ: движка, который мог бы отвергнуть запись
// «тип не найден», в дереве нет, а прямой факт своей базы словаря типов не держит —
// отвергать стало нечему и некому. Два оставшихся живы и проверяются формой вердикта
// в super_admin_cascade_test.go: все ТРИ типа хранилища стоят в переписи объектов её
// мира (`storage_volume`, `storage_snapshot`, `storage_image`), поэтому «достаёт по
// указателю» и «сосед не достаёт» утверждаются там на тех же типах и тем же вопросом,
// каким его задаёт продукт. Двух мест об одном предмете здесь не заводится.
//
// Структурное утверждение выше при этом стало НЕСУЩИМ: план вывода `storage_*.v_*`
// компилируется из той самой строки `define project`, и без неё тип потеряет источники
// «аккаунт» и «кластер» — то есть каскад до тома, снимка и образа просто исчезнет.
