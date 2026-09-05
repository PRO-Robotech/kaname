// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// Block-storage retire gate — the iam half.
//
// kacho-storage owns Volume / Snapshot / Image / DiskType. compute used to serve a
// second, independent copy of the same resources; that copy is gone, and
// services/compute/internal/check/retired_block_storage_test.go keeps it gone.
// What that gate deliberately could NOT cover is stated in its own comment: the
// authorization TYPES outlived the resources, because retracting them is an
// iam-side change. This file is that side.
//
// It is a gate on a CLASS, not on three names. Everything is driven from
// retiredBlockStorage below: add a fourth retired type there and every vocabulary,
// every model artefact and every catalog copy is checked for it at once, with no
// other edit. That is the property to preserve — a per-name assertion would close
// today's instance and let tomorrow's through.
//
// WHY EVERY ASSERTION IS PAIRED. "The retired name is absent" is, on its own,
// indistinguishable from "the vocabulary is empty", "the vocabulary moved", and
// "the accessor was renamed and now answers false to everything". Each check
// therefore also asserts that the LIVE owner of the same resources is present in
// the same vocabulary, through the same accessor. A refactor that guts the table
// fails the positive half; a regression that re-adds the retired type fails the
// negative half.
//
// SCOPE, EXACTLY. This gate reads artefacts that live in the repository: iam's
// four Go vocabularies, the canonical authorization model, and the EMBEDDED copy
// the service compiles its decision plan from. It says nothing about rows in a
// running database —
// the seeded system roles, their selectors and the resource mirror are effective
// state, and they are asserted against a real migrated schema in
// services/iam/internal/repo/kacho/pg/retired_block_storage_integration_test.go.
// Neither half is sufficient alone: a vocabulary can be clean while nine bindable
// roles still name the resource, and the rows can be gone while the code still
// advertises the type as grantable.

// retiredType — one retired block-storage type, in both spellings iam uses: the
// dotted `<module>.<resource>` key (role rules, role_rule_selectors.object_types,
// resource_mirror.object_type, AccessBinding target) and the object type of the
// authorization model.
//
// The `fga` field name is historical and stays: the model file is still
// `fga_model.fga` and the spelling is still its own. What changed is WHO reads it —
// the external relation engine is retired; the model is now compiled into the
// decision plan by `internal/authzmodel` and answered out of iam's own tables.
type retiredType struct {
	dotted string
	fga    string
}

// retiredBlockStorage — the block-storage types iam no longer knows. The list is
// the whole subject of this file; see the file comment on why it is a list.
var retiredBlockStorage = []retiredType{
	{dotted: "compute.disk", fga: "compute_disk"},
	{dotted: "compute.image", fga: "compute_image"},
	{dotted: "compute.snapshot", fga: "compute_snapshot"},
}

// liveBlockStorage — the same resources under their present owner. These are the
// positive control of every assertion: they must be found by exactly the accessor
// that must not find the retired ones.
var liveBlockStorage = []retiredType{
	{dotted: "storage.volumes", fga: "storage_volume"},
	{dotted: "storage.snapshots", fga: "storage_snapshot"},
	{dotted: "storage.images", fga: "storage_image"},
}

// TestRetiredListMatchesTheProductionOne — this file's table and the production
// vocabulary the rule-validator enforces (domain.RetiredTypes) must be ONE list.
//
// The two are written separately on purpose: this gate reads artefacts that
// production code never loads (the model file, the generated ConfigMap), and
// domain must stay pure. Separate spellings of the same set, however, are an
// unwatched edit path — retire a fourth resource in one and the other keeps
// admitting it. This assertion is what makes them a single decision.
func TestRetiredListMatchesTheProductionOne(t *testing.T) {
	prod := domain.RetiredTypes()
	require.NotEmpty(t, prod, "domain.RetiredTypes() is empty — the rule-validator would refuse nothing")

	local := make([]string, 0, len(retiredBlockStorage))
	for _, r := range retiredBlockStorage {
		local = append(local, r.dotted)
	}
	sort.Strings(local)
	require.Equal(t, prod, local,
		"this file's retired table and domain.RetiredTypes() disagree — one of them is admitting a "+
			"type the other retired; they must name the same set")
	t.Logf("lockstep: %d retired types, identical in both spellings", len(prod))
}

// splitDotted splits "compute.disk" into ("compute", "disk").
func splitDotted(t *testing.T, dotted string) (string, string) {
	t.Helper()
	i := strings.IndexByte(dotted, '.')
	require.Greater(t, i, 0, "malformed dotted type %q in this gate's own table", dotted)
	return dotted[:i], dotted[i+1:]
}

// TestRetiredBlockStorageIsNotInIAMVocabularies — the four vocabularies iam speaks
// about resource types. A type named in ANY of them is still addressable: it can be
// granted, it can be the target of an AccessBinding, the emitter will write per-verb
// tuples onto it, and the reconciler will materialize it.
func TestRetiredBlockStorageIsNotInIAMVocabularies(t *testing.T) {
	require.NotEmpty(t, retiredBlockStorage, "empty retired list — this gate would assert nothing")
	require.NotEmpty(t, liveBlockStorage, "empty live list — every assertion below would be unpaired")

	// Volume of what was read, so "no finding" is distinguishable from "nothing
	// was inspected": an accessor that answers false to everything would otherwise
	// pass the negative half of all four checks in silence.
	catalog := authzmap.Catalog()
	materializable := domain.AllMaterializableTypes()
	require.NotEmpty(t, catalog, "authzmap.Catalog() is empty — the grantable taxonomy would assert nothing")
	require.NotEmpty(t, materializable, "domain.AllMaterializableTypes() is empty — the feed would assert nothing")
	t.Logf("scanned: authzmap.Catalog()=%d entries, domain.AllMaterializableTypes()=%d types",
		len(catalog), len(materializable))

	// (1) grantable catalog — what iam advertises to clients as grantable, and what
	// the tuple builder derives an FGA object from.
	for _, r := range retiredBlockStorage {
		module, resource := splitDotted(t, r.dotted)
		got, ok := authzmap.ObjectType(module, resource)
		require.Falsef(t, ok, "authzmap.ObjectType(%q, %q) still resolves to %q — the retired resource is still advertised as grantable; kacho-storage owns it",
			module, resource, got)
	}
	for _, l := range liveBlockStorage {
		module, resource := splitDotted(t, l.dotted)
		got, ok := authzmap.ObjectType(module, resource)
		require.Truef(t, ok, "authzmap.ObjectType(%q, %q) does not resolve — the live owner of this resource must be grantable, or the negative half above proves nothing",
			module, resource)
		require.Equalf(t, l.fga, got, "authzmap.ObjectType(%q, %q) resolved to %q, expected %q", module, resource, got, l.fga)
	}

	// (2) per-verb emission guard — whether the emitter may write v_* onto the type.
	for _, r := range retiredBlockStorage {
		require.Falsef(t, authzmap.TypeHasVerbRelations(r.fga),
			"authzmap.TypeHasVerbRelations(%q) is still true — the emitter would write per-verb tuples onto a type no resource produces", r.fga)
	}
	for _, l := range liveBlockStorage {
		require.Truef(t, authzmap.TypeHasVerbRelations(l.fga),
			"authzmap.TypeHasVerbRelations(%q) is false — the live owner must be verb-bearing, or the negative half above proves nothing", l.fga)
	}

	// (3) AccessBinding target whitelist — what a binding may name as its target.
	//
	// The live control here USED to be compute.instance rather than the storage
	// types, because the target predicate re-spelled the dotted form into the
	// scope-anchor vocabulary and that vocabulary never carried storage: the
	// successor of the retired resources could not be named as a per-object target
	// at all, so the only expressible grant on a volume was the whole anchor. That
	// was recorded here as a separate defect, and it has since been fixed — the
	// predicate now resolves against the materialization feed, the one vocabulary
	// the reconciler actually compares a target against
	// (domain/access_binding_target_vocabulary_test.go holds it for every type).
	//
	// So the control is now the present OWNER of these resources, which is what
	// this file asserts everywhere else: the retire moved the per-object grant, it
	// did not remove it.
	//
	// domain.ResourceType keeps answering for the scope anchor — a different
	// question — but its control is NO LONGER compute_instance, and the reason is
	// the finding itself. The anchor vocabulary is the three hierarchy tiers; a
	// per-object type was never producible as an anchor. It answered true here only
	// because the anchor whitelist was a second, diverged copy carrying 20
	// unreachable entries, so this control was pairing a real negative with a
	// positive that WAS the defect. The whitelist is removed (#1092) and the
	// control is an actual anchor, which is what "the predicate is not false for
	// everything" needs.
	for _, r := range retiredBlockStorage {
		require.Falsef(t, domain.ValidTargetType(r.dotted),
			"domain.ValidTargetType(%q) is still true — an AccessBinding may still target the retired resource", r.dotted)
		require.Errorf(t, domain.ResourceType(r.fga).Validate(),
			"domain.ResourceType(%q).Validate() still accepts the retired type", r.fga)
	}
	for _, l := range liveBlockStorage {
		require.Truef(t, domain.ValidTargetType(l.dotted),
			"domain.ValidTargetType(%q) is false — block storage lost its per-object grant instead of moving it to its present owner, and the negative half above proves nothing", l.dotted)
	}
	require.True(t, domain.ValidTargetType("compute.instance"),
		"domain.ValidTargetType(\"compute.instance\") is false — the live sibling must be targetable, or the negative half above proves nothing")
	require.NoError(t, domain.ResourceType("project").Validate(),
		"domain.ResourceType(\"project\").Validate() rejects a hierarchy tier — the anchor vocabulary is damaged and the negative half above proves nothing")
	require.Error(t, domain.ResourceType("compute_instance").Validate(),
		"domain.ResourceType(\"compute_instance\").Validate() accepts a per-object type as a scope ANCHOR — no write path produces one")

	// (4) label-selectable / materializable feed — what the reconciler may
	// materialize per object, and what a `*.*` wildcard rule expands to.
	inMaterializable := make(map[string]bool, len(materializable))
	for _, ty := range materializable {
		inMaterializable[ty] = true
	}
	for _, r := range retiredBlockStorage {
		require.Falsef(t, domain.IsLabelSelectableType(r.dotted),
			"domain.IsLabelSelectableType(%q) is still true — a match_labels rule may still select the retired resource", r.dotted)
		require.Falsef(t, inMaterializable[r.dotted],
			"domain.AllMaterializableTypes() still contains %q — every wildcard system-role selector expands onto it", r.dotted)
	}
	for _, l := range liveBlockStorage {
		require.Truef(t, domain.IsLabelSelectableType(l.dotted),
			"domain.IsLabelSelectableType(%q) is false — the live owner must be label-selectable, or the negative half above proves nothing", l.dotted)
		require.Truef(t, inMaterializable[l.dotted],
			"domain.AllMaterializableTypes() lacks %q — the live owner must be materializable, or the negative half above proves nothing", l.dotted)
	}
}

// canonicalModelRelPath / embeddedModelRelPath — the two authorization-model
// artefacts in the tree. The first is the source; the second is the copy the
// service EXECUTES — it is what `internal/authzmodel` compiles the decision plan
// from, so both have to be checked.
//
// The second path used to be the generated bootstrap ConfigMap: the block a Job
// sent to the external relation engine. That engine is retired, the sub-chart is
// gone with it, and its artefact no longer exists — but the property this gate
// held does. It simply got SHARPER: the second copy is no longer "what we shipped
// to somebody else's store", it is "what answers the question". A retired type
// surviving there is not stale packaging, it is a live declaration.
//
// Do NOT collapse this to a single path. The two copies are kept byte-identical
// by `make -C deploy fga-model-embed`; a gate reading only one of them would stay
// green while the other drifted, which is the exact failure the pair exists to
// catch.
const (
	canonicalModelRelPath = "proto/kacho/cloud/iam/v1/fga_model.fga"
	embeddedModelRelPath  = "services/iam/internal/authzmodel/fga_model.fga"
)

// monorepoRoot walks up from the package directory to the module root.
func monorepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	dir := wd
	// Корнем берётся САМЫЙ ВНЕШНИЙ `go.mod`, а не первый встречный: у службы
	// теперь СВОЙ модуль (она выносится отдельным репозиторием), и подъём «до
	// первого» останавливался бы в её каталоге. Пути, которые ниже склеиваются с
	// этим корнем, называют место В ДЕРЕВЕ МОНОРЕПО — от корня, — поэтому
	// остановка внутри службы удваивала сегмент и обход искал `services/iam/
	// services/iam/…`, которого не существует.
	outermost := ""
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			outermost = dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			if outermost != "" {
				return outermost
			}
			t.Fatalf("monorepo root (go.mod) not found walking up from %s", wd)
		}
		dir = parent
	}
}

var reModelType = regexp.MustCompile(`(?m)^\s*type (\w+)\s*$`)

// declaredTypes returns the set of `type <name>` declarations in an FGA DSL text.
// The leading-whitespace tolerance is deliberate: the ConfigMap carries the same
// DSL indented by four spaces.
func declaredTypes(dsl string) map[string]bool {
	out := map[string]bool{}
	for _, m := range reModelType.FindAllStringSubmatch(dsl, -1) {
		out[m[1]] = true
	}
	return out
}

// TestRetiredBlockStorageIsNotInAuthorizationModel — the declaration itself, in
// both artefacts. This is the step the compute-side gate explicitly refused to
// authorize, and it is only safe once the vocabularies above are clean: a declared
// type that nothing emits onto is dead weight, but an emitted type that is not
// declared is a question the relational form REFUSES to answer — an error, not a
// denial (`relverdict.Ask` has no plan for it).
func TestRetiredBlockStorageIsNotInAuthorizationModel(t *testing.T) {
	root := monorepoRoot(t)

	canonical, err := os.ReadFile(filepath.Join(root, canonicalModelRelPath))
	require.NoError(t, err, "canonical authorization model %s is missing — this gate has no source of truth", canonicalModelRelPath)
	embRaw, err := os.ReadFile(filepath.Join(root, embeddedModelRelPath))
	require.NoError(t, err, "embedded authorization model %s is missing — the executed model cannot be checked", embeddedModelRelPath)

	canonicalTypes := declaredTypes(string(canonical))
	require.NotEmpty(t, canonicalTypes, "canonical model parsed to zero types — parser or model is broken")
	embTypes := declaredTypes(string(embRaw))
	require.NotEmpty(t, embTypes, "embedded model parsed to zero types — parser or artefact is broken")
	t.Logf("scanned: %s declares %d types, %s declares %d types",
		canonicalModelRelPath, len(canonicalTypes), embeddedModelRelPath, len(embTypes))

	for _, r := range retiredBlockStorage {
		require.Falsef(t, canonicalTypes[r.fga], "%s still declares `type %s` — the authorization type outlives the resource", canonicalModelRelPath, r.fga)
		require.Falsef(t, embTypes[r.fga], "%s still declares `type %s` — the EXECUTED model outlives the resource", embeddedModelRelPath, r.fga)
	}
	for _, l := range liveBlockStorage {
		require.Truef(t, canonicalTypes[l.fga], "%s does not declare `type %s` — the live owner must be declared, or the negative half above proves nothing", canonicalModelRelPath, l.fga)
		require.Truef(t, embTypes[l.fga], "%s does not declare `type %s` — the live owner must be declared, or the negative half above proves nothing", embeddedModelRelPath, l.fga)
	}

	// A third arm stood here: the JSON transform of the model, the block a Job
	// POSTed to the external relation engine. Its predicate was "the DSL copy can be
	// right while the transform is stale". There is no transform any more — the
	// service reads the DSL directly — so the arm had nothing left to disagree with.
	// It is removed with its subject rather than left asserting over an artefact
	// that no longer exists.
}

// TestRetiredBlockStorageIsNotInPermissionCatalog — both embedded copies of the
// permission catalog. They are required to be byte-identical, so checking one
// would let the other drift while this gate stayed green.
func TestRetiredBlockStorageIsNotInPermissionCatalog(t *testing.T) {
	root := monorepoRoot(t)
	copies := []string{
		filepath.Join("gateway", "internal", "middleware", "embed", "permission_catalog.json"),
		filepath.Join("services", "iam", "internal", "apps", "kacho", "seed", "embedded", "permission_catalog.json"),
	}

	type entry struct {
		FQN            string `json:"fqn"`
		Permission     string `json:"permission"`
		ScopeExtractor *struct {
			ObjectType string `json:"object_type"`
		} `json:"scope_extractor"`
	}

	for _, rel := range copies {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		require.NoError(t, err, "permission catalog copy %s is missing", rel)
		var rows []entry
		require.NoError(t, json.Unmarshal(raw, &rows), "decode %s", rel)
		require.NotEmpty(t, rows, "%s decoded to zero entries — this gate would assert nothing", rel)
		t.Logf("scanned: %s has %d entries", rel, len(rows))

		liveSeen := 0
		for _, row := range rows {
			for _, r := range retiredBlockStorage {
				module, resource := splitDotted(t, r.dotted)
				// Permissions are `<module>.<resourcePlural>.<verb>`; the dotted
				// authz key is singular, so match on the module+resource stem.
				require.Falsef(t, strings.HasPrefix(row.Permission, module+"."+resource),
					"%s still carries permission %q on %s — the retired resource is still on the contract", rel, row.Permission, row.FQN)
				if row.ScopeExtractor != nil {
					require.NotEqualf(t, r.fga, row.ScopeExtractor.ObjectType,
						"%s still scopes %s to retired object type %q", rel, row.FQN, r.fga)
				}
			}
			for _, l := range liveBlockStorage {
				if row.ScopeExtractor != nil && row.ScopeExtractor.ObjectType == l.fga {
					liveSeen++
				}
			}
		}
		require.NotZerof(t, liveSeen, "%s scopes no RPC to any live block-storage object type — the negative half above proves nothing", rel)
	}
}
