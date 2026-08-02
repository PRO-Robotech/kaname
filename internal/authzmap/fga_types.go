// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// fga_types.go — closed (module, resource) → fga_object_type table.
//
// RBAC v2. Every concrete-resourceName permission emits a
// direct per-object FGA tuple at the type returned here. Wildcard-
// resourceName permissions emit a tier tuple at the binding's scope
// anchor instead, and the returned ok is false when the pair is unknown
// — the caller falls back to the scope-anchor.
//
// Extending this table requires declaring the type in the canonical
// authorization model `proto/kacho/cloud/iam/v1/fga_model.fga` in lockstep, and
// regenerating the openfga-bootstrap ConfigMap from it (`make
// openfga-model-json` in deploy/). The unconditional drift-gate
// (fga_model_drift_test.go) fails the build on any divergence, in either
// direction. The table is intentionally a closed enumeration: an unknown pair
// must NOT silently land as an arbitrary FGA type.
package authzmap

import (
	"sort"
	"strings"
)

// ObjectType returns the OpenFGA object_type for (module, resource).
// ok=false when the pair is not in the closed table.
func ObjectType(module, resource string) (string, bool) {
	o, ok := objectTypes[module+"."+resource]
	return o, ok
}

// FGAObjectType resolves the OpenFGA object_type for a dotted closed-table key
// ("vpc.securityGroup" → "vpc_security_group", "iam.account" → "account"). It is
// the single canonical dotted→FGA-type mapping (SplitObjectType on the FIRST dot,
// then ObjectType over the closed table) shared by every FGA-object derivation —
// the reconciler's tuple builder and the verify-gate's ledger lookup both route
// through it so their object keys cannot drift. ok=false when the dotted key is not
// in the closed table (callers must NOT fall back to a hand-rolled substitution —
// an unknown type must surface as ok=false, never as an arbitrary FGA type).
func FGAObjectType(dotted string) (string, bool) {
	module, resource, ok := SplitObjectType(dotted)
	if !ok {
		return "", false
	}
	return ObjectType(module, resource)
}

// CatalogEntry — one grantable (module, resource) pair from the closed
// objectTypes table. The dotted key "module.resource" is the canonical token
// form; Module / Resource are its two segments (split on the FIRST dot, same as
// SplitObjectType).
type CatalogEntry struct {
	Module   string
	Resource string
}

// Catalog returns every grantable (module, resource) pair in the closed
// objectTypes table, in a deterministic order (sorted by the dotted
// "module.resource" key). It is the SINGLE exported source of the grantable
// taxonomy — the PermissionCatalogService projects EXACTLY this set
// (no additions, no omissions), so a future objectTypes entry appears in the
// public catalog with no catalog-code change. Pairing it with ObjectType /
// TypeHasVerbRelations gives the per-type FGA object_type and verb-bearing flag.
func Catalog() []CatalogEntry {
	keys := make([]string, 0, len(objectTypes))
	for k := range objectTypes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]CatalogEntry, 0, len(keys))
	for _, k := range keys {
		module, resource, ok := SplitObjectType(k)
		if !ok {
			// objectTypes keys are always well-formed "module.resource"; an
			// unsplittable key would be a table-authoring error. Skip defensively
			// rather than emit a malformed catalog pair.
			continue
		}
		out = append(out, CatalogEntry{Module: module, Resource: resource})
	}
	return out
}

// SplitObjectType splits a dotted "module.resource" key on the FIRST dot
// (the resource segment may itself contain no dot; module never does). ok=false
// when the input has no dot or an empty side. Single source of truth shared by
// the tuple builders in access_binding and access_binding/reconcile (previously
// duplicated in both — unified into one helper so the two paths cannot drift).
func SplitObjectType(typ string) (module, resource string, ok bool) {
	i := strings.IndexByte(typ, '.')
	if i <= 0 || i == len(typ)-1 {
		return "", "", false
	}
	return typ[:i], typ[i+1:], true
}

// DottedType maps an OpenFGA object_type (e.g. "compute_instance") back to the
// dotted closed-table key (e.g. "compute.instance") used by role_rule_selectors
// and resource_mirror.object_type. ok=false when the FGA type is not in the
// closed table — callers may then fall back to the FGA type verbatim (the mirror
// keeps a generic opaque object_type). Reverse of ObjectType.
func DottedType(fgaType string) (string, bool) {
	d, ok := dottedByFGAType[fgaType]
	return d, ok
}

// dottedByFGAType — reverse index of objectTypes, built once at init. Last-wins
// is irrelevant: objectTypes values are unique (each FGA type maps from exactly
// one dotted key).
var dottedByFGAType = func() map[string]string {
	m := make(map[string]string, len(objectTypes))
	for dotted, fga := range objectTypes {
		m[fga] = dotted
	}
	return m
}()

// TypeHasVerbRelations reports whether the FGA object_type carries the closed
// per-verb relation set (v_get/v_list/v_create/v_update/v_delete) in the
// canonical authorization model.
//
// rbac-explicit-model-2026 P3 / D-6 (expand): the hierarchy ancestors
// `account` / `project` are now ALSO verb-bearing — the canonical fga_model.fga
// (P2) defines the full v_* set on both, so a grant of e.g. `iam.account.get`
// materializes `account:<id> # v_get @ subj` (object-level access to the
// account itself, NO cascade to its contents — D-2). This is purely ADDITIVE:
// account/project KEEP their tier relations (admin/editor/viewer, the
// write-authz anchors — D-7) and the scope_grant carrier still operates exactly
// as before. Only the v_* emission gate flips for these two types.
//
// This is the single source of truth the FGA emitter consults before writing a
// per-verb `v_<verb>` tuple or a type-scoped `scope_grant` linking tuple:
// emitting either on a tier-only type is a dangling-relation write that OpenFGA
// rejects → drainer.ErrPermanent → poisoned fga_outbox → partial-grant desync
// (the #177 fail-open class). The set is kept in lockstep with fga_model.fga;
// the CI drift-gate (authzmap/fga_model_drift_test.go) fails the build if this
// set ever diverges from the model.
func TypeHasVerbRelations(fgaType string) bool {
	return len(typeVerbRelations[fgaType]) > 0
}

// VerbRelationsOfType — имена `v_*`-отношений, которые канонический fga_model.fga
// определяет У ЭТОГО типа, в детерминированном (отсортированном) порядке; nil для
// неглагольного типа.
//
// Это ЕДИНСТВЕННЫЙ источник набора для эмиссии: набор есть атрибут ТИПА, а не
// платформенная константа. Возвращается КОПИЯ — вызывающий не вправе испортить
// источник истины эмиссии.
func VerbRelationsOfType(fgaType string) []string {
	set := typeVerbRelations[fgaType]
	if len(set) == 0 {
		return nil
	}
	out := make([]string, len(set))
	copy(out, set)
	return out
}

// VerbsOfType — ГЛАГОЛЫ (без приставки `v_`), объявленные этим типом,
// отсортированно; nil для неглагольного типа.
//
// Та же таблица, что и VerbRelationsOfType, но в форме, на которой говорит домен:
// домен оперирует глаголами правила, модель — именами отношений. Приведение живёт
// ЗДЕСЬ, у владельца таблицы, а не размножается по вызывающим.
func VerbsOfType(fgaType string) []string {
	set := typeVerbRelations[fgaType]
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for _, r := range set {
		out = append(out, strings.TrimPrefix(r, VerbRelationPrefix))
	}
	sort.Strings(out)
	return out
}

// CommonVerbVocabulary — ГЛАГОЛЫ (без приставки `v_`), общие ДЛЯ ВСЕХ глагольных
// типов, то есть ПЕРЕСЕЧЕНИЕ их наборов, отсортированно.
//
// Именно это значение проецируется публичным полем каталога прав. Пока все типы
// несут один набор, пересечение равно ему. С появлением типа с расширенным набором
// пересечение сузится — и это верное поведение поля: оно объявлено как набор,
// общий для всех ресурсов, а не как перечень всех существующих глаголов.
func CommonVerbVocabulary() []string {
	var common map[string]bool
	for _, set := range typeVerbRelations {
		if len(set) == 0 {
			continue
		}
		in := make(map[string]bool, len(set))
		for _, r := range set {
			in[r] = true
		}
		if common == nil {
			common = in
			continue
		}
		for r := range common {
			if !in[r] {
				delete(common, r)
			}
		}
	}
	out := make([]string, 0, len(common))
	for r := range common {
		out = append(out, strings.TrimPrefix(r, VerbRelationPrefix))
	}
	sort.Strings(out)
	return out
}

// VerbRelationPrefix — приставка имени глагольного отношения модели. Она же —
// форма, в которой глагол попадает в кортеж.
const VerbRelationPrefix = "v_"

// fullCrudVerbRelations — набор, который на сегодня объявляет КАЖДЫЙ глагольный
// тип. Это НЕ платформенная константа «набор всех глаголов»: это значение, которое
// 24 типа пока СОВПАДАЮЩЕ объявляют. Тип вправе объявить другой набор — и гейт
// сверит его с моделью ПОТИПОВО, а не с этим литералом.
var fullCrudVerbRelations = []string{"v_create", "v_delete", "v_get", "v_list", "v_update"}

// typeVerbRelations — НАБОР `v_*`-отношений, объявленный КАЖДЫМ типом.
//
// Прежняя редакция таблицы была булевой («несёт полный набор либо ни одного»), и
// это было её СВОЙСТВОМ: набор одного типа не мог отличаться от набора другого,
// потому что набора у типа не было вовсе — была платформенная константа. Теперь
// набор объявлен у типа, а его полнота и точное совпадение с канонической моделью —
// требование ГЕЙТА (fga_model_drift_test.go: TestDrift_TypeVerbSetsMatchModelExactly),
// а не следствие устройства таблицы. Читателю: НЕ «чините» таблицу обратно в булеву
// — гейт требует ровно того же свойства, но проверяемо и по каждому типу отдельно.
//
// Типы перечислены явно (не выводятся вычитанием), чтобы новая запись objectTypes
// НЕ унаследовала глагольность молча — гейт дрейфа вынуждает принять решение здесь.
//
// rbac-explicit-model-2026 P3 / D-6: `account` и `project` глагольные (канонический
// fga_model.fga определяет на обоих полный набор `v_*`, P2). Они ОСТАЮТСЯ ярусными
// предками иерархии (admin/editor/viewer — якоря write-authz, D-7); глагольность
// добавлена сверху, а не вместо.
var typeVerbRelations = map[string][]string{
	"compute_instance":          fullCrudVerbRelations,
	"vpc_network":               fullCrudVerbRelations,
	"vpc_subnet":                fullCrudVerbRelations,
	"vpc_address":               fullCrudVerbRelations,
	"vpc_security_group":        fullCrudVerbRelations,
	"vpc_route_table":           fullCrudVerbRelations,
	"vpc_gateway":               fullCrudVerbRelations,
	"vpc_network_interface":     fullCrudVerbRelations,
	"vpc_address_pool":          fullCrudVerbRelations,
	"nlb_network_load_balancer": fullCrudVerbRelations,
	"nlb_target_group":          fullCrudVerbRelations,
	"nlb_listener":              fullCrudVerbRelations,
	"registry_registry":         fullCrudVerbRelations,
	"registry_repository":       fullCrudVerbRelations,
	// storage (kacho-storage) — Volume/Snapshot/Image per-object authz objects.
	// Verb-bearing so the reconciler materializes per-object v_* for the creator's
	// project binding — the model type + these Go tables + knownModules("storage")
	// are ALL required or owner-GET fail-closes 403 (#71). Parity with nlb (project-
	// only emitter, DIRECT v_*, no `owner` derivation).
	"storage_volume":      fullCrudVerbRelations,
	"storage_snapshot":    fullCrudVerbRelations,
	"storage_image":       fullCrudVerbRelations,
	"iam_user":            fullCrudVerbRelations,
	"iam_service_account": fullCrudVerbRelations,
	"iam_group":           fullCrudVerbRelations,
	"iam_role":            fullCrudVerbRelations,
	"iam_access_binding":  fullCrudVerbRelations,
	// rbac-2026 P3 / D-6: account/project are now verb-bearing (additive — they
	// also keep their tier relations as write-authz anchors, D-7).
	"account": fullCrudVerbRelations,
	"project": fullCrudVerbRelations,
}

// expandableRelations — the closed set of FGA relation names a caller may pass
// to ExpandAccess ("who can do <relation> on <object>"). It is the user-facing
// authorization-decision surface of the canonical fga_model.fga:
//
//   - per-verb leaf relations : v_get / v_list / v_create / v_update / v_delete
//     (the granular CRUD relations every verb-bearing resource type defines).
//   - tier relations          : viewer / editor / admin
//     (the hierarchy-tier relations; admin ⇒ editor ⇒ viewer in the model).
//   - group membership        : member (so "who is a member of group:G" expands).
//
// It deliberately EXCLUDES the model's internal machinery — the scope_grant
// carriers (sg_*), the pull-up resolvers (g_admin_* / g_editor_* / g_vcreate_*),
// and the platform-role relations (system_admin / fga_writer / owner / use / …):
// those are emitter-internal plumbing, not relations a tenant audits "who can do
// X" against. Forwarding an arbitrary string into the FGA Read would let a caller
// probe the model's internal relation graph — ExpandAccess validates against this
// set and rejects anything else with INVALID_ARGUMENT.
//
// XC-3 S1Ф2: глагольная часть больше НЕ перечисляется — она выводится из наборов
// типов, поэтому список не может отстать от модели. Обе стороны запрета
// (принимаемое ⊆ модель, машинерия ∉ принимаемое) держит гейт дрейфа
// (authzmap/fga_model_drift_test.go).
// expandableTierRelations / expandableMembershipRelation — НЕглагольная часть
// поверхности. Глагольная часть не перечисляется: она ВЫВОДИТСЯ как объединение
// наборов всех типов (см. expandableRelations ниже).
var expandableTierRelations = []string{"viewer", "editor", "admin"}

const expandableMembershipRelation = "member"

// expandableRelations — ВЫВОДИМОЕ множество: объединение наборов `v_*` всех
// глагольных типов ∪ ярусные ∪ членство.
//
// Прежде глагольная часть перечислялась отдельным литералом, поэтому новое
// отношение у типа пришлось бы дописывать сюда руками — место, о котором надо не
// забыть, и о котором не напоминает ничто. Теперь: объявил тип отношение — оно
// появилось в принимаемых; снял — исчезло.
//
// Множество остаётся РАСШИРЯЕМЫМ, а не ОТКРЫТЫМ. Внутренняя машинерия модели
// по-прежнему вне его: переносчики охвата (sg_*), подтягивающие резолверы
// (g_admin_* / g_editor_* / g_vcreate_*) и платформенные отношения (system_admin /
// fga_writer / owner / use / …) — эмиттерная сантехника, а не поверхность, против
// которой тенант спрашивает «кто может делать X». Обратная проверка этого запрета
// живёт в гейте дрейфа (TestDrift_ExpandableRelationsMatchModel) и доказана
// инъекцией: объявление машинерии принимаемой краснеет с координатой.
var expandableRelations = func() map[string]bool {
	m := make(map[string]bool, len(expandableTierRelations)+1)
	for _, set := range typeVerbRelations {
		for _, r := range set {
			m[r] = true
		}
	}
	for _, r := range expandableTierRelations {
		m[r] = true
	}
	m[expandableMembershipRelation] = true
	return m
}()

// IsExpandableRelation reports whether `relation` is in the closed set of
// relations ExpandAccess accepts (see expandableRelations). An unknown relation
// must be rejected by the caller with INVALID_ARGUMENT (no probing of
// arbitrary FGA relation strings).
func IsExpandableRelation(relation string) bool {
	return expandableRelations[relation]
}

var objectTypes = map[string]string{
	// compute
	"compute.instance": "compute_instance",

	// vpc
	"vpc.network":          "vpc_network",
	"vpc.subnet":           "vpc_subnet",
	"vpc.address":          "vpc_address",
	"vpc.securityGroup":    "vpc_security_group",
	"vpc.routeTable":       "vpc_route_table",
	"vpc.gateway":          "vpc_gateway",
	"vpc.networkInterface": "vpc_network_interface",
	"vpc.addressPool":      "vpc_address_pool",

	// load balancer (kacho-nlb)
	"loadbalancer.networkLoadBalancers": "nlb_network_load_balancer",
	"loadbalancer.targetGroups":         "nlb_target_group",
	"loadbalancer.listeners":            "nlb_listener",

	// registry (kacho-registry) — object-prefix `registry_` == service name, so
	// no moduleObjectDomain mapping is required. `registries` is the namespace
	// resource; `repositories` is the per-repo authz object (docker pull/push).
	"registry.registries":   "registry_registry",
	"registry.repositories": "registry_repository",

	// storage (kacho-storage) — object-prefix `storage_` == service name (like
	// registry), so no moduleObjectDomain mapping is required. Volume / Snapshot /
	// Image are per-object verb-bearing authz targets: their Get/Update/Delete
	// scope_extractor anchors on the object itself ({storage_volume,volume_id} etc.),
	// so RegisterResource mirrors them here → the reconciler materializes per-object
	// v_* for the creator's project binding (#71). Dotted segments are the plural
	// catalog form (storage.volumes.*).
	"storage.volumes":   "storage_volume",
	"storage.snapshots": "storage_snapshot",
	"storage.images":    "storage_image",

	// iam — note the hierarchy types `account` and `project` are bare
	// (no `iam_` prefix) because they're shared hierarchy ancestors in
	// the FGA model (cluster ▶ account ▶ project ▶ resource).
	"iam.account":        "account",
	"iam.project":        "project",
	"iam.user":           "iam_user",
	"iam.serviceAccount": "iam_service_account",
	"iam.group":          "iam_group",
	"iam.role":           "iam_role",
	"iam.accessBinding":  "iam_access_binding",
}
