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
// authorization model `proto/kacho/cloud/iam/v1/fga_model.fga` in lockstep. There is
// nothing left to regenerate from it: the model used to be shipped to an external
// engine as a ConfigMap, and that engine, its bootstrap chart and the build target
// that rendered the model are all gone. The unconditional drift-gate
// (fga_model_drift_test.go) fails the build on any divergence, in either
// direction. The table is intentionally a closed enumeration: an unknown pair
// must NOT silently land as an arbitrary FGA type.
//
// ─── The resource name here is SINGULAR, and the permission token's is PLURAL.
//
//	authzmap key       vpc.gateway            (this table)
//	permission token   vpc.gateways.get       (proto authz annotation → catalog)
//
// This divergence is DELIBERATE, not drift, and must not be "reconciled" by
// pluralizing these keys. The two names have different referents:
//
//   - the key here names an FGA OBJECT TYPE — the single object a tuple is
//     written on. The canonical model declares those types in the singular
//     (`type vpc_gateway` in fga_model.fga), and the unconditional drift-gate
//     above requires this table to agree with it EXACTLY. Pluralizing a key
//     would either desynchronize the table from the model or force renaming the
//     model's types — a change to the authorization model, not naming hygiene;
//   - the permission token names an ACTION ON A COLLECTION and mirrors the REST
//     collection path it is annotated next to (`/vpc/v1/gateways`). Its resource
//     segment is required to be plural, pluralized exactly once; that rule is
//     held over the .proto annotations by
//     internal/repohygiene TestVpcPermissionTokenPluralizedExactlyOnce.
//
// The two are never compared, so the difference costs nothing. Neither of the
// two callers of ObjectType feeds a catalog token's resource segment in here:
// permission_catalog/list_catalog.go iterates Catalog() — this table's OWN keys —
// and permissions_to_relations.go matches a ROLE's permission patterns, where a
// plural resource segment does not resolve and the caller takes the documented
// scope-anchor fallback (that is the "ok is false when the pair is unknown"
// branch named above, and it behaves identically for `vpc.subnets` and for a
// misspelled `vpc.subnetses`).
package authzmap

import (
	"sort"
	"strings"
)

// ObjectType returns the rights-model object_type for (module, resource).
// ok=false when the pair is not in the closed table.
func ObjectType(module, resource string) (string, bool) {
	o, ok := objectTypes[module+"."+resource]
	return o, ok
}

// FGAObjectType resolves the rights-model object_type for a dotted closed-table key
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

// DottedType maps a rights-model object_type (e.g. "compute_instance") back to the
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

// TypeHasVerbRelations reports whether the FGA object_type carries per-verb
// relations at all in the canonical authorization model — it says nothing about
// WHICH ones. The set is an attribute of the TYPE (VerbRelationsOfType), not a
// platform constant: `nlb_target_group` declares the canonical CRUD plus its two
// membership relations (NLB-TGT-1), so the previous wording — which named the
// five CRUD relations as THE set every verb-bearing type carries — described a
// tree that no longer exists and would have sent the next reader looking for a
// constant instead of the per-type table.
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
// emitting either on a tier-only type writes a relation the model does not declare
// on that type. The external engine refused such a write outright, and the refusal
// travelled the whole way — permanent error, poisoned journal row, partial-grant
// desync. That refusal went away with the engine, which makes this closed set the
// thing that keeps emitter and model in step. The set is kept in lockstep with
// fga_model.fga;
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

// AllVerbVocabulary — ГЛАГОЛЫ (без приставки `v_`), которые объявляет ХОТЬ ОДИН
// глагольный тип, то есть ОБЪЕДИНЕНИЕ их наборов, отсортированно.
//
// ЭТО И ЕСТЬ «ВСЕ ГЛАГОЛЫ ПЛАТФОРМЫ» — величина, которой у нас не было, пока
// наборы типов совпадали. Тогда пересечение, набор любого типа и объединение были
// одним и тем же числом, и вызывающему, которому нужно «всё», доставалось
// `CommonVerbVocabulary` — по совпадению, а не по существу.
//
// РАЗЛИЧИЕ СТАЛО НАБЛЮДАЕМЫМ И СТОИЛО БЫ ДОРОГО. Пересечение объявлено СУЖАЮЩИМСЯ
// (см. его комментарий и поле `closed_verbs` каталога): снял тип у себя глагол —
// пересечение стало короче. Якорь привязки, у которого СВОЕГО набора нет
// (кластер), разворачивает подстановку `*` запасным набором, а ярус выводится из
// развёрнутых глаголов, — значит на пересечении роль-суперпользователь молча
// понижалась бы с администратора до наблюдателя при сужении набора у ЧУЖОГО типа.
// Найдено при снятии `v_delete` с `iam_user` (#1189), когда пересечение стало
// `[get list]`; до этого его спасал `delete`, оставшийся у всех.
//
// Пересечение и объединение — РАЗНЫЕ вопросы, и путать их нельзя: «что даёт ЛЮБОЙ
// ресурс» против «что бывает вообще». Первый спрашивает публичное поле каталога,
// второй — запасной набор для якоря без собственного.
func AllVerbVocabulary() []string {
	all := map[string]bool{}
	for _, set := range typeVerbRelations {
		for _, r := range set {
			all[strings.TrimPrefix(r, VerbRelationPrefix)] = true
		}
	}
	out := make([]string, 0, len(all))
	for v := range all {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// VerbRelationPrefix — приставка имени глагольного отношения модели. Она же —
// форма, в которой глагол попадает в кортеж.
const VerbRelationPrefix = "v_"

// objectVerbRelations — набор, который объявляет типичный глагольный тип: четыре
// операции, выполнимые НАД УЖЕ СУЩЕСТВУЮЩИМ объектом. Это НЕ платформенная
// константа «набор всех глаголов»: это значение, которое 22 типа пока СОВПАДАЮЩЕ
// объявляют. Тип вправе объявить другой набор — и гейт сверит его с моделью
// ПОТИПОВО, а не с этим литералом.
//
// `v_create` В НЁМ НЕТ, и это решение, а не пропуск. Глагольное отношение
// называет операцию НАД объектом, на который указывает кортеж; «создать» такой
// операцией не является — в момент решения объекта ещё нет, поэтому вопрос всегда
// задают РОДИТЕЛЮ, и Kachō отвечает на него ярусом записи на родителе
// (`editor@project` гейтит каждый Create в каталоге прав). Пообъектный `v_create`
// поэтому не спрашивал никто, при том что его объявляли 24 типа и материализовал
// реконсайлер: 41087 кортежей на эталонном стенде, 9.05% всего хранилища.
// Единственный оставшийся носитель — `registry_registry` (контейнерная семантика,
// см. ниже). Обе стороны держит authzmap/verb_relation_has_reader_test.go.
var objectVerbRelations = []string{"v_delete", "v_get", "v_list", "v_update"}

// registryNamespaceVerbRelations — набор `registry_registry`: операции над
// объектом ПЛЮС `v_create`.
//
// Реестр — КОНТЕЙНЕР, и «создать репозиторий в этом пространстве имён» — операция
// именно над ним. Её действительно спрашивают: хендлеры CreateRepository /
// RenameRepository и data-plane docker (push в новый repo, cross-repo mount,
// раскрытие собственного свежего блоба). Это единственный тип, у которого
// `v_create` имеет читателя, — не «пока», а по существу семантики.
var registryNamespaceVerbRelations = []string{
	"v_create", "v_delete", "v_get", "v_list", "v_update",
}

// identityVerbRelations — набор `iam_user`: ТОЛЬКО ЧТЕНИЕ.
//
// Распоряжение строкой личности выражено ИМЕНОВАННЫМИ отношениями, а не глаголами
// типа: правку содержимого спрашивает `record_writer`, запрет и его снятие —
// `identity_suspender` (#1102), снятие самой строки — `identity_remover` (#1131).
// После этих трёх у обоих распоряжающихся глаголов не осталось читателя ни одного,
// и оба сняты: `v_update` (#1128), `v_delete` (#1189). Это единственный суженный
// набор в дереве.
//
// Сужение стало возможно ровно тогда, когда словарь глаголов стал ПО РЕСУРСУ
// (`CatalogResource.verbs`, #1128): пока публичное поле каталога было ПЕРЕСЕЧЕНИЕМ
// наборов всех типов, сужение у одного типа вынимало глагол из выпадающего
// списка редактора ролей у всех остальных.
//
// ПОЧЕМУ ЭТО НЕ «АККАУНТ ПОТЕРЯЛ ПРАВА». Участием человека в аккаунте распоряжается
// аккаунт (`account.member_remover`, #1127); глаголы `iam_user` про ГЛОБАЛЬНУЮ
// строку личности, одну на все аккаунты человека, и права аккаунта за его границу
// не выходят.
var identityVerbRelations = []string{"v_get", "v_list"}

// targetGroupVerbRelations — набор `nlb_target_group`: операции над объектом ПЛЮС
// два отношения управления составом группы (NLB-TGT-1).
//
// Это первый в дереве набор, отличающийся от `objectVerbRelations`, — то есть
// первый предъявленный случай того свойства, ради которого набор вообще стал
// атрибутом типа. Имена выведены приведением авторских глаголов роли
// (`addTargets` → `v_addtargets`), а не выбраны: имя, написанное иначе, чем его
// собирает эмиттер, адресовало бы отношение, по которому никто не постучится.
var targetGroupVerbRelations = []string{
	"v_addtargets", "v_delete", "v_get", "v_list", "v_removetargets", "v_update",
}

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
	"compute_instance": objectVerbRelations,
	// Ключ входа: канонический набор. `v_list` спрашивает список операций ключа —
	// та же форма, что у прочих ресурсов продукта с асинхронными мутациями.
	"compute_guest_access_key":  objectVerbRelations,
	"compute_placement_group":   objectVerbRelations,
	"vpc_network":               objectVerbRelations,
	"vpc_subnet":                objectVerbRelations,
	"vpc_address":               objectVerbRelations,
	"vpc_security_group":        objectVerbRelations,
	"vpc_route_table":           objectVerbRelations,
	"vpc_gateway":               objectVerbRelations,
	"vpc_network_interface":     objectVerbRelations,
	"vpc_address_pool":          objectVerbRelations,
	"vpc_cidr_group":            objectVerbRelations,
	"nlb_network_load_balancer": objectVerbRelations,
	// NLB-TGT-1: первый тип с набором ШИРЕ канонического CRUD — управление составом
	// группы целей отделено от изменения самой группы. Литерал `objectVerbRelations`
	// здесь неприменим по построению: у типа СВОЙ набор, и гейт дрейфа сверяет его с
	// канонической моделью потипово (TestDrift_TypeVerbSetsMatchModelExactly).
	"nlb_target_group":    targetGroupVerbRelations,
	"nlb_listener":        objectVerbRelations,
	"registry_registry":   registryNamespaceVerbRelations,
	"registry_repository": objectVerbRelations,
	// storage (kacho-storage) — Volume/Snapshot/Image per-object authz objects.
	// Verb-bearing so the reconciler materializes per-object v_* for the creator's
	// project binding — the model type + these Go tables + knownModules("storage")
	// are ALL required or owner-GET fail-closes 403 (#71). Parity with nlb (project-
	// only emitter, DIRECT v_*, no `owner` derivation).
	"storage_volume":      objectVerbRelations,
	"storage_snapshot":    objectVerbRelations,
	"storage_image":       objectVerbRelations,
	"iam_user":            identityVerbRelations,
	"iam_service_account": objectVerbRelations,
	"iam_group":           objectVerbRelations,
	"iam_role":            objectVerbRelations,
	"iam_access_binding":  objectVerbRelations,
	// rbac-2026 P3 / D-6: account/project are now verb-bearing (additive — they
	// also keep their tier relations as write-authz anchors, D-7).
	"account": objectVerbRelations,
	"project": objectVerbRelations,
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
	"compute.instance":       "compute_instance",
	"compute.guestAccessKey": "compute_guest_access_key",
	"compute.placementGroup": "compute_placement_group",

	// vpc
	"vpc.network":          "vpc_network",
	"vpc.subnet":           "vpc_subnet",
	"vpc.address":          "vpc_address",
	"vpc.securityGroup":    "vpc_security_group",
	"vpc.routeTable":       "vpc_route_table",
	"vpc.gateway":          "vpc_gateway",
	"vpc.networkInterface": "vpc_network_interface",
	"vpc.addressPool":      "vpc_address_pool",
	"vpc.cidrGroup":        "vpc_cidr_group",

	// load balancer (kacho-nlb)
	"loadbalancer.networkLoadBalancers": "nlb_network_load_balancer",
	"loadbalancer.targetGroups":         "nlb_target_group",
	"loadbalancer.listeners":            "nlb_listener",

	// registry (kacho-registry) — object-prefix `registry_` == service name, so
	// the module-name vocabulary (pkg/platformmodules) declares the two the same.
	// `registries` is the namespace
	// resource; `repositories` is the per-repo authz object (docker pull/push).
	"registry.registries":   "registry_registry",
	"registry.repositories": "registry_repository",

	// storage (kacho-storage) — object-prefix `storage_` == service name (like
	// registry), so the vocabulary declares the two the same. Volume / Snapshot /
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
