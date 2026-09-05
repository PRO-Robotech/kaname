// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// fga_model_drift_test.go — CI drift-gate (system-design W-1, KAC #177
// follow-up). Closes the fail-open risk that re-opened #177: the FGA emitter
// (access_binding/scope_grant_tuples.go) and the catalog (this package's
// objectTypes + TypeHasVerbRelations) must NEVER drift from the canonical
// authorization model. A drift — e.g. an objectTypes entry whose model type does
// not exist, or a v_*-bearing set that claims a type the model never declares —
// makes the emitter write dangling-relation tuples → строка журнала, которую
// проекция принять не может → отравленная партиция `fga_outbox` → рассинхрон
// частичной выдачи.
//
// SINGLE SOURCE OF TRUTH
// ----------------------
// The canonical model is the plain DSL file `proto/kacho/cloud/iam/v1/fga_model.fga`
// in this repository. Everything else is DERIVED from it:
//
//   - вшитая копия `services/iam/internal/authzmodel/fga_model.fga`, из которой
//     служба компилирует план вывода, ПОРОЖДАЕТСЯ целью `make -C deploy
//     fga-model-embed`; побайтовое равенство пары держит
//     `services/iam/internal/authzmodel` `TestEmbeddedModelIsByteIdenticalToCanonical`
//     — здесь оно не пересказывается, чтобы два места об одном предмете не
//     разошлись;
//   - таблицы этого пакета (objectTypes / verbBearingTypes / выразимые
//     отношения) сверяются с каноном здесь.
//
// Здесь стояла третья производная — карта чарта подчарта загрузки движка и цель
// сборки, её порождавшая. Ни карты, ни цели в дереве нет: внешний движок
// отношений снят целиком (S6), а вместе с ним и подчарт, который его поднимал.
// Их имена здесь намеренно НЕ воспроизводятся обратными кавычками: мёртвое имя,
// записанное координатой, читается как живое — и гейтом названных целей сборки,
// и следующим читателем. Вердикт вычисляет форма поверх собственной базы iam
// (`internal/repo/kacho/pg/relverdict`), и производная у канона осталась одна —
// вшитая копия выше.
//
// THE GATE IS UNCONDITIONAL
// -------------------------
// It parses the canonical DSL directly (no Docker → it runs in -short too) and
// it has NO opt-out: a missing canonical file is a FAILURE, never a skip. The
// previous revision skipped itself unless KACHO_IAM_REQUIRE_FGA_MODEL was set,
// and the file it looked for did not exist in the tree at all — so the gate gave
// zero protection on every ordinary run while still reporting `ok`. A skipped
// security gate is neither red nor green; the absence of the source of truth is
// exactly the defect this file exists to catch, so it must be loud.
//
// Assertions, against the model as the single source of truth:
//
//	D-1  every grantable object type (authzmap.Catalog() → ObjectType) exists as
//	     a `type` in the model.
//	D-2  every v_*-bearing resource-type carries the FULL closed per-verb set
//	     (v_get/v_list/v_create/v_update/v_delete) — a partial set would let a
//	     CRUD verb emit a tuple the model cannot satisfy.
//	D-3  authzmap.TypeHasVerbRelations(t) ⟺ the model defines v_* on `t`
//	     (no drift in EITHER direction: the emission guard equals the model).
//	D-4  the tier-only types in the catalog (if any) have NO v_* and are
//	     TypeHasVerbRelations=false (documented + enforced).
//	R-1  REVERSE: every `type` in the model is either a grantable catalog type or
//	     one of the documented non-grantable subject/hierarchy/plumbing types.
//	R-2  REVERSE: no model type outside the catalog carries a v_* relation (that
//	     would be a grantable access surface invisible to the permission catalog).
//	R-3  REVERSE: the closed expandable-relation set equals the model's
//	     v_* / tier / member relation names, in both directions.
//
// D-1..D-4 enumerate the catalog through authzmap.Catalog() — NOT a hand-written
// list. A hand-written list is itself a drift surface: the previous revision's
// literal omitted vpc.anycastAddressPool, registry.* and storage.*, so a phantom
// vpc_anycast_address_pool entry sat in objectTypes (advertised as grantable by
// PermissionCatalogService, guarded as verb-bearing) while the model never
// declared the type — invisible to a gate that only checked what it was told to.
package authzmap_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
)

// XC-3 S1Ф2: прежде здесь лежал литеральный список `v_*`, продублированный ради
// независимости гейта от эмиттера. Он выражал платформенное допущение «набор
// глаголов одинаков у всех типов», поэтому не мог выразить тип с иным набором и
// краснел бы на законном расширении. Список СНЯТ: глагольные отношения опознаются
// по приставке и берутся ИЗ МОДЕЛИ потипово (modelFacts.verbRelationsOfType).
//
// Заявленная независимость при этом СОХРАНЕНА, и формулировать её надо точно:
// ожидаемое значение гейта не выводится из словаря ЭМИТТЕРА — оно выводится из
// модели. Пакетной независимости у этого тестового пакета нет и не было (соседние
// файлы того же пакета импортируют домен), поэтому прежняя формулировка «гейт не
// зависит от пакета эмиттера» была неточна уже до этой правки.

// tierRelations / membershipRelation — the non-verb relations a tenant may
// legitimately expand ("who can do X on object Y"). Mirror of the model's tier
// ladder; R-3 binds this mirror to both the model and
// authzmap.IsExpandableRelation.
var (
	tierRelations      = []string{"viewer", "editor", "admin"}
	membershipRelation = "member"
)

// tierOnlyObjectTypes — catalog object types that carry tier (admin/editor/viewer)
// but NO v_* relations. Documented here so the gate enforces the design decision
// rather than silently tolerating it. Any catalog value NOT in this set is
// expected to be a full v_*-bearing resource-type.
//
// rbac-explicit-model-2026 P3 / D-6: `account` and `project` were removed from
// this set — they became verb-bearing (the canonical model now defines the full
// v_* set on both, P2). They KEEP their tier relations (write-authz anchors,
// D-7), but they are no longer tier-ONLY, so they are now expected to carry the
// full closed v_* set (D-2 path), matching authzmap.TypeHasVerbRelations=true.
var tierOnlyObjectTypes = map[string]bool{}

// nonGrantableModelTypes — the model types that are deliberately NOT in the
// grantable catalog, with the reason each one exists. R-1 pins this set: a new
// `type` in the model must land either in objectTypes (grantable, gated by
// D-1..D-4) or here (explicitly non-grantable), never in neither.
//
// None of these may carry a v_* relation (R-2) — they are not access targets:
//
//   - user / service_account — SUBJECT types. They appear on
//     the left of a tuple, never as an authz object.
//   - group — the subject-SET type (`group#member` usersets). The grantable IAM
//     Group resource is the separate `iam_group` type; this one only carries
//     `member`.
//   - cluster — the platform singleton (`cluster:cluster_kacho_root`). Its
//     relations are the platform-role ladder (system_admin/system_viewer/
//     console); the cluster itself is not a per-project grantable
//     resource, it is the D-9 super-admin short-circuit anchor. С #914 он несёт и
//     `fga_writer` — право модуля писать кортежи, переехавшее сюда с якоря вне
//     иерархии: там оно не выражалось выдачей и не поддавалось отзыву.
//   - iam_fgaproxy — ИСТОРИЧЕСКИЙ якорь того же права. Живых фактов на нём нет
//     (#914 их снял), но выдают его уже ПРИМЕНЁННЫЕ миграции, а применённую
//     миграцию не правят: тип обязан оставаться объявленным, пока они в цепи.
var nonGrantableModelTypes = map[string]string{
	"user":            "subject type (left side of a tuple, never an authz object)",
	"service_account": "subject type (left side of a tuple, never an authz object)",
	"group":           "subject-set type for group#member usersets (the grantable resource is iam_group)",
	"cluster":         "platform singleton cluster:cluster_kacho_root — super-admin ladder anchor, not a grantable resource",
	"iam_fgaproxy":    "исторический якорь права писать кортежи: живых фактов нет (#914), но его выдают уже применённые миграции",
}

// canonicalModelRelPath — the canonical authorization model, relative to the
// monorepo root. This is THE source; the embedded copy the service compiles its
// derivation plan from is generated out of it.
const canonicalModelRelPath = "proto/kacho/cloud/iam/v1/fga_model.fga"

// monorepoRoot walks up from the package directory to the module root (the
// directory holding go.mod). Deterministic and cwd-independent enough for
// `go test ./...` from anywhere inside the tree.
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

// canonicalModelPath resolves the canonical fga_model.fga. There is NO skip
// path and NO environment opt-out: if the single source of truth is absent, the
// drift-gate cannot do its job, and a gate that cannot do its job must be RED.
func canonicalModelPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join(monorepoRoot(t), canonicalModelRelPath)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("canonical authorization model %s is MISSING (%v) — the FGA drift-gate "+
			"has no source of truth and CANNOT verify that objectTypes / verbBearingTypes "+
			"match the model the verdict form actually reads. This is a hard failure by "+
			"design: restore the file (it is the source `make -C deploy fga-model-embed` "+
			"copies into services/iam/internal/authzmodel), never disable the gate.",
			canonicalModelRelPath, err)
	}
	return p
}

var (
	reType = regexp.MustCompile(`^type (\w+)`)
	// a relation definition: indented + `define <name>:`
	// (relations under a type are indented; the type keyword is column 0.)
	reDefine = regexp.MustCompile(`^\s+define (\w+):`)
)

// modelFacts parses the DSL into: set of declared types, and per-type set of
// directly-defined relations.
type modelFacts struct {
	types     map[string]bool
	relations map[string]map[string]bool // type → relation set
}

func parseModel(t *testing.T) modelFacts {
	t.Helper()
	data, err := os.ReadFile(canonicalModelPath(t))
	require.NoError(t, err)
	f := parseModelDSL(string(data))
	require.NotEmpty(t, f.types, "canonical model parsed to zero types — parser or model is broken")
	return f
}

// parseModelDSL is the pure parser (no *testing.T), reused by the ConfigMap
// identity gate.
func parseModelDSL(dsl string) modelFacts {
	f := modelFacts{types: map[string]bool{}, relations: map[string]map[string]bool{}}
	var cur string
	for _, line := range strings.Split(dsl, "\n") {
		if m := reType.FindStringSubmatch(line); m != nil {
			cur = m[1]
			f.types[cur] = true
			f.relations[cur] = map[string]bool{}
			continue
		}
		// `condition <name>(...)` ends the current type body.
		if strings.HasPrefix(line, "condition ") {
			cur = ""
			continue
		}
		if cur == "" {
			continue
		}
		if m := reDefine.FindStringSubmatch(line); m != nil {
			f.relations[cur][m[1]] = true
		}
	}
	return f
}

// verbRelationsOfType — имена `v_*`, которые модель определяет У ЭТОГО типа,
// отсортированно. Опознание по приставке, а не по литеральному списку: список
// выражал бы допущение «набор одинаков у всех» и краснел бы на законном расширении.
func (f modelFacts) verbRelationsOfType(typ string) []string {
	var out []string
	for rel := range f.relations[typ] {
		if strings.HasPrefix(rel, "v_") {
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out
}

// hasAnyVerbRelation reports whether the type defines AT LEAST one v_* relation.
func (f modelFacts) hasAnyVerbRelation(typ string) bool {
	return len(f.verbRelationsOfType(typ)) > 0
}

// allRelationNames returns every relation name defined anywhere in the model.
func (f modelFacts) allRelationNames() map[string]bool {
	out := map[string]bool{}
	for _, rels := range f.relations {
		for r := range rels {
			out[r] = true
		}
	}
	return out
}

// catalogObjectTypes enumerates the FGA object types of every grantable
// (module, resource) pair — derived from authzmap.Catalog(), the SAME closed
// table PermissionCatalogService projects to tenants. Deriving (rather than
// hand-listing) is what makes the gate exhaustive: nothing can be grantable and
// simultaneously outside the gate's view.
func catalogObjectTypes(t *testing.T) []string {
	t.Helper()
	entries := authzmap.Catalog()
	require.NotEmpty(t, entries, "authzmap.Catalog() is empty — nothing would be gated")
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		ot, ok := authzmap.ObjectType(e.Module, e.Resource)
		require.Truef(t, ok, "Catalog() yielded %s.%s but ObjectType does not resolve it", e.Module, e.Resource)
		out = append(out, ot)
	}
	sort.Strings(out)
	return out
}

// D-1: every grantable object type is a declared type in the model.
func TestDrift_ObjectTypesExistInModel(t *testing.T) {
	f := parseModel(t)
	for _, ot := range catalogObjectTypes(t) {
		require.Truef(t, f.types[ot],
			"grantable objectTypes value %q is NOT a `type` in %s — the permission catalog "+
				"advertises it and the emitter would write tuples the projection cannot accept "+
				"(dangling relation → отравленная строка журнала). Either declare the type in the "+
				"canonical model or remove the entry from objectTypes.", ot, canonicalModelRelPath)
	}
}

// D-2 + D-4: each grantable object type is EITHER a full v_*-bearing
// resource-type OR a documented tier-only type with NO v_*. No partial sets.
func TestDrift_VerbBearingTypesHaveFullSet(t *testing.T) {
	f := parseModel(t)
	for _, ot := range catalogObjectTypes(t) {
		if tierOnlyObjectTypes[ot] {
			// D-4: tier-only type must define NO v_* at all.
			require.Falsef(t, f.hasAnyVerbRelation(ot),
				"tier-only objectType %q unexpectedly defines a v_* relation in the model (update tierOnlyObjectTypes / guard)", ot)
			continue
		}
		// D-2: у ресурсного типа модель обязана определять НЕПУСТОЙ набор `v_*`.
		// Какой именно — требует D-2b (TestDrift_TypeVerbSetsMatchModelExactly),
		// потому что набор есть атрибут ТИПА и «полнота» больше не платформенная.
		require.NotEmptyf(t, f.verbRelationsOfType(ot),
			"resource objectType %q defines no v_* relation in the model (a CRUD verb would emit an unsatisfiable tuple)", ot)
	}
}

// D-2b: КАЖДЫЙ каталожный тип объявляет РОВНО тот набор `v_*`, который модель
// определяет у НЕГО — ни больше, ни меньше.
//
// Почему это отдельное утверждение, а не следствие D-2. D-2 требует НАЛИЧИЯ общей
// пятёрки в МОДЕЛИ и об объявленном типом наборе не спрашивает вовсе; D-3 сверяет
// лишь БУЛЕВ ответ «несёт или нет». Пока набор был платформенной константой, этого
// хватало: «четыре из пяти» было невыразимо по устройству таблицы. С набором У ТИПА
// это выразимо — значит требование полноты обязано стать ПРОВЕРКОЙ, иначе
// переформулировка таблицы превратила бы замок в решето. Гейт ставится тем же
// изменением, которое делает дефект выразимым.
func TestDrift_TypeVerbSetsMatchModelExactly(t *testing.T) {
	f := parseModel(t)
	types := catalogObjectTypes(t)
	require.NotEmpty(t, types, "каталог пуст — предпосылка гейта сломана")

	checked := 0
	for _, ot := range types {
		want := f.verbRelationsOfType(ot)
		if want == nil {
			want = []string{}
		}
		got := authzmap.VerbRelationsOfType(ot)
		if got == nil {
			got = []string{}
		}
		require.ElementsMatchf(t, want, got,
			"тип %q объявляет набор %v, а модель определяет у него %v. Недостающее отношение — "+
				"молча не выданный доступ; лишнее — кортеж, который владелец модели отвергает "+
				"окончательно. Набор объявляется У ТИПА, поэтому «четыре из пяти» выразимо и "+
				"обязано ловиться здесь.", ot, got, want)
		checked += len(want)
	}
	t.Logf("перепись: сверено типов: %d; сверено имён отношений: %d", len(types), checked)
}

// D-3: the emission guard (authzmap.TypeHasVerbRelations) must equal the model
// EXACTLY for every grantable object type — no drift in either direction. This
// is the gate that catches a future #177-class fail-open: if someone adds a type
// to objectTypes without v_* but the guard still returns true (or vice-versa),
// the emitter would write dangling tuples again.
func TestDrift_GuardMatchesModel(t *testing.T) {
	f := parseModel(t)
	for _, ot := range catalogObjectTypes(t) {
		modelHasVerbs := f.hasAnyVerbRelation(ot)
		guard := authzmap.TypeHasVerbRelations(ot)
		require.Equalf(t, modelHasVerbs, guard,
			"TypeHasVerbRelations(%q)=%v but model full-v_*-set=%v — emission guard drifted from the canonical model", ot, guard, modelHasVerbs)
	}
	// And the documented tier-only set must agree with the guard returning false.
	for ot := range tierOnlyObjectTypes {
		require.Falsef(t, authzmap.TypeHasVerbRelations(ot),
			"tier-only type %q must have TypeHasVerbRelations=false", ot)
	}
}

// R-1 (REVERSE direction): every `type` declared in the model is accounted for —
// it is either a grantable catalog type (gated by D-1..D-4) or an explicitly
// documented non-grantable subject/hierarchy/plumbing type. Drift is
// bidirectional: a type that exists in the enforced model but in no catalog is
// an authorization surface nobody reviews.
func TestDrift_ModelTypesAreAccountedFor(t *testing.T) {
	f := parseModel(t)
	catalog := map[string]bool{}
	for _, ot := range catalogObjectTypes(t) {
		catalog[ot] = true
	}
	for typ := range f.types {
		if catalog[typ] {
			continue
		}
		reason, documented := nonGrantableModelTypes[typ]
		require.Truef(t, documented,
			"model declares `type %s` which is NEITHER in authzmap.objectTypes (grantable) NOR "+
				"in nonGrantableModelTypes (documented non-grantable). Every enforced type must be "+
				"one or the other: add it to objectTypes so the permission catalog can surface it, "+
				"or document here why it is not grantable.", typ)
		require.NotEmptyf(t, reason, "nonGrantableModelTypes[%q] must carry a reason", typ)
	}
	// The documented set must not itself go stale: every entry must exist in the model.
	for typ := range nonGrantableModelTypes {
		require.Truef(t, f.types[typ],
			"nonGrantableModelTypes lists %q but the canonical model no longer declares that type (stale exemption)", typ)
	}
}

// R-2 (REVERSE direction): no type outside the grantable catalog may carry a
// v_* relation. A verb-bearing type the catalog does not know about is a
// grantable-looking access surface that PermissionCatalogService never shows and
// no reviewer sees — potential excess access by construction.
func TestDrift_NonCatalogTypesCarryNoVerbs(t *testing.T) {
	f := parseModel(t)
	catalog := map[string]bool{}
	for _, ot := range catalogObjectTypes(t) {
		catalog[ot] = true
	}
	for typ := range f.types {
		if catalog[typ] {
			continue
		}
		require.Falsef(t, f.hasAnyVerbRelation(typ),
			"model type %q is NOT in the grantable catalog yet defines a v_* relation — that is an "+
				"authorization surface invisible to PermissionCatalogService. Either make it grantable "+
				"(add to objectTypes) or drop the v_* relations.", typ)
	}
}

// R-3 (REVERSE direction): the closed expandable-relation surface
// (authzmap.IsExpandableRelation — то, что развёртка доступа спрашивает у формы
// вердикта)
// must equal exactly the model's v_* + tier + member relation names. Both
// directions:
//   - a relation we advertise as expandable but the model never defines would
//     let a caller probe a non-existent relation;
//   - a model relation that quietly became expandable would widen the audit
//     surface past review.
func TestDrift_ExpandableRelationsMatchModel(t *testing.T) {
	f := parseModel(t)
	modelRelations := f.allRelationNames()

	// Глагольная часть ВЫВОДИТСЯ: объединение наборов `v_*` каталожных типов.
	// Литеральный список здесь означал бы, что гейт краснеет на законном расширении
	// набора одного типа — то есть сторожил бы платформенное допущение, а не модель.
	want := map[string]bool{}
	for _, ot := range catalogObjectTypes(t) {
		for _, rel := range f.verbRelationsOfType(ot) {
			want[rel] = true
		}
	}
	require.NotEmpty(t, want, "объединение наборов пусто — предпосылка гейта сломана")
	for _, v := range tierRelations {
		want[v] = true
	}
	want[membershipRelation] = true

	// Forward: every relation we advertise as expandable exists in the model AND
	// the guard agrees.
	for rel := range want {
		require.Truef(t, modelRelations[rel],
			"relation %q is advertised as expandable but no model type defines it (phantom expand surface)", rel)
		require.Truef(t, authzmap.IsExpandableRelation(rel),
			"authzmap.IsExpandableRelation(%q)=false but it is a v_*/tier/member relation of the model", rel)
	}
	// Reverse: no other model relation may be expandable (owner/use/ssh/console/
	// fga_writer/announce_writer/system_* are emitter-internal or data-plane
	// plumbing, not a tenant audit surface).
	for rel := range modelRelations {
		if want[rel] {
			continue
		}
		require.Falsef(t, authzmap.IsExpandableRelation(rel),
			"model relation %q is NOT a v_*/tier/member relation yet IsExpandableRelation reports true — "+
				"the ExpandAccess surface drifted past review", rel)
	}
}
