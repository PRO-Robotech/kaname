// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// tier_parity_integration_test.go — the load-bearing tier-parity assertions for
// the RBAC rules model. Testcontainers Postgres 16; reads the system roles the
// migrations actually seeded (permissions + rules columns) and asserts two
// properties over them, plus a census so that "no findings" stays distinguishable
// from "nothing read":
//
//   - CATALOG TIER PARITY — every role family the seed names carries the COMPLETE
//     tier set (admin/edit/view). The expectation is derived from the seeded
//     catalog itself, never written by hand: retiring a resource removes a whole
//     family and the property still holds, while losing a single tier of a family
//     that is still served fails and names the tier.
//   - RULES-VS-PERMISSIONS TIER PARITY — for EVERY role, the rules-derived
//     per-(module,resource) tier EQUALS the legacy permissions-derived one. If any
//     role diverges, the re-seed rules for that role are wrong (fix the migration,
//     never the assertion). This proves the rules[] re-seed grants exactly the same
//     authority the legacy permissions did.
//
// Why no expected total lives here: a hand-written count of seeded roles states
// the wrong thing. It says "the catalog has N members", which is a fact about the
// last migration anyone happened to look at — it goes stale on every deliberate
// retire and has to be re-guessed, and while it is stale the suite is red for a
// reason that has nothing to do with authority. The invariant worth locking is
// that no served resource ends up with a partial tier set; that is what these
// assertions say, and it survives the catalog growing or shrinking.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// tierRank orders the back-compat tiers so "strongest" is well-defined.
var tierRank = map[string]int{"viewer": 1, "editor": 2, "admin": 3}

// catalogTiers is the tier AXIS of the seeded system-role catalog — the suffix
// every catalog family is named over. It is deliberately an axis and not a count:
// retiring a resource removes that resource's whole family and leaves the axis
// untouched, so this list does not go stale when the catalog shrinks or grows.
//
// Not to be confused with tierRank above: that is the authority tier a verb set
// resolves to (viewer/editor/admin); this is the naming suffix the seed uses.
var catalogTiers = []string{"admin", "edit", "view"}

// globalFamily is the display key for the prefix-less family — the three
// cluster-wide roles named by the bare tier (`admin`/`edit`/`view`, seeded as
// "4.1 Wildcards"). It carries the same axis as the per-resource families, so the
// completeness property quantifies over it too rather than exempting it.
const globalFamily = "(global)"

// classifySystemRole splits a seeded system-role name into the catalog family it
// belongs to and the tier it occupies:
//
//	vpc.subnet.edit → ("vpc.subnet", "edit", true)   — per-resource family
//	edit            → ("(global)",   "edit", true)   — prefix-less family
//	owner           → ("",           "",     false)  — non-tiered built-in
//
// The third return says whether the name sits on the tier axis at all. Non-tiered
// built-ins (`owner`, `kacho-system.*`, `loadbalancer.*`, `module.*_sa`) are not
// families and carry no tier by construction — note that `kacho-system.admin`
// ends in a tier word yet is NOT a family member: it is a hand-rolled built-in
// whose sibling is `kacho-system.viewer`, so reading it as a family would demand
// an `edit` tier that was never meant to exist.
func classifySystemRole(name string) (family, tier string, tiered bool) {
	segs := strings.Split(name, ".")
	switch len(segs) {
	case 1:
		if isCatalogTier(segs[0]) {
			return globalFamily, segs[0], true
		}
	case 3:
		if isCatalogTier(segs[2]) {
			return segs[0] + "." + segs[1], segs[2], true
		}
	}
	return "", "", false
}

// tiersTheTypeCanServe — тиры, у которых на этом типе ЕСТЬ содержимое, и признак
// того, что ось у семейства СУЖЕНА относительно полной.
//
// # Зачем это, если ось была полной у всех
//
// Полная ось (`admin`/`edit`/`view`) была верным ожиданием, пока набор глаголов
// был платформенной константой: у каждого типа находился глагол любого тира. С
// набором, ставшим атрибутом ТИПА, это перестало быть верным — у `iam_user` снят
// `update` (#1128), и тир `edit` на нём стал НЕВЫРАЗИМ: роль `iam.user.edit`
// материализовала бы ноль кортежей, а её имя обещало бы правку.
//
// Ожидание поэтому ВЫВОДИТСЯ из набора типа, а не выписывается послаблением:
// перечень исключений устаревал бы молча, а вывод следует за моделью сам.
// Классификация глагола — тем же предикатом, каким её делает соседнее
// утверждение файла (`legacyVerbTier`), чтобы двух вокабуляров не завелось.
//
// Семейство, чей тип не резолвится (префикс-менее `(global)`, имена посева,
// расходящиеся с токеном каталога, — например `iam.service_account` против
// `iam.serviceAccount`), получает ПОЛНУЮ ось: сузить ожидание на непонятом имени
// значило бы выдать незнание за решение.
func tiersTheTypeCanServe(family string) (tiers []string, narrowed bool) {
	module, resource, ok := strings.Cut(family, ".")
	if !ok {
		return catalogTiers, false
	}
	fgaType, known := authzmap.ObjectType(module, resource)
	if !known {
		return catalogTiers, false
	}
	verbs := authzmap.VerbsOfType(fgaType)
	if len(verbs) == 0 {
		return catalogTiers, false
	}
	served := map[string]bool{}
	for _, v := range verbs {
		switch legacyVerbTier(v) {
		case "viewer":
			served["view"] = true
		case "editor":
			served["edit"] = true
		case "admin":
			served["admin"] = true
		}
	}
	for _, t := range catalogTiers {
		if served[t] {
			tiers = append(tiers, t)
		}
	}
	return tiers, len(tiers) < len(catalogTiers)
}

// verbsExpandingWildcardFor — набор, которым разворачивается подстановка `*` для
// ЭТОЙ пары (модуль, ресурс): набор её типа, а для пары, не резолвящейся ни в один
// тип (форма `*.*`), — все глаголы платформы. Тот же выбор, что делает
// материализация (`scopeTypeVerbs`), и сделан он здесь по той же причине: два
// места об одном предмете разойдутся молча.
func verbsExpandingWildcardFor(module, resource string) []string {
	if fgaType, ok := authzmap.ObjectType(module, resource); ok {
		if verbs := authzmap.VerbsOfType(fgaType); len(verbs) > 0 {
			return verbs
		}
	}
	return authzmap.AllVerbVocabulary()
}

func containsTier(in []string, t string) bool {
	for _, x := range in {
		if x == t {
			return true
		}
	}
	return false
}

func isCatalogTier(s string) bool {
	for _, t := range catalogTiers {
		if s == t {
			return true
		}
	}
	return false
}

// legacyVerbTier maps a single permission verb to the tier the consumer authz
// gate resolves it to — the SAME classification authzmap.verbClass /
// PermissionsToRelations uses (get/list/read/view → viewer; delete + verb-`*`
// → admin; everything else → editor). It is kept here in the test (not prod):
// the parity logic lives in the test.
func legacyVerbTier(verb string) string {
	switch strings.ToLower(verb) {
	case "get", "list", "view", "watch", "describe", "read",
		"gettargetstates", "listoperations":
		return "viewer"
	case "*":
		return "admin"
	case "delete":
		return "admin"
	default:
		return "editor"
	}
}

// legacyTierMap groups a role's permission strings by (module, resource) and
// computes the strongest legacy tier per pair. The stored permissions are the
// canonical 4-segment RBAC-v2 grammar `module.resource.resourceName.verb` (mig
// 0005 promoted the original 3-segment seed in-place; e.g. `iam.account.read` →
// `iam.account.*.read`, `iam.account.*` → `iam.account.*.*`). The verb is the
// LAST segment; the key is module.resource. A wildcard module/resource (`*.*.*.*`)
// is keyed by its literal segments ("*"."*") so it compares against the matching
// rule's ["*"]×["*"] pair.
func legacyTierMap(perms []string) map[string]string {
	out := map[string]string{}
	for _, p := range perms {
		segs := strings.Split(p, ".")
		if len(segs) != 4 {
			continue
		}
		key := segs[0] + "." + segs[1]
		t := legacyVerbTier(segs[3])
		if tierRank[t] > tierRank[out[key]] {
			out[key] = t
		}
	}
	return out
}

// rulesTierMap computes the strongest rules-derived tier per (module, resource)
// for a role's rules. For each rule, domain.ResolveVerbsAndTier(verbs) yields the
// rule's tier; that tier is folded into every ({module} × resource) pair the rule
// touches (one module per rule).
//
// НАБОР, КОТОРЫМ РАЗВОРАЧИВАЕТСЯ ПОДСТАНОВКА, БЕРЁТСЯ ПО ПАРЕ, а не общий на все.
// Здесь стояло ПЕРЕСЕЧЕНИЕ наборов всех типов, и пока наборы совпадали, оно
// равнялось набору любого типа — то есть было верным по совпадению. Пересечение
// объявлено СУЖАЮЩИМСЯ: как только тип снимает у себя глагол, оно перестаёт
// совпадать с набором СОСЕДНЕГО типа, и ожидание пробы расходится с тем, что
// считает прод (#1189: пересечение стало `[get list]`, и 17 семейств `admin`
// вычислялись здесь как `viewer`). Предикат обязан спрашивать тот же набор, что
// материализация, — иначе это второе место об одном предмете.
func rulesTierMap(rules domain.Rules) map[string]string {
	out := map[string]string{}
	for _, r := range rules {
		for _, res := range r.Resources {
			key := r.Module + "." + res
			_, tier := domain.ResolveVerbsAndTier(r.Verbs, verbsExpandingWildcardFor(r.Module, res))
			if tierRank[tier] > tierRank[out[key]] {
				out[key] = tier
			}
		}
	}
	return out
}

// jsonRule mirrors the JSONB rule shape stored in roles.rules (scalar module).
type jsonRule struct {
	Module        string            `json:"module"`
	Resources     []string          `json:"resources"`
	Verbs         []string          `json:"verbs"`
	ResourceNames []string          `json:"resource_names,omitempty"`
	MatchLabels   map[string]string `json:"match_labels,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДИКАТ ПАРИТЕТА — ВЫДЕЛЕН, потому что популяций у него ДВЕ
// ─────────────────────────────────────────────────────────────────────────────
//
// Прежде оба свойства стояли ВНУТРИ тела пробы ниже, и воспроизвести их у
// второй популяции было нечем. Копия завела бы второе место об одном предмете,
// и разошлись бы они МОЛЧА: обе стороны остались бы зелёными, утверждая разное.
// Поэтому предикат — функция, а популяция — её аргумент (задача #1894).
//
// Популяций сегодня две, и обе идут через ЭТОТ вызов:
//
//  1. строки, посеянные применёнными миграциями — проба ниже;
//  2. строки, записанные ПРИМЕНИТЕЛЕМ ролей модуля —
//     `module_roles_applier_integration_test.go`, сценарии MOD-RD-26/27,
//     держатель Г11 приёмки `roles-come-as-data-not-migrations.md`.
//
// Читатель популяции тоже ОДИН — `systemRolesOfBase`: `WHERE is_system` без
// различения писателя. Различение было бы отдельным решением, и оно прямо
// отвергнуто (П21 приёмки): строка применителя обязана попадать под тот же
// вопрос, что строка миграции.
//
// # Почему предикат вписан СЮДА, а шапка файла не тронута
//
// Три координаты приёмки `system-role-segments-resolve.md` пинят СТРОКУ
// `legacyVerbTier` (`…tier_parity_integration_test.go:182`), и всякая вставка
// выше неё сдвигает их МОЛЧА: гейта на координату вида `файл:строка` в дереве
// нет (заведено задачей #1896, гейт координат судит только имя пробы). Поэтому
// новое стоит ниже 182-й строки, а объяснение — здесь, у предмета, а не в шапке.
// Координата П21 на выборку популяции всё равно уехала: код, на который она
// указывала, переехал в `systemRolesOfBase`, и удержать её было нечем — но её
// собственный предикат (`grep -n 'WHERE is_system ORDER BY name' …`) резолвится
// по-прежнему.

// tierParityRole — строка, над которой считается паритет: имя, свёрнутые
// разрешения и правила. Форма ОДНА на обе популяции: разойдись входы, предикат
// разошёлся бы сам с собой, и «те же ярусы» доказывалось бы двумя разными
// вопросами.
type tierParityRole struct {
	name  string
	perms []string
	rules domain.Rules
}

// tierParityReport — исход предиката: перепись осмотренного и находки по
// КАЖДОМУ свойству ОТДЕЛЬНО.
//
// Отдельно — не ради вида вывода: вызывающему нужно уметь утверждать про одно
// свойство, не задев остальные. Инъекция, роняющая всё сразу, не доказывает,
// что упало проверяемое, — поэтому MOD-RD-26 требует находки свойства 1 и
// ОТСУТСТВИЯ находок свойства 2 на одном и том же входе.
type tierParityReport struct {
	// Roles — строк прочитано. Перепись, а не украшение: без неё «ноль находок»
	// неотличимо от «ноль прочитанного», и каждое свойство ниже зеленело бы
	// вакуумно на непосеянной базе.
	Roles int
	// Families — семейство → тир → имя роли. Отдаётся вызывающему: свойство
	// полной подстановки квантифицируется по префикс-менее семье, и выводить её
	// второй раз значило бы завести вторую классификацию имён.
	Families map[string]map[string]string
	// OnAxis — ролей, стоящих на оси тиров.
	OnAxis int
	// Untiered — имена, оси не несущие: неярусные встроенные, семейством не
	// являющиеся by construction.
	Untiered []string
	// OffAxis — ПРЕДПОСЫЛКА предиката, а не его находка: имя вида
	// `<модуль>.<ресурс>.<x>` с `x` вне оси читается как «не семейство» и молча
	// уходит из-под свойства 1. Слепая зона, которую эта корзина обнажает.
	OffAxis []string
	// Narrowed — семейств, чья ось СУЖЕНА набором глаголов их типа.
	Narrowed int
	// TierGaps — свойство 1, ОБЕ его стороны: тир, который тип обслуживает, у
	// семейства обязан быть; тир, которому нечем быть, — не должен.
	TierGaps []string
	// Mismatches — свойство 2: ярус, выведенный из правил, равен ярусу,
	// выведенному из легаси-разрешений, у КАЖДОЙ роли и КАЖДОЙ пары.
	Mismatches []string
}

// Census — перепись осмотренного одной строкой. Печатается ВСЕГДА, а не только
// на находке: «ноль находок» обязано быть отличимо от «ноль прочитанного».
func (r tierParityReport) Census() string {
	return fmt.Sprintf("перепись паритета: прочитано системных ролей %d · семейств тиров %d "+
		"(ролей на оси %d) · неярусных встроенных %d · семейств с СУЖЕННОЙ осью %d",
		r.Roles, len(r.Families), r.OnAxis, len(r.Untiered), r.Narrowed)
}

// evaluateTierParity — ПРЕДИКАТ паритета ярусов над произвольной популяцией
// системных ролей. Ничего не утверждает: находки возвращает вызывающему.
//
// Возвращает, а не утверждает, ровно потому, что вызывающих двое и ждут они
// РАЗНОГО: проба посева требует пустых находок, MOD-RD-26 требует находки
// свойства 1 с названным ярусом. Предикат, зашивший в себя `assert`, второму
// вызывающему был бы недоступен, и тот завёл бы копию.
func evaluateTierParity(roles []tierParityRole) tierParityReport {
	rep := tierParityReport{Roles: len(roles), Families: map[string]map[string]string{}}

	for _, r := range roles {
		family, tier, tiered := classifySystemRole(r.name)
		if !tiered {
			// A three-segment name whose last segment is not on the axis would be
			// read as "not a family" and quietly escape the completeness property
			// below — the blind spot this bucket exists to expose.
			if strings.Count(r.name, ".") == 2 {
				rep.OffAxis = append(rep.OffAxis, r.name)
			}
			rep.Untiered = append(rep.Untiered, r.name)
			continue
		}
		if rep.Families[family] == nil {
			rep.Families[family] = map[string]string{}
		}
		rep.Families[family][tier] = r.name
	}
	rep.OnAxis = rep.Roles - len(rep.Untiered)

	// ── Property 1: catalog tier parity. Every family the seed names carries the
	// COMPLETE tier axis. Derived from the seeded catalog, so a retire that removes
	// a whole family (as 0074 did for the compute block-storage resources) leaves
	// this green, while dropping one tier of a family that is still served fails
	// here and names the tier — a resource whose catalog offers `admin` and `view`
	// but no `edit` is a grantable surface with a hole in it.
	familyNames := make([]string, 0, len(rep.Families))
	for f := range rep.Families {
		familyNames = append(familyNames, f)
	}
	sort.Strings(familyNames)
	for _, f := range familyNames {
		want, narrowed := tiersTheTypeCanServe(f)
		if narrowed {
			rep.Narrowed++
		}
		for _, tier := range want {
			if _, ok := rep.Families[f][tier]; !ok {
				rep.TierGaps = append(rep.TierGaps, fmt.Sprintf(
					"%s: tier %q missing (family has %s)", f, tier, presentTiers(rep.Families[f])))
			}
		}
		// Обратная сторона: тир, которому НЕЧЕМ быть, не должен существовать.
		// Без неё сужение оси превратилось бы в послабление: роль, обещающая
		// правку там, где тип правки не объявляет, не даёт ничего.
		for _, tier := range catalogTiers {
			if _, present := rep.Families[f][tier]; !present {
				continue
			}
			if !containsTier(want, tier) {
				rep.TierGaps = append(rep.TierGaps, fmt.Sprintf(
					"%s: tier %q посеян, но тип не объявляет ни одного глагола этого тира — "+
						"роль обещает то, чего материализация не даст", f, tier))
			}
		}
	}

	// ── Property 2: rules-derived tier EQUALS legacy permissions-derived tier.
	for _, r := range roles {
		legacy := legacyTierMap(r.perms)
		rule := rulesTierMap(r.rules)

		// Compare key-by-key. Both maps must be identical (same pairs, same tiers).
		keys := map[string]struct{}{}
		for k := range legacy {
			keys[k] = struct{}{}
		}
		for k := range rule {
			keys[k] = struct{}{}
		}
		var sortedKeys []string
		for k := range keys {
			sortedKeys = append(sortedKeys, k)
		}
		sort.Strings(sortedKeys)
		for _, k := range sortedKeys {
			if legacy[k] != rule[k] {
				rep.Mismatches = append(rep.Mismatches,
					r.name+" ["+k+"]: legacy="+legacy[k]+" rules="+rule[k])
			}
		}
	}

	return rep
}

// requireTierParityPremise — ПРЕДПОСЫЛКА предиката, а не его находка. Оба
// вызывающих обязаны её пройти, каких бы находок они ни ждали: без неё пустая
// популяция удовлетворяет любое утверждение о ярусах вакуумно, а имя вне оси
// молча уходит из-под свойства 1.
func requireTierParityPremise(t *testing.T, rep tierParityReport) {
	t.Helper()
	t.Log(rep.Census())
	require.NotEmpty(t, rep.Families, "перепись: прочитано системных ролей %d и НОЛЬ семейств тиров — "+
		"либо миграции не посеяли каталог, либо соглашение об именовании уехало; "+
		"всякое утверждение о ярусах ниже было бы вакуумно зелёным", rep.Roles)
	require.Empty(t, rep.OffAxis, "перепись: системная роль вида <модуль>.<ресурс>.<x> с <x> вне оси %v — "+
		"такое имя не читается как член семейства, и его паритет не проверяется никогда", catalogTiers)
}

// systemRolesOfBase — ПОПУЛЯЦИЯ паритета: все системные роли базы, кем бы они ни
// были записаны.
//
// Различения писателя здесь нет НАМЕРЕННО (П21 приёмки
// `roles-come-as-data-not-migrations.md`): строка, записанная применителем ролей
// модуля, обязана попадать под тот же вопрос, что строка, посеянная миграцией.
// Читатель ОДИН на обе популяции — иначе «те же роли» читались бы двумя разными
// выборками, и разойтись они могли бы молча.
func systemRolesOfBase(t *testing.T, ctx context.Context, pool *pgxpool.Pool) []tierParityRole {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT name, permissions, rules FROM kacho_iam.roles WHERE is_system ORDER BY name`)
	require.NoError(t, err)
	defer rows.Close()

	var roles []tierParityRole
	for rows.Next() {
		var name string
		var permsJSON, rulesJSON []byte
		require.NoError(t, rows.Scan(&name, &permsJSON, &rulesJSON))

		var perms []string
		require.NoError(t, json.Unmarshal(permsJSON, &perms))

		var jr []jsonRule
		require.NoError(t, json.Unmarshal(rulesJSON, &jr))
		dr := make(domain.Rules, 0, len(jr))
		for _, r := range jr {
			dr = append(dr, domain.Rule{
				Module: r.Module, Resources: r.Resources, Verbs: r.Verbs,
				ResourceNames: r.ResourceNames, MatchLabels: r.MatchLabels,
			})
		}
		roles = append(roles, tierParityRole{name: name, perms: perms, rules: dr})
	}
	require.NoError(t, rows.Err())
	return roles
}

func TestTierParity_AllSystemRoles_F53(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers integration in -short mode")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	roles := systemRolesOfBase(t, ctx, pool)
	rep := evaluateTierParity(roles)
	requireTierParityPremise(t, rep)

	assert.Empty(t, rep.TierGaps, "catalog tier parity: every seeded family must carry the tier axis its TYPE can serve; gaps:\n%s",
		strings.Join(rep.TierGaps, "\n"))
	assert.Empty(t, rep.Mismatches,
		"F-53 tier-parity: rules-derived tier must equal legacy permissions-derived tier for all %d seeded system roles; mismatches:\n%s",
		rep.Roles, strings.Join(rep.Mismatches, "\n"))

	// emit-FACT gap — the tier-parity assertion above proves the tier VALUE
	// matches, but it NEVER proved a wildcard `*.*` system-role rule is actually
	// MATERIALIZABLE as a tuple (the rules path could fail-closed-SKIP every `*.*`
	// → tier VALUE correct in the parity map yet ZERO FGA tuples emitted → empty
	// grant → total access loss). Сам сборщик кортежей неэкспортирован и живёт в
	// другом пакете (`access_binding.buildBindingTuples`), поэтому побайтовое
	// доказательство эмиссии принадлежит ему, а не этому файлу. Прежде здесь стояли
	// координаты двух проб, доказывавших это против ЖИВОГО движка; обе сняты вместе
	// с движком, и воспроизводить их имена значило бы посылать читателя в пустоту.
	// Here — над ФАКТИЧЕСКИ пересеянными ролями — assert the
	// materializability INVARIANT the emitter relies on: every seeded `*.*` rule has
	// a resolvable tier (non-empty) AND is the full-wildcard shape (no
	// resource_names / match_labels), so the tier-tuple path applies. A `*.*` role
	// that did NOT satisfy this is exactly the shape that silently emitted nothing.
	wildcardBearers := map[string]bool{}
	for _, r := range roles {
		for _, rule := range r.rules {
			if !isFullWildcard(rule) {
				continue
			}
			wildcardBearers[r.name] = true
			// Форма `*.*` ни в один тип не резолвится, поэтому подстановку
			// разворачивают ВСЕ глаголы платформы — тот же запасной набор, что берёт
			// материализация на якоре без собственного (см. scopeTypeVerbs).
			_, wantTier := domain.ResolveVerbsAndTier(rule.Verbs, authzmap.AllVerbVocabulary())
			require.Containsf(t, []string{"viewer", "editor", "admin"}, wantTier,
				"#201 emit-fact: wildcard system-role %s must resolve to a tier-tuple relation (got %q) — an unresolved tier is the empty-grant #201 bug",
				r.name, wantTier)
		}
	}
	// The floor is DERIVED, not written down: the prefix-less family is the
	// cluster-wide `*.*` trio, so each of its members must be one of the roles the
	// loop above actually walked. Asserting "at least three such roles exist" would
	// pass on any three — including three that are not the trio — and would have to
	// be re-guessed whenever the catalog moves.
	for _, tier := range catalogTiers {
		name, ok := rep.Families[globalFamily][tier]
		require.Truef(t, ok, "#201 emit-fact: the %s family has no %q member — checked by the catalog tier parity above",
			globalFamily, tier)
		require.Truef(t, wildcardBearers[name],
			"#201 emit-fact: %s family role %q carries no full-wildcard `*.*` rule — that is the shape which silently emits nothing",
			globalFamily, name)
	}
}

// presentTiers renders the tiers a family does carry, so a gap report says what is
// there as well as what is missing.
func presentTiers(byTier map[string]string) string {
	var have []string
	for _, t := range catalogTiers {
		if _, ok := byTier[t]; ok {
			have = append(have, t)
		}
	}
	if len(have) == 0 {
		return "no tiers"
	}
	return strings.Join(have, ", ")
}

// isFullWildcard reports whether a rule is the system-role `*.*` form (module AND
// resource both wildcard, all_in_scope) — the materializable-via-tier-tuple shape.
// A half-wildcard or a names/labels arm is NOT this shape.
func isFullWildcard(r domain.Rule) bool {
	hasWildcard := func(xs []string) bool {
		for _, x := range xs {
			if x == "*" {
				return true
			}
		}
		return false
	}
	return r.Module == "*" && hasWildcard(r.Resources) && len(r.ResourceNames) == 0 && len(r.MatchLabels) == 0
}
