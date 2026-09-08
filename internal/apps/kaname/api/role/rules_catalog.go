// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

// rules_catalog.go — the grantable-token gate for an authored role's rules[].
//
// `domain.Rule.Validate` closes the MODULE segment — членством в наборе, который
// use-case подаёт ему параметром (живой снимок каталога, #1927; прежде это был
// литерал домена, снятый вместе с функцией `domain.IsKnownModule`). Ни
// сегмент РЕСУРСА, ни сегмент ГЛАГОЛА словарём НЕ закрыты: оба проверяются лишь
// грамматикой токена (плюс мощность и одиночность подстановки — `validateVerbs`).
// Прежняя редакция этого абзаца утверждала, что сегмент глагола закрыт словарём
// домена, и тем самым ОТВЕЧАЛА читателю на вопрос, идти ли проверять. Словаря там
// не было; он вводится отдельной под-фазой (XC-3 S2), и до тех пор глагол вне
// набора своего типа просто не материализуется — молча, без сигнала автору роли.
//
// Из двух незакрытых сегментов гейт ниже закрывает РЕСУРС. Класс тихого отказа:
//
//	Role.Create(rules=[{module:"compute", resources:["instances"], verbs:["get"]}])
//	  → 200 (grammar-valid token, known module)
//	AccessBinding.Create(role=that, …)
//	  → 200 (the structural RoleCoversType gate compares the target's type against
//	         the SAME typo, so it matches)
//	reconciler → authzmap.FGAObjectType("compute.instances") → ok=false
//	          → tuple emission SKIPPED fail-closed → grantee 403 FOREVER
//
// with no signal on the role, on the binding, or on the Operation. The gate below
// closes it at authoring time: an unknown `(module, resource)` is rejected SYNC with
// INVALID_ARGUMENT naming the token and the public catalog endpoint.
//
// This is a use-case-layer concern by construction — it owns the catalog
// dependency, keeping `domain` free of it (same layering as
// access_binding/reconcile/tuples.go).
//
// # ИСТОЧНИК — ЖИВЫЕ СТРОКИ КАТАЛОГА, А НЕ СЛОВАРЬ СБОРКИ (kacho#1993)
//
// Здесь стояло `authzmap.ObjectType` — словарь, ПОРОЖДЁННЫЙ СБОРКОЙ
// (`authzmap/tables_gen.go` из манифестов дерева). Замысел гейта верен и
// остаётся; неверен был его ИСТОЧНИК, и неверен в ОБЕ стороны:
//
//   - ЗАВЕДЕНИЕ не проходило. Тип, заведённый применением манифеста в
//     РАБОТАЮЩЕМ процессе, словарю сборки неизвестен, поэтому `Role.Create` и
//     `Role.Update` отвергали правило над ним синхронно, `INVALID_ARGUMENT`.
//     Для арендатора это ПЕРВЫЙ шаг после применения манифеста своего модуля:
//     ниже по цепи чинить нечего — роли нет;
//   - СНЯТИЕ не отвергалось. Словарь сборки продолжал отвечать «грантуем» про
//     ресурс, чья живая строка снята, — правило над ним принималось и
//     материализовалось в ничто, то есть ровно в тот тихий отказ, ради которого
//     гейт и заведён.
//
// Тот же класс уже снят у проекции (#1816), у зеркала (#1982) и у регистрации
// (#1990): имя типа спрашивается у ЖИВОЙ СТРОКИ каталога, а не у сборки. Снимок
// берётся ОДИН на всё вычисление и тот же, которым судится сегмент МОДУЛЯ
// (`domain.Rule.Validate`) и строится проекция глаголов, — обе стороны правила
// обязаны судиться согласованным множеством, а не двумя моментами времени.
//
// # ДВА СЛОВАРЯ ИМЕНИ, и путать их нельзя
//
// Имя КАТАЛОГА (`compute.instance`) содержит точку ВСЕГДА; имя МОДЕЛИ ПРАВ
// (`compute_instance`) — НИКОГДА. Ключ здесь собирается как `<модуль>.<ресурс>`
// и ищется ТОЧНЫМ совпадением, без разбора по первой точке: сегменты уже
// разделены запросом, поэтому вопрос «где кончается модуль» здесь не возникает
// вовсе.

import (
	"fmt"

	"go.uber.org/multierr"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// typeCatalog — ПОРТ живого каталога типов, каким его видит use-case: объявлен
// ли платформой тип с таким ТОЧЕЧНЫМ именем. Объявлен здесь, у потребителя;
// реализация — `catalog.Facts` (снимок живых строк).
//
// Порт узкий намеренно: гейту нужен ровно один факт — есть ли строка. Имя
// модели прав он не читает и читать не должен, иначе завёл бы второй переходник
// об одном предмете.
type typeCatalog interface {
	// FGAObjectType — имя типа МОДЕЛИ для точечного имени КАТАЛОГА; ok=false у
	// ресурса, чья строка снята либо которого в каталоге нет вовсе.
	FGAObjectType(dotted string) (string, bool)
}

// catalogEndpoint — where an author reads the grantable taxonomy. Named in the
// error because the canonical spelling is deliberately NOT uniform across modules
// (compute.instance / iam.serviceAccount singular; storage.volumes /
// registry.registries / loadbalancer.networkLoadBalancers plural), so "guess it"
// is not a viable instruction.
const catalogEndpoint = "GET /iam/v1/permissionCatalog"

// ruleWildcard — the `*` segment. Wildcard module/resource segments are policed by
// domain.Rule.Validate (system-only) and expanded by the rules compiler; they are
// NOT catalog tokens, so the gate skips them rather than double-rejecting (a
// spurious catalog error would mask the real wildcard-policy error).
const ruleWildcard = "*"

// validateRuleCatalog rejects every authored `(module, resource)` pair that is not
// in the published grantable catalog. Errors accumulate (multierr) so an author
// fixing a multi-rule role sees every bad token at once, and are deduplicated so a
// token repeated across rules is reported once. Returns nil when every pair is
// grantable.
//
// systemCtx=true short-circuits to nil, and the reason is SCOPING — not a second
// taxonomy. System roles are unreachable from this gate in practice: Create forces
// is_system=false and Update rejects a system role sync ("System role is read-only")
// before validating. The short-circuit is belt-and-braces documentation of that,
// pinned by TestRuleCatalogGate_SystemContextExempt.
//
// Здесь стояло обоснование, ложное в обе стороны, и оба утверждения пережили свой
// предмет (kacho#513):
//
//   - «токены системных ролей — другая таксономия, ни один не является типом
//     каталога». Сегодня резолвятся ВСЕ пары действующего посева, и это
//     утверждается пробой (TestSeededRoleRulesResolveOrArePinned: записей пина 0).
//     Часть перечисленных имён (`vpc.subnetses`, `iam.projectses`, `compute.zones`)
//     принадлежала служебным учёткам модулей, снятым миграциями 0076 и 0077, — то
//     есть комментарий описывал роли, которых в дереве нет;
//   - «их право несёт ярусный кортеж из permissions[]». Это опровергнуто пробой у
//     самой эмиссии: ветвление идёт по наличию правил, и роль С правилами эмитит
//     только иерархический указатель — ярусный кортеж кладёт ветка для роли БЕЗ
//     правил. Пока пары не резолвились, эти роли не давали НИЧЕГО, и комментарий
//     объяснял, почему это нормально.
//
// Урок, ради которого разбор оставлен: комментарий, объясняющий, почему
// расхождение безвредно, переживает и расхождение, и его починку. Проверять надо
// то, что он утверждает о дереве, а не то, насколько убедительно он звучит.
func validateRuleCatalog(rules domain.Rules, systemCtx bool, types typeCatalog) error {
	if systemCtx {
		return nil
	}
	// Каталог НЕ ПРОВЯЗАН — отказ, а не пропуск, и текст отдельный. Пропуск
	// здесь снял бы гейт целиком и молча: правило над любым токеном проходило бы
	// и материализовалось в ничто — ровно тот тихий отказ, ради которого гейт
	// заведён. Общий текст «unknown type» тоже не годится: он сказал бы
	// арендатору, что виноват его вход, тогда как виновата провязка, и следующий
	// шаг у этих двух разный (тот же довод, что у `validateModule` в домене).
	if types == nil {
		return fmt.Errorf(
			"Illegal argument resources (platform type catalog was not supplied to rule validation)")
	}
	var errs error
	reported := make(map[string]struct{})
	for _, r := range rules {
		if r.Module == ruleWildcard {
			continue
		}
		for _, res := range r.Resources {
			if res == ruleWildcard {
				continue
			}
			// Ключ КАТАЛОГА — точечное имя; ищется точным совпадением, без
			// разбора по первой точке: сегменты уже разделены запросом.
			key := r.Module + "." + res
			if _, ok := types.FGAObjectType(key); ok {
				continue
			}
			if _, dup := reported[key]; dup {
				continue
			}
			reported[key] = struct{}{}
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument resources (unknown type '%s'; grantable types are published by %s)",
				key, catalogEndpoint))
		}
	}
	return errs
}
