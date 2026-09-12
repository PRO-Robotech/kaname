// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_scope_chain_stays_empty.go — САМОИСТЕКАЮЩИЙ гейт решения «меточную ось
// сужать НЕ НАДО» (задача продукта #1913, приёмка
// `docs/engineering/acceptance/role-withdrawal-has-a-producer.md` §2.8, §10
// шаг 8).
//
// Порт с монорепо (`internal/repohygiene/rolescopechainstaysempty.go`, снят
// вынесением службы — `kacho#2597`). Дословно: весь предикат, распознаватели,
// закрытый перечень ярусных источников. Изменилось: пакет (`repohygiene` →
// `check`), путь-приставка обхода (`services/iam/` снята — в kaname код
// службы лежит от корня).
//
// # Что здесь стережётся — ФАКТ О ДЕРЕВЕ, на котором стоит решение
//
// Приёмка решила НЕ сужать меточную ось выдачи по живости роли, и решение
// стоит целиком на одном факте: у роли МОДУЛЯ цепь областей ПУСТА, поэтому
// меточная выдача не достаёт её ни живую, ни снятую. Факт измерен и верен
// сегодня — и НЕ ЗАЩИЩЁН НИЧЕМ:
//
//   - роль модуля всегда кластерного яруса, потому что `owner_module` и
//     `cluster_id` пишет ОДИН оператор, а не ограничение схемы;
//   - у роли кластерного яруса цепь пуста, потому что ни одна ветвь
//     производителя звеньев её не отбирает: ветви берут `account_id` и
//     `project_id`, а у роли модуля они пусты оба.
//
// Значит производителя звена для `iam_role` может завести любая соседняя
// работа. Появится он — решение §2.8 станет неверным, а доступ вернётся
// МОЛЧА. Этот гейт и есть то единственное, что об этом скажет.
//
// # ЧТО СЧИТАЕТСЯ НАХОДКОЙ — ИСТОЧНИК ветви, а не имя типа
//
// Ветвей, производящих звено для `iam_role`, две, и обе ЗАКОННЫ:
//
//	(5a) роль АККАУНТА  → источник `account_id`
//	(5b) роль ПРОЕКТА   → источник `project_id`
//
// Находка — ТРЕТЬЯ ветвь: та, что производит звено для `iam_role`, не
// спрашивая ни одного из двух ярусных столбцов.
//
// # ЧЕГО РАЗБОР НЕ ВИДИТ — НАЗВАНО, А НЕ СПРЯТАНО
//
//  1. звено, приехавшее ЗЕРКАЛОМ ресурса (writer одинаков для всех типов);
//  2. запрос, собранный из кусков в рантайме;
//  3. производителя вне дерева kaname.
package check

import (
	"regexp"
	"strings"
)

// RoleScopeChainType — тип объекта модели прав, чью цепь областей стережёт гейт.
const RoleScopeChainType = "iam_role"

// RoleScopeChainTable — таблица звеньев цепи.
const RoleScopeChainTable = "resource_parent_edge"

// RoleScopeChainTierSources — ярусные столбцы, из которых звено роли берётся
// ЗАКОННО. Перечень закрытый и короткий by construction.
var RoleScopeChainTierSources = []string{"account_id", "project_id"}

var roleScopeChainBranchRe = regexp.MustCompile(
	`(?i)select\s+'` + RoleScopeChainType + `'\s*::\s*text`)

var roleScopeChainDirectRe = regexp.MustCompile(
	`(?is)insert\s+into\s+(?:kaname\.)?` + RoleScopeChainTable + `\b[^;]*?values[^;]*?'` +
		RoleScopeChainType + `'`)

// RoleScopeChainSite — координата одной находки.
type RoleScopeChainSite struct {
	File string
	Line int
	What string
}

// RoleScopeChainCensus — объём осмотренного одним файлом.
type RoleScopeChainCensus struct {
	Statements  int
	Branches    int
	TierSourced int
}

// ScanRoleScopeChain разбирает один файл — SQL миграции либо прод-исходник Go.
func ScanRoleScopeChain(path, src string) (found []RoleScopeChainSite, census RoleScopeChainCensus) {
	lower := strings.ToLower(src)
	if !strings.Contains(lower, RoleScopeChainTable) {
		return nil, census
	}
	census.Statements = strings.Count(lower, RoleScopeChainTable)

	for _, m := range roleScopeChainBranchRe.FindAllStringIndex(src, -1) {
		census.Branches++
		branch := roleScopeChainBranchOf(src, m[0])
		if roleScopeChainSourcedByTier(branch) {
			census.TierSourced++
			continue
		}
		found = append(found, RoleScopeChainSite{
			File: path,
			Line: roleScopeChainLineOf(src, m[0]),
			What: roleScopeChainFirstLine(branch),
		})
	}

	for _, m := range roleScopeChainDirectRe.FindAllStringIndex(src, -1) {
		census.Branches++
		found = append(found, RoleScopeChainSite{
			File: path,
			Line: roleScopeChainLineOf(src, m[0]),
			What: roleScopeChainFirstLine(src[m[0]:m[1]]),
		})
	}
	return found, census
}

func roleScopeChainBranchOf(src string, from int) string {
	rest := src[from:]
	end := len(rest)
	for _, sep := range []string{"UNION ALL", "union all", ";"} {
		if i := strings.Index(rest, sep); i >= 0 && i < end {
			end = i
		}
	}
	return rest[:end]
}

func roleScopeChainSourcedByTier(branch string) bool {
	lower := strings.ToLower(branch)
	for _, src := range RoleScopeChainTierSources {
		if strings.Contains(lower, src) {
			return true
		}
	}
	return false
}

func roleScopeChainLineOf(src string, off int) int {
	if off > len(src) {
		off = len(src)
	}
	return 1 + strings.Count(src[:off], "\n")
}

func roleScopeChainFirstLine(seg string) string {
	for _, line := range strings.Split(seg, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if len(t) > 120 {
			t = t[:120] + "…"
		}
		return t
	}
	return strings.TrimSpace(seg)
}
