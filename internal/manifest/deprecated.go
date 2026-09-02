// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package manifest

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// deprecated.go — раздел `deprecatedVerbs` (приёмка §2.7; сценарии MOD-MR-16 …
// MOD-MR-18).
//
// Раздел объявляет глаголы, которые платформа ПРИНИМАЕТ на чтении и НЕ
// ПРОИЗВОДИТ на записи. Уже выданные права называют глаголы, которых в контракте
// нет: отвергнуть их значит осиротить действующие выдачи, производить новые —
// тиражировать то, от чего уходим. Отсюда третий исход, и каждая запись несёт
// ПРЕДИКАТ СНЯТИЯ — иначе перечень переживёт свой предмет.
//
// # Популяция — РОВНО ОДИН, и предмет назван поимённо
//
// `read`: встречается в правилах системных ролей 19 раз и не производится ни
// одной строкой каталога прав. Замер — приёмка §2.7.
//
// # Обязательность четырёх ключей НАЗНАЧЕНА решением, а не выведена из частоты
//
// Популяция — единица, а узкая популяция предпосылку не подтверждает, а
// СКРЫВАЕТ (`testing.md` §«Гейт на класс», п. 3). Поэтому все четыре ключа
// обязательны по решению: без `class` глагол неклассифицируем, без `removeWhen`
// запись не истечёт никогда.

var (
	// ErrDeprecatedVerbNameEmpty — устаревший глагол не назван.
	ErrDeprecatedVerbNameEmpty = errors.New("manifest: deprecated verb name is empty")
	// ErrDeprecatedVerbIncomplete — у записи нет одного из четырёх ключей.
	ErrDeprecatedVerbIncomplete = errors.New("manifest: deprecated verb entry is incomplete")
	// ErrDeprecatedVerbIsLive — глагол объявлен устаревшим и живым сразу. Два
	// правила об одном предмете — находка, а не выбор в пользу одного из них.
	ErrDeprecatedVerbIsLive = errors.New("manifest: verb is declared both deprecated and live")
)

// DeprecatedVerb — одна запись совместимости.
type DeprecatedVerb struct {
	// Class — во что глагол разрешается на чтении. Судится ТЕМ ЖЕ закрытым
	// набором, что и класс живого глагола: второй словарь классов разошёлся бы
	// с первым молча.
	Class string `yaml:"class"`
	// Since — с какого дня глагол не производится.
	Since string `yaml:"since"`
	// Reason — почему он вообще принимается.
	Reason string `yaml:"reason"`
	// RemoveWhen — ПРЕДИКАТ СНЯТИЯ. Без него запись не истечёт никогда, и
	// перечень переживёт свой предмет.
	RemoveWhen string `yaml:"removeWhen"`
}

// validateDeprecatedVerbs — форма раздела и его согласие с разделом `resources`.
//
// Обход идёт по ОТСОРТИРОВАННЫМ именам: порядок обхода карты в Go случаен, и
// отказ на одном и том же документе читался бы по-разному от прогона к прогону.
func validateDeprecatedVerbs(m *Manifest, doc *yaml.Node) []error {
	if len(m.DeprecatedVerbs) == 0 {
		return nil
	}
	names := make([]string, 0, len(m.DeprecatedVerbs))
	for name := range m.DeprecatedVerbs {
		names = append(names, name)
	}
	sort.Strings(names)

	live := liveVerbCoords(m)

	var faults []error
	for _, name := range names {
		entry := m.DeprecatedVerbs[name]
		if name == "" {
			faults = append(faults, linkFault{
				kind:   ErrDeprecatedVerbNameEmpty,
				coord:  locate(doc, "deprecatedVerbs"),
				detail: "устаревший глагол не назван: ключом записи служит само имя глагола",
			})
			continue
		}
		for _, required := range []struct {
			key, value, why string
		}{
			{"class", entry.Class, "без него глагол неклассифицируем: чтение не знает, во что его разрешать"},
			{"since", entry.Since, "без него неизвестно, с какого дня глагол не производится"},
			{"reason", entry.Reason, "без него следующий не знает, действует ли ещё основание"},
			{"removeWhen", entry.RemoveWhen, "без него запись не истечёт НИКОГДА и переживёт свой предмет"},
		} {
			if strings.TrimSpace(required.value) != "" {
				continue
			}
			faults = append(faults, linkFault{
				kind:  ErrDeprecatedVerbIncomplete,
				coord: locate(doc, "deprecatedVerbs", name),
				detail: fmt.Sprintf("deprecatedVerbs.%s.%s: ключ не назван — %s",
					name, required.key, required.why),
			})
		}
		if entry.Class != "" && !contains(canonicalVerbClasses, entry.Class) {
			faults = append(faults, linkFault{
				kind:  ErrVerbClassUnknown,
				coord: locate(doc, "deprecatedVerbs", name, "class"),
				detail: fmt.Sprintf("deprecatedVerbs.%s.class: класс %q вне закрытого набора; принимаются: %s",
					name, entry.Class, strings.Join(canonicalVerbClasses, ", ")),
			})
		}
		if where, alive := live[name]; alive {
			faults = append(faults, linkFault{
				kind:  ErrDeprecatedVerbIsLive,
				coord: locate(doc, "deprecatedVerbs", name),
				detail: fmt.Sprintf("deprecatedVerbs.%s: глагол объявлен устаревшим и при этом "+
					"производится ресурсом %s — два правила об одном предмете, из которых "+
					"верно одно", name, where),
			})
		}
	}
	return faults
}

// liveVerbCoords — имена действий, которые манифест ПРОИЗВОДИТ, и координата
// первого объявления каждого: отказ обязан назвать оба пути, а не только тот,
// на котором споткнулся.
func liveVerbCoords(m *Manifest) map[string]string {
	out := map[string]string{}
	for i, r := range m.Resources {
		for j, v := range r.Verbs {
			if v.Name == "" {
				continue
			}
			if _, seen := out[v.Name]; seen {
				continue
			}
			out[v.Name] = fmt.Sprintf("%q (resources[%d].verbs[%d])", r.Name, i, j)
		}
	}
	return out
}
