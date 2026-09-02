// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package moduleroleparity — сверка ОБЪЯВЛЕННЫХ манифестом системных ролей
// модуля с тем, что лежит в живой базе (задача продукта #1891).
//
// # Предмет: манифест обязан ОБЪЯВЛЯТЬ то, что у модуля есть
//
// Раздел `resources` каждого манифеста выводится из канона `fga_model.fga` —
// единственного документа, — и проверяется побайтовой сверкой. У раздела `roles`
// такого документа нет: действующее состояние ролей есть результат наложения
// применённых миграций, из которых ранние отменяются поздними. Поэтому
// объявление роли манифестом нельзя ни вывести, ни проверить чтением: угаданный
// раздел не остался бы бумажным — применитель (#1090) пишет им живые выдачи.
//
// Отсюда способ доказательства: ПРОГОН против живой базы. Миграции исполняются
// по-настоящему, строки читаются оттуда, где они лежат, и объявление сверяется с
// НИМИ. Разбор SQL здесь не участвует ни одной строкой — он распознаватель, и
// молча пропустил бы форму записи, которой не знает.
//
// # Операнд «манифеста» производит ПРИМЕНИТЕЛЬ, а не копия его правил
//
// Второй перевод «манифест → строка роли» разошёлся бы с первым молча: оба
// отвечают одинаково на законном входе. Поэтому сторона манифеста собирается
// вызовом настоящего применителя (`moduleroles.Applier`) с писателем, который
// вместо записи ЗАПОМИНАЕТ — см. пробу. Здесь, в чистом ядре, живёт только
// сравнение двух уже готовых наборов.
//
// # Почему сравнение — отдельная чистая функция
//
// Способность гейта упасть доказывается инъекцией, а инъекция, требующая
// поднятой базы, стоила бы контейнера на каждое утверждение. Ядро чисто:
// `parity_injection_test.go` подаёт ему синтетические наборы и утверждает обе
// стороны по каждой оси.
package moduleroleparity

import (
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// Role — системная роль в форме, общей для обеих сторон сверки.
//
// Полей ровно четыре, и каждое ОБЪЯВЛЕНО манифестом либо ВЫВЕДЕНО из
// объявленного применителем:
//
//   - `ID` выводится функцией имени (`domain.SystemRoleID`) — сверяется потому,
//     что именно на него ссылаются выдачи: разошедшийся идентификатор означал бы
//     новую строку рядом со старой, а не приведение старой;
//   - `Name` — `roles[].id` манифеста дословно;
//   - `Description` — назначение роли;
//   - `Rules` — право роли.
//
// Разрешения (`permissions`) здесь НЕ сверяются: они сворачиваются из правил
// одной функцией (`domain.CompileRules`), и сверка свёртки с её же результатом
// была бы утверждением о постоянстве функции, а не о согласии манифеста с базой.
// Их согласие — предмет собственного гейта, и он есть: расхождение свёртки с
// хранимой формой ловит сверка проекций посева.
type Role struct {
	ID          string
	Name        string
	Description string
	Rules       domain.Rules
}

// Census — объём осмотренного. Печатается ВСЕГДА и до всякого вердикта: без него
// «ноль находок» неотличимо от «ноль прочитанного».
type Census struct {
	// Manifests — манифестов модулей прочитано.
	Manifests int
	// Declared — ролей объявлено манифестами суммарно.
	Declared int
	// Live — системных ролей прочитано из базы суммарно.
	Live int
	// Ownerless — живых ролей, чей первый сегмент НЕ член закрытого набора
	// модулей (`admin`, `edit`, `view`, `owner`, `kacho-system.*`). Манифестом
	// они невыразимы by construction и находкой быть не могут: сверять их не с
	// чем, и число названо именно поэтому.
	Ownerless int
	// Postponed — модулей, стоящих в ведомости #1891.
	Postponed int
}

// String — перепись одной строкой.
func (c Census) String() string {
	return fmt.Sprintf("манифестов %d · объявлено ролей %d · живых системных ролей %d "+
		"(из них без модуля-владельца %d) · отложено модулей %d",
		c.Manifests, c.Declared, c.Live, c.Ownerless, c.Postponed)
}

// ModuleState — что известно об одном модуле закрытого набора.
type ModuleState struct {
	// Module — имя модуля так, как его называет манифест.
	Module string
	// ManifestFile — координата манифеста: находка обязана называть, что править.
	ManifestFile string
	// Declared — роли, объявленные манифестом, в порядке объявления.
	Declared []Role
	// Live — роли этого модуля, прочитанные из живой базы.
	Live []Role
}

// Postponement — запись ведомости #1891: модуль, чьи роли ещё не объявлены.
//
// Ведомость ИСТЕКАЕТ САМА, и это её несущее свойство: запись, чей модуль уже
// объявил свои роли, — находка, а не «уже не нужна»; запись модуля, у которого
// живых ролей нет вовсе, — тоже находка: откладывать нечего.
type Postponement struct {
	// Module — модуль, чьё объявление отложено.
	Module string
	// Why — чем отложенное держится: причина и предикат снятия.
	Why string
}

// Diff — находки сверки. Порядок устойчив: находка читается человеком, и её
// перестановка между прогонами читалась бы как изменение.
//
// Осей четыре, и каждая своя:
//
//  1. модуль не объявил живых ролей и не стоит в ведомости;
//  2. объявленная роль не найдена в базе — объявление шире действительности;
//  3. живая роль не объявлена модулем, который ОБЪЯВИЛ хотя бы одну, — раздел
//     неполон, и его неполнота молчит: применитель напишет объявленное и не
//     тронет остальное;
//  4. роль есть на обеих сторонах, а её содержание расходится.
//
// Плюс две оси самоистечения ведомости.
func Diff(states []ModuleState, ledger []Postponement) []string {
	postponed := map[string]Postponement{}
	for _, p := range ledger {
		postponed[p.Module] = p
	}

	var findings []string
	seenModule := map[string]bool{}

	for _, st := range states {
		seenModule[st.Module] = true
		_, isPostponed := postponed[st.Module]

		switch {
		case len(st.Declared) == 0 && len(st.Live) > 0 && !isPostponed:
			findings = append(findings, fmt.Sprintf(
				"%s: живых системных ролей %d, манифест %s не объявил НИ ОДНОЙ, и в ведомости "+
					"#1891 модуля нет — раздел `roles` читается как «ролей у модуля нет», "+
					"а они есть: %s",
				st.Module, len(st.Live), st.ManifestFile, roleNames(st.Live)))
		case len(st.Declared) > 0 && isPostponed:
			findings = append(findings, fmt.Sprintf(
				"%s: ведомость #1891 откладывает объявление, а манифест %s его уже несёт "+
					"(ролей %d) — запись потеряла предмет и обязана быть снята",
				st.Module, st.ManifestFile, len(st.Declared)))
		case len(st.Live) == 0 && isPostponed:
			findings = append(findings, fmt.Sprintf(
				"%s: ведомость #1891 откладывает объявление, а живых системных ролей у модуля "+
					"НОЛЬ — откладывать нечего, запись обязана быть снята", st.Module))
		}

		if len(st.Declared) == 0 {
			continue
		}
		findings = append(findings, compareSets(st)...)
	}

	for _, p := range ledger {
		if !seenModule[p.Module] {
			findings = append(findings, fmt.Sprintf(
				"ведомость #1891 называет модуль %q, которого нет ни в одном манифесте дерева — "+
					"запись адресует предмет, которого не существует", p.Module))
		}
	}
	sort.Strings(findings)
	return findings
}

// compareSets — сверка двух наборов ролей одного модуля, обе стороны.
func compareSets(st ModuleState) []string {
	live := map[string]Role{}
	for _, r := range st.Live {
		live[r.Name] = r
	}
	declared := map[string]Role{}
	for _, r := range st.Declared {
		declared[r.Name] = r
	}

	var findings []string
	for _, d := range st.Declared {
		l, ok := live[d.Name]
		if !ok {
			findings = append(findings, fmt.Sprintf(
				"%s: манифест %s объявляет роль %q, а в живой базе её нет — объявление шире "+
					"действительности, и применитель ЗАВЕДЁТ её, а не приведёт",
				st.Module, st.ManifestFile, d.Name))
			continue
		}
		findings = append(findings, compareOne(st, d, l)...)
	}
	for _, l := range st.Live {
		if _, ok := declared[l.Name]; !ok {
			findings = append(findings, fmt.Sprintf(
				"%s: живая роль %q не объявлена манифестом %s, хотя раздел `roles` в нём есть — "+
					"неполный раздел молчит: применитель напишет объявленное и НЕ ТРОНЕТ эту строку",
				st.Module, l.Name, st.ManifestFile))
		}
	}
	return findings
}

// compareOne — сверка одной роли по каждому полю отдельно.
//
// Поимённо, а не одним «не равны»: автор манифеста обязан узнать, ЧТО именно
// разошлось, иначе на каждую находку тратится прогон против базы.
func compareOne(st ModuleState, declared, live Role) []string {
	var findings []string
	if declared.ID != live.ID {
		findings = append(findings, fmt.Sprintf(
			"%s: роль %q — идентификатор расходится: объявление даёт %q, в базе %q; "+
				"выдачи ссылаются на идентификатор, поэтому применитель завёл бы ВТОРУЮ строку "+
				"рядом со старой, а не привёл эту",
			st.Module, declared.Name, declared.ID, live.ID))
	}
	if declared.Description != live.Description {
		findings = append(findings, fmt.Sprintf(
			"%s: роль %q — назначение расходится:\n    объявлено: %q\n    в базе:    %q",
			st.Module, declared.Name, declared.Description, live.Description))
	}
	if d, l := RulesLiteral(declared.Rules), RulesLiteral(live.Rules); d != l {
		findings = append(findings, fmt.Sprintf(
			"%s: роль %q — право расходится:\n    объявлено: %s\n    в базе:    %s",
			st.Module, declared.Name, d, l))
	}
	return findings
}

// RulesLiteral — правила одной строкой, ДОСЛОВНО и без сортировки.
//
// Приведение к канону здесь запрещено: применённая миграция несёт у ярусов
// чтения ровно `["read","list","get"]`, и сортировка либо разрешение снятого
// имени дали бы ДРУГУЮ строку — то есть сверка объявляла бы согласие там, где
// применитель записал бы иное.
func RulesLiteral(rs domain.Rules) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		var b strings.Builder
		fmt.Fprintf(&b, "{module:%s resources:[%s] verbs:[%s]",
			r.Module, strings.Join(r.Resources, " "), strings.Join(r.Verbs, " "))
		if len(r.ResourceNames) > 0 {
			fmt.Fprintf(&b, " resourceNames:[%s]", strings.Join(r.ResourceNames, " "))
		}
		if len(r.MatchLabels) > 0 {
			keys := make([]string, 0, len(r.MatchLabels))
			for k := range r.MatchLabels {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			pairs := make([]string, 0, len(keys))
			for _, k := range keys {
				pairs = append(pairs, k+"="+r.MatchLabels[k])
			}
			fmt.Fprintf(&b, " matchLabels:{%s}", strings.Join(pairs, " "))
		}
		b.WriteString("}")
		parts = append(parts, b.String())
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// roleNames — имена ролей в устойчивом порядке для текста находки.
func roleNames(rs []Role) string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Name)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
