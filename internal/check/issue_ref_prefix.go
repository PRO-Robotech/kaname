// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issue_ref_prefix.go — ссылка на задачу ДРУГОГО репозитория несёт его имя
// (задача kaname#387).
//
// # Предмет
//
// Служба вынесена из монорепо вместе с историей, и в её дереве остались ссылки
// вида `#<N>` на задачи монорепо. На GitHub такая ссылка разрешается ВНУТРИ
// этого репозитория: номер вне диапазона задач службы даёт 404, номер из
// диапазона — чужую задачу службы, и оба исхода молчаливы. Ссылка без префикса
// здесь значит задачу службы; задача монорепо пишется `kacho#<N>`, воркспейса —
// `kacho-workspace#<N>`, прежнего трекера `kacho-iam` (история до монорепо) —
// `kacho-iam#<N>`.
//
// # Что гейт умеет утверждать и чего — нет
//
// Номер ВЫШЕ потолка задач службы задачей службы быть не может — такая ссылка
// без префикса есть находка без чтения намерения. Номер В ДИАПАЗОНЕ гейт не
// судит: `#337` равно законно значит задачу службы и неверно — задачу монорепо с
// тем же номером, и различить их можно только по референту (сверка по истории
// строки и заголовку задачи — работа kaname#387, не машинное правило). Это
// граница утверждения, а не дыра: она названа и в шапке пробы, и в её выводе
// («ссылок без префикса N, из них выше потолка M»).
//
// # Форма ссылки — та же, что у предиката задачи
//
//	git grep -hIoE '(^|[^A-Za-z0-9/_#-])#[0-9]{3,5}\b'
//
// с одним сужением: `&` перед `#` — числовая сущность разметки (`&#123;`), а не
// ссылка. Цифр три–пять: короче — пункты и заголовки, длиннее — не номер задачи.
// Знак после номера — не буква, не цифра и не `_`: `#15161d` — цвет, не ссылка.
//
// Предикат задачи вычитает ещё `docs/changes`; гейт этого исключения НЕ несёт:
// на дне заведения голых ссылок выше потолка там ноль, а исключение, которому
// нечего прощать, — слепая зона без срока.
package check

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// KanameNumberCeiling — наибольший номер задачи либо запроса службы на день
// замера. Номера у задач и запросов общие, поэтому потолок взят по обоим:
//
//	gh api 'repos/PRO-Robotech/kaname/issues?state=all&per_page=1&sort=created' --jq '.[0].number'
//	→ 704 @ 2026-10-11
//
// Потолок отстаёт от трекера by construction. Ссылку на задачу службы новее
// потолка пишите `kaname#<N>` — префикс законен для любой задачи и потолка не
// требует; поднимать потолок вправе только новый замер той же командой.
const KanameNumberCeiling = 704

// BareIssueRef — ссылка `#<N>` без префикса репозитория.
type BareIssueRef struct {
	Path   string // путь от корня модуля, через `/`
	Line   int    // с единицы
	Number int
	Text   string // строка целиком, без хвостовых пробелов
}

func (r BareIssueRef) String() string {
	return fmt.Sprintf("%s:%d: #%d — %s", r.Path, r.Line, r.Number, r.Text)
}

// IssueRefExclusion — область дерева, которую гейт НЕ судит, с причиной.
//
// Исключение без находок под собой — тоже находка (гейт сверяет это сам):
// послабление, которому нечего прощать, не истечёт больше никогда.
type IssueRefExclusion struct {
	Name  string
	Why   string
	Match func(rel string) bool
}

// IssueRefAllowance — номер в названном файле, где голая форма есть ВХОД, а не
// ссылка: фикстура разборщика, цитата чужого сообщения либо значение данных,
// уже записанное применённой миграцией. Префикс там исказил бы предмет.
type IssueRefAllowance struct {
	Path   string
	Number int
	Why    string
}

var issueRefExclusions = []IssueRefExclusion{
	{
		Name:  "docs/specs/reviews",
		Why:   "записи ревью — свидетельства вердикта по прежнему отпечатку (решение R27 задачи kaname#387)",
		Match: func(rel string) bool { return strings.HasPrefix(rel, "docs/specs/reviews/") },
	},
	{
		Name: "internal/migrations/*.sql",
		Why: "применённая миграция не правится, только новая (ban #5); комментарий — " +
			"часть файла, и его правка есть правка применённого",
		Match: func(rel string) bool {
			return strings.HasPrefix(rel, "internal/migrations/") && path.Ext(rel) == ".sql"
		},
	},
	{
		Name: "docs/engineering/acceptance",
		Why: "приёмки правит их владелец: правка одобренного документа меняет отпечаток, " +
			"по которому вынесен вердикт. Остаток печатается; когда он станет нулём, " +
			"исключение покраснеет и снимается",
		Match: func(rel string) bool { return strings.HasPrefix(rel, "docs/engineering/acceptance/") },
	},
}

var issueRefAllowances = []IssueRefAllowance{
	{Path: "tools/known_failing_expiry_injection_test.go", Number: 4242,
		Why: "выдуманный номер в фикстуре разборщика маркера known-failing: форма `#<N>` и есть разбираемый вход"},
	{Path: "tools/known_failing_expiry_injection_test.go", Number: 7777,
		Why: "то же — второй выдуманный номер фикстуры"},
	{Path: ".github/scripts/newman-suite-debt.py", Number: 999,
		Why: "выдуманный номер в теле шага-фикстуры; судится форма комментария, а не ссылка"},
	{Path: "scripts/hooks/branch-rule-inject.sh", Number: 2840,
		Why: "дословные темы настоящих коммитов монорепо; тема `#<N> …` — форма, которую судит хук"},
	{Path: "manifest.yaml", Number: 914,
		Why: "значение описания группы: посев пишет его в базу, и то же значение записала применённая миграция"},
	{Path: "internal/servicemanifest/manifest.embedded.yaml", Number: 914,
		Why: "побайтовая вшитая копия manifest.yaml"},
	{Path: "internal/apps/kaname/moduleseed/apply_test.go", Number: 914,
		Why: "фикстура манифеста повторяет значение описания дословно"},
	{Path: "internal/apps/kaname/seed/orphan_scope_sweep.go", Number: 810,
		Why: "значение поля reason события аудита — данные, которые читают потребители журнала"},
}

// IssueRefExclusions — объявленные исключения; копия, проба её не двигает.
func IssueRefExclusions() []IssueRefExclusion {
	out := make([]IssueRefExclusion, len(issueRefExclusions))
	copy(out, issueRefExclusions)
	return out
}

// IssueRefAllowances — объявленные позволения; копия, проба её не двигает.
func IssueRefAllowances() []IssueRefAllowance {
	out := make([]IssueRefAllowance, len(issueRefAllowances))
	copy(out, issueRefAllowances)
	return out
}

// BareIssueRefs — все ссылки `#<N>` без префикса в src, с любым номером.
// Отсев по потолку делает вызывающий: перепись обязана знать и те, что ниже.
func BareIssueRefs(rel string, src []byte) []BareIssueRef {
	var out []BareIssueRef
	for i, line := range bytes.Split(src, []byte("\n")) {
		for _, n := range bareRefNumbers(line) {
			out = append(out, BareIssueRef{
				Path: rel, Line: i + 1, Number: n,
				Text: strings.TrimRight(string(line), " \t\r"),
			})
		}
	}
	return out
}

// bareRefNumbers — номера голых ссылок в одной строке.
func bareRefNumbers(line []byte) []int {
	var out []int
	for i := 0; i < len(line); i++ {
		if line[i] != '#' || (i > 0 && refPrefixByte(line[i-1])) {
			continue
		}
		j := i + 1
		for j < len(line) && line[j] >= '0' && line[j] <= '9' {
			j++
		}
		digits := j - i - 1
		if digits < 3 || digits > 5 || (j < len(line) && refWordByte(line[j])) {
			continue
		}
		n, err := strconv.Atoi(string(line[i+1 : j]))
		if err == nil {
			out = append(out, n)
		}
		i = j - 1
	}
	return out
}

// refPrefixByte — знак перед `#`, с которым это не голая ссылка: имя
// репозитория (`kacho#`), путь (`/#`), повтор (`##`), сущность (`&#`).
// Многобайтовый знак сюда не попадает: кириллица перед `#` префиксом
// репозитория не бывает, и предикат задачи её тоже не исключает.
func refPrefixByte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' ||
		b == '/' || b == '_' || b == '#' || b == '&' || b == '-'
}

// refWordByte — знак после цифр, с которым это не номер (`#15161d` — цвет).
func refWordByte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_'
}

// IssueRefCensus — объём осмотренного: «находок ноль» обязано быть отличимо от
// «ноль прочитанного».
type IssueRefCensus struct {
	Listed       int            // путей подано
	Read         int            // текстовых файлов прочитано
	Binary       int            // пропущено как двоичные
	Bare         int            // голых ссылок в судимых файлах, любой номер
	AboveCeiling int            // из них выше потолка (до позволений)
	Excluded     map[string]int // голых ссылок выше потолка под каждым исключением
	Allowed      map[string]int // под каждым позволением, ключ — "путь#номер"
}

func (c IssueRefCensus) String() string {
	return fmt.Sprintf("путей %d · прочитано %d · двоичных %d · ссылок без префикса %d, "+
		"из них выше потолка %d · под исключениями %s · под позволениями %s",
		c.Listed, c.Read, c.Binary, c.Bare, c.AboveCeiling, sortedCounts(c.Excluded), sortedCounts(c.Allowed))
}

// AllowanceKey — ключ позволения в переписи.
func AllowanceKey(a IssueRefAllowance) string { return fmt.Sprintf("%s#%d", a.Path, a.Number) }

// AuditBareIssueRefs судит файлы rels под root: голая ссылка с номером выше
// ceiling вне исключений и позволений — находка.
//
// Пустой перечень — ошибка, а не «чисто»: ноль поданного означал бы ноль
// прочитанного при любом состоянии дерева.
func AuditBareIssueRefs(root string, rels []string, ceiling int) ([]BareIssueRef, IssueRefCensus, error) {
	census := IssueRefCensus{Listed: len(rels), Excluded: map[string]int{}, Allowed: map[string]int{}}
	if len(rels) == 0 {
		return nil, census, errors.New("перечень путей пуст — судить нечего, и молчание ничего не утверждало бы")
	}
	if ceiling <= 0 {
		return nil, census, fmt.Errorf("потолок %d: всякий номер оказался бы выше него", ceiling)
	}
	allowed := map[string]bool{}
	for _, a := range issueRefAllowances {
		allowed[AllowanceKey(a)] = true
		census.Allowed[AllowanceKey(a)] += 0
	}
	for _, e := range issueRefExclusions {
		census.Excluded[e.Name] += 0
	}
	var findings []BareIssueRef
	for _, rel := range rels {
		rel = filepath.ToSlash(rel)
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) // #nosec G304 -- путь из индекса своего дерева
		if err != nil {
			return nil, census, fmt.Errorf("%s: %w", rel, err)
		}
		if bytes.IndexByte(src[:min(len(src), 8000)], 0) >= 0 {
			census.Binary++
			continue
		}
		census.Read++
		excludedBy := ""
		for _, e := range issueRefExclusions {
			if e.Match(rel) {
				excludedBy = e.Name
				break
			}
		}
		for _, ref := range BareIssueRefs(rel, src) {
			if excludedBy == "" {
				census.Bare++
			}
			if ref.Number <= ceiling {
				continue
			}
			switch key := fmt.Sprintf("%s#%d", rel, ref.Number); {
			case excludedBy != "":
				census.Excluded[excludedBy]++
			case allowed[key]:
				census.AboveCeiling++
				census.Allowed[key]++
			default:
				census.AboveCeiling++
				findings = append(findings, ref)
			}
		}
	}
	return findings, census, nil
}

func sortedCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
