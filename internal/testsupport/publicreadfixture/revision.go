// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicreadfixture

// revision.go — фикстуры редакции манифеста (P14 приёмки
// `module-manifest-revision-only-moves-forward.md`, kaname#865).
//
// Каждая фикстура — ПРАВКА ТЕКСТА документа, а не сборка структуры: документ
// идёт в пробу через тот же загрузчик, что и в продукте, и фикстура не вправе
// быть снисходительнее продукта. Разность каждой правки с исходником сверяется
// здесь же (`requireDelta`): близнец обязан отличаться ровно объявленным фактом.

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	// moduleLine — строка ключа `module` верхнего уровня. Редакция встаёт
	// сразу за ней: так она оказывается рядом с остальной оболочкой.
	moduleLine = regexp.MustCompile(`(?m)^module: .*\n`)
	// revisionLine — строка ключа `revision` верхнего уровня.
	revisionLine = regexp.MustCompile(`(?m)^revision:.*\n`)
	// topKeyLine — строка ключа верхнего уровня: начинается с буквы в первой
	// колонке. Комментарии и пустые строки ключами не считаются.
	topKeyLine = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*:`)
)

// WithRevision вписывает `revision: n` (десятичной записью). Если ключ уже
// есть, заменяется ровно его строка; иначе строка вставляется за строкой
// `module`. Разность с исходником — ровно эта строка.
func WithRevision(doc []byte, n int64) ([]byte, error) {
	return WithRevisionText(doc, strconv.FormatInt(n, 10))
}

// WithRevisionText — то же, но значение вписывается ТЕКСТОМ как есть: так
// пишутся отрицательные кейсы формы значения (`0x10`, `"5"`, `1.5`, `~`).
func WithRevisionText(doc []byte, text string) ([]byte, error) {
	line := strings.TrimRight("revision: "+text, " ")
	if locs := revisionLine.FindAllIndex(doc, -1); len(locs) > 0 {
		if len(locs) != 1 {
			return nil, fmt.Errorf("publicreadfixture: строк ключа revision %d, ожидалась одна", len(locs))
		}
		old := strings.TrimSuffix(string(doc[locs[0][0]:locs[0][1]]), "\n")
		twin := append(append(append([]byte{}, doc[:locs[0][0]]...), line+"\n"...), doc[locs[0][1]:]...)
		if old == line {
			return twin, nil
		}
		return twin, requireDelta(doc, twin, []string{old}, []string{line})
	}
	locs := moduleLine.FindAllIndex(doc, -1)
	if len(locs) != 1 {
		return nil, fmt.Errorf("publicreadfixture: строк ключа module %d, ожидалась одна", len(locs))
	}
	at := locs[0][1]
	twin := append(append(append([]byte{}, doc[:at]...), line+"\n"...), doc[at:]...)
	return twin, requireDelta(doc, twin, nil, []string{line})
}

// WithoutRevision вычёркивает строку ключа `revision`. Разность — ровно она.
func WithoutRevision(doc []byte) ([]byte, error) {
	locs := revisionLine.FindAllIndex(doc, -1)
	if len(locs) != 1 {
		return nil, fmt.Errorf("publicreadfixture: строк ключа revision %d, ожидалась одна", len(locs))
	}
	old := strings.TrimSuffix(string(doc[locs[0][0]:locs[0][1]]), "\n")
	twin := append(append([]byte{}, doc[:locs[0][0]]...), doc[locs[0][1]:]...)
	return twin, requireDelta(doc, twin, []string{old}, nil)
}

// ViewerRoleID — роль, которую дописывает [WithRoles]: форма `<модуль>.<имя>`
// модуля фикстуры `probemod`.
const ViewerRoleID = "probemod.viewer"

// WithRoles дописывает в конец раздел `roles` из одной роли кластерного
// яруса: `id: probemod.viewer`, описание `description` ВПИСАНО КАК ЕСТЬ, без
// кавычек (так пишутся документы `Q(n, open, t)`: тег скаляра описания
// назначает разборщик), правило — `get` над `boxes`.
func WithRoles(doc []byte, description string) ([]byte, error) {
	if bytes.Contains(doc, []byte("\nroles:")) {
		return nil, fmt.Errorf("publicreadfixture: раздел roles уже объявлен")
	}
	section := "\nroles:\n" +
		"  - id: " + ViewerRoleID + "\n" +
		"    description: " + description + "\n" +
		"    tier: {tierType: iam.cluster, tierId: cluster_root}\n" +
		"    rules:\n" +
		"      - {module: probemod, resources: [boxes], classes: [get]}\n"
	return append(append([]byte{}, doc...), section...), nil
}

// WithEmptyRoles дописывает `roles: []` — раздел объявлен и пуст (документ
// `E(n, open)`): применитель ролей снимает роли модуля, которых раздел не
// называет.
func WithEmptyRoles(doc []byte) ([]byte, error) {
	if bytes.Contains(doc, []byte("\nroles:")) {
		return nil, fmt.Errorf("publicreadfixture: раздел roles уже объявлен")
	}
	return append(append([]byte{}, doc...), "\nroles: []\n"...), nil
}

// Reformatted — тот же документ в ИНОЙ ЗАПИСИ, без изменения смысла:
//
//   - блоки ключей верхнего уровня переставлены в обратном порядке (блок —
//     строка ключа в первой колонке и все строки до следующей такой);
//   - добавлена строка комментария;
//   - последовательность `parents: [project]` записана блоком;
//   - значение `module` взято в двойные кавычки.
//
// Отказывает, если хоть одна из правок не нашла своего места: близнец, в
// котором правка не применилась, отличался бы от исходника меньшим, чем
// объявлено, и проба «переформатирование — не конфликт» зеленела бы на
// неизменном документе.
func Reformatted(doc []byte) ([]byte, error) {
	lines := strings.SplitAfter(string(doc), "\n")
	var head []string
	var blocks [][]string
	for _, l := range lines {
		if l == "" {
			continue
		}
		if topKeyLine.MatchString(l) {
			blocks = append(blocks, []string{l})
			continue
		}
		if len(blocks) == 0 {
			head = append(head, l)
			continue
		}
		blocks[len(blocks)-1] = append(blocks[len(blocks)-1], l)
	}
	if len(blocks) < 2 {
		return nil, fmt.Errorf("publicreadfixture: ключей верхнего уровня %d — переставлять нечего", len(blocks))
	}
	var b strings.Builder
	for _, l := range head {
		b.WriteString(l)
	}
	b.WriteString("# переформатировано: смысл документа не изменён\n")
	for i := len(blocks) - 1; i >= 0; i-- {
		block := strings.Join(blocks[i], "")
		if !strings.HasSuffix(block, "\n") {
			block += "\n"
		}
		b.WriteString(block)
	}
	out := b.String()

	const flowParents = "    parents: [project]\n"
	if strings.Count(out, flowParents) != 1 {
		return nil, fmt.Errorf("publicreadfixture: строк %q %d, ожидалась одна", strings.TrimSpace(flowParents), strings.Count(out, flowParents))
	}
	out = strings.Replace(out, flowParents, "    parents:\n      - project\n", 1)

	quoted := moduleLine.ReplaceAllStringFunc(out, func(l string) string {
		v := strings.TrimSpace(strings.TrimPrefix(l, "module:"))
		return "module: \"" + v + "\"\n"
	})
	if quoted == out {
		return nil, fmt.Errorf("publicreadfixture: строки module не нашлось")
	}
	return []byte(quoted), nil
}
