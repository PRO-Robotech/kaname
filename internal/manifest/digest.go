// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

// digest.go — отпечаток содержимого документа манифеста (kaname#865, приёмка
// `docs/engineering/acceptance/module-manifest-revision-only-moves-forward.md`,
// решение Д9).
//
// # Что такое отпечаток
//
// `sha256:` и 64 строчные шестнадцатеричные цифры SHA-256 над байтами
// КАНОНИЧЕСКОЙ формы документа в UTF-8. Каноническая форма — JSON по RFC 8785
// (JCS) над деревом узлов YAML-документа:
//
//	отображение      объект JCS; ключ — текст узла ключа, порядок — по
//	                 кодовым единицам UTF-16 (RFC 8785 §3.2.3)
//	последовательность  массив JCS в порядке документа
//	скаляр           строка JCS: короткий тег, один пробел, ТЕКСТ скаляра
//	псевдоним        форма узла его якоря; имя якоря в форму не входит
//
// Тег КОЛЛЕКЦИИ в форму не входит: форма коллекции — её элементы. Принятый
// загрузчиком документ коллекцию с собственным тегом читает по элементам же, и
// тег её значения не меняет.
//
// # Почему не `encoding/json`
//
// Стандартный кодировщик экранирует `<`, `>`, `&`, U+2028 и U+2029 и
// сортирует ключи карты по байтам UTF-8; JCS не экранирует ни одного из них и
// сортирует по UTF-16. Отпечаток, посчитанный кодировщиком, не был бы
// отпечатком формы, объявленной контрактом, и разошёлся бы с ней ровно на
// документах с такими знаками — молча. Сторонней реализации JCS в зависимостях
// службы нет, поэтому форма пишется здесь, и её свойства держит проба
// `digest_internal_test.go`.
//
// # Почему число не приводится
//
// Строковое поле получает ТЕКСТ скаляра при любом теге (§0.1 приёмки): `16` и
// `0x10` в описании роли — разные описания. Приведи форма число по тегу — и
// два документа с разным прочитанным содержимым получили бы одну форму, то есть
// равный номер с иным содержимым прошёл бы повтором молча.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// digestPrefix — приставка формы отпечатка (Д9). Та же форма закреплена
// проверкой схемы колонки `catalog_module.applied_digest`.
const digestPrefix = "sha256:"

// digestOfNode — отпечаток документа над его деревом узлов.
func digestOfNode(n *yaml.Node) (string, error) {
	form, err := canonicalForm(n)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(form))
	return digestPrefix + hex.EncodeToString(sum[:]), nil
}

// canonicalForm — каноническая форма документа (см. шапку файла).
func canonicalForm(n *yaml.Node) (string, error) {
	var b strings.Builder
	if err := writeForm(&b, n, map[*yaml.Node]bool{}); err != nil {
		return "", err
	}
	return b.String(), nil
}

// writeForm пишет форму узла. `open` — узлы на текущем пути обхода: якорь,
// содержащий себя, даёт петлю, и она — отказ, а не бесконечная рекурсия.
func writeForm(b *strings.Builder, n *yaml.Node, open map[*yaml.Node]bool) error {
	if n == nil {
		return errors.New("manifest: canonical form: empty node")
	}
	if open[n] {
		return fmt.Errorf("manifest: canonical form: line %d: anchor contains itself", n.Line)
	}
	open[n] = true
	defer delete(open, n)

	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) != 1 {
			return fmt.Errorf("manifest: canonical form: document holds %d nodes, one expected", len(n.Content))
		}
		return writeForm(b, n.Content[0], open)
	case yaml.AliasNode:
		return writeForm(b, n.Alias, open)
	case yaml.SequenceNode:
		b.WriteByte('[')
		for i, c := range n.Content {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeForm(b, c, open); err != nil {
				return err
			}
		}
		b.WriteByte(']')
		return nil
	case yaml.MappingNode:
		return writeMapping(b, n, open)
	case yaml.ScalarNode:
		return writeJCSString(b, n.ShortTag()+" "+n.Value)
	default:
		return fmt.Errorf("manifest: canonical form: line %d: node %s", n.Line, nodeKindName(n.Kind))
	}
}

// writeMapping — объект JCS: ключи по кодовым единицам UTF-16.
func writeMapping(b *strings.Builder, n *yaml.Node, open map[*yaml.Node]bool) error {
	type entry struct {
		key   string
		units []uint16
		value *yaml.Node
	}
	entries := make([]entry, 0, len(n.Content)/2)
	seen := make(map[string]bool, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, err := resolveAlias(n.Content[i])
		if err != nil {
			return fmt.Errorf("manifest: canonical form: line %d: key: %w", n.Content[i].Line, err)
		}
		if k.Kind != yaml.ScalarNode {
			return fmt.Errorf("manifest: canonical form: line %d: key is %s", k.Line, nodeKindName(k.Kind))
		}
		if seen[k.Value] {
			return fmt.Errorf("manifest: canonical form: line %d: key %q repeats", k.Line, k.Value)
		}
		seen[k.Value] = true
		entries = append(entries, entry{key: k.Value, units: utf16.Encode([]rune(k.Value)), value: n.Content[i+1]})
	}
	sort.Slice(entries, func(i, j int) bool { return lessUTF16(entries[i].units, entries[j].units) })

	b.WriteByte('{')
	for i, e := range entries {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := writeJCSString(b, e.key); err != nil {
			return err
		}
		b.WriteByte(':')
		if err := writeForm(b, e.value, open); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

// lessUTF16 — порядок по кодовым единицам UTF-16 (RFC 8785 §3.2.3).
func lessUTF16(a, b []uint16) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// writeJCSString — строка JCS (RFC 8785 §3.2.2.2): экранируются кавычка,
// обратная косая и управляющие знаки ниже U+0020; прочее пишется как есть.
// Недопустимая последовательность UTF-8 — отказ: JCS её не представляет, а
// загрузчик такой документ не принимает вовсе.
func writeJCSString(b *strings.Builder, s string) error {
	if !utf8.ValidString(s) {
		return errors.New("manifest: canonical form: text is not valid UTF-8")
	}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return nil
}
