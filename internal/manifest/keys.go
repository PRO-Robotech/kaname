// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package manifest

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// keys.go — ключ отображения обязан быть СТРОКОЙ, и судится это по тегу узла
// разбора (приёмка §2.2, сценарии MOD-MF-08 · 09 · 10 · 11 · 12).
//
// # Почему по тегу, а не по результату разбора
//
// Результат ловушку ПРЯЧЕТ, причём двумя разными способами, и оба измерены:
//
//	типизированная цель map[string]map[string]string
//	  вход:  grant: {on: a, true: b}
//	  err:   <nil>
//	  итог:  map[grant:map[on:a true:b]]   ← булев ключ стал строкой "true" МОЛЧА
//
//	нетипизированная карта map[any]any
//	  вход:  17 написанных ключей → 16 ключей карты
//	  `null:` и `~:` схлопнулись в один ключ nil, одно значение исчезло
//
// Тег узла несёт и ТИП, и НОМЕР СТРОКИ, поэтому отказ называет предмет, а не
// «invalid manifest».
//
// # Ловушка названа для ЭТОЙ библиотеки, а не для YAML вообще
//
// `on`, `off`, `yes`, `no`, `y`, `n` (и их регистровые написания) на
// gopkg.in/yaml.v3 ОСТАЮТСЯ СТРОКАМИ: булевость этих слов — свойство YAML 1.1, а
// ядро v3 читает YAML 1.2. Проверка, написанная под них, была бы зелена всегда и
// не видела бы шести настоящих форм: `true`, `false`, `null`, `~`, `123`, `0x1f`.
//
// # Ключ слияния `<<` отвергается — это решение, а не побочный эффект
//
// Его тег `!!merge`, то есть не `!!str`, и проверка его находит. Так и задумано:
// манифест есть объявление, читаемое человеком и платформой, и склейка чужого
// отображения по якорю делает состав раздела невыводимым из места, где он
// написан. Понадобится — снимается ОСОЗНАННО, вместе с пробой.

// keyFault — один ключ-нестрока: где написан, как написан и чем оказался.
type keyFault struct {
	Line    int
	Column  int
	Literal string
	Tag     string
}

// Error называет строку, само написание и тег — три вещи, по которым автор
// манифеста находит место, не читая кода загрузчика.
func (f keyFault) Error() string {
	return fmt.Sprintf("line %d: key `%s` is %s, not a string; quote it (%q) if a literal key was meant",
		f.Line, f.Literal, f.Tag, f.Literal)
}

// checkStringKeys обходит всё дерево документа и собирает КАЖДЫЙ ключ-нестроку,
// а не первый.
//
// Все, а не первый — потому что `null:` и `~:` в одном отображении суть два
// разных написания, схлопывающихся в один ключ карты: назвав только первое,
// проверка сообщила бы ровно половину того, что автор потерял.
func checkStringKeys(n *yaml.Node) []keyFault {
	var faults []keyFault
	collectKeyFaults(n, &faults)
	return faults
}

func collectKeyFaults(n *yaml.Node, out *[]keyFault) {
	if n == nil {
		return
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Tag != "!!str" {
				*out = append(*out, keyFault{
					Line:    key.Line,
					Column:  key.Column,
					Literal: keyLiteral(key),
					Tag:     key.Tag,
				})
			}
		}
	}
	for _, c := range n.Content {
		collectKeyFaults(c, out)
	}
}

// keyLiteral — как ключ написан в документе. У составного ключа (отображение или
// список в позиции ключа) значения-скаляра нет вовсе, и назвать его дословно
// нечем: тогда называется его вид, иначе отказ печатал бы пустую строку.
func keyLiteral(key *yaml.Node) string {
	if key.Value != "" {
		return key.Value
	}
	return nodeKindName(key.Kind)
}

// joinFaults — все находки одной строкой, разделитель `; `.
func joinFaults(faults []keyFault) string {
	parts := make([]string, 0, len(faults))
	for _, f := range faults {
		parts = append(parts, f.Error())
	}
	return strings.Join(parts, "; ")
}
