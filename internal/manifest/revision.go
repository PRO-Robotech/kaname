// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

// revision.go — ключ `revision`: номер редакции манифеста (kaname#865,
// приёмка `docs/engineering/acceptance/module-manifest-revision-only-moves-forward.md`,
// решение Д1).
//
// # Почему номер судится по УЗЛУ, а не по приведённому значению
//
// Разборщик приводит к `int64` молча то, что целым не является: `1.5` даёт 1,
// `5.0` — 5, `1e3` — 1000 (замер §0.1 приёмки). Отказ на нецелое производит
// поэтому только проверка ТЕГА узла, и стоит она ДО всякого приведения.
//
// Недесятичная запись целого (`010`, `0x10`, `0o10`, `+5`, `1_000`) разборщик
// читает без ошибки и в иное число, чем написано (`010` — 8). Номер, читаемый
// иначе, чем написан, вводил бы оператора в заблуждение, а от взаимной
// однозначности текста и значения зависит и отпечаток (Д9). Поэтому номер
// берётся из ТЕКСТА узла и только десятичной записи без знака и ведущего нуля.
//
// # Почему номер и отпечаток лежат в неэкспортируемых полях
//
// Это факты о ДОКУМЕНТЕ, которые судит загрузчик, а не поля, которые
// вызывающий вправе собрать сам: экспортируй их — и манифест, собранный
// структурой в обход загрузчика, нёс бы номер, которого ни один документ не
// объявлял. Наружу — только читатели [Manifest.Revision] и [Manifest.Digest].

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"gopkg.in/yaml.v3"
)

// ErrRevisionNotPositive — номер редакции записан целым, но не положительным
// либо не десятичной записью. Текст отказа называет запись ДОСЛОВНО, как она
// стоит в документе (Д7).
var ErrRevisionNotPositive = errors.New("manifest: revision must be a positive integer")

// revisionKeyName — имя ключа верхнего уровня оболочки.
const revisionKeyName = "revision"

// decimalRevision — десятичная запись без знака и без ведущего нуля.
var decimalRevision = regexp.MustCompile(`^[1-9][0-9]*$`)

// revisionKey — место ключа `revision` в СТРОГОМ разборе.
//
// Строгий разбор (`KnownFields(true)`) отвергает всякий ключ, которому нет
// поля; поле поэтому есть, но значения не несёт: номер судится по узлу
// документа ДО разбора ([judgeRevision]), и второго судьи у него не заводится.
// Разбор в это поле принимает любой узел — неверный уже отвергнут раньше.
type revisionKey struct{}

// UnmarshalYAML принимает узел, ничего не записывая: см. тип.
func (revisionKey) UnmarshalYAML(*yaml.Node) error { return nil }

// Revision — номер редакции, объявленный документом, и признак объявления.
//
// Ложный признак означает «документ ключа не несёт» (стадия S1 приёмки), а не
// «номер ноль»: нуля редакцией не бывает, и отсутствие представлено отдельно
// от значения.
func (m *Manifest) Revision() (int64, bool) {
	return m.revision, m.revisionDeclared
}

// Digest — отпечаток содержимого документа (Д9): `sha256:` и 64 строчные
// шестнадцатеричные цифры над канонической формой (digest.go).
//
// Непуст у всякого манифеста, принятого [Load]; у собранного структурой в
// обход загрузчика — пуст: документа, над которым его считать, у такого
// манифеста нет.
func (m *Manifest) Digest() string { return m.digest }

// judgeRevision — объявлен ли номер редакции и какой.
//
// Объявленность судится по УЗЛУ документа: ключ есть — номер объявлен, и
// пустое значение либо `~` есть отказ формы, а не «ключа нет». Псевдоним
// разворачивается до проверки тега: тег судится у узла, который разборщик
// подставил бы на место ключа.
func judgeRevision(doc *yaml.Node) (int64, bool, error) {
	var key, value *yaml.Node
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == revisionKeyName {
			key, value = doc.Content[i], doc.Content[i+1]
			break
		}
	}
	if key == nil {
		return 0, false, nil
	}
	v, err := resolveAlias(value)
	if err != nil {
		return 0, false, fmt.Errorf("%w: line %d: revision: %w", ErrShape, key.Line, err)
	}
	if v.Kind != yaml.ScalarNode || v.ShortTag() != "!!int" {
		return 0, false, fmt.Errorf("%w: line %d: revision is %s %q, a revision is a !!int scalar written in decimal",
			ErrShape, key.Line, tagOrKind(v), v.Value)
	}
	if !decimalRevision.MatchString(v.Value) {
		return 0, false, fmt.Errorf("%w, got %s", ErrRevisionNotPositive, v.Value)
	}
	n, err := strconv.ParseInt(v.Value, 10, 64)
	if err != nil {
		// Десятичная запись за пределом 64 бит: число законной формы, но не
		// представимое колонкой BIGINT.
		return 0, false, fmt.Errorf("%w: line %d: revision %s is beyond 64 bits", ErrShape, key.Line, v.Value)
	}
	return n, true, nil
}

// resolveAlias — узел, который стоит на месте псевдонима. Цепочка псевдонимов
// разворачивается до узла якоря; петля — отказ, а не бесконечный обход.
func resolveAlias(n *yaml.Node) (*yaml.Node, error) {
	seen := map[*yaml.Node]bool{}
	for n.Kind == yaml.AliasNode {
		if n.Alias == nil || seen[n] {
			return nil, errors.New("alias does not resolve to a node")
		}
		seen[n] = true
		n = n.Alias
	}
	return n, nil
}

// tagOrKind — тег скаляра либо вид коллекции: отказ формы называет то, что
// автор видит в документе.
func tagOrKind(n *yaml.Node) string {
	if n.Kind == yaml.ScalarNode {
		return n.ShortTag()
	}
	return nodeKindName(n.Kind)
}
