// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

// writes.go — проверка ключа `writes` ресурса (kaname#982, приёмка
// docs/engineering/acceptance/kaname-derives-the-parent-of-a-registered-object.md,
// Р2, DP-20 a–h).
//
// Ключ — вторая половина закрытой политики записи модуля: первую (указатели)
// объявил `parents`. Загрузка отвергает документ, ни одной строки каталога не
// применяя, и называет координату `resources[i].writes[j]` с полем. Находки
// копятся все: названная первая заставила бы автора чинить их по одной.

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/corelib/authz/proxytuple"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// writesKey — ключ записи ресурса в документе (тег поля [Resource.Writes]).
const writesKey = "writes"

// validateResourceWrites — ключ `writes` ресурса resources[i].
func validateResourceWrites(r *Resource, doc *yaml.Node, i int) []error {
	// Присутствие ключа спрашивается у УЗЛА документа, а не у длины перечня:
	// «ключа нет» и «ключ пуст» дают один и тот же пустой срез, а значат разное.
	if mapValue(seqItem(mapValue(doc, "resources"), i), writesKey) == nil {
		return nil
	}
	if len(r.Writes) == 0 {
		return []error{linkFault{
			kind:  ErrWritesEmpty,
			coord: locate(doc, "resources", i, writesKey),
			detail: fmt.Sprintf("resources[%d].writes: пустой перечень не принимается — ключ либо "+
				"отсутствует (модуль пишет только указатель), либо называет хотя бы одну запись", i),
		}}
	}

	pointers := make(map[string]struct{}, len(r.Parents))
	for _, p := range r.Parents {
		pointers[p.Name] = struct{}{}
	}
	authored := make(map[string]struct{}, len(r.Relations))
	for _, rel := range r.Relations {
		authored[rel.Name] = struct{}{}
	}

	var faults []error
	seen := map[string]int{}
	for j, w := range r.Writes {
		coord := locate(doc, "resources", i, writesKey, j, "relation")
		field := fmt.Sprintf("resources[%d].writes[%d].relation", i, j)
		if first, dup := seen[w.Relation]; dup {
			faults = append(faults, linkFault{
				kind:  ErrWriteDuplicate,
				coord: coord,
				detail: fmt.Sprintf("%s: отношение %q уже названо записью resources[%d].writes[%d] — "+
					"одно отношение, объявленное дважды, и верно из двух одно", field, w.Relation, i, first),
			})
		} else {
			seen[w.Relation] = j
			if fault, bad := writeRelationFault(w.Relation, field, coord, pointers, authored); bad {
				faults = append(faults, fault)
			}
		}
		if detail, bad := writeSubjectsFault(w.Subjects); bad {
			faults = append(faults, linkFault{
				kind:  ErrWriteSubjectsInvalid,
				coord: locate(doc, "resources", i, writesKey, j, "subjects"),
				detail: fmt.Sprintf("resources[%d].writes[%d].subjects: %s; принимаются: %s, каждый не более одного раза",
					i, j, detail, strings.Join(domain.WriteSubjectTypes(), ", ")),
			})
		}
	}
	return faults
}

// writeRelationFault — отношение записи: не указатель, объявлено авторским
// отношением ресурса и дано модулю правилом проксируемой записи. Порядок
// несущий: указатель тоже объявлен (в `parents`) и тоже дан правилом, поэтому он
// называется первым — иначе автор чинил бы не ту причину.
func writeRelationFault(relation, field string, coord docCoord,
	pointers, authored map[string]struct{},
) (linkFault, bool) {
	if _, isPointer := pointers[relation]; isPointer {
		return linkFault{kind: ErrWriteIsPointer, coord: coord, detail: fmt.Sprintf(
			"%s: %q — указатель ресурса: регистрацию указателем уже объявил parents, и второе "+
				"объявление того же было бы ложью одного из двух мест", field, relation)}, true
	}
	if _, declared := authored[relation]; !declared {
		return linkFault{kind: ErrWriteRelationUndeclared, coord: coord, detail: fmt.Sprintf(
			"%s: отношения %q среди relations ресурса нет — запись обещала бы кортеж, которого "+
				"модель не объявляет", field, relation)}, true
	}
	if !proxytuple.Hierarchical(proxytuple.Relation(relation)) {
		return linkFault{kind: ErrWriteRelationNotWritable, coord: coord, detail: fmt.Sprintf(
			"%s: отношение %q объявлено, но модулю его писать не дано — правило проксируемой записи "+
				"отвергнет такой кортеж на каждой доставке; модуль пишет только %s",
			field, relation, hierarchicalRelationList())}, true
	}
	return linkFault{}, false
}

// writeSubjectsFault — перечень субъектов записи: непуст, в закрытом перечне,
// без повторов. Причина — словами для находки.
func writeSubjectsFault(subjects []string) (string, bool) {
	if len(subjects) == 0 {
		return "перечень субъектов пуст", true
	}
	seen := make(map[string]struct{}, len(subjects))
	for _, s := range subjects {
		if !domain.IsWriteSubjectType(s) {
			return fmt.Sprintf("тип субъекта %q вне закрытого перечня — класс или группа в отношении "+
				"иерархии раздали бы доступ мимо выдачи", s), true
		}
		if _, dup := seen[s]; dup {
			return fmt.Sprintf("тип субъекта %q назван дважды", s), true
		}
		seen[s] = struct{}{}
	}
	return "", false
}

// hierarchicalRelationList — отношения иерархии правила проксируемой записи
// словами для находки.
func hierarchicalRelationList() string {
	rels := proxytuple.HierarchicalRelations()
	out := make([]string, 0, len(rels))
	for _, r := range rels {
		out = append(out, string(r))
	}
	return strings.Join(out, ", ")
}
