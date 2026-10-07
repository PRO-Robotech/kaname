// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// email_change_gates_ec24_test.go — сценарий EC-24 приёмки
// `docs/engineering/acceptance/email-change-is-confirmed-from-the-new-address.md`
// (задача PRO-Robotech/kaname#635): второй писатель адреса — гейт красный,
// законный — молчит; то же для перечня производителей очереди смены субъекта.
//
// Вход — НАСТОЯЩЕЕ дерево (корпус гейта по индексу git) с одним изменённым
// фактом: инъекция второго писателя в настоящий файл, снятие записи перечня.
// Контроль — то же дерево без инъекции.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// ecChangeRepoRel и ecChangeSQL — файл и оператор законного писателя: якорь
// инъекции «второй писатель в той же функции».
const (
	ecChangeRepoRel = "internal/repo/kaname/pg/email_change_repo.go"
	ecChangeFunc    = "humanSessionWriter.ChangeEmail"
	ecChangeSQL     = "UPDATE users SET email = $2 WHERE id = $1"
	ecProducerRel   = "internal/apps/kaname/api/humansession/email_change.go"
)

func ecMutate(t *testing.T, corpus check.TreeCorpus, rel, from, to string) check.TreeCorpus {
	t.Helper()
	src, ok := corpus[rel]
	if !ok {
		t.Fatalf("EC-24 ЧЕСТНЫЙ-КРАСНЫЙ: файла %s в корпусе нет — законного писателя ещё нет", rel)
	}
	if strings.Count(src, from) != 1 {
		t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ: инъекция не легла — якорь %q в %s встречается %d раз", from, rel, strings.Count(src, from))
	}
	out := check.TreeCorpus{}
	for k, v := range corpus {
		out[k] = v
	}
	out[rel] = strings.Replace(src, from, to, 1)
	return out
}

// TestEC24_ASecondAddressWriterIsRedAndTheLawfulOneIsSilent — EC-24, гейт
// писателей адреса.
func TestEC24_ASecondAddressWriterIsRedAndTheLawfulOneIsSilent(t *testing.T) {
	t.Parallel()
	corpus := peopleAddressCorpus(t)

	// (б) дерево без инъекции: зелёное, законный писатель один.
	control, census, err := check.JudgePeopleAddressWriters(corpus)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Logf("EC-24 (б): законных писателей адреса = %d; перепись: %s", len(census.Lawful), census)
	if len(control) != 0 {
		t.Fatalf("EC-24 (б): дерево без инъекции не зелёное — %d находок:\n  %s", len(control), strings.Join(control, "\n  "))
	}
	if len(census.Lawful) != 1 {
		t.Fatalf("EC-24 (б): законных писателей адреса %d, ожидался 1 (записей перечня %d, вне корпуса %d)",
			len(census.Lawful), census.LawfulEntries, census.LawfulOutOfCorpus)
	}

	cases := []struct {
		name, rel, from, to, where string
	}{
		{
			name:  "второе место в другом файле",
			rel:   peopleWriterRel,
			from:  "UPDATE users SET labels = $2 WHERE id = $1",
			to:    "UPDATE users SET labels = $2, email = $3 WHERE id = $1",
			where: "userWriter.UpdateLabels",
		},
		{
			name:  "второй оператор в функции законного писателя",
			rel:   ecChangeRepoRel,
			from:  ecChangeSQL,
			to:    ecChangeSQL + "; UPDATE users SET email = $2 WHERE id = $1",
			where: ecChangeFunc,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			injected, _, err := check.JudgePeopleAddressWriters(ecMutate(t, corpus, tc.rel, tc.from, tc.to))
			if err != nil {
				t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
			}
			added := newFindings(control, injected)
			if len(added) != 1 {
				t.Fatalf("EC-24 (а): инъекция обязана дать ровно одну находку, дала %d:\n  %s", len(added), strings.Join(added, "\n  "))
			}
			if !strings.Contains(added[0], tc.rel) || !strings.Contains(added[0], tc.where) {
				t.Fatalf("EC-24 (а): находка не называет место %s в %s(): %s", tc.rel, tc.where, added[0])
			}
		})
	}

	// Без записи перечня законный писатель — находка: перечень, а не имя
	// функции, делает его законным.
	bare, _, err := check.JudgePeopleAddressWritersWith(corpus, nil)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	added := newFindings(control, bare)
	if len(added) != 1 || !strings.Contains(added[0], ecChangeRepoRel) {
		t.Fatalf("EC-24: без записи перечня оператор исхода смены обязан стать находкой, находок %d:\n  %s",
			len(added), strings.Join(added, "\n  "))
	}
}

// TestEC24_TheNewSubjectChangeProducerIsDeclared — EC-24, перечень
// производителей очереди смены субъекта: без строки о новом производителе
// гейт красный, со строкой — зелёный.
func TestEC24_TheNewSubjectChangeProducerIsDeclared(t *testing.T) {
	t.Parallel()
	tree, err := treecorpus.NewTree(peopleAddressRoot(t))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева: %v", err)
	}
	corpus, err := check.SubjectChangeProducerCorpus(tree)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	var producers []check.SubjectChangeProducer
	for _, rel := range corpus.Rels() {
		p, perr := check.SubjectChangeProducersIn(rel, corpus[rel])
		if perr != nil {
			t.Fatalf("%v", perr)
		}
		producers = append(producers, p...)
	}

	full := check.CompareSubjectChangeRoster(producers, subjectChangeProducerRoster)
	if !full.Empty() {
		t.Fatalf("EC-24: со строкой о производителе гейт обязан молчать: необъявленных %v, без предмета %v",
			full.Undeclared, full.Stale)
	}
	without := map[string]int{}
	for k, v := range subjectChangeProducerRoster {
		if k != ecProducerRel {
			without[k] = v
		}
	}
	if len(without) == len(subjectChangeProducerRoster) {
		t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ: перечень не несёт строки о %s", ecProducerRel)
	}
	diff := check.CompareSubjectChangeRoster(producers, without)
	if len(diff.Undeclared) != 1 || !strings.Contains(diff.Undeclared[0], ecProducerRel) {
		t.Fatalf("EC-24: без строки о новом производителе гейт обязан покраснеть на %s, необъявленных %v",
			ecProducerRel, diff.Undeclared)
	}
}
