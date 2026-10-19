// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmodel

// admit_key_terms_test.go — клауза Д3 при перечне термов ключа
// `publicReadToChildren` (приёмка
// docs/engineering/acceptance/public-read-container-of-a-module-type-is-admitted.md,
// отпечаток a129f53c4c46525b390d5f71bda31866e43e0776c6c556326806ce313836babf,
// Р1, Р3, Р4; задача PRO-Robotech/kaname#866).
//
// Здесь — свойства самого допуска на синтетическом тексте: что перечень
// исключает ровно терм и только в его объявлении, что он обязан описывать ЭТОТ
// текст, что ребро режется только в сторону объявленного нового контейнера, и
// что находка стоит на семени. Сценарии над манифестом П1 живут у цепочки старта
// (`internal/modelcompose`, `cmd/kaname`).

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// keyBox / keyItem — контейнер и ребёнок в той форме, в какой их пишет рендер
// ключа: класс первым в `v_get`/`v_list` контейнера и `public_reader` у него же,
// `or public_reader from box` в `v_get`/`v_list` ребёнка.
const keyBox = `type acme_box
  relations
    define project: [project]
    define super_admin: super_admin from project
    define public_reader: [system_class]
    define v_get: [system_class, user, service_account, group#member] or super_admin
    define v_list: [system_class, user, service_account, group#member] or super_admin
    define v_update: [user, service_account, group#member] or super_admin
`

const keyItem = `type acme_item
  relations
    define box: [acme_box]
    define super_admin: super_admin from box
    define v_get: [user, service_account, group#member] or super_admin or public_reader from box
    define v_list: [user, service_account, group#member] or super_admin or public_reader from box
    define v_update: [user, service_account, group#member] or super_admin
`

// keyTerms — перечень термов, который ключ вносит в keyBox и keyItem.
func keyTerms() []KeyTerm {
	return []KeyTerm{
		{Type: "acme_box", Relation: "public_reader"},
		{Type: "acme_box", Relation: "v_get"},
		{Type: "acme_box", Relation: "v_list"},
		{Type: "acme_item", Relation: "v_get", Pointer: "box"},
		{Type: "acme_item", Relation: "v_list", Pointer: "box"},
	}
}

func mustAdmitKey(t *testing.T, composed string, terms ...KeyTerm) AdmissionReport {
	t.Helper()
	rep, err := Admit(composed, terms...)
	if err != nil {
		t.Fatalf("допуск вернул ошибку, а ожидался отчёт: %v", err)
	}
	return rep
}

// seedsOf — множество «тип.отношение» находок правила.
func seedsOf(rep AdmissionReport, rule Rule) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range findingsOf(rep, rule) {
		out[f.Type+"."+f.Relation] = f
	}
	return out
}

// TestAdmitKeyTermsAdmitExactlyTheThreeTermsOfTheKey — Р1: три терма ключа
// допускаются при перечне; без перечня (строгий режим) — отказ, как сегодня.
func TestAdmitKeyTermsAdmitExactlyTheThreeTermsOfTheKey(t *testing.T) {
	composed := compose(keyBox, keyItem)

	rep := mustAdmitKey(t, composed, keyTerms()...)
	if !rep.Admitted() {
		t.Fatalf("три терма ключа при перечне обязаны допускаться; находки %v; %s", rep.Findings, rep.Census())
	}

	strict := mustAdmitKey(t, composed)
	got := seedsOf(strict, RuleD3)
	for _, want := range []string{"acme_box.public_reader", "acme_box.v_get", "acme_box.v_list"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("строгий режим (пустой перечень) обязан отвергать класс в %s, как сегодня; находки %v", want, strict.Findings)
		}
	}
	if strict.Admitted() {
		t.Fatal("строгий режим обязан отказать")
	}
}

// TestAdmitKeyTermsMustDescribeThisText — CE-04: запись перечня, которой нет
// среди новых типов текста либо которой текст не несёт, — отказ допуска.
func TestAdmitKeyTermsMustDescribeThisText(t *testing.T) {
	composed := compose(keyBox, keyItem)
	cases := []struct {
		name string
		term KeyTerm
	}{
		{"канонический тип", KeyTerm{Type: "registry_registry", Relation: "public_reader"}},
		{"тип, которого нет", KeyTerm{Type: "acme_nosuch", Relation: "public_reader"}},
		{"объявление без голого класса", KeyTerm{Type: "acme_box", Relation: "v_update"}},
		{"объявления нет", KeyTerm{Type: "acme_box", Relation: "v_nosuch"}},
		{"терма с указателем нет", KeyTerm{Type: "acme_item", Relation: "v_update", Pointer: "box"}},
		{"указатель не тот", KeyTerm{Type: "acme_item", Relation: "v_get", Pointer: "project"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			terms := append(keyTerms(), c.term)
			rep, err := Admit(composed, terms...)
			if !errors.Is(err, ErrKeyTermNotInText) {
				t.Fatalf("запись перечня %+v обязана быть отказом ErrKeyTermNotInText, получено err=%v", c.term, err)
			}
			if rep.Admitted() {
				t.Fatal("отказ перечня не вправе давать «допущено»")
			}
		})
	}
}

// TestAdmitKeyTermExcludesOnlyTheBareClassRecord — CE-06: исключается голая
// запись `system_class`; поимённая запись класса в том же объявлении — находка.
func TestAdmitKeyTermExcludesOnlyTheBareClassRecord(t *testing.T) {
	box := swapDecl(keyBox,
		"define v_get: [system_class, user, service_account, group#member] or super_admin",
		"define v_get: [system_class, system_class:anonymous, user, service_account, group#member] or super_admin")
	rep := mustAdmitKey(t, compose(box, keyItem), keyTerms()...)
	got := seedsOf(rep, RuleD3)
	if len(got) != 1 {
		t.Fatalf("ждали ровно одну находку Д3, получено %v", rep.Findings)
	}
	f, ok := got["acme_box.v_get"]
	if !ok || f.Term != "system_class:anonymous" {
		t.Fatalf("находка обязана стоять на acme_box.v_get с записью system_class:anonymous, получено %+v", rep.Findings)
	}
}

// TestAdmitKeyTermDoesNotCoverAnotherRecordOfItsDeclaration — Р1, PM-10 в
// синтетике: законный терм п. 3 в объявлении ребёнка не покрывает класс,
// записанный рядом с ним.
func TestAdmitKeyTermDoesNotCoverAnotherRecordOfItsDeclaration(t *testing.T) {
	item := swapDecl(keyItem,
		"define v_get: [user, service_account, group#member] or super_admin or public_reader from box",
		"define v_get: [system_class, user, service_account, group#member] or super_admin or public_reader from box")
	rep := mustAdmitKey(t, compose(keyBox, item), keyTerms()...)
	got := seedsOf(rep, RuleD3)
	if len(got) != 1 {
		t.Fatalf("ждали ровно одну находку Д3, получено %v", rep.Findings)
	}
	if f, ok := got["acme_item.v_get"]; !ok || f.Term != "system_class" {
		t.Fatalf("находка обязана стоять на acme_item.v_get с записью system_class, получено %+v", rep.Findings)
	}
}

// TestAdmitPathThroughAnotherDeclarationsLawfulTermIsAFinding — Р3: путь через
// законную точку ДРУГОГО объявления законным не становится; находка — на семени.
func TestAdmitPathThroughAnotherDeclarationsLawfulTermIsAFinding(t *testing.T) {
	item := swapDecl(keyItem,
		"define v_update: [user, service_account, group#member] or super_admin",
		"define v_update: [user, service_account, group#member] or super_admin or v_get")
	rep := mustAdmitKey(t, compose(keyBox, item), keyTerms()...)
	got := seedsOf(rep, RuleD3)
	if len(got) != 1 {
		t.Fatalf("ждали ровно одну находку Д3 (на семени), получено %v", rep.Findings)
	}
	f, ok := got["acme_item.v_update"]
	if !ok {
		t.Fatalf("находка обязана стоять на объявлении-семени acme_item.v_update, получено %+v", rep.Findings)
	}
	const path = "acme_item.v_update → acme_item.v_get → acme_box.public_reader"
	if !strings.Contains(f.Text, path) || f.Term != "system_class" {
		t.Fatalf("находка обязана называть путь %q и запись system_class, получено %+v", path, f)
	}
}

// TestAdmitEdgeIsCutOnlyTowardADeclaredNewContainer — CE-07: терм
// `public_reader from <указатель>` законен, только когда указатель ведёт в НОВЫЙ
// тип, объявленный контейнером этим же перечнем. Близнец — keyItem.
func TestAdmitEdgeIsCutOnlyTowardADeclaredNewContainer(t *testing.T) {
	const child = `type acme_thing
  relations
    define reg: [registry_registry]
    define super_admin: super_admin from reg
    define v_get: [user, service_account, group#member] or super_admin or public_reader from reg
`
	terms := append(keyTerms(), KeyTerm{Type: "acme_thing", Relation: "v_get", Pointer: "reg"})
	rep := mustAdmitKey(t, compose(keyBox, keyItem, child), terms...)
	got := seedsOf(rep, RuleD3)
	if _, ok := got["acme_thing.v_get"]; !ok || len(got) != 1 {
		t.Fatalf("указатель в КАНОНИЧЕСКИЙ контейнер законным термом не становится: ждали одну находку "+
			"на acme_thing.v_get, получено %v", rep.Findings)
	}

	// Новый тип, НЕ объявленный контейнером (в перечне нет его public_reader):
	// ребро в него не режется.
	partial := []KeyTerm{
		{Type: "acme_item", Relation: "v_get", Pointer: "box"},
		{Type: "acme_item", Relation: "v_list", Pointer: "box"},
	}
	rep = mustAdmitKey(t, compose(keyBox, keyItem), partial...)
	got = seedsOf(rep, RuleD3)
	for _, want := range []string{"acme_item.v_get", "acme_item.v_list", "acme_box.public_reader"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("ребро в контейнер, не объявленный перечнем, не режется: ждали находку на %s, получено %v",
				want, rep.Findings)
		}
	}
}

// TestAdmitFindingsAreDeterministic — CE-08: текст, порядок и записи находок не
// зависят от обхода карт; порядок — по семени.
func TestAdmitFindingsAreDeterministic(t *testing.T) {
	item := swapDecl(keyItem,
		"define v_update: [user, service_account, group#member] or super_admin",
		"define v_update: [user, service_account, group#member] or super_admin or v_get or v_list")
	box := swapDecl(keyBox,
		"define v_update: [user, service_account, group#member] or super_admin",
		"define v_update: [user, service_account, group#member] or super_admin or v_list or v_get")
	composed := compose(box, item)
	first := mustAdmitKey(t, composed, keyTerms()...)
	if len(first.Findings) != 2 {
		t.Fatalf("ждали две находки (acme_box.v_update, acme_item.v_update), получено %v", first.Findings)
	}
	if first.Findings[0].Type != "acme_box" || first.Findings[1].Type != "acme_item" {
		t.Fatalf("порядок находок — по семени (тип в порядке объявления), получено %v", first.Findings)
	}
	for i := 0; i < 200; i++ {
		again := mustAdmitKey(t, composed, keyTerms()...)
		if !reflect.DeepEqual(first.Findings, again.Findings) {
			t.Fatalf("прогон %d дал другие находки:\n  %v\n  %v", i, first.Findings, again.Findings)
		}
	}
}
