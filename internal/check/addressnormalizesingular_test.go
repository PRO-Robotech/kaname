// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// addressnormalizesingular_test.go — NTF1-B27 (гейт) по дереву kaname:
// нормализация адреса и её доменная часть ровно одни (Р8, З16).
//
//   - узел IDNA — ссылка на функцию golang.org/x/net/idna вне пакета
//     corelib/notify/address;
//   - узел приёмника address.Domain — ссылка на тип, подстановка в параметр
//     типа, отброшенная ошибка и иное использование NormalizeDomain.
//
// ТОНКИЙ ВЫЗЫВАЮЩИЙ: оба узла и их допустимое место живут в corelib
// (`treehygiene.AuditIDNASingular`, `treehygiene.AuditDomainReceivers`), здесь
// только корень дерева и каталог стабов. Инъекция B27 (гейт) (1) прогоном по
// kaname — в notifytypesafety_test.go, вместе с прочими инъекциями той же
// копии дерева.
package check_test

import (
	"testing"

	"github.com/PRO-Robotech/corelib/treehygiene"
)

// TestNTF1B27Gate_OnKaname — узел IDNA по дереву kaname: ссылок на idna 0.
func TestNTF1B27Gate_OnKaname(t *testing.T) {
	root := notifyTreeRoot(t)
	r, err := treehygiene.AuditIDNASingular(root, notifyStubDir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Log(r.String())
	requireTreeCensus(t, root, r.Census)
	for _, f := range r.Findings {
		t.Errorf("NTF1-B27 (гейт) · %s", f)
	}
}

// TestNTF1B27Receiver_OnKaname — узел приёмника address.Domain по дереву
// kaname: допустимых мест приёмника нет (Д19), узлов 0.
func TestNTF1B27Receiver_OnKaname(t *testing.T) {
	root := notifyTreeRoot(t)
	r, err := treehygiene.AuditDomainReceivers(root, notifyStubDir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Log(r.String())
	requireTreeCensus(t, root, r.Census)
	for _, f := range r.Findings {
		t.Errorf("NTF1-B27 (гейт, приёмник address.Domain) · %s", f)
	}
}
