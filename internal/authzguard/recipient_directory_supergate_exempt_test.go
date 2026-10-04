// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// recipient_directory_supergate_exempt_test.go — приёмка NTF-3 (kacho#2918),
// Р28 и NTF3-151, места Д-6 (`checkAdapter.Check`) и Д-7 (`AllowsVerb`)
// переписи §1.11 NTF-1 — для типа справочника адресов
// `notification_recipient_directory`.
//
// Перечень типов без надзора администратора облака дополняется третьим типом
// (Р28): адреса пользователей установки читает только `service:notify`, и
// администратор облака мимо модели их не читает ни на одном пути двери, где
// надзор спрашивается. Места Д-6 и Д-7 зовутся напрямую по тому же доводу, что
// в `supergate_exempt_test.go`: у обобщённой двери тип — параметр.
//
// Близнец по типу — `iam_user:<U2>` с `token_issuer` (форма NTF1-F12):
// администратору облака его даёт только надзор, и «да» там означает, что надзор
// жив вне перечня. Без близнеца «нет» на справочнике зеленело бы на двери,
// отказывающей всем.

import (
	"context"
	"testing"
)

const recipientDirectoryObject = "notification_recipient_directory:root"

// TestNTF3151_SuperGateExempt_OwnDoorCheckAdapter_RecipientDirectory — Д-6.
func TestNTF3151_SuperGateExempt_OwnDoorCheckAdapter_RecipientDirectory(t *testing.T) {
	facts := &adminOnlyFacts{}
	door := checkAdapter{inner: facts}

	// Близнец по типу ПЕРВЫМ: сломанный надзор не имеет права выдать себя за
	// снятый перечнем.
	twin, err := door.Check(context.Background(), "user:"+exemptAdminID, "token_issuer", "iam_user:"+exemptTwinUser)
	if err != nil {
		t.Fatalf("Д-6 близнец: %v", err)
	}
	if !twin {
		t.Fatal("Д-6 близнец по типу iam_user:<U2>: отказ — надзор вне перечня обязан остаться в силе; " +
			"вопрос пробы сломан, предмет не спрошен")
	}
	facts.superAsks = 0

	allowed, err := door.Check(context.Background(), "user:"+exemptAdminID, "reader", recipientDirectoryObject)
	if err != nil {
		t.Fatalf("Д-6 %s: %v", recipientDirectoryObject, err)
	}
	if allowed {
		t.Fatalf("Д-6 %s: разрешено администратору облака без кортежа — надзор решил исход на типе справочника (Р28)",
			recipientDirectoryObject)
	}
	if facts.superAsks != 0 {
		t.Fatalf("Д-6: надзор спрошен %d раз на типе справочника", facts.superAsks)
	}
}

// TestNTF3151_SuperGateExempt_AllowsVerb_RecipientDirectory — Д-7: надзор здесь
// спрашивается ПЕРВЫМ, поэтому на типе перечня он обязан не спрашиваться вовсе.
func TestNTF3151_SuperGateExempt_AllowsVerb_RecipientDirectory(t *testing.T) {
	facts := &adminOnlyFacts{}

	twin, err := AllowsVerb(adminPrincipalCtx(), facts, "token_issuer", "iam_user", exemptTwinUser)
	if err != nil {
		t.Fatalf("Д-7 близнец: %v", err)
	}
	if !twin {
		t.Fatal("Д-7 близнец по типу iam_user/<U2>: отказ — надзор вне перечня обязан остаться в силе; " +
			"вопрос пробы сломан, предмет не спрошен")
	}
	facts.superAsks = 0

	allowed, err := AllowsVerb(adminPrincipalCtx(), facts, "reader", "notification_recipient_directory", "root")
	if err != nil {
		t.Fatalf("Д-7 notification_recipient_directory: %v", err)
	}
	if allowed {
		t.Fatal("Д-7 notification_recipient_directory/root: разрешено администратору облака без кортежа (Р28)")
	}
	if facts.superAsks != 0 {
		t.Fatalf("Д-7: надзор спрошен %d раз на типе справочника", facts.superAsks)
	}
}

// TestNTF3151_SuperGateExemptListNamesTheRecipientDirectory — перечень один и
// несёт три типа (Р28): прежние два и тип справочника. Отдельно от мест двери:
// место, зовущее предикат, и содержимое предиката — две оси, и красное каждой
// называет свою.
func TestNTF3151_SuperGateExemptListNamesTheRecipientDirectory(t *testing.T) {
	for _, typ := range []string{"notification_feed", "notification_namespace"} {
		if !SuperGateExempt(typ) {
			t.Fatalf("положительный контроль: %s выпал из перечня — вопрос пробы сломан", typ)
		}
	}
	if SuperGateExempt("iam_user") {
		t.Fatal("контроль: iam_user в перечне — перечень отвечает «да» всем, и вопрос о справочнике ничего не различит")
	}
	if !SuperGateExempt("notification_recipient_directory") {
		t.Fatalf("тип справочника notification_recipient_directory не в перечне без надзора (Р28); перечень: %v",
			superGateExemptTypes)
	}
	if n := len(superGateExemptTypes); n != 3 {
		t.Fatalf("в перечне без надзора %d типов, ожидалось ровно 3 (Р28): %v", n, superGateExemptTypes)
	}
}
