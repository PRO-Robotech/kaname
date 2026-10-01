// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// supergate_exempt_test.go — NTF1-F12 (ж): места Д-6 (`checkAdapter.Check`,
// дверь собственного публичного слушателя) и Д-7 (`AllowsVerb`, читающие стражи)
// переписи §1.11 приёмки NTF-1.
//
// Сегодня ни одно из двух мест типов ленты не получает: каталог публичных
// методов kaname этих типов не называет, а вызывающие `AllowsVerb` передают
// литералы своих типов. Предикат перечня стоит в обоих всё равно — у обобщённой
// двери тип есть параметр, и довод «сюда не доходит» истёк бы с первым же
// вызывающим, передавшим тип перечня. Поэтому проба зовёт оба места напрямую.
//
// Близнец по типу — `iam_user:<U2>` с `token_issuer`: администратору облака его
// даёт только надзор, и «да» там означает, что надзор жив вне перечня.

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
)

const (
	exemptAdminID  = "usr0000000000000ca01"
	exemptTwinUser = "usr0000000000000u201"
)

// adminOnlyFacts — хранилище, где у администратора облака есть ровно один факт:
// `system_admin` на синглтоне кластера. Считает вопросы надзора.
type adminOnlyFacts struct{ superAsks int }

func (f *adminOnlyFacts) Check(_ context.Context, subject, relation, object string) (bool, error) {
	if relation == "system_admin" {
		f.superAsks++
	}
	return subject == "user:"+exemptAdminID && relation == "system_admin" && object == ClusterObject(), nil
}

func adminPrincipalCtx() context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{ID: exemptAdminID, Type: "user"})
}

// TestSuperGateExempt_OwnDoorCheckAdapter — Д-6.
func TestSuperGateExempt_OwnDoorCheckAdapter(t *testing.T) {
	facts := &adminOnlyFacts{}
	door := checkAdapter{inner: facts}

	for _, object := range []string{"notification_feed:probe", "notification_namespace:probe"} {
		allowed, err := door.Check(context.Background(), "user:"+exemptAdminID, "reader", object)
		if err != nil {
			t.Fatalf("Д-6 %s: %v", object, err)
		}
		if allowed {
			t.Fatalf("Д-6 %s: разрешено администратору облака без кортежа — надзор решил исход на типе перечня", object)
		}
	}
	if facts.superAsks != 0 {
		t.Fatalf("Д-6: надзор спрошен %d раз на типах перечня", facts.superAsks)
	}

	allowed, err := door.Check(context.Background(), "user:"+exemptAdminID, "token_issuer", "iam_user:"+exemptTwinUser)
	if err != nil {
		t.Fatalf("Д-6 близнец: %v", err)
	}
	if !allowed {
		t.Fatal("Д-6 близнец по типу iam_user:<U2>: отказ — надзор вне перечня обязан остаться в силе")
	}
}

// TestSuperGateExempt_AllowsVerb — Д-7: надзор здесь спрашивается ПЕРВЫМ, поэтому
// на типе перечня он обязан не спрашиваться вовсе.
func TestSuperGateExempt_AllowsVerb(t *testing.T) {
	facts := &adminOnlyFacts{}
	for _, typ := range []string{"notification_feed", "notification_namespace"} {
		allowed, err := AllowsVerb(adminPrincipalCtx(), facts, "reader", typ, "probe")
		if err != nil {
			t.Fatalf("Д-7 %s: %v", typ, err)
		}
		if allowed {
			t.Fatalf("Д-7 %s/probe: разрешено администратору облака без кортежа", typ)
		}
	}
	if facts.superAsks != 0 {
		t.Fatalf("Д-7: надзор спрошен %d раз на типах перечня", facts.superAsks)
	}

	allowed, err := AllowsVerb(adminPrincipalCtx(), facts, "token_issuer", "iam_user", exemptTwinUser)
	if err != nil {
		t.Fatalf("Д-7 близнец: %v", err)
	}
	if !allowed {
		t.Fatal("Д-7 близнец по типу iam_user/<U2>: отказ — надзор вне перечня обязан остаться в силе")
	}
}

// TestSplitModelObject_IsTheModelsParse — разделитель — ПЕРВОЕ двоеточие, как у
// модели; строка, не являющаяся объектом, не разбирается.
func TestSplitModelObject_IsTheModelsParse(t *testing.T) {
	for _, tc := range []struct{ in, wantType, wantID string }{
		{"notification_feed:probe", "notification_feed", "probe"},
		{"notification_feed:x:probe", "notification_feed", "x:probe"},
		{"registry_repository:reg_1/app:v1", "registry_repository", "reg_1/app:v1"},
	} {
		gotType, gotID, ok := SplitModelObject(tc.in)
		if !ok || gotType != tc.wantType || gotID != tc.wantID {
			t.Fatalf("SplitModelObject(%q) = (%q, %q, %v), ожидалось (%q, %q)", tc.in, gotType, gotID, ok, tc.wantType, tc.wantID)
		}
	}
	for _, bad := range []string{"", "notification_feed", ":probe", "notification_feed:"} {
		if gotType, gotID, ok := SplitModelObject(bad); ok {
			t.Fatalf("SplitModelObject(%q) = (%q, %q) — строка объектом не является", bad, gotType, gotID)
		}
	}
}
