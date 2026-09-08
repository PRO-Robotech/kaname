// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package refusaldomain_test

// refusaldomain_test.go — сценарии WIRE-3-01 и WIRE-3-03 приёмки WIRE-1
// (APPROVED, 2026-09-06; предмет ПР-3, задача продукта #2099).
//
// # Что здесь утверждается
//
// Домен в теле отказа — то, ЧЕМ ПРОДУКТ НАЗЫВАЕТ СЕБЯ перед клиентом. Клиент
// различает полосы отказа по паре «домен + признак полосы», а не разбором прозы
// сообщения, — значит поле есть часть контракта отказа, а не косметика.
//
// Суффикс объявляется ОДИН раз и читается как ВЕЛИЧИНА. Сборка, его не
// объявившая, не поднимается: величина, которую построение подставляет молча,
// предметом стража быть не может — он зелен при любом входе.

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"

	kerrors "github.com/PRO-Robotech/kacho/pkg/errors"

	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
)

// TestWIRE_3_01_RefusalCarriesTheProductsOwnDomain — несущее утверждение.
func TestWIRE_3_01_RefusalCarriesTheProductsOwnDomain(t *testing.T) {
	got := refusaldomain.Compose(refusaldomain.ProductSuffix, refusaldomain.ServiceIAM)
	if got != "iam.kaname.cloud" {
		t.Fatalf("домен отказа = %q, ожидался %q", got, "iam.kaname.cloud")
	}
	if refusaldomain.ProductSuffix == "kacho.cloud" {
		t.Fatalf("продукт объявляет суффикс платформы — своего имени у него нет")
	}
}

// TestWIRE_3_02_PlatformKeepsItsOwn — положительный близнец, и он несущий: без
// него «фундамент переименован» неотличимо от «фундамент сломан для всех, кроме
// Kaname». Фундамент здесь тот же, из которого собран сервис Kachō, — служба его
// импортирует, поэтому близнец наблюдаем ровно отсюда.
func TestWIRE_3_02_PlatformKeepsItsOwn(t *testing.T) {
	err := kerrors.ReasonPeerResourceMissing.Errf(
		kerrors.PeerRef{Service: "vpc", ResourceType: "vpc.network", ResourceID: "net-1"}, "network not found")
	domain := domainOf(t, err)
	if domain != "vpc.kacho.cloud" {
		t.Fatalf("домен отказа платформы = %q, ожидался прежний %q", domain, "vpc.kacho.cloud")
	}
}

// TestWIRE_3_03_UndeclaredSuffixRefusesTheStart — страж старта.
func TestWIRE_3_03_UndeclaredSuffixRefusesTheStart(t *testing.T) {
	refusaldomain.ResetForTest(t)

	if err := refusaldomain.Require(); err == nil {
		t.Fatalf("сборка без объявленного суффикса поднялась — стража нет")
	} else if !errors.Is(err, refusaldomain.ErrUndeclared) {
		t.Fatalf("отказ старта = %v, ожидался %v", err, refusaldomain.ErrUndeclared)
	}
	// Отказ обязан НАЗЫВАТЬ незаданную величину: оператор и следующий
	// собирающий обязаны узнать из текста, что именно не объявлено.
	if err := refusaldomain.Require(); !containsAll(err.Error(), "refusaldomain.Declare") {
		t.Fatalf("отказ старта не называет величину: %q", err.Error())
	}
	// Ни один отказ не уезжает с пустым доменом и с подставленным умолчанием.
	if got := refusaldomain.For(refusaldomain.ServiceIAM); got != "" {
		t.Fatalf("необъявленный суффикс дал домен %q — умолчание подставлено молча", got)
	}

	// Положительный близнец: объявленный суффикс снимает отказ и даёт домен.
	if err := refusaldomain.Declare(refusaldomain.ProductSuffix); err != nil {
		t.Fatalf("объявление суффикса: %v", err)
	}
	if err := refusaldomain.Require(); err != nil {
		t.Fatalf("сборка с объявленным суффиксом не поднялась: %v", err)
	}
	if got := refusaldomain.For(refusaldomain.ServiceIAM); got != "iam.kaname.cloud" {
		t.Fatalf("домен после объявления = %q, ожидался %q", got, "iam.kaname.cloud")
	}
}

// TestDeclare_EmptyIsRefused — пустая величина объявлением НЕ является.
func TestDeclare_EmptyIsRefused(t *testing.T) {
	refusaldomain.ResetForTest(t)
	if err := refusaldomain.Declare("   "); err == nil {
		t.Fatalf("пустой суффикс принят за объявление")
	}
}

// TestDeclare_SecondDifferentValueIsRefused — второе объявление ДРУГИМ
// значением отвергается: два имени одного продукта расходятся молча, и
// расходятся они у клиента, который уже ключуется на первое.
func TestDeclare_SecondDifferentValueIsRefused(t *testing.T) {
	refusaldomain.ResetForTest(t)
	if err := refusaldomain.Declare(refusaldomain.ProductSuffix); err != nil {
		t.Fatalf("первое объявление: %v", err)
	}
	if err := refusaldomain.Declare("kacho.cloud"); err == nil {
		t.Fatalf("второе объявление другим значением принято")
	}
	// Повтор ТЕМ ЖЕ значением — не находка: композиционный корень и проба
	// объявляют одно и то же, и запрещать это значило бы запрещать проверяемость.
	if err := refusaldomain.Declare(refusaldomain.ProductSuffix); err != nil {
		t.Fatalf("повтор того же объявления отвергнут: %v", err)
	}
}

// TestCompose_NeitherHalfMayBeEmpty — половины домена обязаны быть обе.
func TestCompose_NeitherHalfMayBeEmpty(t *testing.T) {
	for _, c := range []struct{ suffix, service string }{
		{"", refusaldomain.ServiceIAM},
		{refusaldomain.ProductSuffix, ""},
		{"", ""},
	} {
		if got := refusaldomain.Compose(c.suffix, c.service); got != "" {
			t.Fatalf("Compose(%q, %q) = %q, ожидалась пустая строка", c.suffix, c.service, got)
		}
	}
}

// domainOf — домен из `google.rpc.ErrorInfo` отказа.
func domainOf(t *testing.T, err error) string {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("отказ не является статусом gRPC: %v", err)
	}
	for _, d := range st.Details() {
		if ei, isInfo := d.(*errdetails.ErrorInfo); isInfo {
			return ei.GetDomain()
		}
	}
	t.Fatalf("у отказа нет `ErrorInfo`: %v", err)
	return ""
}

// containsAll — все подстроки присутствуют.
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
