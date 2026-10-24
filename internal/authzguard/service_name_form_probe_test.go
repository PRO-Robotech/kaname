// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// service_name_form_probe_test.go — форма имени службы, которой пробы пакета
// объявляют установку, и доказательство того, что читатели разбора спрашивают
// именно объявленную форму (kaname#308).
//
// Приставка проб нарочно НЕ совпадает ни с одной, которую страж прав когда-либо
// держал литералом: проба, объявляющая ту же приставку, что стояла в коде,
// осталась бы зелёной и при вернувшемся литерале.

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/servicesan"
)

// testServiceNameForm — форма учёток модулей в пробах пакета.
var testServiceNameForm = servicesan.NewForm("mod-{service}")

// probeTrustDomain — домен доверия проб пакета.
const probeTrustDomain = "kacho.cloud"

// verifiedCtx — контекст с проверенным SAN в домене проб.
func verifiedCtx(san string) context.Context {
	return grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain(probeTrustDomain), san, true)
}

// Инъекция предмета задачи по всем читателям внутреннего и публичного
// слушателей: край назван учёткой ЧУЖОЙ формы — пол его не узнаёт и отказывает
// в боевой посадке. Близнец — тот же край в объявленной форме — проходит.
func TestReadersAskTheDeclaredForm_ForeignFormEdgeIsRefused(t *testing.T) {
	const (
		declared = "spiffe://" + probeTrustDomain + "/ns/platform/sa/mod-api-gateway"
		foreign  = "spiffe://" + probeTrustDomain + "/ns/platform/sa/other-api-gateway"
	)

	internal := NewCallerPolicy(true, GatewayFrontedInternalRPCs(), testServiceNameForm)
	if err := internal.allow(verifiedCtx(declared), gatewayOnlyMethod); err != nil {
		t.Fatalf("внутренний слушатель: край объявленной формы отвергнут: %v", err)
	}
	if code := status.Code(internal.allow(verifiedCtx(foreign), gatewayOnlyMethod)); code != codes.PermissionDenied {
		t.Fatalf("внутренний слушатель: край чужой формы получил %v, ждали PermissionDenied — пол не спрашивает "+
			"объявленную форму", code)
	}

	public := NewPublicCallerPolicy(true, PublicPeerCallableRPCs(), nil,
		func(context.Context) bool { return false }, testServiceNameForm)
	if err := public.allow(verifiedCtx(declared), publicProjectGetMethod); err != nil {
		t.Fatalf("публичный слушатель: край объявленной формы отвергнут: %v", err)
	}
	if err := public.allow(verifiedCtx(foreign), publicProjectGetMethod); err == nil {
		t.Fatal("публичный слушатель: край чужой формы допущен — пол не спрашивает объявленную форму")
	}

	if svc, ok := ServiceNameFromSAN(grpcsrv.NewTrustDomain(probeTrustDomain), testServiceNameForm, foreign); ok {
		t.Fatalf("разбор узнал учётку чужой формы службой %q", svc)
	}
}

// Политика, собранная с НЕОБЪЯВЛЕННОЙ формой, не узнаёт никого — ни край, ни
// модуль: нулевое значение фейл-клоуз, а не «принимаем любую приставку».
func TestReadersAskTheDeclaredForm_UndeclaredFormRecognizesNobody(t *testing.T) {
	const edge = "spiffe://" + probeTrustDomain + "/ns/platform/sa/mod-api-gateway"
	var undeclared servicesan.Form

	p := NewCallerPolicy(true, GatewayFrontedInternalRPCs(), undeclared)
	if code := status.Code(p.allow(verifiedCtx(edge), floorOnlyMethod)); code != codes.PermissionDenied {
		t.Fatalf("пол при необъявленной форме пропустил предъявителя: %v", code)
	}
	if _, ok := SANToServiceAccountID(grpcsrv.NewTrustDomain(probeTrustDomain), undeclared, edge); ok {
		t.Fatal("идентификатор служебной учётки выведен по необъявленной форме")
	}
}
