// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// service_name_form_probe_test.go — форма имени службы, которой пробы пакета
// объявляют установку, и доказательство того, что читатели признания спрашивают
// именно объявленную форму (kaname#308) через перечень личностей (kaname#984).
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

	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
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

// edgeRosterOfForm — перечень, объявляющий краем учётку формы form в
// пространстве `platform`, и идентификатор этого края.
func edgeRosterOfForm(t *testing.T, form servicesan.Form) (moduleidentity.Roster, string) {
	t.Helper()
	account := form.Account("api-gateway")
	r, err := moduleidentity.Parse(form, []string{"platform/" + account + "=edge"})
	if err != nil {
		t.Fatalf("перечень формы %s не разобрался: %v", form, err)
	}
	return r, "spiffe://" + probeTrustDomain + "/ns/platform/sa/" + account
}

// Инъекция предмета задачи по читателям внутреннего и публичного слушателей:
// край узнаётся учёткой ОБЪЯВЛЕННОЙ формы, какой бы она ни была, а учётка
// другой формы — нет. Две формы, ни одна не совпадает с литералом прежнего
// разбора; у каждой близнец отрицания — край другой формы.
func TestReadersAskTheDeclaredForm_ForeignFormEdgeIsRefused(t *testing.T) {
	mod, other := testServiceNameForm, servicesan.NewForm("other-{service}-sa")
	modRoster, modEdge := edgeRosterOfForm(t, mod)
	otherRoster, otherEdge := edgeRosterOfForm(t, other)

	for _, tc := range []struct {
		name            string
		roster          moduleidentity.Roster
		declared, alien string
	}{
		{"форма mod-{service}", modRoster, modEdge, otherEdge},
		{"форма other-{service}-sa", otherRoster, otherEdge, modEdge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			internal := NewCallerPolicy(true, GatewayFrontedInternalRPCs()).WithModuleRoster(tc.roster)
			if err := internal.allow(verifiedCtx(tc.declared), gatewayOnlyMethod); err != nil {
				t.Fatalf("внутренний слушатель: край объявленной формы отвергнут: %v", err)
			}
			if code := status.Code(internal.allow(verifiedCtx(tc.alien), gatewayOnlyMethod)); code != codes.PermissionDenied {
				t.Fatalf("внутренний слушатель: край чужой формы получил %v, ждали PermissionDenied — пол не "+
					"спрашивает объявленную форму", code)
			}

			public := NewPublicCallerPolicy(true, PublicPeerCallableRPCs(), nil,
				func(context.Context) bool { return false }).WithModuleRoster(tc.roster)
			if err := public.allow(verifiedCtx(tc.declared), publicProjectGetMethod); err != nil {
				t.Fatalf("публичный слушатель: край объявленной формы отвергнут: %v", err)
			}
			if err := public.allow(verifiedCtx(tc.alien), publicProjectGetMethod); err == nil {
				t.Fatal("публичный слушатель: край чужой формы допущен — пол не спрашивает объявленную форму")
			}
		})
	}
}

// Перечень при НЕОБЪЯВЛЕННОЙ форме не собирается с записями, а политика без
// перечня не узнаёт никого — ни край, ни модуль: нулевое значение фейл-клоуз,
// а не «принимаем любую приставку».
func TestReadersAskTheDeclaredForm_UndeclaredFormRecognizesNobody(t *testing.T) {
	const edge = "spiffe://" + probeTrustDomain + "/ns/platform/sa/mod-api-gateway"
	var undeclared servicesan.Form

	if _, err := moduleidentity.Parse(undeclared, []string{"platform/mod-api-gateway=edge"}); err == nil {
		t.Fatal("перечень собран при необъявленной форме имени службы")
	}
	p := NewCallerPolicy(true, GatewayFrontedInternalRPCs()).WithModuleRoster(moduleidentity.Roster{})
	if code := status.Code(p.allow(verifiedCtx(edge), floorOnlyMethod)); code != codes.PermissionDenied {
		t.Fatalf("пол без перечня пропустил предъявителя: %v", code)
	}
}
