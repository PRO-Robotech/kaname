// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authorize

import (
	"context"
	"testing"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/testsupport/moduleroster"
)

// TestCallerAuthority_ModuleRecognitionAgreesWithEveryOtherPath — kaname#984,
// DoD п. 4, путь обработчика решений.
//
// Пир без переданной личности допускается к вопросу о чужом субъекте только
// как ПРИЗНАННЫЙ модуль. Набор форм — тот же, что у путей стража
// (`authzguard.TestModuleRoster_EveryCallerCheckPathDecidesTheSame`): решение
// этого пути обязано совпасть с ожиданием формы так же, как у них.
func TestCallerAuthority_ModuleRecognitionAgreesWithEveryOtherPath(t *testing.T) {
	h := newHandlerWithAuthorityProd(true, &authorityStub{allow: map[string]bool{}}).
		WithModuleRoster(moduleroster.Roster(t))
	req := &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_bob",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_any"},
		Action:   "iam.accounts.get",
	}
	for _, form := range moduleroster.Forms() {
		_, err := h.Check(form.Context(context.Background()), req)
		if got := err == nil; got != form.Module {
			t.Errorf("форма %q (%s): обработчик решений признал модулем = %v, ожидалось %v (ошибка %v)",
				form.Name, form.SAN, got, form.Module, err)
		}
	}
}
