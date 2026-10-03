// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// user_token_own_issuance_wiring_test.go — сборка выдачи удостоверения
// человека объявляет use-case токен-эндпоинт из ТОГО ЖЕ условия, что сборка
// ключей служебной учётки (задача kaname#547).
//
// # Что здесь утверждается
//
// Провязку, а не её последствия у use-case (их держит
// `user_tokens/issuance_needs_the_token_endpoint_test.go`): собранный корнем
// обработчик на посадке без эндпоинта отвергает ключевую пару отказом с
// именем ручки, а на посадке с эндпоинтом — нет. Отказ решается до всякого
// чтения, поэтому базы проба не требует: пул смотрит на адрес, где никто не
// слушает, и на посадке с эндпоинтом выдача доходит до чтения и падает на нём —
// это и есть «отказа эндпоинта нет».
package main

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

func TestBuildUserTokensHandler_EndpointFollowsTheSAKeyCondition(t *testing.T) {
	const knob = "authn.client-token.enabled"
	for _, tc := range []struct {
		name          string
		enabled       bool
		wantKnobRefus bool
	}{
		{name: "эндпоинта нет — ключевая пара отвергается с именем ручки", enabled: false, wantKnobRefus: true},
		// Положительный близнец: без него проба зеленела бы на сборке,
		// отвергающей ключевую пару всегда.
		{name: "эндпоинт объявлен — отказа эндпоинта нет", enabled: true, wantKnobRefus: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg config.Config
			cfg.AuthN.ClientToken.Enabled = tc.enabled
			if cfg.SAKeyIssuanceIsOurs() != tc.enabled {
				t.Fatalf("предпосылка: условие сборки ключей (%v) не следует ручке (%v)",
					cfg.SAKeyIssuanceIsOurs(), tc.enabled)
			}
			h := buildUserTokensHandler(deadPool(t), nil, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

			ctx, cancel := context.WithTimeout(operations.WithPrincipal(context.Background(),
				operations.Principal{Type: "user", ID: "usr00000000000000001"}), 10*time.Second)
			defer cancel()
			_, err := h.Issue(ctx, &iamv1.IssueUserTokenRequest{
				UserId:         "usr00000000000000001",
				CredentialKind: iamv1.CredentialKind_CREDENTIAL_KIND_KEYPAIR,
			})
			if err == nil {
				t.Fatal("выдача на мёртвом пуле обязана отказать (до чтения либо на нём)")
			}
			st := status.Convert(err)
			gotKnob := st.Code() == codes.FailedPrecondition && strings.Contains(st.Message(), knob)
			if gotKnob != tc.wantKnobRefus {
				t.Errorf("отказ эндпоинта = %v, ожидалось %v; код %s, текст %q",
					gotKnob, tc.wantKnobRefus, st.Code(), st.Message())
			}
		})
	}
}
