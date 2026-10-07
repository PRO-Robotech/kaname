// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// user_token_own_issuance_wiring_test.go — одно условие на два пути выдачи
// (приёмка `docs/engineering/acceptance/credential-verbs-refusal-outcomes.md`,
// сценарий CVR-26, задача kaname#547).
//
// Сборка выдачи токенов человека спрашивает о посадке ТО ЖЕ условие, что
// сборка ключей служебных учёток, — `saKeyIssuanceIsOurs`. Наблюдается это
// исходом настоящего обработчика, собранного настоящей сборкой корня:
//
//   - ветвь б (`authn.client-token.enabled=false`) — выдача ключевой пары
//     отказывает `FAILED_PRECONDITION` с именем ручки ДО всякого чтения;
//   - ветвь а (`true`) — тот же запрос отказом посадки НЕ встречен и доходит
//     до хранилища. Хранилище здесь — пул на заведомо недостижимый адрес,
//     поэтому дошедший запрос получает `UNAVAILABLE`: это и есть свидетельство,
//     что посадка его пропустила, а не что выдача сломана.
package main

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestUserTokenIssuance_FollowsTheExchangeEndpoint(t *testing.T) {
	ctx := context.Background()
	// Пул без соединений: pgxpool не звонит при построении, а первый вызов
	// получает отказ соединения — ровно «хранилище не ответило».
	pool, err := pgxpool.New(ctx, "postgres://u:p@127.0.0.1:1/kaname?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("пул на недостижимый адрес не построен: %v", err)
	}
	t.Cleanup(pool.Close)

	user := ids.NewID(domain.PrefixUser)
	call := operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: user})
	req := &iamv1.IssueUserTokenRequest{UserId: user, CredentialKind: iamv1.CredentialKind_CREDENTIAL_KIND_KEYPAIR}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock, err := buildSharedClock(pool)
	if err != nil {
		t.Fatalf("общий источник моментов не построен: %v", err)
	}

	for _, tc := range []struct {
		name    string
		enabled bool
		want    codes.Code
	}{
		{name: "ветвь а: эндпоинт объявлен — отказа посадки нет, запрос дошёл до хранилища", enabled: true, want: codes.Unavailable},
		{name: "ветвь б: эндпоинта нет — отказ посадки с именем ручки", enabled: false, want: codes.FailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := devOwnWithoutOwnSAKeyIssuance()
			cfg.AuthN.ClientToken.Enabled = tc.enabled
			if got := saKeyIssuanceIsOurs(cfg); got != tc.enabled {
				t.Fatalf("предпосылка: saKeyIssuanceIsOurs = %v при ручке %v", got, tc.enabled)
			}
			h := buildUserTokensHandler(pool, nil, cfg, clock, logger)
			_, err := h.Issue(call, req)
			if got := grpcstatus.Code(err); got != tc.want {
				t.Fatalf("исход выдачи ключевой пары человека %v (%v), ожидался %v", got, err, tc.want)
			}
			hasKnob := strings.Contains(grpcstatus.Convert(err).Message(), "authn.client-token.enabled")
			if hasKnob != !tc.enabled {
				t.Fatalf("имя ручки в отказе: %v при ручке %v — %v", hasKnob, tc.enabled, err)
			}
		})
	}
}
