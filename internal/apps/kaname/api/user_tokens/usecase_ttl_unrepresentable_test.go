// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_ttl_unrepresentable_test.go — второй глагол выдачи того же класса,
// что kaname#993: `ttl_seconds` умножался на `time.Second` без проверки
// диапазона, и срок длиннее 9223372036 секунд заворачивался по модулю 2^64.
// Значение 2^55 давало ровно ноль: у SECRET — ключ на умолчание политики, у
// KEYPAIR — истекающий в миг выдачи; 9223372037 — срок истечения в прошлом.
//
// Незаданный срок (ноль на проводе) — по контракту: KEYPAIR бессрочен, SECRET
// получает умолчание политики; это держат пробы BAT-1-17 и
// TestIssue_KeypairWithZeroTTLIsIssuedWithoutExpiry, здесь — только заворот.
package user_tokens

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
)

func TestIssue_TTLWithoutPositiveLifetimeIsRefusedForAPerson(t *testing.T) {
	at := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	issue := func(kind domain.CredentialKind, ttl int64) (*stubUserClientRepo, *stubOpsRepo, error) {
		repo := &stubUserClientRepo{}
		ops := &stubOpsRepo{}
		uc := NewIssueUserTokenUseCase(repo, &stubTx{}, ops).WithIssuanceClock(momentclock.At(at)).WithOwnIssuance()
		_, err := uc.Execute(context.Background(), IssueInput{
			UserID: "usr00000000000000001", CreatedByUserID: "usr00000000000000001",
			CredentialKind: kind, TTLSeconds: ttl,
		})
		return repo, ops, err
	}

	refused := []struct {
		name    string
		kind    domain.CredentialKind
		ttl     int64
		wantMsg string
	}{
		{"KEYPAIR: заворот в ноль", domain.CredentialKindKeypair, 1 << 55, "ttl_seconds must be <= 9223372036"},
		{"KEYPAIR: заворот в отрицательное", domain.CredentialKindKeypair, 9223372037, "ttl_seconds must be <= 9223372036"},
		{"SECRET: заворот в ноль", domain.CredentialKindSecret, 1 << 55,
			"ttl_seconds: exceeds the SECRET ceiling of 7776000 seconds for credential_kind SECRET"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			repo, _, err := issue(tc.kind, tc.ttl)
			st, _ := grpcstatus.FromError(err)
			if st.Code() != codes.InvalidArgument {
				t.Fatalf("код = %v (err=%v); ожидался InvalidArgument: срок %d секунд положительной длительности не даёт",
					st.Code(), err, tc.ttl)
			}
			if st.Message() != tc.wantMsg {
				t.Errorf("текст отказа = %q; ожидался %q", st.Message(), tc.wantMsg)
			}
			if repo.inserted.ID != "" {
				t.Errorf("отказанный срок записал удостоверение с expires_at=%v", repo.inserted.ExpiresAt)
			}
		})
	}

	twins := []struct {
		name string
		kind domain.CredentialKind
		ttl  int64
		want time.Duration
	}{
		{"KEYPAIR: +1h", domain.CredentialKindKeypair, 3600, time.Hour},
		{"SECRET: +1h", domain.CredentialKindSecret, 3600, time.Hour},
		{"KEYPAIR: наибольший представимый", domain.CredentialKindKeypair, 9223372036, 9223372036 * time.Second},
	}
	for _, tc := range twins {
		t.Run(tc.name, func(t *testing.T) {
			repo, ops, err := issue(tc.kind, tc.ttl)
			if err != nil {
				t.Fatalf("законный срок %d отвергнут: %v", tc.ttl, err)
			}
			if tc.kind == domain.CredentialKindKeypair {
				waitForOp(t, ops)
			}
			if repo.inserted.ExpiresAt == nil {
				t.Fatal("удостоверение записано бессрочным либо не записано")
			}
			if got, want := *repo.inserted.ExpiresAt, at.Add(tc.want); !got.Equal(want) {
				t.Errorf("expires_at = %v; ожидалось %v", got, want)
			}
		})
	}
}
