// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_ttl_unrepresentable_test.go — названный срок, который НЕ ДАЁТ
// положительной длительности, отвергается, а не превращается в ключ на срок по
// умолчанию, в уже истёкший ключ или в ключ на доли секунды (kaname#993).
//
// Механизм: `ttl_seconds` умножался на `time.Second` без проверки диапазона.
// Срок длиннее 9223372036 секунд в `time.Duration` не помещается, и
// произведение заворачивается по модулю 2^64. Значение 2^55 даёт РОВНО ноль —
// у вида SECRET это «срок не назван», и выдавался ключ на умолчание политики;
// у KEYPAIR и FEDERATED — истекающий в миг выдачи. Значение 9223372037 даёт
// отрицательную длительность: срок истечения в прошлом. Потолок установки
// сравнивался с тем же завёрнутым числом и такой запрос пропускал.
//
// «Срок не задан» на проводе — ноль: поле `ttl_seconds` скалярное, и контракт
// метода объявляет ноль написанием «срок не назван» (умолчание установки).
// Отдельного «явного нуля» контракт не выражает; проба закрепляет названный
// контрактом исход незаданного срока — умолчание установки.
//
// Каждый отказ держится в паре с законным близнецом, отличающимся ОДНИМ
// фактом — значением срока.
package sa_keys

import (
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

const (
	// ttlWrapsToZero — 2^55 секунд: произведение на 10^9 кратно 2^64.
	ttlWrapsToZero int64 = 1 << 55
	// ttlWrapsNegative — на секунду длиннее наибольшего представимого срока:
	// произведение переходит через верх int64 и становится отрицательным.
	ttlWrapsNegative int64 = 9223372037
	// ttlWrapsToFraction — произведение заворачивается в 0,29 секунды.
	ttlWrapsToFraction int64 = 18446744074
	// ttlLongestRepresentable — наибольший срок в секундах, помещающийся в
	// time.Duration без заворота.
	ttlLongestRepresentable int64 = 9223372036
)

// federatedSubject — законный доверенный субъект для федеративной выдачи.
func federatedSubject() []domain.TrustedSubject {
	return []domain.TrustedSubject{{
		Issuer:         "https://kube.cluster.local",
		SubjectPattern: "^system:serviceaccount:ci:deployer$",
		PublicKeyPEM:   testIssuerPublicKeyPEM,
		KeyAlgorithm:   "ES256",
	}}
}

// TestIssue_TTLWithoutPositiveLifetimeIsRefused — срок, не дающий положительной
// длительности, отвергается INVALID_ARGUMENT с именем поля до всякой записи:
// операции нет, строки ключа нет, записи доверия нет.
func TestIssue_TTLWithoutPositiveLifetimeIsRefused(t *testing.T) {
	cases := []struct {
		name    string
		ttl     int64
		kind    domain.CredentialKind
		fed     bool
		maxTTL  time.Duration
		wantMsg string
	}{
		{name: "срок в прошлом", ttl: -1, kind: domain.CredentialKindKeypair, maxTTL: 365 * 24 * time.Hour,
			wantMsg: "ttl_seconds must be >= 0"},
		{name: "KEYPAIR: заворот в ноль при потолке", ttl: ttlWrapsToZero, kind: domain.CredentialKindKeypair, maxTTL: 365 * 24 * time.Hour,
			wantMsg: "ttl_seconds must be <= 31536000 (8760h0m0s)"},
		{name: "KEYPAIR: заворот в отрицательное при потолке", ttl: ttlWrapsNegative, kind: domain.CredentialKindKeypair, maxTTL: 365 * 24 * time.Hour,
			wantMsg: "ttl_seconds must be <= 31536000 (8760h0m0s)"},
		{name: "KEYPAIR: заворот в доли секунды при потолке", ttl: ttlWrapsToFraction, kind: domain.CredentialKindKeypair, maxTTL: 365 * 24 * time.Hour,
			wantMsg: "ttl_seconds must be <= 31536000 (8760h0m0s)"},
		{name: "KEYPAIR: заворот в ноль без потолка", ttl: ttlWrapsToZero, kind: domain.CredentialKindKeypair, maxTTL: 0,
			wantMsg: "ttl_seconds must be <= 9223372036"},
		{name: "KEYPAIR: заворот в отрицательное без потолка", ttl: ttlWrapsNegative, kind: domain.CredentialKindKeypair, maxTTL: 0,
			wantMsg: "ttl_seconds must be <= 9223372036"},
		{name: "SECRET: заворот в ноль", ttl: ttlWrapsToZero, kind: domain.CredentialKindSecret, maxTTL: 365 * 24 * time.Hour,
			wantMsg: "ttl_seconds: exceeds the SECRET ceiling of 7776000 seconds for credential_kind SECRET"},
		{name: "SECRET: заворот в отрицательное", ttl: ttlWrapsNegative, kind: domain.CredentialKindSecret, maxTTL: 365 * 24 * time.Hour,
			wantMsg: "ttl_seconds: exceeds the SECRET ceiling of 7776000 seconds for credential_kind SECRET"},
		{name: "FEDERATED: заворот в ноль без потолка", ttl: ttlWrapsToZero, fed: true, maxTTL: 0,
			wantMsg: "ttl_seconds must be <= 9223372036"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTTLHarness(t)
			h.uc.DefaultTTL = 90 * 24 * time.Hour
			h.uc.MaxTTL = tc.maxTTL
			in := IssueInput{TTLSeconds: tc.ttl, CredentialKind: tc.kind}
			if tc.fed {
				in.CredentialKind = ""
				in.TrustedSubjects = federatedSubject()
			}

			err := h.issue(t, in)

			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("код = %v (err=%v); ожидался InvalidArgument: срок %d секунд положительной длительности не даёт",
					status.Code(err), err, tc.ttl)
			}
			if got := status.Convert(err).Message(); got != tc.wantMsg {
				t.Errorf("текст отказа = %q; ожидался %q", got, tc.wantMsg)
			}
			if h.ops.created {
				t.Error("отказанный срок завёл операцию")
			}
			if h.repo.insertOK {
				t.Errorf("отказанный срок записал ключ с expires_at=%v", h.repo.inserted.ExpiresAt)
			}
			if len(h.trust.calls) != 0 {
				t.Errorf("отказанный срок записал доверие издателю: %+v", h.trust.calls)
			}
		})
	}
}

// TestIssue_TTLTwinsKeepTheirContract — законные близнецы отказов: названный
// срок применяется дословно, наибольший представимый срок без потолка
// принимается без заворота, незаданный срок получает умолчание по контракту.
func TestIssue_TTLTwinsKeepTheirContract(t *testing.T) {
	cases := []struct {
		name   string
		ttl    int64
		kind   domain.CredentialKind
		fed    bool
		maxTTL time.Duration
		want   time.Duration
	}{
		{name: "KEYPAIR: +1h", ttl: 3600, kind: domain.CredentialKindKeypair, maxTTL: 365 * 24 * time.Hour, want: time.Hour},
		{name: "SECRET: +1h", ttl: 3600, kind: domain.CredentialKindSecret, maxTTL: 365 * 24 * time.Hour, want: time.Hour},
		{name: "FEDERATED: +1h", ttl: 3600, fed: true, maxTTL: 365 * 24 * time.Hour, want: time.Hour},
		{name: "KEYPAIR: наибольший представимый без потолка", ttl: ttlLongestRepresentable, kind: domain.CredentialKindKeypair,
			maxTTL: 0, want: time.Duration(ttlLongestRepresentable) * time.Second},
		{name: "KEYPAIR: срок не задан — умолчание установки", ttl: 0, kind: domain.CredentialKindKeypair,
			maxTTL: 365 * 24 * time.Hour, want: 90 * 24 * time.Hour},
		{name: "SECRET: срок не задан — умолчание политики", ttl: 0, kind: domain.CredentialKindSecret,
			maxTTL: 365 * 24 * time.Hour, want: 30 * 24 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTTLHarness(t)
			h.uc.DefaultTTL = 90 * 24 * time.Hour
			h.uc.MaxTTL = tc.maxTTL
			in := IssueInput{TTLSeconds: tc.ttl, CredentialKind: tc.kind}
			if tc.fed {
				in.CredentialKind = ""
				in.TrustedSubjects = federatedSubject()
			}

			if err := h.issue(t, in); err != nil {
				t.Fatalf("законный срок %d отвергнут: %v", tc.ttl, err)
			}
			waitForOp(t, h.ops)
			if !h.repo.insertOK || h.repo.inserted.ExpiresAt == nil {
				t.Fatalf("ключ не записан либо записан бессрочным: insertOK=%v", h.repo.insertOK)
			}
			if got, want := *h.repo.inserted.ExpiresAt, h.now.Add(tc.want); !got.Equal(want) {
				t.Errorf("expires_at = %v; ожидалось %v", got, want)
			}
		})
	}
}
