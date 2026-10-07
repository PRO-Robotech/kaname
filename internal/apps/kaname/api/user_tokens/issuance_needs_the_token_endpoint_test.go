// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issuance_needs_the_token_endpoint_test.go — ключевая пара человека не
// выдаётся посадкой, где нет токен-эндпоинта платформы (приёмка
// `docs/engineering/acceptance/credential-verbs-refusal-outcomes.md`, сценарии
// CVR-21 … CVR-25, задача kaname#547).
//
// Ключевая пара предъявляется ОБМЕНОМ: подписанное утверждение меняется на
// токен, и обменивает его только наш токен-эндпоинт
// (`authn.client-token.enabled`). Выдача без него вернула бы ключ, который
// обменять негде. Отказ тот же, что у ключа служебной учётки (Р4): синхронный
// `FAILED_PRECONDITION` с именем ручки, после разбора запроса и до всякого
// чтения хранилища. Неназванный вид разрешается в KEYPAIR и отказывает так же;
// SECRET обмена не требует и выдаётся.
//
// Законные близнецы — та же выдача при объявленном эндпоинте (CVR-23) и SECRET
// без эндпоинта (CVR-24).
package user_tokens

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
)

// clientTokenKnob — ручка, которую обязан назвать отказ.
const clientTokenKnob = "authn.client-token.enabled"

// tokenEndpointDeclarer — объявление эндпоинта глаголу выдачи. Спрашивается
// утверждением о методе, чтобы проба собиралась и на дереве, где объявления
// ещё нет: там близнец «с эндпоинтом» и «без» — одна и та же сборка.
type tokenEndpointDeclarer interface {
	WithOwnIssuance() *IssueUserTokenUseCase
}

// withTokenEndpoint — глагол, которому объявлен токен-эндпоинт.
func withTokenEndpoint(uc *IssueUserTokenUseCase) *IssueUserTokenUseCase {
	if d, ok := any(uc).(tokenEndpointDeclarer); ok {
		return d.WithOwnIssuance()
	}
	return uc
}

// issueByOwner — человек выдаёт себе удостоверение названного вида.
func issueByOwner(kind domain.CredentialKind, ttl int64) IssueInput {
	return IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000001",
		CredentialKind:  kind,
		TTLSeconds:      ttl,
	}
}

// TestIssue_WithoutTheTokenEndpoint_KeypairIsRefusedNamingTheKnob — CVR-21
// (вид назван) и CVR-22 (вид не назван): отказ синхронный, с именем ручки,
// ничего не записано и хранилище не читалось. Исходы двух строк побайтово
// равны.
func TestIssue_WithoutTheTokenEndpoint_KeypairIsRefusedNamingTheKnob(t *testing.T) {
	msgs := map[string]string{}
	for name, kind := range map[string]domain.CredentialKind{
		"CVR-21 KEYPAIR":       domain.CredentialKindKeypair,
		"CVR-22 вид не назван": "",
	} {
		t.Run(name, func(t *testing.T) {
			repo := &stubUserClientRepo{}
			ops := &stubOpsRepo{}
			op, err := NewIssueUserTokenUseCase(repo, &stubTx{}, ops).WithIssuanceClock(momentclock.Func(time.Now)).Execute(context.Background(), issueByOwner(kind, 0))
			require.Error(t, err, "выдача ключевой пары, которую обменять негде, обязана отказать")
			require.Nil(t, op, "отказ синхронный: операции не заводится")
			require.Equal(t, codes.FailedPrecondition, grpcstatus.Code(err), "отказ: %v", err)
			require.Contains(t, grpcstatus.Convert(err).Message(), clientTokenKnob,
				"отказ обязан назвать ручку, которой он снимается")
			require.False(t, ops.created, "отказ до всякой записи: строки операции нет")
			require.Empty(t, repo.inserted.ID, "отказ до всякой записи: строки удостоверения нет")
			require.Zero(t, repo.accountCalls, "отказ стоит до разрешения аккаунта владельца: хранилище не читалось")
			msgs[name] = grpcstatus.Convert(err).Message()
		})
	}
	require.Equal(t, msgs["CVR-21 KEYPAIR"], msgs["CVR-22 вид не назван"],
		"CVR-22: неназванный вид разрешается в KEYPAIR до отказа — исходы равны")
}

// TestIssue_WithTheTokenEndpoint_KeypairIsIssued — CVR-23, законный близнец:
// та же выдача при объявленном эндпоинте проходит (поведение без изменений).
func TestIssue_WithTheTokenEndpoint_KeypairIsIssued(t *testing.T) {
	for name, kind := range map[string]domain.CredentialKind{
		"KEYPAIR":       domain.CredentialKindKeypair,
		"вид не назван": "",
	} {
		t.Run(name, func(t *testing.T) {
			repo := &stubUserClientRepo{}
			ops := &stubOpsRepo{}
			_, err := withTokenEndpoint(NewIssueUserTokenUseCase(repo, &stubTx{}, ops).WithIssuanceClock(momentclock.Func(time.Now))).
				Execute(context.Background(), issueByOwner(kind, 0))
			require.NoError(t, err)
			waitForOp(t, ops)
			require.Nil(t, ops.lastErr, "выдача при объявленном эндпоинте обязана состояться")
			require.Equal(t, domain.CredentialKindKeypair, repo.inserted.CredentialKind)
		})
	}
}

// TestIssue_WithoutTheTokenEndpoint_SecretIsIssued — CVR-24: SECRET обмена не
// требует и выдаётся без эндпоинта.
func TestIssue_WithoutTheTokenEndpoint_SecretIsIssued(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	op, err := NewIssueUserTokenUseCase(repo, &stubTx{}, ops).WithIssuanceClock(momentclock.Func(time.Now)).
		Execute(context.Background(), issueByOwner(domain.CredentialKindSecret, 3600))
	require.NoError(t, err, "секрет не обменивается и эндпоинта не требует")
	require.NotNil(t, op)
	require.Nil(t, op.Error)
	require.Equal(t, domain.CredentialKindSecret, repo.inserted.CredentialKind)
	require.NotEmpty(t, repo.inserted.ID, "строка секрета обязана быть записана")
}

// TestIssue_WithoutTheTokenEndpoint_MalformedRequestIsRefusedFirst — CVR-25:
// разбор запроса идёт раньше вопроса о посадке — `ttl_seconds = -1` получает
// свой отказ с именем поля.
func TestIssue_WithoutTheTokenEndpoint_MalformedRequestIsRefusedFirst(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	_, err := NewIssueUserTokenUseCase(repo, &stubTx{}, ops).WithIssuanceClock(momentclock.Func(time.Now)).
		Execute(context.Background(), issueByOwner(domain.CredentialKindKeypair, -1))
	require.Equal(t, codes.InvalidArgument, grpcstatus.Code(err), "отказ: %v", err)
	require.Contains(t, grpcstatus.Convert(err).Message(), "ttl_seconds")
	require.NotContains(t, grpcstatus.Convert(err).Message(), clientTokenKnob)
}
