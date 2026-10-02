// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issue_revoke_all_test.go — отсечка отзыва-всех владельца на нашей полосе
// выдачи (задача kaname#379).
//
// Планка — наблюдаемое: ключ пользователя, выданный не позже отсечки его
// владельца, не получает токена; ключ, выданный после неё, получает; ключ
// служебной учётки отсечкой человека не затронут; неотвеченный вопрос об
// отсечке — отказ, а не выдача. «Порт спросили» планкой не является: выдача,
// прочитавшая отсечку и выпустившая токен, прошла бы её.
package client_token_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/client_token"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// TestIssue_KeyIssuedNoLaterThanTheOwnersCutoffGetsNoToken — ключ пользователя
// до отсечки и ровно в её момент токена не получает.
func TestIssue_KeyIssuedNoLaterThanTheOwnersCutoffGetsNoToken(t *testing.T) {
	owner := ownerFor(domain.AssertionClientUser)
	issued := now.Add(-2 * time.Hour)

	for name, cutoff := range map[string]time.Time{
		"отсечка позже выдачи ключа":      issued.Add(time.Hour),
		"отсечка ровно в момент выдачи":   issued,
		"отсечка на шаг позже выдачи":     issued.Add(time.Microsecond),
		"отсечка в момент текущей выдачи": now,
	} {
		t.Run(name, func(t *testing.T) {
			uc, claims, cutoffs := newUseCaseWithCutoffs(t)
			claims.keyIssuedAt = issued
			cutoffs.at[owner] = cutoff

			out, outcome, err := uc.Issue(context.Background(), client_token.Input{Client: client()})
			require.Error(t, err, "ключ, выданный не позже отсечки владельца, токена не получает")
			require.Equal(t, clientassertion.OutcomeOwnerRevoked, outcome)
			require.Empty(t, out.AccessToken, "в отказе не бывает токена")
			require.Equal(t, []string{owner}, cutoffs.asked,
				"отсечка читается по идентификатору человека, разрешённому объявлением состава")
		})
	}
}

// TestIssue_KeyIssuedAfterTheOwnersCutoffIsServed — законный близнец:
// полномочие, установленное после отсечки, действует. Отсечка прекращает
// прежнее, а не запирает учётку.
func TestIssue_KeyIssuedAfterTheOwnersCutoffIsServed(t *testing.T) {
	owner := ownerFor(domain.AssertionClientUser)
	cutoff := now.Add(-2 * time.Hour)

	uc, claims, cutoffs := newUseCaseWithCutoffs(t)
	claims.keyIssuedAt = cutoff.Add(time.Microsecond)
	cutoffs.at[owner] = cutoff

	out, outcome, err := uc.Issue(context.Background(), client_token.Input{Client: client()})
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, outcome)
	require.NotEmpty(t, out.AccessToken)
	require.Equal(t, []string{owner}, cutoffs.asked, "отсечка прочитана, а не обойдена")
}

// TestIssue_NoCutoffIsServed — контроль: без отсечки тот же ключ токен
// получает, то есть пробы выше закрепляют отсечку, а не выдачу, отказывающую
// всем.
func TestIssue_NoCutoffIsServed(t *testing.T) {
	uc, _, cutoffs := newUseCaseWithCutoffs(t)
	_, outcome, err := uc.Issue(context.Background(), client_token.Input{Client: client()})
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, outcome)
	require.Len(t, cutoffs.asked, 1, "отсечку спросили и не нашли — это «отсечки нет»")
}

// TestIssue_ServiceAccountKeyIsUnaffectedByAPersonsCutoff — отсечка человека о
// ключе машины ничего не говорит и для него не читается.
func TestIssue_ServiceAccountKeyIsUnaffectedByAPersonsCutoff(t *testing.T) {
	uc, _, cutoffs := newUseCaseWithCutoffs(t)
	// Отсечки стоят у всех, кого фикстура может назвать, и в будущем: ключу
	// машины они не мешают не потому, что ни одна не совпала.
	cutoffs.at[ownerFor(domain.AssertionClientUser)] = now.Add(time.Hour)
	cutoffs.at[ownerFor(domain.AssertionClientServiceAccount)] = now.Add(time.Hour)

	_, outcome, err := uc.Issue(context.Background(), client_token.Input{
		Client: client(ofKind(domain.AssertionClientServiceAccount)),
	})
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, outcome)
	require.Empty(t, cutoffs.asked, "для ключа служебной учётки отсечка человека не читается")
}

// TestIssue_UnansweredCutoffQuestionIsARefusal — хранилище отсечек не
// ответило: отказ своим исходом, а не выдача и не чужой исход.
func TestIssue_UnansweredCutoffQuestionIsARefusal(t *testing.T) {
	uc, _, cutoffs := newUseCaseWithCutoffs(t)
	cutoffs.err = errors.New("cutoff store: backend unavailable")

	out, outcome, err := uc.Issue(context.Background(), client_token.Input{Client: client()})
	require.Error(t, err)
	require.Equal(t, clientassertion.OutcomeRevocationCheckFailed, outcome,
		"«спросить не удалось» — свой исход: слитый с «выпуск не состоялся» он прятал бы отказ хранилища")
	require.Empty(t, out.AccessToken)
}

// TestIssue_PersonWithoutAnchorUnderACutoffIsRefused — принципал-человек, не
// назвавший момента своего полномочия, при живой отсечке токена не получает:
// показать, что полномочие возникло после неё, нечем.
func TestIssue_PersonWithoutAnchorUnderACutoffIsRefused(t *testing.T) {
	uc, claims, cutoffs := newUseCaseWithCutoffs(t)
	claims.dropAnchor = true
	cutoffs.at[ownerFor(domain.AssertionClientUser)] = now.Add(-365 * 24 * time.Hour)

	_, outcome, err := uc.Issue(context.Background(), client_token.Input{Client: client()})
	require.Error(t, err)
	require.Equal(t, clientassertion.OutcomeOwnerRevoked, outcome)
}

// TestIssue_CutoffIsWeighedBeforeAnythingIsSigned — отказ по отсечке наступает
// ДО подписи: подписанный и затем выброшенный токен — уже выпущенный токен.
func TestIssue_CutoffIsWeighedBeforeAnythingIsSigned(t *testing.T) {
	cfg := client_token.Config{
		AllowedAudiences: []string{audResource},
		DefaultAudience:  audResource,
		TokenTTL:         15 * time.Minute,
		Clock:            func() time.Time { return now },
	}
	signer := &countingSigner{inner: newSigner(t)}
	cutoffs := &stubCutoffs{at: map[string]time.Time{ownerFor(domain.AssertionClientUser): now}}
	uc, err := client_token.New(cfg, signer, &stubClaims{}, cutoffs)
	require.NoError(t, err)

	_, outcome, err := uc.Issue(context.Background(), client_token.Input{Client: client()})
	require.Error(t, err)
	require.Equal(t, clientassertion.OutcomeOwnerRevoked, outcome)
	require.Zero(t, signer.calls, "подписант позван при отказе по отсечке")

	// Контроль счётчика: при выдаче подписант зовётся — иначе ноль выше ничего
	// не утверждает.
	delete(cutoffs.at, ownerFor(domain.AssertionClientUser))
	_, _, err = uc.Issue(context.Background(), client_token.Input{Client: client()})
	require.NoError(t, err)
	require.Equal(t, 1, signer.calls)
}

// countingSigner — подписант, считающий обращения.
type countingSigner struct {
	inner client_token.Signer
	calls int
}

func (c *countingSigner) Sign(ctx context.Context, req tokensigner.Request) (tokensigner.Token, error) {
	c.calls++
	return c.inner.Sign(ctx, req)
}

func (c *countingSigner) Issuer() string { return c.inner.Issuer() }
