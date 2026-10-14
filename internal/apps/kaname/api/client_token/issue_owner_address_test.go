// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issue_owner_address_test.go — EV-65 приёмки
// `docs/engineering/acceptance/access-beyond-login-needs-a-verified-address.md`,
// половина токен-эндпоинта (kaname#472).
//
// Пробу EV-65 прежде держал `internal/handler/iamhooks`; её половину хуков сняли
// вместе с хуками (#363), а половина токен-эндпоинта ушла вместе с ней, хотя её
// предмет — отказ нашей полосы выдачи ключу человека без отметки — жив. Опыт до
// этой пробы: ветка `Unverified` в `weighCutoff`, подменённая выдачей, не
// роняла ни одной пробы модуля (`go test ./...` с контейнерами).
//
// Близнецы различаются ОДНИМ фактом — отметкой адреса владельца ключа.
package client_token_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/client_token"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// markedCutoffs — отсечек нет, а строки людей есть: отметка адреса каждого
// названного человека задана картой. Идентификатор вне карты — не человек
// (служебная учётка), как у настоящего читателя.
type markedCutoffs struct {
	stubCutoffs
	marks map[string]bool
	asked [][]string
}

func (m *markedCutoffs) PersonMarks(_ context.Context, ids []string) (map[string]bool, error) {
	m.asked = append(m.asked, append([]string(nil), ids...))
	out := map[string]bool{}
	for _, id := range ids {
		if v, ok := m.marks[id]; ok {
			out[id] = v
		}
	}
	return out, nil
}

func newUseCaseWithMarks(t *testing.T, marks map[string]bool) (*client_token.UseCase, *countingSigner, *markedCutoffs) {
	t.Helper()
	cfg := client_token.Config{
		AllowedAudiences: []string{audResource, audRegistry},
		DefaultAudience:  audResource,
		TokenTTL:         15 * time.Minute,
		Clock:            func() time.Time { return now },
	}
	signer := &countingSigner{inner: newSigner(t)}
	lookup := &markedCutoffs{stubCutoffs: stubCutoffs{at: map[string]time.Time{}}, marks: marks}
	uc, err := client_token.New(cfg, signer, &stubClaims{}, lookup)
	require.NoError(t, err)
	return uc, signer, lookup
}

// TestEV65_TokenEndpointRefusesTheKeyOfAPersonWithoutTheMark — EV-65 (а):
// ключ человека без отметки токена не получает, исход — своя клетка
// `owner-unverified`, и отказ наступает до подписи.
func TestEV65_TokenEndpointRefusesTheKeyOfAPersonWithoutTheMark(t *testing.T) {
	owner := ownerFor(domain.AssertionClientUser)
	uc, signer, lookup := newUseCaseWithMarks(t, map[string]bool{owner: false})

	out, outcome, err := uc.Issue(context.Background(), client_token.Input{Client: client()})
	require.Error(t, err, "EV-65 (а): токен-эндпоинт токена не выдаёт")
	require.Equal(t, clientassertion.OutcomeOwnerUnverified, outcome, "EV-65 (а): своя клетка словаря исходов полосы")
	require.Empty(t, out.AccessToken, "в отказе не бывает токена")
	require.Zero(t, signer.calls, "подписант позван при отказе по отметке: подписанный и выброшенный токен — уже выпущенный")
	require.Equal(t, [][]string{{owner}}, lookup.asked, "отметка спрошена по владельцу ключа")
}

// TestEV65_TokenEndpointServesTheKeyOfAPersonWithTheMark — EV-65 (б), законный
// близнец: тот же ключ, владелец с отметкой — токен выдан. Без него проба выше
// закрепляла бы выдачу, отказывающую всем.
func TestEV65_TokenEndpointServesTheKeyOfAPersonWithTheMark(t *testing.T) {
	owner := ownerFor(domain.AssertionClientUser)
	uc, signer, _ := newUseCaseWithMarks(t, map[string]bool{owner: true})

	out, outcome, err := uc.Issue(context.Background(), client_token.Input{Client: client()})
	require.NoError(t, err, "EV-65 (б): токен-эндпоинт выдаёт")
	require.Equal(t, clientassertion.OutcomeAccepted, outcome)
	require.NotEmpty(t, out.AccessToken)
	require.Equal(t, 1, signer.calls)
}

// TestEV65_ServiceAccountKeyIsUntouchedByAPersonsMark — EV-65: ключ служебной
// учётки отметкой человека не затронут, даже если тот же идентификатор
// владельца назван в карте отметок без отметки.
func TestEV65_ServiceAccountKeyIsUntouchedByAPersonsMark(t *testing.T) {
	sa := ownerFor(domain.AssertionClientServiceAccount)
	uc, _, lookup := newUseCaseWithMarks(t, map[string]bool{sa: false})

	out, outcome, err := uc.Issue(context.Background(),
		client_token.Input{Client: client(ofKind(domain.AssertionClientServiceAccount))})
	require.NoError(t, err, "EV-65: ключ служебной учётки отметкой человека не затронут")
	require.Equal(t, clientassertion.OutcomeAccepted, outcome)
	require.NotEmpty(t, out.AccessToken)
	require.Empty(t, lookup.asked, "для служебной учётки отметка человека не читается")
}
