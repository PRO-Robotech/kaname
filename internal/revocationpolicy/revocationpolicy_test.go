// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// revocationpolicy_test.go — вердикт отсечки отзыва-всех как функция от
// (принципал, момент полномочия, ответ хранилища) и ни от чего иного.
package revocationpolicy_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/service"
)

var cutoff = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// cutoffs — хранилище отсечек. Считает обращения: проба, утверждающая «для
// машины не читается», обязана это видеть, а не выводить из исхода.
type cutoffs struct {
	at    map[string]time.Time
	err   error
	asked []string
}

func (c *cutoffs) UserRevokedBefore(_ context.Context, userID string) (time.Time, bool, error) {
	c.asked = append(c.asked, userID)
	if c.err != nil {
		return time.Time{}, false, c.err
	}
	t, ok := c.at[userID]
	return t, ok, nil
}

func person(id string, issued *time.Time) service.ResolvedPrincipal {
	return service.ResolvedPrincipal{Kind: service.PrincipalUser, UserID: id, StandingCredentialIssuedAt: issued}
}

func at(t time.Time) *time.Time { return &t }

// TestForbids_BoundaryIsInclusiveAndTheUnknownInstantIsARefusal — граница и
// нулевой момент.
func TestForbids_BoundaryIsInclusiveAndTheUnknownInstantIsARefusal(t *testing.T) {
	for _, c := range []struct {
		name   string
		anchor time.Time
		want   bool
	}{
		{"полномочие раньше отсечки", cutoff.Add(-time.Second), true},
		// Равенство — запрет: «не позже отсечки» и есть то, что она называет.
		{"полномочие ровно в момент отсечки", cutoff, true},
		{"полномочие на шаг позже отсечки", cutoff.Add(time.Microsecond), false},
		{"полномочие намного позже отсечки", cutoff.Add(24 * time.Hour), false},
		// Нулевой момент нельзя показать возникшим после отсечки.
		{"момент полномочия не назван", time.Time{}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, revocationpolicy.Forbids(cutoff, c.anchor))
		})
	}
}

// TestAnchor_StandingCredentialOutranksTheSession — у долговременного
// удостоверения якорь — его выдача, даже когда обмен назвал момент сессии.
func TestAnchor_StandingCredentialOutranksTheSession(t *testing.T) {
	issued := cutoff.Add(-time.Hour)
	session := cutoff.Add(time.Hour)

	require.True(t, revocationpolicy.Anchor(person("usr_a", &issued), session).Equal(issued),
		"долговременное удостоверение судится моментом своей выдачи")
	require.True(t, revocationpolicy.Anchor(person("usr_a", nil), session).Equal(session),
		"интерактивный обмен судится моментом своей аутентификации")
	require.True(t, revocationpolicy.Anchor(person("usr_a", nil), time.Time{}).IsZero(),
		"обмен, не назвавший ни того, ни другого, якоря не имеет")
}

// TestAtIssuance_Verdicts — полный перечень исходов по закрытому словарю.
func TestAtIssuance_Verdicts(t *testing.T) {
	ctx := context.Background()
	unavailable := errors.New("backend unavailable")

	for _, c := range []struct {
		name      string
		store     *cutoffs
		principal service.ResolvedPrincipal
		session   time.Time
		want      revocationpolicy.Verdict
		wantErr   error
		wantAsked []string
	}{
		{
			name:      "отсечки нет",
			store:     &cutoffs{},
			principal: person("usr_a", at(cutoff.Add(-time.Hour))),
			want:      revocationpolicy.Allowed,
			wantAsked: []string{"usr_a"},
		},
		{
			name:      "ключ выдан до отсечки",
			store:     &cutoffs{at: map[string]time.Time{"usr_a": cutoff}},
			principal: person("usr_a", at(cutoff.Add(-time.Hour))),
			want:      revocationpolicy.Revoked,
			wantAsked: []string{"usr_a"},
		},
		{
			name:      "ключ выдан ровно в момент отсечки",
			store:     &cutoffs{at: map[string]time.Time{"usr_a": cutoff}},
			principal: person("usr_a", at(cutoff)),
			want:      revocationpolicy.Revoked,
			wantAsked: []string{"usr_a"},
		},
		{
			// Законный близнец: полномочие, установленное после отсечки.
			name:      "ключ выдан после отсечки",
			store:     &cutoffs{at: map[string]time.Time{"usr_a": cutoff}},
			principal: person("usr_a", at(cutoff.Add(time.Hour))),
			want:      revocationpolicy.Allowed,
			wantAsked: []string{"usr_a"},
		},
		{
			// Ключ, выданный до отсечки, не оживляется свежей сессией обмена.
			name:      "ключ до отсечки при сессии после неё",
			store:     &cutoffs{at: map[string]time.Time{"usr_a": cutoff}},
			principal: person("usr_a", at(cutoff.Add(-time.Hour))),
			session:   cutoff.Add(time.Hour),
			want:      revocationpolicy.Revoked,
			wantAsked: []string{"usr_a"},
		},
		{
			name:      "сессия после отсечки",
			store:     &cutoffs{at: map[string]time.Time{"usr_a": cutoff}},
			principal: person("usr_a", nil),
			session:   cutoff.Add(time.Hour),
			want:      revocationpolicy.Allowed,
			wantAsked: []string{"usr_a"},
		},
		{
			name:      "отсечка есть, момента полномочия нет",
			store:     &cutoffs{at: map[string]time.Time{"usr_a": cutoff}},
			principal: person("usr_a", nil),
			want:      revocationpolicy.Revoked,
			wantAsked: []string{"usr_a"},
		},
		{
			name:      "хранилище не ответило",
			store:     &cutoffs{err: unavailable},
			principal: person("usr_a", at(cutoff.Add(time.Hour))),
			want:      revocationpolicy.Undecidable,
			wantErr:   unavailable,
			wantAsked: []string{"usr_a"},
		},
		{
			name:      "человек без идентификатора",
			store:     &cutoffs{at: map[string]time.Time{"": cutoff}},
			principal: person("", at(cutoff.Add(time.Hour))),
			want:      revocationpolicy.Undecidable,
			wantErr:   revocationpolicy.ErrPrincipalWithoutID,
		},
		{
			// Отсечка человека о ключе машины не говорит ничего — и не
			// читается вовсе.
			name:      "служебная учётка при отсечке человека",
			store:     &cutoffs{at: map[string]time.Time{"usr_a": cutoff.Add(time.Hour)}},
			principal: service.ResolvedPrincipal{Kind: service.PrincipalServiceAccount},
			want:      revocationpolicy.Allowed,
		},
		{
			name:      "принципал не разрешён",
			store:     &cutoffs{at: map[string]time.Time{"usr_a": cutoff.Add(time.Hour)}},
			principal: service.ResolvedPrincipal{},
			want:      revocationpolicy.Allowed,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := revocationpolicy.AtIssuance(ctx, c.store, c.principal, c.session)
			require.Equal(t, c.want, got)
			if c.wantErr != nil {
				require.ErrorIs(t, err, c.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, c.wantAsked, c.store.asked, "к хранилищу обратились не с тем идентификатором либо не тогда")
		})
	}
}

// TestAtIssuance_NoLookupIsUndecidableNotAllowed — неподанный читатель не
// означает «отсечки нет».
func TestAtIssuance_NoLookupIsUndecidableNotAllowed(t *testing.T) {
	got, err := revocationpolicy.AtIssuance(context.Background(), nil, person("usr_a", at(cutoff)), time.Time{})
	require.Equal(t, revocationpolicy.Undecidable, got)
	require.ErrorIs(t, err, revocationpolicy.ErrNoLookup)

	// Для машины читатель не нужен вовсе, и его отсутствие ей не мешает.
	got, err = revocationpolicy.AtIssuance(context.Background(), nil,
		service.ResolvedPrincipal{Kind: service.PrincipalServiceAccount}, time.Time{})
	require.Equal(t, revocationpolicy.Allowed, got)
	require.NoError(t, err)
}

// TestVerdictZeroValueIsNoneOfTheThree — нулевое значение типа не совпадает ни
// с одним исходом: вызывающий, получивший его, не может принять его за «можно».
func TestVerdictZeroValueIsNoneOfTheThree(t *testing.T) {
	var zero revocationpolicy.Verdict
	for _, v := range []revocationpolicy.Verdict{
		revocationpolicy.Allowed, revocationpolicy.Revoked, revocationpolicy.Undecidable,
	} {
		require.NotEqual(t, zero, v)
	}
}
