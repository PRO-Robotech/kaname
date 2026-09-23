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

// TestAtIssuance_PrincipalKindIsAClosedDictionary — вид принципала судится
// закрытым словарём: машина и неразрешённый субъект — не человек, отсечка
// человека о них не говорит ничего и не читается; человек сверяется; вид вне
// словаря — «решить нечем», а не «можно».
//
// Вид вне словаря — не выдумка пробы: принципала строит вызывающий, и новое
// значение, заведённое рядом с тремя, без этой развилки получало бы выдачу
// молча — ровно тем путём, каким её получает машина.
func TestAtIssuance_PrincipalKindIsAClosedDictionary(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name      string
		kind      service.PrincipalKind
		want      revocationpolicy.Verdict
		wantAsked []string
	}{
		{"машина", service.PrincipalServiceAccount, revocationpolicy.Allowed, nil},
		{"субъект не разрешён", service.PrincipalUnresolved, revocationpolicy.Allowed, nil},
		// Человек с отсечкой позже выдачи — сверка действительно идёт.
		{"человек", service.PrincipalUser, revocationpolicy.Revoked, []string{"usr_a"}},
		{"вид вне словаря", service.PrincipalKind("robot"), revocationpolicy.Undecidable, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			store := &cutoffs{at: map[string]time.Time{"usr_a": cutoff}}
			p := person("usr_a", at(cutoff.Add(-time.Hour)))
			p.Kind = c.kind
			got, err := revocationpolicy.AtIssuance(ctx, store, p, time.Time{})
			require.Equal(t, c.want, got)
			if c.want == revocationpolicy.Undecidable {
				require.ErrorIs(t, err, revocationpolicy.ErrUnknownPrincipalKind,
					"«решить нечем» обязано назвать причину для журнала")
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, c.wantAsked, store.asked, "хранилище спрошено не тогда")
		})
	}
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

// deadlineCutoffs — читатель, запоминающий срок контекста вызова.
type deadlineCutoffs struct {
	called   bool
	deadline time.Time
	had      bool
}

func (d *deadlineCutoffs) UserRevokedBefore(ctx context.Context, _ string) (time.Time, bool, error) {
	d.called = true
	d.deadline, d.had = ctx.Deadline()
	return time.Time{}, false, nil
}

// TestWithDeadline_EachReadCarriesItsOwnLimitAndAnAbsentReaderStaysAbsent —
// обёртка ставит свой срок на вызов с контекстом без срока, а неподанный
// читатель не превращается в поданный.
func TestWithDeadline_EachReadCarriesItsOwnLimitAndAnAbsentReaderStaysAbsent(t *testing.T) {
	const limit = 2 * time.Second
	inner := &deadlineCutoffs{}
	_, _, err := revocationpolicy.WithDeadline(inner, limit).UserRevokedBefore(context.Background(), "usr_x")
	require.NoError(t, err)
	require.True(t, inner.called, "чтение обязано дойти до читателя")
	require.True(t, inner.had, "чтение обязано нести свой срок и при контексте без срока")
	require.LessOrEqual(t, time.Until(inner.deadline), limit)
	require.Positive(t, time.Until(inner.deadline))

	require.Nil(t, revocationpolicy.WithDeadline(nil, limit),
		"обёртка над неподанным читателем обязана остаться неподанной: иначе «не провязан» неотличим от «провязан»")

	// Неподанный читатель через обёртку — по-прежнему Undecidable, а не паника
	// и не выдача.
	v, err := revocationpolicy.AtIssuance(context.Background(), revocationpolicy.WithDeadline(nil, limit),
		person("usr_x", nil), cutoff)
	require.Equal(t, revocationpolicy.Undecidable, v)
	require.ErrorIs(t, err, revocationpolicy.ErrNoLookup)
}
