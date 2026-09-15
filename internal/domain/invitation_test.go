// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// invitation_test.go — срок приглашения, его выкупаемость и частота писем на
// адрес (приёмка ID-MAIL-1: Р14, Р21а, Р22, Р24; §10 пп. 13, 16, 17, 22).
//
// Утверждается ОБЕ стороны каждой оси: законное значение принимается, и рядом
// отвергается то, что делало бы величину пустой. Односторонняя проба зеленела
// бы на валидаторе, отвергающем всё.

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestInvitationTerm_PositiveAndBoundedOnly(t *testing.T) {
	for _, ok := range []time.Duration{time.Second, 7 * 24 * time.Hour, MaxInvitationTerm} {
		require.NoError(t, InvitationTerm(ok).Validate(), "законный срок %s обязан приниматься", ok)
	}
	for _, bad := range []time.Duration{0, -time.Second, MaxInvitationTerm + time.Second} {
		err := InvitationTerm(bad).Validate()
		require.Error(t, err,
			"срок %s обязан отвергаться: ноль и отрицательное означали бы «приглашение не выкупается никогда» "+
				"либо «срока нет», а сверх потолка срок перестаёт быть сроком", bad)
		require.Contains(t, err.Error(), "invitation term",
			"отказ обязан называть величину, а не только факт отказа")
	}
}

func TestInviteMailAddressRate_BothValuesMustBePositive(t *testing.T) {
	require.NoError(t, InviteMailAddressRate{Letters: 1, Window: time.Second}.Validate(),
		"наименьшая законная пара обязана приниматься")
	for _, bad := range []InviteMailAddressRate{
		{Letters: 0, Window: time.Hour},
		{Letters: -1, Window: time.Hour},
		{Letters: 3, Window: 0},
		{Letters: 3, Window: -time.Second},
		{},
	} {
		err := bad.Validate()
		require.Error(t, err,
			"пара %+v обязана отвергаться: у ограничения частоты нет значения «без ограничения» (Р14)", bad)
		require.True(t, strings.Contains(err.Error(), "letters") || strings.Contains(err.Error(), "window"),
			"отказ обязан называть величину, которой не хватает: %v", err)
	}
}

// Классификация выкупаемости — ОДНА функция на читателя стоянки и на CAS
// активации: разойдясь, они разошлись бы там, где расхождение опасно, — пречек
// сказал бы «можно», а выкуп отказал бы молча (или наоборот).
func TestClassifyInvitation_EveryStandingHasItsOwnReason(t *testing.T) {
	cases := []struct {
		name  string
		state InvitationState
		want  InvitationStanding
	}{
		{"строки нет", InvitationState{}, InvitationAbsent},
		{"строка уже активна",
			InvitationState{Exists: true, Status: InviteStatusActive}, InvitationNotPending},
		{"строка заблокирована",
			InvitationState{Exists: true, Status: InviteStatusBlocked}, InvitationNotPending},
		{"строка ожидания без срока — не приглашение",
			InvitationState{Exists: true, Status: InviteStatusPending, HasPendingMembership: true},
			InvitationNotIssued},
		{"все членства в ожидании сняты",
			InvitationState{Exists: true, Status: InviteStatusPending, HasTerm: true},
			InvitationWithdrawn},
		{"срок вышел",
			InvitationState{Exists: true, Status: InviteStatusPending, HasTerm: true, Expired: true,
				HasPendingMembership: true},
			InvitationExpired},
		{"выкупаема",
			InvitationState{Exists: true, Status: InviteStatusPending, HasTerm: true,
				HasPendingMembership: true},
			InvitationRedeemable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, ClassifyInvitation(tc.state))
		})
	}
}

// Снятое приглашение сильнее истёкшего: человеку, у которого приглашения нет
// вовсе, сказать «срок вышел, попросите продлить» значит послать его просить
// то, чего аккаунт больше не предлагает.
func TestClassifyInvitation_WithdrawnOutranksExpired(t *testing.T) {
	require.Equal(t, InvitationWithdrawn, ClassifyInvitation(InvitationState{
		Exists: true, Status: InviteStatusPending, HasTerm: true, Expired: true,
	}))
}

func TestInviteActivationOutcomes_ClosedSetHasNoDuplicates(t *testing.T) {
	seen := map[InviteActivationOutcome]bool{}
	for _, o := range InviteActivationOutcomes() {
		require.False(t, seen[o], "исход %q объявлен дважды", o)
		seen[o] = true
	}
	for _, want := range []InviteActivationOutcome{
		InviteActivationActivated, InviteActivationAlreadyActive, InviteActivationExpired,
		InviteActivationWithdrawn, InviteActivationNotIssued, InviteActivationFailed,
	} {
		require.True(t, seen[want], "исход %q обязан входить в закрытый набор клеток", want)
	}
}

// Каждая стоянка отображается в РОВНО одну клетку счётчика, и выкупаемая — в
// «активировано». Стоянка без клетки была бы исходом, которого не видно.
func TestInvitationStanding_EveryStandingMapsToACell(t *testing.T) {
	cells := map[InviteActivationOutcome]bool{}
	for _, o := range InviteActivationOutcomes() {
		cells[o] = true
	}
	for _, st := range InvitationStandings() {
		o := st.ActivationOutcome()
		require.True(t, cells[o], "стоянка %q отображена в клетку %q, которой нет в наборе", st, o)
	}
	require.Equal(t, InviteActivationActivated, InvitationRedeemable.ActivationOutcome())
}
