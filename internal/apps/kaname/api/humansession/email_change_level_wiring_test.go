// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// email_change_level_wiring_test.go — провязка условия уровня глаголов смены
// (kaname#770, приёмка email-change Р2): без читателя заведённого глаголы не
// собираются, а сессия, уровень которой не ниже любого возможного порога,
// заведённого не читает.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
)

func TestEmailChangeVerbsRefuseToBuildWithoutTheEnrolledReader(t *testing.T) {
	s, _ := newECStore(t)
	d := ecDeps(s)
	require.NotNil(t, d.Methods, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): близнец собран с читателем")
	_, err := humansession.NewRequestEmailChangeUseCase(d)
	require.NoError(t, err, "близнец: с читателем запрос собирается")

	d.Methods = nil
	_, err = humansession.NewRequestEmailChangeUseCase(d)
	require.ErrorContains(t, err, "enrolled login methods reader required", "запрос без читателя заведённого не собирается")
	_, err = humansession.NewConfirmEmailChangeUseCase(d)
	require.ErrorContains(t, err, "enrolled login methods reader required", "предъявление без читателя заведённого не собирается")
}

func TestEmailChangeLevelTwoSessionDoesNotReadTheEnrolled(t *testing.T) {
	st, d, b := ec2Cell(t, "2", &ec2Methods{key: true, totp: true})
	uc, err := humansession.NewRequestEmailChangeUseCase(d)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): глагол собран")
	_, err = uc.Execute(context.Background(), humansession.RequestEmailChangeInput{Bearer: b, NewEmail: "new@example.test"})
	require.NoError(t, err, "сессия «2» — исход EC-01")
	require.Zero(t, st.methods.reads, "сессия «2» заведённого не читает: исход от прочитанного не зависит")

	st1, d1, b1 := ec2Cell(t, "1", &ec2Methods{})
	uc1, err := humansession.NewRequestEmailChangeUseCase(d1)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): глагол собран")
	_, err = uc1.Execute(context.Background(), humansession.RequestEmailChangeInput{Bearer: b1, NewEmail: "new@example.test"})
	require.NoError(t, err, "близнец: сессия «1» без способа «2» — исход EC-01")
	require.NotZero(t, st1.methods.reads, "близнец: сессия «1» заведённое читает")
}
