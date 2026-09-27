// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_admission_test.go — EV-69 (а)/(б) приёмки
// `access-beyond-login-needs-a-verified-address.md` (kaname#456, Р5а): наш
// токен человека с неподтверждённым адресом на публичном слушателе
// недействителен — единственный отказ читателя, побайтно тот же, что у
// истёкшего токена; близнец — отметка на месте, принципал назван. Половина
// (в) — принципал, названный из кеша положительного вердикта, упирается в
// рубеж — держат пробы рубежа.
package presentedcred_test

import (
	"testing"
	"time"
)

func TestEV69_OurTokenOfTheUnverifiedIsNotAcceptedOnThePublicListener(t *testing.T) {
	s := newStand(t, withCacheTTL(30*time.Second))
	raw := s.good(t)
	p, present, err := s.present(t, raw)
	if err != nil || !present || p.ID != testPrincipalID {
		t.Fatalf("EV-69 (б): отметка на месте — принципал назван (present=%v, id=%q, err=%v)", present, p.ID, err)
	}

	s.revs.unmark(testSubject)
	s.clock.advance(31 * time.Second) // окно кеша положительного вердикта прошло
	_, _, err = s.present(t, raw)
	if err == nil {
		t.Fatal("EV-69 (а): отметка снята — токен принят; контроль стоит только на выдаче")
	}
	assertSingleRefusal(t, err)

	expired := goodMint(s.key, s.now)
	expired.expiry = s.now.Add(-time.Second)
	_, _, expErr := newStand(t).present(t, expired.sign(t))
	if expErr == nil || expErr.Error() != err.Error() {
		t.Fatalf("EV-69 (а): отказ побайтно тот же, что у истёкшего токена: %v против %v", err, expErr)
	}
}
