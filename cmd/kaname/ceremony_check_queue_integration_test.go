// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_check_queue_integration_test.go — одновременные обмены
// конфиденциального клиента на ОДНОМ процессоре укладываются в срок операции
// (kaname#882).
//
// Каждый обмен конфиденциального клиента доказывает секрет вычислением
// argon2id; одновременные вычисления делят процессор и кончаются вместе.
// Срок операции, не учитывавший очередь проверок, кончался у всех разом, и
// обмены отвечали 503 `temporarily_unavailable` — отказ по сроку, а не по
// ёмкости и не о погашении (kaname#818: 0 из 16).
package main

import (
	"net/http"
	"net/url"
	"runtime"
	"testing"
	"time"
)

// TestKN882_ConfidentialExchangesOfTheWholeShareOnOneProcessorMeetTheDeadline —
// столько одновременных обменов РАЗНЫМИ кодами, сколько мест у сверки
// церемонии (половина ёмкости проверяющего мира), на одном процессоре: все
// проходят. Разные коды — чтобы исход каждого был один (200): предмет — срок,
// а не погашение.
//
// Процессор сужается ДО сборки мира: срок операции выводится из стоимости
// проверки, измеренной при сборке, и замер обязан видеть те же процессоры, что
// и обмены.
func TestKN882_ConfidentialExchangesOfTheWholeShareOnOneProcessorMeetTheDeadline(t *testing.T) {
	prev := runtime.GOMAXPROCS(1)
	t.Cleanup(func() { runtime.GOMAXPROCS(prev) })

	w := newCeremonyWorld(t, "KN-882", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	n := ceremonyWorldCheckerCapacity / 2
	forms := make([]url.Values, n)
	for i := range forms {
		forms[i] = exchangeForm(w.issueCode(w.ic1, lineA1R))
	}
	start := time.Now()
	recs := w.raceExchange(w.ic1, forms)
	elapsed := time.Since(start)
	passed := 0
	for i, rec := range recs {
		if rec.Code == http.StatusOK {
			passed++
			continue
		}
		t.Errorf("%s: обмен %d из %d на одном процессоре ответил %d; тело %q", w.id, i, n, rec.Code, rec.Body.String())
	}
	t.Logf("%s: одновременных обменов конфиденциального клиента %d на одном процессоре: прошло %d за %v",
		w.id, n, passed, elapsed)
}
