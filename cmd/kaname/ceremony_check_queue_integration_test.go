// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_check_queue_integration_test.go — одновременные обмены
// конфиденциального клиента на ОДНОМ процессоре укладываются в срок операции
// (kaname#882).
//
// Каждый обмен конфиденциального клиента доказывает секрет вычислением
// argon2id. До правки одновременные вычисления делили процессор и кончались
// вместе, а срок операции не учитывал очередь проверок и кончался у всех
// разом: обмены отвечали 503 `temporarily_unavailable` — отказ по сроку, а не
// по ёмкости и не о погашении (0 из 16, `port_deadline` на выборке кода).
// После — вычисления ждут места процессора по очереди, а срок учитывает очередь.
//
// Проба — сквозная, о симптоме, и различает она ВЕРОЯТНОСТНО: срок без
// очереди (два предела вызова базы) она ловит лишь тогда, когда очередь сверок
// доли длиннее этих двух пределов, а это зависит от процессора узла и `-race`
// (на коммите пробы до правки — красная не в каждом прогоне, kaname#882).
// Детерминированно предмет держат три пробы: формулу срока —
// `TestCeremonyOperationDeadline_CoversAFullQueueOfChecks`, проводку
// стоимости проверки от полосы входа к сроку —
// `TestLoginLaneSecretCheckCost_IsTheCalibratedEnvelopeFloor` (мир берёт
// стоимость тем же `loginLane.secretCheckCost`, что корень), порядок прихода к
// месту вычисления, на котором держится предел очереди, —
// `passwordverify.TestProcessorGate_WaitersTakeTheSlotInArrivalOrder`.
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
// Процессор сужается ДО сборки мира: места вычисления проверяющего читают
// число процессоров при построении, а срок операции выводится из стоимости
// проверки, откалиброванной при сборке, — и то и другое обязано видеть те же
// процессоры, что и обмены.
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
