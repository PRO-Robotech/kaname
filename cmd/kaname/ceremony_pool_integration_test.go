// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_pool_integration_test.go — обмен кода и пул службы (задача
// PRO-Robotech/kaname#423, возвраты ревью сборки 425).
//
// Транзакция запроса обмена держит связь пула от погашения кода до
// урегулирования. Внутри этого окна ничто не вправе брать ВТОРУЮ связь того же
// пула: когда одновременных обменов столько же, сколько связей, каждый держатель
// ждал бы вторую, и не шёл бы никто до срока вызова порта.
//
// Клиент проб — ПУБЛИЧНЫЙ: у него нет сверки секрета перед погашением, и ничто
// не разносит обмены во времени. Ключ подписанта мир читает продуктовым
// читателем ключницы (`ceremonyKeys`), как подписант службы.
package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
)

// racePublic — одновременные обмены форм публичного клиента.
func (w *ceremonyWorld) racePublic(forms []url.Values) []*httptest.ResponseRecorder {
	w.t.Helper()
	out := make([]*httptest.ResponseRecorder, len(forms))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, f := range forms {
		wg.Add(1)
		go func(i int, f url.Values) {
			defer wg.Done()
			<-start
			out[i] = w.post(clienttokenhttp.TokenPath, f, nil)
		}(i, f)
	}
	close(start)
	wg.Wait()
	return out
}

// tally — исходы по коду ответа и первое тело отказа сервера.
func tally(recs []*httptest.ResponseRecorder) (map[int]int, string) {
	counts := map[int]int{}
	first5xx := ""
	for _, r := range recs {
		counts[r.Code]++
		if r.Code >= 500 && first5xx == "" {
			first5xx = r.Body.String()
		}
	}
	return counts, first5xx
}

// Обмены ОДНОГО кода публичного клиента, обменов вдвое больше, чем связей
// пула: ровно один выдаёт, прочие — повтор (invalid_grant), и ни одного отказа
// сервера. Близнец — тот же набег на пуле шире набега.
func TestLINEA1Pool_OneCodeRacedByAPublicClientOnANarrowPool(t *testing.T) {
	const racers = 8
	for _, cell := range []struct {
		name  string
		width int
	}{
		{"пул 4", 4},
		{"близнец: пул 16", 16},
	} {
		t.Run(cell.name, func(t *testing.T) {
			w := newCeremonyWorld(t, "POOL-RACE", "1", withPoolWidth(cell.width))
			w.requireGrant(grantAuthorizationCode)
			w.requireAuthorizeEndpoint()
			pub := w.seedPublicClient("ceremony-public", []string{lineA1R})
			ic := w.issueCode(pub, lineA1R)
			forms := make([]url.Values, racers)
			for i := range forms {
				forms[i] = exchangeForm(ic)
			}
			counts, body := tally(w.racePublic(forms))
			if counts[http.StatusOK] != 1 || counts[http.StatusBadRequest] != racers-1 {
				w.red("%d обменов одного кода на пуле %d: исходы %v (ожидалось 200×1 и 400×%d); первое тело отказа "+
					"сервера %q", racers, cell.width, counts, racers-1, body)
			}
		})
	}
}

// Обмены РАЗНЫХ кодов публичного клиента на пуле вдвое уже набега — обычная
// нагрузка без повтора: выдают все.
func TestLINEA1Pool_DistinctCodesOfAPublicClientOnANarrowPool(t *testing.T) {
	const racers, width = 8, 4
	w := newCeremonyWorld(t, "POOL-DISTINCT", "1", withPoolWidth(width))
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()
	pub := w.seedPublicClient("ceremony-public", []string{lineA1R})
	forms := make([]url.Values, racers)
	for i := range forms {
		forms[i] = exchangeForm(w.issueCode(pub, lineA1R))
	}
	counts, body := tally(w.racePublic(forms))
	if counts[http.StatusOK] != racers {
		w.red("%d обменов разных кодов на пуле %d: исходы %v (ожидалось 200×%d); первое тело отказа сервера %q",
			racers, width, counts, racers, body)
	}
}

// Пул в ОДНУ связь, один обмен: всякое второе взятие связи внутри окна
// транзакции запроса ждало бы само себя. Близнец — пул в две связи.
func TestLINEA1Pool_OneExchangeOnAOneConnectionPool(t *testing.T) {
	for _, cell := range []struct {
		name  string
		width int
	}{
		{"пул 1", 1},
		{"близнец: пул 2", 2},
	} {
		t.Run(cell.name, func(t *testing.T) {
			w := newCeremonyWorld(t, "POOL-ONE", "1", withPoolWidth(cell.width))
			w.requireGrant(grantAuthorizationCode)
			w.requireAuthorizeEndpoint()
			pub := w.seedPublicClient("ceremony-public", []string{lineA1R})
			ic := w.issueCode(pub, lineA1R)
			rec := w.post(clienttokenhttp.TokenPath, exchangeForm(ic), nil)
			if rec.Code != http.StatusOK {
				w.red("обмен на пуле %d ответил %d, ожидалось 200; тело %q", cell.width, rec.Code, rec.Body.String())
			}
		})
	}
}
