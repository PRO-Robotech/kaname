// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_admission_ceremony_integration_test.go — полоса Ж приёмки
// `access-beyond-login-needs-a-verified-address.md` (kaname#456), часть
// собственной церемонии: авторизация клиента (EV-67), наш токен на сверке края
// (EV-68), обмен кода (EV-77), оборот токена обновления (EV-78) и порядок
// суждения полосы оборота (EV-79). Мир — `ceremony_world_integration_test.go`;
// отметка человека мира ставится писателем продукта и снимается без смены
// адреса (посев G3 круга 1 приёмки).
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/tokenintrospecthttp"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// markPerson — отметка человека мира писателем продукта.
func (w *ceremonyWorld) markPerson() {
	w.t.Helper()
	if err := kanamepg.NewLoginMethodRepo(w.pool).MarkEmailVerified(w.ctx, w.user, domain.Email(w.email), time.Now().UTC()); err != nil {
		w.fixture("посев отметки человека мира: %v", err)
	}
}

// unmarkPerson — снятие отметки без смены адреса.
func (w *ceremonyWorld) unmarkPerson() {
	w.t.Helper()
	if _, err := w.pool.Exec(w.ctx, `UPDATE kaname.users SET email_verified_at = NULL WHERE id = $1`, string(w.user)); err != nil {
		w.fixture("снятие отметки человека мира: %v", err)
	}
}

// censusOf — клетка переписи исходов церемонии.
func (w *ceremonyWorld) censusOf(outcome string) uint64 {
	w.t.Helper()
	got, ok := w.census.Read()[outcome]
	if !ok {
		w.red("клетки %q в переписи исходов церемонии нет — словарь её не знает", outcome)
	}
	return got
}

// introspect — ответ сверки края о нашем токене.
func (w *ceremonyWorld) introspect(raw string) (int, bool) {
	w.t.Helper()
	h := tokenintrospecthttp.NewHandler(tokenintrospecthttp.Config{
		Issuer:      lineA1Issuer,
		Keys:        ceremonyPublished{w: w},
		Revocations: kanamepg.NewMintedTokenRevocationRepo(w.pool),
	})
	req := httptest.NewRequest(http.MethodPost, tokenintrospecthttp.IntrospectPath, strings.NewReader(url.Values{"token": {raw}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var ans struct {
		Active bool `json:"active"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &ans)
	return rec.Code, ans.Active
}

// TestEV67_ClientAuthorizationInTheVerificationPosition — EV-67.
func TestEV67_ClientAuthorizationInTheVerificationPosition(t *testing.T) {
	w := newCeremonyWorld(t, "EV-67", "1")
	w.requireAuthorizeEndpoint()
	for _, verified := range []bool{false, true} {
		if verified {
			w.markPerson()
		} else {
			w.unmarkPerson()
		}
		verifier, challenge := pkcePair()
		_ = verifier
		rec := w.get(lineA1AuthorizePath, authorizeQuery(w.ic1, lineA1R, stateOfLen(lineA1StateFloor+8), challenge), true)
		if rec.Code != http.StatusFound {
			w.red("авторизация (подтверждён=%v) ответила %d, ожидалось 302; тело %q", verified, rec.Code, rec.Body.String())
		}
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			w.fixture("Location неразбираем: %v", err)
		}
		if verified {
			if loc.Query().Get("code") == "" {
				w.red("EV-67 (б): в обычном положении перенаправление несёт code: %q", loc.String())
			}
			continue
		}
		if loc.Query().Get("error") != "access_denied" || loc.Query().Get("code") != "" {
			w.red("EV-67 (а): в положении подтверждения — error=access_denied без code, получено %q", loc.String())
		}
	}
}

// TestEV68_OurTokenAtTheEdgeCheck — EV-68 (половина о человеке; контроль вида
// владельца — токен служебной учётной записи — держит проба правила
// предъявления в `internal/tokenrevocation`).
func TestEV68_OurTokenAtTheEdgeCheck(t *testing.T) {
	w := newCeremonyWorld(t, "EV-68", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()
	w.markPerson()
	pair := w.redeem(w.issueCode(w.ic1, lineA1R))

	if code, active := w.introspect(pair.AccessToken); code != http.StatusOK || !active {
		w.fixture("Дано: токен, выданный при стоящей отметке, действителен (код %d, active %v)", code, active)
	}
	w.unmarkPerson()
	code, active := w.introspect(pair.AccessToken)
	if code != http.StatusOK || active {
		w.red("EV-68 (а): отметка снята — ожидалось 200 {\"active\": false}, получено %d active=%v", code, active)
	}
	w.markPerson()
	if code, active := w.introspect(pair.AccessToken); code != http.StatusOK || !active {
		w.red("EV-68 (а): после подтверждения выданное снова действует — получено %d active=%v", code, active)
	}
}

// TestEV77_CeremonyCodeExchange — EV-77 (а)/(б); вторая половина (а) — после
// подтверждения в S тот же C погашен, новый код обменивается — держит проба
// подтверждения, заведённая с глаголом.
func TestEV77_CeremonyCodeExchange(t *testing.T) {
	for _, unmark := range []bool{true, false} {
		w := newCeremonyWorld(t, "EV-77", "1")
		w.requireGrant(grantAuthorizationCode)
		w.requireAuthorizeEndpoint()
		w.markPerson()
		ic := w.issueCode(w.ic1, lineA1R)
		if !unmark {
			w.redeem(ic)
			continue
		}
		w.unmarkPerson()
		refusedBefore := w.censusOf("token-grant-refused")
		rec := w.exchangeAs(ic.client, exchangeForm(ic))
		if rec.Code != http.StatusBadRequest || rec.Body.String() != `{"error":"invalid_grant"}`+"\n" {
			w.red("EV-77 (а): обмен кода при снятой отметке — ожидалось 400 {\"error\":\"invalid_grant\"}, получено %d %q",
				rec.Code, rec.Body.String())
		}
		if got := w.censusOf("token-owner-unverified"); got != 1 {
			w.red("EV-77 (а): клетка token-owner-unverified выросла на 1 — получено %d", got)
		}
		if got := w.censusOf("token-grant-refused"); got != refusedBefore {
			w.red("EV-77 (а): клетка token-grant-refused не растёт — было %d, стало %d", refusedBefore, got)
		}
	}
}

// TestEV78_CeremonyRefreshRotation_ab — EV-78 (а)/(б): отказ по отметке не
// оборачивает предъявленный токен обновления и не отзывает семейство.
func TestEV78_CeremonyRefreshRotation_ab(t *testing.T) {
	for _, unmark := range []bool{true, false} {
		w := newCeremonyWorld(t, "EV-78", "1")
		w.requireGrant(grantRefreshToken)
		w.requireGrant(grantAuthorizationCode)
		w.requireAuthorizeEndpoint()
		w.markPerson()
		pair := w.firstPair()
		if !unmark {
			w.rotate("EV-78 (б): R1 → R2", pair)
			continue
		}
		w.unmarkPerson()
		rec := w.refresh(w.ic1, pair.RefreshToken)
		if rec.Code != http.StatusBadRequest || rec.Body.String() != `{"error":"invalid_grant"}`+"\n" {
			w.red("EV-78 (а): оборот при снятой отметке — ожидалось 400 {\"error\":\"invalid_grant\"}, получено %d %q",
				rec.Code, rec.Body.String())
		}
		if got := w.censusOf("token-owner-unverified"); got != 1 {
			w.red("EV-78 (а): клетка token-owner-unverified — получено %d", got)
		}
		// Строка R1 не обёрнута, семейство живо: после отметки (посев) тот же R1
		// оборачивается обычным исходом.
		w.markPerson()
		w.rotate("EV-78 (а): R1 не обёрнут и семейство живо", pair)
	}
}

// TestEV79_RefreshReplayBeforeTheMarkAndUnansweredQuestion — EV-79 (а), первая
// половина (зелена и до кода — положительный контроль порядка), и (б).
func TestEV79_RefreshReplayBeforeTheMarkAndUnansweredQuestion(t *testing.T) {
	t.Run("а — повтор раньше отметки", func(t *testing.T) {
		w := newCeremonyWorld(t, "EV-79а", "1")
		w.requireGrant(grantRefreshToken)
		w.requireAuthorizeEndpoint()
		w.markPerson()
		r1 := w.firstPair()
		r2 := w.rotate("R1 → R2", r1)
		w.unmarkPerson()
		requireInvalidGrant(t, w.id, "повтор R1 при снятой отметке", w.refresh(w.ic1, r1.RefreshToken))
		var revoked int
		if err := w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.token_families WHERE revoked_reason = 'refresh-replay'`).Scan(&revoked); err != nil {
			w.fixture("чтение причины отзыва семейства: %v", err)
		}
		if revoked != 1 {
			w.red("EV-79 (а): семейство F отозвано с причиной refresh-replay — таких %d", revoked)
		}
		w.markPerson()
		requireInvalidGrant(t, w.id, "R2 после подтверждения: отказ по отметке повтора не спрятал", w.refresh(w.ic1, r2.RefreshToken))
	})
	t.Run("б — вопрос без ответа", func(t *testing.T) {
		w := newCeremonyWorld(t, "EV-79б", "1")
		w.requireGrant(grantRefreshToken)
		w.requireAuthorizeEndpoint()
		w.markPerson()
		r1 := w.firstPair()
		conn, err := pgx.ConnectConfig(w.ctx, w.pool.Config().ConnConfig.Copy())
		if err != nil {
			w.fixture("связь держателя замка: %v", err)
		}
		defer func() { _ = conn.Close(context.Background()) }()
		tx, err := conn.Begin(w.ctx)
		if err != nil {
			w.fixture("транзакция держателя: %v", err)
		}
		if _, err := tx.Exec(w.ctx, `LOCK TABLE kaname.users IN ACCESS EXCLUSIVE MODE`); err != nil {
			w.fixture("замок таблицы людей: %v", err)
		}
		rec := w.refresh(w.ic1, r1.RefreshToken)
		_ = tx.Rollback(w.ctx)
		if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != `{"error":"temporarily_unavailable"}`+"\n" {
			w.red("EV-79 (б): хранилище отметок не ответило — ожидалось 503 temporarily_unavailable, получено %d %q",
				rec.Code, rec.Body.String())
		}
		if got := w.censusOf("token-unavailable"); got != 1 {
			w.red("EV-79 (б): клетка token-unavailable — получено %d", got)
		}
		w.rotate("EV-79 (б): после восстановления тот же R1 — новая пара", r1)
	})
}
