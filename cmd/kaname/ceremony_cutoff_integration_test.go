// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_cutoff_integration_test.go — выдача церемонии и отсечка субъекта
// (задача PRO-Robotech/kaname#423, возврат ревью безопасности сборки 425).
//
// Отсечку кладёт продуктовый писатель; сессия человека и семейство при этом
// живы — так пишут её писатели, не снимающие сессий. Сессия мира
// аутентифицирована раньше отсечки, и ни один ход церемонии — выдача кода,
// обмен, оборот — выдать по ней не вправе. У каждой клетки близнец в одно
// значение: отсечка раньше аутентификации сессии.
package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// cutSubject — отсечка человека мира в момент at продуктовым писателем.
func (w *ceremonyWorld) cutSubject(at time.Time) {
	w.t.Helper()
	if err := kanamepg.NewUserTokenRevocationRepo(w.pool).UpsertRevokeAll(w.ctx, domain.UserTokenRevocation{
		UserID: w.user, RevokeBefore: at, Reason: domain.RevokeReasonSecondFactorReset,
	}, ""); err != nil {
		w.fixture("отсечка субъекта: %v", err)
	}
}

// cutoffShifts — отсечка после аутентификации сессии мира (предмет) и её
// близнец — раньше неё.
var cutoffShifts = []struct {
	name    string
	shift   time.Duration
	refused bool
}{
	{"отсечка после аутентификации сессии", time.Second, true},
	{"близнец: отсечка раньше аутентификации сессии", -time.Second, false},
}

func TestLINEA1Cutoff_AuthorizeAfterTheSubjectCutoff(t *testing.T) {
	for _, cell := range cutoffShifts {
		t.Run(cell.name, func(t *testing.T) {
			w := newCeremonyWorld(t, "CUTOFF-AUTHORIZE", "1")
			w.requireAuthorizeEndpoint()
			w.cutSubject(w.session.authAt.Add(cell.shift))
			_, challenge := pkcePair()
			rec := w.get(lineA1AuthorizePath, authorizeQuery(w.ic1, lineA1R, stateOfLen(lineA1StateFloor+8), challenge), true)
			switch {
			case cell.refused && (rec.Code != http.StatusUnauthorized || rec.Body.String() != `{"error":"login_required"}`+"\n"):
				w.red("выдача кода по сессии, аутентифицированной до отсечки субъекта: %d %q (Location %q), "+
					"ожидалось 401 login_required", rec.Code, rec.Body.String(), rec.Header().Get("Location"))
			case !cell.refused && rec.Code != http.StatusFound:
				w.red("близнец: выдача кода ответила %d, ожидалось 302; тело %q", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestLINEA1Cutoff_ExchangeAfterTheSubjectCutoff(t *testing.T) {
	for _, cell := range cutoffShifts {
		t.Run(cell.name, func(t *testing.T) {
			w := newCeremonyWorld(t, "CUTOFF-EXCHANGE", "1")
			w.requireGrant(grantAuthorizationCode)
			w.requireAuthorizeEndpoint()
			ic := w.issueCode(w.ic1, lineA1R)
			w.cutSubject(w.session.authAt.Add(cell.shift))
			rec := w.exchangeAs(w.ic1, exchangeForm(ic))
			if cell.refused {
				requireInvalidGrant(t, w.id, "обмен кода сессии, аутентифицированной до отсечки субъекта", rec)
				return
			}
			if rec.Code != http.StatusOK {
				w.red("близнец: обмен ответил %d, ожидалось 200; тело %q", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestLINEA1Cutoff_RefreshAfterTheSubjectCutoff(t *testing.T) {
	for _, cell := range cutoffShifts {
		t.Run(cell.name, func(t *testing.T) {
			w := newCeremonyWorld(t, "CUTOFF-REFRESH", "1")
			w.requireGrant(grantAuthorizationCode)
			w.requireGrant(grantRefreshToken)
			w.requireAuthorizeEndpoint()
			tr := w.redeem(w.issueCode(w.ic1, lineA1R))
			if tr.RefreshToken == "" {
				w.fixture("обмен не выдал токена обновления")
			}
			w.cutSubject(w.session.authAt.Add(cell.shift))
			rec := w.refresh(w.ic1, tr.RefreshToken)
			if cell.refused {
				requireInvalidGrant(t, w.id, "оборот токена обновления сессии, аутентифицированной до отсечки субъекта", rec)
				return
			}
			if rec.Code != http.StatusOK {
				w.red("близнец: оборот ответил %d, ожидалось 200; тело %q", rec.Code, rec.Body.String())
			}
		})
	}
}
