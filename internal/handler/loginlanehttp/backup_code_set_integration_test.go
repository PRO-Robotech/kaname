// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// backup_code_set_integration_test.go — пробы службы приёмки
// `docs/engineering/acceptance/backup-code-set-has-one-form.md` (kaname#297) на
// настоящей базе через обработчик полосы: набор запасных кодов в ответах раздела
// второго фактора — одна форма. `backupCodes` — только массив кодов ответа
// `confirm` и перечеканки; состояние набора — объект `backupCodeSet` ровно по
// таблице Р4; плоского `backupCodesRemaining` нет ни в одном ответе; «сводки нет»
// — отсутствие ключа, а не нуль (BCS-50, BCS-51 — дефект хранения, через край
// не строится, поэтому держатель здесь).
//
// Посев G0 — `bcsSeed`: регистрация, вход паролем, `enroll`, `confirm` первым
// кодом НАСТОЯЩИМИ глаголами; сессия S — сессия ответа `confirm` (уровень «2»,
// свежая), коды C1…C10 — из того же ответа.

package loginlanehttp_test

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

const (
	bcsTextFormCode   = "Illegal argument code: must be 10 characters of the backup-code alphabet"
	bcsTextFormLogin  = "Illegal argument secondFactor.code: must be 10 characters of the backup-code alphabet"
	bcsZeroMoment     = "0001-01-01T00:00:00Z"
	bcsMalformedCode  = "ABC"
	bcsKeySet         = "backupCodeSet"
	bcsKeyCodes       = "backupCodes"
	bcsKeyFlatRemains = "backupCodesRemaining"
)

// bcsCodeForm — форма кода набора: десять знаков алфавита запасных кодов.
var bcsCodeForm = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{10}$`)

// bcsG0 — посев G0: человек, сессия S ответа `confirm`, тело этого ответа.
type bcsG0 struct {
	p       *suaPerson
	s       laneSession
	confirm map[string]any
}

// bodyOf — тело ответа картой.
func bodyOf(t *testing.T, id string, r reply) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoErrorf(t, json.Unmarshal([]byte(r.body), &m), "%s: тело — объект JSON: %s", id, r.body)
	return m
}

// bcsSeed — G0 настоящими глаголами; коды набора — в `p.codes`.
func (h *suaStand) bcsSeed(t *testing.T, tag string) bcsG0 {
	t.Helper()
	p := h.person(t, tag)
	s := h.login(t, p)
	r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathSecondFactorEnroll,
		map[string]any{"csrfToken": h.csrfFor(t, domain.FormSecondFactor, s.form)}, fwd(), s.bearer, s.form)
	require.Equalf(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): enroll: %s", r.body)
	var en struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &en), r.body)
	require.NotEmpty(t, en.Secret, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): ответ enroll несёт секрет")
	p.secret = en.Secret
	r = h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathSecondFactorConfirm,
		map[string]any{"code": h.totpNow(t, p), "csrfToken": h.csrfFor(t, domain.FormSecondFactor, s.form)}, fwd(), s.bearer, s.form)
	require.Equalf(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): confirm первым кодом: %s", r.body)
	body := bodyOf(t, "G0", r)
	var cf struct {
		BackupCodes []string `json:"backupCodes"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &cf), r.body)
	require.Len(t, cf.BackupCodes, passwordverify.BackupCodeCount, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): confirm выдал набор")
	p.codes = cf.BackupCodes
	return bcsG0{p: p, s: rotated(t, "G0", r, s), confirm: body}
}

// requireSet — `backupCodeSet` тела: объект с ключами ровно из Р2, первые три
// обязательны; `lastUsedAt` — по hasLastUsed. Значения не совпадают ни с одним
// кодом набора.
func requireSet(t *testing.T, id string, body map[string]any, remaining int, hasLastUsed bool, codes []string) map[string]any {
	t.Helper()
	raw, ok := body[bcsKeySet]
	if !ok {
		b, _ := json.Marshal(body)
		t.Fatalf("ЧЕСТНЫЙ-КРАСНЫЙ %s: ключа `%s` нет: %s", id, bcsKeySet, b)
	}
	set, ok := raw.(map[string]any)
	require.Truef(t, ok, "%s: `%s` — объект: %v", id, bcsKeySet, raw)
	want := []string{"issuedAt", "remaining", "total"}
	if hasLastUsed {
		want = append(want, "lastUsedAt")
	}
	got := make([]string, 0, len(set))
	for k := range set {
		got = append(got, k)
	}
	sort.Strings(want)
	sort.Strings(got)
	require.Equalf(t, want, got, "%s: ключи `%s` ровно по Р2", id, bcsKeySet)
	require.EqualValuesf(t, remaining, set["remaining"], "%s: remaining", id)
	require.EqualValuesf(t, passwordverify.BackupCodeCount, set["total"], "%s: total", id)
	momentOf(t, id, body, bcsKeySet+".issuedAt")
	if hasLastUsed {
		momentOf(t, id, body, bcsKeySet+".lastUsedAt")
	}
	for k, v := range set {
		for _, c := range codes {
			require.NotEqualf(t, c, v, "%s: значение `%s.%s` — не код набора", id, bcsKeySet, k)
		}
	}
	return set
}

// requireNoSetKeys — в теле нет ни сводки, ни плоского остатка.
func requireNoSetKeys(t *testing.T, id string, body map[string]any) {
	t.Helper()
	require.NotContainsf(t, body, bcsKeySet, "%s: ключа `%s` нет", id, bcsKeySet)
	require.NotContainsf(t, body, bcsKeyFlatRemains, "%s: ключа `%s` нет", id, bcsKeyFlatRemains)
}

// requireFormRefusal — отказ формы запасного кода (Р5): 400, `code` 3, текст
// дословно.
func requireFormRefusal(t *testing.T, id string, r reply, text string) {
	t.Helper()
	require.Equalf(t, http.StatusBadRequest, r.status, "%s: статус: %s", id, r.body)
	ref := parseRefusal(t, r.body)
	require.Equalf(t, 3, ref.Code, "%s: code: %s", id, r.body)
	require.Equalf(t, text, ref.Message, "%s: текст отказа дословно", id)
}

// stepUp — повышение способом кода под сессией s.
func (h *suaStand) bcsStepUp(t *testing.T, s laneSession, method, code string) reply {
	t.Helper()
	return h.stepUpCode(t, s, method, code)
}

// bcsConfirmed — перечеканка либо снятие (`{"method","code"}`).
func (h *suaStand) bcsConfirmed(t *testing.T, s laneSession, path, method, code string) reply {
	t.Helper()
	return h.lane.do(t, h.c, http.MethodPost, path,
		map[string]any{"method": method, "code": code, "csrfToken": h.csrfFor(t, domain.FormSecondFactor, s.form)}, fwd(), s.bearer, s.form)
}

// bcsOutsideSet — код годной формы, не входящий в набор.
func bcsOutsideSet(t *testing.T, codes []string) string {
	t.Helper()
	for _, c := range []string{"0000000000", "1111111111", "2222222222", "ZZZZZZZZZZ"} {
		in := false
		for _, x := range codes {
			in = in || x == c
		}
		if !in {
			require.Regexp(t, bcsCodeForm, c, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): код годной формы")
			return c
		}
	}
	t.Fatal("НЕ-ВЫПОЛНИЛОСЬ(фикстура): нет кода вне набора")
	return ""
}

// TestBCS_ReadAndConfirmCarryOneForm — BCS-01, BCS-30 (чтение), BCS-02
// (близнец без фактора), BCS-03 (подтверждение).
func TestBCS_ReadAndConfirmCarryOneForm(t *testing.T) {
	h := newSUAStand(t)

	t.Run("BCS-03", func(t *testing.T) {
		const id = "BCS-03"
		g := h.bcsSeed(t, "bcs03")
		raw, ok := g.confirm[bcsKeyCodes].([]any)
		require.Truef(t, ok, "%s: `backupCodes` — массив: %v", id, g.confirm[bcsKeyCodes])
		require.Lenf(t, raw, passwordverify.BackupCodeCount, "%s: ровно 10 кодов", id)
		seen := map[string]bool{}
		for _, x := range raw {
			c, ok := x.(string)
			require.Truef(t, ok, "%s: код — строка", id)
			require.Regexp(t, bcsCodeForm, c, id)
			require.Falsef(t, seen[c], "%s: коды различны", id)
			seen[c] = true
		}
		set := requireSet(t, id, g.confirm, 10, false, g.p.codes)
		next := h.status(t, g.s)
		require.Equalf(t, set, requireSet(t, id+" следующий GET", next, 10, false, g.p.codes), "%s: confirm = следующий GET", id)
	})

	t.Run("BCS-01", func(t *testing.T) {
		const id = "BCS-01"
		g := h.bcsSeed(t, "bcs01")
		st := h.status(t, g.s)
		requireSet(t, id, st, 10, false, g.p.codes)
		// BCS-30: прежнего объекта под `backupCodes` нет; близнец — BCS-03.
		require.NotContainsf(t, st, bcsKeyCodes, "BCS-30: ключа `backupCodes` в чтении нет")
		require.Containsf(t, g.confirm, bcsKeyCodes, "BCS-30 близнец: confirm той же службы несёт `backupCodes`")
	})

	t.Run("BCS-02", func(t *testing.T) {
		const id = "BCS-02"
		q := h.person(t, "bcs02")
		st := h.status(t, h.login(t, q))
		require.Equalf(t, false, requireDeclared(t, id, st, "totp.enrolled"), "%s: totp.enrolled", id)
		require.NotContainsf(t, st, bcsKeySet, "%s: ключа `backupCodeSet` нет", id)
		require.NotContainsf(t, st, bcsKeyCodes, "%s: ключа `backupCodes` нет", id)
	})
}

// TestBCS_StepUpAndRegenerateCarryTheSetAfterTheVerb — BCS-04, BCS-05, BCS-06,
// BCS-07, BCS-08, BCS-31 (повышение).
func TestBCS_StepUpAndRegenerateCarryTheSetAfterTheVerb(t *testing.T) {
	h := newSUAStand(t)

	t.Run("BCS-06", func(t *testing.T) {
		const id = "BCS-06"
		g := h.bcsSeed(t, "bcs06")
		issued := requireSet(t, id+" Дано", h.status(t, g.s), 10, false, g.p.codes)["issuedAt"]
		r := h.bcsStepUp(t, g.s, "lookup_secret", g.p.codes[0])
		require.Equalf(t, http.StatusOK, r.status, "%s: %s", id, r.body)
		body := bodyOf(t, id, r)
		set := requireSet(t, id, body, 9, true, g.p.codes)
		require.Equalf(t, issued, set["issuedAt"], "%s: issuedAt — прежний", id)
		require.NotContainsf(t, body, bcsKeyFlatRemains, "%s, BCS-31: плоского остатка нет", id)
		next := h.status(t, rotated(t, id, r, g.s))
		require.Equalf(t, set, requireSet(t, id+" следующий GET", next, 9, true, g.p.codes), "%s: повышение = следующий GET", id)
	})

	t.Run("BCS-07", func(t *testing.T) {
		const id = "BCS-07"
		g := h.bcsSeed(t, "bcs07")
		r := h.bcsStepUp(t, g.s, "totp", h.totpNow(t, g.p))
		require.Equalf(t, http.StatusOK, r.status, "%s: %s", id, r.body)
		requireNoSetKeys(t, id, bodyOf(t, id, r))
		requireSet(t, id+" следующий GET", h.status(t, rotated(t, id, r, g.s)), 10, false, g.p.codes)
	})

	for _, tc := range []struct{ id, method string }{{"BCS-04", "totp"}, {"BCS-05", "lookup_secret"}} {
		t.Run(tc.id, func(t *testing.T) {
			id := tc.id
			g := h.bcsSeed(t, "bcs-regen-"+tc.method)
			spent := h.bcsStepUp(t, g.s, "lookup_secret", g.p.codes[0])
			require.Equalf(t, http.StatusOK, spent.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): трата C1: %s", spent.body)
			s := rotated(t, id, spent, g.s)
			before := h.status(t, s)
			requireSet(t, id+" Дано", before, 9, true, g.p.codes)
			prevIssued := momentOf(t, id, before, bcsKeySet+".issuedAt")
			code := g.p.codes[1]
			if tc.method == "totp" {
				code = h.totpNow(t, g.p)
			}
			r := h.bcsConfirmed(t, s, loginlanehttp.PathSecondFactorBackupCodes, tc.method, code)
			require.Equalf(t, http.StatusOK, r.status, "%s: %s", id, r.body)
			body := bodyOf(t, id, r)
			var fresh struct {
				BackupCodes []string `json:"backupCodes"`
			}
			require.NoError(t, json.Unmarshal([]byte(r.body), &fresh), r.body)
			require.Lenf(t, fresh.BackupCodes, passwordverify.BackupCodeCount, "%s: 10 новых кодов", id)
			for _, c := range fresh.BackupCodes {
				require.NotContainsf(t, g.p.codes, c, "%s: новый код не входит в C1…C10", id)
			}
			set := requireSet(t, id, body, 10, false, fresh.BackupCodes)
			require.Falsef(t, momentOf(t, id, body, bcsKeySet+".issuedAt").Before(prevIssued), "%s: issuedAt не раньше прежнего", id)
			next := h.status(t, rotated(t, id, r, s))
			require.Equalf(t, set, requireSet(t, id+" следующий GET", next, 10, false, fresh.BackupCodes), "%s: перечеканка = следующий GET", id)
		})
	}

	t.Run("BCS-08", func(t *testing.T) {
		const id = "BCS-08"
		g := h.bcsSeed(t, "bcs08")
		s := g.s
		for i := 0; i < 9; i++ {
			r := h.bcsStepUp(t, s, "lookup_secret", g.p.codes[i])
			require.Equalf(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): трата C%d: %s", i+1, r.body)
			s = rotated(t, id, r, s)
		}
		r := h.bcsStepUp(t, s, "lookup_secret", g.p.codes[9])
		require.Equalf(t, http.StatusOK, r.status, "%s: %s", id, r.body)
		requireSet(t, id, bodyOf(t, id, r), 0, true, g.p.codes)
		st := h.status(t, rotated(t, id, r, s))
		require.Equalf(t, true, requireDeclared(t, id, st, "totp.enrolled"), "%s: totp.enrolled", id)
		requireSet(t, id+" следующий GET", st, 0, true, g.p.codes)
		require.NotContainsf(t, methodsOf(t, id, st), "lookup_secret", "%s: исчерпанный набор способом не назван", id)
	})
}

// TestBCS_RefusalsCarryNoSetAndNameTheFormText — BCS-09, BCS-12, BCS-13,
// BCS-14, BCS-16, BCS-17, BCS-18.
func TestBCS_RefusalsCarryNoSetAndNameTheFormText(t *testing.T) {
	h := newSUAStand(t)

	t.Run("BCS-09", func(t *testing.T) {
		const id = "BCS-09"
		g := h.bcsSeed(t, "bcs09")
		r := h.bcsStepUp(t, g.s, "lookup_secret", g.p.codes[0])
		require.Equalf(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): трата C1: %s", r.body)
		s := rotated(t, id, r, g.s)
		r = h.bcsStepUp(t, s, "lookup_secret", g.p.codes[0])
		requireAuthFailed(t, id, r)
		requireNoSetKeys(t, id, bodyOf(t, id, r))
		requireSet(t, id+" следующий GET", h.status(t, s), 9, true, g.p.codes)
	})

	t.Run("BCS-12", func(t *testing.T) {
		const id = "BCS-12"
		g := h.bcsSeed(t, "bcs12")
		r := h.bcsConfirmed(t, g.s, loginlanehttp.PathSecondFactorRemove, "lookup_secret", bcsMalformedCode)
		requireFormRefusal(t, id, r, bcsTextFormCode)
		st := h.status(t, g.s)
		require.Equalf(t, true, requireDeclared(t, id, st, "totp.enrolled"), "%s: фактор не снят", id)
		requireSet(t, id+" следующий GET", st, 10, false, g.p.codes)
	})

	t.Run("BCS-13", func(t *testing.T) {
		const id = "BCS-13"
		g := h.bcsSeed(t, "bcs13")
		r := h.bcsConfirmed(t, g.s, loginlanehttp.PathSecondFactorRemove, "lookup_secret", bcsOutsideSet(t, g.p.codes))
		require.Equalf(t, http.StatusUnauthorized, r.status, "%s: отказ сверки, а не формы: %s", id, r.body)
		ref := parseRefusal(t, r.body)
		require.Equalf(t, 16, ref.Code, "%s: code", id)
		require.Equalf(t, suaTextAuthFailed, ref.Message, "%s: текст", id)
	})

	t.Run("BCS-17", func(t *testing.T) {
		const id = "BCS-17"
		g := h.bcsSeed(t, "bcs17")
		r := h.bcsStepUp(t, g.s, "lookup_secret", bcsMalformedCode)
		requireFormRefusal(t, id, r, bcsTextFormCode)
		requireNoSetKeys(t, id, bodyOf(t, id, r))
		requireSet(t, id+" следующий GET", h.status(t, g.s), 10, false, g.p.codes)
	})

	t.Run("BCS-18", func(t *testing.T) {
		const id = "BCS-18"
		g := h.bcsSeed(t, "bcs18")
		before := requireSet(t, id+" Дано", h.status(t, g.s), 10, false, g.p.codes)
		r := h.bcsConfirmed(t, g.s, loginlanehttp.PathSecondFactorBackupCodes, "lookup_secret", bcsMalformedCode)
		requireFormRefusal(t, id, r, bcsTextFormCode)
		body := bodyOf(t, id, r)
		require.NotContainsf(t, body, bcsKeyCodes, "%s: ключа `backupCodes` нет", id)
		require.NotContainsf(t, body, bcsKeySet, "%s: ключа `backupCodeSet` нет", id)
		require.Equalf(t, before, requireSet(t, id+" следующий GET", h.status(t, g.s), 10, false, g.p.codes), "%s: набор не изменился", id)
	})

	login := func(t *testing.T, p *suaPerson, code string) reply {
		t.Helper()
		tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
		return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathLogin, map[string]any{
			"email": p.email, "password": integrationPassword, "csrfToken": tok,
			"secondFactor": map[string]string{"method": "lookup_secret", "code": code},
		}, fwd(), ctxCk)
	}

	t.Run("BCS-14", func(t *testing.T) {
		const id = "BCS-14"
		g := h.bcsSeed(t, "bcs14")
		requireFormRefusal(t, id, login(t, g.p, bcsMalformedCode), bcsTextFormLogin)
	})

	t.Run("BCS-16", func(t *testing.T) {
		const id = "BCS-16"
		g := h.bcsSeed(t, "bcs16")
		r := login(t, g.p, g.p.codes[0])
		require.Equalf(t, http.StatusOK, r.status, "%s: %s", id, r.body)
		body := bodyOf(t, id, r)
		keys := make([]string, 0, len(body))
		for k := range body {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		require.Equalf(t, []string{"session", "user"}, keys, "%s: ключи тела ровно user, session", id)
		require.Equalf(t, "2", requireDeclared(t, id, body, "session.assuranceLevel"), "%s: уровень «2»", id)
		s := laneSession{bearer: cookieNamed(r.cookies, loginlanehttp.CookieSession), form: cookieNamed(r.cookies, loginlanehttp.CookieForm)}
		require.NotNilf(t, s.bearer, "%s: вход пишет носитель", id)
		require.NotNilf(t, s.form, "%s: вход сменяет контекст формы", id)
		requireSet(t, id+" следующий GET", h.status(t, s), 9, true, g.p.codes)
	})
}

// TestBCS_RemoveCarriesNoSet — BCS-10, BCS-11, BCS-31 (снятие): ключи тела ровно
// `session`, `assurance`; остатка снятого набора нет ни под каким ключом
// (инвариант kaname#275).
func TestBCS_RemoveCarriesNoSet(t *testing.T) {
	h := newSUAStand(t)
	for _, tc := range []struct{ id, method string }{{"BCS-10", "totp"}, {"BCS-11", "lookup_secret"}} {
		t.Run(tc.id, func(t *testing.T) {
			id := tc.id
			g := h.bcsSeed(t, "bcs-remove-"+tc.method)
			code := g.p.codes[0]
			if tc.method == "totp" {
				code = h.totpNow(t, g.p)
			}
			r := h.bcsConfirmed(t, g.s, loginlanehttp.PathSecondFactorRemove, tc.method, code)
			require.Equalf(t, http.StatusOK, r.status, "%s: %s", id, r.body)
			body := bodyOf(t, id, r)
			keys := make([]string, 0, len(body))
			for k := range body {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			require.Equalf(t, []string{"assurance", "session"}, keys, "%s: ключи тела ровно session, assurance", id)
			st := h.status(t, rotated(t, id, r, g.s))
			require.Equalf(t, false, requireDeclared(t, id, st, "totp.enrolled"), "%s: фактор снят", id)
			require.NotContainsf(t, st, bcsKeySet, "%s: ключа `backupCodeSet` нет", id)
		})
	}
}

// TestBCS32_OneTypePerKeyAcrossTheSection — BCS-32: обход всех ответов
// раздела одной последовательностью; присутствие `backupCodeSet` — ровно по
// таблице Р4, `backupCodes` — массив из 10 строк и только у `confirm` и
// перечеканки, `backupCodesRemaining` — нигде.
func TestBCS32_OneTypePerKeyAcrossTheSection(t *testing.T) {
	const id = "BCS-32"
	h := newSUAStand(t)
	g := h.bcsSeed(t, "bcs32")
	type step struct {
		verb     string
		body     map[string]any
		hasSet   bool
		hasCodes bool
	}
	var steps []step
	s := g.s
	take := func(verb string, r reply, hasSet, hasCodes bool) {
		t.Helper()
		require.Equalf(t, http.StatusOK, r.status, "%s: %s: %s", id, verb, r.body)
		steps = append(steps, step{verb: verb, body: bodyOf(t, id, r), hasSet: hasSet, hasCodes: hasCodes})
		if b := cookieNamed(r.cookies, loginlanehttp.CookieSession); b != nil {
			s = laneSession{bearer: b, form: s.form}
		}
	}
	get := func(verb string, hasSet bool) {
		t.Helper()
		steps = append(steps, step{verb: verb, body: h.status(t, s), hasSet: hasSet})
	}

	get("GET заведённого", true)
	take("повышение password", h.lane.do(t, h.c, http.MethodPost, suaPathStepUp,
		map[string]any{"method": "password", "password": integrationPassword, "csrfToken": h.csrfFor(t, domain.FormStepUp, s.form)}, fwd(), s.bearer, s.form), false, false)
	take("повышение totp", h.bcsStepUp(t, s, "totp", h.totpNow(t, g.p)), false, false)
	take("повышение lookup_secret", h.bcsStepUp(t, s, "lookup_secret", g.p.codes[0]), true, false)
	take("перечеканка totp", h.bcsConfirmed(t, s, loginlanehttp.PathSecondFactorBackupCodes, "totp", h.totpNow(t, g.p)), true, true)
	get("GET после перечеканки", true)
	take("снятие totp", h.bcsConfirmed(t, s, loginlanehttp.PathSecondFactorRemove, "totp", h.totpNow(t, g.p)), false, false)
	get("GET после снятия", false)
	r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathSecondFactorEnroll,
		map[string]any{"csrfToken": h.csrfFor(t, domain.FormSecondFactor, s.form)}, fwd(), s.bearer, s.form)
	take("enroll", r, false, false)
	secret, ok := steps[len(steps)-1].body["secret"].(string)
	require.Truef(t, ok, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): ответ enroll несёт секрет")
	g.p.secret = secret
	take("confirm", h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathSecondFactorConfirm,
		map[string]any{"code": h.totpNow(t, g.p), "csrfToken": h.csrfFor(t, domain.FormSecondFactor, s.form)}, fwd(), s.bearer, s.form), true, true)
	get("GET после confirm", true)

	require.Len(t, steps, 11, "%s: обход — одиннадцать ответов", id)
	allowed := map[string]bool{"remaining": true, "total": true, "issuedAt": true, "lastUsedAt": true}
	withSet, withCodes := 0, 0
	for _, st := range steps {
		where := id + ": " + st.verb
		require.NotContainsf(t, st.body, bcsKeyFlatRemains, "%s: ключа `%s` нет", where, bcsKeyFlatRemains)
		codes, has := st.body[bcsKeyCodes]
		require.Equalf(t, st.hasCodes, has, "%s: присутствие `backupCodes`", where)
		if has {
			withCodes++
			arr, ok := codes.([]any)
			require.Truef(t, ok, "%s: `backupCodes` — массив: %v", where, codes)
			require.Lenf(t, arr, passwordverify.BackupCodeCount, "%s: ровно 10 строк", where)
			for _, x := range arr {
				_, ok := x.(string)
				require.Truef(t, ok, "%s: элемент `backupCodes` — строка", where)
			}
		}
		raw, has := st.body[bcsKeySet]
		require.Equalf(t, st.hasSet, has, "%s: присутствие `backupCodeSet` по таблице Р4", where)
		if has {
			withSet++
			set, ok := raw.(map[string]any)
			require.Truef(t, ok, "%s: `backupCodeSet` — объект: %v", where, raw)
			for k := range set {
				require.Truef(t, allowed[k], "%s: ключ `backupCodeSet.%s` вне Р2", where, k)
			}
			for _, k := range []string{"remaining", "total", "issuedAt"} {
				require.Containsf(t, set, k, "%s: обязательный ключ `backupCodeSet.%s`", where, k)
			}
		}
	}
	require.Equalf(t, 6, withSet, "%s: тел со сводкой — шесть", id)
	require.Equalf(t, 2, withCodes, "%s: тел с массивом кодов — два", id)
}

// TestBCS50_51_StatusWithoutAReadableSetHasNoSummary — BCS-50 (строки набора
// нет), BCS-51 (материал не открывается) против близнеца BCS-01: фактор
// заведён, сводки нет — ни нулевого остатка, ни нулевого момента; `lookup_secret`
// способом повышения не назван; наружу оба дефекта не различаются.
func TestBCS50_51_StatusWithoutAReadableSetHasNoSummary(t *testing.T) {
	h := newSUAStand(t)
	bodies := map[string]map[string]any{}
	for _, tc := range []struct {
		id    string
		spoil string
	}{
		{"BCS-01", ""},
		{"BCS-50", `DELETE FROM kaname.user_login_methods WHERE user_id = $1 AND kind = 'lookup_secret'`},
		{"BCS-51", `UPDATE kaname.user_login_methods SET verifier = '$unknown-format$v=1$c29tZQ$Ym9keQ' WHERE user_id = $1 AND kind = 'lookup_secret'`},
	} {
		t.Run(tc.id, func(t *testing.T) {
			id := tc.id
			g := h.bcsSeed(t, "bcs-unread-"+id)
			if tc.spoil != "" {
				tag, err := h.pool.Exec(h.ctx, tc.spoil, string(g.p.user))
				require.NoErrorf(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): %s порча строки набора", id)
				require.EqualValuesf(t, 1, tag.RowsAffected(), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): %s тронута ровно строка набора", id)
			}
			st := h.status(t, g.s)
			require.Equalf(t, true, requireDeclared(t, id, st, "totp.enrolled"), "%s: фактор заведён", id)
			if tc.spoil == "" {
				requireSet(t, id, st, 10, false, g.p.codes)
				require.Containsf(t, methodsOf(t, id, st), "lookup_secret", "%s: набор прочитан — способ назван", id)
				return
			}
			require.NotContainsf(t, st, bcsKeySet, "%s: ключа `backupCodeSet` нет — сводки нет, а не нули", id)
			require.NotContainsf(t, st, bcsKeyCodes, "%s: ключа `backupCodes` нет", id)
			require.NotContainsf(t, methodsOf(t, id, st), "lookup_secret", "%s: способом не назван", id)
			raw, err := json.Marshal(st)
			require.NoError(t, err)
			require.NotContainsf(t, string(raw), bcsZeroMoment, "%s: нулевого момента в теле нет", id)
			// Моменты фактора `totp` у разных людей разные — сравнение без них.
			totp, ok := st["totp"].(map[string]any)
			require.Truef(t, ok, "%s: `totp` — объект", id)
			delete(totp, "confirmedAt")
			delete(totp, "lastUsedAt")
			bodies[id] = st
		})
	}
	require.Len(t, bodies, 2, "НЕ-ВЫПОЛНИЛОСЬ: оба дефектных тела собраны")
	require.Equal(t, bodies["BCS-50"], bodies["BCS-51"], "BCS-51: тело равно телу BCS-50 — отсутствие и нечитаемость наружу не различаются")
}
