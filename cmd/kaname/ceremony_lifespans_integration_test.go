// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_lifespans_integration_test.go — сроки церемонии, названные
// установкой, сквозь собранную церемонию на настоящей базе (kaname#318;
// приёмка `ceremony-lifespans-are-declared-within-their-ceilings.md`,
// сценарии KN-CTTL-09…12).
//
// Мир, ступени пробы и слова исхода — `ceremony_world_integration_test.go`.
// Сроки миру называет его настройка (`withCeremonyLifespans`), и сборка — та
// же, что у корня (`buildCeremonySurface`).
//
// # Возраст — сдвигом ОДНОЙ записи, а не ожиданием (Р7)
//
// Сдвиг переносит на Δ назад все моменты, записанные испытуемым у одной записи:
// у кода — выдачу и срок, у семейства — отметку рождения и выдачу со сроком
// каждого его токена обновления. Промежутки, записанные испытуемым, сохраняются,
// поэтому база (срок записи против `now()`) и правило границы (рождение плюс
// срок семейства) видят ровно прошествие Δ. Сессия не сдвигается: её срок —
// 12 ч от входа, дальше любого возраста ниже, и границы семейства она не сужает.
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// cttlCeremonyOnRecord — запись журнала старта «own OAuth ceremony is on».
const cttlCeremonyOnRecord = "own OAuth ceremony is on"

// codeFamilies — семейства, у которых есть запись кода.
func (w *ceremonyWorld) codeFamilies() map[string]bool {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx, `SELECT family_id FROM `+lineA1CodeStore)
	if err != nil {
		w.fixture("чтение семейств кода: %v", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			w.fixture("чтение семейства кода: %v", err)
		}
		out[id] = true
	}
	if err := rows.Err(); err != nil {
		w.fixture("чтение семейств кода: %v", err)
	}
	return out
}

// issueCodeInFamily — выдача кода и семейство, которое она завела.
func (w *ceremonyWorld) issueCodeInFamily(c *ceremonyClient, redirect string) (issuedCode, string) {
	w.t.Helper()
	before := w.codeFamilies()
	ic := w.issueCode(c, redirect)
	var born []string
	for id := range w.codeFamilies() {
		if !before[id] {
			born = append(born, id)
		}
	}
	if len(born) != 1 {
		w.fixture("выдача кода завела семейств %d, ожидалось одно: %v", len(born), born)
	}
	return ic, born[0]
}

// firstPairInFamily — первая пара обменом кода клиента ic1 и её семейство.
func (w *ceremonyWorld) firstPairInFamily() (tokenResponse, string) {
	w.t.Helper()
	ic, family := w.issueCodeInFamily(w.ic1, lineA1R)
	tr := w.redeem(ic)
	if tr.RefreshToken == "" {
		w.t.Fatalf("%s: обмен кода не выдал refresh_token", w.id)
	}
	return tr, family
}

// shiftCode переносит выдачу и срок ОДНОЙ записи кода на d назад.
func (w *ceremonyWorld) shiftCode(family string, d time.Duration) {
	w.t.Helper()
	tag, err := w.pool.Exec(w.ctx, `UPDATE `+lineA1CodeStore+`
		   SET issued_at = issued_at - make_interval(secs => $2),
		       expires_at = expires_at - make_interval(secs => $2)
		 WHERE family_id = $1`, family, d.Seconds())
	if err != nil || tag.RowsAffected() != 1 {
		w.fixture("сдвиг записи кода семейства %s на %s не лёг (строк %d): %v", family, d, tag.RowsAffected(), err)
	}
}

// shiftFamily переносит рождение семейства и выдачу со сроком каждого его токена
// обновления на d назад — одной транзакцией.
func (w *ceremonyWorld) shiftFamily(family string, d time.Duration) {
	w.t.Helper()
	tx, err := w.pool.Begin(w.ctx)
	if err != nil {
		w.fixture("сдвиг семейства %s: транзакция не открылась: %v", family, err)
	}
	defer func() { _ = tx.Rollback(w.ctx) }()
	tag, err := tx.Exec(w.ctx, `UPDATE kaname.token_families
		   SET created_at = created_at - make_interval(secs => $2)
		 WHERE id = $1`, family, d.Seconds())
	if err != nil || tag.RowsAffected() != 1 {
		w.fixture("сдвиг рождения семейства %s на %s не лёг (строк %d): %v", family, d, tag.RowsAffected(), err)
	}
	tag, err = tx.Exec(w.ctx, `UPDATE kaname.refresh_tokens
		   SET issued_at = issued_at - make_interval(secs => $2),
		       expires_at = expires_at - make_interval(secs => $2)
		 WHERE family_id = $1`, family, d.Seconds())
	if err != nil || tag.RowsAffected() == 0 {
		w.fixture("сдвиг токенов обновления семейства %s на %s не лёг (строк %d): %v", family, d, tag.RowsAffected(), err)
	}
	if err := tx.Commit(w.ctx); err != nil {
		w.fixture("сдвиг семейства %s не закреплён: %v", family, err)
	}
}

// codeSpan — `expires_at − issued_at` записи кода семейства.
func (w *ceremonyWorld) codeSpan(family string) time.Duration {
	w.t.Helper()
	var secs float64
	if err := w.pool.QueryRow(w.ctx, `SELECT extract(epoch FROM expires_at - issued_at)::float8
		  FROM `+lineA1CodeStore+` WHERE family_id = $1`, family).Scan(&secs); err != nil {
		w.fixture("срок записи кода семейства %s не прочитан: %v", family, err)
	}
	return time.Duration(secs * float64(time.Second))
}

// firstRefreshSpan — `expires_at − token_families.created_at` единственного
// токена обновления семейства после первого обмена.
func (w *ceremonyWorld) firstRefreshSpan(family string) time.Duration {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx, `SELECT extract(epoch FROM t.expires_at - f.created_at)::float8
		  FROM kaname.refresh_tokens t JOIN kaname.token_families f ON f.id = t.family_id
		 WHERE t.family_id = $1`, family)
	if err != nil {
		w.fixture("срок токена обновления семейства %s не прочитан: %v", family, err)
	}
	defer rows.Close()
	var spans []float64
	for rows.Next() {
		var s float64
		if err := rows.Scan(&s); err != nil {
			w.fixture("срок токена обновления семейства %s: %v", family, err)
		}
		spans = append(spans, s)
	}
	if err := rows.Err(); err != nil || len(spans) != 1 {
		w.fixture("у семейства %s после первого обмена токенов обновления %d, ожидался один: %v", family, len(spans), err)
	}
	return time.Duration(spans[0] * float64(time.Second))
}

// ceremonyOnRecord — запись журнала старта церемонии, разобранная.
func (w *ceremonyWorld) ceremonyOnRecord() map[string]any {
	w.t.Helper()
	var found []map[string]any
	for _, line := range strings.Split(w.logs.String(), "\n") {
		if !strings.Contains(line, cttlCeremonyOnRecord) {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			w.fixture("запись журнала старта неразбираема: %v; %q", err, line)
		}
		if rec["msg"] == cttlCeremonyOnRecord {
			found = append(found, rec)
		}
	}
	if len(found) != 1 {
		w.fixture("записей «%s» в журнале мира %d, ожидалась одна", cttlCeremonyOnRecord, len(found))
	}
	return found[0]
}

func requireSpanWithin(t *testing.T, id, what string, got, lo, hi time.Duration) {
	t.Helper()
	if got < lo || got > hi {
		t.Errorf("%s: %s — %s, ожидалось от %s до %s", id, what, got, lo, hi)
	}
}

// requireSameRefusal — отказ тот же байт в байт, что эталон (400 invalid_grant
// на неизвестном артефакте, судимый до сдвига). Несовпадение — ошибка, а не
// остановка: близнец той же пробы исполняется и на дереве, где отказа нет.
func requireSameRefusal(t *testing.T, id, what string, got, reference *httptest.ResponseRecorder) {
	t.Helper()
	if got.Code != reference.Code || got.Body.String() != reference.Body.String() {
		t.Errorf("%s: %s: отказ отличается от эталона: %d %q против %d %q",
			id, what, got.Code, got.Body.String(), reference.Code, reference.Body.String())
	}
}

// ── KN-CTTL-09 ───────────────────────────────────────────────────────────────

// TestKNCTTL09_LifespansReachTheRecordsAndTheStartLog — величины ручек доезжают
// до журнала старта и до записей кода и токена обновления. Два мира с разными
// величинами: сборка, читающая константы, дала бы в обоих одно.
func TestKNCTTL09_LifespansReachTheRecordsAndTheStartLog(t *testing.T) {
	for _, tc := range []struct {
		id                  string
		code, refresh       time.Duration
		codeLog, refreshLog string
	}{
		{id: "KN-CTTL-09/1", code: 30 * time.Second, refresh: 2 * time.Hour, codeLog: "30s", refreshLog: "2h0m0s"},
		{id: "KN-CTTL-09/2", code: 45 * time.Second, refresh: 3 * time.Hour, codeLog: "45s", refreshLog: "3h0m0s"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			w := newCeremonyWorld(t, tc.id, "1", withCeremonyLifespans(tc.code, tc.refresh))
			w.requireGrant(grantAuthorizationCode)
			w.requireGrant(grantRefreshToken)
			w.requireAuthorizeEndpoint()

			rec := w.ceremonyOnRecord()
			if got := rec["authorization_code_lifespan"]; got != tc.codeLog {
				t.Errorf("%s: журнал старта называет срок кода %v, ожидался %s", w.id, got, tc.codeLog)
			}
			if got := rec["refresh_token_lifespan"]; got != tc.refreshLog {
				t.Errorf("%s: журнал старта называет срок семейства %v, ожидался %s", w.id, got, tc.refreshLog)
			}

			ic, family := w.issueCodeInFamily(w.ic1, lineA1R)
			requireSpanWithin(t, w.id, "срок записи кода от выдачи", w.codeSpan(family), tc.code-2*time.Second, tc.code)
			if tr := w.redeem(ic); tr.RefreshToken == "" {
				t.Fatalf("%s: обмен кода не выдал refresh_token", w.id)
			}
			requireSpanWithin(t, w.id, "срок первого токена обновления от рождения семейства",
				w.firstRefreshSpan(family), tc.refresh-2*time.Second, tc.refresh)
		})
	}
}

// ── KN-CTTL-10 ───────────────────────────────────────────────────────────────

// TestKNCTTL10_CodeOlderThanItsLifespanIsNotExchanged — код старше `code-ttl`
// отвергается тем же отказом, что неизвестный; моложе — обменивается. Возраст
// 40 с меньше потолка 60 с: отвергает срок ручки, а не потолок.
func TestKNCTTL10_CodeOlderThanItsLifespanIsNotExchanged(t *testing.T) {
	w := newCeremonyWorld(t, "KN-CTTL-10", "1", withCeremonyLifespans(30*time.Second, 2*time.Hour))
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()
	w.requireSecret(w.ic1)

	p, pFamily := w.issueCodeInFamily(w.ic1, lineA1R)
	q, qFamily := w.issueCodeInFamily(w.ic1, lineA1R)

	unknown := exchangeForm(q)
	unknown.Set("code", randomToken(32))
	reference := w.exchangeAs(w.ic1, unknown)
	requireInvalidGrant(t, w.id, "эталон: неизвестный код", reference)

	w.shiftCode(pFamily, 40*time.Second)
	requireSameRefusal(t, w.id, "код старше срока кода", w.exchangeAs(w.ic1, exchangeForm(p)), reference)

	w.shiftCode(qFamily, 20*time.Second)
	if rec := w.exchangeAs(w.ic1, exchangeForm(q)); rec.Code != http.StatusOK {
		t.Fatalf("%s: близнец: код моложе срока ответил %d, ожидалось 200; тело %q", w.id, rec.Code, rec.Body.String())
	}
}

// ── KN-CTTL-11 ───────────────────────────────────────────────────────────────

// TestKNCTTL11_FamilyOlderThanItsLifespanIsNotRotated — семейство старше
// `refresh-ttl` не оборачивается тем же отказом, что неизвестный токен
// обновления; моложе — оборачивается.
func TestKNCTTL11_FamilyOlderThanItsLifespanIsNotRotated(t *testing.T) {
	w := newCeremonyWorld(t, "KN-CTTL-11", "1", withCeremonyLifespans(time.Minute, 2*time.Hour))
	w.requireGrant(grantRefreshToken)
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	a, aFamily := w.firstPairInFamily()
	b, bFamily := w.firstPairInFamily()

	reference := w.refresh(w.ic1, randomToken(32))
	requireInvalidGrant(t, w.id, "эталон: неизвестный токен обновления", reference)

	w.shiftFamily(aFamily, 2*time.Hour+time.Minute)
	requireSameRefusal(t, w.id, "семейство старше срока семейства", w.refresh(w.ic1, a.RefreshToken), reference)

	w.shiftFamily(bFamily, time.Hour+59*time.Minute)
	w.rotate("близнец: семейство моложе срока", b)
}

// ── KN-CTTL-12 ───────────────────────────────────────────────────────────────

// TestKNCTTL12_RotationDoesNotExtendTheFamily — оборот не продлевает семейство:
// преемник семейства старше `refresh-ttl` от первой выдачи отвергнут, хотя от
// оборота прошло меньше срока; моложе — оборачивается.
func TestKNCTTL12_RotationDoesNotExtendTheFamily(t *testing.T) {
	w := newCeremonyWorld(t, "KN-CTTL-12", "1", withCeremonyLifespans(time.Minute, 2*time.Hour))
	w.requireGrant(grantRefreshToken)
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	a, aFamily := w.firstPairInFamily()
	b, bFamily := w.firstPairInFamily()
	w.shiftFamily(aFamily, time.Hour)
	w.shiftFamily(bFamily, time.Hour)
	a2 := w.rotate("оборот A через час", a)
	b2 := w.rotate("оборот B через час", b)

	reference := w.refresh(w.ic1, randomToken(32))
	requireInvalidGrant(t, w.id, "эталон: неизвестный токен обновления", reference)

	w.shiftFamily(aFamily, time.Hour+time.Minute)
	requireSameRefusal(t, w.id, "преемник A: 2 ч 1 мин от первой выдачи, 1 ч 1 мин от оборота",
		w.refresh(w.ic1, a2.RefreshToken), reference)

	w.shiftFamily(bFamily, 59*time.Minute)
	w.rotate("близнец: преемник B, 1 ч 59 мин от первой выдачи", b2)
}
