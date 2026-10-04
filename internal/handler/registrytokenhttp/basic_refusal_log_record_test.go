// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package registrytokenhttp_test

// basic_refusal_log_record_test.go — отказ базового секрета на полосе реестра —
// ОДНА запись журнала ОБЪЯВЛЕННОГО уровня с причиной, и ни предъявленной
// строки, ни имени (задача kaname#390).
//
// Уровни — таблица службы (`docs/engineering/components/32-observability.md`):
// отклонённое предъявление — WARN; отказ без названной причины — нарушение
// контракта авторитета, то есть наш дефект, — ERROR. Тело ответа побайтово то
// же, что у всякого отказа аутентификации.

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	registrytokenuc "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registry_token"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/registrytokenhttp"
)

func TestBasicRefusal_OneRecordOfTheDeclaredLevelNamingTheReason(t *testing.T) {
	const user, presented = "soc_0000000000000log1", "kacho-presented-string-0000000000"
	type branch struct {
		name      string
		err       error
		wantLevel string
		wantCause string
	}
	var branches []branch
	for _, r := range domain.BasicCredentialRefusalReasons() {
		branches = append(branches, branch{string(r),
			errors.Join(registrytokenuc.ErrUnauthenticated, domain.RefuseBasicCredential(r)),
			slog.LevelWarn.String(), string(r)})
	}
	branches = append(branches, branch{"причина не названа",
		errors.Join(registrytokenuc.ErrUnauthenticated, domain.ErrBasicCredentialRefused),
		slog.LevelError.String(), ""})

	// Тело эталона — отказ аутентификации без причины.
	plainBody := func() string {
		h := registrytokenhttp.NewTokenHandler(registrytokenhttp.Config{
			Realm: "https://api.kacho.local/iam/token", DefaultService: "registry.kacho.local",
		}, issuerStub{err: registrytokenuc.ErrUnauthenticated})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local", nil)
		req.SetBasicAuth(user, presented)
		h.ServeHTTP(rec, req)
		return rec.Body.String()
	}()

	for _, b := range branches {
		t.Run(b.name, func(t *testing.T) {
			var log bytes.Buffer
			h := registrytokenhttp.NewTokenHandler(registrytokenhttp.Config{
				Realm: "https://api.kacho.local/iam/token", DefaultService: "registry.kacho.local",
			}, issuerStub{err: b.err}).WithLogger(slog.New(slog.NewJSONHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug})))
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local", nil)
			req.SetBasicAuth(user, presented)
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized || rec.Body.String() != plainBody {
				t.Fatalf("наружу не прежний отказ: %d %q", rec.Code, rec.Body.String())
			}
			var lines []string
			for _, l := range strings.Split(strings.TrimSpace(log.String()), "\n") {
				if l != "" {
					lines = append(lines, l)
				}
			}
			if len(lines) != 1 {
				t.Fatalf("записей на один отказ %d, а не одна: %q", len(lines), log.String())
			}
			var rec0 map[string]any
			if err := json.Unmarshal([]byte(lines[0]), &rec0); err != nil {
				t.Fatalf("запись не разбирается: %v", err)
			}
			if rec0[slog.LevelKey] != b.wantLevel {
				t.Errorf("уровень %v, объявлен %s: %s", rec0[slog.LevelKey], b.wantLevel, lines[0])
			}
			if b.wantCause != "" && !strings.Contains(lines[0], b.wantCause) {
				t.Errorf("запись не называет причину %q: %s", b.wantCause, lines[0])
			}
			for _, leak := range []string{presented, user} {
				if strings.Contains(log.String(), leak) {
					t.Errorf("в журнале предъявленное %q: %s", leak, lines[0])
				}
			}
		})
	}
}
