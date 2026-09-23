// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// issuance_hooks_cutoff_deadline_test.go — чтение отсечки отзыва-всех на обеих
// полосах хука, СОБРАННЫХ корнем, идёт под объявленным пределом времени на
// вызов — тем же, что у токен-эндпоинта (задача kaname#379).
//
// # Почему через сборку, а не через обёртку
//
// Проба, зовущая обёртку напрямую, утверждает, что обёртка ставит срок, и молчит
// о том, ставит ли её сборка. Снятая из сборки обёртка оставила бы такую пробу
// зелёной. Здесь читатель подаётся СБОРКЕ полос, запрос идёт в собранный хук, и
// срок смотрится у читателя — там, куда он приходит на живом пути.
//
// # Чем проба защищена от собственной снисходительности
//
// Полоса, не дошедшая до чтения отсечки, — не «срок есть», а «не измерено»:
// проба называет её и падает. Контекст запроса — без срока: будь предел у
// вызывающего, а не у сборки, его здесь не было бы вовсе.
//
// Тела запросов — дословные записи поставщика из `internal/handler/iamhooks/
// testdata`: полоса обязана дойти до чтения отсечки на том, что поставщик
// действительно присылает, а не на форме, придуманной под эту пробу.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	handlerinternal "github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// capturedHookBodies — каталог дословных записей тел поставщика.
const capturedHookBodies = "../../internal/handler/iamhooks/testdata"

// deadlineHookSubject — субъект записанной интерактивной сессии.
const deadlineHookSubject = "cap-user-external-sub"

// cutoffReadCall — одно чтение отсечки глазами читателя: был ли у контекста
// срок и сколько до него оставалось.
type cutoffReadCall struct {
	hadDeadline bool
	remaining   time.Duration
}

// recordingCutoffReader — читатель отсечки, запоминающий срок каждого вызова.
// Об исходе он не утверждает ничего: отсечки нет, и полоса выдаёт.
type recordingCutoffReader struct {
	mu    sync.Mutex
	calls []cutoffReadCall
}

func (r *recordingCutoffReader) UserRevokedBefore(ctx context.Context, _ string) (time.Time, bool, error) {
	dl, had := ctx.Deadline()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, cutoffReadCall{hadDeadline: had, remaining: time.Until(dl)})
	return time.Time{}, false, nil
}

// take отдаёт накопленные вызовы и начинает счёт заново.
func (r *recordingCutoffReader) take() []cutoffReadCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.calls
	r.calls = nil
	return out
}

// deadlineHookUsers — строка человека записанной сессии, в любом состоянии,
// как порт её отдаёт.
type deadlineHookUsers struct {
	user domain.User
}

func (u deadlineHookUsers) FindByExternalID(_ context.Context, ext domain.ExternalSubject) ([]domain.User, error) {
	if ext != u.user.ExternalID {
		return nil, nil
	}
	return []domain.User{u.user}, nil
}

func (u deadlineHookUsers) GetByID(_ context.Context, id domain.UserID) (domain.User, error) {
	if id != u.user.ID {
		return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "no user %s", id)
	}
	return u.user, nil
}

// discardAudit — приёмник аудита; предмет пробы — срок чтения, не журнал.
type discardAudit struct{}

func (discardAudit) Emit(context.Context, handlerinternal.AuditEvent) error { return nil }

func capturedHookBody(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(capturedHookBodies, name))
	if err != nil {
		t.Fatalf("дословная запись тела поставщика %s обязана быть на месте: %v", name, err)
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("запись %s не разбирается как JSON: %v", name, err)
	}
	return raw
}

// TestIssuanceHookLanesReadTheCutoffUnderTheDeclaredLimit — обе полосы хука,
// собранные корнем, читают отсечку под объявленным пределом на вызов.
func TestIssuanceHookLanesReadTheCutoffUnderTheDeclaredLimit(t *testing.T) {
	if issuancePeerTimeout <= 0 {
		t.Fatalf("предпосылка: объявленный предел на вызов обязан быть положительным, объявлено %s", issuancePeerTimeout)
	}
	users := deadlineHookUsers{user: domain.User{
		ID:           "usr_01abcdefghjkmnpqx",
		AccountID:    "acc_01abcdefghjkmnpqx",
		ExternalID:   deadlineHookSubject,
		Email:        "deadline@example.com",
		InviteStatus: domain.InviteStatusActive,
	}}
	enricher := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "api.test.cloud", HydraIssuer: "https://hydra.test.cloud"},
		users,
	)
	reader := &recordingCutoffReader{}
	const secret = "deadline-hook-secret"
	tokenHook, refreshHook := buildIssuanceHooks(issuanceHookConfig{
		hookSecret:  secret,
		domain:      "api.test.cloud",
		hydraIssuer: "https://hydra.test.cloud",
	}, issuanceHookPorts{
		users:    users,
		enricher: enricher,
		cutoffs:  reader,
		audit:    discardAudit{},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	lanes := []struct {
		name    string
		handler http.Handler
		path    string
		body    string
	}{
		{"хук выпуска", tokenHook, "/iam/v1/hooks/token", "provider-token-hook-authorization-code.json"},
		{"хук обновления", refreshHook, "/iam/v1/hooks/refresh", "provider-refresh-hook.json"},
	}

	var reached, bounded int
	for _, l := range lanes {
		// Контекст запроса — БЕЗ срока: httptest строит его от фонового.
		req := httptest.NewRequest(http.MethodPost, l.path, strings.NewReader(string(capturedHookBody(t, l.body))))
		req.Header.Set("X-Kacho-Hook-Token", secret)
		if _, had := req.Context().Deadline(); had {
			t.Fatalf("предпосылка: контекст запроса пробы не несёт срока, а у %q он есть", l.name)
		}
		w := httptest.NewRecorder()
		l.handler.ServeHTTP(w, req)

		calls := reader.take()
		if len(calls) == 0 {
			t.Fatalf("%s: полоса не дошла до чтения отсечки (ответ %d %s) — предел НЕ ИЗМЕРЕН, это не зелёное",
				l.name, w.Code, w.Body.String())
		}
		reached++
		lane := 0
		for i, c := range calls {
			if !c.hadDeadline {
				t.Errorf("%s: чтение отсечки #%d идёт без своего предела времени — неотвечающее хранилище "+
					"держит обработчик сколько угодно", l.name, i+1)
				continue
			}
			if c.remaining <= 0 || c.remaining > issuancePeerTimeout {
				t.Errorf("%s: чтение отсечки #%d несёт срок %s, а объявленный предел на вызов — %s",
					l.name, i+1, c.remaining, issuancePeerTimeout)
				continue
			}
			lane++
		}
		if lane == len(calls) {
			bounded++
		}
	}
	t.Logf("перепись: полос хука собрано %d · дошли до чтения отсечки %d · читают под пределом %s — %d",
		len(lanes), reached, issuancePeerTimeout, bounded)
}
