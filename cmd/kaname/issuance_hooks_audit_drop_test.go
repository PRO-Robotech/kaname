// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// issuance_hooks_audit_drop_test.go — запись журнала выдачи, которую полоса
// хука, СОБРАННАЯ корнем, не записала, видна величиной (kaname#389, возврат
// рецензента).
//
// # Признак
//
// Запись журнала идёт под пределом на вызов. Запись, не успевшая за предел,
// откатывается, а обработчик обслуживает дальше: хук отвечает, токен выдан,
// строки в журнале нет. Сигналом была одна строка журнала процесса.
//
// # Как судится
//
// Через сборку полос, а не через обёртку: обёртка, не надетая сборкой, оставила
// бы пробу обёртки зелёной. Порт журнала ЗАВИСАЕТ — отпускает его только срок
// контекста, — и проба смотрит, двинулся ли приёмник потерь, поданный сборке.
// Законный близнец — тот же сценарий с отвечающим портом: запись записана,
// потерь ноль. Дельта одна: ответил ли порт журнала.
//
// Контекст запроса несёт ОТМЕНУ через тройной предел, а не срок: будь у
// обращения к журналу только срок вызывающего, порт увидел бы отмену, а не
// истечение предела, и проба назвала бы это.
//
// Перепись видов — из набора, объявленного пакетом полосы: вид записи, до
// которого не дошёл ни один сценарий, НЕ ИЗМЕРЕН, и проба падает.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	handlerinternal "github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
)

// auditDropSpy — приёмник потерь журнала глазами пробы.
type auditDropSpy struct {
	mu      sync.Mutex
	dropped map[string]int
}

func (s *auditDropSpy) AuditDropped(eventType string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dropped == nil {
		s.dropped = map[string]int{}
	}
	s.dropped[eventType]++
}

func (s *auditDropSpy) total() (int, map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	out := map[string]int{}
	for k, v := range s.dropped {
		n += v
		out[k] = v
	}
	return n, out
}

// probeAudit — порт журнала: зависает до конца контекста либо записывает.
type probeAudit struct {
	hang bool

	mu      sync.Mutex
	emitted []string
	ended   []error
}

func (p *probeAudit) Emit(ctx context.Context, evt handlerinternal.AuditEvent) error {
	var err error
	if p.hang {
		<-ctx.Done()
		err = ctx.Err()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.emitted = append(p.emitted, evt.EventType)
	p.ended = append(p.ended, err)
	return err
}

// TestIssuanceHookLanesCountTheAuditRecordTheStoreDidNotTake — запись журнала,
// срезанная пределом на вызов, видна величиной у приёмника, поданного сборке;
// записанная — не видна.
func TestIssuanceHookLanesCountTheAuditRecordTheStoreDidNotTake(t *testing.T) {
	if credentialLanePeerTimeout <= 0 {
		t.Fatalf("предпосылка: объявленный предел на вызов обязан быть положительным, объявлено %s", credentialLanePeerTimeout)
	}
	active := domain.User{
		ID:           "usr_01abcdefghjkmnpqy",
		AccountID:    "acc_01abcdefghjkmnpqy",
		ExternalID:   capturedHumanSubject,
		Email:        "audit-drop@example.com",
		InviteStatus: domain.InviteStatusActive,
	}
	blocked := active
	blocked.InviteStatus = domain.InviteStatusBlocked
	absent := active
	absent.ExternalID = "someone-else"

	const secret = "audit-drop-hook-secret"
	scenarios := []struct {
		name       string
		lane, path string
		body       string
		user       domain.User
		wantStatus int
		wantEvent  string
	}{
		{"хук выпуска выдаёт", "token", "/iam/v1/hooks/token",
			"provider-token-hook-authorization-code.json", active, http.StatusOK, handlerinternal.AuditTokenIssued},
		{"хук выпуска отказывает заблокированному", "token", "/iam/v1/hooks/token",
			"provider-token-hook-authorization-code.json", blocked, http.StatusForbidden, handlerinternal.AuditTokenDenied},
		{"хук обновления выдаёт", "refresh", "/iam/v1/hooks/refresh",
			"provider-refresh-hook.json", active, http.StatusOK, handlerinternal.AuditRefreshIssued},
		{"хук обновления отказывает неизвестному", "refresh", "/iam/v1/hooks/refresh",
			"provider-refresh-hook.json", absent, http.StatusForbidden, handlerinternal.AuditRefreshDenied},
	}

	declared := handlerinternal.AuditEventTypes()
	if len(declared) == 0 {
		t.Fatal("предпосылка: пакет полосы не объявил ни одного вида записи журнала — судить нечего")
	}
	isDeclared := map[string]bool{}
	for _, e := range declared {
		isDeclared[e] = true
	}

	var mu sync.Mutex
	reached := map[string]bool{}
	var runs, counted int

	for _, sc := range scenarios {
		for _, hang := range []bool{true, false} {
			variant := "порт журнала отвечает"
			if hang {
				variant = "порт журнала зависает"
			}
			t.Run(sc.name+" — "+variant, func(t *testing.T) {
				t.Parallel()
				store := &laneStore{user: sc.user}
				ports := store.portsOf()
				audit := &probeAudit{hang: hang}
				ports.Audit = audit
				drops := &auditDropSpy{}

				tokenHook, refreshHook, err := buildIssuanceHooks(issuanceHookConfig{
					hookSecret:  secret,
					domain:      "api.test.cloud",
					hydraIssuer: "https://hydra.test.cloud",
				}, ports, drops, slog.New(slog.NewTextHandler(io.Discard, nil)))
				if err != nil {
					t.Fatalf("сборка полос отказала с поданным приёмником потерь: %v", err)
				}
				handler := http.Handler(tokenHook)
				if sc.lane == "refresh" {
					handler = refreshHook
				}

				// Отмена, а не срок: предел обязан прийти от сборки.
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				stop := time.AfterFunc(3*credentialLanePeerTimeout, cancel)
				defer stop.Stop()
				req := httptest.NewRequestWithContext(ctx, http.MethodPost, sc.path,
					strings.NewReader(string(capturedHookBody(t, sc.body))))
				req.Header.Set("X-Kacho-Hook-Token", secret)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)

				if w.Code != sc.wantStatus {
					t.Fatalf("полоса ответила %d %s, ожидалось %d — сценарий прошёл не той дорогой, "+
						"и запись журнала НЕ ИЗМЕРЕНА", w.Code, w.Body.String(), sc.wantStatus)
				}
				audit.mu.Lock()
				emitted, ended := append([]string(nil), audit.emitted...), append([]error(nil), audit.ended...)
				audit.mu.Unlock()
				if len(emitted) != 1 || emitted[0] != sc.wantEvent {
					t.Fatalf("полоса обратилась к журналу записями %v, ожидалась одна %q", emitted, sc.wantEvent)
				}
				if !isDeclared[emitted[0]] {
					t.Errorf("вид записи %q не объявлен пакетом полосы — клетки величины у него нет", emitted[0])
				}
				n, byType := drops.total()

				if hang {
					if !errors.Is(ended[0], context.DeadlineExceeded) {
						t.Fatalf("зависший порт журнала отпущен не пределом сборки, а %v — "+
							"у записи журнала нет своего предела на вызов", ended[0])
					}
					if n != 1 || byType[sc.wantEvent] != 1 {
						t.Errorf("запись %q срезана пределом %s и НЕ ЗАПИСАНА, полоса ответила %d, "+
							"а приёмник потерь журнала насчитал %v (всего %d, ожидалась ровно 1 по этому виду) — "+
							"потеря видна только строкой журнала процесса",
							sc.wantEvent, credentialLanePeerTimeout, w.Code, byType, n)
					}
				} else if n != 0 {
					t.Errorf("законный близнец: запись %q записана, а приёмник потерь насчитал %v", sc.wantEvent, byType)
				}

				mu.Lock()
				runs++
				reached[sc.wantEvent] = true
				if hang && n == 1 {
					counted++
				}
				mu.Unlock()
			})
		}
	}

	t.Cleanup(func() {
		missing := []string{}
		for _, e := range declared {
			if !reached[e] {
				missing = append(missing, e)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			t.Errorf("виды записей %v не достигнуты ни одним сценарием — их потеря НЕ ИЗМЕРЕНА", missing)
		}
		t.Logf("перепись: видов объявлено %d, достигнуто %d · прогонов %d (зависаний %d, "+
			"сосчитано потерь %d) · предел на вызов %s",
			len(declared), len(reached), runs, len(scenarios), counted, credentialLanePeerTimeout)
	})
}

// TestIssuanceHooksAssemblyRefusesWithoutAnAuditDropObserver — сборка без
// приёмника потерь журнала отказывает; законный близнец с приёмником строится.
func TestIssuanceHooksAssemblyRefusesWithoutAnAuditDropObserver(t *testing.T) {
	store := &laneStore{}
	cfg := issuanceHookConfig{hookSecret: "s", domain: "api.test.cloud", hydraIssuer: "https://hydra.test.cloud"}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	if _, _, err := buildIssuanceHooks(cfg, store.portsOf(), nil, quiet); !errors.Is(err, handlerinternal.ErrAuditDropObserverMissing) {
		t.Fatalf("сборка полос без приёмника потерь журнала вернула %v, ожидался отказ %v", err, handlerinternal.ErrAuditDropObserverMissing)
	}
	if _, _, err := buildIssuanceHooks(cfg, store.portsOf(), &auditDropSpy{}, quiet); err != nil {
		t.Fatalf("законный близнец: с приёмником сборка обязана строиться, err=%v", err)
	}
}
