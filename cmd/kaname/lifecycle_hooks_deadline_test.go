// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// lifecycle_hooks_deadline_test.go — хуки заведения и восстановления человека,
// СОБРАННЫЕ корнем, отвечают отказом в пределах объявленной величины, когда их
// use-case не отвечает (задача kaname#441; полосы выдачи — kaname#389).
//
// # Почему через сборку, а не через обёртку
//
// Проба, зовущая обёртку напрямую, утверждает, что обёртка ставит срок, и молчит
// о том, ставит ли её сборка. Здесь сборке хуков подаются свои порты, запросы
// идут в собранные хуки, и срок смотрится у порта — там, где на живом пути стоит
// use-case.
//
// # Чем проба защищена от собственной снисходительности
//
// Контекст запроса — без срока: будь предел у вызывающего, а не у сборки, его
// здесь не было бы вовсе. Зависший порт ждёт, пока его не отпустит срок либо
// сама проба, и отпускание пробой — не зелёное: оно значит, что хук ответил бы
// поставщику только по его собственному сроку. Законный близнец — тот же хук с
// отвечающим портом: ответ успеха, под тем же пределом. Порт сборки, до
// которого не дошёл ни один сценарий, не измерен: перечень портов берётся из
// типа входа сборки, а не из этого файла.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	handlerinternal "github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
)

// lifecycleSlack — запас сверх объявленного предела на ответ обработчика после
// того, как срок оборвал обращение: запись ответа и планировщик под -race.
const lifecycleSlack = time.Second

// lifecycleCall — одно обращение хука к своему use-case глазами порта.
type lifecycleCall struct {
	port        string
	hadDeadline bool
	remaining   time.Duration
	endedBy     error
}

// lifecyclePort — порт хука: отвечает сразу либо висит, пока его не отпустит
// срок контекста или проба.
type lifecyclePort struct {
	name    string
	hang    bool
	release chan struct{}

	mu    sync.Mutex
	calls []lifecycleCall
}

func (p *lifecyclePort) serve(ctx context.Context) error {
	dl, had := ctx.Deadline()
	c := lifecycleCall{port: p.name, hadDeadline: had, remaining: time.Until(dl)}
	var out error
	if p.hang {
		select {
		case <-ctx.Done():
			out = ctx.Err()
		case <-p.release:
			out = errors.New("порт отпущен пробой, а не сроком")
		}
	}
	c.endedBy = out
	p.mu.Lock()
	p.calls = append(p.calls, c)
	p.mu.Unlock()
	return out
}

func (p *lifecyclePort) taken() []lifecycleCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]lifecycleCall(nil), p.calls...)
}

type lifecycleProvisioner struct{ *lifecyclePort }

func (p lifecycleProvisioner) Provision(ctx context.Context, _ handlerinternal.ProvisionInput) error {
	return p.serve(ctx)
}

type lifecycleRecovery struct{ *lifecyclePort }

func (p lifecycleRecovery) CompleteRecovery(ctx context.Context, _ handlerinternal.RecoveryInput) error {
	return p.serve(ctx)
}

// TestLifecycleHooksAnswerAHangingPortWithinTheDeclaredLimit — каждый хук
// заведения и восстановления, собранный корнем, на зависшем use-case отвечает
// отказом не позже объявленного предела, а на отвечающем — успехом под тем же
// пределом.
func TestLifecycleHooksAnswerAHangingPortWithinTheDeclaredLimit(t *testing.T) {
	if credentialLanePeerTimeout <= 0 {
		t.Fatalf("предпосылка: объявленный предел на вызов обязан быть положительным, объявлено %s", credentialLanePeerTimeout)
	}
	const secret = "lifecycle-hook-secret"
	scenarios := []struct {
		name, port, path, body string
		hang                   bool
		wantCode               int
	}{
		{"заведение, зависший use-case", "Provisioner", "/iam/v1/hooks/provision",
			`{"external_id":"ext-lifecycle","email":"lifecycle@example.com","display_name":"L"}`, true, http.StatusInternalServerError},
		{"заведение, законный близнец: use-case отвечает", "Provisioner", "/iam/v1/hooks/provision",
			`{"external_id":"ext-lifecycle","email":"lifecycle@example.com","display_name":"L"}`, false, http.StatusOK},
		{"восстановление, зависший use-case", "Recovery", "/iam/v1/hooks/recovery",
			`{"external_id":"ext-lifecycle","email":"lifecycle@example.com","recovery_jti":"jti-lifecycle"}`, true, http.StatusInternalServerError},
		{"восстановление, законный близнец: use-case отвечает", "Recovery", "/iam/v1/hooks/recovery",
			`{"external_id":"ext-lifecycle","email":"lifecycle@example.com","recovery_jti":"jti-lifecycle"}`, false, http.StatusNoContent},
	}

	var (
		mu      sync.Mutex
		reached = map[string]bool{}
		bounded int
	)
	t.Run("сценарии", func(t *testing.T) {
		for _, sc := range scenarios {
			t.Run(sc.name, func(t *testing.T) {
				t.Parallel()
				port := &lifecyclePort{name: sc.port, hang: sc.hang, release: make(chan struct{})}
				provision, recovery, err := buildLifecycleHooks(secret, handlerinternal.LifecyclePorts{
					Provisioner: lifecycleProvisioner{port},
					Recovery:    lifecycleRecovery{port},
				}, quietLogger())
				if err != nil {
					t.Fatalf("сборка хуков отказала с объявленным пределом %s: %v", credentialLanePeerTimeout, err)
				}
				handler := http.Handler(provision)
				if sc.port == "Recovery" {
					handler = recovery
				}

				// Контекст запроса — БЕЗ срока: httptest строит его от фонового.
				req := httptest.NewRequest(http.MethodPost, sc.path, strings.NewReader(sc.body))
				req.Header.Set("X-Kacho-Hook-Token", secret)
				if _, had := req.Context().Deadline(); had {
					t.Fatalf("предпосылка: контекст запроса пробы не несёт срока, а у %q он есть", sc.name)
				}
				w := httptest.NewRecorder()
				done := make(chan struct{})
				start := time.Now()
				go func() {
					defer close(done)
					handler.ServeHTTP(w, req)
				}()
				budget := credentialLanePeerTimeout + lifecycleSlack
				select {
				case <-done:
				case <-time.After(budget):
					close(port.release)
					<-done
					t.Fatalf("%s: хук не ответил за %s (объявленный предел %s + запас %s) — зависший use-case "+
						"держит обработчик столько, сколько ждёт поставщик; порт отпущен пробой",
						sc.name, budget, credentialLanePeerTimeout, lifecycleSlack)
				}
				elapsed := time.Since(start)

				if w.Code != sc.wantCode {
					t.Fatalf("%s: хук ответил %d %s за %s, ожидался %d", sc.name, w.Code, w.Body.String(), elapsed, sc.wantCode)
				}
				calls := port.taken()
				if len(calls) != 1 {
					t.Fatalf("%s: хук обратился к порту %d раз вместо одного — предел НЕ ИЗМЕРЕН", sc.name, len(calls))
				}
				c := calls[0]
				if c.port != sc.port {
					t.Fatalf("%s: хук позвал порт %s, а сценарий заведён для %s", sc.name, c.port, sc.port)
				}
				if !c.hadDeadline {
					t.Fatalf("%s: обращение к порту %s идёт без своего предела времени", sc.name, c.port)
				}
				if c.remaining <= 0 || c.remaining > credentialLanePeerTimeout {
					t.Fatalf("%s: обращение к порту %s несёт срок %s, а объявленный предел — %s",
						sc.name, c.port, c.remaining, credentialLanePeerTimeout)
				}
				if sc.hang && !errors.Is(c.endedBy, context.DeadlineExceeded) {
					t.Fatalf("%s: зависшее обращение оборвано не сроком: %v", sc.name, c.endedBy)
				}
				mu.Lock()
				reached[c.port] = true
				bounded++
				mu.Unlock()
				t.Logf("%s: ответ %d за %s, срок у порта %s", sc.name, w.Code, elapsed.Round(time.Millisecond),
					c.remaining.Round(time.Millisecond))
			})
		}
	})

	portType := reflect.TypeOf(handlerinternal.LifecyclePorts{})
	if portType.NumField() == 0 {
		t.Fatal("предпосылка: у входа сборки хуков нет ни одного порта — судить нечего")
	}
	for i := 0; i < portType.NumField(); i++ {
		if name := portType.Field(i).Name; !reached[name] {
			t.Errorf("порт сборки %s не достигнут ни одним сценарием — его предел НЕ ИЗМЕРЕН", name)
		}
	}
	names := make([]string, 0, len(reached))
	for n := range reached {
		names = append(names, n)
	}
	sort.Strings(names)
	t.Logf("перепись: сценариев %d · портов сборки %d, достигнуто %d (%s) · под пределом %s — %d",
		len(scenarios), portType.NumField(), len(reached), strings.Join(names, ", "), credentialLanePeerTimeout, bounded)
}
