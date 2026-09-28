// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// issuance_hooks_store_deadline_test.go — КАЖДОЕ обращение обеих полос хука,
// СОБРАННЫХ корнем, к своей базе идёт под объявленным пределом времени на
// вызов (задача kaname#389; чтение отсечки отзыва-всех — kaname#379).
//
// # Почему через сборку, а не через обёртку
//
// Проба, зовущая обёртку напрямую, утверждает, что обёртка ставит срок, и молчит
// о том, ставит ли её сборка. Снятая из сборки обёртка оставила бы такую пробу
// зелёной. Здесь сборке полос подаются порты-записыватели, запросы идут в
// собранные хуки, и срок смотрится у порта — там, где на живом пути стоит база.
//
// # Перепись — из исполненного, а не выписанным перечнем
//
// Обращения не перечислены здесь заранее: их записывают сами порты, и проба
// судит всё, что записано. Выписанный перечень молчал бы об обращении, которого
// в нём нет, — а это ровно то обращение, что пришло с новой веткой полосы.
// Пустая перепись — не «сроки есть», а «не измерено», и проба падает. Порт
// сборки, до которого не дошёл ни один сценарий, тоже не измерен: перечень
// портов берётся из типа входа сборки, а не из этого файла.
//
// # Чем проба защищена от собственной снисходительности
//
// Контекст запроса — без срока: будь предел у вызывающего, а не у сборки, его
// здесь не было бы вовсе. Сценарий, ответивший не 200, прошёл не той дорогой,
// ради которой заведён, и проба падает, а не засчитывает его. Тела запросов —
// дословные записи поставщика из `internal/handler/iamhooks/testdata`.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/servicecontract"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	handlerinternal "github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
)

// capturedHookBodies — каталог дословных записей тел поставщика.
const capturedHookBodies = "../../internal/handler/iamhooks/testdata"

// Субъекты записанных тел: интерактивной сессии и машинного клиента.
const (
	capturedHumanSubject  = "cap-user-external-sub"
	capturedMachineClient = "cap-machine"
)

// storeCall — одно обращение полосы к базе глазами порта.
type storeCall struct {
	port, method string
	hadDeadline  bool
	remaining    time.Duration
}

func (c storeCall) name() string { return c.port + "." + c.method }

// laneStore — база полос, как её видят порты: строка человека, учётка за
// ключом и персональный токен. Какая из строк есть, решает сценарий.
type laneStore struct {
	mu    sync.Mutex
	calls []storeCall

	user      domain.User
	saClient  *domain.ServiceAccountOAuthClient
	sa        domain.ServiceAccount
	userToken *domain.UserOAuthClient
}

func (s *laneStore) record(ctx context.Context, port, method string) {
	dl, had := ctx.Deadline()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, storeCall{port: port, method: method, hadDeadline: had, remaining: time.Until(dl)})
}

func (s *laneStore) take() []storeCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.calls
	s.calls = nil
	return out
}

// Имена портов — имена полей входа сборки: перепись портов сверяется с типом.
type storeUsers struct{ *laneStore }

func (s storeUsers) FindByExternalID(ctx context.Context, ext domain.ExternalSubject) ([]domain.User, error) {
	s.record(ctx, "Users", "FindByExternalID")
	if ext != s.user.ExternalID {
		return nil, nil
	}
	return []domain.User{s.user}, nil
}

func (s storeUsers) GetByID(ctx context.Context, id domain.UserID) (domain.User, error) {
	s.record(ctx, "Users", "GetByID")
	if id != s.user.ID {
		return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "no user %s", id)
	}
	return s.user, nil
}

type storeServiceAccounts struct{ *laneStore }

func (s storeServiceAccounts) LookupByOAuthClientID(ctx context.Context, id domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	s.record(ctx, "ServiceAccounts", "LookupByOAuthClientID")
	if s.saClient == nil || s.saClient.OAuthClientID != id {
		return domain.ServiceAccountOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no sa client %s", id)
	}
	return *s.saClient, nil
}

func (s storeServiceAccounts) GetServiceAccount(ctx context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	s.record(ctx, "ServiceAccounts", "GetServiceAccount")
	if id != s.sa.ID {
		return domain.ServiceAccount{}, iamerr.Wrapf(iamerr.ErrNotFound, "no sa %s", id)
	}
	return s.sa, nil
}

func (s storeServiceAccounts) FindByExternalSubject(ctx context.Context, _, _ string) (domain.ServiceAccountOAuthClient, error) {
	s.record(ctx, "ServiceAccounts", "FindByExternalSubject")
	return domain.ServiceAccountOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no trusted subject")
}

type storeUserTokens struct{ *laneStore }

func (s storeUserTokens) LookupByOAuthClientID(ctx context.Context, id domain.OAuthClientID) (domain.UserOAuthClient, error) {
	s.record(ctx, "UserTokens", "LookupByOAuthClientID")
	if s.userToken == nil || s.userToken.OAuthClientID != id {
		return domain.UserOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "no user token %s", id)
	}
	return *s.userToken, nil
}

func (s storeUserTokens) GetUser(ctx context.Context, id domain.UserID) (domain.User, error) {
	s.record(ctx, "UserTokens", "GetUser")
	if id != s.user.ID {
		return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "no user %s", id)
	}
	return s.user, nil
}

type storeCutoffs struct{ *laneStore }

func (s storeCutoffs) UserRevokedBefore(ctx context.Context, _ string) (time.Time, bool, error) {
	s.record(ctx, "Cutoffs", "UserRevokedBefore")
	return time.Time{}, false, nil
}

type storeAudit struct{ *laneStore }

func (s storeAudit) Emit(ctx context.Context, _ handlerinternal.AuditEvent) error {
	s.record(ctx, "Audit", "Emit")
	return nil
}

// portsOf — вход сборки, у которого каждый порт пишет в эту базу.
func (s *laneStore) portsOf() handlerinternal.IssuancePorts {
	return handlerinternal.IssuancePorts{
		Users:           storeUsers{s},
		ServiceAccounts: storeServiceAccounts{s},
		UserTokens:      storeUserTokens{s},
		Cutoffs:         storeCutoffs{s},
		Audit:           storeAudit{s},
	}
}

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

// TestIssuanceHookLanesCallTheStoreUnderTheDeclaredLimit — всякое обращение
// обеих полос хука, собранных корнем, к базе несёт срок не больше объявленного.
func TestIssuanceHookLanesCallTheStoreUnderTheDeclaredLimit(t *testing.T) {
	if credentialLanePeerTimeout <= 0 {
		t.Fatalf("предпосылка: объявленный предел на вызов обязан быть положительным, объявлено %s", credentialLanePeerTimeout)
	}
	human := domain.User{
		ID:           "usr_01abcdefghjkmnpqx",
		AccountID:    "acc_01abcdefghjkmnpqx",
		ExternalID:   capturedHumanSubject,
		Email:        "deadline@example.com",
		InviteStatus: domain.InviteStatusActive,
	}
	const (
		secret    = "deadline-hook-secret"
		tokenPath = "/iam/v1/hooks/token"
	)
	scenarios := []struct {
		name  string
		lane  string
		path  string
		body  string
		state func(*laneStore)
	}{
		{"хук выпуска, интерактивная сессия", "token", tokenPath,
			"provider-token-hook-authorization-code.json", func(*laneStore) {}},
		{"хук выпуска, ключ служебной учётки", "token", tokenPath,
			"provider-token-hook-client-credentials.json", func(s *laneStore) {
				s.saClient = &domain.ServiceAccountOAuthClient{ID: "sak_deadline", SvaID: "sva_deadline",
					OAuthClientID: capturedMachineClient}
				s.sa = domain.ServiceAccount{ID: "sva_deadline", AccountID: human.AccountID, Enabled: true}
			}},
		{"хук выпуска, персональный токен", "token", tokenPath,
			"provider-token-hook-client-credentials.json", func(s *laneStore) {
				s.userToken = &domain.UserOAuthClient{ID: "uoc_deadline", UserID: human.ID,
					OAuthClientID: capturedMachineClient, CreatedAt: time.Now().Add(-time.Hour)}
			}},
		{"хук обновления", "refresh", "/iam/v1/hooks/refresh",
			"provider-refresh-hook.json", func(*laneStore) {}},
	}

	reachedPorts := map[string]bool{}
	executed := map[string]int{}
	var total, bounded int
	for _, sc := range scenarios {
		store := &laneStore{user: human}
		sc.state(store)
		tokenHook, refreshHook, err := buildIssuanceHooks(issuanceHookConfig{
			hookSecret: secret,
			domain:     "api.test.cloud",
		}, store.portsOf(), &auditDropSpy{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatalf("%s: сборка полос отказала с объявленным пределом %s: %v", sc.name, credentialLanePeerTimeout, err)
		}
		handler := http.Handler(tokenHook)
		if sc.lane == "refresh" {
			handler = refreshHook
		}

		// Контекст запроса — БЕЗ срока: httptest строит его от фонового.
		req := httptest.NewRequest(http.MethodPost, sc.path, strings.NewReader(string(capturedHookBody(t, sc.body))))
		req.Header.Set("X-Kacho-Hook-Token", secret)
		if _, had := req.Context().Deadline(); had {
			t.Fatalf("предпосылка: контекст запроса пробы не несёт срока, а у %q он есть", sc.name)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: полоса ответила %d %s — сценарий прошёл не той дорогой, ради которой заведён, "+
				"и его обращения НЕ ИЗМЕРЕНЫ", sc.name, w.Code, w.Body.String())
		}

		calls := store.take()
		if len(calls) == 0 {
			t.Fatalf("%s: полоса не обратилась к базе ни разу — предел НЕ ИЗМЕРЕН, это не зелёное", sc.name)
		}
		for i, c := range calls {
			total++
			executed[c.name()]++
			reachedPorts[c.port] = true
			if !c.hadDeadline {
				t.Errorf("%s: обращение #%d %s идёт без своего предела времени — неотвечающая база "+
					"держит обработчик столько, сколько ждёт поставщик", sc.name, i+1, c.name())
				continue
			}
			if c.remaining <= 0 || c.remaining > credentialLanePeerTimeout {
				t.Errorf("%s: обращение #%d %s несёт срок %s, а объявленный предел на вызов — %s",
					sc.name, i+1, c.name(), c.remaining, credentialLanePeerTimeout)
				continue
			}
			bounded++
		}
	}

	portType := reflect.TypeOf(handlerinternal.IssuancePorts{})
	if portType.NumField() == 0 {
		t.Fatal("предпосылка: у входа сборки полос нет ни одного порта — судить нечего")
	}
	for i := 0; i < portType.NumField(); i++ {
		if name := portType.Field(i).Name; !reachedPorts[name] {
			t.Errorf("порт сборки %s не достигнут ни одним сценарием — его обращения НЕ ИЗМЕРЕНЫ", name)
		}
	}

	names := make([]string, 0, len(executed))
	for n, k := range executed {
		names = append(names, n+"×"+strconv.Itoa(k))
	}
	sort.Strings(names)
	t.Logf("перепись: сценариев %d · портов сборки %d, достигнуто %d · обращений к базе %d, под пределом %s — %d · %s",
		len(scenarios), portType.NumField(), len(reachedPorts), total, credentialLanePeerTimeout, bounded,
		strings.Join(names, ", "))
}

// TestIssuanceLanesAssemblyRefusalStopsTheStart — сборка полос без обработчика
// (и без отказа) не поднимает поверхность под внешним поставщиком с объявленным
// адресом: построитель отказывает, и корень не стартует. Законный близнец — та
// же посадка с собранным обработчиком: поверхность строится. Отказ сборки,
// поданный значением, и его причину в отказе старта держит
// `TestIssuanceLanesAssemblyRefusalReachesTheStartWithItsCause` (kaname#440).
func TestIssuanceLanesAssemblyRefusalStopsTheStart(t *testing.T) {
	cfg := roadCfg(config.IdentityProviderExternal, "9097")
	cfg.AuthN.HooksHTTPEndpoint = "tcp://0.0.0.0:9092"
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}

	_, err := hooksLaneSurface(cfg, servicecontract.ModeProduction, quietLogger(), tlsCfg,
		func() (http.Handler, error) { return nil, nil })
	if err == nil {
		t.Fatal("под внешним поставщиком с объявленным адресом поверхность вебхуков построилась без " +
			"обработчика — отказ сборки полос выдачи не остановил бы старт")
	}

	desc, err := hooksLaneSurface(cfg, servicecontract.ModeProduction, quietLogger(), tlsCfg,
		func() (http.Handler, error) { return http.NotFoundHandler(), nil })
	if err != nil || !desc.Enabled() {
		t.Fatalf("законный близнец: с обработчиком поверхность обязана строиться и подниматься, err=%v", err)
	}
}

// PersonMarks — строк людей в мире дублёра нет: предмет этих проб — отсечка и
// предел, а не отметка адреса (kaname#456; её держат пробы полос над базой).
func (storeCutoffs) PersonMarks(context.Context, []string) (map[string]bool, error) {
	return map[string]bool{}, nil
}
