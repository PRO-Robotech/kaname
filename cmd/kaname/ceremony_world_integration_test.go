// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_world_integration_test.go — драйвер полосы RED под-фазы LINE-A-1
// (приёмка `sub-phase-LINE-A-1-own-authorization-endpoint-and-code-acceptance.md`,
// отпечаток b755886f…, задача PRO-Robotech/kacho#2721): церемония OAuth 2.1
// `authorization_code` нашими силами.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕТЫРЕ СОСТОЯНИЯ ПРОБЫ, И ПОРЯДОК ИХ НЕСУЩИЙ
//
// Каждая проба сценария проходит три ступени, и отказ на каждой называет себя
// своим словом — по нему прогон и считается:
//
//  1. МИР (фикстура). База пробы — клон цепи миграций дерева; человек, его
//     сессия и интерактивные клиенты заведены посевом и ПРОЧИТАНЫ обратно
//     продуктовыми хранилищами; поверхность выдачи собрана теми же вызовами,
//     что корень (`serve.go`), и её состав сверен с корнем разбором исходника;
//     соседний эндпоинт этой поверхности ОТВЕЧАЕТ. Отказ здесь —
//     «НЕ-ВЫПОЛНИЛОСЬ(фикстура)»: сломан вопрос, а не ответ.
//  2. ВОЗМОЖНОСТЬ. Спрашивается, объявил ли испытуемый нужное: смонтирован ли
//     путь, принимает ли токен-эндпоинт вид выдачи. «Нет» — положительное
//     определение («маршрута нет», «вид выдачи вне перечня») и даёт
//     «ЧЕСТНЫЙ-КРАСНЫЙ». Ответ, который нельзя разобрать, — это
//     «НЕ-ВЫПОЛНИЛОСЬ(проба возможности)», а не «нет».
//  3. ПРЕДМЕТ. Утверждения сценария. Отказ здесь несёт только номер сценария.
//
// Проба возможности стоит ПОСЛЕ всей проверки мира: обратный порядок дал бы
// сломанной фикстуре право выдать себя за отсутствующую возможность.
//
// Шаги посева, которые выразимы только ВМЕСТЕ с предметом (проверочное
// значение секрета клиента, срок записи кода), исполняются после ступени 2 и
// отказывают словом «НЕ-ВЫПОЛНИЛОСЬ(фикстура)» — за отсутствие возможности они
// себя выдать не могут: к ним доходит только проба, у которой возможность есть.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПОВЕРХНОСТЬ СОБРАНА ЗДЕСЬ, А ЕЁ СОСТАВ СВЕРЕН С КОРНЕМ
//
// Поверхность выдачи собирается в теле `runServe`, отдельного построителя у неё
// нет. Проба собирает её теми же вызовами (`registrytokenwire.Build` +
// `buildClientTokenEndpoint` + монтаж), как это делает соседний образец
// `serve_client_token_wiring_test.go`, — и ДОБАВЛЯЕТ то, чего у образца нет:
// перепись того, как корень пользуется муксом поверхности, выводится разбором
// `serve.go` и сверяется с перечнем, который собирает проба. Реализация,
// смонтировавшая путь церемонии в корне, меняет перепись — и проба отказывает
// словом «фикстура», пока её сборка не повторит корень. Молча разойтись две
// сборки не могут.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/corelib/tokenpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	sessionrevapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/session_revocations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
	"github.com/PRO-Robotech/kaname/internal/handler/registrytokenhttp"
	"github.com/PRO-Robotech/kaname/internal/handler/tokenintrospecthttp"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	"github.com/PRO-Robotech/kaname/internal/registrytokenwire"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// Координаты церемонии, объявленные приёмкой (§5, §1).
const (
	lineA1AuthorizePath = "/iam/v1/authorize"
	lineA1DiscoveryPath = "/.well-known/oauth-authorization-server"

	grantAuthorizationCode = "authorization_code"
	grantRefreshToken      = "refresh_token"

	// lineA1StateFloor — пол длины `state` (Р13 п. 2): длина записи BASE64URL
	// от 16 случайных байтов. Литерал НАМЕРЕННЫЙ: проба утверждает число
	// приёмки, а не пересказывает величину, которой его задаст реализация.
	lineA1StateFloor = 22

	lineA1Issuer = "https://kaname.kacho.local"
	lineA1Scope  = "openid"
)

// Цели перенаправления мира. Зарегистрированы у клиента `ic-1`: R, R2 и цель
// с собственной строкой запроса (заказ разбора классов: код добавляется к
// разобранной цели, её собственный запрос сохраняется). Незарегистрированные
// отличаются от R ровно в одном: хостом либо хвостовым слэшем (точное
// равенство, без нормализации — LAX-4).
const (
	lineA1R        = "https://console.line-a-1.test/auth/callback"
	lineA1R2       = "https://console.line-a-1.test/auth/other"
	lineA1RQ       = "https://console.line-a-1.test/auth/cb?tenant=a"
	lineA1Foreign  = "https://elsewhere.line-a-1.test/auth/callback"
	lineA1Trailing = lineA1R + "/"
)

// Слова исхода — по ним считается прогон (см. шапку).
const (
	outcomeRed     = "ЧЕСТНЫЙ-КРАСНЫЙ"
	outcomeFixture = "НЕ-ВЫПОЛНИЛОСЬ(фикстура)"
	outcomeSeam    = "НЕ-ВЫПОЛНИЛОСЬ(проба возможности)"
)

// lineA1IssuanceRootUses — как ЭТА сборка пользуется муксом поверхности
// выдачи. Сверяется с переписью корня (`rootIssuanceUses`); форма записи —
// печать узла разбора со сжатыми пробелами.
var lineA1IssuanceRootUses = []string{
	"Handler: registryTokenHandler",
	"mux.Handle(clienttokenhttp.TokenPath, clientTokenHandler)",
	"registryTokenHandler = mux",
}

// ─────────────────────────────────────────────────────────────────────────────
// Мир пробы

type ceremonySession struct {
	bearer domain.SessionBearer
	id     domain.HumanSessionID
	level  string
	authAt time.Time
}

type ceremonyClient struct {
	rec    domain.InteractiveClient
	secret string
}

type ceremonyWorld struct {
	t       *testing.T
	id      string
	ctx     context.Context
	pool    *pgxpool.Pool
	surface *http.ServeMux
	priv    *ecdsa.PrivateKey
	kid     string
	logs    *lockedBuffer

	user    domain.UserID
	email   string
	session ceremonySession
	// ic1 — ACTIVE, цели R, R2, RQ; ic2 — ACTIVE, цель R; gone — DELETING.
	ic1, ic2, gone *ceremonyClient
}

// lockedBuffer — журнал пробы: обработчики пишут в него конкурентно.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *lockedBuffer) Records() int {
	return strings.Count(b.String(), "\n")
}

func (w *ceremonyWorld) fixture(format string, args ...any) {
	w.t.Helper()
	w.t.Fatalf("%s %s: %s", w.id, outcomeFixture, fmt.Sprintf(format, args...))
}

func (w *ceremonyWorld) red(format string, args ...any) {
	w.t.Helper()
	w.t.Fatalf("%s %s: %s", w.id, outcomeRed, fmt.Sprintf(format, args...))
}

func (w *ceremonyWorld) seam(format string, args ...any) {
	w.t.Helper()
	w.t.Fatalf("%s %s: %s", w.id, outcomeSeam, fmt.Sprintf(format, args...))
}

// newCeremonyWorld собирает мир и проверяет каждую его часть ДО того, как
// проба спросит испытуемого. level — уровень доверия посеянной сессии.
func newCeremonyWorld(t *testing.T, id, level string) *ceremonyWorld {
	t.Helper()
	if testing.Short() {
		t.Skip("интеграция: нужен Postgres в контейнере")
	}
	w := &ceremonyWorld{t: t, id: id, ctx: context.Background(), logs: &lockedBuffer{}}

	pool, err := pgxpool.New(w.ctx, iampgtest.NewTestPostgres(t))
	if err != nil {
		w.fixture("пул к базе пробы: %v", err)
	}
	pgtest.ClosePoolAtEnd(t, pool)
	w.pool = pool

	w.requireStorePremise()
	w.seedPerson()
	w.session = w.seedSession(level)
	w.ic1 = w.seedClient("ceremony-first", domain.InteractiveClientActive, []string{lineA1R, lineA1R2, lineA1RQ})
	w.ic2 = w.seedClient("ceremony-second", domain.InteractiveClientActive, []string{lineA1R})
	w.gone = w.seedClient("ceremony-gone", domain.InteractiveClientDeleting, []string{lineA1R})
	w.buildSurface()
	w.requireRootParity()
	w.requireSurfaceAnswers()
	return w
}

// requireStorePremise — таблицы, из которых мир заводится, есть в схеме,
// поднятой цепью миграций (иначе посев ниже упал бы на «отношение не
// существует» — в месте, к причине отношения не имеющем).
func (w *ceremonyWorld) requireStorePremise() {
	w.t.Helper()
	for _, rel := range []string{"kaname.users", "kaname.accounts", "kaname.human_sessions", "kaname.interactive_clients"} {
		var present bool
		if err := w.pool.QueryRow(w.ctx, `SELECT to_regclass($1) IS NOT NULL`, rel).Scan(&present); err != nil {
			w.fixture("каталог базы не отвечает о %s: %v", rel, err)
		}
		if !present {
			w.fixture("в схеме пробы нет %s — мир не из чего завести", rel)
		}
	}
}

// seedPerson — человек и его аккаунт посевом (форма соседних проб хранилища
// входа). Прочитан обратно: посев без проверки — фикстура на слово.
func (w *ceremonyWorld) seedPerson() {
	w.t.Helper()
	w.user = domain.UserID(ids.NewID("usr"))
	account := ids.NewID("acc")
	w.email = strings.ToLower(string(w.user)) + "@line-a-1.invalid"

	tx, err := w.pool.Begin(w.ctx)
	if err != nil {
		w.fixture("транзакция посева человека: %v", err)
	}
	defer func() { _ = tx.Rollback(w.ctx) }()
	if _, err := tx.Exec(w.ctx, `SET CONSTRAINTS ALL DEFERRED`); err != nil {
		w.fixture("отложенные ограничения посева: %v", err)
	}
	if _, err := tx.Exec(w.ctx, `
		INSERT INTO users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		string(w.user), "ext-"+string(w.user), w.email, "ceremony person", account); err != nil {
		w.fixture("посев человека: %v", err)
	}
	if _, err := tx.Exec(w.ctx, `INSERT INTO accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		account, "acc-"+strings.ToLower(account[3:9]), string(w.user)); err != nil {
		w.fixture("посев аккаунта: %v", err)
	}
	if err := tx.Commit(w.ctx); err != nil {
		w.fixture("коммит посева человека: %v", err)
	}
	var n int
	if err := w.pool.QueryRow(w.ctx, `SELECT count(*) FROM users WHERE id = $1`, string(w.user)).Scan(&n); err != nil || n != 1 {
		w.fixture("посеянный человек не читается обратно (строк %d, ошибка %v)", n, err)
	}
}

// seedSession — сессия человека НАШЕГО входа (контракт Ф1) продуктовым
// писателем хранилища сессий и прочитанная обратно его же читателем.
func (w *ceremonyWorld) seedSession(level string) ceremonySession {
	w.t.Helper()
	methods := []string{"password"}
	if level != "1" {
		methods = []string{"password", "totp"}
	}
	authAt := time.Now().Add(-5 * time.Minute).UTC().Truncate(time.Microsecond)
	s := domain.HumanSession{
		ID:               domain.HumanSessionID("hss-" + strings.ToLower(ids.NewID("hss")[3:])),
		UserID:           w.user,
		AuthenticatedAt:  authAt,
		LastPresentedAt:  authAt,
		ExpiresAt:        authAt.Add(12 * time.Hour),
		AssuranceLevel:   level,
		PresentedMethods: methods,
	}
	bearer, err := domain.NewSessionBearer()
	if err != nil {
		w.fixture("носитель сессии: %v", err)
	}
	repo := kanamepg.NewHumanSessionRepo(w.pool)
	wr, err := repo.Writer(w.ctx)
	if err != nil {
		w.fixture("писатель сессий: %v", err)
	}
	if err := wr.InsertSession(w.ctx, s, bearer.Digest()); err != nil {
		_ = wr.Rollback(w.ctx)
		w.fixture("запись сессии: %v", err)
	}
	if err := wr.RememberFirstAuthentication(w.ctx, s.UserID, s.AuthenticatedAt); err != nil {
		_ = wr.Rollback(w.ctx)
		w.fixture("память первой аутентификации: %v", err)
	}
	if err := wr.Commit(w.ctx); err != nil {
		w.fixture("коммит сессии: %v", err)
	}
	got, reason, err := repo.Resolve(w.ctx, bearer.Digest(), time.Now())
	if err != nil || reason != humansession.SessionFound {
		w.fixture("посеянная сессия не резолвится по своему носителю (причина %v, ошибка %v)", reason, err)
	}
	if got.User.ID != w.user || got.Session.AssuranceLevel != level {
		w.fixture("сессия резолвится не в того человека либо не того уровня: %s/%s", got.User.ID, got.Session.AssuranceLevel)
	}
	return ceremonySession{bearer: bearer, id: s.ID, level: level, authAt: authAt}
}

// seedClient — интерактивный клиент посевом продуктовым хранилищем реестра
// (приёмка §1: здесь клиент — Given, сконструированный посевом). Его
// идентификатор предъявления — наш `ic-…` (§5, 02).
func (w *ceremonyWorld) seedClient(name string, status domain.InteractiveClientStatus, redirects []string) *ceremonyClient {
	w.t.Helper()
	id := domain.InteractiveClientID(ids.NewHyphenID(ids.PrefixInteractiveClientHyphen))
	repo := kanamepg.NewInteractiveClientRepo(w.pool)
	in := domain.InteractiveClient{
		ID:                     id,
		Name:                   domain.InteractiveClientName(name),
		RedirectURIs:           redirects,
		PostLogoutRedirectURIs: []string{},
		ClientID:               string(id),
		Audiences:              []string{"https://api.kacho.local"},
		GrantTypes:             []string{grantAuthorizationCode, grantRefreshToken},
		Status:                 status,
	}
	if _, err := repo.Insert(w.ctx, in); err != nil {
		w.fixture("посев интерактивного клиента %s: %v", name, err)
	}
	got, err := repo.Get(w.ctx, id)
	if err != nil {
		w.fixture("посеянный клиент %s не читается: %v", name, err)
	}
	if got.Status != status || strings.Join(got.RedirectURIs, " ") != strings.Join(redirects, " ") {
		w.fixture("клиент %s прочитан не таким, каким посеян: статус %s, цели %v", name, got.Status, got.RedirectURIs)
	}
	return &ceremonyClient{rec: got}
}

// buildSurface собирает внешнюю поверхность выдачи теми же вызовами, что
// корень, на базе пробы и с настоящим подписантом.
func (w *ceremonyWorld) buildSurface() {
	w.t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		w.fixture("ключ подписанта: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		w.fixture("разметка ключа: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		w.fixture("разметка открытого ключа: %v", err)
	}
	w.priv, w.kid = priv, "kaname-line-a-1"
	signer, err := tokensigner.New(tokensigner.Config{
		Issuer: lineA1Issuer, Clock: time.Now, MaxTokenTTL: tokenpolicy.MaxTokenTTL,
	}, ceremonyKeys{mat: tokensigner.SigningMaterial{
		KID:           domain.KeyID(w.kid),
		Algorithm:     domain.SigningAlgES256,
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		PublicKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
	}})
	if err != nil {
		w.fixture("подписант: %v", err)
	}

	logger := slog.New(slog.NewJSONHandler(w.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mux, err := registrytokenwire.Build(w.pool, registrytokenwire.BuildConfig{
		Realm:   "https://api.kacho.local/iam/token",
		Service: "registry.kacho.local",
		Logger:   logger,
		Signer:   signer,
		TokenTTL: 15 * time.Minute,
	})
	if err != nil {
		w.fixture("сборка поверхности выдачи: %v", err)
	}
	var cfg config.Config
	cfg.AuthN.ClientToken = config.ClientTokenConfig{
		Enabled:          true,
		AllowedAudiences: "https://api.kacho.local,registry.kacho.local",
		DefaultAudience:  "https://api.kacho.local",
		TokenTTL:         15 * time.Minute,
		BodyCeiling:      64 << 10,
	}
	clientTokenHandler, err := buildClientTokenEndpoint(w.pool, cfg, signer, logger)
	if err != nil || clientTokenHandler == nil {
		w.fixture("сборка токен-эндпоинта: обработчик %v, ошибка %v", clientTokenHandler != nil, err)
	}
	// Ровно так, как это делает композиционный корень (перечень —
	// lineA1IssuanceRootUses, сверка — requireRootParity).
	mux.Handle(clienttokenhttp.TokenPath, clientTokenHandler)
	w.surface = mux
}

type ceremonyKeys struct{ mat tokensigner.SigningMaterial }

func (k ceremonyKeys) ActiveSigningKey(context.Context) (tokensigner.SigningMaterial, error) {
	return k.mat, nil
}

// requireRootParity — сборка пробы повторяет корень. Перепись выводится
// разбором `serve.go`, пустая перепись — отказ (не «совпало»).
func (w *ceremonyWorld) requireRootParity() {
	w.t.Helper()
	got, err := rootIssuanceUses([]byte(readFileT(w.t, "serve.go")))
	if err != nil {
		w.fixture("перепись корня: %v", err)
	}
	if strings.Join(got, "\n") != strings.Join(lineA1IssuanceRootUses, "\n") {
		w.fixture("сборка пробы разошлась с корнем: корень пользуется муксом поверхности выдачи так %q, "+
			"проба — так %q; повторите монтаж корня в buildSurface и в перечне", got, lineA1IssuanceRootUses)
	}
}

// requireSurfaceAnswers — положительный контроль мира: соседи по поверхности
// ОТВЕЧАЮТ. Без него «маршрута нет» ниже было бы неотличимо от «мукс пуст».
func (w *ceremonyWorld) requireSurfaceAnswers() {
	w.t.Helper()
	rec := w.post(clienttokenhttp.TokenPath, url.Values{
		"grant_type":            {tokenpolicy.GrantTypeClientCredentials},
		"client_assertion_type": {tokenpolicy.ClientAssertionType},
		"client_assertion":      {"a.b.c"},
	}, nil)
	if rec.Code != http.StatusUnauthorized {
		w.fixture("соседний токен-эндпоинт поверхности не отвечает отказом аутентификации (код %d, тело %q)", rec.Code, rec.Body.String())
	}
	if r := w.get(registrytokenhttp.TokenPath, nil, false); r.Code == http.StatusNotFound {
		w.fixture("путь %s перестал резолвиться: сборка поверхности неполна", registrytokenhttp.TokenPath)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Пробы возможности (ступень 2)

// requireAuthorizeEndpoint — объявлен ли путь эндпоинта авторизации. Спрашивает
// без параметров и без сессии: у вопроса нет побочного действия.
func (w *ceremonyWorld) requireAuthorizeEndpoint() {
	w.t.Helper()
	if rec := w.get(lineA1AuthorizePath, nil, false); rec.Code == http.StatusNotFound {
		w.red("путь %s не объявлен поверхностью выдачи (код 404 — маршрута нет): эндпоинта авторизации нет", lineA1AuthorizePath)
	}
}

// requireDiscoveryEndpoint — объявлен ли путь метаданных обнаружения.
func (w *ceremonyWorld) requireDiscoveryEndpoint() {
	w.t.Helper()
	if rec := w.get(lineA1DiscoveryPath, nil, false); rec.Code == http.StatusNotFound {
		w.red("путь %s не объявлен поверхностью выдачи (код 404 — маршрута нет): метаданных обнаружения нет", lineA1DiscoveryPath)
	}
}

// requireGrant — принимает ли токен-эндпоинт вид выдачи. «Вид выдачи вне
// перечня» — объявленный ответ испытуемого о своём наборе, то есть «нет».
func (w *ceremonyWorld) requireGrant(grant string) {
	w.t.Helper()
	rec := w.post(clienttokenhttp.TokenPath, url.Values{"grant_type": {grant}}, nil)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		w.seam("токен-эндпоинт ответил на вид выдачи %q неразбираемым телом (код %d): %v", grant, rec.Code, err)
	}
	if rec.Code == http.StatusBadRequest && body["error"] == "unsupported_grant_type" {
		w.red("токен-эндпоинт %s не принимает вид выдачи %q (400 unsupported_grant_type): полосы нет", clienttokenhttp.TokenPath, grant)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Посев, выразимый только вместе с предметом (после ступени 2)

// giveSecret заводит клиенту секрет: проверочное значение (argon2id службы,
// разметка PHC) кладётся в реестр посевом. Вызывается ТОЛЬКО после того, как
// возможность обмена подтверждена.
func (w *ceremonyWorld) giveSecret(c *ceremonyClient) {
	w.t.Helper()
	if c.secret != "" {
		return
	}
	secret := randomToken(32)
	hasher, err := passwordverify.NewHasher(passwordverify.Declared{
		Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: 65536, domain.CostParamArgon2Iterations: 3, domain.CostParamArgon2Parallelism: 4,
		},
	})
	if err != nil {
		w.fixture("хешер секрета клиента: %v", err)
	}
	v, err := hasher.Hash(secret)
	if err != nil {
		w.fixture("проверочное значение секрета клиента: %v", err)
	}
	tag, err := w.pool.Exec(w.ctx,
		`UPDATE kaname.interactive_clients SET secret_verifier = $1, secret_verifier_set_at = now() WHERE id = $2`,
		v.Reveal(), string(c.rec.ID))
	if err != nil || tag.RowsAffected() != 1 {
		w.fixture("посев секрета клиента %s не лёг (строк %d): %v", c.rec.ID, tag.RowsAffected(), err)
	}
	c.secret = secret
}

// codeStore — таблица записей кода, найденная по признаку приёмки: запись
// связывает `code_challenge` (Р5). Ровно одна — иначе «найдено» не адрес.
func (w *ceremonyWorld) codeStore() string {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx, `
		SELECT table_name FROM information_schema.columns
		WHERE table_schema = 'kaname' AND column_name = 'code_challenge' ORDER BY table_name`)
	if err != nil {
		w.fixture("каталог о хранилище кода: %v", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			w.fixture("каталог о хранилище кода: %v", err)
		}
		names = append(names, n)
	}
	if len(names) != 1 {
		w.fixture("хранилище кода по признаку `code_challenge` найдено %d раз(а): %v", len(names), names)
	}
	return "kaname." + names[0]
}

// codeRecords — записи кода мира, каждая — JSON строки.
func (w *ceremonyWorld) codeRecords() []string {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx, `SELECT row_to_json(c)::text FROM `+w.codeStore()+` c`)
	if err != nil {
		w.fixture("чтение записей кода: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			w.fixture("чтение записи кода: %v", err)
		}
		out = append(out, s)
	}
	return out
}

// ageCodes переносит срок ВСЕХ записей кода мира в прошлое — средствами
// базы. Срок держит база (Р5), поэтому истёкший код создаётся её временем.
func (w *ceremonyWorld) ageCodes() {
	w.t.Helper()
	store := w.codeStore()
	var hasIssued bool
	if err := w.pool.QueryRow(w.ctx, `
		SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_schema = 'kaname' AND table_name = $1 AND column_name = 'issued_at')`,
		strings.TrimPrefix(store, "kaname.")).Scan(&hasIssued); err != nil {
		w.fixture("каталог о сроке кода: %v", err)
	}
	q := `UPDATE ` + store + ` SET expires_at = now() - interval '1 hour'`
	if hasIssued {
		q = `UPDATE ` + store + ` SET issued_at = now() - interval '2 hours', expires_at = now() - interval '1 hour'`
	}
	tag, err := w.pool.Exec(w.ctx, q)
	if err != nil || tag.RowsAffected() == 0 {
		w.fixture("перенос срока кода в прошлое не лёг (строк %d): %v", tag.RowsAffected(), err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Ходы церемонии

func (w *ceremonyWorld) get(path string, q url.Values, withSession bool) *httptest.ResponseRecorder {
	return w.getWith(path, q, withSession, w.session.bearer)
}

func (w *ceremonyWorld) getWith(path string, q url.Values, withSession bool, b domain.SessionBearer) *httptest.ResponseRecorder {
	target := path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if withSession {
		req.AddCookie(&http.Cookie{Name: "kaname_session", Value: b.CookieValue()})
	}
	rec := httptest.NewRecorder()
	w.surface.ServeHTTP(rec, req)
	return rec
}

// post — форма на путь; basic — пара (идентификатор, секрет) клиента.
func (w *ceremonyWorld) post(path string, form url.Values, basic []string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(basic) == 2 {
		req.SetBasicAuth(url.QueryEscape(basic[0]), url.QueryEscape(basic[1]))
	}
	rec := httptest.NewRecorder()
	w.surface.ServeHTTP(rec, req)
	return rec
}

// pkcePair — verifier и его S256-вызов (RFC 7636 §4.1–4.2).
func pkcePair() (verifier, challenge string) {
	verifier = randomToken(32)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// randomToken — BASE64URL без выравнивания от n случайных байтов.
func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// stateOfLen — непрозрачная строка клиента ровно из n знаков ASCII.
func stateOfLen(n int) string {
	s := randomToken(n)
	for len(s) < n {
		s += randomToken(n)
	}
	return s[:n]
}

// authorizeQuery — валидный запрос авторизации сценария 02.
func authorizeQuery(c *ceremonyClient, redirect, state, challenge string) url.Values {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {string(c.rec.ID)},
		"redirect_uri":          {redirect},
		"scope":                 {lineA1Scope},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if state != "" {
		q.Set("state", state)
	}
	return q
}

type issuedCode struct {
	code, verifier, redirect, state string
	client                          *ceremonyClient
}

// issueCode — валидная выдача кода (02) в этом мире. Отказ — отказ предмета
// сценария, ради которого код понадобился.
func (w *ceremonyWorld) issueCode(c *ceremonyClient, redirect string) issuedCode {
	w.t.Helper()
	return w.issueCodeWith(c, redirect, w.session.bearer)
}

func (w *ceremonyWorld) issueCodeWith(c *ceremonyClient, redirect string, b domain.SessionBearer) issuedCode {
	w.t.Helper()
	verifier, challenge := pkcePair()
	state := stateOfLen(lineA1StateFloor + 8)
	rec := w.getWith(lineA1AuthorizePath, authorizeQuery(c, redirect, state, challenge), true, b)
	if rec.Code != http.StatusFound {
		w.t.Fatalf("%s: выдача кода (02) ответила %d, ожидалось 302; тело %q", w.id, rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		w.t.Fatalf("%s: Location выдачи неразбираем: %v", w.id, err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		w.t.Fatalf("%s: в перенаправлении выдачи нет кода: %q", w.id, loc.String())
	}
	return issuedCode{code: code, verifier: verifier, redirect: redirect, state: state, client: c}
}

// exchangeForm — форма обмена кода (10).
func exchangeForm(ic issuedCode) url.Values {
	return url.Values{
		"grant_type":    {grantAuthorizationCode},
		"code":          {ic.code},
		"redirect_uri":  {ic.redirect},
		"client_id":     {string(ic.client.rec.ID)},
		"code_verifier": {ic.verifier},
	}
}

// exchangeAs — обмен формы с аутентификацией клиента c.
func (w *ceremonyWorld) exchangeAs(c *ceremonyClient, form url.Values) *httptest.ResponseRecorder {
	w.t.Helper()
	w.giveSecret(c)
	return w.post(clienttokenhttp.TokenPath, form, []string{string(c.rec.ID), c.secret})
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
}

func decodeToken(t *testing.T, id string, rec *httptest.ResponseRecorder) tokenResponse {
	t.Helper()
	var tr tokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &tr); err != nil {
		t.Fatalf("%s: ответ токен-эндпоинта неразбираем (код %d): %v; тело %q", id, rec.Code, err, rec.Body.String())
	}
	return tr
}

// redeem — успешный обмен кода (10); отказ — отказ предмета сценария.
func (w *ceremonyWorld) redeem(ic issuedCode) tokenResponse {
	w.t.Helper()
	rec := w.exchangeAs(ic.client, exchangeForm(ic))
	if rec.Code != http.StatusOK {
		w.t.Fatalf("%s: обмен кода (10) ответил %d, ожидалось 200; тело %q", w.id, rec.Code, rec.Body.String())
	}
	tr := decodeToken(w.t, w.id, rec)
	if tr.AccessToken == "" {
		w.t.Fatalf("%s: обмен кода вернул 200 без предъявителя: %q", w.id, rec.Body.String())
	}
	return tr
}

// refresh — предъявление обновляющего удостоверения клиентом c.
func (w *ceremonyWorld) refresh(c *ceremonyClient, rt string) *httptest.ResponseRecorder {
	w.t.Helper()
	return w.exchangeAs(c, url.Values{
		"grant_type":    {grantRefreshToken},
		"refresh_token": {rt},
		"client_id":     {string(c.rec.ID)},
	})
}

// requireInvalidGrant — отказ обмена после именования кода (Р10).
func requireInvalidGrant(t *testing.T, id, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("%s: %s: ожидался 400 invalid_grant, получен %d; тело %q", id, what, rec.Code, rec.Body.String())
	}
	tr := decodeToken(t, id, rec)
	if tr.Error != "invalid_grant" || tr.AccessToken != "" {
		t.Fatalf("%s: %s: ожидался invalid_grant без предъявителя, получено %q", id, what, rec.Body.String())
	}
}

// bearerClaims — предъявитель проверен НАШИМ открытым ключом и нашим
// издателем; иначе это не наш подписанный предъявитель.
func (w *ceremonyWorld) bearerClaims(raw string) jwt.MapClaims {
	w.t.Helper()
	claims := jwt.MapClaims{}
	_, err := jwt.NewParser(
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer(lineA1Issuer),
		jwt.WithExpirationRequired(),
	).ParseWithClaims(raw, claims, func(tok *jwt.Token) (any, error) {
		if kid, _ := tok.Header["kid"].(string); kid != w.kid {
			return nil, fmt.Errorf("kid %q не наш", kid)
		}
		return &w.priv.PublicKey, nil
	})
	if err != nil {
		w.t.Fatalf("%s: предъявитель не проверяется нашим ключом и издателем: %v", w.id, err)
	}
	return claims
}

// claimACR — уровень так, как его читает край: `acr`, затем `kaname_acr`.
func claimACR(c jwt.MapClaims) string {
	if v, ok := c["acr"].(string); ok && v != "" {
		return v
	}
	v, _ := c["kaname_acr"].(string)
	return v
}

// claimAuthTime — момент аутентификации (`auth_time`, секунды).
func claimAuthTime(c jwt.MapClaims) (int64, bool) {
	f, ok := c["auth_time"].(float64)
	return int64(f), ok
}

// presentation — ответ НАШИХ читателей отзыва на предъявлении так, как их
// спрашивает край: авторитет отзыва наших токенов, отзыв по `jti` и отсечка
// субъекта по моменту аутентификации. refused — хоть один отказал.
func (w *ceremonyWorld) presentation(raw string) (refused bool, why string) {
	w.t.Helper()
	claims := w.bearerClaims(raw)
	introspect := tokenintrospecthttp.NewHandler(tokenintrospecthttp.Config{
		Issuer:      lineA1Issuer,
		Keys:        ceremonyPublished{w: w},
		Revocations: kanamepg.NewMintedTokenRevocationRepo(w.pool),
	})
	req := httptest.NewRequest(http.MethodPost, tokenintrospecthttp.IntrospectPath, strings.NewReader(url.Values{"token": {raw}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	introspect.ServeHTTP(rec, req)
	var ans struct {
		Active bool `json:"active"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &ans) != nil {
		w.t.Fatalf("%s: авторитет отзыва не ответил (код %d, тело %q)", w.id, rec.Code, rec.Body.String())
	}
	if !ans.Active {
		return true, "авторитет отзыва наших токенов: active=false"
	}

	rev := sessionrevapp.NewHandler(nil, kanamepg.NewSessionRevocationsAdapter(w.pool)).
		WithCutoffReader(kanamepg.NewUserTokenRevocationRepo(w.pool))
	jti, _ := claims["jti"].(string)
	isRev, err := rev.IsRevoked(w.ctx, &iamv1.IsRevokedRequest{TokenJti: jti})
	if err != nil {
		w.t.Fatalf("%s: отзыв по jti не ответил: %v", w.id, err)
	}
	if isRev.GetRevoked() {
		return true, "отзыв по jti: revoked"
	}
	sub, _ := claims["sub"].(string)
	cut, err := rev.SessionCutoffOf(w.ctx, &iamv1.SessionCutoffOfRequest{UserId: sub})
	if err != nil {
		w.t.Fatalf("%s: отсечка субъекта не ответила: %v", w.id, err)
	}
	if at, ok := claimAuthTime(claims); cut.GetFound() && ok && !time.Unix(at, 0).After(cut.GetRevokeBefore().AsTime()) {
		return true, "отсечка субъекта покрывает момент аутентификации"
	}
	return false, ""
}

type ceremonyPublished struct{ w *ceremonyWorld }

func (p ceremonyPublished) PublishedSet(context.Context) ([]domain.PublishedKey, error) {
	der, err := x509.MarshalPKIXPublicKey(&p.w.priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return []domain.PublishedKey{{
		KID: domain.KeyID(p.w.kid), Algorithm: domain.SigningAlgES256,
		PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
	}}, nil
}

// requireNoStore — ответ, несущий удостоверение, не кэшируется (LAX-19 в).
func requireNoStore(t *testing.T, id, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("%s: %s: Cache-Control %q без no-store — удостоверение кэшируемо", id, what, cc)
	}
	if p := rec.Header().Get("Pragma"); p != "no-cache" {
		t.Errorf("%s: %s: Pragma %q, ожидалось no-cache", id, what, p)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Перепись корня (разбор `serve.go`)

// rootIssuanceUses — все употребления муксом поверхности выдачи в корне:
// переменной, которой присвоен результат `registrytokenwire.Build`, и
// переменной, которой присвоен сам мукс. Каждое употребление печатается
// ближайшим узлом-носителем (вызов, присваивание, поле литерала).
func rootIssuanceUses(src []byte) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", src, 0)
	if err != nil {
		return nil, fmt.Errorf("разбор: %w", err)
	}
	var muxObj *ast.Object
	ast.Inspect(file, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 || muxObj != nil {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Build" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "registrytokenwire" {
			if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Obj != nil {
				muxObj = id.Obj
			}
		}
		return true
	})
	if muxObj == nil {
		return nil, fmt.Errorf("сборка поверхности выдачи (registrytokenwire.Build) в корне не найдена — переписывать нечего")
	}
	objs := map[*ast.Object]bool{muxObj: true}
	// Переменная, принявшая мукс (`X = mux`), — тоже носитель поверхности.
	ast.Inspect(file, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			if r, ok := as.Rhs[0].(*ast.Ident); ok && r.Obj == muxObj {
				if l, ok := as.Lhs[0].(*ast.Ident); ok && l.Obj != nil {
					objs[l.Obj] = true
				}
			}
		}
		return true
	})

	seen := map[string]bool{}
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		stack = append(stack, n)
		id, ok := n.(*ast.Ident)
		if !ok || id.Obj == nil || !objs[id.Obj] || isDeclaringIdent(id) {
			return true
		}
		for i := len(stack) - 2; i >= 0; i-- {
			switch p := stack[i].(type) {
			case *ast.CallExpr, *ast.AssignStmt, *ast.KeyValueExpr, *ast.ReturnStmt:
				var b bytes.Buffer
				if err := format.Node(&b, fset, p); err == nil {
					seen[strings.Join(strings.Fields(b.String()), " ")] = true
				}
				return true
			}
		}
		return true
	})
	out := make([]string, 0, len(seen))
	for s := range seen {
		// Определение (`mux, berr := registrytokenwire.Build(...)`) — не
		// употребление.
		if strings.Contains(s, "registrytokenwire.Build(") {
			continue
		}
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("мукс поверхности выдачи найден, употреблений у него ноль — перепись пуста")
	}
	return out, nil
}

// isDeclaringIdent — идентификатор стоит в месте своего объявления.
func isDeclaringIdent(id *ast.Ident) bool {
	switch d := id.Obj.Decl.(type) {
	case *ast.ValueSpec:
		for _, n := range d.Names {
			if n == id {
				return true
			}
		}
	case *ast.AssignStmt:
		if d.Tok == token.DEFINE {
			for _, l := range d.Lhs {
				if l == id {
					return true
				}
			}
		}
	}
	return false
}
