// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// session_lane_integration_harness_test.go — СТЕНД проб сессии на ПРОВОДЕ:
// слушатель полосы формы над НАСТОЯЩИМИ глаголами (вход, выход, смена пароля,
// церемония повышения, запрос и завершение восстановления) с настоящими
// адаптерами базы плюс ответ службы краю о сессии
// (`InternalHumanSessionService.Resolve`) через gRPC-соединение. Пробы —
// `step_up_integration_test.go` (Ф11-09, -10, -12, -13, -31) и
// `recovery_session_integration_test.go` (Ф5-24).
//
// # Почему настоящие глаголы, а не дублёр
//
// Предмет этих проб — исход, который РОЖДАЕТ вариант использования над базой:
// перевыпуск носителя, накопление множества, отзыв, неизменность после отказа.
// Дублёр отвечал бы объявленным исходом, и каждое утверждение зеленело бы при
// любом коде полосы. Поэтому сборка повторяет композиционный корень
// (`cmd/kaname/loginlane.go`, `buildLoginLane`): те же конструкторы, те же
// адаптеры `pg`, тот же проверяющий пароля, он же проверяющий набора и тот же
// хешер. Расходится она с корнем ровно в трёх величинах, и все три — не предмет
// проб: огибающая по времени нулевая (время держат пробы огибающей Ф3 Р17),
// постановка письма синхронна (иначе код восстановления пришлось бы ждать
// временем), журнал молчит.
//
// # Почему ответ краю — через соединение
//
// Край читает сессию СООБЩЕНИЕМ на проводе: поле, которого сервер больше не
// объявляет, но всё ещё пишет, клиент увидит только как неизвестное поле
// разобранного сообщения. Вызов обработчика напрямую этого не показал бы
// (Ф5-24: «ни один ответ — ключа требования сменить пароль»).
package loginlanehttp_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Величины профиля стенда. Окно свежести — величина Ф1 §4.1 (15 мин); срок —
// абсолютный, как в профиле (F4d Р5).
const (
	laneSessionTTL    = 24 * time.Hour
	laneFreshness     = 15 * time.Minute
	laneRecoveryTTL   = 5 * time.Minute
	laneProbeDomain   = "console.example.invalid"
	laneWrongPassword = "this-is-not-the-password-7"
)

// sessionVerbs — глаголы слушателя: шесть настоящих, остальные — дублёр (их
// эти пробы не зовут; позванный дублёр ответил бы нулевым исходом, и проба
// увидела бы это как отказ, а не как успех).
type sessionVerbs struct {
	*stubLane
	login    *humansession.LoginUseCase
	logout   *humansession.LogoutUseCase
	change   *humansession.ChangePasswordUseCase
	stepUp   *humansession.StepUpUseCase
	request  *humansession.RequestRecoveryUseCase
	complete *humansession.CompleteRecoveryUseCase
}

func (v sessionVerbs) Login(ctx context.Context, in humansession.LoginInput) (humansession.LoginOutput, error) {
	return v.login.Execute(ctx, in)
}

func (v sessionVerbs) Logout(ctx context.Context, b domain.SessionBearer) (bool, error) {
	return v.logout.Execute(ctx, b)
}

func (v sessionVerbs) ChangePassword(ctx context.Context, in humansession.ChangePasswordInput) (humansession.ChangePasswordOutput, error) {
	return v.change.Execute(ctx, in)
}

func (v sessionVerbs) StepUp(ctx context.Context, in humansession.StepUpInput) (humansession.StepUpOutput, error) {
	return v.stepUp.Execute(ctx, in)
}

func (v sessionVerbs) RequestRecovery(ctx context.Context, in humansession.RequestRecoveryInput) error {
	return v.request.Execute(ctx, in)
}

func (v sessionVerbs) CompleteRecovery(ctx context.Context, in humansession.CompleteRecoveryInput) (humansession.CompleteRecoveryOutput, error) {
	return v.complete.Execute(ctx, in)
}

// sessionLane — база, личность с паролем (зарегистрирована полосой Ф4),
// слушатель над настоящими глаголами и клиент ответа краю о сессии.
type sessionLane struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	email    string
	user     domain.User
	sessions *kanamepg.HumanSessionRepo
	users    *kanamepg.Repository
	lane     *lane
	c        *http.Client
	resolver iamv1.InternalHumanSessionServiceClient
}

// laneSession — сессия, как её держит браузер: носитель и контекст формы,
// выданный вместе с ней (Р12: выдача сессии сменяет контекст).
type laneSession struct {
	bearer *http.Cookie
	form   *http.Cookie
}

func newSessionLane(t *testing.T) *sessionLane {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	logger := slog.New(slog.DiscardHandler)

	declared := passwordverify.Declared{Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: 65536, domain.CostParamArgon2Iterations: 3, domain.CostParamArgon2Parallelism: 4}}
	hasher, err := passwordverify.NewHasher(declared)
	require.NoError(t, err)
	verifier, err := passwordverify.New(4, nopVerifyObserver{})
	require.NoError(t, err)
	decoy, err := hasher.Hash("decoy-of-the-probe")
	require.NoError(t, err)
	require.NoError(t, verifier.SetDecoy(decoy))
	rule, err := humansession.NewPasswordRule(12, nil, humansession.NopObserver{}, logger)
	require.NoError(t, err)

	// Личность с паролем — регистрацией полосой Ф4: зеркало, строка способа и
	// сессия одним исходом, как в посадке.
	regLane, ok := registration.LaneByName(registration.LanePassword)
	require.True(t, ok)
	register, err := registration.NewRegisterUseCase(registration.Deps{
		Store: pgRegistrationStore{inner: kanamepg.NewRegistrationStore(pool)}, Rule: rule, Hasher: hasher, Lane: regLane,
		TTL: laneSessionTTL, Observer: registration.NopObserver{}, Now: time.Now, Logger: logger,
	})
	require.NoError(t, err)
	email := "sl-" + ids.NewID("tst")[3:11] + "@example.invalid"
	reg, err := register.Execute(ctx, registration.Input{Email: email, Password: integrationPassword, Source: fwd()[loginlanehttp.HeaderForwardedFor]})
	require.NoError(t, err)
	require.NotEmpty(t, reg.View.User.ID, "регистрация назвала личность")

	key := make([]byte, keywrap.KeySize)
	for i := range key {
		key[i] = 7
	}
	wrapper, err := keywrap.New(key)
	require.NoError(t, err)
	totp, err := totpverify.New(wrapper)
	require.NoError(t, err)

	sessions := kanamepg.NewHumanSessionRepo(pool)
	methods := kanamepg.NewLoginMethodRepo(pool)
	users := kanamepg.New(pool, nil)
	limits := humansession.Limits{AddressAttempts: 5, AddressWindow: 10 * time.Minute, SourceAttempts: 50, SourceWindow: 10 * time.Minute}
	nop := humansession.NopObserver{}

	login, err := humansession.NewLoginUseCase(humansession.LoginDeps{
		Store: sessions, Users: kanamepg.NewUserDirectory(users), Methods: methods, Verifier: verifier, Hasher: hasher,
		Limits: limits, TTL: laneSessionTTL, Observer: nop, Now: time.Now, Logger: logger,
		Envelope: zeroEnvelope{}, TOTP: totp, Sets: verifier,
	})
	require.NoError(t, err)
	logout, err := humansession.NewLogoutUseCase(sessions, nop, time.Now, logger)
	require.NoError(t, err)
	change, err := humansession.NewChangePasswordUseCase(humansession.ChangePasswordDeps{
		Store: sessions, Methods: methods, Verifier: verifier, Hasher: hasher, Rule: rule,
		Limits: limits, Observer: nop, Now: time.Now, Logger: logger,
	})
	require.NoError(t, err)
	stepUp, err := humansession.NewStepUpUseCase(humansession.SecondFactorDeps{
		Store: sessions, Methods: methods, TOTP: totp, Sets: verifier, SetHasher: hasher, Verifier: verifier,
		Limits: limits, Freshness: laneFreshness, Domain: laneProbeDomain, Observer: nop, Now: time.Now, Logger: logger,
	})
	require.NoError(t, err)
	request, err := humansession.NewRequestRecoveryUseCase(humansession.RequestRecoveryDeps{
		Store: sessions, CodeTTL: laneRecoveryTTL, Dispatcher: humansession.SyncDispatcher{}, Observer: nop, Now: time.Now, Logger: logger,
	})
	require.NoError(t, err)
	complete, err := humansession.NewCompleteRecoveryUseCase(humansession.CompleteRecoveryDeps{
		Store: sessions, Hasher: hasher, Rule: rule, Limits: limits, TTL: laneSessionTTL, Observer: nop, Now: time.Now, Logger: logger,
	})
	require.NoError(t, err)
	resolveUC, err := humansession.NewResolveUseCase(sessions, nop, time.Now)
	require.NoError(t, err)

	l := newLaneOver(t, sessionVerbs{stubLane: &stubLane{}, login: login, logout: logout, change: change,
		stepUp: stepUp, request: request, complete: complete}, "")
	return &sessionLane{
		ctx: ctx, pool: pool, email: email, user: reg.View.User, sessions: sessions, users: users,
		lane: l, c: l.client(t, gatewaySAN), resolver: serveResolve(t, humansession.NewHandler(resolveUC)),
	}
}

// serveResolve — ответ службы краю о сессии на gRPC-соединении: край читает
// разобранное сообщение, и проба читает его так же.
func serveResolve(t *testing.T, h iamv1.InternalHumanSessionServiceServer) iamv1.InternalHumanSessionServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	iamv1.RegisterInternalHumanSessionServiceServer(srv, h)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///resolve",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return iamv1.NewInternalHumanSessionServiceClient(conn)
}

// login — вход паролем через слушатель; сессия и контекст формы, который
// выдача сменила.
func (h *sessionLane) login(t *testing.T, password string) laneSession {
	t.Helper()
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathLogin,
		map[string]any{"email": h.email, "password": password, "csrfToken": tok}, fwd(), ctxCk)
	require.Equal(t, http.StatusOK, r.status, "Дано: вход паролем выдаёт сессию: %s", r.body)
	s := laneSession{bearer: cookieNamed(r.cookies, loginlanehttp.CookieSession), form: cookieNamed(r.cookies, loginlanehttp.CookieForm)}
	require.NotNil(t, s.bearer, "Дано: вход пишет носитель")
	require.NotNil(t, s.form, "Дано: выдача сессии сменяет контекст формы (Р12)")
	return s
}

// csrfFor — признак вида kind в контексте формы сессии.
func (h *sessionLane) csrfFor(t *testing.T, kind domain.FormKind, form *http.Cookie) string {
	t.Helper()
	tok, _ := h.lane.csrf(t, h.c, string(kind), form)
	return tok
}

// stepUpPassword — церемония, ветвь пароля. Пустой признак — поле не
// отправляется вовсе.
func (h *sessionLane) stepUpPassword(t *testing.T, s laneSession, password, csrfToken string) reply {
	t.Helper()
	body := map[string]any{"method": "password", "password": password}
	if csrfToken != "" {
		body["csrfToken"] = csrfToken
	}
	return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathStepUp, body, fwd(), s.bearer, s.form)
}

// logout — выход через слушатель.
func (h *sessionLane) logout(t *testing.T, s laneSession) reply {
	t.Helper()
	return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathLogout,
		map[string]any{"csrfToken": h.csrfFor(t, domain.FormLogout, s.form)}, fwd(), s.bearer, s.form)
}

// resolve — ответ службы краю о носителе.
func (h *sessionLane) resolve(t *testing.T, bearer string) *iamv1.ResolveHumanSessionResponse {
	t.Helper()
	return resolveOver(t, h.resolver, bearer)
}

func resolveOver(t *testing.T, c iamv1.InternalHumanSessionServiceClient, bearer string) *iamv1.ResolveHumanSessionResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := c.Resolve(ctx, &iamv1.ResolveHumanSessionRequest{Bearer: bearer})
	require.NoError(t, err, "ответ краю о сессии не получен")
	return out
}

// resolveWire — тот же ответ байтами: «побайтово равный» сравнивается по
// детерминированной сериализации сообщения.
func (h *sessionLane) resolveWire(t *testing.T, bearer string) []byte {
	t.Helper()
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(h.resolve(t, bearer))
	require.NoError(t, err)
	return b
}

// sessionRow — запись сессии в хранилище службы.
type sessionRow struct {
	id       string
	digest   string
	level    string
	methods  []string
	lastSeen time.Time
	ended    bool
}

func (h *sessionLane) rowByBearer(t *testing.T, bearer string) (sessionRow, bool) {
	t.Helper()
	return h.rowWhere(t, `bearer_digest = $1`, string(domain.PresentedSessionBearer(bearer).Digest()))
}

func (h *sessionLane) rowByID(t *testing.T, id string) sessionRow {
	t.Helper()
	row, ok := h.rowWhere(t, `id = $1`, id)
	require.True(t, ok, "запись сессии %s есть в хранилище", id)
	return row
}

func (h *sessionLane) rowWhere(t *testing.T, cond, arg string) (sessionRow, bool) {
	t.Helper()
	var (
		r     sessionRow
		ended *time.Time
	)
	err := h.pool.QueryRow(h.ctx, `SELECT id, bearer_digest, assurance_level, presented_methods, last_presented_at, ended_at
		  FROM human_sessions WHERE `+cond, arg).Scan(&r.id, &r.digest, &r.level, &r.methods, &r.lastSeen, &ended)
	if err != nil {
		return sessionRow{}, false
	}
	r.ended = ended != nil
	return r, true
}

// sessionsOfPerson — записей сессий личности всего и живых.
func (h *sessionLane) sessionsOfPerson(t *testing.T) (total, live int) {
	t.Helper()
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*), count(*) FILTER (WHERE ended_at IS NULL) FROM human_sessions WHERE user_id = $1`,
		string(h.user.ID)).Scan(&total, &live))
	return total, live
}

// ghostBearer — носитель, которого хранилище не знает: «несуществующая сессия».
func ghostBearer(t *testing.T) *http.Cookie {
	t.Helper()
	b, err := domain.NewSessionBearer()
	require.NoError(t, err)
	return &http.Cookie{Name: loginlanehttp.CookieSession, Value: b.CookieValue()}
}

// ceremonyLevels — уровень, который называет ответ церемонии: объект
// `assurance` и состав сессии.
func ceremonyLevels(t *testing.T, body string) (assuranceLevel, sessionLevel string) {
	t.Helper()
	var out struct {
		Session struct {
			AssuranceLevel string `json:"assuranceLevel"`
		} `json:"session"`
		Assurance struct {
			Level string `json:"level"`
		} `json:"assurance"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &out), body)
	return out.Assurance.Level, out.Session.AssuranceLevel
}

// setInviteStatus — состояние членства личности писателем продукта
// (`UserService.Block` / `Unblock` пишут им же), своей транзакцией.
func (h *sessionLane) setInviteStatus(t *testing.T, st domain.InviteStatus) {
	t.Helper()
	w, err := h.users.Writer(h.ctx)
	require.NoError(t, err)
	_, err = w.UsersW().SetInviteStatus(h.ctx, h.user.ID, st)
	require.NoError(t, err, "состояние членства %s не записано", st)
	require.NoError(t, w.Commit(h.ctx))
}
