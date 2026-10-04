// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_verification_harness_integration_test.go — СТЕНД проб приёмки
// `docs/engineering/acceptance/access-beyond-login-needs-a-verified-address.md`
// (задача PRO-Robotech/kaname#456) на ПРОВОДЕ полосы формы: слушатель над
// настоящими глаголами и настоящими адаптерами базы, ответ краю о сессии через
// соединение, часы глаголов — управляемые.
//
// # Ступени пробы и их слова
//
// Каждая проба проходит три ступени (форма проб мира церемонии), и отказ на
// каждой называет себя своим словом:
//
//  1. МИР — база, человек, сессия заведены и прочитаны обратно. Отказ —
//     «НЕ-ВЫПОЛНИЛОСЬ(фикстура)»: сломан вопрос, а не ответ.
//  2. ВОЗМОЖНОСТЬ — глагол подтверждения смонтирован на слушателе. Путь,
//     отвечающий 404, — «ЧЕСТНЫЙ-КРАСНЫЙ: глагола нет» (§10 приёмки, группы В,
//     Г). Ступень стоит ПОСЛЕ мира: сломанная фикстура не может выдать себя за
//     отсутствие глагола.
//  3. ПРЕДМЕТ — утверждения сценария; отказ несёт номер сценария.
//
// Код, где он нужен, берётся ИЗ СТРОКИ ОЧЕРЕДИ письма этого человека до её
// дренажа (§5 приёмки): проба судит производителя письма, а не выдумывает код.
package loginlanehttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/journalfixture"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Пути и виды формы глагола подтверждения — ДОСЛОВНО из приёмки (Р6, Ф6 Р15):
// проба называет их литералами, а не константами слушателя, потому что её
// предмет и есть то, что слушатель их объявил.
const (
	avPathRequest     = "/iam/v1/auth/verify-email"
	avPathConfirm     = "/iam/v1/auth/verify-email/confirm"
	avFormRequest     = "verify-email"
	avFormConfirm     = "verify-email-confirm"
	avMailKind        = "mail.verification.send"
	avRefusalDomain   = "iam.kaname.cloud"
	avIntervalProfile = 60 * time.Second
	avWindowProfile   = 24 * time.Hour
	avLimitProfile    = 5
	avCodeTTLProfile  = 30 * time.Minute
	avAttemptsProfile = 5
)

// avRefusalBody — значение отказа положения на полосе формы (Р3) побайтово.
const avRefusalBody = `{"code":7,"message":"email address is not verified","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"EMAIL_NOT_VERIFIED","domain":"iam.kaname.cloud"}]}`

// avClock — управляемые часы глаголов стенда.
type avClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *avClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *avClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// avSession — сессия, как её держит браузер.
type avSession struct {
	user   domain.UserID
	email  string
	bearer *http.Cookie
	form   *http.Cookie
}

// avLane — стенд.
type avLane struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	lane     *lane
	c        *http.Client
	resolver iamv1.InternalHumanSessionServiceClient
	clock    *avClock
	sessions *kanamepg.HumanSessionRepo
	methods  *kanamepg.LoginMethodRepo
	users    *kanamepg.Repository
	hasher   humansession.Hasher
	secondF  humansession.SecondFactorDeps
	// failApply — хранилище отказывает на операции применения кода (EV-42):
	// обёртка стенда передаёт каждый прочий вызов настоящему адаптеру.
	failApply *atomic.Bool
	// door — дверь решения над той же базой (как её провязывает корень).
	door *authzcascade.Client
}

// avOptions — величины входа, которыми стенд расходится со стендом по
// умолчанию. Нулевое значение — стенд по умолчанию.
type avOptions struct {
	// logger — журнал процесса глаголов; nil — молчащий.
	logger *slog.Logger
	// registrationsPerSource — окно регистраций одного источника; 0 — величина
	// стенда по умолчанию, не мешающая пробам с одним источником.
	registrationsPerSource int
	// recoveryLettersPerRecipient — окно писем восстановления адресату; 0 —
	// величина стенда по умолчанию.
	recoveryLettersPerRecipient int
}

// Величины стенда по умолчанию для окон условий аудита: столько обращений ни
// одна проба стенда с общим источником не делает.
const (
	avDefaultPerSource    = 10000
	avDefaultPerRecipient = 10000
)

// newAVLane — стенд над настоящими глаголами полосы.
func newAVLane(t *testing.T) *avLane {
	t.Helper()
	return newAVLaneWith(t, avOptions{})
}

// newAVLaneLogging — стенд с журналом процесса пробы.
func newAVLaneLogging(t *testing.T, logger *slog.Logger) *avLane {
	t.Helper()
	return newAVLaneWith(t, avOptions{logger: logger})
}

// newAVLaneWith — стенд с величинами входа опций.
func newAVLaneWith(t *testing.T, opts avOptions) *avLane {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := iampgtest.NewTestPostgres(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): пул к базе стенда")
	t.Cleanup(pool.Close)
	logger := slog.New(slog.DiscardHandler)
	if opts.logger != nil {
		logger = opts.logger
	}
	clock := &avClock{now: time.Now().UTC().Truncate(time.Microsecond)}

	declared := passwordverify.Declared{Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: 65536, domain.CostParamArgon2Iterations: 3, domain.CostParamArgon2Parallelism: 4}}
	hasher, err := passwordverify.NewHasher(declared)
	require.NoError(t, err)
	verifier, err := passwordverify.New(8, nopVerifyObserver{})
	require.NoError(t, err)
	decoy, err := hasher.Hash("decoy-of-the-address-probe")
	require.NoError(t, err)
	require.NoError(t, verifier.SetDecoy(decoy))
	rule, err := humansession.NewPasswordRule(12, nil, humansession.NopObserver{}, logger)
	require.NoError(t, err)

	key := make([]byte, keywrap.KeySize)
	for i := range key {
		key[i] = 9
	}
	wrapper, err := keywrap.New(key)
	require.NoError(t, err)
	totp, err := totpverify.New(wrapper)
	require.NoError(t, err)

	sessions := kanamepg.NewHumanSessionRepo(pool)
	methods := kanamepg.NewLoginMethodRepo(pool)
	users := kanamepg.New(pool, nil)
	limits := humansession.Limits{AddressAttempts: 50, AddressWindow: 10 * time.Minute, SourceAttempts: 500, SourceWindow: 10 * time.Minute}
	nop := humansession.NopObserver{}
	pace := humansession.VerificationPace{
		CodeTTL: avCodeTTLProfile, Attempts: avAttemptsProfile, Interval: avIntervalProfile,
		Limit: avLimitProfile, Window: avWindowProfile,
	}
	perSource := avDefaultPerSource
	if opts.registrationsPerSource > 0 {
		perSource = opts.registrationsPerSource
	}
	perRecipient := avDefaultPerRecipient
	if opts.recoveryLettersPerRecipient > 0 {
		perRecipient = opts.recoveryLettersPerRecipient
	}
	registrationPG := kanamepg.NewRegistrationStore(pool)

	regLane, ok := registration.LaneByName(registration.LanePassword)
	require.True(t, ok)
	register, err := registration.NewRegisterUseCase(registration.Deps{
		Store: pgRegistrationStore{inner: registrationPG}, Rule: rule, Hasher: hasher, Lane: regLane,
		TTL: laneSessionTTL, Observer: registration.NopObserver{}, Letter: pace,
		Sources: sessions, SourcePace: humansession.SourcePace{Limit: perSource, Window: time.Hour},
		Now: clock.Now, Logger: logger,
	})
	require.NoError(t, err)
	login, err := humansession.NewLoginUseCase(humansession.LoginDeps{
		Store: sessions, Users: kanamepg.NewUserDirectory(users), Methods: methods, Verifier: verifier, Hasher: hasher,
		Limits: limits, TTL: laneSessionTTL, Observer: nop, Now: clock.Now, Logger: logger,
		Envelope: zeroEnvelope{}, TOTP: totp, Sets: verifier,
	})
	require.NoError(t, err)
	logout, err := humansession.NewLogoutUseCase(sessions, nop, clock.Now, logger)
	require.NoError(t, err)
	change, err := humansession.NewChangePasswordUseCase(humansession.ChangePasswordDeps{
		Store: sessions, Methods: methods, Verifier: verifier, Hasher: hasher, Rule: rule,
		Limits: limits, Observer: nop, Now: clock.Now, Logger: logger,
	})
	require.NoError(t, err)
	sf := humansession.SecondFactorDeps{
		Store: sessions, Methods: methods, TOTP: totp, Sets: verifier, SetHasher: hasher, Verifier: verifier,
		Limits: limits, Freshness: laneFreshness, Domain: laneProbeDomain, Observer: nop, Now: clock.Now, Logger: logger,
	}
	stepUp, err := humansession.NewStepUpUseCase(sf)
	require.NoError(t, err)
	status, err := humansession.NewSecondFactorStatusUseCase(sf)
	require.NoError(t, err)
	enroll, err := humansession.NewEnrollSecondFactorUseCase(sf)
	require.NoError(t, err)
	confirmSF, err := humansession.NewConfirmSecondFactorUseCase(sf)
	require.NoError(t, err)
	remove, err := humansession.NewRemoveSecondFactorUseCase(sf)
	require.NoError(t, err)
	regen, err := humansession.NewRegenerateBackupCodesUseCase(sf)
	require.NoError(t, err)
	resolveUC, err := humansession.NewResolveUseCase(sessions, nop, clock.Now)
	require.NoError(t, err)
	recovery, err := humansession.NewRequestRecoveryUseCase(humansession.RequestRecoveryDeps{
		Store: sessions, CodeTTL: laneRecoveryTTL, Dispatcher: humansession.SyncDispatcher{},
		Sources: sessions, SourcePace: humansession.SourcePace{Limit: avDefaultPerSource, Window: time.Hour},
		MailLimit: outboxtypes.InviteMailRateLimit{MaxPerWindow: perRecipient, Window: time.Hour},
		Observer:  nop, Now: clock.Now, Logger: logger,
	})
	require.NoError(t, err)
	failApply := &atomic.Bool{}
	vdeps := humansession.VerificationDeps{
		Store: avVerificationStore{sessions: sessions, inner: registrationPG, failApply: failApply}, Pace: pace,
		Now: clock.Now, Logger: logger,
	}
	requestV, err := humansession.NewRequestVerificationUseCase(vdeps)
	require.NoError(t, err)
	confirmV, err := humansession.NewConfirmVerificationUseCase(vdeps)
	require.NoError(t, err)
	position, err := humansession.NewPositionUseCase(sessions, clock.Now)
	require.NoError(t, err)

	verbs := avVerbs{stubLane: &stubLane{}, register: register, login: login, logout: logout, change: change,
		stepUp: stepUp, status: status, enroll: enroll, confirmSF: confirmSF, remove: remove, regen: regen, recovery: recovery,
		requestV: requestV, confirmV: confirmV, position: position}
	l := newLaneOver(t, verbs, "")
	return &avLane{
		ctx: ctx, pool: pool, lane: l, c: l.client(t, gatewaySAN), resolver: serveResolve(t, humansession.NewHandler(resolveUC)),
		clock: clock, sessions: sessions, methods: methods, users: users, hasher: hasher, secondF: sf,
		failApply: failApply,
		door:      authzcascade.WrapAdmitted(relverdict.NewAsker(pool), personmarks.New(pool)),
	}
}

// avVerificationStore — хранилище глагола подтверждения тем же составом, что в
// композиционном корне (`verificationStore`); failApply — хранилище отказывает
// на операции применения кода (EV-42), прочее — настоящий адаптер.
type avVerificationStore struct {
	sessions  *kanamepg.HumanSessionRepo
	inner     *kanamepg.RegistrationStore
	failApply *atomic.Bool
}

func (s avVerificationStore) Resolve(ctx context.Context, digest domain.BearerDigest, now time.Time) (humansession.Resolved, humansession.NoSessionReason, error) {
	return s.sessions.Resolve(ctx, digest, now)
}

func (s avVerificationStore) VerificationWriter(ctx context.Context, userID domain.UserID) (humansession.VerificationWriter, error) {
	w, err := s.inner.VerificationWriter(ctx, userID)
	if err != nil {
		return nil, err
	}
	return avVerificationWriter{RegistrationWriter: w, failApply: s.failApply}, nil
}

type avVerificationWriter struct {
	*kanamepg.RegistrationWriter
	failApply *atomic.Bool
}

func (w avVerificationWriter) PresentVerificationCode(ctx context.Context, userID domain.UserID, digest domain.CodeDigest, now time.Time, attempts int) (humansession.PresentedCode, domain.Email, error) {
	if w.failApply.Load() {
		return humansession.CodeNotFound, "", errors.New("injected: the store did not answer the code application")
	}
	return w.RegistrationWriter.PresentVerificationCode(ctx, userID, digest, now, attempts)
}

func (w avVerificationWriter) ActivateInviteOnVerification(ctx context.Context, pending domain.User) (humansession.InviteActivation, error) {
	res, err := user.ActivateInviteOnVerificationTx(ctx, w.MirrorWriter(), pending, string(pending.ID))
	if err != nil {
		if errors.Is(err, iamerr.ErrInviteExpired) || errors.Is(err, iamerr.ErrNotFound) {
			return humansession.InviteActivation{}, humansession.ErrInviteNotValid
		}
		return humansession.InviteActivation{}, err
	}
	return humansession.InviteActivation{User: res.User, OwnerBindingID: res.OwnerBindingID}, nil
}

// avVerbs — глаголы слушателя стенда: настоящие варианты использования.
type avVerbs struct {
	*stubLane
	register  *registration.RegisterUseCase
	login     *humansession.LoginUseCase
	logout    *humansession.LogoutUseCase
	change    *humansession.ChangePasswordUseCase
	stepUp    *humansession.StepUpUseCase
	status    *humansession.SecondFactorStatusUseCase
	enroll    *humansession.EnrollSecondFactorUseCase
	confirmSF *humansession.ConfirmSecondFactorUseCase
	remove    *humansession.RemoveSecondFactorUseCase
	regen     *humansession.RegenerateBackupCodesUseCase
	recovery  *humansession.RequestRecoveryUseCase
	requestV  *humansession.RequestVerificationUseCase
	confirmV  *humansession.ConfirmVerificationUseCase
	position  *humansession.PositionUseCase
}

func (v avVerbs) RequestEmailVerification(ctx context.Context, b domain.SessionBearer) (humansession.RequestVerificationOutput, error) {
	return v.requestV.Execute(ctx, b)
}

func (v avVerbs) ConfirmEmailVerification(ctx context.Context, in humansession.ConfirmVerificationInput) (humansession.ConfirmVerificationOutput, error) {
	return v.confirmV.Execute(ctx, in)
}

func (v avVerbs) AddressPosition(ctx context.Context, b domain.SessionBearer) (humansession.Position, error) {
	return v.position.Execute(ctx, b)
}

func (v avVerbs) RequestRecovery(ctx context.Context, in humansession.RequestRecoveryInput) error {
	return v.recovery.Execute(ctx, in)
}

func (v avVerbs) Register(ctx context.Context, in registration.Input) (registration.Output, error) {
	return v.register.Execute(ctx, in)
}

func (v avVerbs) Login(ctx context.Context, in humansession.LoginInput) (humansession.LoginOutput, error) {
	return v.login.Execute(ctx, in)
}

func (v avVerbs) Logout(ctx context.Context, b domain.SessionBearer) (bool, error) {
	return v.logout.Execute(ctx, b)
}

func (v avVerbs) ChangePassword(ctx context.Context, in humansession.ChangePasswordInput) (humansession.ChangePasswordOutput, error) {
	return v.change.Execute(ctx, in)
}

func (v avVerbs) StepUp(ctx context.Context, in humansession.StepUpInput) (humansession.StepUpOutput, error) {
	return v.stepUp.Execute(ctx, in)
}

func (v avVerbs) SecondFactorStatus(ctx context.Context, in humansession.StatusInput) (humansession.StatusOutput, error) {
	return v.status.Execute(ctx, in)
}

func (v avVerbs) EnrollSecondFactor(ctx context.Context, in humansession.EnrollInput) (humansession.EnrollOutput, error) {
	return v.enroll.Execute(ctx, in)
}

func (v avVerbs) ConfirmSecondFactor(ctx context.Context, in humansession.ConfirmInput) (humansession.ConfirmOutput, error) {
	return v.confirmSF.Execute(ctx, in)
}

func (v avVerbs) RemoveSecondFactor(ctx context.Context, in humansession.RemoveSecondFactorInput) (humansession.RemoveSecondFactorOutput, error) {
	return v.remove.Execute(ctx, in)
}

func (v avVerbs) RegenerateBackupCodes(ctx context.Context, in humansession.RegenerateBackupCodesInput) (humansession.RegenerateBackupCodesOutput, error) {
	return v.regen.Execute(ctx, in)
}

// freshAddress — адрес, которого нет ни у кого.
func freshAddress(tag string) string {
	return "av-" + tag + "-" + strings.ToLower(ids.NewID("tst")[3:13]) + "@example.invalid"
}

// register — регистрация через слушатель, как её проходит человек (EV-01).
func (h *avLane) register(t *testing.T, email string) avSession {
	t.Helper()
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormRegister), nil)
	r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRegister,
		map[string]any{"email": email, "password": integrationPassword, "csrfToken": tok}, fwd(), ctxCk)
	require.Equal(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): регистрация %s: %s", email, r.body)
	var out struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &out))
	s := avSession{user: domain.UserID(out.User.ID), email: email,
		bearer: cookieNamed(r.cookies, loginlanehttp.CookieSession), form: cookieNamed(r.cookies, loginlanehttp.CookieForm)}
	require.NotEmpty(t, s.user, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): регистрация не назвала человека")
	require.NotNil(t, s.bearer, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): регистрация не выдала носитель")
	require.NotNil(t, s.form, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): регистрация не сменила контекст формы")
	return s
}

// loginReply — вход паролем через слушатель; ответ как есть.
func (h *avLane) loginReply(t *testing.T, email, password string) reply {
	t.Helper()
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathLogin,
		map[string]any{"email": email, "password": password, "csrfToken": tok}, fwd(), ctxCk)
}

// login — вход, выдавший сессию.
func (h *avLane) login(t *testing.T, s avSession) avSession {
	t.Helper()
	r := h.loginReply(t, s.email, integrationPassword)
	require.Equal(t, http.StatusOK, r.status, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вход %s: %s", s.email, r.body)
	out := s
	out.bearer = cookieNamed(r.cookies, loginlanehttp.CookieSession)
	out.form = cookieNamed(r.cookies, loginlanehttp.CookieForm)
	require.NotNil(t, out.bearer, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вход не выдал носитель")
	return out
}

// token — признак вида kind в контексте формы сессии. Вычисляется той же
// свёрткой, которой его судит слушатель (`humansession.FormToken`), а не
// выдачей csrf-глагола: вид глагола подтверждения до его появления в перечне
// глагол выдачи признака не принимает, и проба спросила бы не то.
func (h *avLane) token(s avSession, kind string) string {
	return humansession.FormToken(s.form.Value, domain.FormKind(kind))
}

// post — обращение под сессией; body без признака — как есть.
func (h *avLane) post(t *testing.T, s avSession, path string, body map[string]any) reply {
	t.Helper()
	cookies := []*http.Cookie{}
	if s.bearer != nil {
		cookies = append(cookies, s.bearer)
	}
	if s.form != nil {
		cookies = append(cookies, s.form)
	}
	return h.lane.do(t, h.c, http.MethodPost, path, body, fwd(), cookies...)
}

// requestLetter — запрос письма (Р6).
func (h *avLane) requestLetter(t *testing.T, s avSession) reply {
	t.Helper()
	return h.post(t, s, avPathRequest, map[string]any{"csrfToken": h.token(s, avFormRequest)})
}

// confirm — предъявление кода (Р6).
func (h *avLane) confirm(t *testing.T, s avSession, code string) reply {
	t.Helper()
	return h.post(t, s, avPathConfirm, map[string]any{"code": code, "csrfToken": h.token(s, avFormConfirm)})
}

// requireVerbs — ступень ВОЗМОЖНОСТИ: оба пути глагола смонтированы. 404 —
// честный красный (§10 приёмки: «пути verify-email* отвечают 404»).
func (h *avLane) requireVerbs(t *testing.T, id string) {
	t.Helper()
	probe := avSession{bearer: ghostBearer(t), form: &http.Cookie{Name: loginlanehttp.CookieForm, Value: "probe-context"}}
	for _, p := range []string{avPathRequest, avPathConfirm} {
		r := h.post(t, probe, p, map[string]any{})
		if r.status == http.StatusNotFound {
			t.Fatalf("%s ЧЕСТНЫЙ-КРАСНЫЙ: глагола подтверждения нет — %s отвечает 404: %s", id, p, r.body)
		}
	}
}

// avLetter — строка очереди письма подтверждения.
type avLetter struct {
	id      int64
	code    string
	minutes int
	to      string
}

// letters — строки очереди письма подтверждения этого человека, по порядку
// постановки.
func (h *avLane) letters(t *testing.T, user domain.UserID) []avLetter {
	t.Helper()
	rows, err := h.pool.Query(h.ctx, `
		SELECT id, coalesce(payload->>'code', ''), coalesce((payload->>'code_valid_minutes')::int, 0), coalesce(payload->>'to', '')
		  FROM kaname.invite_mail_outbox
		 WHERE event_type = $1 AND payload->>'user_id' = $2
		 ORDER BY id`, avMailKind, string(user))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): чтение очереди писем")
	defer rows.Close()
	var out []avLetter
	for rows.Next() {
		var l avLetter
		require.NoError(t, rows.Scan(&l.id, &l.code, &l.minutes, &l.to))
		out = append(out, l)
	}
	require.NoError(t, rows.Err())
	return out
}

// latestCode — код последнего письма; письма нет — красное сценария id.
func (h *avLane) latestCode(t *testing.T, id string, user domain.UserID) string {
	t.Helper()
	ls := h.letters(t, user)
	if len(ls) == 0 {
		t.Fatalf("%s ЧЕСТНЫЙ-КРАСНЫЙ: в очереди нет ни одной строки вида %s для %s", id, avMailKind, user)
	}
	return ls[len(ls)-1].code
}

// mark — отметка подтверждения посевом, писателем продукта.
func (h *avLane) mark(t *testing.T, s avSession) {
	t.Helper()
	require.NoError(t, h.methods.MarkEmailVerified(journalfixture.Writing(h.ctx), s.user, domain.Email(s.email), h.clock.Now()),
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев отметки")
}

// unmark — снятие отметки БЕЗ смены адреса (посев G3 круга 1 приёмки).
func (h *avLane) unmark(t *testing.T, user domain.UserID) {
	t.Helper()
	_, err := h.pool.Exec(h.ctx, `UPDATE kaname.users SET email_verified_at = NULL WHERE id = $1`, string(user))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): снятие отметки посевом")
}

// markedAt — момент отметки в строке человека; нет — ok=false.
func (h *avLane) markedAt(t *testing.T, user domain.UserID) (time.Time, bool) {
	t.Helper()
	var at *time.Time
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT email_verified_at FROM kaname.users WHERE id = $1`, string(user)).Scan(&at))
	if at == nil {
		return time.Time{}, false
	}
	return *at, true
}

// resolve — ответ службы краю о носителе.
func (h *avLane) resolve(t *testing.T, bearer *http.Cookie) *iamv1.ResolveHumanSessionResponse {
	t.Helper()
	return resolveOver(t, h.resolver, bearer.Value)
}

// endReason — причина конца записи сессии по носителю; запись жива — "".
func (h *avLane) endReason(t *testing.T, bearer *http.Cookie) string {
	t.Helper()
	var reason *string
	err := h.pool.QueryRow(h.ctx, `SELECT ended_reason FROM kaname.human_sessions WHERE bearer_digest = $1`,
		string(domain.PresentedSessionBearer(bearer.Value).Digest())).Scan(&reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return "<no row>"
	}
	require.NoError(t, err)
	if reason == nil {
		return ""
	}
	return *reason
}

// endReasonByID — то же по идентификатору записи.
func (h *avLane) endReasonByID(t *testing.T, id string) string {
	t.Helper()
	var reason *string
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT ended_reason FROM kaname.human_sessions WHERE id = $1`, id).Scan(&reason))
	if reason == nil {
		return ""
	}
	return *reason
}

// auditEvents — события аудита данного вида о человеке.
func (h *avLane) auditEvents(t *testing.T, eventType string, user domain.UserID) []map[string]any {
	t.Helper()
	rows, err := h.pool.Query(h.ctx, `
		SELECT event_payload FROM kaname.audit_outbox
		 WHERE event_type = $1 AND event_payload->>'user_id' = $2 ORDER BY created_at, id`, eventType, string(user))
	require.NoError(t, err)
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var raw []byte
		require.NoError(t, rows.Scan(&raw))
		var m map[string]any
		require.NoError(t, json.Unmarshal(raw, &m))
		out = append(out, m)
	}
	require.NoError(t, rows.Err())
	return out
}

// refusal — разобранное тело отказа полосы.
type avRefusal struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details []struct {
		Type   string `json:"@type"`
		Reason string `json:"reason"`
		Domain string `json:"domain"`
	} `json:"details"`
}

func parseRefusal(t *testing.T, body string) avRefusal {
	t.Helper()
	var r avRefusal
	require.NoError(t, json.Unmarshal([]byte(body), &r), "тело отказа не разбирается: %s", body)
	return r
}

func (r avRefusal) reason() string {
	if len(r.Details) == 0 {
		return ""
	}
	return r.Details[0].Reason
}

// sessionEmailVerified — поле `session.emailVerified` тела ответа.
func sessionEmailVerified(t *testing.T, body string) (bool, bool) {
	t.Helper()
	var out struct {
		Session map[string]any `json:"session"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &out), body)
	v, ok := out.Session["emailVerified"].(bool)
	return v, ok
}

func toString(v any) string { return fmt.Sprint(v) }

func jsonUnmarshal(body string, into any) error { return json.Unmarshal([]byte(body), into) }

func sortStrings(s []string) { sort.Strings(s) }
