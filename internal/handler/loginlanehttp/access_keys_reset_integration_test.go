// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_keys_reset_integration_test.go — сброс ключей доступа человека
// администратором облака на НАСТОЯЩЕЙ базе (задача PRO-Robotech/kaname#638;
// приёмка `docs/engineering/acceptance/cloud-administrator-resets-login-methods.md`,
// редакция 5, отпечаток 120ae199…; сценарии LMR-01, -02, -04…-07, -09).
//
// # Что наблюдается
//
// «Дано» строится действием продукта: личность с паролем — регистрацией полосы
// пароля, сессии — входом через слушатель, второй фактор — глаголами заведения
// и подтверждения, ключи — писателем продукта (`InsertKey`) либо настоящей
// регистрацией (`access_keys.FinishRegistrationUseCase`). Сброс — НАСТОЯЩИМ
// глаголом `user.ResetAccessKeysUseCase` над адаптерами базы, теми же, что
// провязывает корень композиции.
//
// Сессия «отсечена» судится тем же правилом, каким край судит предъявление:
// жива, только если момент аутентификации записи ПОЗЖЕ отсечки личности
// (`RevokedBefore`, сравнение включающее). Сессия, выданная после сброса, —
// вход паролем, который сброс не трогает (Р3, Р8): проба сама проверяет, что
// запись резолвится и её момент позже отсечки.
//
// Снимок способа входа — строка пароля (её байты сравниваются хешем строки в
// базе, значение в журнал не выводится), отметка открытого пути и статус;
// сверка — равенство снимков, а не «ошибки нет».
//
// Run: `go test ./internal/handler/loginlanehttp/ -run ResetAccessKeys -count=1` (Docker).
// Skipped under -short.
package loginlanehttp_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// Имена приёмки — литералами: проба судит контракт, а не константу, которую
// правит тот же автор.
const (
	lmrReason      = "access-keys-reset"
	lmrEvent       = "iam.user.access_keys_reset"
	lmrToken       = "ACCESS_KEYS_NOT_ENROLLED"
	lmrRefusalText = "user has no access key to reset"
)

// lmrStore — порт писателя сброса над адаптером базы: соответствие закрепляется
// здесь, как в корне композиции. gate — точка, в которой писатель ждёт, пока
// названное число сбросов не дойдёт до открытия транзакции (гонка LMR-07 (а)):
// оба исполнителя прошли синхронную сверку раньше, чем любой из них снял ключи.
//
// window — окно между началом исполнения сброса и захватом строки личности
// (гонка LMR-07 (в)): писатель сообщает о приходе и ждёт, пока проба не
// исполнит в этом окне вход ключом до фиксации.
type lmrStore struct {
	keys   *kanamepg.AccessKeyRepo
	gate   *lmrBarrier
	window *lmrWindow
}

func (s lmrStore) ResetWriter(ctx context.Context, userID domain.UserID) (userapp.AccessKeysResetWriter, error) {
	if s.gate != nil {
		s.gate.arrive()
	}
	if s.window != nil {
		s.window.hold()
	}
	w, err := s.keys.AccessKeysResetWriter(ctx, userID)
	if err != nil {
		return nil, err
	}
	return w, nil
}

// lmrBarrier — n участников ждут друг друга (со сроком: зависание — отказ пробы,
// а не вечный прогон).
type lmrBarrier struct {
	mu      sync.Mutex
	n       int
	arrived int
	all     chan struct{}
}

func newLMRBarrier(n int) *lmrBarrier { return &lmrBarrier{n: n, all: make(chan struct{})} }

func (b *lmrBarrier) arrive() {
	b.mu.Lock()
	b.arrived++
	if b.arrived == b.n {
		close(b.all)
	}
	b.mu.Unlock()
	select {
	case <-b.all:
	case <-time.After(20 * time.Second):
	}
}

// lmrWindow — окно до захвата строки личности сбросом: arrived закрывается,
// когда исполнитель сброса дошёл до открытия транзакции, release — когда проба
// исполнила встречное действие (со сроком: зависание — отказ пробы).
type lmrWindow struct {
	once    sync.Once
	arrived chan struct{}
	release chan struct{}
}

func newLMRWindow() *lmrWindow {
	return &lmrWindow{arrived: make(chan struct{}), release: make(chan struct{})}
}

func (w *lmrWindow) hold() {
	w.once.Do(func() { close(w.arrived) })
	select {
	case <-w.release:
	case <-time.After(20 * time.Second):
	}
}

// adminCtx — личность администратора облака, как её передаёт край (право
// судит край по записи каталога — LMR-03, пакет `internal/service`).
func adminCtx(ctx context.Context, admin domain.UserID) context.Context {
	return operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: string(admin)})
}

// resetUC — глагол сброса над адаптерами базы.
func (h *sessionLane) resetUC(gate *lmrBarrier) *userapp.ResetAccessKeysUseCase {
	return h.resetUCOver(lmrStore{keys: kanamepg.NewAccessKeyRepo(h.pool), gate: gate})
}

// resetUCOver — глагол сброса над названным швом писателя.
func (h *sessionLane) resetUCOver(s lmrStore) *userapp.ResetAccessKeysUseCase {
	return userapp.NewResetAccessKeysUseCase(h.users, operations.NewRepo(h.pool, "kaname"),
		kanamepg.NewLoginMethodRepo(h.pool), s)
}

// awaitOp — принятая операция дожидается исполнителя (событием очереди, не
// сроком) и возвращается терминальной.
func (h *sessionLane) awaitOp(t *testing.T, id string) *operations.Operation {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(h.ctx, 30*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx), "НЕ ВЫПОЛНИЛОСЬ: исполнитель операций не завершил очередь")
	got, err := operations.NewRepo(h.pool, "kaname").Get(h.ctx, id)
	require.NoErrorf(t, err, "НЕ ВЫПОЛНИЛОСЬ: операция %s не прочитана", id)
	require.Truef(t, got.Done, "операция %s не терминальна", id)
	return got
}

// resetKeys — сброс ключей user администратором admin; синхронный отказ — как есть.
func (h *sessionLane) resetKeys(t *testing.T, admin, user domain.UserID) (*operations.Operation, error) {
	t.Helper()
	op, err := h.resetUC(nil).Execute(adminCtx(h.ctx, admin), user)
	if err != nil {
		return nil, err
	}
	return h.awaitOp(t, op.ID), nil
}

// requireResetDone — сброс исполнен без ошибки, ответ — личность цели.
func (h *sessionLane) requireResetDone(t *testing.T, admin, user domain.UserID, what string) {
	t.Helper()
	op, err := h.resetKeys(t, admin, user)
	require.NoErrorf(t, err, "%s: синхронный отказ сброса", what)
	require.Nilf(t, op.Error, "%s: сброс завершён ошибкой: %v", what, op.Error)
	require.NotNilf(t, op.Response, "%s: операция без ответа", what)
	require.Containsf(t, op.Description, "Reset access keys", "%s: описание операции", what)
}

// keysOf — строк ключей человека.
func (h *sessionLane) keysOf(t *testing.T, user domain.UserID) int {
	t.Helper()
	var n int
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM user_access_keys WHERE user_id = $1`, string(user)).Scan(&n))
	return n
}

// keySlots — занятые слоты потолка ключей человека (счётчик триггера).
func (h *sessionLane) keySlots(t *testing.T, user domain.UserID) int64 {
	t.Helper()
	var used int64
	err := h.pool.QueryRow(h.ctx, `
		SELECT COALESCE((SELECT used FROM project_resource_quotas
		                  WHERE carrier_type = 'iam.user' AND carrier_id = $1 AND kind = 'iam.user.accessKey'), 0)`,
		string(user)).Scan(&used)
	require.NoError(t, err)
	return used
}

// lmrCutoff — отсечка личности: момент, причина, решивший; found=false — нет.
type lmrCutoff struct {
	at     time.Time
	reason string
	by     string
	found  bool
}

func (h *sessionLane) cutoffOf(t *testing.T, user domain.UserID) lmrCutoff {
	t.Helper()
	var c lmrCutoff
	var by *string
	err := h.pool.QueryRow(h.ctx, `SELECT revoke_before, reason, revoked_by_user_id FROM user_token_revocations WHERE user_id = $1`,
		string(user)).Scan(&c.at, &c.reason, &by)
	if err != nil {
		return lmrCutoff{}
	}
	c.found = true
	if by != nil {
		c.by = *by
	}
	return c
}

// resetEvents — событий сброса с субъектом user.
func (h *sessionLane) resetEvents(t *testing.T, user domain.UserID) int {
	t.Helper()
	var n int
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM audit_outbox WHERE event_type = $1 AND event_payload->>'user_id' = $2`,
		lmrEvent, string(user)).Scan(&n))
	return n
}

// cutBySubjectCutoff — запись сессии носителя покрыта отсечкой личности тем же
// правилом, что у края: момент аутентификации НЕ позже отсечки.
func (h *sessionLane) cutBySubjectCutoff(t *testing.T, user domain.UserID, bearer string) bool {
	t.Helper()
	var auth time.Time
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT authenticated_at FROM human_sessions WHERE bearer_digest = $1`,
		string(domain.PresentedSessionBearer(bearer).Digest())).Scan(&auth))
	at, found, err := kanamepg.NewUserTokenRevocationRepo(h.pool).RevokedBefore(h.ctx, string(user))
	require.NoError(t, err)
	return found && !auth.After(at)
}

// alive — носитель годен краю: запись резолвится и отсечкой не покрыта.
func (h *sessionLane) alive(t *testing.T, user domain.UserID, bearer string) bool {
	t.Helper()
	return h.resolve(t, bearer).GetFound() && !h.cutBySubjectCutoff(t, user, bearer)
}

// wayIn — снимок способа входа (§5 «Снимок»).
type wayIn struct {
	passwordRow string // хеш строки пароля целиком; "" — строки нет
	open        bool
	status      string
}

func (h *sessionLane) wayInOf(t *testing.T, user domain.UserID) wayIn {
	t.Helper()
	var s wayIn
	require.NoError(t, h.pool.QueryRow(h.ctx, `
		SELECT COALESCE((SELECT md5(m::text) FROM user_login_methods m WHERE m.user_id = u.id AND m.kind = 'password'), ''),
		       u.recovery_path_opened_at IS NOT NULL, u.invite_status
		  FROM users u WHERE u.id = $1`, string(user)).Scan(&s.passwordRow, &s.open, &s.status))
	return s
}

// secondFactorRows — хеш строк второго фактора личности (`totp`, `lookup_secret`).
func (h *sessionLane) secondFactorRows(t *testing.T, user domain.UserID) string {
	t.Helper()
	var s string
	require.NoError(t, h.pool.QueryRow(h.ctx, `
		SELECT COALESCE(string_agg(md5(m::text), ',' ORDER BY m.kind), '')
		  FROM user_login_methods m WHERE m.user_id = $1 AND m.kind IN ('totp', 'lookup_secret')`, string(user)).Scan(&s))
	return s
}

// openPathOf — личность приводится к форме «после переноса»: без пароля, с
// отметкой открытого пути, одной транзакцией (иначе фиксацию отвергнет база).
func (h *sessionLane) openPathOf(t *testing.T, user domain.UserID) {
	t.Helper()
	tx, err := h.pool.Begin(h.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(h.ctx) }()
	_, err = tx.Exec(h.ctx, `DELETE FROM user_login_methods WHERE user_id = $1`, string(user))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): снятие строки пароля")
	_, err = tx.Exec(h.ctx, `UPDATE users SET email_verified_at = NULL, recovery_path_opened_at = now() WHERE id = $1`, string(user))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): отметка пути")
	require.NoError(t, tx.Commit(h.ctx), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев формы «после переноса» отвергнут")
}

// statusOf — состояние личности писателем продукта (им же пишут Block/Unblock).
func (h *sessionLane) statusOf(t *testing.T, user domain.UserID, st domain.InviteStatus) {
	t.Helper()
	w, err := h.users.Writer(h.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(h.ctx) }()
	_, err = w.UsersW().SetInviteStatus(h.ctx, user, st)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): состояние %s", st)
	require.NoError(t, w.Commit(h.ctx))
}

// loginReply — попытка входа адресом email паролем password; исход судит проба.
func (h *sessionLane) loginReply(t *testing.T, email, password string) reply {
	t.Helper()
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathLogin,
		map[string]any{"email": email, "password": password, "csrfToken": tok}, fwd(), ctxCk)
}

// sessionAfter — сессия, выданная после сброса: вход паролем; проба сама
// проверяет, что запись резолвится и её момент позже отсечки (иначе —
// «фикстура», а не «по существу»).
func (h *sessionLane) sessionAfter(t *testing.T, user domain.UserID) laneSession {
	t.Helper()
	s := h.login(t, integrationPassword)
	require.True(t, h.resolve(t, s.bearer.Value).GetFound(), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): сессия-после резолвится")
	require.False(t, h.cutBySubjectCutoff(t, user, s.bearer.Value), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): сессия-после позже отсечки")
	return s
}

// keyDeps — зависимости глаголов ключа над адаптерами базы, как в корне.
func (h *sessionLane) keyDeps() access_keys.Deps {
	return access_keys.Deps{
		Store:           kanamepg.NewAccessKeyRepo(h.pool),
		Freshness:       kanamepg.NewHumanSessionFreshness(h.pool),
		Methods:         kanamepg.NewLoginMethodRepo(h.pool),
		Binding:         laneKeyBinding(),
		FreshnessWindow: laneFreshness,
		Now:             time.Now,
	}
}

// presentKey — предъявление ключа k человеком user (Ф7): испытание и сверка
// настоящими глаголами; возвращает перечень удостоверений испытания и исход.
func (h *sessionLane) presentKey(t *testing.T, user domain.UserID, auth *webauthntest.Authenticator) (int, error) {
	t.Helper()
	begin, err := access_keys.NewBeginAssertionUseCase(h.keyDeps())
	require.NoError(t, err)
	finish, err := access_keys.NewFinishAssertionUseCase(h.keyDeps())
	require.NoError(t, err)
	ch, err := begin.Execute(h.ctx, access_keys.BeginAssertionInput{UserID: user})
	require.NoError(t, err, "испытание предъявления выдано")
	as := auth.Assert(t, webauthntest.AssertionOptions{Challenge: ch.Challenge, Origin: akProbeOrigin, RPID: akProbeRPID})
	_, err = finish.Execute(h.ctx, access_keys.FinishAssertionInput{
		UserID: user, CredentialID: as.CredentialID, ClientDataJSON: as.ClientDataJSON,
		AuthenticatorData: as.AuthenticatorData, Signature: as.Signature,
	})
	return len(ch.AllowCredentials), err
}

// pendingRegistration — выданное испытание регистрации и собранный на нём
// результат подставного аутентификатора (Ф7-01): регистрация ждёт завершения.
type pendingRegistration struct {
	in access_keys.FinishRegistrationInput
}

func (h *sessionLane) beginRegistration(t *testing.T, user domain.UserID) pendingRegistration {
	t.Helper()
	begin, err := access_keys.NewBeginRegistrationUseCase(h.keyDeps())
	require.NoError(t, err)
	out, err := begin.Execute(h.ctx, access_keys.BeginRegistrationInput{UserID: user, Actor: user})
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): испытание регистрации выдано")
	auth := webauthntest.New(t, webauthntest.AlgES256)
	cdj, att := auth.Register(t, webauthntest.RegistrationOptions{Challenge: out.Challenge, Origin: akProbeOrigin, RPID: akProbeRPID})
	rk := true
	return pendingRegistration{in: access_keys.FinishRegistrationInput{
		UserID: user, Actor: user, CredentialID: auth.CredentialID(), ClientDataJSON: cdj, AttestationObject: att, Discoverable: &rk,
	}}
}

// finishRegistration — завершение регистрации настоящим глаголом; синхронный
// отказ — как есть, принятая операция — её исход.
func (h *sessionLane) finishRegistration(t *testing.T, p pendingRegistration) (*operations.Operation, error) {
	t.Helper()
	uc, err := access_keys.NewFinishRegistrationUseCase(h.keyDeps(), operations.NewRepo(h.pool, "kaname"))
	require.NoError(t, err)
	op, err := uc.Execute(h.ctx, p.in)
	if err != nil {
		return nil, err
	}
	return h.awaitOp(t, op.ID), nil
}

// TestResetAccessKeys_LMR01_KeysGoneSessionsCutPasswordAndFactorKept — LMR-01:
// у человека с паролем, двумя ключами и вторым фактором сброс снимает ключи и
// гасит обе сессии; пароль и фактор целы; снятый ключ неотличим от неизвестного.
func TestResetAccessKeys_LMR01_KeysGoneSessionsCutPasswordAndFactorKept(t *testing.T) {
	h := newSessionLane(t)
	admin := registerPerson(t, h, "lmr01-admin")
	u := h.user.ID
	_, backup, _ := h.enrolledSecondFactor(t)
	kA := givenAcceptedKey(t, h, u)
	givenAcceptedKey(t, h, u)
	s1 := h.login(t, integrationPassword)
	pre := h.login(t, integrationPassword)
	up := h.stepUpCode(t, pre, "lookup_secret", backup[0], h.csrfFor(t, domain.FormStepUp, pre.form))
	require.Equalf(t, http.StatusOK, up.status, "Дано: сессия «2» подъёмом: %s", up.body)
	s2 := cookieNamed(up.cookies, loginlanehttp.CookieSession)
	require.NotNil(t, s2, "Дано: подъём выдал носитель")
	row, ok := h.rowByBearer(t, s2.Value)
	require.True(t, ok)
	require.Equal(t, "2", row.level, "Дано: вторая сессия уровня «2»")

	// Положительный контроль наблюдения — до сброса.
	require.Equal(t, 2, h.keysOf(t, u), "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: два ключа до сброса")
	require.EqualValues(t, 2, h.keySlots(t, u), "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: два слота потолка заняты")
	require.True(t, h.alive(t, u, s1.bearer.Value), "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: сессия «1» годна")
	require.True(t, h.alive(t, u, s2.Value), "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: сессия «2» годна")
	creds, err := h.presentKey(t, u, kA.auth)
	require.NoError(t, err, "близнец по одному факту: ДО сброса тот же ключ предъявляется успешно (Ф7-06)")
	require.Equal(t, 2, creds)
	snapBefore := h.wayInOf(t, u)
	require.NotEmpty(t, snapBefore.passwordRow, "Дано: строка пароля есть")
	sfBefore := h.secondFactorRows(t, u)
	require.NotEmpty(t, sfBefore, "Дано: строки второго фактора есть")

	before := time.Now().UTC()
	h.requireResetDone(t, admin, u, "LMR-01")

	require.Zero(t, h.keysOf(t, u), "LMR-01: строк ключей ноль")
	require.Zero(t, h.keySlots(t, u), "LMR-01: слоты потолка возвращены")
	require.False(t, h.alive(t, u, s1.bearer.Value), "LMR-01: сессия «1» отсечена")
	require.False(t, h.alive(t, u, s2.Value), "LMR-01: сессия «2» отсечена")
	cut := h.cutoffOf(t, u)
	require.True(t, cut.found, "LMR-01: отсечка записана")
	require.Equal(t, lmrReason, cut.reason, "LMR-01: причина отсечки")
	require.Equal(t, string(admin), cut.by, "LMR-01: актор отсечки — администратор")
	require.False(t, cut.at.Before(before.Truncate(time.Microsecond)), "LMR-01: отсечка моментом now")
	require.Equal(t, 1, h.resetEvents(t, u), "LMR-01: событие ровно одно")
	var payload string
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT event_payload::text FROM audit_outbox WHERE event_type = $1 AND event_payload->>'user_id' = $2`, lmrEvent, string(u)).Scan(&payload))
	require.Contains(t, payload, `"actor": "`+string(admin)+`"`)
	require.Contains(t, payload, `"reason": "`+lmrReason+`"`)
	require.NotContains(t, payload, h.email, "в событии нет адреса")

	// Пароль сброс не тронул: вход прежним паролем выдаёт новую сессию «1».
	after := h.sessionAfter(t, u)
	afterRow, ok := h.rowByBearer(t, after.bearer.Value)
	require.True(t, ok)
	require.Equal(t, "1", afterRow.level, "LMR-01: вход прежним паролем — сессия «1»")
	require.Equal(t, snapBefore, h.wayInOf(t, u), "LMR-01: снимок способа входа после сброса равен снимку до него")
	require.Equal(t, sfBefore, h.secondFactorRows(t, u), "LMR-01: строки второго фактора те же")

	// Снятый ключ — тот же единый отказ, что у неизвестного удостоверения.
	creds, errRemoved := h.presentKey(t, u, kA.auth)
	require.Error(t, errRemoved, "LMR-01: снятый ключ не предъявляется")
	require.Zero(t, creds, "LMR-01: перечень удостоверений испытания пуст")
	_, errUnknown := h.presentKey(t, u, webauthntest.New(t, webauthntest.AlgES256))
	require.Error(t, errUnknown)
	require.Equal(t, status.Code(errUnknown), status.Code(errRemoved), "LMR-01: код отказа как у неизвестного удостоверения")
	require.True(t, proto.Equal(status.Convert(errUnknown).Proto(), status.Convert(errRemoved).Proto()),
		"LMR-01: отказ по снятому ключу побайтово равен отказу по неизвестному: %v / %v", errRemoved, errUnknown)
}

// TestResetAccessKeys_LMR02_PersonWithoutPasswordKeepsTheOpenPath — LMR-02:
// личность без пароля с отметкой открытого пути: сняты ключи, и только они.
func TestResetAccessKeys_LMR02_PersonWithoutPasswordKeepsTheOpenPath(t *testing.T) {
	h := newSessionLane(t)
	admin := registerPerson(t, h, "lmr02-admin")
	p := h.user.ID
	h.openPathOf(t, p)
	givenAcceptedKey(t, h, p)
	var live string
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT bearer_digest FROM human_sessions WHERE user_id = $1 AND ended_at IS NULL LIMIT 1`, string(p)).Scan(&live),
		"Дано: живая сессия личности (выдана регистрацией)")
	snapBefore := h.wayInOf(t, p)
	require.Equal(t, wayIn{passwordRow: "", open: true, status: "ACTIVE"}, snapBefore, "Дано: ACTIVE без пароля, путь открыт")

	h.requireResetDone(t, admin, p, "LMR-02")

	require.Zero(t, h.keysOf(t, p), "LMR-02: строк ключей ноль")
	require.Zero(t, h.keySlots(t, p), "LMR-02: слот возвращён")
	cut := h.cutoffOf(t, p)
	require.True(t, cut.found)
	require.Equal(t, lmrReason, cut.reason, "LMR-02: отсечка причиной сброса")
	var auth time.Time
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT authenticated_at FROM human_sessions WHERE bearer_digest = $1`, live).Scan(&auth))
	require.False(t, auth.After(cut.at), "LMR-02: живая сессия покрыта отсечкой")
	require.Equal(t, 1, h.resetEvents(t, p), "LMR-02: событие одно")
	require.Equal(t, snapBefore, h.wayInOf(t, p), "LMR-02: снимок неизменен — строки пароля нет, отметка на месте, ACTIVE")
}

// TestResetAccessKeys_LMR04_NothingToResetRefusesSynchronously — LMR-04: у
// человека с паролем без ключей и у приглашённого без способов — один и тот же
// синхронный отказ; ничего не тронуто. Близнец — у цели есть ключ.
func TestResetAccessKeys_LMR04_NothingToResetRefusesSynchronously(t *testing.T) {
	h := newSessionLane(t)
	admin := registerPerson(t, h, "lmr04-admin")
	u := h.user.ID
	givenAcceptedKey(t, h, u)
	h.requireResetDone(t, admin, u, "LMR-04 близнец: у цели есть ключ")
	cutU := h.cutoffOf(t, u)
	snapU := h.wayInOf(t, u)
	require.NotEmpty(t, snapU.passwordRow, "Дано: у U строка пароля есть")

	v := domain.UserID(ids.NewID(domain.PrefixUser))
	acc := ids.NewID(domain.PrefixAccount)
	tx, err := h.pool.Begin(h.ctx)
	require.NoError(t, err)
	_, err = tx.Exec(h.ctx, `INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, '', $3, 'V', 'PENDING')`, string(v), acc, "v-"+strings.ToLower(string(v)[4:12])+"@example.invalid")
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): приглашённая личность")
	_, err = tx.Exec(h.ctx, `INSERT INTO accounts (id, name, owner_user_id, labels) VALUES ($1, $2, $3, '{}'::jsonb)`,
		acc, "acc-"+strings.ToLower(acc[4:12]), string(v))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): аккаунт приглашённой")
	require.NoError(t, tx.Commit(h.ctx), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев V")
	snapV := h.wayInOf(t, v)
	require.Empty(t, snapV.passwordRow, "Дано: у V строки пароля нет")

	opsBefore := h.opsOf(t)
	var refusals []error
	for _, target := range []domain.UserID{u, v} {
		op, err := h.resetUC(nil).Execute(adminCtx(h.ctx, admin), target)
		require.Errorf(t, err, "LMR-04: сброс %s отвергнут", target)
		require.Nil(t, op, "LMR-04: Operation не порождена")
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		require.Equal(t, lmrRefusalText, status.Convert(err).Message())
		require.Equal(t, lmrToken, rsfReasonOf(t, err))
		refusals = append(refusals, err)
	}
	require.True(t, proto.Equal(status.Convert(refusals[0]).Proto(), status.Convert(refusals[1]).Proto()),
		"LMR-04: отказы U и V побайтово равны — наличие пароля исхода не меняет")
	require.Equal(t, opsBefore, h.opsOf(t), "LMR-04: новых операций нет")
	require.Equal(t, cutU, h.cutoffOf(t, u), "LMR-04: отсечка U прежняя")
	require.False(t, h.cutoffOf(t, v).found, "LMR-04: у V отсечки нет")
	require.Equal(t, 1, h.resetEvents(t, u), "LMR-04: новых событий у U нет")
	require.Zero(t, h.resetEvents(t, v), "LMR-04: событий у V нет")
	require.Equal(t, snapU, h.wayInOf(t, u))
	require.Equal(t, snapV, h.wayInOf(t, v))
}

// opsOf — число строк операций.
func (h *sessionLane) opsOf(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM operations`).Scan(&n))
	return n
}

// opReasonOf — `ErrorInfo.reason` ошибки операции.
func opReasonOf(t *testing.T, op *operations.Operation) string {
	t.Helper()
	for _, d := range op.Error.GetDetails() {
		var ei errdetails.ErrorInfo
		if d.UnmarshalTo(&ei) == nil {
			return ei.GetReason()
		}
	}
	return ""
}

// rsfReasonOf — `ErrorInfo.reason` отказа.
func rsfReasonOf(t *testing.T, err error) string {
	t.Helper()
	for _, d := range status.Convert(err).Details() {
		if ei, ok := d.(interface{ GetReason() string }); ok {
			return ei.GetReason()
		}
	}
	return ""
}

// TestResetAccessKeys_LMR05_RecoveryReturnsTheWayIn — LMR-05: после сброса
// человек восстанавливает доступ, входит и заводит новый ключ; (а) пароль есть —
// материал заменён; (б) пароля нет — первый пароль заведён, отметка снята.
func TestResetAccessKeys_LMR05_RecoveryReturnsTheWayIn(t *testing.T) {
	t.Run("(а) с паролем", func(t *testing.T) {
		h := newSessionLane(t)
		admin := registerPerson(t, h, "lmr05a-admin")
		u := h.user.ID
		require.NoError(t, kanamepg.NewLoginMethodRepo(h.pool).MarkEmailVerified(h.ctx, u, domain.Email(h.email), time.Now().UTC()),
			"НЕ-ВЫПОЛНИЛОСЬ(фикстура): адрес подтверждён")
		givenAcceptedKey(t, h, u)
		h.requireResetDone(t, admin, u, "LMR-05 (а)")
		before := h.wayInOf(t, u)
		old := h.sessionAfter(t, u)
		require.Equal(t, http.StatusOK, h.loginReply(t, h.email, integrationPassword).status,
			"LMR-05 пара с LMR-01: ДО восстановления прежний пароль проходит")

		const src = "203.0.113.138"
		r, ctxCk := h.requestCodeFrom(t, h.email, src)
		require.Equal(t, http.StatusOK, r.status, "LMR-05 (а): запрос кода: %s", r.body)
		code := h.lastRecoveryCode(t, u)
		const fresh = "a-new-password-after-reset-638"
		done := h.completeRecovery(t, code, fresh, map[string]string{loginlanehttp.HeaderForwardedFor: src}, ctxCk)
		require.Equal(t, http.StatusOK, done.status, "LMR-05 (а): завершение выдаёт сессию: %s", done.body)

		after := h.wayInOf(t, u)
		require.NotEmpty(t, after.passwordRow, "LMR-05 (а): строка пароля на месте")
		require.NotEqual(t, before.passwordRow, after.passwordRow, "LMR-05 (а): материал пароля заменён")
		require.False(t, h.alive(t, u, old.bearer.Value), "LMR-05 (а): сессия, выданная до завершения, отсечена")
		require.Equal(t, "password-change", h.cutoffOf(t, u).reason, "LMR-05 (а): причина отсечки — смена пароля")

		oldTry := h.loginReply(t, h.email, integrationPassword)
		wrong := h.loginReply(t, h.email, laneWrongPassword)
		require.Equal(t, http.StatusUnauthorized, oldTry.status, "LMR-05 (а): прежний пароль после восстановления — отказ")
		require.Equal(t, wrong.status, oldTry.status)
		require.Equal(t, wrong.body, oldTry.body, "LMR-05 (а): отказ побайтово равен отказу по неверному паролю")
		require.Contains(t, oldTry.body, "authentication failed")
		s := h.login(t, fresh)
		row, ok := h.rowByBearer(t, s.bearer.Value)
		require.True(t, ok)
		require.Equal(t, "1", row.level, "LMR-05 (а): вход новым паролем — уровень «1»")

		op, err := h.finishRegistration(t, h.beginRegistration(t, u))
		require.NoError(t, err, "LMR-05 (а): регистрация ключа принята")
		require.Nil(t, op.Error, "LMR-05 (а): регистрация исполнена: %v", op.Error)
		require.Equal(t, 1, h.keysOf(t, u), "LMR-05 (а): ключ один")
	})

	t.Run("(б) без пароля с открытым путём", func(t *testing.T) {
		h := newSessionLane(t)
		admin := registerPerson(t, h, "lmr05b-admin")
		p := h.user.ID
		h.openPathOf(t, p)
		givenAcceptedKey(t, h, p)
		h.requireResetDone(t, admin, p, "LMR-05 (б)")
		require.Equal(t, wayIn{passwordRow: "", open: true, status: "ACTIVE"}, h.wayInOf(t, p), "Дано: P после сброса")

		const src = "203.0.113.139"
		r, ctxCk := h.requestCodeFrom(t, h.email, src)
		require.Equal(t, http.StatusOK, r.status, "LMR-05 (б): запрос кода: %s", r.body)
		code := h.lastRecoveryCode(t, p)
		const fresh = "b-first-password-after-reset-638"
		done := h.completeRecovery(t, code, fresh, map[string]string{loginlanehttp.HeaderForwardedFor: src}, ctxCk)
		require.Equal(t, http.StatusOK, done.status, "LMR-05 (б): завершение выдаёт сессию: %s", done.body)
		got := h.wayInOf(t, p)
		require.NotEmpty(t, got.passwordRow, "LMR-05 (б): первый пароль заведён")
		require.False(t, got.open, "LMR-05 (б): отметка снята")
		require.Equal(t, "ACTIVE", got.status)
		var verified bool
		require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT email_verified_at IS NOT NULL FROM users WHERE id = $1`, string(p)).Scan(&verified))
		require.True(t, verified, "LMR-05 (б): адрес подтверждён той же транзакцией")
		h.login(t, fresh)
	})
}

// TestResetAccessKeys_LMR06_SecondFactorAndBlockSurvive — LMR-06: фактор и
// блокировка сбросом не тронуты.
func TestResetAccessKeys_LMR06_SecondFactorAndBlockSurvive(t *testing.T) {
	h := newSessionLane(t)
	admin := registerPerson(t, h, "lmr06-admin")
	u := h.user.ID

	// (а) фактор пережил сброс: подъём кодом из сессии-после.
	_, backup, _ := h.enrolledSecondFactor(t)
	givenAcceptedKey(t, h, u)
	h.requireResetDone(t, admin, u, "LMR-06 (а)")
	s := h.sessionAfter(t, u)
	up := h.stepUpCode(t, s, "lookup_secret", backup[1], h.csrfFor(t, domain.FormStepUp, s.form))
	require.Equalf(t, http.StatusOK, up.status, "LMR-06 (а): подъём проходит: %s", up.body)
	fresh := cookieNamed(up.cookies, loginlanehttp.CookieSession)
	require.NotNil(t, fresh)
	row, ok := h.rowByBearer(t, fresh.Value)
	require.True(t, ok)
	require.Equal(t, "2", row.level, "LMR-06 (а): сессия — «2»")

	// (б) блокировка пережила сброс; близнец — LMR-01 (не заблокирован).
	b := registerPerson(t, h, "lmr06-blocked")
	givenAcceptedKey(t, h, b)
	h.statusOf(t, b, domain.InviteStatusBlocked)
	snap := h.wayInOf(t, b)
	h.requireResetDone(t, admin, b, "LMR-06 (б)")
	require.Zero(t, h.keysOf(t, b), "LMR-06 (б): ключей ноль")
	rd, err := h.users.Reader(h.ctx)
	require.NoError(t, err)
	got, err := rd.Users().Get(h.ctx, b)
	_ = rd.Rollback(h.ctx)
	require.NoError(t, err)
	require.Equal(t, domain.InviteStatusBlocked, got.InviteStatus, "LMR-06 (б): B по-прежнему заблокирован")
	require.Equal(t, snap, h.wayInOf(t, b), "LMR-06 (б): снимок прежний")
}

// TestResetAccessKeys_LMR07a_TwoResetsAtOnce — LMR-07 (а): два сброса
// одновременно, оба прошли синхронную сверку; ровно один исполнен, второй —
// `FAILED_PRECONDITION` тем же токеном; отсечка и событие — по одному.
func TestResetAccessKeys_LMR07a_TwoResetsAtOnce(t *testing.T) {
	h := newSessionLane(t)
	admin := registerPerson(t, h, "lmr07a-admin")
	u := h.user.ID
	givenAcceptedKey(t, h, u)
	snap := h.wayInOf(t, u)

	gate := newLMRBarrier(2)
	uc := h.resetUC(gate)
	var ids2 []string
	for i := 0; i < 2; i++ {
		op, err := uc.Execute(adminCtx(h.ctx, admin), u)
		require.NoErrorf(t, err, "LMR-07 (а): сброс %d прошёл синхронную сверку", i+1)
		ids2 = append(ids2, op.ID)
	}
	var okN, refusedN int
	for _, id := range ids2 {
		got := h.awaitOp(t, id)
		if got.Error == nil {
			okN++
			continue
		}
		refusedN++
		require.EqualValues(t, codes.FailedPrecondition, got.Error.Code, "LMR-07 (а): проигравший — состояние")
		require.Equal(t, lmrRefusalText, got.Error.Message)
		require.Equal(t, lmrToken, opReasonOf(t, got), "LMR-07 (а): проигравший несёт тот же токен")
	}
	require.Equal(t, 1, okN, "LMR-07 (а): ровно одна операция исполнена")
	require.Equal(t, 1, refusedN, "LMR-07 (а): вторая — отказ")
	require.Equal(t, 1, h.resetEvents(t, u), "LMR-07 (а): событие одно")
	require.Equal(t, lmrReason, h.cutoffOf(t, u).reason)
	require.Equal(t, snap, h.wayInOf(t, u), "LMR-07 (а): снимок прежний")
}

// TestResetAccessKeys_LMR07b_ResetRacesARegistrationFromACutSession — LMR-07
// (б): сброс и завершение регистрации из сессии, выданной до сброса, —
// параллельно; после обоих исходов строк ключей ноль в любом порядке фиксации
// (50 раундов). Близнец — регистрация из сессии-после проходит.
func TestResetAccessKeys_LMR07b_ResetRacesARegistrationFromACutSession(t *testing.T) {
	h := newSessionLane(t)
	admin := registerPerson(t, h, "lmr07b-admin")
	const rounds = 50
	outcomes := map[string]int{}
	for i := 0; i < rounds; i++ {
		w := registerPerson(t, h, fmt.Sprintf("lmr07b-w%02d", i))
		givenAcceptedKey(t, h, w)
		pending := h.beginRegistration(t, w)

		start := make(chan struct{})
		var wg sync.WaitGroup
		var resetErr, regErr error
		var resetOp, regOp *operations.Operation
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			op, err := h.resetUC(nil).Execute(adminCtx(h.ctx, admin), w)
			resetOp, resetErr = op, err
		}()
		go func() {
			defer wg.Done()
			<-start
			uc, err := access_keys.NewFinishRegistrationUseCase(h.keyDeps(), operations.NewRepo(h.pool, "kaname"))
			if err != nil {
				regErr = err
				return
			}
			op, err := uc.Execute(h.ctx, pending.in)
			regOp, regErr = op, err
		}()
		close(start)
		wg.Wait()
		require.NoErrorf(t, resetErr, "раунд %d: сброс прошёл синхронную сверку (у W был ключ)", i)
		reset := h.awaitOp(t, resetOp.ID)
		require.Nilf(t, reset.Error, "раунд %d: сброс исполнен: %v", i, reset.Error)
		regOutcome := "sync-refused"
		if regErr == nil {
			reg := h.awaitOp(t, regOp.ID)
			if reg.Error == nil {
				regOutcome = "registered-then-removed"
			} else {
				regOutcome = "refused-in-operation"
			}
		}
		outcomes[regOutcome]++
		require.Zerof(t, h.keysOf(t, w), "раунд %d (%s): после обоих исходов строк ключей W ноль", i, regOutcome)
	}
	t.Logf("LMR-07 (б): раундов %d · исходы регистрации %v", rounds, outcomes)

	// Близнец по одному факту: испытание выдано сессии-после.
	u := h.user.ID
	givenAcceptedKey(t, h, u)
	h.requireResetDone(t, admin, u, "LMR-07 (б) близнец")
	h.sessionAfter(t, u)
	op, err := h.finishRegistration(t, h.beginRegistration(t, u))
	require.NoError(t, err, "близнец: регистрация из сессии-после принята")
	require.Nil(t, op.Error, "близнец: регистрация из сессии-после исполнена: %v", op.Error)
	require.Equal(t, 1, h.keysOf(t, u), "близнец: строк ключей одна")
}

// TestResetAccessKeys_LMR07c_KeyLoginCommittedBeforeTheResetTakesThePersonIsCut
// — LMR-07 (в), Р4 «ВСЕ сессии гаснут»: вход ключом зафиксирован ПОСЛЕ начала
// исполнения сброса, но РАНЬШЕ, чем сброс взял строку личности (тот же порядок
// фиксаций, что у входа, первым взявшего личность, пока сброс ждёт). Сессия,
// выданная только что снятым ключом, после исхода сброса краю не годна.
// Близнец по одному факту — сессия, выданная ПОСЛЕ фиксации сброса (вход
// паролем, который сброс не трогает), годна: суждение «отсечена» не пустое.
func TestResetAccessKeys_LMR07c_KeyLoginCommittedBeforeTheResetTakesThePersonIsCut(t *testing.T) {
	h := newSessionLane(t)
	admin := registerPerson(t, h, "lmr07c-admin")
	u := h.user.ID
	k := givenAcceptedKey(t, h, u)

	win := newLMRWindow()
	op, err := h.resetUCOver(lmrStore{keys: kanamepg.NewAccessKeyRepo(h.pool), window: win}).Execute(adminCtx(h.ctx, admin), u)
	require.NoError(t, err, "LMR-07 (в): сброс прошёл синхронную сверку (у человека ключ)")
	select {
	case <-win.arrived:
	case <-time.After(20 * time.Second):
		close(win.release)
		require.FailNow(t, "условие не создано", "исполнитель сброса не дошёл до открытия транзакции")
	}
	bearer := keySession(t, h, k)
	require.True(t, h.alive(t, u, bearer), "условие не создано: сессия, выданная ключом в окне, годна до исхода сброса")
	close(win.release)

	got := h.awaitOp(t, op.ID)
	require.Nilf(t, got.Error, "LMR-07 (в): сброс исполнен: %v", got.Error)
	require.Zero(t, h.keysOf(t, u), "LMR-07 (в): строк ключей ноль")
	require.Equal(t, lmrReason, h.cutoffOf(t, u).reason, "LMR-07 (в): отсечка причиной сброса")
	require.False(t, h.alive(t, u, bearer),
		"LMR-07 (в)/Р4: сессия, выданная ключом до захвата личности сбросом, пережила сброс")

	after := h.sessionAfter(t, u)
	require.True(t, h.alive(t, u, after.bearer.Value), "близнец: сессия, выданная после сброса, годна")
}

// TestResetAccessKeys_LMR07c_ResetRacesAKeyLogin — LMR-07 (в) без шва: сброс и
// вход ключом того же человека параллельно, N раундов; после обоих исходов
// сессия, которую вход выдал, краю не годна при любом порядке фиксации. Число
// раундов ограничено окном обращений источника стенда (`SourceAttempts` 50 за
// 10 минут; раунд — испытание и вход): упор в окно — «условие не создано».
func TestResetAccessKeys_LMR07c_ResetRacesAKeyLogin(t *testing.T) {
	h := newSessionLane(t)
	admin := registerPerson(t, h, "lmr07c-race-admin")
	const rounds = 20
	outcomes := map[string]int{}
	ops := operations.NewRepo(h.pool, "kaname")
	for i := 0; i < rounds; i++ {
		w := registerPerson(t, h, fmt.Sprintf("lmr07c-w%02d", i))
		k := givenAcceptedKey(t, h, w)
		f := givenAKForm(t, h)
		c := givenChallenge(t, h, f)
		as := assertOver(t, k, c, webauthntest.AssertionOptions{})

		start := make(chan struct{})
		done := make(chan error, 1)
		// Сдвиг старта сброса по раунду разводит порядок фиксаций: без него
		// сброс всякий раз опережает вход, и выданной сессии проба не видит.
		lag := time.Duration(i%10) * 3 * time.Millisecond
		go func() {
			<-start
			<-time.After(lag)
			op, err := h.resetUC(nil).Execute(adminCtx(h.ctx, admin), w)
			if err != nil {
				done <- fmt.Errorf("сброс отвергнут синхронно: %w", err)
				return
			}
			waitCtx, cancel := context.WithTimeout(h.ctx, 20*time.Second)
			defer cancel()
			if err := operations.Wait(waitCtx); err != nil {
				done <- fmt.Errorf("исполнитель операций не завершил очередь: %w", err)
				return
			}
			got, err := ops.Get(h.ctx, op.ID)
			switch {
			case err != nil:
				done <- fmt.Errorf("операция %s не прочитана: %w", op.ID, err)
			case !got.Done:
				done <- fmt.Errorf("операция %s не терминальна", op.ID)
			case got.Error != nil:
				done <- fmt.Errorf("операция %s отказала: %v", op.ID, got.Error)
			default:
				done <- nil
			}
		}()
		close(start)
		r := akLogin(t, h, f, map[string]any{"csrfToken": f.login, "credential": credentialBody(as, k.handle)})
		require.NoErrorf(t, <-done, "раунд %d: сброс исполнен", i)
		require.Zerof(t, h.keysOf(t, w), "раунд %d: строк ключей ноль", i)
		outcome := "login-refused"
		if r.status == http.StatusOK {
			outcome = "login-issued"
			ck := cookieNamed(r.cookies, loginlanehttp.CookieSession)
			require.NotNilf(t, ck, "раунд %d: вход выдал ответ без носителя", i)
			require.Falsef(t, h.alive(t, w, ck.Value),
				"раунд %d: сессия, выданная ключом параллельно сбросу, пережила сброс (Р4)", i)
		}
		outcomes[outcome]++
	}
	t.Logf("LMR-07 (в): раундов %d · исходы входа %v", rounds, outcomes)
}

// TestResetAccessKeys_LMR09_NoFormIsLeftWithoutAWayIn — LMR-09: сброс не
// производит исхода, который отвергла бы база, ни на одной форме личности;
// контроль — проверка базы в этом мире жива.
func TestResetAccessKeys_LMR09_NoFormIsLeftWithoutAWayIn(t *testing.T) {
	h := newSessionLane(t)
	admin := registerPerson(t, h, "lmr09-admin")
	u1 := registerPerson(t, h, "lmr09-u1")
	p1 := registerPerson(t, h, "lmr09-p1")
	h.openPathOf(t, p1)
	b1 := registerPerson(t, h, "lmr09-b1")
	h.statusOf(t, b1, domain.InviteStatusBlocked)
	for _, c := range []struct {
		id   domain.UserID
		form string
	}{{u1, "ACTIVE с паролем"}, {p1, "ACTIVE без пароля с отметкой"}, {b1, "BLOCKED с паролем"}} {
		givenAcceptedKey(t, h, c.id)
		snap := h.wayInOf(t, c.id)
		h.requireResetDone(t, admin, c.id, "LMR-09 "+c.form)
		require.Zerof(t, h.keysOf(t, c.id), "LMR-09 %s: ключей ноль", c.form)
		require.Equalf(t, snap, h.wayInOf(t, c.id), "LMR-09 %s: снимок прежний", c.form)
	}

	// Контроль: удаление строки пароля U₁ прямой записью отвергается базой.
	tx, err := h.pool.Begin(h.ctx)
	require.NoError(t, err)
	_, err = tx.Exec(h.ctx, `DELETE FROM user_login_methods WHERE user_id = $1 AND kind = 'password'`, string(u1))
	require.NoError(t, err, "удаление строки исполнено; судится фиксация")
	err = tx.Commit(h.ctx)
	var pgErr *pgconn.PgError
	require.Truef(t, errors.As(err, &pgErr), "КОНТРОЛЬ: фиксация отвергнута базой, получено %v", err)
	require.Equal(t, "23503", pgErr.Code, "КОНТРОЛЬ: отложенная проверка AWI (форма AWI-04)")
	require.NotEmpty(t, h.wayInOf(t, u1).passwordRow, "КОНТРОЛЬ: строка пароля U₁ на месте")
}
