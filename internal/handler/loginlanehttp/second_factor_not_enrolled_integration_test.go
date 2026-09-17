// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// second_factor_not_enrolled_integration_test.go — ВХОД С КОДОМ ПРИ
// НЕЗАВЕДЁННОМ ФАКТОРЕ НЕ ВЫДАЁТ СОВПАДЕНИЯ ПАРОЛЯ (задача PRO-Robotech/kaname#257;
// приёмка Ф12 `docs/engineering/acceptance/second-factor-totp-and-recovery-codes.md`
// редакции 8, Ф12-13 «е», Р4, Р7; Ф3-02).
//
// # Что доказывается — на ПРОВОДЕ, а не у дублёра
//
// Пробы транспорта этого пакета подставляют глаголы дублёром: он отвечает
// объявленным исходом, и утверждение «два ответа побайтово равны» на нём
// зеленело бы при любом коде полосы. Предмет же здесь — исход, который
// РОЖДАЕТ вариант использования и который транспорт переводит в тело: поэтому
// слушатель собирается над настоящим `LoginUseCase` с настоящими адаптерами
// базы (те же, что в композиционном корне), и обращения идут через TLS-слушатель.
//
// Три обращения, одно различие между первыми двумя — пароль:
//
//	(1) неверный пароль + код `totp` у личности без фактора → 401
//	(2) ВЕРНЫЙ  пароль + код `totp` у личности без фактора → 401, тело == (1)
//	(3) верный пароль БЕЗ поля `secondFactor`                → 200, сессия «1»
//
// (3) — положительный близнец (2): без него равенство (1)/(2) зеленело бы на
// полосе, отвергающей всё. Окно частоты: (1) и (2) — попытки, обе (Р7,
// редакция 8): иначе темп окна отличал бы совпавший пароль от несовпавшего.
//
// # Чем краснеет ДО кода
//
// Полоса до kaname#257 отвечала на (2) `400 SECOND_FACTOR_NOT_ENROLLED` —
// код и тело отличались от (1). Проба красна на этом различии.
//
// Run: `go test ./internal/handler/loginlanehttp/ -run Integration -count=1`
// (Docker). Skipped under -short.
package loginlanehttp_test

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// integrationPassword — годный по правилу пароль (длина ≥ 12).
const integrationPassword = "correct-horse-battery-staple-9"

// nopVerifyObserver — приёмник исходов проверяющего, ничего не считающий.
type nopVerifyObserver struct{}

func (nopVerifyObserver) VerificationObserved(passwordverify.Outcome) {}

// zeroEnvelope — огибающая с нулевым потолком: предмет пробы — тела, не время;
// время держит огибающая Ф3 Р17 своими пробами.
type zeroEnvelope struct{}

func (zeroEnvelope) Floor() time.Duration { return 0 }
func (zeroEnvelope) Admit(context.Context, domain.PasswordCostClass, passwordverify.EnvelopeTrigger) (passwordverify.Admission, error) {
	return passwordverify.Admission{}, nil
}

// realLoginLane — глаголы слушателя: вход — настоящий, остальные — дублёр
// (в этой пробе их не зовут).
type realLoginLane struct {
	*stubLane
	login *humansession.LoginUseCase
}

func (l realLoginLane) Login(ctx context.Context, in humansession.LoginInput) (humansession.LoginOutput, error) {
	return l.login.Execute(ctx, in)
}

// pgRegistrationStore — адаптер хранилища регистрации к порту, как в корне.
type pgRegistrationStore struct{ inner *kanamepg.RegistrationStore }

func (s pgRegistrationStore) Writer(ctx context.Context) (registration.Writer, error) {
	w, err := s.inner.Writer(ctx)
	if err != nil {
		return nil, err
	}
	return pgRegistrationWriter{RegistrationWriter: w}, nil
}

type pgRegistrationWriter struct{ *kanamepg.RegistrationWriter }

func (w pgRegistrationWriter) Mirror(ctx context.Context, in registration.MirrorInput) (registration.MirrorResult, error) {
	return user.RegisterMirrorTx(ctx, w.MirrorWriter(), in)
}

// notEnrolledHarness — база, личность с паролем и без фактора, слушатель над
// настоящим входом.
type notEnrolledHarness struct {
	ctx   context.Context
	pool  *pgxpool.Pool
	email string
	lane  *lane
}

func newNotEnrolledHarness(t *testing.T) *notEnrolledHarness {
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

	// Личность с паролем — регистрацией той же полосой (Ф4): зеркало, строка
	// способа, сессия — одним исходом; фактора у неё нет by construction.
	regLane, ok := registration.LaneByName(registration.LanePassword)
	require.True(t, ok)
	register, err := registration.NewRegisterUseCase(registration.Deps{
		Store: pgRegistrationStore{inner: kanamepg.NewRegistrationStore(pool)}, Rule: rule, Hasher: hasher, Lane: regLane,
		TTL: 24 * time.Hour, Observer: registration.NopObserver{}, Now: time.Now, Logger: logger,
	})
	require.NoError(t, err)
	email := "ne-" + ids.NewID("tst")[3:11] + "@example.invalid"
	_, err = register.Execute(ctx, registration.Input{Email: email, Password: integrationPassword, Source: "203.0.113.7"})
	require.NoError(t, err)

	key := make([]byte, keywrap.KeySize)
	for i := range key {
		key[i] = 7
	}
	wrapper, err := keywrap.New(key)
	require.NoError(t, err)
	totp, err := totpverify.New(wrapper)
	require.NoError(t, err)

	sessions := kanamepg.NewHumanSessionRepo(pool)
	login, err := humansession.NewLoginUseCase(humansession.LoginDeps{
		Store: sessions, Users: kanamepg.NewUserDirectory(kanamepg.New(pool, nil)), Methods: kanamepg.NewLoginMethodRepo(pool),
		Verifier: verifier, Hasher: hasher,
		Limits: humansession.Limits{AddressAttempts: 5, AddressWindow: 10 * time.Minute, SourceAttempts: 50, SourceWindow: 10 * time.Minute},
		TTL:    24 * time.Hour, Observer: humansession.NopObserver{}, Now: time.Now, Logger: logger,
		Envelope: zeroEnvelope{}, TOTP: totp, Sets: verifier,
	})
	require.NoError(t, err)

	return &notEnrolledHarness{ctx: ctx, pool: pool, email: email,
		lane: newLaneOver(t, realLoginLane{stubLane: &stubLane{}, login: login}, "")}
}

// failuresByAddress — попыток по адресу в окне (Ф3 Р10), из базы.
func (h *notEnrolledHarness) failuresByAddress(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM login_failures WHERE scope = $1 AND key = $2`,
		string(humansession.FailureByAddress), humansession.AddressKey(h.email)).Scan(&n))
	return n
}

// TestLaneIntegration_F12_13e_NotEnrolledOnLoginIsByteIdenticalToAWrongPassword
// — Ф12-13 «е» редакции 8: неверный пароль + код и верный пароль + код у
// личности без фактора дают побайтово равные тела и коды 401; обе — попытки;
// положительный близнец — верный пароль без поля даёт сессию «1».
func TestLaneIntegration_F12_13e_NotEnrolledOnLoginIsByteIdenticalToAWrongPassword(t *testing.T) {
	h := newNotEnrolledHarness(t)
	c := h.lane.client(t, gatewaySAN)
	tok, ctxCk := h.lane.csrf(t, c, "login", nil)
	withCode := func(password string) map[string]any {
		return map[string]any{"email": h.email, "password": password, "csrfToken": tok,
			"secondFactor": map[string]string{"method": "totp", "code": "000000"}}
	}

	// (1) неверный пароль + код — отказ входа.
	r1 := h.lane.do(t, c, http.MethodPost, "/iam/v1/auth/login", withCode("not-the-password"), fwd(), ctxCk)
	require.Equal(t, http.StatusUnauthorized, r1.status, r1.body)
	require.JSONEq(t, `{"code":16,"message":"authentication failed","details":[]}`, r1.body)
	require.Empty(t, r1.cookies, "отказ печений не пишет")
	require.Equal(t, 1, h.failuresByAddress(t), "(1) — попытка")

	// (2) ВЕРНЫЙ пароль + код при незаведённом факторе — тот же отказ, побайтово.
	r2 := h.lane.do(t, c, http.MethodPost, "/iam/v1/auth/login", withCode(integrationPassword), fwd(), ctxCk)
	require.Equal(t, r1.status, r2.status, "код ответа не называет совпавший пароль: %s", r2.body)
	require.Equal(t, r1.body, r2.body, "тело ответа не называет совпавший пароль")
	require.Empty(t, r2.cookies, "отказ печений не пишет")
	require.Equal(t, 2, h.failuresByAddress(t), "(2) — попытка, как (1): темп окна не называет совпавший пароль")

	// (3) положительный близнец: тот же пароль без поля — сессия «1».
	r3 := h.lane.do(t, c, http.MethodPost, "/iam/v1/auth/login",
		map[string]any{"email": h.email, "password": integrationPassword, "csrfToken": tok}, fwd(), ctxCk)
	require.Equal(t, http.StatusOK, r3.status, r3.body)
	require.Contains(t, r3.body, `"assuranceLevel":"1"`)
	require.NotNil(t, cookieNamed(r3.cookies, "kaname_session"), "успех выдаёт носитель")
	require.Zero(t, h.failuresByAddress(t), "успешный вход обнуляет счёт по адресу (Ф3 Р10)")
}
