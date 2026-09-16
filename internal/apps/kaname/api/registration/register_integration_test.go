// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_integration_test.go — ТРИ СЛЕДСТВИЯ РЕГИСТРАЦИИ — ОДНА ТРАНЗАКЦИЯ
// нашей базы (приёмка Ф4 `docs/engineering/acceptance/registration-and-its-three-consequences.md`,
// Р1, Р3, Р6; сценарии Ф4-01…Ф4-05, Ф4-11, Ф4-13, Ф4-20, Ф4-23, Ф4-24; Ф1-62).
//
// # Что доказывается
//
// Испытание односторонним быть не вправе (Р1): отказ вносится ПО ОЧЕРЕДИ в
// каждое из трёх следствий — зеркало (Ф4-02), строка адреса (Ф4-03), строка
// сессии (Ф4-04) — и после каждого не остаётся ничего из трёх, а повтор тем же
// адресом проходит. Рядом положительный контроль без внесённого отказа (Ф4-05):
// без него отрицания не отличали бы «транзакция откатилась» от «не записывается
// никогда».
//
// Внесённое различие — РОВНО ОДНО на сценарий (§8 инв. 3): обёртка хранилища
// отвергает одну названную запись, всё прочее — настоящий адаптер на настоящей
// базе.
//
// # Чем краснеет ДО кода
//
// Глагола регистрации нашим кодом не существует: обращение некому обслужить,
// транзакции нет (приёмка §9). Проба не собирается — это красное по отсутствию
// предмета, а не по опечатке.
//
// Run: `go test ./internal/apps/kaname/api/registration/ -run Integration -count=1`
// (Docker). Skipped under -short.
package registration_test

import (
	"context"
	stderrors "errors"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// goodPassword — годный по правилу пароль (длина ≥ 12, не похож на адрес).
const goodPassword = "correct-horse-battery-staple-9"

// errInjected — внесённый отказ: отличим от любого отказа адаптера.
var errInjected = stderrors.New("injected refusal")

// faultyStore — хранилище с ОДНИМ внесённым различием: названная запись
// отвергается; всё прочее — настоящий адаптер.
type faultyStore struct {
	inner registration.Store
	on    string
}

func (f *faultyStore) Writer(ctx context.Context) (registration.Writer, error) {
	w, err := f.inner.Writer(ctx)
	if err != nil {
		return nil, err
	}
	return &faultyWriter{Writer: w, on: f.on}, nil
}

type faultyWriter struct {
	registration.Writer
	on string
}

func (w *faultyWriter) Mirror(ctx context.Context, in registration.MirrorInput) (registration.MirrorResult, error) {
	if w.on == "mirror" {
		return registration.MirrorResult{}, errInjected
	}
	return w.Writer.Mirror(ctx, in)
}

func (w *faultyWriter) InsertLoginMethod(ctx context.Context, m domain.LoginMethod) error {
	if w.on == "address" {
		return errInjected
	}
	return w.Writer.InsertLoginMethod(ctx, m)
}

func (w *faultyWriter) InsertSession(ctx context.Context, s domain.HumanSession, digest domain.BearerDigest) error {
	if w.on == "session" {
		return errInjected
	}
	return w.Writer.InsertSession(ctx, s, digest)
}

// countingObserver — клетки исходов регистрации.
type countingObserver struct {
	mu       sync.Mutex
	outcomes map[registration.Outcome]int
}

func (o *countingObserver) RegistrationObserved(_ string, x registration.Outcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.outcomes == nil {
		o.outcomes = map[registration.Outcome]int{}
	}
	o.outcomes[x]++
}

func (o *countingObserver) count(x registration.Outcome) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.outcomes[x]
}

type harness struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	repo     *kanamepg.Repository
	sessions *kanamepg.HumanSessionRepo
	store    registration.Store
	obs      *countingObserver
	hasher   *passwordverify.Hasher
	rule     *humansession.PasswordRule
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	hasher, err := passwordverify.NewHasher(floorHasher())
	require.NoError(t, err)
	rule, err := humansession.NewPasswordRule(12, nil, humansession.NopObserver{}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	repo := kanamepg.New(pool, nil)
	return &harness{
		ctx: ctx, pool: pool, repo: repo,
		sessions: kanamepg.NewHumanSessionRepo(pool),
		store:    kanamepg.NewRegistrationStore(pool),
		obs:      &countingObserver{}, hasher: hasher, rule: rule,
	}
}

// useCase — глагол над данным хранилищем (настоящим либо с внесённым отказом).
func (h *harness) useCase(t *testing.T, store registration.Store) *registration.RegisterUseCase {
	t.Helper()
	lane, ok := registration.LaneByName(registration.LanePassword)
	require.True(t, ok)
	uc, err := registration.NewRegisterUseCase(registration.Deps{
		Store: store, Rule: h.rule, Hasher: h.hasher, Lane: lane, TTL: 24 * time.Hour,
		Observer: h.obs, Now: time.Now, Logger: slog.New(slog.DiscardHandler),
	})
	require.NoError(t, err)
	return uc
}

// rows — сколько строк каждого следствия несёт база по адресу.
type rows struct{ users, methods, sessions, accounts int }

func (h *harness) rowsFor(t *testing.T, email string) rows {
	t.Helper()
	var r rows
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM users WHERE lower(email) = lower($1)`, email).Scan(&r.users))
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM user_login_methods m JOIN users u ON u.id = m.user_id WHERE lower(u.email) = lower($1)`, email).Scan(&r.methods))
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM human_sessions s JOIN users u ON u.id = s.user_id WHERE lower(u.email) = lower($1)`, email).Scan(&r.sessions))
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM accounts a JOIN users u ON u.id = a.owner_user_id WHERE lower(u.email) = lower($1)`, email).Scan(&r.accounts))
	return r
}

func (h *harness) register(t *testing.T, uc *registration.RegisterUseCase, email string) (registration.Output, error) {
	t.Helper()
	return uc.Execute(h.ctx, registration.Input{Email: email, Password: goodPassword, Source: "203.0.113.7"})
}

// assertAllThree — Ф1-20: зеркало · адрес неподтверждён · сессия годна.
func (h *harness) assertAllThree(t *testing.T, email string, out registration.Output) {
	t.Helper()
	r := h.rowsFor(t, email)
	require.Equal(t, rows{users: 1, methods: 1, sessions: 1, accounts: 1}, r, "три следствия одним исходом")

	var status, ext string
	var verifiedAt *time.Time
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT invite_status, external_id, email_verified_at FROM users WHERE lower(email) = lower($1)`, email).
		Scan(&status, &ext, &verifiedAt))
	require.Equal(t, "ACTIVE", status)
	require.True(t, domain.ExternalSubject(ext).IsOwnLane(), "идентичность отчеканена нашей полосой (F4d-52): %q", ext)
	require.Nil(t, verifiedAt, "адрес числится НЕподтверждённым (Ф1-20)")
	require.False(t, out.View.EmailVerified)

	// Сессия годна немедленно — резолв по носителю, без доставки чего-либо ещё (Ф4-20).
	resolved, reason, err := h.sessions.Resolve(h.ctx, out.Bearer.Digest(), time.Now())
	require.NoError(t, err)
	require.Equal(t, humansession.SessionFound, reason, "сессия обязана резолвиться сразу после регистрации")
	require.Equal(t, out.View.User.ID, resolved.User.ID)
	require.Equal(t, "1", resolved.Session.AssuranceLevel, "уровень пароля по правилу Ф11")
}

func freshEmail(tag string) string {
	return "reg-" + tag + "-" + ids.NewID("tst")[3:11] + "@example.invalid"
}

// TestRegisterIntegration_F4_01_05_SuccessGivesAllThreeConsequences — Ф4-01 и
// положительный контроль Ф4-05: ни одного внесённого различия — все три
// следствия на месте после ОДНОГО обращения.
func TestRegisterIntegration_F4_01_05_SuccessGivesAllThreeConsequences(t *testing.T) {
	h := newHarness(t)
	email := freshEmail("f4-01")
	out, err := h.register(t, h.useCase(t, h.store), email)
	require.NoError(t, err)
	h.assertAllThree(t, email, out)
	require.Equal(t, 1, h.obs.count(registration.OutcomeIssued))

	// Событие регистрации и намерения материализации — ТОЙ ЖЕ транзакцией (Ф-б).
	var audits, intents int
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM audit_outbox WHERE event_type = $1 AND event_payload->>'user_id' = $2`,
		registration.AuditUserRegistered, string(out.View.User.ID)).Scan(&audits))
	require.Equal(t, 1, audits, "событие регистрации в очереди аудита")
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM fga_outbox WHERE payload::text LIKE '%' || $1 || '%'`,
		string(out.View.User.ID)).Scan(&intents))
	require.Positive(t, intents, "намерения материализации прав лежат в очереди той же транзакцией")
}

// TestRegisterIntegration_F4_02_04_RefusedConsequenceLeavesNothing — отказ
// ЛЮБОГО из трёх следствий не оставляет ни одного, и повтор тем же адресом
// проходит: адрес не занят наполовину (Ф1-21).
func TestRegisterIntegration_F4_02_04_RefusedConsequenceLeavesNothing(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct{ scenario, on string }{
		{"Ф4-02 отказ зеркала", "mirror"},
		{"Ф4-03 отказ строки адреса", "address"},
		{"Ф4-04 отказ строки сессии", "session"},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			email := freshEmail(tc.on)
			faulty := h.useCase(t, &faultyStore{inner: h.store, on: tc.on})
			_, err := h.register(t, faulty, email)
			require.Error(t, err, "внесённый отказ обязан дойти до вызывающего")
			require.NotErrorIs(t, err, registration.ErrRefused, "внесённый отказ хранилища — не отказ регистрации")
			require.Equal(t, rows{}, h.rowsFor(t, email), "%s: не осталось НИЧЕГО из трёх", tc.scenario)

			// Повтор тем же адресом проходит — настоящим хранилищем.
			out, err := h.register(t, h.useCase(t, h.store), email)
			require.NoError(t, err, "повтор регистрации тем же адресом обязан пройти")
			h.assertAllThree(t, email, out)
		})
	}
	require.Equal(t, 3, h.obs.count(registration.OutcomeStoreFailed))
}

// TestRegisterIntegration_F4_11_24_OccupiedAddressIsOneRefusal — занятый адрес
// (Ф4-11) и повтор тем же человеком (Ф4-24) отвечают ОДНИМ отказом; второго
// зеркала, второго личного аккаунта и второй сессии не заводится. Положительный
// контроль Ф4-13 — свободный адрес рядом проходит.
func TestRegisterIntegration_F4_11_24_OccupiedAddressIsOneRefusal(t *testing.T) {
	h := newHarness(t)
	uc := h.useCase(t, h.store)
	email := freshEmail("f4-11")
	first, err := h.register(t, uc, email)
	require.NoError(t, err)

	_, err = h.register(t, uc, email)
	require.ErrorIs(t, err, registration.ErrRefused)
	require.Equal(t, registration.TextRegistrationRefused, err.Error(), "текст отказа — контракт, без причины")
	require.Equal(t, rows{users: 1, methods: 1, sessions: 1, accounts: 1}, h.rowsFor(t, email),
		"Ф4-24: второго заведения не происходит")

	// Тот же адрес другим регистром — тот же адрес (ключ по lower(email)).
	_, err = h.register(t, uc, "REG-"+email[4:])
	require.ErrorIs(t, err, registration.ErrRefused)

	// Ф4-13: свободный адрес при неисчерпанном пределе — успех.
	other := freshEmail("f4-13")
	out, err := h.register(t, uc, other)
	require.NoError(t, err)
	h.assertAllThree(t, other, out)
	require.NotEqual(t, first.View.User.ID, out.View.User.ID)
	require.Equal(t, 2, h.obs.count(registration.OutcomeRefusedOccupied))
}

// TestRegisterIntegration_F1_62_ConcurrentRegistrationsAdmitExactlyOne — две
// регистрации одним свободным адресом ОДНОВРЕМЕННО: ровно одна даёт все три
// следствия, вторая получает тот же отказ, что занятость (Ф1-22, С6).
func TestRegisterIntegration_F1_62_ConcurrentRegistrationsAdmitExactlyOne(t *testing.T) {
	h := newHarness(t)
	uc := h.useCase(t, h.store)
	email := freshEmail("f1-62")

	const n = 4
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = h.register(t, uc, email)
		}(i)
	}
	close(start)
	wg.Wait()

	var ok, refused int
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case stderrors.Is(err, registration.ErrRefused):
			refused++
		default:
			t.Fatalf("исход, которого у регистрации нет: %v", err)
		}
	}
	require.Equal(t, 1, ok, "ровно одна регистрация проходит")
	require.Equal(t, n-1, refused, "прочие получают отказ занятости, не ALREADY_EXISTS")
	require.Equal(t, rows{users: 1, methods: 1, sessions: 1, accounts: 1}, h.rowsFor(t, email),
		"второй личности с этим адресом не заведено ни в каком виде")
}

// TestRegisterIntegration_F4_23_InvitedPersonRegistersByTheSameLane — адрес с
// приглашением: те же три следствия, строка приглашения перестаёт числиться
// ожидающей, второго личного аккаунта не заводится; идентичность отчеканена
// нашей полосой (Р6).
func TestRegisterIntegration_F4_23_InvitedPersonRegistersByTheSameLane(t *testing.T) {
	h := newHarness(t)
	email := freshEmail("f4-23")

	// Приглашение заводится существующим глаголом хранилища: PENDING-строка в
	// аккаунте приглашающего.
	inviter := seedActiveUserWithAccount(t, h, freshEmail("inviter"))
	w, err := h.repo.Writer(h.ctx)
	require.NoError(t, err)
	pending, _, err := w.UsersW().InsertPending(h.ctx, domain.User{
		ID: domain.UserID(ids.NewID(domain.PrefixUser)), AccountID: inviter.AccountID,
		Email: domain.Email(email), DisplayName: "Invited One", InviteStatus: domain.InviteStatusPending,
		InvitedBy: inviter.ID,
	}, time.Now().Add(24*time.Hour))
	require.NoError(t, err)
	require.NoError(t, w.Commit(h.ctx))

	out, err := h.register(t, h.useCase(t, h.store), email)
	require.NoError(t, err)
	require.True(t, out.Activated, "регистрация активировала приглашение")
	require.Equal(t, pending.ID, out.View.User.ID, "строка приглашённого сохранила свой идентификатор")
	h.assertAllThree(t, email, out)

	var pendingLeft int
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM users WHERE lower(email) = lower($1) AND invite_status = 'PENDING'`, email).Scan(&pendingLeft))
	require.Zero(t, pendingLeft, "строка приглашения перестала числиться ожидающей")
	require.Equal(t, "Invited One", string(out.View.User.DisplayName), "имя приглашённого сохранено")
	require.Equal(t, 1, h.obs.count(registration.OutcomeIssuedInvited))

	// Повтор — тот же единый отказ (Ф4-24).
	_, err = h.register(t, h.useCase(t, h.store), email)
	require.ErrorIs(t, err, registration.ErrRefused)
}

// seedActiveUserWithAccount — действующая личность с личным аккаунтом (посев
// приглашающего), тем же транзакционным телом, что зеркало.
func seedActiveUserWithAccount(t *testing.T, h *harness, email string) domain.User {
	t.Helper()
	out, err := h.register(t, h.useCase(t, h.store), email)
	require.NoError(t, err)
	return out.View.User
}

// TestRegisterIntegration_F4_12_17_ExhaustedRateIsTheSameRefusalAsOccupied —
// Ф4-12: адрес свободен, предел темпа по его носителю исчерпан — отказ
// побайтово равен отказу занятости (Р3). Ф4-17: первая регистрация носителя
// при потолке НОЛЬ проходит. Положительный контроль Ф4-13 — свободный адрес
// при неисчерпанном пределе проходит.
//
// «Предел исчерпан у свободного адреса» строится по-честному: окно носителя
// (адреса) уже несёт заведения — ровно то состояние, которое оставляет
// регистрация с последующим снятием строки человека.
func TestRegisterIntegration_F4_12_17_ExhaustedRateIsTheSameRefusalAsOccupied(t *testing.T) {
	h := newHarness(t)
	uc := h.useCase(t, h.store)
	projector := kanamepg.NewOwnCeilingRepo(h.pool)

	// Ф4-17: потолок ноль — первая регистрация носителя проходит.
	_, err := projector.ApplyAdmissionRate(h.ctx, 0, time.Hour)
	require.NoError(t, err)
	first := freshEmail("f4-17")
	out, err := h.register(t, uc, first)
	require.NoError(t, err, "первое заведение носителя безусловно при любой величине")
	h.assertAllThree(t, first, out)

	// Ф4-11: занятый адрес — эталон отказа.
	_, errOccupied := h.register(t, uc, first)
	require.ErrorIs(t, errOccupied, registration.ErrRefused)

	// Ф4-12: свободный адрес, чьё окно уже полно (потолок один, заведение одно).
	_, err = projector.ApplyAdmissionRate(h.ctx, 1, time.Hour)
	require.NoError(t, err)
	exhausted := freshEmail("f4-12")
	_, err = h.pool.Exec(h.ctx, `
		INSERT INTO identity_admission_windows (carrier_id, kind, window_started_at, admitted)
		VALUES ($1, 'iam.account', now(), 1)`, humansession.AddressKey(exhausted))
	require.NoError(t, err)
	_, errRate := h.register(t, uc, exhausted)
	require.ErrorIs(t, errRate, registration.ErrRefused)
	require.Equal(t, errOccupied.Error(), errRate.Error(), "тело отказа побайтово равно занятости (Р3)")
	require.Equal(t, rows{}, h.rowsFor(t, exhausted), "отказ по темпу не оставил ничего из трёх")
	require.Equal(t, 1, h.obs.count(registration.OutcomeRefusedRate), "причина различима только клеткой счётчика")
	require.Equal(t, 1, h.obs.count(registration.OutcomeRefusedOccupied))

	// Ф4-13: свободный адрес при неисчерпанном пределе — успех.
	free := freshEmail("f4-13b")
	out, err = h.register(t, uc, free)
	require.NoError(t, err)
	h.assertAllThree(t, free, out)
}

// TestRegisterIntegration_F4_14_LiveOnPostgres — живой замер Ф4-14 на
// НАСТОЯЩЕЙ базе: полоса «адрес занят» отвечает ключом почты на вставке
// строки человека, полоса «предел исчерпан» — триггером на фиксации, после
// прочих записей транзакции. Критерий Ф1-48 тот же (`judgeTiming`); ручной
// прогон, как у соседних измерительных приборов:
//
//	KACHO_REGISTRATION_TIMING=1 go test ./internal/apps/kaname/api/registration/ -run TestRegisterIntegration_F4_14_LiveOnPostgres -count=1 -v
func TestRegisterIntegration_F4_14_LiveOnPostgres(t *testing.T) {
	if os.Getenv(timingEnv) == "" {
		t.Skipf("измерительная проба идёт РУЧНЫМ прогоном: %s=1", timingEnv)
	}
	h := newHarness(t)
	uc := h.useCase(t, h.store)
	projector := kanamepg.NewOwnCeilingRepo(h.pool)
	_, err := projector.ApplyAdmissionRate(h.ctx, 1, time.Hour)
	require.NoError(t, err)

	occupied := freshEmail("t-occupied")
	_, err = h.register(t, uc, occupied)
	require.NoError(t, err)
	exhausted := freshEmail("t-exhausted")
	_, err = h.pool.Exec(h.ctx, `
		INSERT INTO identity_admission_windows (carrier_id, kind, window_started_at, admitted)
		VALUES ($1, 'iam.account', now(), 1)`, humansession.AddressKey(exhausted))
	require.NoError(t, err)

	a, b := timingLane{name: "адрес занят"}, timingLane{name: "предел исчерпан"}
	for _, e := range []string{occupied, exhausted} {
		_, _ = h.register(t, uc, e) // прогрев
	}
	for i := 0; i < timingLaneN; i++ {
		for _, x := range []struct {
			email string
			l     *timingLane
		}{{occupied, &a}, {exhausted, &b}} {
			start := time.Now()
			_, err := h.register(t, uc, x.email)
			x.l.samples = append(x.l.samples, time.Since(start))
			require.ErrorIs(t, err, registration.ErrRefused)
		}
	}
	for _, l := range []timingLane{a, b} {
		m, q := l.stats()
		t.Logf("полоса %-18s медиана %10v · IQR %10v · n=%d", l.name, m, q, len(l.samples))
	}
	v := judgeTiming(a, b, timingIQRCeilng, timingLowerN)
	t.Log(v.text)
	switch v.kind {
	case "ok":
	case "not-performed":
		t.Skip(v.text)
	default:
		t.Fatal(v.text)
	}
}
