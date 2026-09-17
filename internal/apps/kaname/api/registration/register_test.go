// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_test.go — глагол регистрации на подставных портах: порядок внутри
// транзакции, единый отказ (Р3), исполнение объявленных следствий (Р4),
// хеширование ДО транзакции (Р7 — половина, которую держит устройство глагола).
package registration_test

import (
	"context"
	stderrors "errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

var unitBase = time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)

// floorHasher — ручка «что писать» на полу записи argon2id (64 МиБ · 3 · 4):
// единственный записываемый формат; bcrypt продукт только читает.
func floorHasher() passwordverify.Declared {
	return passwordverify.Declared{Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: 65536, domain.CostParamArgon2Iterations: 3, domain.CostParamArgon2Parallelism: 4}}
}

// recorder — журнал шагов харнесса: кто и когда позван.
type recorder struct{ steps []string }

func (r *recorder) record(s string) { r.steps = append(r.steps, s) }

// unitStore — подставное хранилище: один writer на обращение, шаги в журнал.
type unitStore struct {
	rec        *recorder
	writerErr  error
	mirrorErr  error
	methodErr  error
	sessionErr error
	commitErr  error
	writers    []*unitWriter
}

func (s *unitStore) Writer(context.Context) (registration.Writer, error) {
	s.rec.record("writer")
	if s.writerErr != nil {
		return nil, s.writerErr
	}
	w := &unitWriter{store: s}
	s.writers = append(s.writers, w)
	return w, nil
}

type unitWriter struct {
	humansession.Writer // не зовётся сверх названных ниже — nil-паника выдаст неучтённый вызов
	store               *unitStore
	committed, rolled   bool
	sessions            []domain.HumanSession
	audits              []outboxtypes.AuditEvent
	methods             []domain.LoginMethod
}

func (w *unitWriter) Mirror(_ context.Context, in registration.MirrorInput) (registration.MirrorResult, error) {
	w.store.rec.record("mirror")
	if w.store.mirrorErr != nil {
		return registration.MirrorResult{}, w.store.mirrorErr
	}
	return registration.MirrorResult{User: domain.User{
		ID: "usr-1", AccountID: "acc-1", ExternalID: in.ExternalID, Email: in.Email,
		DisplayName: "Ann", InviteStatus: domain.InviteStatusActive,
	}}, nil
}

func (w *unitWriter) InsertLoginMethod(_ context.Context, m domain.LoginMethod) error {
	w.store.rec.record("login-method")
	if w.store.methodErr != nil {
		return w.store.methodErr
	}
	w.methods = append(w.methods, m)
	return nil
}

func (w *unitWriter) InsertSession(_ context.Context, s domain.HumanSession, _ domain.BearerDigest) error {
	w.store.rec.record("session")
	if w.store.sessionErr != nil {
		return w.store.sessionErr
	}
	w.sessions = append(w.sessions, s)
	return nil
}

func (w *unitWriter) RememberFirstAuthentication(context.Context, domain.UserID, time.Time) error {
	w.store.rec.record("first-auth")
	return nil
}

func (w *unitWriter) EmitAudit(_ context.Context, ev outboxtypes.AuditEvent) error {
	w.store.rec.record("audit:" + ev.EventType)
	w.audits = append(w.audits, ev)
	return nil
}

func (w *unitWriter) Commit(context.Context) error {
	w.store.rec.record("commit")
	if w.store.commitErr != nil {
		return w.store.commitErr
	}
	w.committed = true
	return nil
}

func (w *unitWriter) Rollback(context.Context) error {
	w.store.rec.record("rollback")
	w.rolled = true
	return nil
}

// recordingHasher — хешер, пишущий шаг: порядок «хеш → транзакция» несущий.
type recordingHasher struct {
	rec   *recorder
	inner *passwordverify.Hasher
}

func (h *recordingHasher) Hash(p string) (domain.LoginVerifier, error) {
	h.rec.record("hash")
	return h.inner.Hash(p)
}

func (h *recordingHasher) Declared() passwordverify.Declared { return h.inner.Declared() }

type unitObserver struct{ seen map[registration.Outcome]int }

func (o *unitObserver) RegistrationObserved(_ string, x registration.Outcome) {
	if o.seen == nil {
		o.seen = map[registration.Outcome]int{}
	}
	o.seen[x]++
}

type unit struct {
	rec   *recorder
	store *unitStore
	obs   *unitObserver
	uc    *registration.RegisterUseCase
}

func newUnit(t *testing.T, mut func(*unitStore)) *unit {
	t.Helper()
	rec := &recorder{}
	store := &unitStore{rec: rec}
	if mut != nil {
		mut(store)
	}
	inner, err := passwordverify.NewHasher(floorHasher())
	require.NoError(t, err)
	rule, err := humansession.NewPasswordRule(12, nil, humansession.NopObserver{}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	lane, ok := registration.LaneByName(registration.LanePassword)
	require.True(t, ok)
	obs := &unitObserver{}
	uc, err := registration.NewRegisterUseCase(registration.Deps{
		Store: store, Rule: rule, Hasher: &recordingHasher{rec: rec, inner: inner}, Lane: lane,
		TTL: 24 * time.Hour, Observer: obs, Now: func() time.Time { return unitBase },
		Logger: slog.New(slog.DiscardHandler),
	})
	require.NoError(t, err)
	return &unit{rec: rec, store: store, obs: obs, uc: uc}
}

func (u *unit) register(t *testing.T, email string) (registration.Output, error) {
	t.Helper()
	return u.uc.Execute(context.Background(), registration.Input{Email: email, Password: goodPassword, Source: "203.0.113.7"})
}

// TestRegister_F4_01_ThreeConsequencesInOneWriterInDeclaredOrder — один writer,
// следствия в объявленном порядке, сессия последней, фиксация одна.
func TestRegister_F4_01_ThreeConsequencesInOneWriterInDeclaredOrder(t *testing.T) {
	u := newUnit(t, nil)
	out, err := u.register(t, "Ann@Example.Invalid")
	require.NoError(t, err)
	require.Equal(t, []string{"hash", "writer", "mirror", "login-method", "session", "first-auth",
		"audit:" + registration.AuditUserRegistered, "commit", "rollback"}, u.rec.steps,
		"хеш до транзакции; один writer; зеркало → адрес → сессия; откат после фиксации — no-op")
	require.Len(t, u.store.writers, 1)
	w := u.store.writers[0]
	require.True(t, w.committed)
	require.Len(t, w.methods, 1)
	require.Equal(t, domain.LoginMethodPassword, w.methods[0].Kind)
	require.Equal(t, domain.UserID("usr-1"), w.methods[0].UserID)
	require.Len(t, w.sessions, 1)
	require.Equal(t, unitBase, w.sessions[0].AuthenticatedAt)
	require.Equal(t, unitBase.Add(24*time.Hour), w.sessions[0].ExpiresAt)
	require.Equal(t, []string{"password"}, w.sessions[0].PresentedMethods)
	require.NotEmpty(t, out.Bearer.CookieValue())
	require.Equal(t, w.sessions[0].ID, out.View.Session.ID)
	require.Equal(t, "ann@example.invalid", string(out.View.User.Email), "адрес нормализован ключом")
	require.True(t, out.View.User.ExternalID.IsOwnLane(), "идентичность отчеканена нашей полосой")
	require.False(t, out.View.EmailVerified)
	require.Equal(t, 1, u.obs.seen[registration.OutcomeIssued])
	// Событие регистрации — без адреса и имени (гейт `audit_payload_pii`).
	require.Len(t, w.audits, 1)
	require.Equal(t, "usr-1", w.audits[0].Payload["user_id"])
	require.Equal(t, registration.LanePassword, w.audits[0].Payload["lane"])
	require.NotContains(t, w.audits[0].Payload, "email")
}

// TestRegister_F4_11_12_OccupiedAndRateAreOneRefusal — занятость адреса (ключ
// зеркала) и потолок темпа (отказ на фиксации) отвечают ОДНИМ отказом: тот же
// сентинел, тот же текст; причина различима только клеткой счётчика (Р3).
func TestRegister_F4_11_12_OccupiedAndRateAreOneRefusal(t *testing.T) {
	occupied := newUnit(t, func(s *unitStore) { s.mirrorErr = iamerr.Wrapf(iamerr.ErrAlreadyExists, "users email") })
	_, errOccupied := occupied.register(t, "ann@example.invalid")
	require.ErrorIs(t, errOccupied, registration.ErrRefused)
	require.True(t, occupied.store.writers[0].rolled)
	require.False(t, occupied.store.writers[0].committed)

	rate := newUnit(t, func(s *unitStore) { s.commitErr = iamerr.Wrapf(iamerr.ErrQuotaRateExceeded, "window full") })
	_, errRate := rate.register(t, "ann@example.invalid")
	require.ErrorIs(t, errRate, registration.ErrRefused)

	require.Equal(t, errOccupied.Error(), errRate.Error(), "тело отказа побайтово равно")
	require.Equal(t, registration.TextRegistrationRefused, errRate.Error())
	require.Equal(t, 1, occupied.obs.seen[registration.OutcomeRefusedOccupied])
	require.Equal(t, 1, rate.obs.seen[registration.OutcomeRefusedRate])
	// Внесённый отказ хранилища — не отказ регистрации, а недоступность.
	broken := newUnit(t, func(s *unitStore) { s.sessionErr = stderrors.New("boom") })
	_, err := broken.register(t, "ann@example.invalid")
	require.ErrorIs(t, err, humansession.ErrStoreUnavailable)
	require.Equal(t, 1, broken.obs.seen[registration.OutcomeStoreFailed])
}

// TestRegister_F1_32_PasswordRuleRefusalNamesTheFieldBeforeAnyWrite — правило
// пароля зовётся до транзакции; отказ называет поле и правило (осознанное
// исключение из единого отказа — Р3).
func TestRegister_F1_32_PasswordRuleRefusalNamesTheFieldBeforeAnyWrite(t *testing.T) {
	u := newUnit(t, nil)
	_, err := u.register(t, "ann@example.invalid")
	require.NoError(t, err)
	u2 := newUnit(t, nil)
	_, err = u2.uc.Execute(context.Background(), registration.Input{Email: "ann@example.invalid", Password: "short"})
	var fe *humansession.FieldError
	require.ErrorAs(t, err, &fe)
	require.Equal(t, "password", fe.Field)
	require.Empty(t, u2.rec.steps, "до транзакции и до хеша дело не дошло")
	require.Equal(t, 1, u2.obs.seen[registration.OutcomeRefusedPassword])

	for _, tc := range []struct{ email, password, field string }{
		{"", goodPassword, "email"},
		{"not-an-address", goodPassword, "email"},
		{"ann@example.invalid", "", "password"},
	} {
		u3 := newUnit(t, nil)
		_, err := u3.uc.Execute(context.Background(), registration.Input{Email: tc.email, Password: tc.password})
		require.ErrorAs(t, err, &fe, "%+v", tc)
		require.Equal(t, tc.field, fe.Field)
		require.Empty(t, u3.rec.steps)
	}
}

// TestRegister_R4_LaneMustDeclareEveryConsequence — глагол собирается ТОЛЬКО
// для полосы, объявившей все три следствия: отсутствующее названо по имени;
// положительный контроль — полоса объявления собирается.
func TestRegister_R4_LaneMustDeclareEveryConsequence(t *testing.T) {
	deps := func(lane registration.Lane) registration.Deps {
		inner, _ := passwordverify.NewHasher(floorHasher())
		rule, _ := humansession.NewPasswordRule(12, nil, humansession.NopObserver{}, slog.New(slog.DiscardHandler))
		return registration.Deps{Store: &unitStore{rec: &recorder{}}, Rule: rule, Hasher: inner, Lane: lane, TTL: time.Hour}
	}
	full, ok := registration.LaneByName(registration.LanePassword)
	require.True(t, ok)
	_, err := registration.NewRegisterUseCase(deps(full))
	require.NoError(t, err, "полоса объявления собирается")

	partial := registration.Lane{Name: "probe", Consequences: []registration.Consequence{registration.ConsequenceMirror, registration.ConsequenceAddress}}
	_, err = registration.NewRegisterUseCase(deps(partial))
	require.Error(t, err)
	require.Contains(t, err.Error(), "probe")
	require.Contains(t, err.Error(), string(registration.ConsequenceSession))

	_, err = registration.NewRegisterUseCase(deps(registration.Lane{}))
	require.Error(t, err, "полоса без имени не собирается")
}
