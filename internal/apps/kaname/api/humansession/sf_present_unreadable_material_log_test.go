// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// sf_present_unreadable_material_log_test.go — неоткрывающийся материал второго
// фактора отвечает 503 «громко»: кроме клетки счётчика — запись журнала уровня
// ошибки (PRO-Robotech/kaname#700; приёмка `second-factor-totp-and-recovery-codes.md`
// Р2, Ф12-35 «в» и «г»). Уровень I: проверяющий кода по времени — настоящий,
// над настоящей обёрткой ключей; условие (в) строится сменой перечня, а не
// подменой материала: фактор заведён под `K1`, глаголы собраны под `K2` без `K1`.
//
// Запись одна на предъявление и живёт в одном слое — в общей сверке
// (`sf_present.go`), а не на крае: край не знает ни личности, ни способа.
// Отсутствие второй записи на крае держит `loginlanehttp`
// (`TestLane_F12_35_UnavailableLeavesTheRecordToTheVerb`).

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// recordedLog — записи журнала, снятые дублёром обработчика.
type recordedLog struct {
	mu      sync.Mutex
	records []slog.Record
}

type recordingHandler struct {
	log   *recordedLog
	attrs []slog.Attr
}

func (recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h recordingHandler) Handle(_ context.Context, r slog.Record) error {
	c := r.Clone()
	c.AddAttrs(h.attrs...)
	h.log.mu.Lock()
	defer h.log.mu.Unlock()
	h.log.records = append(h.log.records, c)
	return nil
}

func (h recordingHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return recordingHandler{log: h.log, attrs: append(append([]slog.Attr{}, h.attrs...), as...)}
}

func (h recordingHandler) WithGroup(string) slog.Handler { return h }

// errors — записи уровня ERROR и выше.
func (l *recordedLog) errors() []slog.Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []slog.Record
	for _, r := range l.records {
		if r.Level >= slog.LevelError {
			out = append(out, r)
		}
	}
	return out
}

func (l *recordedLog) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = nil
}

// attrsOf — атрибуты записи строками (значение разрешено).
func attrsOf(r slog.Record) map[string]string {
	out := map[string]string{}
	r.Attrs(func(a slog.Attr) bool {
		out[a.Key] = a.Value.Resolve().String()
		return true
	})
	return out
}

// renderedRecord — запись целиком текстом: сообщение и все атрибуты.
func renderedRecord(r slog.Record) string {
	var b strings.Builder
	b.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%s", a.Key, a.Value.Resolve().String())
		return true
	})
	return b.String()
}

// wrapKey — ключ обёртки пробы, заполненный одним байтом.
func wrapKey(fill byte) []byte {
	k := make([]byte, keywrap.KeySize)
	for i := range k {
		k[i] = fill
	}
	return k
}

// probeKeyK1 — ключ проверяющего харнесса (`probeTOTPVerifier`): под ним
// заводится фактор. probeKeyK2 — ключ, сменивший его в перечне.
var (
	probeKeyK1 = wrapKey(7)
	probeKeyK2 = wrapKey(9)
)

func totpUnder(t *testing.T, keys ...[]byte) *totpverify.Verifier {
	t.Helper()
	w, err := keywrap.New(keys...)
	require.NoError(t, err)
	v, err := totpverify.New(w)
	require.NoError(t, err)
	return v
}

// keyedVerbs — глаголы предъявления кода, собранные над хранилищем харнесса,
// но с другим перечнем ключей и журналом, который читает проба.
type keyedVerbs struct {
	log    *recordedLog
	verbs  map[string]func(p *naPerson, f humansession.SecondFactorPresentation) error
	stepUp func(p *naPerson, f humansession.SecondFactorPresentation) error
}

func (h *sfHarness) verbsUnder(t *testing.T, totp *totpverify.Verifier) keyedVerbs {
	t.Helper()
	log := &recordedLog{}
	logger := slog.New(recordingHandler{log: log})
	now := func() time.Time { return h.clock }
	deps := humansession.SecondFactorDeps{
		Store: h.store, Methods: fakeMethods{h.store}, TOTP: totp, Sets: h.verifier, SetHasher: h.hasher,
		Verifier: h.verifier, Limits: sfLimits(), Freshness: sfWindow, Domain: sfDomain,
		Observer: h.obs, Now: now, Logger: logger,
	}
	stepUp, err := humansession.NewStepUpUseCase(deps)
	require.NoError(t, err)
	remove, err := humansession.NewRemoveSecondFactorUseCase(deps)
	require.NoError(t, err)
	regenerate, err := humansession.NewRegenerateBackupCodesUseCase(deps)
	require.NoError(t, err)
	login, err := humansession.NewLoginUseCase(humansession.LoginDeps{
		CutoffClock: momentclock.Func(now),
		Store:       h.store, Users: fakeUsers{h.store}, Methods: fakeMethods{h.store}, Verifier: h.verifier,
		Hasher: h.hasher, Limits: sfLimits(), TTL: ucTTL, Observer: h.obs, Now: now, Logger: logger,
		Envelope: h.envelopePort, TOTP: totp, Sets: h.verifier,
	})
	require.NoError(t, err)
	ctx := context.Background()
	su := func(p *naPerson, f humansession.SecondFactorPresentation) error {
		_, err := stepUp.Execute(ctx, humansession.StepUpInput{Bearer: p.bearer, Method: f.Method, Code: f.Code, Source: naSource})
		return err
	}
	return keyedVerbs{log: log, stepUp: su, verbs: map[string]func(*naPerson, humansession.SecondFactorPresentation) error{
		"step-up": su,
		"login": func(p *naPerson, f humansession.SecondFactorPresentation) error {
			_, err := login.Execute(ctx, humansession.LoginInput{Email: p.email, Password: naPassword, Source: naSource, SecondFactor: &f})
			return err
		},
		"remove": func(p *naPerson, f humansession.SecondFactorPresentation) error {
			_, err := remove.Execute(ctx, humansession.RemoveSecondFactorInput{Bearer: p.bearer, Factor: f, Source: naSource})
			return err
		},
		"regenerate": func(p *naPerson, f humansession.SecondFactorPresentation) error {
			_, err := regenerate.Execute(ctx, humansession.RegenerateBackupCodesInput{Bearer: p.bearer, Factor: f, Source: naSource})
			return err
		},
	}}
}

// requireOneUnreadableRecord — ровно одна запись уровня ERROR; она несёт
// личность и способ, как соседние записи сверки (`step_up.go`), и не несёт ни
// байта материала, ни кода, ни значения ключа.
func requireOneUnreadableRecord(t *testing.T, log *recordedLog, userID domain.UserID, method assurance.Method, leaks map[string]string) {
	t.Helper()
	recs := log.errors()
	require.Len(t, recs, 1, "Ф12-35 (в), (г): неоткрывающийся материал — ровно одна запись журнала уровня ошибки на предъявление")
	attrs := attrsOf(recs[0])
	require.Equal(t, string(userID), attrs["user_id"], "запись называет личность")
	require.Equal(t, method.String(), attrs["method"], "запись называет способ")
	text := strings.ToLower(renderedRecord(recs[0]))
	for what, v := range leaks {
		require.NotEmpty(t, v, "предпосылка: значение %s известно пробе", what)
		require.NotContains(t, text, strings.ToLower(v), "запись не несёт %s", what)
	}
}

// TestF12_35_UnreadableMaterialLeavesOneErrorRecordPerPresentation — Ф12-35 «в»
// у всех глаголов общей сверки: фактор заведён под `K1`; под перечнем `K2` без
// `K1` верный код — 503 и одна запись уровня ERROR; законный близнец — тот же
// код под перечнем `K2,K1` проходит без единой записи уровня ERROR (отличающий
// факт один: есть ли `K1` в перечне).
func TestF12_35_UnreadableMaterialLeavesOneErrorRecordPerPresentation(t *testing.T) {
	for _, verb := range []string{"step-up", "login", "remove", "regenerate"} {
		t.Run(verb, func(t *testing.T) {
			h := newSFHarness(t)
			p := h.withFactor(t, "usr-ml", "ml@example.invalid")
			stored, ok := h.sfRow(p.id, domain.LoginMethodTOTP)
			require.True(t, ok, "предпосылка: строка totp заведена")
			code := probeTOTP(t, p.secret, h.step())

			rotated := h.verbsUnder(t, totpUnder(t, probeKeyK2))
			refused := rotated.verbs[verb](p, totpOf(code))
			require.ErrorIs(t, refused, humansession.ErrSecondFactorUnavailable, "предпосылка: под `K2` без `K1` материал не открывается")
			requireOneUnreadableRecord(t, rotated.log, p.id, assurance.MethodTOTP, map[string]string{
				"секрета фактора":     p.secret.Base32(),
				"кода предъявления":   code,
				"хранимого материала": stored.Verifier.Reveal(),
				"ключа K1":            hex.EncodeToString(probeKeyK1),
				"ключа K2":            hex.EncodeToString(probeKeyK2),
			})

			twin := h.verbsUnder(t, totpUnder(t, probeKeyK2, probeKeyK1))
			require.NoError(t, twin.verbs[verb](p, totpOf(code)), "близнец: `K2,K1` — код сверяется")
			require.Empty(t, twin.log.errors(), "близнец: материал открылся — записи уровня ошибки нет")
		})
	}
}

// TestF12_35_UnreadableBackupSetLeavesOneErrorRecord — Ф12-35 «г»: строка
// `totp` — `active`, строки набора нет (снята мимо глаголов) — `step-up` с
// запасным кодом — 503 и одна запись уровня ERROR со способом `lookup_secret`;
// близнец — набор цел, тот же код сверяется без записи уровня ERROR.
func TestF12_35_UnreadableBackupSetLeavesOneErrorRecord(t *testing.T) {
	h := newSFHarness(t)
	p := h.withFactor(t, "usr-mg", "mg@example.invalid")
	require.NotEmpty(t, p.codes, "предпосылка: набор выпущен")
	set, ok := h.sfRow(p.id, domain.LoginMethodLookupSecret)
	require.True(t, ok, "предпосылка: строка набора есть")
	code := p.codes[0]

	verbs := h.verbsUnder(t, totpUnder(t, probeKeyK1))
	delete(h.store.factors[p.id], domain.LoginMethodLookupSecret)
	refused := verbs.stepUp(p, lookupOf(code))
	require.ErrorIs(t, refused, humansession.ErrSecondFactorUnavailable, "предпосылка: без строки набора материал не открывается")
	requireOneUnreadableRecord(t, verbs.log, p.id, assurance.MethodLookupSecret, map[string]string{
		"запасного кода": code,
		"набора":         set.Verifier.Reveal(),
	})

	h.store.factors[p.id][domain.LoginMethodLookupSecret] = &set
	verbs.log.reset()
	require.NoError(t, verbs.stepUp(p, lookupOf(code)), "близнец: набор цел — код сверяется")
	require.Empty(t, verbs.log.errors(), "близнец: записи уровня ошибки нет")
}
