// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// timing_probe_test.go — ИЗМЕРИТЕЛЬНАЯ проба Ф4-14…Ф4-16 (Р7): отказ
// регистрации неразличим по ВРЕМЕНИ между «адрес занят» (Ф4-11) и «адрес
// свободен, предел темпа исчерпан» (Ф4-12). Критерий — Ф1-48 дословно, своей
// величины Ф4 не вводит ни одной.
//
// # Что меряется
//
// Две полосы обращений к `Register.Execute`, чередуясь по кругу (Ф1-48:
// чередование, а не блоками — иначе дрейф машины лёг бы на одну полосу):
//
//   - «адрес занят» — писатель зеркала отвечает ключом почты (ErrAlreadyExists);
//   - «предел исчерпан» — фиксация отвечает потолком темпа (ErrQuotaRateExceeded).
//
// Хранилище подставное: измеряется УСТРОЙСТВО глагола — хеш до транзакции в
// обеих полосах, единый отказ, — а не задержка базы. Критерий Ф1-48:
// |медиана₁ − медиана₂| ≤ max(IQR₁, IQR₂); печатаются медианы, размахи, N на
// полосу, потолок годности, нижняя граница и сам критерий.
//
// # Три исхода, и они РАЗВЕДЕНЫ ФУНКЦИЕЙ
//
// Зелёный · красное с именем более быстрой полосы и разницей (Ф4-15) · «не
// выполнилось» — размах любой полосы выше потолка годности (Ф4-16). Вердикт
// выносит `judgeTiming`, и он же проверен на синтетических рядах
// (`TestRegisterTiming_F4_14_16_CriterionOnSyntheticSamples`) — всегда, без
// ручки: критерий обязан уметь дать каждый из трёх ответов.
//
// # Инъекция Ф4-15 — стоимость ОДНОЙ проверки пароля, и не больше
//
// В полосу «предел исчерпан» вносится ровно один лишний хеш той же ручки
// (argon2id, 64 МиБ · 3 · 4): различие порядка стоимости проверки пароля
// (Ф1 §4.1). Проба обязана покраснеть, назвав полосу. Различие, заметно
// превосходящее эту величину, краснело бы при любом шуме и контролем не было бы.
//
// # Почему живой замер — ручным прогоном
//
// Стоимость хеша на полу записи — десятки-сотни миллисекунд; N=12 на две
// полосы плюс инъекция — секунды, и на общем ранере размах превышает потолок
// годности by construction. Прогон — ручкой, как у соседних измерительных
// приборов (Ф3-31):
//
//	KACHO_REGISTRATION_TIMING=1 go test ./internal/apps/kaname/api/registration/ -run TestRegisterTiming_F4_14_15_Live -count=1 -v -timeout 30m
package registration_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
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

const (
	timingEnv = "KACHO_REGISTRATION_TIMING"
	// timingLaneN — обращений на полосу; нижняя граница Ф1-48 — 10.
	timingLaneN     = 12
	timingLowerN    = 10
	timingIQRCeilng = 250 * time.Millisecond
)

// timingLane — ряд замеров одной полосы.
type timingLane struct {
	name    string
	samples []time.Duration
}

func (l timingLane) stats() (median, iqr time.Duration) {
	s := append([]time.Duration(nil), l.samples...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	q := func(p float64) time.Duration { return s[int(float64(len(s)-1)*p)] }
	return q(0.5), q(0.75) - q(0.25)
}

// timingVerdict — один из трёх исходов.
type timingVerdict struct {
	kind string // "ok" · "red" · "not-performed"
	text string
}

// judgeTiming — критерий Ф1-48 над двумя полосами; потолок годности и нижняя
// граница объявлены и печатаются вызывающим.
func judgeTiming(a, b timingLane, ceiling time.Duration, lowerN int) timingVerdict {
	for _, l := range []timingLane{a, b} {
		if len(l.samples) < lowerN {
			return timingVerdict{"not-performed", fmt.Sprintf("полоса %q: обращений %d ниже нижней границы %d — вердикта нет", l.name, len(l.samples), lowerN)}
		}
		if _, iqr := l.stats(); iqr > ceiling {
			return timingVerdict{"not-performed", fmt.Sprintf("НЕ ВЫПОЛНИЛОСЬ (Ф4-16): размах полосы %q %v выше потолка годности %v — стенд шумит сильнее измеряемого, вердикта нет", l.name, iqr, ceiling)}
		}
	}
	ma, qa := a.stats()
	mb, qb := b.stats()
	// Быстрее та полоса, чья медиана меньше.
	diff, faster := ma-mb, b.name
	if diff < 0 {
		diff, faster = -diff, a.name
	}
	bound := qa
	if qb > bound {
		bound = qb
	}
	if diff > bound {
		return timingVerdict{"red", fmt.Sprintf("КРАСНОЕ (Ф4-15): полоса %q быстрее на %v, |Δмедиан| %v > IQR %v", faster, diff, diff, bound)}
	}
	return timingVerdict{"ok", fmt.Sprintf("ok: |Δмедиан| %v ≤ IQR %v", diff, bound)}
}

// TestRegisterTiming_F4_14_16_CriterionOnSyntheticSamples — критерий даёт
// каждый из трёх ответов на рядах, у которых исход известен по построению.
func TestRegisterTiming_F4_14_16_CriterionOnSyntheticSamples(t *testing.T) {
	ms := func(vs ...int) []time.Duration {
		out := make([]time.Duration, 0, len(vs))
		for _, v := range vs {
			out = append(out, time.Duration(v)*time.Millisecond)
		}
		return out
	}
	base := ms(100, 101, 99, 102, 98, 100, 103, 97, 101, 99, 100, 102)
	shifted := ms(150, 151, 149, 152, 148, 150, 153, 147, 151, 149, 150, 152)
	noisy := ms(100, 400, 90, 380, 110, 350, 95, 420, 105, 390, 100, 410)

	v := judgeTiming(timingLane{"занят", base}, timingLane{"предел", base}, timingIQRCeilng, timingLowerN)
	require.Equal(t, "ok", v.kind, v.text)

	v = judgeTiming(timingLane{"занят", base}, timingLane{"предел", shifted}, timingIQRCeilng, timingLowerN)
	require.Equal(t, "red", v.kind, v.text)
	require.Contains(t, v.text, `"занят"`, "красное называет более быструю полосу")
	require.Contains(t, v.text, "50ms", "и на сколько")

	v = judgeTiming(timingLane{"занят", base}, timingLane{"предел", noisy}, timingIQRCeilng, timingLowerN)
	require.Equal(t, "not-performed", v.kind, v.text)
	require.Contains(t, v.text, "НЕ ВЫПОЛНИЛОСЬ")

	v = judgeTiming(timingLane{"занят", base[:5]}, timingLane{"предел", base}, timingIQRCeilng, timingLowerN)
	require.Equal(t, "not-performed", v.kind, "ниже нижней границы — вердикта нет")
	t.Logf("потолок годности IQR %v · нижняя граница N %d · критерий Ф1-48: |Δмедиан| ≤ max(IQR)", timingIQRCeilng, timingLowerN)
}

// timingStore — подставное хранилище двух полос: «занят» отвечает ключом
// почты на зеркале, «предел» — потолком темпа на фиксации; extra — внесённое
// различие (лишний хеш) в полосе «предел».
type timingStore struct {
	lane  string
	extra func()
}

func (s *timingStore) Writer(context.Context) (registration.Writer, error) {
	return &timingWriter{store: s}, nil
}

type timingWriter struct {
	humansession.Writer
	store *timingStore
}

func (w *timingWriter) Mirror(context.Context, registration.MirrorInput) (registration.MirrorResult, error) {
	if w.store.lane == "занят" {
		return registration.MirrorResult{}, iamerr.Wrapf(iamerr.ErrAlreadyExists, "users email")
	}
	return registration.MirrorResult{User: domain.User{ID: "usr-1", AccountID: "acc-1", Email: "probe@example.invalid",
		DisplayName: "Probe", InviteStatus: domain.InviteStatusActive}}, nil
}

func (w *timingWriter) InsertLoginMethod(context.Context, domain.LoginMethod) error { return nil }

func (w *timingWriter) InsertSession(context.Context, domain.HumanSession, domain.BearerDigest) error {
	return nil
}

func (w *timingWriter) RememberFirstAuthentication(context.Context, domain.UserID, time.Time) error {
	return nil
}

func (w *timingWriter) EmitAudit(context.Context, outboxtypes.AuditEvent) error { return nil }

func (w *timingWriter) Commit(context.Context) error {
	if w.store.extra != nil {
		w.store.extra()
	}
	return iamerr.Wrapf(iamerr.ErrQuotaRateExceeded, "window full")
}

func (w *timingWriter) Rollback(context.Context) error { return nil }

// TestRegisterTiming_F4_14_15_Live — живой замер на устройстве глагола: обе
// полосы (Ф4-14) и та же проба с внесённым различием в одной из них (Ф4-15).
func TestRegisterTiming_F4_14_15_Live(t *testing.T) {
	if os.Getenv(timingEnv) == "" {
		t.Skipf("измерительная проба Ф4-14…16 идёт РУЧНЫМ прогоном: %s=1 go test ./internal/apps/kaname/api/registration/ -run TestRegisterTiming_F4_14_15_Live -count=1 -v", timingEnv)
	}
	hasher, err := passwordverify.NewHasher(floorHasher())
	require.NoError(t, err)
	rule, err := humansession.NewPasswordRule(12, nil, humansession.NopObserver{}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	lane, ok := registration.LaneByName(registration.LanePassword)
	require.True(t, ok)
	build := func(store registration.Store) *registration.RegisterUseCase {
		uc, err := registration.NewRegisterUseCase(registration.Deps{
			Store: store, Rule: rule, Hasher: hasher, Lane: lane, TTL: time.Hour, Logger: slog.New(slog.DiscardHandler),
		})
		require.NoError(t, err)
		return uc
	}
	measure := func(t *testing.T, extra func()) (timingLane, timingLane) {
		t.Helper()
		ctx := context.Background()
		occupied := build(&timingStore{lane: "занят"})
		exhausted := build(&timingStore{lane: "предел", extra: extra})
		a, b := timingLane{name: "адрес занят"}, timingLane{name: "предел исчерпан"}
		// Прогрев — по обращению на полосу, в замер не идёт.
		_, _ = occupied.Execute(ctx, registration.Input{Email: "warm@example.invalid", Password: goodPassword})
		_, _ = exhausted.Execute(ctx, registration.Input{Email: "warm@example.invalid", Password: goodPassword})
		for i := 0; i < timingLaneN; i++ {
			for _, x := range []struct {
				uc *registration.RegisterUseCase
				l  *timingLane
			}{{occupied, &a}, {exhausted, &b}} {
				start := time.Now()
				_, err := x.uc.Execute(ctx, registration.Input{Email: "probe@example.invalid", Password: goodPassword})
				x.l.samples = append(x.l.samples, time.Since(start))
				require.ErrorIs(t, err, registration.ErrRefused, "полоса %s: отказ обязан быть единым отказом регистрации", x.l.name)
			}
		}
		for _, l := range []timingLane{a, b} {
			m, q := l.stats()
			t.Logf("полоса %-18s медиана %10v · IQR %10v · n=%d", l.name, m, q, len(l.samples))
		}
		return a, b
	}
	t.Logf("обращений на полосу %d · нижняя граница N %d · потолок годности IQR %v · критерий Ф1-48",
		timingLaneN, timingLowerN, timingIQRCeilng)

	t.Run("Ф4-14 без различия", func(t *testing.T) {
		a, b := measure(t, nil)
		v := judgeTiming(a, b, timingIQRCeilng, timingLowerN)
		t.Log(v.text)
		switch v.kind {
		case "ok":
		case "not-performed":
			t.Skip(v.text)
		default:
			t.Fatal(v.text)
		}
	})
	t.Run("Ф4-15 внесённое различие — один лишний хеш", func(t *testing.T) {
		a, b := measure(t, func() { _, _ = hasher.Hash("one-more-verification-cost") })
		v := judgeTiming(a, b, timingIQRCeilng, timingLowerN)
		t.Log(v.text)
		switch v.kind {
		case "red":
			require.Contains(t, v.text, `"адрес занят"`, "красное называет более быструю полосу")
		case "not-performed":
			t.Skip(v.text)
		default:
			t.Fatal("инъекция стоимости одной проверки НЕ покраснела — контроль проходит вхолостую: " + v.text)
		}
	})
}
