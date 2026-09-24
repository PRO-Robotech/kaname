// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// timing_probe_test.go — ИЗМЕРИТЕЛЬНАЯ проба Ф3-31: критерий Ф1-48 на полосе
// входа по классам стоимости ID-PW-1 PWV-03 и полосам «материала нет» (PWV-06)
// и «адреса нет».
//
// # Что меряется
//
// Полосы обращений к `Login.Execute` с неверным паролем, чередуясь по кругу
// (Ф1-48: чередование, а не блоками — иначе дрейф машины лёг бы на одну
// полосу), по каждому классу мира прогона:
//
//   - A-популяция — bcrypt со стоимостью популяции (PWV-12: `bcrypt.MinCost` в
//     переносе фикстур этого дерева; настоящую перепись источника несёт Ф2);
//   - A-потолок — bcrypt на потолке записи (14);
//   - B-ручка — argon2id параметрами ручки «что писать» (пол: 64 МиБ · 3 · 4);
//   - B-потолок — argon2id на потолке записи (128 МиБ · 10 · 8);
//   - B-ниже-пола — память вдвое ниже пола, прочее — пол (законный перенос);
//   - материала нет — личность без строки способа входа;
//   - адреса нет — адрес, не принадлежащий никому.
//
// Критерий Ф1-48 на КАЖДОЙ паре: |медиана₁ − медиана₂| ≤ max(IQR₁, IQR₂).
// Печатаются медианы, размахи, N обращений на полосу, T и N предела частоты и
// сам критерий по парам; отказов по частоте — ноль (Ф3-30).
//
// Второе утверждение (Ф3-31 «Тогда», заказ kaname#220 (а)): НИ ОДНА медиана
// не ниже потолка огибающей — медиана раньше потолка есть красное С ИМЕНЕМ
// полосы: либо ожидание полосы не настоящее (часы порта вместо монотонных,
// отсчёт не от ворот), либо числа калибровки выбраны неверно (Р17). Проверка
// стоит ДО критерия пар: на полосе, ушедшей раньше потолка, пары краснеют
// следствием, и виновник назывался бы через них, а не по имени.
//
// # Огибающая по потолку (решение kaname#188)
//
// Полоса получает НАСТОЯЩУЮ огибающую (`passwordverify.Envelope`),
// откалиброванную на классах мира прогона и на классе ручки — ровно так, как
// композиционный корень калибрует её по переписи хранилища и ручке «что
// писать» при старте. Проба печатает калибровку (класс → стоимость) и потолок:
// критерий выполняется не потому, что полосы одинаково дороги, а потому, что
// ни один исход не уходит раньше потолка. Стоимости здесь — свойство машины
// прогона, а не контракт: контракт — критерий.
//
// # Три исхода
//
// Зелёный — критерий выполнен на всех парах. Красный — не выполнен хотя бы на
// одной: полоса названа. «Не выполнилось» — размах любой полосы выше потолка
// годности (`timingIQRCeiling`): стенд шумит сильнее, чем различимость, которую
// меряют, и вердикта нет ни в одну сторону (Ф1-50).
//
// # Почему ручной прогон
//
// Стоимость: A-потолок ≈ 1–2 с на обращение, B-потолок сравнимо; при N=12 на
// семь полос — минуты, и на общем ранере размах превышает потолок годности by
// construction. Прогон — ручкой, как у соседних измерительных приборов:
//
//	KACHO_LOGIN_TIMING=1 go test ./internal/apps/kaname/api/humansession/ -run TestLogin_F3_31 -count=1 -v -timeout 60m
package humansession_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

const (
	timingEnv        = "KACHO_LOGIN_TIMING"
	timingRunCommand = "KACHO_LOGIN_TIMING=1 go test ./internal/apps/kaname/api/humansession/ " +
		"-run TestLogin_F3_31 -count=1 -v -timeout 60m"
	// timingLaneN — обращений на полосу; нижняя граница Ф1-48 — 10.
	timingLaneN = 12
	// timingIQRCeiling — потолок годности замера: размах выше него означает,
	// что стенд шумит сильнее измеряемого, и вердикта нет (Ф1-50).
	timingIQRCeiling = 250 * time.Millisecond
)

type timingLane struct {
	name     string
	email    string
	password string
	samples  []time.Duration
}

func (l *timingLane) stats() (median, iqr time.Duration) {
	s := append([]time.Duration(nil), l.samples...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	q := func(p float64) time.Duration { return s[int(float64(len(s)-1)*p)] }
	return q(0.5), q(0.75) - q(0.25)
}

func argon2Verifier(t *testing.T, memory, iterations, parallelism uint32, password string) domain.LoginVerifier {
	t.Helper()
	h, err := passwordverify.NewHasher(passwordverify.Declared{Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: memory, domain.CostParamArgon2Iterations: iterations,
			domain.CostParamArgon2Parallelism: parallelism}})
	require.NoError(t, err)
	v, err := h.Hash(password)
	require.NoError(t, err)
	return v
}

// argon2Transferred — значение ниже пола записи, каким оно приходит ПЕРЕНОСОМ:
// хешер продукта его не пишет (отказ ниже пола), а проверяющий читает законно.
func argon2Transferred(t *testing.T, memory, iterations uint32, parallelism uint8, password string) domain.LoginVerifier {
	t.Helper()
	salt := []byte("0123456789abcdef")
	key := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, 32)
	phc := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
	v, err := domain.NewLoginVerifier(phc)
	require.NoError(t, err)
	return v
}

func bcryptVerifier(t *testing.T, cost int, password string) domain.LoginVerifier {
	t.Helper()
	b, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	require.NoError(t, err)
	v, err := domain.NewLoginVerifier(string(b))
	require.NoError(t, err)
	return v
}

// TestLogin_F3_31_RefusalTimeIsIndistinguishableAcrossCostClasses — проба Ф1-48 на
// полосе входа: критерий на каждой паре полос, отказов по частоте — ноль.
func TestLogin_F3_31_RefusalTimeIsIndistinguishableAcrossCostClasses(t *testing.T) {
	if os.Getenv(timingEnv) == "" {
		t.Skipf("измерительная проба Ф3-31 идёт РУЧНЫМ прогоном: %s", timingRunCommand)
	}
	h := newHarness(t, nil)
	ctx := context.Background()
	// Предел частоты — выше числа обращений на полосу с запасом: проба не
	// должна получить ни одного отказа по частоте (Ф3-30).
	limitN, limitT := timingLaneN*10, 24*time.Hour

	people := []struct {
		lane, email string
		material    domain.LoginVerifier
	}{
		{"A-популяция bcrypt(cost=min)", "a-pop@example.invalid", bcryptVerifier(t, bcrypt.MinCost, "real-a-pop")},
		{"A-потолок bcrypt(cost=14)", "a-ceil@example.invalid", bcryptVerifier(t, 14, "real-a-ceil")},
		{"B-ручка argon2id(64MiB·3·4)", "b-knob@example.invalid", argon2Verifier(t, 65536, 3, 4, "real-b-knob")},
		{"B-потолок argon2id(128MiB·10·8)", "b-ceil@example.invalid", argon2Verifier(t, 131072, 10, 8, "real-b-ceil")},
		{"B-ниже-пола argon2id(32MiB·3·4)", "b-low@example.invalid", argon2Transferred(t, 32768, 3, 4, "real-b-low")},
	}
	var lanes []*timingLane
	for i, p := range people {
		u := h.person(t, fmt.Sprintf("usr-t%d", i), p.email, "placeholder", true)
		h.store.verifiers[u.ID] = p.material
		lanes = append(lanes, &timingLane{name: p.lane, email: p.email, password: "wrong-" + strconv.Itoa(i)})
	}
	// Огибающая — как в композиционном корне: перепись классов хранилища
	// (здесь она известна пробе) плюс класс ручки, каждый — калибровкой.
	envelope, err := passwordverify.NewEnvelope(h.verifier, passwordverify.NopEnvelopeObserver{}, passwordverify.WallClockCostMeter)
	require.NoError(t, err)
	population := []domain.PasswordCostClass{
		costClass(domain.PasswordHashFormatBcrypt, domain.CostParamBcryptCost, uint32(bcrypt.MinCost)),
		costClass(domain.PasswordHashFormatBcrypt, domain.CostParamBcryptCost, 14),
		argon2Class(65536, 3, 4), argon2Class(131072, 10, 8), argon2Class(32768, 3, 4),
		{Format: h.hasher.Declared().Format, Params: h.hasher.Declared().Params},
	}
	for _, class := range population {
		adm, err := envelope.Admit(ctx, class, passwordverify.EnvelopeTriggerStartup)
		require.NoError(t, err, "калибровка класса %s", class.Key())
		t.Logf("калибровка %-52s стоимость %10v · калибрована %v", class.Key(), adm.Cost, adm.Calibrated)
	}
	ceiling, ok := envelope.Ceiling()
	require.True(t, ok)
	t.Logf("огибающая: потолок %v · класс-потолок %s (стоимость %v) · классов %d",
		envelope.Floor(), ceiling.Class.Key(), ceiling.Cost, len(envelope.Classes()))
	h.envelopePort = envelope
	require.NoError(t, rebuildLoginWithLimits(h, limitN, limitT))
	// Материала нет — личность без строки способа входа.
	noMat := h.person(t, "usr-nomat", "nomat@example.invalid", "placeholder", true)
	delete(h.store.verifiers, noMat.ID)
	lanes = append(lanes, &timingLane{name: "материала нет", email: "nomat@example.invalid", password: "wrong-nomat"})
	// Адреса нет.
	lanes = append(lanes, &timingLane{name: "адреса нет", email: "nobody@example.invalid", password: "wrong-nobody"})

	// Прогрев — по одному обращению на полосу, в замер не идёт.
	for _, l := range lanes {
		_, _ = h.login.Execute(ctx, humansession.LoginInput{Email: l.email, Password: l.password, Source: "203.0.113.31"})
	}
	// Чередование по кругу.
	for i := 0; i < timingLaneN; i++ {
		for _, l := range lanes {
			start := time.Now()
			_, err := h.login.Execute(ctx, humansession.LoginInput{Email: l.email, Password: l.password, Source: "203.0.113.31"})
			l.samples = append(l.samples, time.Since(start))
			require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "полоса %s: отказ обязан быть отказом входа, не частоты", l.name)
		}
	}
	require.Zero(t, h.obs.login[humansession.LoginOutcomeRateLimited], "Ф3-30: отказов по частоте ноль")

	t.Logf("предел частоты: N=%d за T=%v · обращений на полосу %d · потолок годности IQR %v · нижняя граница N — 10",
		limitN, limitT, timingLaneN, timingIQRCeiling)
	type row struct {
		lane        *timingLane
		median, iqr time.Duration
	}
	var rows []row
	floor := envelope.Floor()
	var belowFloor []string
	for _, l := range lanes {
		m, q := l.stats()
		rows = append(rows, row{l, m, q})
		t.Logf("полоса %-36s медиана %10v · IQR %10v · n=%d · потолок %v", l.name, m, q, len(l.samples), floor)
		if q > timingIQRCeiling {
			t.Fatalf("НЕ ВЫПОЛНИЛОСЬ (Ф1-50): размах полосы %q %v выше потолка годности %v — стенд шумит сильнее измеряемого, вердикта нет",
				l.name, q, timingIQRCeiling)
		}
		if m < floor {
			belowFloor = append(belowFloor, fmt.Sprintf("%s: медиана %v раньше потолка %v", l.name, m, floor))
		}
	}
	require.Empty(t, belowFloor, "Ф3-31: медиана раньше потолка огибающей — исход ушёл до потолка (ожидание не настоящее либо числа калибровки выбраны неверно, Р17)")
	var failures []string
	for i := range rows {
		for j := i + 1; j < len(rows); j++ {
			diff := rows[i].median - rows[j].median
			if diff < 0 {
				diff = -diff
			}
			bound := rows[i].iqr
			if rows[j].iqr > bound {
				bound = rows[j].iqr
			}
			verdict := "ok"
			if diff > bound {
				verdict = "КРАСНОЕ"
				failures = append(failures, fmt.Sprintf("%s ↔ %s: |Δмедиан| %v > IQR %v", rows[i].lane.name, rows[j].lane.name, diff, bound))
			}
			t.Logf("пара %-36s ↔ %-36s |Δмедиан| %10v ≤ IQR %10v — %s", rows[i].lane.name, rows[j].lane.name, diff, bound, verdict)
		}
	}
	require.Empty(t, failures, "Ф1-48 нарушен на парах полос: время отказа различает класс стоимости либо наличие материала")
}

func costClass(format domain.PasswordHashFormat, param domain.PasswordHashCostParam, value uint32) domain.PasswordCostClass {
	return domain.PasswordCostClass{Format: format, Params: map[domain.PasswordHashCostParam]uint32{param: value}}
}

func argon2Class(memory, iterations, parallelism uint32) domain.PasswordCostClass {
	return domain.PasswordCostClass{Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: memory, domain.CostParamArgon2Iterations: iterations,
			domain.CostParamArgon2Parallelism: parallelism}}
}

// rebuildLoginWithLimits — тот же вход с другим пределом частоты: проба времени
// не должна упереться в предел (Ф3-30), а умолчание харнесса низкое намеренно.
func rebuildLoginWithLimits(h *harness, attempts int, window time.Duration) error {
	login, err := humansession.NewLoginUseCase(humansession.LoginDeps{
		Store: h.store, Users: fakeUsers{h.store}, Methods: fakeMethods{h.store}, Verifier: h.verifier,
		Hasher: h.hasher, TTL: ucTTL, Observer: h.obs, Now: func() time.Time { return h.clock },
		Logger: slog.New(slog.DiscardHandler), Envelope: h.envelopePort, TOTP: h.totp, Sets: h.verifier,
		Limits: humansession.Limits{AddressAttempts: attempts, AddressWindow: window, SourceAttempts: attempts * 10, SourceWindow: window},
	})
	if err != nil {
		return err
	}
	h.login = login
	return nil
}
