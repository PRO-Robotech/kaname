// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_key_timing_probe_test.go — ИЗМЕРИТЕЛЬНАЯ проба ветви «л» Ф13-06:
// критерий Ф1-48 на полосе входа ключом доступа (приёмка
// `docs/engineering/acceptance/passwordless-login-with-access-key.md`, редакция
// 11, отпечаток 5b2f7bfc…, §6.4 «Ф13-06 «л» — уровень I»; задача kaname#468).
// Форма — строка «(л)» Ф13-06, образец — проба Ф3-31 (`timing_probe_test.go`).
//
// # Что меряется
//
// Полоса входа ключом идёт в процессе службы: настоящий глагол
// [humansession.AccessKeyLoginUseCase], за ним — настоящий проверяющий Ф7
// (`webauthnverify.VerifyAssertion`, Р13) и настоящая выдача; хранилище —
// дублёр `akStore`, не снисходительнее настоящего (испытание однократно и
// привязано к контексту). Время — настенными часами вокруг одного обращения ко
// входу; выдача испытания и подпись утверждения в замер не входят.
//
// Полос две, и они чередуются по кругу (Ф1-48: чередование, а не блоками —
// дрейф машины лёг бы на одну полосу):
//
//   - (а) «подпись не сверяется» — удостоверение известно, утверждение
//     подписано чужим ключом того же алгоритма;
//   - (б) «удостоверения нет» — удостоверения в хранилище нет вовсе.
//
// Различие, которое проба обязана поймать, — работа сверки: у известного
// удостоверения сверка идёт над открытым ключом строки, у неизвестного — над
// приманкой того же семейства (Р7 «л»). Полоса, сверяющая только известное,
// отвечала бы на (б) раньше на стоимость одной сверки.
//
// Критерий Ф1-48 на паре: |медиана(а) − медиана(б)| ≤ max(IQR(а), IQR(б)).
// Печатаются медианы, размахи, N обращений на полосу, T и N предела частоты,
// стоимость одной сверки и потолок годности; отказов по частоте — ноль.
//
// # Три исхода
//
// Зелёный — критерий выполнен. Красный — не выполнен, и красное называет пару
// полос. «Не выполнилось» — размах любой полосы выше потолка годности: стенд
// шумит сильнее различия, которое меряют, и вердикта нет ни в одну сторону
// (Ф1-50). Потолок — ПОЛОВИНА откалиброванной стоимости одной сверки: при
// размахе не выше неё различие в одну сверку выходит за размах вдвое, и
// инъекция Ф1-49 краснеет; выше — различие в одну сверку неотличимо от шума, и
// зелёный ничего бы не значил. Потолок и его судья — общие с Ф3-31
// (timingFitnessCeiling, timingCeilingFault): потолок не ниже различия —
// красное, дефект пробы. «Не выполнилось» подаётся `t.Skip` с меткой
// timingNotPerformed, а не `t.Fatalf`, и вердикт ручного прогона читает
// прогонщик `.github/scripts/go-test-verdict.py`: 0 · 1 · 2 «не выполнилось»
// (kaname#861).
//
// # Инъекция Ф1-49 — способность критерия упасть
//
// Ручка `KACHO_LOGIN_ACCESS_KEY_TIMING_INJECT=<имя полосы>` вносит в ОДНУ полосу
// ровно ту работу, которую выравнивание делает равной: одну лишнюю сверку
// утверждения этой полосы проверяющим Ф7, внутри замера. Это и есть класс
// дефекта — «сверка идёт только по одну сторону» — поданный настоящей работой,
// а не сном: сон на полосе в сотню микросекунд упёрся бы в разрешение таймера.
// С ручкой проба обязана покраснеть С ИМЕНЕМ этой полосы; без неё — зелёная
// (положительный контроль). Имя, которого среди полос нет, — «не выполнилось»
// словами. Способность критерия упасть на синтетике держит
// `timing_probe_verdict_test.go` на каждой отправке.
//
//	KACHO_LOGIN_ACCESS_KEY_TIMING=1 KACHO_LOGIN_ACCESS_KEY_TIMING_INJECT='(б) удостоверения нет' go test ./internal/apps/kaname/api/humansession/ -run TestAccessKeyLogin_F13_06_RefusalTimeIsIndistinguishableAcrossCredentialStates -count=1 -json > ak-timing.json; python3 .github/scripts/go-test-verdict.py < ak-timing.json
//
// # Почему ручной прогон
//
// Измерение настенными часами на общем ранере даёт размах выше потолка
// годности by construction (Ф1-50, §6.4 приёмки: уровень E у ветви снят по той
// же причине), и в наборе отправки такой прогон был бы жребием. Прогон — ручкой,
// как у соседних измерительных проб:
//
//	KACHO_LOGIN_ACCESS_KEY_TIMING=1 go test ./internal/apps/kaname/api/humansession/ -run TestAccessKeyLogin_F13_06 -count=1 -json > ak-timing.json; python3 .github/scripts/go-test-verdict.py < ak-timing.json
package humansession_test

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

const (
	akTimingEnv = "KACHO_LOGIN_ACCESS_KEY_TIMING"
	// akTimingInjectEnv — ручка инъекции Ф1-49: имя полосы, в которую внутри
	// замера вносится одна лишняя сверка утверждения проверяющим Ф7.
	akTimingInjectEnv  = "KACHO_LOGIN_ACCESS_KEY_TIMING_INJECT"
	akTimingRunCommand = "KACHO_LOGIN_ACCESS_KEY_TIMING=1 go test ./internal/apps/kaname/api/humansession/ " +
		"-run TestAccessKeyLogin_F13_06 -count=1 -json > ak-timing.json; " +
		"python3 .github/scripts/go-test-verdict.py < ak-timing.json"
	// akTimingLaneN — обращений на полосу; нижняя граница Ф1-48 — 10. Одно
	// обращение стоит доли миллисекунды, поэтому N объявлено с запасом над
	// границей: медиана тысячи обращений устойчива к редким выбросам планировщика
	// и сборщика мусора, которые на десятке легли бы в медиану.
	akTimingLaneN = 1000
	// akTimingLaneFloor — нижняя граница числа обращений на полосу (Ф1-48).
	akTimingLaneFloor = 10
	// akTimingCalibrationN — сверок в калибровке стоимости одной сверки.
	akTimingCalibrationN = 400
	akLaneSignature      = "(а) подпись не сверяется"
	akLaneUnknown        = "(б) удостоверения нет"
	akTimingSource       = "203.0.113.61"
)

// akTimingLane — полоса пробы: утверждение строится заново на каждое
// обращение, удостоверение и рукоятка — свои у полосы.
type akTimingLane struct {
	lane *timingLane
	// auth — аутентификатор, чьё удостоверение предъявляется.
	auth *webauthntest.Authenticator
	// forge — подписать чужим ключом того же алгоритма (ветвь «а»).
	forge bool
	// outcome — клетка, в которую обязан лечь отказ полосы: проба судит
	// фикстуру по ней ДО замера.
	outcome humansession.AccessKeyLoginOutcome
	// inject — внести одну лишнюю сверку внутри замера (Ф1-49).
	inject bool
}

// akMedian — медиана выборки длительностей.
func akMedian(s []time.Duration) time.Duration {
	c := append([]time.Duration(nil), s...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return c[len(c)/2]
}

// TestAccessKeyLogin_F13_06_RefusalTimeIsIndistinguishableAcrossCredentialStates —
// Ф13-06 «л»: работа по неизвестному удостоверению выполняется наравне с работой
// по известному, критерий Ф1-48 на паре полос (а) и (б).
func TestAccessKeyLogin_F13_06_RefusalTimeIsIndistinguishableAcrossCredentialStates(t *testing.T) {
	if os.Getenv(akTimingEnv) == "" {
		t.Skipf("измерительная проба Ф13-06 «л» идёт РУЧНЫМ прогоном: %s", akTimingRunCommand)
	}
	require.GreaterOrEqual(t, akTimingLaneN, akTimingLaneFloor, "N ниже нижней границы Ф1-48")
	h := newHarness(t, nil)
	ctx := context.Background()
	u := h.person(t, "usr-akt", "akt@example.invalid", "", true)
	known := webauthntest.New(t, webauthntest.AlgES256)
	stranger := webauthntest.New(t, webauthntest.AlgES256)
	handle := bytes.Repeat([]byte{6}, 64)
	keys := &akStore{user: u, key: domain.AccessKey{
		ID: "ak-akt", UserID: u.ID, CredentialID: known.CredentialID(), PublicKey: known.COSEPublicKey(t),
		Algorithm: known.Algorithm(), UserHandle: handle,
	}}
	h.store.accessKeyRows[keys.key.ID] = u.ID
	binding := webauthnverify.Binding{RPID: clkRPID, Origins: []string{clkOrigin},
		Algorithms: []webauthnverify.Algorithm{webauthnverify.AlgES256}}
	// Предел частоты — выше числа обращений с запасом: каждый отказ — попытка
	// по источнику (Р9), и проба не должна получить ни одного отказа по частоте.
	limitN, limitT := (akTimingLaneN+1)*2*10, 24*time.Hour
	now := func() time.Time { return h.clock }
	deps := humansession.AccessKeyLoginDeps{
		Store: h.store, Keys: keys, Methods: fakeMethods{h.store}, Binding: binding,
		ChallengeTTL: access_keys.ChallengeTTL, UserVerification: access_keys.UserVerificationAssertion,
		Limits: humansession.Limits{AddressAttempts: limitN, AddressWindow: limitT, SourceAttempts: limitN, SourceWindow: limitT},
		TTL:    ucTTL, Observer: h.obs, Now: now, Logger: slog.New(slog.DiscardHandler), CutoffClock: momentclock.Func(now),
	}
	begin, err := humansession.NewBeginAccessKeyLoginUseCase(deps)
	require.NoError(t, err)
	login, err := humansession.NewAccessKeyLoginUseCase(deps)
	require.NoError(t, err)
	form, err := humansession.NewFormContext()
	require.NoError(t, err)

	lanes := []*akTimingLane{
		{lane: &timingLane{name: akLaneSignature}, auth: known, forge: true, outcome: humansession.AccessKeyLoginSignature},
		{lane: &timingLane{name: akLaneUnknown}, auth: stranger, outcome: humansession.AccessKeyLoginCredentialUnknown},
	}
	// present — одно обращение полосы: испытание и утверждение — до замера,
	// вход (и инъекция) — внутри.
	present := func(l *akTimingLane) (time.Duration, error) {
		ch, err := begin.Execute(ctx, humansession.BeginAccessKeyLoginInput{FormContext: form, Source: akTimingSource})
		require.NoError(t, err, "Дано: испытание выдано")
		as := l.auth.Assert(t, webauthntest.AssertionOptions{Challenge: ch.Challenge, Origin: clkOrigin, RPID: clkRPID,
			ForgeSignature: l.forge})
		in := humansession.AccessKeyLoginInput{
			FormContext: form, CredentialID: as.CredentialID, ClientDataJSON: as.ClientDataJSON,
			AuthenticatorData: as.AuthenticatorData, Signature: as.Signature, UserHandle: handle, Source: akTimingSource,
		}
		extra := webauthnverify.AssertionInput{
			Challenge: ch.Challenge, Binding: binding, ClientDataJSON: as.ClientDataJSON,
			AuthenticatorData: as.AuthenticatorData, Signature: as.Signature,
			PublicKey: keys.key.PublicKey, Algorithm: webauthnverify.Algorithm(keys.key.Algorithm),
		}
		start := time.Now()
		_, err = login.Execute(ctx, in)
		if l.inject {
			// Ф1-49: работа одной сверки по одну сторону — класс дефекта
			// «сверка идёт только по известному удостоверению».
			_, _ = webauthnverify.VerifyAssertion(extra)
		}
		return time.Since(start), err
	}

	// Фикстура — ДО замера: каждая полоса обязана быть той ветвью, которую
	// называет, — единый отказ входа в своей клетке счётчика. Иначе сломанная
	// фикстура (полоса, отвергнутая формой или частотой) выдала бы себя за
	// неразличимость.
	for _, l := range lanes {
		before := h.obs.akLogin[l.outcome]
		_, err := present(l)
		require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "Дано: полоса %s — единый отказ входа", l.lane.name)
		require.Equal(t, before+1, h.obs.akLogin[l.outcome],
			"Дано: полоса %s — отказ в клетке %q; иначе это не та ветвь Ф13-06", l.lane.name, l.outcome)
	}
	require.Zero(t, h.obs.akLogin[humansession.AccessKeyLoginIssued], "Дано: ни одна полоса сессии не выдала")

	// Калибровка: стоимость одной сверки проверяющим Ф7 на машине прогона.
	calib := make([]time.Duration, 0, akTimingCalibrationN)
	ch, err := begin.Execute(ctx, humansession.BeginAccessKeyLoginInput{FormContext: form, Source: akTimingSource})
	require.NoError(t, err)
	as := stranger.Assert(t, webauthntest.AssertionOptions{Challenge: ch.Challenge, Origin: clkOrigin, RPID: clkRPID})
	probe := webauthnverify.AssertionInput{
		Challenge: ch.Challenge, Binding: binding, ClientDataJSON: as.ClientDataJSON,
		AuthenticatorData: as.AuthenticatorData, Signature: as.Signature,
		PublicKey: keys.key.PublicKey, Algorithm: webauthnverify.Algorithm(keys.key.Algorithm),
	}
	for i := 0; i < akTimingCalibrationN; i++ {
		start := time.Now()
		_, verr := webauthnverify.VerifyAssertion(probe)
		calib = append(calib, time.Since(start))
		require.Error(t, verr, "калибровка: подпись чужого ключа обязана не сойтись — иначе сверка не прошла целиком")
	}
	verifyCost := akMedian(calib)
	ceiling := timingFitnessCeiling(verifyCost)
	t.Logf("калибровка: стоимость одной сверки проверяющим Ф7 (ES256) — медиана %v из %d · потолок годности IQR %v (половина)",
		verifyCost, akTimingCalibrationN, ceiling)
	if err := timingCeilingFault(ceiling, verifyCost); err != nil {
		t.Fatalf("Ф1-50: %v", err)
	}

	// Инъекция Ф1-49 — по ручке, в одну названную полосу.
	injectName := os.Getenv(akTimingInjectEnv)
	if injectName != "" {
		// Имя, которого среди полос нет, — отказ словами с перечнем законных:
		// молча не внесённая инъекция дала бы зелёное, и оно прочиталось бы как
		// «критерий слеп».
		var names []string
		for _, l := range lanes {
			l.inject = l.lane.name == injectName
			if l.inject {
				names = nil
				break
			}
			names = append(names, strconv.Quote(l.lane.name))
		}
		if names != nil {
			t.Skipf("%s: ручка %s называет полосу %q, а такой полосы нет; законные: %s",
				timingNotPerformed, akTimingInjectEnv, injectName, strings.Join(names, ", "))
		}
		t.Logf("инъекция Ф1-49: полоса %q · одна лишняя сверка проверяющим Ф7 внутри замера (≈ %v)", injectName, verifyCost)
	}

	// Прогрев — по одному обращению на полосу, в замер не идёт.
	for _, l := range lanes {
		_, _ = present(l)
	}
	// Чередование по кругу.
	for i := 0; i < akTimingLaneN; i++ {
		for _, l := range lanes {
			d, err := present(l)
			require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "полоса %s: отказ обязан быть отказом входа, не частоты", l.lane.name)
			l.lane.samples = append(l.lane.samples, d)
		}
	}
	require.Zero(t, h.obs.akLogin[humansession.AccessKeyLoginRateLimited], "Ф13-06 «л»: отказов по частоте ноль")
	require.Zero(t, h.obs.akLogin[humansession.AccessKeyLoginIssued], "Ф13-06: ни одна ветвь сессии не выдала")

	t.Logf("предел частоты: N=%d за T=%v · обращений на полосу %d (нижняя граница %d) · потолок годности IQR %v",
		limitN, limitT, akTimingLaneN, akTimingLaneFloor, ceiling)
	rows := make([]timingRow, 0, len(lanes))
	for _, l := range lanes {
		m, q := l.lane.stats()
		rows = append(rows, timingRow{lane: l.lane, median: m, iqr: q})
		t.Logf("полоса %-28s медиана %10v · IQR %10v · n=%d · потолок годности %v", l.lane.name, m, q, len(l.lane.samples), ceiling)
	}
	if text, unfit := timingUnfitLane(rows, ceiling); unfit {
		t.Skip(text)
	}
	failures, lines := timingPairFailures(rows)
	for _, line := range lines {
		t.Logf("%s", line)
	}
	if injectName != "" {
		t.Logf("инъекция Ф1-49 при потолке годности IQR %v и N=%d: нарушивших пар %d — ждём красное С ИМЕНЕМ полосы %q",
			ceiling, akTimingLaneN, len(failures), injectName)
	}
	require.Empty(t, failures, "Ф13-06 «л» (Ф1-48) нарушен на паре полос: время единого отказа различает "+
		"известное удостоверение и его отсутствие")
}
