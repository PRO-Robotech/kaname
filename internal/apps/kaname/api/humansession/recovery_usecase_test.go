// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// recovery_usecase_test.go — ВОССТАНОВЛЕНИЕ ДОСТУПА на дублёре хранилища (фаза
// Ф5, задача PRO-Robotech/kacho#1271; приёмка
// `docs/engineering/acceptance/recovery-of-access.md`): запрос кода (Ф5-01,
// Ф5-02), предъявление в срок и завершение одним исходом (Ф5-03, Ф5-16…19),
// отказы — после срока, повторно, свёрткой, по частоте (Ф5-04, Ф5-05, Ф5-07,
// Ф5-08), заблокированная личность (Ф5-17, Ф1-59).
//
// Часы — пробы (форма Ф-д). Постановка письма идёт синхронным диспетчером:
// предмет проб — записи, а не то, что ответ их не ждёт (это Р2, и его держит
// проба диспетчера и полоса времени).

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

const rcSource = "203.0.113.42"

// letterOf — код из последнего письма дублёра: единственный путь, которым код
// доходит до человека.
func (h *harness) letterOf(t *testing.T, user domain.UserID) string {
	t.Helper()
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	for i := len(h.store.mail) - 1; i >= 0; i-- {
		if h.store.mail[i].UserID == user {
			return h.store.mail[i].Code.Letter()
		}
	}
	t.Fatalf("письма для %s нет", user)
	return ""
}

func (h *harness) request(t *testing.T, email string) {
	t.Helper()
	require.NoError(t, h.recoveryRequest.Execute(context.Background(),
		humansession.RequestRecoveryInput{Email: email, Source: rcSource}))
}

func (h *harness) complete(email, code, password string) (humansession.CompleteRecoveryOutput, error) {
	return h.completeFrom(email, code, password, rcSource)
}

func (h *harness) completeFrom(email, code, password, source string) (humansession.CompleteRecoveryOutput, error) {
	return h.recoveryComplete.Execute(context.Background(),
		humansession.CompleteRecoveryInput{Email: email, Code: code, NewPassword: password, Source: source})
}

// TestRecovery_F5_01_RequestForAVerifiedAddressMintsACodeAndQueuesTheLetter —
// Ф5-01: код чеканится со сроком нашей настройки, письмо ложится в очередь;
// ответ вызывающему ничего не несёт.
func TestRecovery_F5_01_RequestForAVerifiedAddressMintsACodeAndQueuesTheLetter(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-r01", "R01@Example.invalid", "old-password-1", true)

	h.request(t, "r01@example.invalid")

	codes := h.store.codesOf(u.ID)
	require.Len(t, codes, 1, "один запрос — один код")
	require.True(t, codes[0].ExpiresAt.Equal(ucBase.Add(rcCodeTTL)), "срок — момент выдачи плюс величина настройки (Ф1 §4.1: 5 минут)")
	require.True(t, codes[0].IssuedAt.Equal(ucBase))
	require.Nil(t, codes[0].ConsumedAt)
	require.Len(t, h.store.mail, 1, "письмо поставлено в нашу очередь")
	require.Equal(t, "R01@Example.invalid", h.store.mail[0].To, "письмо — на адрес личности, как он записан")
	require.Equal(t, u.ID, h.store.mail[0].UserID)
	require.Equal(t, rcCodeTTL, h.store.mail[0].ValidFor)
	require.NotEmpty(t, h.store.mail[0].Code.Letter())
	require.Equal(t, 1, h.obs.recoveryRequest[humansession.RecoveryRequestQueued])
}

// TestRecovery_F5_02_RequestForNobodyOrUnverifiedQueuesNothingAndAnswersTheSame —
// Ф5-02 (Ф1-26): адреса нет ни у кого — в очередь не поставлено ничего, ответ
// тот же; неподтверждённый адрес — то же (Ф1-25: код — для подтверждённого).
func TestRecovery_F5_02_RequestForNobodyOrUnverifiedQueuesNothingAndAnswersTheSame(t *testing.T) {
	h := newHarness(t, nil)
	unverified := h.person(t, "usr-r02", "r02@example.invalid", "old-password-2", false)

	h.request(t, "nobody@example.invalid")
	h.request(t, "r02@example.invalid")

	require.Empty(t, h.store.mail, "ни одного письма")
	require.Empty(t, h.store.codesOf(unverified.ID))
	require.Equal(t, 1, h.obs.recoveryRequest[humansession.RecoveryRequestNoRow])
	require.Equal(t, 1, h.obs.recoveryRequest[humansession.RecoveryRequestUnverified])

	// Форма — до всего: пустой адрес называется полем, а не глотается.
	err := h.recoveryRequest.Execute(context.Background(), humansession.RequestRecoveryInput{Source: rcSource})
	var fe *humansession.FieldError
	require.ErrorAs(t, err, &fe)
	require.Equal(t, "email", fe.Field)
}

// TestRecovery_F5_03_CorrectCodeCompletesInOneOutcome — Ф5-03 (Ф1-27), Ф5-18,
// Ф5-19, Ф5-16 (журнал), Р4: код в срок → прежние сессии сняты (обе, включая
// ту, из которой запрошено), отсечка «смена пароля» актором-человеком, новый
// материал записан, журнал по ключу потока, событие, выдана сессия по коду.
func TestRecovery_F5_03_CorrectCodeCompletesInOneOutcome(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-r03", "r03@example.invalid", "old-password-3", true)
	first := h.mustLogin(t, "r03@example.invalid", "old-password-3")
	h.clock = ucBase.Add(time.Minute)
	second := h.mustLogin(t, "r03@example.invalid", "old-password-3") // из неё запрошено
	h.clock = ucBase.Add(2 * time.Minute)
	h.request(t, "r03@example.invalid")
	letter := h.letterOf(t, u.ID)

	h.clock = ucBase.Add(3 * time.Minute)
	out, err := h.complete("r03@example.invalid", letter, "brand-new-password-3")
	require.NoError(t, err)

	s := out.View.Session
	require.Equal(t, []string{"recovery_code"}, s.PresentedMethods, "множество предъявленного — код (Ф11 Р8)")
	require.Equal(t, "1", s.AssuranceLevel, "уровень — нижняя ступень по правилу Ф11")
	// «пароль задан этим же исходом — требования нет» держится построением:
	// поля требования у сессии нет (kacho#2697, kaname#201); Ф5-24 — сессия
	// восстановления полноправна.
	require.True(t, s.AuthenticatedAt.After(h.clock), "сессия аутентифицирована ПОЗЖЕ отсечки (Ф5-19, Ф1 §4.2)")
	require.True(t, s.AuthenticatedAt.Equal(h.clock.Add(time.Microsecond)), "на единицу разрешения позже отсечки")
	require.True(t, s.ExpiresAt.Equal(s.AuthenticatedAt.Add(ucTTL)))
	require.False(t, out.Bearer.IsZero())
	require.Equal(t, u.ID, out.View.User.ID)
	require.True(t, out.View.EmailVerified)

	// Прежние сессии — обе негодны (Ф5-19), выданная восстановлением — годна.
	for _, b := range []domain.SessionBearer{first.Bearer, second.Bearer} {
		_, reason, err := h.store.Resolve(context.Background(), b.Digest(), h.clock.Add(time.Second))
		require.NoError(t, err)
		require.Equal(t, humansession.NoSessionEnded, reason)
	}
	got, reason, err := h.store.Resolve(context.Background(), out.Bearer.Digest(), h.clock.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, humansession.SessionFound, reason)
	require.Equal(t, s.ID, got.Session.ID)
	cut := h.store.cutoffs[u.ID]
	require.True(t, cut.at.Equal(h.clock), "отсечка — моментом завершения")
	require.Equal(t, domain.RevokeReasonPasswordChange, cut.reason, "причина — «смена пароля» (Ф1-17)")
	require.Equal(t, u.ID, cut.actor, "актор — сам человек")

	// Материал сменён: новым паролем входит (Ф5-18), прежним — нет.
	h.mustLogin(t, "r03@example.invalid", "brand-new-password-3")
	_, err = h.login.Execute(context.Background(), humansession.LoginInput{Email: "r03@example.invalid", Password: "old-password-3", Source: rcSource})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)

	// Журнал по ключу потока — идентификатору кода (Р4), событие — своё.
	codes := h.store.codesOf(u.ID)
	require.Len(t, codes, 1)
	require.NotNil(t, codes[0].ConsumedAt, "код применён")
	rc, ok := h.store.completions[string(codes[0].ID)]
	require.True(t, ok, "журнал завершений несёт ключ потока")
	require.Equal(t, u.ID, rc.UserID)
	require.Empty(t, rc.ExternalID, "наш поток внешнего субъекта не называет")
	var recovered, issued int
	for _, ev := range h.store.audit {
		switch ev.EventType {
		case humansession.AuditRecoveryCompleted:
			recovered++
			require.Equal(t, string(u.ID), ev.Payload["user_id"])
			require.Equal(t, string(codes[0].ID), ev.Payload["recovery_jti"])
			require.NotContains(t, ev.Payload, "email")
		case humansession.AuditSessionIssued:
			issued++
		}
	}
	require.Equal(t, 1, recovered, "событие завершения ровно одно")
	require.Equal(t, 3, issued, "события выдачи — у трёх входов (двух до и одного после): восстановление своего не дублирует (Ф3-47)")
	require.Equal(t, 1, h.obs.recoveryCompletion[humansession.RecoveryCompletionIssued])
}

// TestRecovery_F5_04_ExpiredCodeIsRefusedAndDoesNotRevive — Ф5-04 (Ф1-28).
func TestRecovery_F5_04_ExpiredCodeIsRefusedAndDoesNotRevive(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-r04", "r04@example.invalid", "old-password-4", true)
	h.request(t, "r04@example.invalid")
	letter := h.letterOf(t, u.ID)

	h.clock = ucBase.Add(rcCodeTTL)
	_, err := h.complete("r04@example.invalid", letter, "brand-new-password-4")
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "в момент срока кода уже нет")
	h.clock = ucBase.Add(rcCodeTTL + time.Minute)
	_, err = h.complete("r04@example.invalid", letter, "brand-new-password-4")
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "повтор не оживляет")
	require.Empty(t, h.store.rows, "сессия не выдана")
	require.Nil(t, h.store.codesOf(u.ID)[0].ConsumedAt)
	require.Equal(t, 2, h.obs.recoveryCompletion[humansession.RecoveryCompletionCodeRejected])
	require.Len(t, h.store.failures, 4, "каждое неверное предъявление — след по обеим осям (Ф5-08)")
}

// TestRecovery_F5_05_SecondPresentationIsRefused — Ф5-05 (Ф1-29): применённый
// код однократен.
func TestRecovery_F5_05_SecondPresentationIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-r05", "r05@example.invalid", "old-password-5", true)
	h.request(t, "r05@example.invalid")
	letter := h.letterOf(t, u.ID)

	_, err := h.complete("r05@example.invalid", letter, "brand-new-password-5")
	require.NoError(t, err)
	_, err = h.complete("r05@example.invalid", letter, "another-new-password-5")
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	require.Len(t, h.store.rows, 1, "второй сессии нет")
	require.Len(t, h.store.completions, 1, "второй записи журнала нет (Ф5-16)")
}

// TestRecovery_F5_07_StoredDigestIsNotAPresentation — Ф5-07: прочитанное из
// хранилища предъявлением не является; отказ равен отказу Ф5-04.
func TestRecovery_F5_07_StoredDigestIsNotAPresentation(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-r07", "r07@example.invalid", "old-password-7", true)
	h.request(t, "r07@example.invalid")
	stored := string(h.store.codesOf(u.ID)[0].Digest)

	_, err := h.complete("r07@example.invalid", stored, "brand-new-password-7")
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	_, err = h.complete("r07@example.invalid", h.letterOf(t, u.ID), "brand-new-password-7")
	require.NoError(t, err, "положительный контроль: настоящий код в тот же срок проходит")
}

// TestRecovery_F5_08_TooManyWrongCodesIsARateRefusalThatRevealsNothing — Ф5-08
// (Ф1-30): величины — настройка; отказ по частоте одинаков для существующего и
// несуществующего адреса; в пределах величины верный код принимается.
func TestRecovery_F5_08_TooManyWrongCodesIsARateRefusalThatRevealsNothing(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-r08", "r08@example.invalid", "old-password-8", true)
	h.request(t, "r08@example.invalid")
	n := limits().AddressAttempts

	// Полосы идут с РАЗНЫХ источников: ось источника общая, и с одного она
	// исчерпалась бы раньше оси адреса, смешав две причины в одном замере.
	var errExisting, errNobody error
	for i := 0; i <= n; i++ {
		_, errExisting = h.completeFrom("r08@example.invalid", "AAAAA-AAAAA", "brand-new-password-8", "203.0.113.81")
		_, errNobody = h.completeFrom("nobody@example.invalid", "AAAAA-AAAAA", "brand-new-password-8", "203.0.113.82")
	}
	var tmaExisting, tmaNobody *humansession.TooManyAttemptsError
	require.ErrorAs(t, errExisting, &tmaExisting, "после N неверных — отказ по частоте")
	require.ErrorAs(t, errNobody, &tmaNobody, "и для адреса, которого нет, — тот же")
	require.Equal(t, tmaExisting.Scope, tmaNobody.Scope)
	require.Equal(t, tmaExisting.RetryAfter, tmaNobody.RetryAfter)
	require.Equal(t, 2, h.obs.recoveryCompletion[humansession.RecoveryCompletionRateLimited])

	// Положительный контроль: в пределах величины верный код принимается.
	h2 := newHarness(t, nil)
	u2 := h2.person(t, "usr-r08b", "r08b@example.invalid", "old-password-8", true)
	h2.request(t, "r08b@example.invalid")
	for i := 0; i < n-1; i++ {
		_, err := h2.complete("r08b@example.invalid", "AAAAA-AAAAA", "brand-new-password-8")
		require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	}
	_, err := h2.complete("r08b@example.invalid", h2.letterOf(t, u2.ID), "brand-new-password-8")
	require.NoError(t, err)
	_ = u
}

// TestRecovery_F5_17_BlockedIdentityGetsTheBlockedLoginRefusal — Ф5-17, Ф1-59:
// запрос кода отвечает как всем; предъявление — тот же отказ, что на входе
// заблокированной; учётные данные сменены, отсечка стоит, журнал написан,
// сессия НЕ выдана, блокировка остаётся; войти по-прежнему нельзя.
func TestRecovery_F5_17_BlockedIdentityGetsTheBlockedLoginRefusal(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-r17", "r17@example.invalid", "old-password-17", true)
	prior := h.mustLogin(t, "r17@example.invalid", "old-password-17")
	u.InviteStatus = domain.InviteStatusBlocked
	h.store.users[u.ID] = u

	h.request(t, "r17@example.invalid")
	require.Len(t, h.store.mail, 1, "Ф1-59: ответ на запрос кода — как у всех, письмо уходит")
	letter := h.letterOf(t, u.ID)

	h.clock = ucBase.Add(time.Minute)
	_, err := h.complete("r17@example.invalid", letter, "brand-new-password-17")
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "тот же отказ, что на входе заблокированной (Ф1-05)")
	require.Equal(t, 1, h.obs.recoveryCompletion[humansession.RecoveryCompletionBlocked])

	require.Len(t, h.store.rows, 1, "новая сессия не выдана")
	_, reason, err := h.store.Resolve(context.Background(), prior.Bearer.Digest(), h.clock)
	require.NoError(t, err)
	require.Equal(t, humansession.NoSessionEnded, reason, "прежняя сессия снята")
	require.True(t, h.store.cutoffs[u.ID].at.Equal(h.clock), "отсечка ставится и на заблокированной строке")
	require.Len(t, h.store.completions, 1, "журнал написан")
	require.Equal(t, domain.InviteStatusBlocked, h.store.users[u.ID].InviteStatus, "блокировка остаётся")
	require.NotNil(t, h.store.codesOf(u.ID)[0].ConsumedAt, "код применён — повторно не оживёт")

	// Учётные данные сменены (Ф5-17): войти нельзя ни новым, ни старым — блокировка.
	_, err = h.login.Execute(context.Background(), humansession.LoginInput{Email: "r17@example.invalid", Password: "brand-new-password-17", Source: rcSource})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
	require.Equal(t, 1, h.obs.login[humansession.LoginOutcomeBlocked], "причина — блокировка, а не пароль: материал сменён")
	u.InviteStatus = domain.InviteStatusActive
	h.store.users[u.ID] = u
	h.mustLogin(t, "r17@example.invalid", "brand-new-password-17")
}

// TestRecovery_F5_25_CompletionResetsTheAddressCountOnlyAsALoginCompletedToEveryEnrolledFactor —
// Ф5-25 (Р5, Д13; правило — Ф3 Р10 и Ф12 Р7; задача PRO-Robotech/kaname#305):
// завершение восстановления решает счёт по адресу тем же местом решения, что
// вход. Сессия восстановления — «1» (`recovery_code`, Ф11 Р8), поэтому счёт
// обнуляется только у незаблокированной личности без второго фактора.
//
// Три личности, один отличающий факт у каждого замка против близнеца (б):
//
//	(а) [замок]   A — второй фактор заведён: счёт НЕ обнулён — второй неверный
//	              пароль после завершения упирается в частоту;
//	(б) [близнец] B — без второго фактора: счёт обнулён — оба неверных пароля
//	              после завершения — отказ входа;
//	(в) [замок]   C — заблокирована: сессии нет, отказ завершения сосчитан
//	              попыткой, счёт НЕ обнулён — первый же неверный пароль после
//	              упирается в частоту.
//
// Способность упасть — в обе стороны: обнуление, не связанное с достигнутым
// уровнем, краснеет на (а) и (в); отсутствие обнуления — на (б).
func TestRecovery_F5_25_CompletionResetsTheAddressCountOnlyAsALoginCompletedToEveryEnrolledFactor(t *testing.T) {
	lim := limits()
	// Дано: профиль, при котором ось источника не вмешивается в замер оси адреса.
	require.GreaterOrEqual(t, lim.AddressAttempts, 2, "Дано: N_адрес ≥ 2")
	require.Greater(t, lim.SourceAttempts, lim.AddressAttempts+1, "Дано: N_источник > N_адрес + 1")
	t.Logf("профиль: N_адрес %d за %v · N_источник %d за %v", lim.AddressAttempts, lim.AddressWindow,
		lim.SourceAttempts, lim.SourceWindow)

	h := newHarness(t, nil)
	type person struct {
		label          string
		user           domain.User
		email, source  string
		factor, locked bool
	}
	people := []*person{
		{label: "(а) A — второй фактор заведён", email: "r25a@example.invalid", source: "203.0.113.251", factor: true},
		{label: "(б) B — без второго фактора", email: "r25b@example.invalid", source: "203.0.113.252"},
		{label: "(в) C — заблокирована", email: "r25c@example.invalid", source: "203.0.113.253", locked: true},
	}
	for i, p := range people {
		p.user = h.person(t, fmt.Sprintf("usr-r25%d", i), p.email, "old-password-25", true)
		if p.factor {
			// Дано: строка второго фактора в состоянии «заведён» — посевом в
			// хранилище способов, без церемонии заведения (§7, строка Ф5-25).
			material, err := domain.NewLoginVerifier("seeded-second-factor-25")
			require.NoError(t, err)
			h.store.factors[p.user.ID] = map[domain.LoginMethodKind]*domain.LoginMethod{
				domain.LoginMethodTOTP: {UserID: p.user.ID, Kind: domain.LoginMethodTOTP, Verifier: material,
					State: domain.LoginMethodStateActive, CreatedAt: ucBase},
			}
		}
		if p.locked {
			p.user.InviteStatus = domain.InviteStatusBlocked
			h.store.users[p.user.ID] = p.user
		}
		h.request(t, p.email)
	}

	wrong := func(p *person) error {
		_, err := h.login.Execute(context.Background(),
			humansession.LoginInput{Email: p.email, Password: "not-the-password-25", Source: p.source})
		return err
	}
	isAuthFailed := func(err error) bool { return errors.Is(err, humansession.ErrAuthenticationFailed) }
	isAddressRate := func(err error) bool {
		var tma *humansession.TooManyAttemptsError
		return errors.As(err, &tma) && tma.Scope == humansession.FailureByAddress
	}

	type outcome struct {
		completion humansession.CompleteRecoveryOutput
		err        error
		after      [2]error
		count      int
	}
	got := map[*person]outcome{}
	for _, p := range people {
		// Когда: N_адрес − 1 неверных паролей на входе в одном окне.
		for i := 0; i < lim.AddressAttempts-1; i++ {
			require.True(t, isAuthFailed(wrong(p)), "%s: Дано — неверный пароль до завершения есть отказ входа", p.label)
		}
		var o outcome
		o.completion, o.err = h.completeFrom(p.email, h.letterOf(t, p.user.ID), "brand-new-password-25", p.source)
		o.count, _ = h.store.CountFailures(context.Background(), humansession.FailureByAddress,
			humansession.AddressKey(p.email), h.clock.Add(-lim.AddressWindow))
		o.after[0], o.after[1] = wrong(p), wrong(p)
		got[p] = o
		t.Logf("%s: завершение %v · счёт по адресу после завершения %d · неверные после: %v, %v",
			p.label, o.err, o.count, o.after[0], o.after[1])
	}

	a, b, c := got[people[0]], got[people[1]], got[people[2]]

	// (б) близнец — первым: без него замки ниже краснели бы и на полосе, не
	// выдающей ничего.
	require.NoError(t, b.err, "(б): завершение — исход Ф5-03")
	require.False(t, b.completion.Bearer.IsZero(), "(б): сессия выдана")
	assert.True(t, isAuthFailed(b.after[0]) && isAuthFailed(b.after[1]),
		"(б): счёт по адресу обнулён — оба неверных пароля после завершения есть отказ входа, получено %v, %v",
		b.after[0], b.after[1])

	// (а) замок: заведён второй фактор — «1» не уровень всех её факторов.
	require.NoError(t, a.err, "(а): завершение — исход Ф5-03")
	require.False(t, a.completion.Bearer.IsZero(), "(а): сессия выдана")
	require.Equal(t, []string{"recovery_code"}, a.completion.View.Session.PresentedMethods, "(а): сессия восстановления")
	require.True(t, isAuthFailed(a.after[0]), "(а): первый неверный пароль после завершения — отказ входа, получено %v", a.after[0])
	assert.True(t, isAddressRate(a.after[1]),
		"(а): второй неверный пароль обязан упереться в частоту по адресу — счёт НЕ обнулён завершением, "+
			"и бюджет подбора кода второго фактора не обновлён; получено %v (счёт после завершения %d)", a.after[1], a.count)

	// (в) замок: заблокирована — сессии нет, вход не завершён, отказ — попытка.
	require.ErrorIs(t, c.err, humansession.ErrAuthenticationFailed, "(в): тот же отказ, что на входе заблокированной (Ф1-59)")
	require.True(t, c.completion.Bearer.IsZero(), "(в): сессии нет")
	assert.True(t, isAddressRate(c.after[0]),
		"(в): первый неверный пароль после завершения обязан упереться в частоту по адресу — отказ завершения "+
			"сосчитан N_адрес-й попыткой, счёт НЕ обнулён; получено %v (счёт после завершения %d)", c.after[0], c.count)
	require.Equal(t, 1, h.obs.recoveryCompletion[humansession.RecoveryCompletionBlocked])
}

// TestRecovery_PolicyRefusalNamesTheFieldAndDoesNotConsumeTheCode — новый пароль
// судится правилом Ф1-32…38 ДО применения кода: отказ называет поле, код
// остаётся годным, и человек не тратит его на негодный пароль.
func TestRecovery_PolicyRefusalNamesTheFieldAndDoesNotConsumeTheCode(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-rpl", "rpl@example.invalid", "old-password-pl", true)
	h.request(t, "rpl@example.invalid")
	letter := h.letterOf(t, u.ID)

	_, err := h.complete("rpl@example.invalid", letter, "short")
	var fe *humansession.FieldError
	require.ErrorAs(t, err, &fe)
	require.Equal(t, "newPassword", fe.Field)
	require.Nil(t, h.store.codesOf(u.ID)[0].ConsumedAt, "код не применён")
	require.Empty(t, h.store.failures, "отказ формы попыткой не считается")

	_, err = h.complete("rpl@example.invalid", letter, "brand-new-password-pl")
	require.NoError(t, err)

	// Поля формы — до всего.
	for _, in := range []humansession.CompleteRecoveryInput{
		{Code: "x", NewPassword: "brand-new-password-pl"},
		{Email: "rpl@example.invalid", NewPassword: "brand-new-password-pl"},
		{Email: "rpl@example.invalid", Code: "x"},
	} {
		_, err := h.recoveryComplete.Execute(context.Background(), in)
		require.ErrorAs(t, err, &fe)
	}
}

// TestRecovery_F5_16_LedgerAlreadyHoldingTheFlowKeyIsAnInconsistencyNotASecondCutoff —
// Р4: ключ идемпотентности один. Ключ, уже стоящий в журнале при применённом
// впервые коде, — наша несогласованность: исход откатывается целиком, второго
// сдвига отсечки нет.
func TestRecovery_F5_16_LedgerAlreadyHoldingTheFlowKeyIsAnInconsistencyNotASecondCutoff(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-r16", "r16@example.invalid", "old-password-16", true)
	h.request(t, "r16@example.invalid")
	code := h.store.codesOf(u.ID)[0]
	h.store.completions[string(code.ID)] = domain.RecoveryCompletion{RecoveryJTI: string(code.ID), UserID: u.ID}

	_, err := h.complete("r16@example.invalid", h.letterOf(t, u.ID), "brand-new-password-16")
	require.ErrorIs(t, err, humansession.ErrStoreUnavailable)
	require.Empty(t, h.store.rows)
	_, ok := h.store.cutoffs[u.ID]
	require.False(t, ok, "второго сдвига отсечки нет")
	h.mustLogin(t, "r16@example.invalid", "old-password-16")
}

// TestRecovery_StoreRefusalLeavesTheCodeUsable — отказ хранилища посреди исхода
// откатывает всё: код остаётся годным, пароль прежний, сессии нет; повтор проходит.
func TestRecovery_StoreRefusalLeavesTheCodeUsable(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-rsf", "rsf@example.invalid", "old-password-sf", true)
	h.request(t, "rsf@example.invalid")
	letter := h.letterOf(t, u.ID)

	// "reset-failures" — решение о счёте по адресу местом решения входа: у
	// личности без второго фактора оно обнуляет счёт той же транзакцией.
	for _, op := range []string{"replace", "cutoff", "end-others", "reset-failures", "audit", "insert", "commit"} {
		h.store.failOn = op
		_, err := h.complete("rsf@example.invalid", letter, "brand-new-password-sf")
		require.ErrorIs(t, err, humansession.ErrStoreUnavailable, "отказ на %q", op)
		require.Empty(t, h.store.rows, "сессии нет (%s)", op)
		require.Nil(t, h.store.codesOf(u.ID)[0].ConsumedAt, "код не применён (%s)", op)
	}
	h.store.failOn = ""
	require.Equal(t, 7, h.obs.recoveryCompletion[humansession.RecoveryCompletionStoreFailed])
	_, err := h.complete("rsf@example.invalid", letter, "brand-new-password-sf")
	require.NoError(t, err)
}

// TestRecovery_WrongCodeRefusalIsTheSameForNobodyAndForSomeone — отказ по
// неверному коду не раскрывает, существует ли адрес: одна ошибка, одинаковый
// след по обеим осям.
func TestRecovery_WrongCodeRefusalIsTheSameForNobodyAndForSomeone(t *testing.T) {
	h := newHarness(t, nil)
	h.person(t, "usr-rwc", "rwc@example.invalid", "old-password-wc", true)
	h.request(t, "rwc@example.invalid")

	_, errSomeone := h.complete("rwc@example.invalid", "AAAAA-AAAAA", "brand-new-password-wc")
	_, errNobody := h.complete("nobody@example.invalid", "AAAAA-AAAAA", "brand-new-password-wc")
	require.ErrorIs(t, errSomeone, humansession.ErrAuthenticationFailed)
	require.ErrorIs(t, errNobody, humansession.ErrAuthenticationFailed)
	require.True(t, errors.Is(errSomeone, errNobody))
	require.Equal(t, errSomeone.Error(), errNobody.Error())
	require.Len(t, h.store.failures, 4)
	require.Equal(t, 1, h.obs.recoveryCompletion[humansession.RecoveryCompletionCodeRejected])
	require.Equal(t, 1, h.obs.recoveryCompletion[humansession.RecoveryCompletionNoRow])
}

// TestRecovery_ClosedOutcomeSetsAreDeclared — клетки счётчиков заводятся по
// закрытым перечням (форма Ф-е).
func TestRecovery_ClosedOutcomeSetsAreDeclared(t *testing.T) {
	require.ElementsMatch(t, []humansession.RecoveryRequestOutcome{
		humansession.RecoveryRequestQueued, humansession.RecoveryRequestNoRow, humansession.RecoveryRequestUnverified,
		humansession.RecoveryRequestStoreFailed,
	}, humansession.RecoveryRequestOutcomes())
	require.ElementsMatch(t, []humansession.RecoveryCompletionOutcome{
		humansession.RecoveryCompletionIssued, humansession.RecoveryCompletionNoRow, humansession.RecoveryCompletionCodeRejected,
		humansession.RecoveryCompletionBlocked, humansession.RecoveryCompletionRateLimited, humansession.RecoveryCompletionPasswordRejected,
		humansession.RecoveryCompletionStoreFailed,
	}, humansession.RecoveryCompletionOutcomes())
}

// TestGoDispatcher_WorkOutlivesTheRequestAndWaitReturnsAfterIt — Р2: постановка
// письма не удерживает ответ и не умирает вместе с контекстом запроса; остановка
// дожидается начатого.
func TestGoDispatcher_WorkOutlivesTheRequestAndWaitReturnsAfterIt(t *testing.T) {
	d := humansession.NewGoDispatcher(5 * time.Second)
	reqCtx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	var sawCancelled bool
	d.Dispatch(reqCtx, func(ctx context.Context) {
		close(started)
		<-release
		sawCancelled = ctx.Err() != nil
	})
	<-started
	cancel() // запрос ушёл, ответ отдан — работа продолжается
	close(release)
	d.Wait()
	require.False(t, sawCancelled, "контекст работы отвязан от контекста запроса")

	// Диспетчер, остановленный до постановки, работу не берёт и не теряет молча: он
	// исполняет её сразу, синхронно — иначе письмо, принятое ответом, не ушло бы.
	d2 := humansession.NewGoDispatcher(5 * time.Second)
	d2.Wait()
	ran := make(chan struct{}, 1)
	d2.Dispatch(context.Background(), func(context.Context) { ran <- struct{}{} })
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("работа после остановки не исполнена")
	}
}
