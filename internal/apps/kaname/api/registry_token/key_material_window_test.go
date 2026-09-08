// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// key_material_window_test.go — ОКНО ПЕРЕХОДА У ЛОМАЮЩЕГО ИЗМЕНЕНИЯ #1143.
//
// # Предмет
//
// Введение базового токена (#1142) и снятие приёма ключевого материала (#1143)
// уезжают ОДНИМ образом. Для арендатора это значит: выпустить удостоверение
// нового вида ДО обновления нельзя (глагол выдачи ещё прежний), войти прежним
// ПОСЛЕ обновления — тоже. Между этими двумя состояниями нет ни одного, в
// котором работает хоть что-то.
//
// Окно перехода — ручка, которой оператор ВРЕМЕННО принимает оба вида, пока
// переводит клиентов.
//
// # Почему окно — МГНОВЕНИЕ, а не флажок
//
// Флажок «принимать оба» не истекает никогда: он закрывается только тогда, когда
// кто-то вспомнит. Тогда ломающее изменение не наступает вовсе, а его предмет —
// приватная половина пары, идущая по сети, — остаётся навсегда и молча (ровно
// класс «контроль открыт навсегда и молча», security.md §Hardening п.8).
// Мгновение истекает САМО: бессрочное окно этой ручкой невыразимо by
// construction, и это утверждает BAT-2-03.
//
// # Почему каждое отрицание идёт в паре с положительным
//
// «Ключевой материал отвергнут» одинаково верно при закрытом окне и при полосе,
// сломанной целиком. Поэтому рядом с каждым отказом стоит вход, который обязан
// пройти.

package registry_token

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/credsecret"
)

// fakeKeyMaterialValidator — авторитет прежней полосы. Признаёт РОВНО одну
// пару; всё прочее отвергает так же, как отвергал настоящий, — дублёр,
// принимающий больше настоящего, сделал бы невидимым то, ради чего его
// подставляют.
type fakeKeyMaterialValidator struct {
	clientID string
	material string
	subject  string
	calls    int
}

func (f *fakeKeyMaterialValidator) Validate(_ context.Context, clientID, material string) (Credential, error) {
	f.calls++
	if clientID != f.clientID || material != f.material {
		return Credential{}, ErrInvalidCredentials
	}
	return Credential{ClientID: clientID, KeyID: clientID, Subject: f.subject}, nil
}

// recordingObserver — счётчик исходов полос, поднятый в пробу портом. Считает
// ВСЕ исходы, а не только отказы: счётчик одних отказов не отличает «отказов не
// было» от «входов не было вовсе».
type recordingObserver struct{ seen map[string]int }

func newRecordingObserver() *recordingObserver {
	return &recordingObserver{seen: map[string]int{}}
}

func (o *recordingObserver) ObserveCredentialKind(outcome string) { o.seen[outcome]++ }

// windowLane собирает полосу, у которой ОБЕ полосы предъявленного удостоверения
// провязаны, и возвращает средства управлять окном и читать счётчик.
func windowLane(t *testing.T, windowUntil time.Time, now time.Time) (
	uc *IssueRegistryTokenUseCase,
	obs *recordingObserver,
	basicID, basicSecret string,
	kmClientID, kmMaterial string,
) {
	t.Helper()
	const credID, svaID = "soc_0000000000001143w", "sva0000000000001143w"
	secret, _, err := credsecret.Mint(credID)
	if err != nil {
		t.Fatal(err)
	}
	res := &fakeBasicResolver{
		live:  map[string]string{credID: secret},
		svaOf: map[string]string{credID: svaID},
	}
	uc, _ = basicDockerLane(t, res)
	obs = newRecordingObserver()

	km := &fakeKeyMaterialValidator{
		clientID: "soc_0000000000001143k",
		material: pemLikeKeyMaterial,
		subject:  "sva0000000000001143k",
	}
	uc = uc.
		WithClock(func() time.Time { return now }).
		WithCredentialKindObserver(obs).
		WithKeyMaterialWindow(windowUntil, km)

	return uc, obs, credID, secret, km.clientID, km.material
}

// BAT-2-01 — УМОЛЧАНИЕ: окна нет, прежний вид отвергается; базовый проходит.
//
// Утверждается и счётчик: без него оператор, у которого обновление сломало
// вход арендаторам, узнаёт об этом из жалобы, а не из наблюдения.
func TestBAT2_01_WithoutAWindowKeyMaterialIsRefusedAndCounted(t *testing.T) {
	// Нулевое мгновение — «окно не объявлено». Это и есть умолчание.
	uc, obs, basicID, basicSecret, kmID, kmMaterial := windowLane(t, time.Time{}, time.Now())

	// Положительный контроль ПЕРВЫМ.
	if _, err := uc.Execute(context.Background(), IssueInput{
		Username: basicID, Password: basicSecret, Service: "registry",
	}); err != nil {
		t.Fatalf("вход базовым токеном обязан проходить — иначе отрицание ниже вакуумно: %v", err)
	}

	_, err := uc.Execute(context.Background(), IssueInput{
		Username: kmID, Password: kmMaterial, Service: "registry",
	})
	if !errors.Is(err, ErrCredentialKindNotAccepted) {
		t.Fatalf("без объявленного окна ключевой материал обязан отвергаться: %v", err)
	}

	if got := obs.seen[OutcomeBasicAccepted]; got != 1 {
		t.Errorf("исход basic_accepted обязан считаться (знаменатель): %d", got)
	}
	if got := obs.seen[OutcomeKeyMaterialRefused]; got != 1 {
		t.Errorf("отказ прежнему виду обязан считаться СЧЁТЧИКОМ, а не только строкой журнала: %d", got)
	}
	if got := obs.seen[OutcomeKeyMaterialAcceptedInWindow]; got != 0 {
		t.Errorf("без окна принятых прежним видом быть не может: %d", got)
	}
}

// BAT-2-02 — ОКНО ОТКРЫТО: прежний вид принимается и считается ОТДЕЛЬНЫМ
// исходом. Отдельным — потому что это и есть предикат закрытия окна: пока он
// не ноль, закрывать нельзя.
func TestBAT2_02_OpenWindowAcceptsKeyMaterialAndCountsItApart(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	uc, obs, basicID, basicSecret, kmID, kmMaterial := windowLane(t, now.Add(time.Hour), now)

	out, err := uc.Execute(context.Background(), IssueInput{
		Username: kmID, Password: kmMaterial, Service: "registry",
	})
	if err != nil {
		t.Fatalf("при открытом окне прежний вид обязан приниматься — иначе окна нет: %v", err)
	}
	if out.Token == "" {
		t.Fatal("удостоверение реестра не выдано на открытом окне")
	}

	// Положительный контроль: окно НЕ подменяет собой новую полосу.
	if _, err := uc.Execute(context.Background(), IssueInput{
		Username: basicID, Password: basicSecret, Service: "registry",
	}); err != nil {
		t.Fatalf("открытое окно обязано принимать ОБА вида, а не заменять один другим: %v", err)
	}

	if got := obs.seen[OutcomeKeyMaterialAcceptedInWindow]; got != 1 {
		t.Errorf("принятое окном обязано считаться ОТДЕЛЬНО: это предикат его закрытия: %d", got)
	}
	if got := obs.seen[OutcomeBasicAccepted]; got != 1 {
		t.Errorf("исход basic_accepted обязан считаться: %d", got)
	}
	if got := obs.seen[OutcomeKeyMaterialRefused]; got != 0 {
		t.Errorf("при открытом окне отказов прежнему виду быть не должно: %d", got)
	}
}

// BAT-2-03 — ОКНО ИСТЕКАЕТ САМО. Полоса та же, ручка та же; двинулись ТОЛЬКО
// часы. Это и есть утверждение «бессрочное окно невыразимо»: закрывает его
// время, а не чьё-то решение и не второй флажок.
func TestBAT2_03_WindowClosesByTheClockAloneNotByAnyDecision(t *testing.T) {
	declared := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	before := declared.Add(-time.Minute)
	ucOpen, _, _, _, kmID, kmMaterial := windowLane(t, declared, before)
	if _, err := ucOpen.Execute(context.Background(), IssueInput{
		Username: kmID, Password: kmMaterial, Service: "registry",
	}); err != nil {
		t.Fatalf("до объявленного мгновения окно обязано быть открыто — иначе отрицание ниже вакуумно: %v", err)
	}

	after := declared.Add(time.Minute)
	ucClosed, obs, basicID, basicSecret, _, _ := windowLane(t, declared, after)
	_, err := ucClosed.Execute(context.Background(), IssueInput{
		Username: kmID, Password: kmMaterial, Service: "registry",
	})
	if !errors.Is(err, ErrCredentialKindNotAccepted) {
		t.Fatalf("после объявленного мгновения окно обязано быть закрыто САМО: %v", err)
	}
	if got := obs.seen[OutcomeKeyMaterialRefused]; got != 1 {
		t.Errorf("отказ по истёкшему окну обязан считаться — оператор узнаёт, кого он ещё не перевёл: %d", got)
	}

	// Положительный контроль: истёкшее окно закрывает ТОЛЬКО прежний вид.
	if _, err := ucClosed.Execute(context.Background(), IssueInput{
		Username: basicID, Password: basicSecret, Service: "registry",
	}); err != nil {
		t.Fatalf("истёкшее окно не имеет права закрывать базовую полосу: %v", err)
	}
}

// BAT-2-04 — ОТКАЗ НЕРАЗЛИЧИМ. Предъявитель не узнаёт, объявлено ли окно на
// этом контуре: иначе ручка стала бы оракулом посадки, а перебор по ней —
// способом узнать, принимает ли контур ключевой материал.
func TestBAT2_04_RefusalDoesNotRevealWhetherAWindowIsDeclared(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	// Окна нет вовсе.
	ucNoWindow, _, _, _, kmID, kmMaterial := windowLane(t, time.Time{}, now)
	_, errNoWindow := ucNoWindow.Execute(context.Background(), IssueInput{
		Username: kmID, Password: kmMaterial, Service: "registry",
	})

	// Окно объявлено и ОТКРЫТО, но предъявлен негодный материал.
	ucOpen, _, _, _, kmID2, _ := windowLane(t, now.Add(time.Hour), now)
	_, errBadInWindow := ucOpen.Execute(context.Background(), IssueInput{
		Username: kmID2, Password: "-----BEGIN PRIVATE KEY-----\nwrong\n-----END PRIVATE KEY-----",
		Service: "registry",
	})

	if !errors.Is(errNoWindow, ErrUnauthenticated) || !errors.Is(errBadInWindow, ErrUnauthenticated) {
		t.Fatalf("оба отказа обязаны быть отказами аутентификации: %v / %v", errNoWindow, errBadInWindow)
	}
	if errNoWindow.Error() == errBadInWindow.Error() {
		return // тексты совпали — различить нечем, это и требуется
	}
	// Тексты РАЗНЫЕ — законно ровно постольку, поскольку наружу их не отдают:
	// обработчик отвечает одним фиксированным телом. Здесь утверждается, что
	// различие не выходит за пределы sentinel'ов, которые читает журнал.
	if !errors.Is(errNoWindow, ErrCredentialKindNotAccepted) {
		t.Fatalf("отказ без окна обязан нести журнальный sentinel вида: %v", errNoWindow)
	}
	if errors.Is(errBadInWindow, ErrCredentialKindNotAccepted) {
		t.Fatalf("негодный материал ПРИ ОТКРЫТОМ окне — не «негодный вид»: %v", errBadInWindow)
	}
}
