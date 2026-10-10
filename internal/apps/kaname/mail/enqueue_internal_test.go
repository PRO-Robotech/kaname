// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// enqueue_internal_test.go — решение Enqueue (замысел issue-2917 З1, З2;
// приёмка NTF-2 NTF2-52 в части модуля): при выключенном флаге — исход
// Disabled, и постановка ленты НЕ зовётся (строк 0 по построению); близнец —
// флаг включён, постановка позвана, исход Queued с id строки. Письмо здесь
// собрано мимо конструкторов — подменённой постановкой, чтобы судить решение
// Enqueue отдельно от ленты; конструкторы судит letters_test.go.
package mail

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/corelib/notify/feed"
)

func enabled(t *testing.T, on bool) Enabled {
	t.Helper()
	e, err := EnabledFrom(&on)
	if err != nil {
		t.Fatalf("фикстура: EnabledFrom(%v): %v", on, err)
	}
	return e
}

func enqueuer(t *testing.T, on bool) Enqueuer {
	t.Helper()
	q, err := NewEnqueuer(enabled(t, on))
	if err != nil {
		t.Fatalf("фикстура: NewEnqueuer: %v", err)
	}
	return q
}

// stubLetter — письмо с подменённой постановкой; calls считает вызовы.
func stubLetter(calls *int, id string, queued bool, err error) Letter {
	return Letter{template: "recovery", put: func(context.Context, pgx.Tx) (string, bool, error) {
		*calls++
		return id, queued, err
	}}
}

// TestEnqueueDisabledDoesNotPut — NTF2-52 (модуль): флаг выключен → Disabled,
// постановка не позвана; близнец — флаг включён → постановка позвана, Queued
// с id. Пара меняет ровно флаг.
func TestEnqueueDisabledDoesNotPut(t *testing.T) {
	var calls int
	r, err := enqueuer(t, false).Enqueue(context.Background(), nil, stubLetter(&calls, "ntf-1", true, nil))
	if err != nil {
		t.Fatalf("флаг false: ошибка %v", err)
	}
	if r.Outcome() != OutcomeDisabled {
		t.Fatalf("флаг false: исход %s, ожидался %s", r.Outcome(), OutcomeDisabled)
	}
	if calls != 0 {
		t.Fatalf("флаг false: постановка позвана %d раз — строка ленты была бы записана", calls)
	}
	if id, ok := r.FeedID(); ok || id != "" {
		t.Fatalf("флаг false: id строки %q, %v", id, ok)
	}

	// Близнец: тот же вызов при флаге true.
	r, err = enqueuer(t, true).Enqueue(context.Background(), nil, stubLetter(&calls, "ntf-1", true, nil))
	if err != nil {
		t.Fatalf("близнец: ошибка %v", err)
	}
	if calls != 1 || r.Outcome() != OutcomeQueued {
		t.Fatalf("близнец: вызовов %d, исход %s — ожидалось 1 и %s", calls, r.Outcome(), OutcomeQueued)
	}
	if id, ok := r.FeedID(); !ok || id != "ntf-1" {
		t.Fatalf("близнец: id строки %q, %v — ожидался ntf-1", id, ok)
	}
}

// TestEnqueueTemplateLimitIsCapped — лимит шаблона ленты исчерпан → исход
// Capped без ошибки: транзакция события пригодна к коммиту (feed З7).
func TestEnqueueTemplateLimitIsCapped(t *testing.T) {
	var calls int
	exhausted := fmt.Errorf("%w: шаблон recovery", feed.ErrLimitExhausted)
	r, err := enqueuer(t, true).Enqueue(context.Background(), nil, stubLetter(&calls, "", false, exhausted))
	if err != nil {
		t.Fatalf("лимит шаблона: ошибка %v — ожидался исход политики", err)
	}
	if r.Outcome() != OutcomeCapped {
		t.Fatalf("лимит шаблона: исход %s, ожидался %s", r.Outcome(), OutcomeCapped)
	}
	if _, ok := r.FeedID(); ok {
		t.Fatalf("лимит шаблона: id строки есть")
	}
}

// TestEnqueueDefectsAreErrors — сторожа постановки, кроме лимита, и ошибка
// хранилища — не исход политики, а ошибка: транзакция события откатывается
// (З1, О6). Корзины «прочее» нет.
func TestEnqueueDefectsAreErrors(t *testing.T) {
	cases := []error{
		feed.ErrAttrsInvalid,
		feed.ErrRecipientInvalid,
		feed.ErrDeliveryNotConfigured,
		feed.ErrSecondLimitedPut,
		feed.ErrSourceUnbound,
		errors.New("pg: соединение разорвано"),
	}
	for _, cause := range cases {
		t.Run(cause.Error(), func(t *testing.T) {
			var calls int
			r, err := enqueuer(t, true).Enqueue(context.Background(), nil, stubLetter(&calls, "", false, cause))
			if !errors.Is(err, cause) {
				t.Fatalf("ошибка %v — ожидалась с причиной %v", err, cause)
			}
			if !strings.Contains(err.Error(), "шаблон recovery") {
				t.Fatalf("ошибка %q не называет шаблон", err)
			}
			if r.Outcome() != OutcomeUnset {
				t.Fatalf("при ошибке исход %s — исхода быть не должно", r.Outcome())
			}
		})
	}
}

// TestEnqueueRowMissingUnderEnabledFlagIsAnError — флаг пакета включён, а
// постановка строки не записала: флаг пакета и источника ленты разошлись — это
// дефект сборки корня, а не Queued без id.
func TestEnqueueRowMissingUnderEnabledFlagIsAnError(t *testing.T) {
	var calls int
	r, err := enqueuer(t, true).Enqueue(context.Background(), nil, stubLetter(&calls, "", false, nil))
	if !errors.Is(err, ErrFlagMismatch) {
		t.Fatalf("ошибка %v — ожидалась ErrFlagMismatch", err)
	}
	if r.Outcome() != OutcomeUnset {
		t.Fatalf("исход %s при расхождении флагов", r.Outcome())
	}
}

// TestEnqueueRefusesUnbuiltLetter — письмо мимо конструктора (нулевой Letter)
// не принимается ни при каком флаге: решение о флаге не прячет дефект сборки.
func TestEnqueueRefusesUnbuiltLetter(t *testing.T) {
	for _, on := range []bool{false, true} {
		r, err := enqueuer(t, on).Enqueue(context.Background(), nil, Letter{})
		if !errors.Is(err, ErrLetterUnbuilt) {
			t.Fatalf("флаг %v: ошибка %v — ожидалась ErrLetterUnbuilt", on, err)
		}
		if r.Outcome() != OutcomeUnset {
			t.Fatalf("флаг %v: исход %s", on, r.Outcome())
		}
	}
}

// TestEnabledIsDeclaredNotDefaulted — флаг судится по наличию (З2, NTF2-50):
// nil — отказ с именем ключа; false — законное значение; нулевой Enabled
// NewEnqueuer не принимает.
func TestEnabledIsDeclaredNotDefaulted(t *testing.T) {
	if _, err := EnabledFrom(nil); err == nil || !strings.Contains(err.Error(), "notifications.enabled") {
		t.Fatalf("EnabledFrom(nil): %v — ожидался отказ с именем ключа", err)
	}
	off := enabled(t, false)
	if !off.Set() || off.On() {
		t.Fatalf("false: Set=%v On=%v", off.Set(), off.On())
	}
	on := enabled(t, true)
	if !on.Set() || !on.On() {
		t.Fatalf("true: Set=%v On=%v", on.Set(), on.On())
	}
	if _, err := NewEnqueuer(Enabled{}); err == nil {
		t.Fatalf("NewEnqueuer(Enabled{}) принят — неразобранный флаг неотличим от выключенного")
	}
}

// TestOutcomeVocabularies — закрытые перечни: исходов Enqueue восемь (З1),
// исходов метрики семь (Р6 приёмки), глаголов метрики три (работы окна З11);
// исход Enqueue переводится в исход метрики только там, где он им является.
func TestOutcomeVocabularies(t *testing.T) {
	var names []string
	for _, o := range Outcomes() {
		names = append(names, o.String())
	}
	want := []string{"queued", "resent_same", "floor", "trusted_device", "capped", "cooldown", "disabled", "no_recipient"}
	if !slices.Equal(names, want) {
		t.Fatalf("исходы Enqueue %v, ожидались %v", names, want)
	}
	if OutcomeUnset.String() != "unset" {
		t.Fatalf("нулевой исход: %q", OutcomeUnset.String())
	}

	var intents []string
	for _, o := range IntentOutcomes() {
		intents = append(intents, string(o))
	}
	wantIntents := []string{"queued", "resent_same", "cooldown", "capped", "floor", "trusted_device", "dropped_overload"}
	if !slices.Equal(intents, wantIntents) {
		t.Fatalf("исходы метрики %v, ожидались %v (приёмка NTF-2, Р6)", intents, wantIntents)
	}
	var verbs []string
	for _, v := range Verbs() {
		verbs = append(verbs, string(v))
	}
	if !slices.Equal(verbs, []string{"recovery", "register", "verify-email"}) {
		t.Fatalf("глаголы метрики %v", verbs)
	}

	mapped := map[Outcome]IntentOutcome{}
	for _, o := range Outcomes() {
		if i, ok := o.Intent(); ok {
			mapped[o] = i
		}
	}
	if len(mapped) != 6 {
		t.Fatalf("исходов Enqueue, являющихся исходом метрики, %d — ожидалось 6 (кроме disabled и no_recipient)", len(mapped))
	}
	for o, i := range mapped {
		if string(i) != o.String() {
			t.Fatalf("исход %s переведён в %s", o, i)
		}
	}
	for _, o := range []Outcome{OutcomeDisabled, OutcomeNoRecipient, OutcomeUnset} {
		if _, ok := o.Intent(); ok {
			t.Fatalf("исход %s переведён в исход метрики", o)
		}
	}
}
