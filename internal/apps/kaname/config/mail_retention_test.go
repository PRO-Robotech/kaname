// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_retention_test.go — СРОК ХРАНЕНИЯ МОМЕНТОВ выводится из верхних границ
// окон, которые их читают (замысел NTF-2 З26, CX2-29).
//
//	Х1  для каждого вида каждой таблицы моментов срок хранения строго больше
//	    верхней границы каждого читающего окна — по таблице границ, а не по
//	    настроенному значению;
//	Х2  вывод функции совпадает со строками таблицы замысла «Сроки на границах
//	    Р8» — числа там вывод, а не объявление;
//	Х3  инъекция: вид `throttled` с литералом 25 ч вместо вывода — находка с
//	    именем вида и границы; близнец — функция как есть — молчит.
//
// Разбор вынесен в функцию, возвращающую находки, чтобы инъекция подавала ему
// битую функцию срока, не роняя саму пробу.
package config_test

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// upperWindow — верхняя граница окна ручки по таблице границ: у длительности —
// её Max, у счёта — окно, заданное именем.
func upperWindow(b config.MailBound) (time.Duration, bool) {
	switch b.Kind {
	case config.MailBoundDuration:
		return time.Duration(b.Max), b.HasMax
	case config.MailBoundCount:
		return b.Window, b.Window > 0
	default:
		return 0, false
	}
}

// auditRetention — находки Х1 для функции срока retention и число осмотренных
// пар «вид × читающее окно».
func auditRetention(retention func(config.MailMomentKind) time.Duration) (findings []string, pairs int) {
	byKey := map[string]config.MailBound{}
	for _, b := range config.MailBounds {
		byKey[b.Key] = b
	}
	kinds := make([]string, 0, len(config.MailMomentReaders))
	for k := range config.MailMomentReaders {
		kinds = append(kinds, string(k))
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		kind := config.MailMomentKind(k)
		got := retention(kind)
		for _, key := range config.MailMomentReaders[kind] {
			b, ok := byKey[key]
			if !ok {
				findings = append(findings, fmt.Sprintf("вид %s: читающее окно %s не объявлено таблицей границ", kind, key))
				continue
			}
			w, ok := upperWindow(b)
			if !ok {
				findings = append(findings, fmt.Sprintf("вид %s: у окна %s нет верхней границы — срок хранения не выводится", kind, key))
				continue
			}
			pairs++
			if got <= w {
				findings = append(findings, fmt.Sprintf("вид %s: срок хранения %s не больше верхней границы %s окна %s",
					kind, got, w, key))
			}
		}
	}
	return findings, pairs
}

// Х1.
func TestMailRetentionExceedsEveryReadingWindow(t *testing.T) {
	findings, pairs := auditRetention(config.MailRetention)
	for _, f := range findings {
		t.Error(f)
	}
	require.Positive(t, pairs, "обход пуст: не осмотрено ни одной пары — вердикт о непрочитанном")
	t.Logf("перепись: видов %d · пар «вид × окно» %d · находок %d", len(config.MailMomentReaders), pairs, len(findings))
}

// Х2.
func TestMailRetentionMatchesTheDesignTable(t *testing.T) {
	want := map[config.MailMomentKind]time.Duration{
		config.MailMomentThrottled:     30*24*time.Hour + time.Hour,
		config.MailMomentProgression:   25 * time.Hour,
		config.MailMomentFloor:         25 * time.Hour,
		config.MailMomentTrustedDevice: 25 * time.Hour,
		config.MailMomentInviteActs:    25 * time.Hour,
		config.MailMomentTrustedLabels: 365*24*time.Hour + time.Hour,
	}
	require.Len(t, config.MailMomentReaders, len(want), "видов в таблице замысла столько же, сколько у функции")
	for kind, d := range want {
		require.Equal(t, d, config.MailRetention(kind), "вид %s", kind)
	}
}

// Х3.
func TestMailRetentionAuditFindsALiteral(t *testing.T) {
	injected := func(kind config.MailMomentKind) time.Duration {
		if kind == config.MailMomentThrottled {
			return 25 * time.Hour
		}
		return config.MailRetention(kind)
	}
	findings, _ := auditRetention(injected)
	require.Len(t, findings, 1, "литерал 25 ч у `throttled` — ровно одна находка: %v", findings)
	require.Contains(t, findings[0], string(config.MailMomentThrottled))
	require.Contains(t, findings[0], "authn.login.mail-throttled-interval")
	require.Contains(t, findings[0], (30 * 24 * time.Hour).String())

	clean, _ := auditRetention(config.MailRetention)
	require.Empty(t, clean, "близнец: функция как есть — находок нет")
}
