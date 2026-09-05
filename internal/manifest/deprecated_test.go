// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// deprecated_test.go — раздел `deprecatedVerbs` (приёмка §2.7; сценарии
// MOD-MR-16 … MOD-MR-18).
//
// Раздел объявляет глаголы, которые платформа ПРИНИМАЕТ на чтении и НЕ
// ПРОИЗВОДИТ. Популяция сегодня — РОВНО ОДИН: `read` встречается в правилах
// системных ролей 19 раз и не производится ни одной строкой каталога.
//
// Обязательность всех четырёх ключей НАЗНАЧЕНА решением, а не выведена из
// частоты: узкая популяция предпосылку не подтверждает, а скрывает.
package manifest_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

const deprecatedBase = "apiVersion: iam/v1\nmodule: vpc\ndeprecatedVerbs:\n  read:\n%s"

const deprecatedAllKeys = "    class: get\n    since: \"2026-08-23\"\n" +
	"    reason: синоним чтения из прежней грамматики\n" +
	"    removeWhen: выдач с правом на сегмент .read ноль\n"

// ── MOD-MR-16 ───────────────────────────────────────────────────────────────

// TestMODMR16TheSingleLivingEntryLoadsAndResolvesToAClass — единственный
// сегодняшний вход принимается, и класс доступен вызывающему.
func TestMODMR16TheSingleLivingEntryLoadsAndResolvesToAClass(t *testing.T) {
	m, err := manifest.Load([]byte(strings.Replace(deprecatedBase, "%s", deprecatedAllKeys, 1)))
	if err != nil {
		t.Fatalf("действующая запись устаревшего глагола отвергнута: %v", err)
	}
	entry, ok := m.DeprecatedVerbs["read"]
	if !ok {
		t.Fatalf("глагол read не прочитан: %+v", m.DeprecatedVerbs)
	}
	if entry.Class != "get" {
		t.Errorf("класс устаревшего глагола прочитан как %q, объявлен get", entry.Class)
	}
	if entry.Since == "" || entry.Reason == "" || entry.RemoveWhen == "" {
		t.Errorf("запись прочитана неполно: %+v", entry)
	}

	// Та же запись живёт и в полной фикстуре — чтобы раздел не проверялся
	// только на синтетическом входе.
	full, err := manifest.Load([]byte(mustReadResourcesFixture(t)))
	if err != nil {
		t.Fatalf("фикстура отвергнута: %v", err)
	}
	if len(full.DeprecatedVerbs) != 1 {
		t.Errorf("устаревших глаголов в фикстуре %d, популяция — единица", len(full.DeprecatedVerbs))
	}
}

// ── MOD-MR-17 ───────────────────────────────────────────────────────────────

// TestMODMR17EveryOneOfTheFourKeysIsRequiredByName — отказ называет ИМЕННО тот
// ключ, которого нет: «запись неполна» посылает автора сличать четыре ключа
// руками.
//
// `removeWhen` обязателен наравне с прочими: без него запись не истечёт
// никогда, и список переживёт свой предмет.
func TestMODMR17EveryOneOfTheFourKeysIsRequiredByName(t *testing.T) {
	lines := map[string]string{
		"class":      "    class: get\n",
		"since":      "    since: \"2026-08-23\"\n",
		"reason":     "    reason: синоним чтения из прежней грамматики\n",
		"removeWhen": "    removeWhen: выдач с правом на сегмент .read ноль\n",
	}
	for missing := range lines {
		t.Run("без "+missing, func(t *testing.T) {
			body := ""
			for key, line := range lines {
				if key != missing {
					body += line
				}
			}
			_, err := manifest.Load([]byte(strings.Replace(deprecatedBase, "%s", body, 1)))
			if err == nil {
				t.Fatalf("запись без ключа %q принята", missing)
			}
			if !errors.Is(err, manifest.ErrDeprecatedVerbIncomplete) {
				t.Errorf("отказ не отнесён к своей причине: %v", err)
			}
			if !strings.Contains(err.Error(), "deprecatedVerbs.read."+missing) {
				t.Errorf("отказ не называет отсутствующий ключ %q: %v", missing, err)
			}
			for other := range lines {
				if other == missing {
					continue
				}
				if strings.Contains(err.Error(), "deprecatedVerbs.read."+other) {
					t.Errorf("отказ называет присутствующий ключ %q: %v", other, err)
				}
			}
		})
	}

	// Парный положительный: все четыре.
	if _, err := manifest.Load([]byte(strings.Replace(deprecatedBase, "%s", deprecatedAllKeys, 1))); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
}

// TestMODMR17DeprecatedClassIsCheckedAgainstTheSameClosedSet — класс
// устаревшего глагола судится ТЕМ ЖЕ закрытым набором, что и класс живого:
// второй словарь классов разошёлся бы с первым молча.
func TestMODMR17DeprecatedClassIsCheckedAgainstTheSameClosedSet(t *testing.T) {
	body := strings.Replace(deprecatedAllKeys, "class: get", "class: fetch", 1)
	_, err := manifest.Load([]byte(strings.Replace(deprecatedBase, "%s", body, 1)))
	if err == nil {
		t.Fatalf("класс вне закрытого набора принят у устаревшего глагола")
	}
	if !errors.Is(err, manifest.ErrVerbClassUnknown) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	if !strings.Contains(err.Error(), "deprecatedVerbs.read.class") {
		t.Errorf("отказ не называет поле: %v", err)
	}
}

// ── MOD-MR-18 ───────────────────────────────────────────────────────────────

// TestMODMR18AVerbIsNotBothDeprecatedAndLive — два правила об одном предмете —
// находка, а не выбор в пользу одного из них.
func TestMODMR18AVerbIsNotBothDeprecatedAndLive(t *testing.T) {
	base := "apiVersion: iam/v1\nmodule: vpc\nresources:\n" +
		"  - name: network\n    objectType: vpc_network\n    parents: [project]\n    producer: derived\n" +
		"    verbs: [get, list]\n" +
		"deprecatedVerbs:\n  %s:\n" + deprecatedAllKeys

	_, err := manifest.Load([]byte(strings.Replace(base, "%s", "get", 1)))
	if err == nil {
		t.Fatalf("глагол принят одновременно устаревшим и живым")
	}
	if !errors.Is(err, manifest.ErrDeprecatedVerbIsLive) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	for _, want := range []string{"deprecatedVerbs.get", "resources[0].verbs[0]", "network"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}

	// Парный положительный: устаревший глагол, которого нет ни в одном `verbs`.
	if _, err := manifest.Load([]byte(strings.Replace(base, "%s", "read", 1))); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
}
