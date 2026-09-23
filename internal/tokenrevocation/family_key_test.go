// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// family_key_test.go — ключ СЕМЕЙСТВА в правиле отзыва (задача
// PRO-Robotech/kaname#396, K1).
//
// Токен доступа церемонии несёт ключ семейства — идентификатор гранта, общий
// у всех выпусков одной выдачи. Отзыв семейства пишет отсечку по этому ключу,
// и предъявленный токен отозванного семейства обязан получить отказ ПРИ
// ЛЮБОЙ отметке выпуска: у отозванного семейства законного нового выпуска нет,
// а выпуск, лёгший позже отметки отзыва (одновременный повтор кода), и есть
// тот токен, ради снятия которого отзыв исполнялся.
package tokenrevocation_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
)

const (
	familyOfTest = "tfm-0123456789abcdefg"
	otherFamily  = "tfm-zyxwvtsrqpnmkjhgf"
)

// Ключ семейства входит в перечень ключей отсечки: иначе отсечку по нему не
// спросил бы ни один читатель, и отзыв семейства не доехал бы до предъявления.
func TestKeys_FamilyKeyIsACutoffKey(t *testing.T) {
	c := claims(map[string]any{
		"sub": "usr-alice", "iat": float64(1), tokenrevocation.FamilyKeyClaim: familyOfTest,
	})
	keys := tokenrevocation.Keys(c)
	if !slices.Contains(keys, familyOfTest) {
		t.Fatalf("ключ семейства %q не входит в ключи отсечки %v", familyOfTest, keys)
	}
	if !slices.Contains(keys, "usr-alice") {
		t.Fatalf("субъект выпал из ключей отсечки при ключе семейства: %v", keys)
	}
}

// Отсечка по ключу семейства действует на токен семейства ПРИ ЛЮБОЙ отметке
// выпуска — раньше отсечки, позже её и много позже. Близнец идёт первым:
// токен того же вида, но НЕОТОЗВАННОГО семейства, принимается — иначе
// отрицание зеленело бы на правиле, объявляющем отозванным всё.
func TestRevoked_FamilyCutoffRefusesAtAnyIssuedAt(t *testing.T) {
	cutoff := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	store := func() *stubReader {
		return &stubReader{before: map[string]time.Time{familyOfTest: cutoff}}
	}

	t.Run("близнец: семейство без отсечки принимается", func(t *testing.T) {
		r := store()
		revoked, err := tokenrevocation.Revoked(context.Background(), r, claims(map[string]any{
			"sub": "usr-alice", "iat": float64(cutoff.Add(-time.Minute).Unix()),
			tokenrevocation.FamilyKeyClaim: otherFamily,
		}))
		if err != nil {
			t.Fatalf("ошибка: %v", err)
		}
		if revoked {
			t.Fatal("токен неотозванного семейства объявлен отозванным")
		}
		if !slices.Contains(r.asked, otherFamily) {
			t.Fatalf("отсечку по ключу семейства не спросили; спрошены %v", r.asked)
		}
	})

	for _, tc := range []struct {
		name string
		iat  time.Time
	}{
		{"выпуск раньше отсечки", cutoff.Add(-time.Minute)},
		{"выпуск в миг отсечки", cutoff},
		{"выпуск позже отсечки", cutoff.Add(time.Second)},
		{"выпуск много позже отсечки", cutoff.Add(10 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := store()
			revoked, err := tokenrevocation.Revoked(context.Background(), r, claims(map[string]any{
				"sub": "usr-alice", "iat": float64(tc.iat.Unix()),
				tokenrevocation.FamilyKeyClaim: familyOfTest,
			}))
			if err != nil {
				t.Fatalf("ошибка: %v", err)
			}
			if !revoked {
				t.Fatalf("токен отозванного семейства с iat=%s принят при отсечке %s; спрошены %v",
					tc.iat.Format(time.RFC3339), cutoff.Format(time.RFC3339), r.asked)
			}
		})
	}
}

// Отсечка СУБЪЕКТА по-прежнему действует вперёд и при ключе семейства в
// составе: правило ключа семейства не переписывает правило субъекта.
func TestRevoked_SubjectCutoffStaysForwardBesideTheFamilyKey(t *testing.T) {
	cutoff := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	r := &stubReader{before: map[string]time.Time{"usr-alice": cutoff}}

	revoked, err := tokenrevocation.Revoked(context.Background(), r, claims(map[string]any{
		"sub": "usr-alice", "iat": float64(cutoff.Add(time.Minute).Unix()),
		tokenrevocation.FamilyKeyClaim: familyOfTest,
	}))
	if err != nil {
		t.Fatalf("ошибка: %v", err)
	}
	if revoked {
		t.Fatal("выпуск после отсечки субъекта объявлен отозванным: отсечка субъекта " +
			"стала вечной блокировкой принципала")
	}
}
