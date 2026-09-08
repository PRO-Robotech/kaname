// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// rule_test.go — правило отзыва: три исхода и симметрия «отозвать нечем».
package tokenrevocation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
)

type stubReader struct {
	before map[string]time.Time
	err    error
	asked  []string
}

func (s *stubReader) RevokedBefore(_ context.Context, subject string) (time.Time, bool, error) {
	s.asked = append(s.asked, subject)
	if s.err != nil {
		return time.Time{}, false, s.err
	}
	t, ok := s.before[subject]
	return t, ok, nil
}

func claims(m map[string]any) jwt.MapClaims {
	c := jwt.MapClaims{}
	for k, v := range m {
		c[k] = v
	}
	return c
}

// Материал, у которого НЕТ НИ ОДНОГО ключа отсечки, отозвать нечем — как и
// материал без отметки выпуска. Оба исхода обязаны совпасть: асимметрия внутри
// одного правила означала бы, что безопасность держится внешним предусловием у
// одного из двух вызывающих, а не построением самого правила.
//
// Положительный близнец идёт первым, иначе отрицание зеленело бы на правиле,
// объявляющем отозванным вообще всё.
func TestRevoked_NothingToRevokeAgainstIsRefused(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	r := &stubReader{}

	t.Run("положительный близнец: субъект назван, отсечки нет", func(t *testing.T) {
		revoked, err := tokenrevocation.Revoked(context.Background(), r,
			claims(map[string]any{"sub": "usr-alice", "iat": float64(now.Unix())}))
		if err != nil {
			t.Fatalf("ошибка: %v", err)
		}
		if revoked {
			t.Error("токен с названным субъектом и без отсечки объявлен отозванным")
		}
	})

	t.Run("ни одного ключа отсечки", func(t *testing.T) {
		revoked, err := tokenrevocation.Revoked(context.Background(), r,
			claims(map[string]any{"iat": float64(now.Unix())}))
		if err != nil {
			t.Fatalf("ошибка: %v", err)
		}
		if !revoked {
			t.Error("материал без единого ключа отсечки принят — отозвать его нечем " +
				"ни сейчас, ни потом")
		}
	})

	t.Run("нет отметки выпуска", func(t *testing.T) {
		revoked, err := tokenrevocation.Revoked(context.Background(), r,
			claims(map[string]any{"sub": "usr-alice"}))
		if err != nil {
			t.Fatalf("ошибка: %v", err)
		}
		if !revoked {
			t.Error("материал без отметки выпуска принят — он не сопоставим ни с какой отсечкой")
		}
	})
}

// Недоступность хранилища — ТРЕТИЙ исход, а не «не отозван».
func TestRevoked_UnreachableStoreIsAThirdOutcome(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	r := &stubReader{err: errors.New("хранилище недоступно")}

	revoked, err := tokenrevocation.Revoked(context.Background(), r,
		claims(map[string]any{"sub": "usr-alice", "iat": float64(now.Unix())}))
	if err == nil {
		t.Fatal("сбой хранилища прочитан как суждение — он неотличим от отсутствия отзыва")
	}
	if revoked {
		t.Error("при ошибке суждение выдано вместе с ней")
	}
}

// Ключей отсечки НЕСКОЛЬКО, и это не несколько механизмов, а несколько ключей у
// одного: отзыв клиента снимает и выданные им токены.
func TestRevoked_ClientKeyRevokesTokensItIssued(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	c := claims(map[string]any{
		"sub": "usr-alice", "iat": float64(now.Unix()), "kaname_user_token_id": "utk-1",
	})

	r := &stubReader{before: map[string]time.Time{"utk-1": now.Add(time.Minute)}}
	revoked, err := tokenrevocation.Revoked(context.Background(), r, c)
	if err != nil {
		t.Fatalf("ошибка: %v", err)
	}
	if !revoked {
		t.Errorf("отзыв клиента не снял выданный им токен; спрошены ключи: %v", r.asked)
	}

	// Отзыв действует ВПЕРЁД: выпущенное ПОСЛЕ отсечки действительно.
	later := claims(map[string]any{
		"sub": "usr-alice", "iat": float64(now.Add(2 * time.Minute).Unix()), "kaname_user_token_id": "utk-1",
	})
	revoked, err = tokenrevocation.Revoked(context.Background(),
		&stubReader{before: map[string]time.Time{"utk-1": now.Add(time.Minute)}}, later)
	if err != nil {
		t.Fatalf("ошибка: %v", err)
	}
	if revoked {
		t.Error("отзыв заблокировал принципала навсегда вместо снятия выданного")
	}
}
