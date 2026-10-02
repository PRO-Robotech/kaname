// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// family_test.go — отзыв СЕМЕЙСТВА выпуска — часть ТОГО ЖЕ правила, что и
// отсечки по ключам (kaname#319, решение К10 вариант А; приёмка LINE-A-1,
// сценарии 01 и 21).
//
// # Что утверждается
//
// Правило спрашивает хранилище о семействе выпуска ПО ЕГО ИДЕНТИФИКАТОРУ и
// отвечает о нём тем же вызовом, что об отсечках. Отдельного обращения за
// семейством у вызывающего нет: поверхность, спросившая правило, получила и
// ответ о семействе, — иначе одно решение о доступе принимали бы два читателя.
//
// # Близнецы
//
// Каждое отрицание отличается от своего близнеца ОДНИМ фактом: отозвано ли
// семейство (T1), то ли это семейство (T2), ответило ли хранилище (третий
// исход). Без близнеца отрицание зеленело бы на правиле, объявляющем
// отозванным всё.
package tokenrevocation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
)

// familyClaims — годный состав выпуска семейства: субъект, отметка выпуска и
// идентификатор. Отсечек по ключам у стаба нет, поэтому исход решает ТОЛЬКО
// ответ о семействе.
func familyClaims(jti string, issued time.Time) map[string]any {
	return map[string]any{"sub": "usr-alice", "iat": float64(issued.Unix()), "jti": jti}
}

// TestRevoked_LINE_A_1_21_FamilyOfTheIssuanceIsJudgedByTheSameRule — отзыв
// семейства действует на предъявлении тем же правилом, что отсечки.
func TestRevoked_LINE_A_1_21_FamilyOfTheIssuanceIsJudgedByTheSameRule(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

	t.Run("T1 близнец: семейство живо — токен принят, семейство спрошено", func(t *testing.T) {
		r := &stubReader{families: map[string]bool{"tokaaaaaaaaaaaaaaaaa": false}}
		revoked, err := tokenrevocation.Revoked(context.Background(), r,
			claims(familyClaims("tokaaaaaaaaaaaaaaaaa", now)))
		if err != nil {
			t.Fatalf("ошибка: %v", err)
		}
		if revoked {
			t.Error("выпуск живого семейства объявлен отозванным")
		}
		if len(r.familyAsked) != 1 || r.familyAsked[0] != "tokaaaaaaaaaaaaaaaaa" {
			t.Errorf("о семействе выпуска правило не спросило по его идентификатору: спрошено %v",
				r.familyAsked)
		}
	})

	t.Run("семейство отозвано — токен отозван", func(t *testing.T) {
		r := &stubReader{families: map[string]bool{"tokaaaaaaaaaaaaaaaaa": true}}
		revoked, err := tokenrevocation.Revoked(context.Background(), r,
			claims(familyClaims("tokaaaaaaaaaaaaaaaaa", now)))
		if err != nil {
			t.Fatalf("ошибка: %v", err)
		}
		if !revoked {
			t.Errorf("выпуск отозванного семейства принят: правило не спросило о семействе "+
				"(спрошено %v) — решение о доступе принимал бы второй читатель", r.familyAsked)
		}
	})

	t.Run("отзыв семейства не зависит от отметки выпуска", func(t *testing.T) {
		// Выпуск ПОЗЖЕ любого мыслимого момента отзыва: отзыв семейства снимает
		// всякий его токен, когда бы тот ни был выпущен.
		r := &stubReader{families: map[string]bool{"tokaaaaaaaaaaaaaaaaa": true}}
		revoked, err := tokenrevocation.Revoked(context.Background(), r,
			claims(familyClaims("tokaaaaaaaaaaaaaaaaa", now.Add(24*time.Hour))))
		if err != nil {
			t.Fatalf("ошибка: %v", err)
		}
		if !revoked {
			t.Error("выпуск отозванного семейства, выпущенный позже, принят")
		}
	})

	t.Run("T2 близнец: отозвано ДРУГОЕ семейство — токен принят", func(t *testing.T) {
		r := &stubReader{families: map[string]bool{
			"tokaaaaaaaaaaaaaaaaa": true,
			"tokbbbbbbbbbbbbbbbbb": false,
		}}
		revoked, err := tokenrevocation.Revoked(context.Background(), r,
			claims(familyClaims("tokbbbbbbbbbbbbbbbbb", now)))
		if err != nil {
			t.Fatalf("ошибка: %v", err)
		}
		if revoked {
			t.Error("отзыв одного семейства снял выпуск другого: решение шире семейства")
		}
	})

	t.Run("хранилище семейств не ответило — третий исход", func(t *testing.T) {
		r := &stubReader{familyErr: errors.New("хранилище недоступно")}
		revoked, err := tokenrevocation.Revoked(context.Background(), r,
			claims(familyClaims("tokaaaaaaaaaaaaaaaaa", now)))
		if err == nil {
			t.Fatalf("сбой хранилища семейств прочитан как суждение (отозван=%v) — "+
				"он неотличим от живого семейства", revoked)
		}
		if revoked {
			t.Error("при ошибке суждение выдано вместе с ней")
		}
	})
}

// TestRevoked_CredentialWithoutIdentifierIsNotAskedAboutAFamily — материал без
// идентификатора выпуском семейства не бывает: запись выпуска ключуется
// идентификатором. Спрашивать о нём хранилище семейств нечем, и судят его
// отсечки по ключам — как судили до этого правила.
func TestRevoked_CredentialWithoutIdentifierIsNotAskedAboutAFamily(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	r := &stubReader{}
	revoked, err := tokenrevocation.Revoked(context.Background(), r,
		claims(map[string]any{"sub": "usr-alice", "iat": float64(now.Unix())}))
	if err != nil {
		t.Fatalf("ошибка: %v", err)
	}
	if revoked {
		t.Error("материал без идентификатора и без отсечки объявлен отозванным")
	}
	if len(r.familyAsked) != 0 {
		t.Errorf("о семействе спрошено по пустому идентификатору: %v", r.familyAsked)
	}
}
