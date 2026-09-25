// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// family_test.go — читатель предъявленного на публичном слушателе отвергает
// выпуск ОТОЗВАННОГО СЕМЕЙСТВА (kaname#319, решение К10 вариант А; приёмка
// LINE-A-1, сценарии 01 и 21).
//
// Окно — то же объявленное окно кеша, что у отсечек по ключам: ответ о
// семействе приходит тем же вопросом к тому же правилу, поэтому второго окна и
// второй политики на неответ у него нет.
package presentedcred_test

import (
	"errors"
	"testing"
	"time"
)

// testJTI — идентификатор годного выпуска стенда (см. mint.sign).
const testJTI = "tok-" + testSubject

// TestKAN_REV_LINE_A_1_21_RevokedFamilyIsRefusedAfterTheCacheWindow — сквозь
// обе стороны: отозвали семейство → предъявили его выпуск → отказ.
func TestKAN_REV_LINE_A_1_21_RevokedFamilyIsRefusedAfterTheCacheWindow(t *testing.T) {
	s := newStand(t, withCacheTTL(30*time.Second))
	raw := s.good(t)

	if _, _, err := s.present(t, raw); err != nil {
		t.Fatalf("исходное предъявление обязано пройти (T1 близнец): %v", err)
	}

	s.revs.revokeFamily(testJTI)
	s.clock.advance(31 * time.Second) // срок кеша истёк; срок токена — НЕТ

	if _, _, err := s.present(t, raw); err == nil {
		t.Fatal("выпуск отозванного семейства принят после истечения срока кеша — " +
			"читатель спросил только отсечки по ключам")
	} else {
		assertSingleRefusal(t, err)
	}
}

// TestKAN_REV_LINE_A_1_21_OtherFamilyRevokedKeepsBeingAccepted — T2 близнец:
// отозвано ДРУГОЕ семейство, выпуск этого принимается и после окна кеша.
func TestKAN_REV_LINE_A_1_21_OtherFamilyRevokedKeepsBeingAccepted(t *testing.T) {
	s := newStand(t, withCacheTTL(30*time.Second))
	raw := s.good(t)

	s.revs.revokeFamily("tok-другого-семейства")
	s.clock.advance(31 * time.Second)
	if _, _, err := s.present(t, raw); err != nil {
		t.Fatalf("отзыв чужого семейства снял этот выпуск: %v", err)
	}
}

// TestKAN_REV_LINE_A_1_21_UnavailableFamilyStoreRefuses — хранилище семейств не
// ответило: отказ, а не проход.
func TestKAN_REV_LINE_A_1_21_UnavailableFamilyStoreRefuses(t *testing.T) {
	s := newStand(t)
	s.revs.familyErr = errors.New("хранилище семейств недоступно")

	_, _, err := s.present(t, s.good(t))
	if err == nil {
		t.Fatal("недоступность хранилища семейств засчитана как «не отозван»")
	}
	assertSingleRefusal(t, err)
	if got := s.reader.Stats(); got.Unavailable == 0 {
		t.Errorf("исход «ответить не смогли» не отличим в измерителях: %+v", got)
	}
}
