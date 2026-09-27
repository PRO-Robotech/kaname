// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// family_test.go — авторитет отзыва отвечает и об отзыве СЕМЕЙСТВА выпуска
// (kaname#319, решение К10 вариант А; приёмка LINE-A-1, сценарии 01 и 21).
//
// Этот авторитет — то место, куда край идёт на пути запроса за НАШИМ токеном.
// Поэтому ответ о семействе обязан быть здесь, в том же документе
// `{"active": …}`, а не в отдельном вопросе, которого край не задаёт.
package tokenintrospecthttp_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestIntrospect_LINE_A_1_21_RevokedFamilyIsInactive — семейство выпуска
// отозвано, отсечек по ключам нет: ответ `active:false`.
func TestIntrospect_LINE_A_1_21_RevokedFamilyIsInactive(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	var pub domain.PublishedKey
	// Идентификатор выпуска — «tok-» + субъект (см. mintToken).
	tok := mintToken(t, "usr-alice", now.Add(-time.Minute), &pub)
	keys := stubKeys{keys: []domain.PublishedKey{pub}}

	t.Run("T1 близнец: семейство живо — active:true", func(t *testing.T) {
		h := newHandler(keys, stubRevocations{families: map[string]bool{"tok-usr-alice": false}}, now)
		code, out := ask(t, h, tok.raw)
		if code != http.StatusOK || out["active"] != true {
			t.Fatalf("выпуск живого семейства обязан быть действительным: %d %v", code, out["active"])
		}
	})

	t.Run("семейство отозвано — active:false", func(t *testing.T) {
		h := newHandler(keys, stubRevocations{families: map[string]bool{"tok-usr-alice": true}}, now)
		code, out := ask(t, h, tok.raw)
		if code != http.StatusOK {
			t.Fatalf("авторитет обязан отвечать по существу, получено %d", code)
		}
		if out["active"] != false {
			t.Fatalf("выпуск отозванного семейства объявлен действительным: авторитет "+
				"спросил только отсечки по ключам (active=%v)", out["active"])
		}
	})

	t.Run("хранилище семейств не ответило — 503, не суждение", func(t *testing.T) {
		h := newHandler(keys, stubRevocations{familyErr: errors.New("хранилище недоступно")}, now)
		code, out := ask(t, h, tok.raw)
		if code != http.StatusServiceUnavailable {
			t.Fatalf("сбой хранилища семейств обязан давать отказ, а не суждение: %d %v", code, out)
		}
	})
}
