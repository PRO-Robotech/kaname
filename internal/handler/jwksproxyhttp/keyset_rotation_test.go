// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// keyset_rotation_test.go — перевёрнутое утверждение ведомости §7 (строка 4).
//
// До этой фазы проба публикатора требовала, чтобы ПОСЛЕ РОТАЦИИ в ответе не
// было ни одного НАШЕГО идентификатора ключа: набор был чужим зеркалом. Теперь
// наша запись обязана нести наш новый ключ, а прежний остаётся в ней всю
// отсрочку — снятие раньше её истечения есть та самая тихая инверсия, отказы
// от которой начинаются позже действия, их вызвавшего, и у разных потребителей
// в разное время.
package jwksproxyhttp_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/handler/jwksproxyhttp"
)

func TestKeySet_AfterRotationOurRecordCarriesTheNewKey(t *testing.T) {
	before := ourKey(t, "kacho-before")
	src := &togglableSource{keys: []domain.PublishedKey{before}}
	h := jwksproxyhttp.NewKeySetHandler(jwksproxyhttp.KeySetConfig{Source: src})

	_, body := getPath(t, h, http.MethodGet, "/keys")
	if !strings.Contains(body, "kacho-before") {
		t.Fatalf("до ротации наша запись обязана нести действующий ключ: %s", body)
	}

	// Ротация: новый ключ ПОЯВЛЯЕТСЯ в наборе, прежний из него ещё не уходит.
	after := ourKey(t, "kacho-after")
	src.keys = []domain.PublishedKey{before, after}
	_, body = getPath(t, h, http.MethodGet, "/keys")
	kids := kidsIn(t, body)
	if len(kids) != 2 {
		t.Fatalf("после ротации в наборе ожидались оба ключа, получено %v", kids)
	}
	for _, want := range []string{"kacho-after", "kacho-before"} {
		if !strings.Contains(body, want) {
			t.Fatalf("после ротации ключ %q отсутствует в нашей записи: %s", want, body)
		}
	}

	// И ни одного чужого: наша запись содержит ТОЛЬКО наши ключи, чужие живут
	// в отдельной записи зеркала и в нашу не попадают.
	for _, foreign := range []string{"provider-1", "hydra-kid-1", "attacker-1"} {
		if strings.Contains(body, foreign) {
			t.Fatalf("в НАШЕЙ записи оказался чужой ключ %q: %s", foreign, body)
		}
	}
}
