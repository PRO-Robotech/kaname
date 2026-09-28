// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// binding_single_issuer_test.go — у публикатора ОДНА запись, наша (kaname#361).
//
// Вторая запись существовала ради прежнего издателя: зеркало его публичного
// набора жило до последней фазы отказа от внешнего сервера и ушло вместе с ним.
// Привязка, которая снова приняла бы вторую запись, вернула бы ровно это
// состояние — ключ одного издателя рядом с ключами другого на том же слушателе,
// — и вернула бы его молча, потому что каждая запись по отдельности законна.
//
// Отрицание стоит в паре с законным близнецом: без него «вторая отвергнута»
// зеленело бы на привязке, которая отвергает всё.
package jwksproxyhttp_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/jwksproxyhttp"
)

// TestBinding_HoldsExactlyOneRecord_TheSecondIsRefused — проба привязки
// «издатель → путь»: одна запись строится, вторая — отказ в старте.
func TestBinding_HoldsExactlyOneRecord_TheSecondIsRefused(t *testing.T) {
	ours := jwksproxyhttp.NewKeySetHandler(jwksproxyhttp.KeySetConfig{
		Source: stubKeySet{keys: []domain.PublishedKey{ourKey(t, "kaname-a")}},
	})
	own := jwksproxyhttp.Record{Issuer: "https://kaname.kacho.local", Path: "/.well-known/kaname/jwks.json", Handler: ours}

	// ЗАКОННЫЙ БЛИЗНЕЦ: наша запись одна — привязка строится и несёт ровно её.
	b, err := jwksproxyhttp.NewBinding([]jwksproxyhttp.Record{own})
	if err != nil {
		t.Fatalf("привязка из нашей единственной записи обязана строиться: %v", err)
	}
	if paths := b.Paths(); len(paths) != 1 || paths[0] != own.Path {
		t.Fatalf("привязка обязана нести ровно нашу запись, получено %v", paths)
	}

	// ВТОРАЯ ЗАПИСЬ — чужой издатель на своём пути: каждая по отдельности
	// законна, и отказывать обязана именно мощность, а не форма записи.
	second := jwksproxyhttp.Record{Issuer: "https://provider.kacho.local", Path: "/.well-known/jwks.json", Handler: ours}
	_, err = jwksproxyhttp.NewBinding([]jwksproxyhttp.Record{own, second})
	if err == nil {
		t.Fatal("привязка построилась из ДВУХ записей — публикатор снова несёт набор второго издателя рядом с нашим")
	}
	for _, want := range []string{"exactly one", "https://provider.kacho.local"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("отказ обязан назвать правило и лишнего издателя (%q), получено: %v", want, err)
		}
	}
}
