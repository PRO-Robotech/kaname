// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// httpedgetls_publisher_name_test.go — отказ стража транспорта называет
// слушатель ключей проверки тем, что он ОТДАЁТ, а не тем, что с него снято.
//
// Имя ребра — первое, что оператор читает в отказе старта, и по нему он идёт
// проверять слушатель. Имя называло «зеркало ключей проверки» по каноническому
// пути well-known, а зеркало снято вместе с прежним издателем (kaname#361):
// запись у публикатора одна — наша, по пути `authn.token-signing.key-set-path`,
// а канонический путь маршрутизатор не отдаёт вовсе (это утверждает
// `internal/check/ceremony_surface_test.go`). Оператор, пошедший по имени,
// получал бы 404 по адресу, которого у слушателя нет.
//
// Судится НАБЛЮДАЕМОЕ — текст отказа, собранный тем же перечнем рёбер, что
// зовёт подъём, — а не поле структуры.
package main

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// retiredMirrorPath — путь снятой записи зеркала. Слушатель его не отдаёт.
const retiredMirrorPath = "/.well-known/jwks.json"

func TestKeySetPublisherEdgeRefusalNamesWhatTheListenerServes(t *testing.T) {
	// Поднят ровно один слушатель — публикатор; прочие адреса пусты, и страж
	// их пропускает by construction. Транспорт не объявлен, посадка боевая:
	// отказ обязан прозвучать, и прозвучать о нём одном.
	_, err := requireHTTPEdgeTLS(true, iamHTTPEdges("", "", "0.0.0.0:9097", "", "", config.MTLSConfig{}))
	if err == nil {
		t.Fatal("публикатор открытым текстом в боевой посадке обязан получить отказ — страж смолчал, судить нечего")
	}
	msg := err.Error()

	// ПРЕДПОСЫЛКА: отказ — о том ребре. Без неё отсутствие снятого пути
	// читалось бы как верное имя у отказа о чём-то другом.
	if !strings.Contains(msg, "KANAME_JWKSPROXY_SERVER_MTLS_ENABLE") {
		t.Fatalf("отказ не называет ручку публикатора — проба судит не то ребро: %s", msg)
	}
	if !strings.Contains(msg, "authn.token-signing.key-set-path") {
		t.Errorf("отказ не называет настройку, по чьему пути слушатель отдаёт набор: %s", msg)
	}
	if strings.Contains(msg, retiredMirrorPath) {
		t.Errorf("отказ называет путь %s, которого слушатель не отдаёт (запись зеркала снята, kaname#361): %s",
			retiredMirrorPath, msg)
	}
	for _, retired := range []string{"mirror", "зеркал"} {
		if strings.Contains(strings.ToLower(msg), retired) {
			t.Errorf("отказ называет слушатель зеркалом (%q), а зеркала на нём нет: %s", retired, msg)
		}
	}
}
