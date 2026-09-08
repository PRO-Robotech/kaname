// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// internalrestclientauth_test.go — страж требования клиентского сертификата на
// внутреннем REST-фронте.
//
// Пары здесь ВЕЗДЕ: односторонняя проба («страж отказывает») зеленела бы на
// страже, отказывающем всякой посадке, а односторонняя проба «страж молчит» — на
// страже, не отказывающем никогда. Различает только сравнение миров, отличных
// ОДНИМ фактом.

import (
	"strings"
	"testing"
)

// postureStub — посадка, поданная пробе напрямую: узкий интерфейс стража
// позволяет не собирать её из окружения.
type postureStub struct {
	requiresClientCert bool
	mode               string
}

func (p postureStub) InternalRESTRequiresClientCert() bool    { return p.requiresClientCert }
func (p postureStub) InternalRESTClientAuthModeValue() string { return p.mode }

const internalRESTTestAddr = "tcp://0.0.0.0:9099"

// TestInternalRESTClientAuth_ProductionRefusesTheOneWayEdge — НЕСУЩЕЕ
// утверждение: боевая посадка с односторонним режимом не поднимается.
func TestInternalRESTClientAuth_ProductionRefusesTheOneWayEdge(t *testing.T) {
	err := requireInternalRESTMutualClientAuth(true, internalRESTTestAddr,
		postureStub{requiresClientCert: false, mode: "server-tls-only"})
	if err == nil {
		t.Fatalf("боевая посадка с односторонним режимом на внутреннем фронте поднялась — " +
			"отказа нет вовсе")
	}
	msg := err.Error()
	// Отказ обязан назвать РУЧКУ: без неё оператор знает, что не так, и не знает,
	// где это чинить.
	if !strings.Contains(msg, "KANAME_INTERNALREST_SERVER_MTLS_CLIENTAUTHMODE") {
		t.Fatalf("отказ не называет ручку: %q", msg)
	}
	// И ОБЕ величины — прочитанную и требуемую. Отказ, называющий одну, говорит
	// «не то» и не говорит «что именно».
	if !strings.Contains(msg, `"server-tls-only"`) {
		t.Fatalf("отказ не называет прочитанное значение: %q", msg)
	}
	if !strings.Contains(msg, `"mutual"`) {
		t.Fatalf("отказ не называет требуемое значение: %q", msg)
	}
	if !strings.Contains(msg, internalRESTTestAddr) {
		t.Fatalf("отказ не называет адрес поверхности: %q", msg)
	}
}

// TestInternalRESTClientAuth_ProductionAdmitsTheMutualEdge — ЗАКОННЫЙ БЛИЗНЕЦ.
// Без него утверждение выше зеленело бы на страже, отвергающем любую посадку.
func TestInternalRESTClientAuth_ProductionAdmitsTheMutualEdge(t *testing.T) {
	if err := requireInternalRESTMutualClientAuth(true, internalRESTTestAddr,
		postureStub{requiresClientCert: true, mode: "mutual"}); err != nil {
		t.Fatalf("боевая посадка со взаимным режимом отвергнута: %v", err)
	}
}

// TestInternalRESTClientAuth_ProductionRefusesTheRequestingMode — ГРАНИЦА,
// названная исходом: запрашивающий режим сужением не является.
//
// Проба стоит отдельно от первой намеренно: «server-tls-only» и
// «optional-mutual» — разные объявления оператора, и второе выглядит взаимным.
// Без этой пробы страж мог бы принимать его молча.
func TestInternalRESTClientAuth_ProductionRefusesTheRequestingMode(t *testing.T) {
	err := requireInternalRESTMutualClientAuth(true, internalRESTTestAddr,
		postureStub{requiresClientCert: false, mode: "optional-mutual"})
	if err == nil {
		t.Fatalf("запрашивающий режим принят как сужение — а соединение без " +
			"удостоверения он пропускает")
	}
	if !strings.Contains(err.Error(), `"optional-mutual"`) {
		t.Fatalf("отказ обязан назвать прочитанное значение: %q", err.Error())
	}
}

// TestInternalRESTClientAuth_NonProductionIsANoOp — граница посадки: вне боевой
// страж молчит, как и соседние стражи рёбер.
func TestInternalRESTClientAuth_NonProductionIsANoOp(t *testing.T) {
	if err := requireInternalRESTMutualClientAuth(false, internalRESTTestAddr,
		postureStub{requiresClientCert: false, mode: "server-tls-only"}); err != nil {
		t.Fatalf("не-боевая посадка отвергнута: %v", err)
	}
}

// TestInternalRESTClientAuth_UnraisedFrontIsANoOp — граница предмета: фронта
// нет, судить нечего.
//
// Отдельная проба, а не строка в таблице: отказ здесь означал бы, что посадка
// без внутреннего фронта не поднимается вовсе, — и заметили бы это только на
// установке, где его не объявляют.
func TestInternalRESTClientAuth_UnraisedFrontIsANoOp(t *testing.T) {
	for _, addr := range []string{"", "   "} {
		if err := requireInternalRESTMutualClientAuth(true, addr,
			postureStub{requiresClientCert: false, mode: "server-tls-only"}); err != nil {
			t.Fatalf("посадка без внутреннего фронта (адрес %q) отвергнута: %v", addr, err)
		}
	}
}
