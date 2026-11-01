// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront

import (
	"net/http"
	"testing"
)

// Публичный фронт пишет адрес своего клиента ровно одним значением — адресом
// соединения, а не тем, что прислал клиент (kaname#991).
func TestPublicFrontWritesItsClientAddressOnce(t *testing.T) {
	hdrs := map[string]string{
		// Обе формы, которыми клиент мог бы назвать адрес сам.
		http.CanonicalHeaderKey(MetadataClientAddr):                    "203.0.113.66",
		"Grpc-Metadata-" + http.CanonicalHeaderKey(MetadataClientAddr): "203.0.113.67",
		"X-Forwarded-For": "203.0.113.68",
	}
	md := metadataThroughMux(t, newPublicMux(), hdrs)
	got := md.Get(MetadataClientAddr)
	// httptest.NewRequest ставит адрес соединения 192.0.2.1:1234.
	if len(got) != 1 || got[0] != "192.0.2.1" {
		t.Fatalf("адрес клиента фронта = %v, ожидалось ровно [192.0.2.1] — адрес соединения без порта", got)
	}
}

// Законный близнец: внутренний фронт адреса не пишет — его слушатель ключуется
// листом модуля, и чужое значение ему не нужно.
func TestInternalFrontWritesNoClientAddress(t *testing.T) {
	md := metadataThroughMux(t, newMux(), map[string]string{})
	if got := md.Get(MetadataClientAddr); len(got) != 0 {
		t.Fatalf("внутренний фронт записал адрес клиента: %v", got)
	}
}
