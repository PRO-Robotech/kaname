// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clients_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/clients"
)

// TestProviderAPIError_SurvivesWrappingAndNamesThePortRole — отказ
// административной дороги распознаётся по ТИПУ сквозь обёртку и печатает роль
// порта, код и тело ответа.
//
// Тип, а не текст, — несущее: на распознавании кода стоит идемпотентность
// создания интерактивного клиента (409) и разделение «вход отвергнут» против
// «поставщик лёг» (classifyProviderCall). Текст закреплён дословно, потому что
// его же воспроизводит дублёр поставщика в пробах сценария интерактивного
// клиента: дублёр, печатающий то, чего продукт не печатает, проверял бы не тот
// отказ.
func TestProviderAPIError_SurvivesWrappingAndNamesThePortRole(t *testing.T) {
	err := fmt.Errorf("register interactive client: %w",
		&clients.ProviderAPIError{StatusCode: http.StatusConflict, Body: `{"error":"resource_exists"}`})

	var apiErr *clients.ProviderAPIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("отказ административной дороги не распознаётся по типу сквозь обёртку: %v", err)
	}
	if apiErr.StatusCode != http.StatusConflict {
		t.Fatalf("код отказа = %d, ожидался %d", apiErr.StatusCode, http.StatusConflict)
	}
	const want = `provider admin api: status 409: {"error":"resource_exists"}`
	if got := apiErr.Error(); got != want {
		t.Fatalf("текст отказа = %q, ожидался %q", got, want)
	}
}
