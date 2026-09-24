// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// basic_credential_limit_test.go — полоса докер-реестра не собирается без
// объявленного предела на обращение авторитета о базовом секрете (задача
// kaname#379).
//
// Оператор тот же, что у глаголов внутреннего слушателя, и для строки
// удостоверения человека он читает и отсечку отзыва-всех. Предел — у
// авторитета, поэтому сборка без него — отказ в старте, а не полоса,
// висящая на неотвечающей базе, пока не кончатся горутины.
package registrytokenwire_test

import (
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/registrytokenwire"
)

// TestBuild_RefusesAnUndeclaredBasicCredentialLimit — без предела сборка
// отказывает и называет его; с пределом та же сборка проходит.
func TestBuild_RefusesAnUndeclaredBasicCredentialLimit(t *testing.T) {
	cfg := registrytokenwire.BuildConfig{
		Realm:   "https://api.kacho.local/iam/token",
		Service: "registry.probe.local",
	}
	_, err := registrytokenwire.Build(nil, cfg)
	if err == nil {
		t.Fatal("полоса собрана без предела на обращение авторитета — вход в реестр висел бы на неотвечающей базе")
	}
	if !strings.Contains(err.Error(), "per-call limit") {
		t.Fatalf("отказ сборки не называет предел: %v", err)
	}

	// Законный близнец: ровно один факт другой.
	cfg.BasicCredentialTimeout = time.Second
	if _, err := registrytokenwire.Build(nil, cfg); err != nil {
		t.Fatalf("полоса с объявленным пределом не собралась: %v", err)
	}
}
