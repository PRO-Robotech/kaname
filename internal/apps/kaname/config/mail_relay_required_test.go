// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_relay_required_test.go — почтовый узел есть условие боевого старта
// (PRO-Robotech/kaname#475).
//
// Доступ дальше входа получает только человек с подтверждённым адресом
// (kaname#456), и подтвердить адрес — как и восстановить доступ — можно только
// кодом из письма. Посадка, поднятая без почтового узла, стартовала здоровой, а
// ни один человек — первый администратор кластера тоже — дальше входа не
// проходил; видно это было только клеткой `misconfigured` счётчика исходов
// отправки. Теперь незаданный узел — отказ старта с именами ключей.
package config_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// mailLaneSettings — почтовый узел, объявленный так, как его принимает страж
// отправителя: адрес узла и адрес отправителя.
func mailLaneSettings() config.InviteMailConfig {
	return config.InviteMailConfig{Relay: "relay.example.invalid:587", From: "kaname@example.invalid"}
}

// Отказ: боевой старт без почтового узла называет оба ключа и их переменные
// окружения. Меняется один факт против близнеца ниже — узел.
func TestProductionStartWithoutTheMailRelayIsRefused(t *testing.T) {
	cfg := laneCfg()
	cfg.InviteMail = config.InviteMailConfig{}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil; без почтового узла ни один человек не подтвердит адрес — старт обязан отказать")
	}
	for _, want := range []string{"invite-mail.relay", "invite-mail.from", "KANAME_INVITE_MAIL__RELAY", "KANAME_INVITE_MAIL__FROM"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("отказ обязан называть %q, получено: %q", want, err.Error())
		}
	}
}

// Законный близнец: тот же вход с объявленным узлом старт проходит.
func TestProductionStartWithTheMailRelayBoots(t *testing.T) {
	cfg := laneCfg()
	cfg.InviteMail = mailLaneSettings()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v; объявленный почтовый узел обязан пропускать старт", err)
	}
}
