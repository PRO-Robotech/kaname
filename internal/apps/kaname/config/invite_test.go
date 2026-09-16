// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// invite_test.go — величины приглашения: молчащий профиль срок НЕ снимает,
// отрицательная величина роняет старт, значения «без срока» в словаре нет.

import (
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// TestInviteTTL_SilentPostureKeepsTheDeadline — молчащий профиль ограничение НЕ
// снимает: умолчание непустое и положительное.
//
// Отрицание без этого контроля зеленело бы на конфигурации, где срока нет вовсе.
func TestInviteTTL_SilentPostureKeepsTheDeadline(t *testing.T) {
	t.Parallel()
	var c config.InviteConfig // профиль о сроке не высказался
	got := c.TTLOrDefault()
	if got <= 0 {
		t.Fatalf("молчащий профиль дал срок %s — приглашение стало бы выкупаемым навсегда", got)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("молчание профиля отвергнуто стражем: %v", err)
	}
}

// TestInviteTTL_DeclaredValueWins — положительный контроль: объявленная величина
// применяется, а не подменяется умолчанием.
func TestInviteTTL_DeclaredValueWins(t *testing.T) {
	t.Parallel()
	c := config.InviteConfig{TTL: 36 * time.Hour}
	if got := c.TTLOrDefault(); got != 36*time.Hour {
		t.Fatalf("объявленная величина не применилась: %s", got)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("законная величина отвергнута: %v", err)
	}
}

// TestInviteTTL_NegativeIsRefusedAtStart — отрицательная величина роняет старт,
// и отказ называет РУЧКУ: без имени ручки оператор не знает, что править.
func TestInviteTTL_NegativeIsRefusedAtStart(t *testing.T) {
	t.Parallel()
	err := config.InviteConfig{TTL: -time.Second}.Validate()
	if err == nil {
		t.Fatal("отрицательный срок принят — страж зелен при любом входе")
	}
	if !strings.Contains(err.Error(), "invite.ttl") {
		t.Errorf("отказ не называет ручку: %v", err)
	}
}

// TestInviteTTL_ZeroReadsAsUnsetAndNotAsUnlimited — ноль читается как
// «не объявлено» и заменяется умолчанием, а НЕ как «без срока».
//
// Это и есть предмет: значения, означающего «без ограничения», в словаре ручки
// не существует вовсе, поэтому снять срок профиль не может ничем.
func TestInviteTTL_ZeroReadsAsUnsetAndNotAsUnlimited(t *testing.T) {
	t.Parallel()
	c := config.InviteConfig{TTL: 0}
	if got := c.TTLOrDefault(); got <= 0 {
		t.Fatalf("ноль прочитан как «без срока»: %s", got)
	}
	if got, silent := c.TTLOrDefault(), (config.InviteConfig{}).TTLOrDefault(); got != silent {
		t.Errorf("явный ноль и молчание профиля дали разные сроки (%s ≠ %s) — "+
			"разбор настроек их не различает, и требовать разного значило бы "+
			"требовать невыразимого", got, silent)
	}
}
