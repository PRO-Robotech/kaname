// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// invite_test.go — величины приглашения: молчащий профиль срок НЕ снимает,
// отрицательная величина роняет старт, значения «без срока» в словаре нет.

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// legalMailLimit — законное ограничение частоты для проб, чей предмет — СРОК.
// Секция одна на обе величины, а страж судит обе: проба о сроке обязана
// принести законное соседнее, иначе она красна о чужом предмете. Умолчание
// частоты живёт у ЗАГРУЗЧИКА (invite_mail_rate_limit_test.go), поэтому голая
// структура его не несёт — и это намеренно: явный ноль отвергается.
var legalMailLimit = config.InviteMailRateLimitConfig{MaxPerWindow: 3, Window: time.Hour}

// TestInviteTTL_SilentPostureKeepsTheDeadline — молчащий профиль ограничение НЕ
// снимает: умолчание непустое и положительное.
//
// Отрицание без этого контроля зеленело бы на конфигурации, где срока нет вовсе.
func TestInviteTTL_SilentPostureKeepsTheDeadline(t *testing.T) {
	t.Parallel()
	c := config.InviteConfig{MailRateLimit: legalMailLimit} // профиль о сроке не высказался
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
	c := config.InviteConfig{TTL: 36 * time.Hour, MailRateLimit: legalMailLimit}
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
	err := config.InviteConfig{TTL: -time.Second, MailRateLimit: legalMailLimit}.Validate()
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
	c := config.InviteConfig{TTL: 0, MailRateLimit: legalMailLimit}
	if got := c.TTLOrDefault(); got <= 0 {
		t.Fatalf("ноль прочитан как «без срока»: %s", got)
	}
	if got, silent := c.TTLOrDefault(), (config.InviteConfig{}).TTLOrDefault(); got != silent {
		t.Errorf("явный ноль и молчание профиля дали разные сроки (%s ≠ %s) — "+
			"разбор настроек их не различает, и требовать разного значило бы "+
			"требовать невыразимого", got, silent)
	}
}

// TestInviteTTL_EnvKnobReachesTheProcess — ручка доезжает до процесса
// переменной окружения ровно тем именем, которым её называет INSTALL.md.
//
// Проба заведена не ради viper, а ради ДОКУМЕНТА: имя, названное оператору и не
// связанное разбором, есть возможность, объявленная и неисполнимая. Оператор
// задаёт величину, служба её не видит, и сигнала нет ни одного.
func TestInviteTTL_EnvKnobReachesTheProcess(t *testing.T) {
	// Молчание окружения — контроль: без него утверждение ниже зеленело бы и
	// на ручке, которая всегда отдаёт одно и то же.
	silent, err := config.Load("")
	require.NoError(t, err)
	assert.Zero(t, silent.Invite.TTL,
		"молчащее окружение обязано оставлять величину незаданной")

	t.Setenv("KANAME_INVITE__TTL", "36h")
	got, lerr := config.Load("")
	require.NoError(t, lerr)
	assert.Equal(t, 36*time.Hour, got.Invite.TTL,
		"ручка `invite.ttl` не связана с переменной `KANAME_INVITE__TTL` — "+
			"имя названо оператору в INSTALL.md и не читается разбором")
	assert.Equal(t, 36*time.Hour, got.Invite.TTLOrDefault())
}
