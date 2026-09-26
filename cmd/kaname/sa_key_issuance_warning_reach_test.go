// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// sa_key_issuance_warning_reach_test.go — ГДЕ ДОСТИЖИМА ветвь предупреждения о
// неисполняемой выдаче ключей служебных учёток и ЧТО она называет оператору
// (задача #428).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Ветвь в `buildSAKeysHandler` срабатывает на одной комбинации: посадка `own`
// (дороги к внешнему поставщику нет) при непереведённом контуре выдачи
// (`authn.client-token.enabled` не включён). Страж старта из задачи #337 эту
// комбинацию в боевых режимах не поднимает, а требования полосы вне боевых
// режимов не предъявляются вовсе. Значит ветвь исполняется ТОЛЬКО в режиме
// разработчика, и эта проба утверждает обе половины на одном входе, меняя
// ровно один факт — режим:
//
//   - dev: вход принят стражем старта, и сборка ключей печатает предупреждение
//     ровно один раз; предупреждение называет, чем оно снимается, — ручкой
//     `authn.client-token.enabled` и существующей задачей kacho#1120;
//   - production и production-strict: тот же вход отвергнут стражем старта
//     строкой контура выдачи, то есть до сборки ключей процесс не доходит.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАКОННЫЕ БЛИЗНЕЦЫ
//
// Без них «предупреждение напечатано» зеленело бы на ветви, печатающей всегда:
// тот же вход с включённым токен-эндпоинтом и тот же вход на посадке
// `external` (дорога построена) не печатают ничего.
package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// devOwnWithoutOwnSAKeyIssuance — вход случая: режим разработчика, посадка
// `own`, токен-эндпоинт платформы не включён. Прочие величины — те, без которых
// страж старта отказал бы в любом режиме по причине, к предмету не относящейся.
func devOwnWithoutOwnSAKeyIssuance() config.Config {
	ceiling := func(v int64) *int64 { return &v }
	var cfg config.Config
	cfg.AuthN.Mode = config.ModeDev
	cfg.AuthN.IdentityProvider = config.IdentityProviderOwn
	cfg.AuthN.Domain = "access.example.invalid"
	cfg.AuthN.TrustedForwarderSANs = []string{"spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"}
	cfg.AuthN.TrustDomainName = "kacho.cloud"
	cfg.APIServer.Endpoint = "tcp://0.0.0.0:9090"
	cfg.APIServer.InternalEndpoint = "tcp://0.0.0.0:9091"
	cfg.Repository.Postgres.URL = "postgres://u:p@db:5432/kaname"
	cfg.Repository.Postgres.SSLMode = "disable"
	cfg.Retention = config.RetentionConfig{Interval: 5 * time.Minute, Batch: 1000, MaxBatchesPerPass: 20}
	cfg.AuthZ = config.AuthZConfig{CacheTTL: 5 * time.Second}
	cfg.OwnCeilings = config.OwnCeilingsConfig{
		AccountsPerIdentity:          ceiling(5),
		CredentialsPerUser:           ceiling(12),
		CredentialsPerServiceAccount: ceiling(24),
		AccessKeysPerUser:            ceiling(3),
	}
	cfg.Invite = config.InviteConfig{MailRateLimit: config.InviteMailRateLimitConfig{
		MaxPerWindow: config.DefaultInviteMailPerWindow,
		Window:       config.DefaultInviteMailWindow,
	}}
	return cfg
}

// saKeysWarnings — записи уровня WARN, которые напечатала сборка ключей на
// данном входе. Сборка зовётся настоящая, та же, что в композиционном корне;
// базы она при сборке не касается, поэтому пул не нужен.
func saKeysWarnings(t *testing.T, cfg config.Config) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if h := buildSAKeysHandler(nil, nil, cfg, nil, nil, logger); h == nil {
		t.Fatal("buildSAKeysHandler() = nil: сборка ключей не состоялась, судить нечего")
	}
	var (
		out     []map[string]any
		records int
	)
	for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("запись журнала не разбирается: %v: %s", err, line)
		}
		records++
		if rec[slog.LevelKey] == slog.LevelWarn.String() {
			out = append(out, rec)
		}
	}
	// Предпосылка разбора: сборка печатает перепись `sa_keys wired` всегда. Ноль
	// записей значил бы, что журнал не прочитан, а не что предупреждения нет.
	if records == 0 {
		t.Fatal("сборка ключей не напечатала ни одной записи: журнал не прочитан, " +
			"«предупреждения нет» отсюда не следует")
	}
	return out
}

// TestSAKeyIssuanceWarning_ReachedOnlyOutsideProductionModes — ветвь достижима
// в режиме разработчика и недостижима в боевых: тот же вход там отвергает
// страж старта.
func TestSAKeyIssuanceWarning_ReachedOnlyOutsideProductionModes(t *testing.T) {
	cfg := devOwnWithoutOwnSAKeyIssuance()
	if cfg.SAKeyIssuanceIsOurs() {
		t.Fatal("предпосылка случая не создана: контур выдачи уже переведён на свою чеканку")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v: вход режима разработчика обязан приниматься стражем старта — "+
			"иначе проба судит не достижимость ветви, а неподнявшуюся фикстуру", err)
	}

	warns := saKeysWarnings(t, cfg)
	if len(warns) != 1 {
		t.Fatalf("предупреждений %d, ожидалось ровно одно: dev-посадка own без своего "+
			"контура выдачи поднимается, и всякая выдача ключа на ней отказывает", len(warns))
	}
	lift, _ := warns[0]["снимается"].(string)
	for _, want := range []string{"authn.client-token.enabled", "kacho#1120"} {
		if !strings.Contains(lift, want) {
			t.Errorf("предупреждение обязано называть, чем снимается, через %q; получено «снимается»=%q",
				want, lift)
		}
	}

	for _, mode := range []config.Mode{config.ModeProduction, config.ModeProductionStrict} {
		t.Run(mode.String(), func(t *testing.T) {
			prod := cfg
			prod.AuthN.Mode = mode
			err := prod.Validate()
			if err == nil {
				t.Fatal("Validate() = nil: боевая посадка own без своего контура выдачи " +
					"поднимается — ветвь предупреждения была бы достижима на развёрнутом стенде")
			}
			if !strings.Contains(err.Error(), "authn.client-token.enabled is false") {
				t.Fatalf("отказ старта обязан прийти строкой контура выдачи (задача #337), получено: %v", err)
			}
		})
	}
}

// TestSAKeyIssuanceWarning_SilentWhereIssuanceHasAnExecutor — законные
// близнецы: у выдачи есть исполнитель, и предупреждения нет.
func TestSAKeyIssuanceWarning_SilentWhereIssuanceHasAnExecutor(t *testing.T) {
	t.Run("own со своим контуром выдачи", func(t *testing.T) {
		cfg := devOwnWithoutOwnSAKeyIssuance()
		cfg.AuthN.ClientToken.Enabled = true
		if !cfg.SAKeyIssuanceIsOurs() {
			t.Fatal("предпосылка близнеца не создана: контур выдачи не переведён")
		}
		if warns := saKeysWarnings(t, cfg); len(warns) != 0 {
			t.Fatalf("предупреждений %d при переведённом контуре: %v", len(warns), warns)
		}
	})
	t.Run("external без своего контура выдачи", func(t *testing.T) {
		cfg := devOwnWithoutOwnSAKeyIssuance()
		cfg.AuthN.IdentityProvider = config.IdentityProviderExternal
		cfg.AuthN.HydraAdminURL = "https://hydra-admin.kaname.test"
		if warns := saKeysWarnings(t, cfg); len(warns) != 0 {
			t.Fatalf("предупреждений %d там, где зеркало заводится у существующего поставщика: %v",
				len(warns), warns)
		}
	})
}
