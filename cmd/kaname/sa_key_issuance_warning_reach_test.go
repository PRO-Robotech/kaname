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
// комбинацию в боевых режимах отвергает, а требования полосы вне боевых
// режимов не предъявляются вовсе. Значит ветвь исполняется ТОЛЬКО в режиме
// разработчика.
//
// «Недостижима в боевых режимах» — утверждение из ДВУХ половин, и держатель
// у каждой свой:
//
//   - ВЕРДИКТ СТРАЖА ПО РЕЖИМАМ. На одном входе, меняя ровно один факт —
//     режим: в dev вход принят и сборка ключей печатает предупреждение ровно
//     один раз, называя, чем оно снимается (ручка `authn.client-token.enabled`
//     и задача kacho#1120); в production и production-strict тот же вход
//     отвергнут строкой контура выдачи.
//     Держит `TestSAKeyIssuanceWarning_ReachedOnlyOutsideProductionModes`.
//   - ПОРЯДОК В `main`. Отказ стража ОСТАНАВЛИВАЕТ процесс до сборки: за
//     записью отказа не исполняется ничего. Без этой половины первая молчала
//     бы о `main`, продолжающем после отказа, — и ветвь стала бы достижимой на
//     боевом стенде при зелёном вердикте стража. Так и было: снятый выход после
//     отказа оставлял первую половину зелёной.
//     Держит `TestSAKeyIssuanceWarning_ProductionRefusalStopsMainBeforeWiring`.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАКОННЫЕ БЛИЗНЕЦЫ
//
// Без них «предупреждение напечатано» зеленело бы на ветви, печатающей всегда:
// тот же вход с включённым токен-эндпоинтом и тот же вход на посадке
// `external` (дорога построена) не печатают ничего.
//
// Близнец ОБЯЗАН подниматься: молчание, измеренное на входе, который страж
// старта отвергает, есть молчание процесса, до сборки не дошедшего, и о ветви
// оно не говорит ничего. И близнец меняет РОВНО ОДИН факт против входа случая:
// второй изменённый факт мог бы нести нагрузку сам, и отрицание судило бы не
// то, что названо. Оба свойства проверяются, а не объявляются: страж старта
// зовётся на близнеце, а расхождение с входом случая перечисляется разбором
// полей настройки.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// devOwnWithoutOwnSAKeyIssuance — вход случая: режим разработчика, посадка
// `own`, токен-эндпоинт платформы не включён. Прочие величины — те, без которых
// страж старта отказал бы в любом режиме по причине, к предмету не относящейся.
//
// Величины самого контура выдачи ОБЪЯВЛЕНЫ, а контур выключен одной ручкой
// `authn.client-token.enabled`: своя чеканка, слушатель, на котором эндпоинт
// монтируется, перечень адресатов, срок и потолок тела. Пока ручка выключена,
// страж эндпоинта их не читает, и случай от них не зависит. Нужны они близнецу:
// без них включённый эндпоинт отвергается стражем старта, и близнец,
// переводящий контур, либо не поднимался бы, либо менял бы не один факт.
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
	cfg.AuthN.TokenSigning = config.TokenSigningConfig{
		Enabled:           true,
		Issuer:            "https://iam.kacho.cloud",
		Algorithm:         "RS256",
		AllowedAlgorithms: "RS256",
		KeySetPath:        "/.well-known/kaname/jwks.json",
		KeyLifetime:       90 * 24 * time.Hour,
	}
	cfg.APIServer.RegistryToken = config.RegistryTokenConfig{
		Endpoint: "tcp://0.0.0.0:9096",
		Service:  "registry.kacho.local",
	}
	cfg.AuthN.ClientToken = config.ClientTokenConfig{
		Enabled:          false,
		AllowedAudiences: "registry.kacho.local, https://api.kacho.cloud",
		DefaultAudience:  "https://api.kacho.cloud",
		TokenTTL:         15 * time.Minute,
		BodyCeiling:      64 << 10,
	}
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

// differingFacts — пути полей настройки, в которых два входа расходятся.
// Структуры обходятся вглубь, прочее сравнивается целиком.
//
// Предпосылка разбора — все поля настройки экспортируемы (сегодня так: полей
// 127, неэкспортируемых 0). Неэкспортируемое поле сравнить нечем, и молчать о
// нём нельзя: оно называется расхождением ВСЕГДА, и проба близнеца краснеет с
// его путём, пока разбор его не узнает.
func differingFacts(a, b reflect.Value, path string) []string {
	if a.Kind() != reflect.Struct {
		if reflect.DeepEqual(a.Interface(), b.Interface()) {
			return nil
		}
		return []string{path}
	}
	var out []string
	for i := 0; i < a.NumField(); i++ {
		f := a.Type().Field(i)
		name := f.Name
		if path != "" {
			name = path + "." + f.Name
		}
		if !f.IsExported() {
			out = append(out, name+" (неэкспортируемое, не сравнимо)")
			continue
		}
		out = append(out, differingFacts(a.Field(i), b.Field(i), name)...)
	}
	return out
}

// requireOneFactTwin — близнец отличается от входа случая ровно фактом fact
// (путь поля настройки, например `AuthN.IdentityProvider`) и ничем больше.
func requireOneFactTwin(t *testing.T, caseIn, twin config.Config, fact string) {
	t.Helper()
	facts := differingFacts(reflect.ValueOf(caseIn), reflect.ValueOf(twin), "")
	if len(facts) != 1 || facts[0] != fact {
		t.Fatalf("близнец обязан менять ровно один факт %s против входа случая, меняет %d: %v",
			fact, len(facts), facts)
	}
}

// requireStartableTwin — близнец принят стражем старта в своём режиме.
func requireStartableTwin(t *testing.T, twin config.Config) {
	t.Helper()
	if err := twin.Validate(); err != nil {
		t.Fatalf("Validate() = %v: близнец не поднимается, и его молчание — молчание процесса, "+
			"до сборки ключей не дошедшего, а не ветви", err)
	}
}

// TestSAKeyIssuanceWarning_ReachedOnlyOutsideProductionModes — вердикт стража
// старта по режимам на одном входе: в режиме разработчика вход принят и ветвь
// печатает предупреждение, в боевых тот же вход отвергнут строкой контура
// выдачи. Что процесс после такого отказа не идёт дальше, держит
// TestSAKeyIssuanceWarning_ProductionRefusalStopsMainBeforeWiring.
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
			requireOneFactTwin(t, cfg, prod, "AuthN.Mode")
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

// mainChildEnv — признак, по которому экземпляр тестового бинаря исполняет
// `main` вместо пробы. Имя вне префикса настройки службы: загрузчик настройки
// его не читает.
const mainChildEnv = "SA_KEY_REACH_PROBE_RUN_MAIN"

// mainChildCommand — команда, с которой `main` запускается в дочернем
// процессе. Заведомо неизвестная, и это несущее: следующая за стражем
// инструкция `main` — разбор команды, и на неизвестной он печатает свою запись
// и выходит. Продолжение за отказом стража поэтому НАБЛЮДАЕМО и КОНЕЧНО. На
// `serve` продолжение ушло бы в подъём слушателей: исход не конечный и зависит
// от машины.
const mainChildCommand = "sa-key-reach-probe-no-such-command"

// mainReturnedCode — код дочернего процесса, если `main` ВЕРНУЛСЯ, а не
// завершил процесс. Отличен от кода отказа, чтобы возврат не выглядел отказом.
const mainReturnedCode = 86

// TestSAKeyIssuanceWarning_ProductionRefusalStopsMainBeforeWiring — половина
// «порядок в main»: на боевой посадке own без своего контура выдачи `main`
// печатает отказ стража строкой контура выдачи и ЗАВЕРШАЕТ процесс — за
// записью отказа не исполняется ничего, до сборки ключей он не доходит.
//
// Судится настоящий `main` в дочернем процессе этого же бинаря: вход приходит
// тем путём, каким приходит на стенде, — загрузчиком настройки из окружения.
func TestSAKeyIssuanceWarning_ProductionRefusalStopsMainBeforeWiring(t *testing.T) {
	if os.Getenv(mainChildEnv) == "1" {
		os.Args = []string{"kaname", mainChildCommand}
		main()
		os.Exit(mainReturnedCode)
	}

	for _, mode := range []config.Mode{config.ModeProduction, config.ModeProductionStrict} {
		t.Run(mode.String(), func(t *testing.T) {
			records, code, raw := runMainChild(t, map[string]string{
				"KANAME_AUTHN__MODE":              mode.String(),
				"KANAME_AUTHN__IDENTITY_PROVIDER": config.IdentityProviderOwn.String(),
			})
			if code == mainReturnedCode {
				t.Fatalf("main вернулся, а не завершил процесс, — отказ стража старта не остановил "+
					"подъём; вывод: %s", raw)
			}
			if len(records) == 0 {
				t.Fatalf("дочерний main не напечатал ни одной записи (код %d): отказа стража нет, "+
					"судить нечего; вывод: %s", code, raw)
			}
			first := records[0]
			if msg, _ := first[slog.MessageKey].(string); msg != "config validation failed" {
				t.Fatalf("первая запись обязана быть отказом стража старта, получено %q (код %d); "+
					"вывод: %s", msg, code, raw)
			}
			if reason, _ := first["err"].(string); !strings.Contains(reason, "authn.client-token.enabled is false") {
				t.Fatalf("отказ стража обязан нести строку контура выдачи (задача #337), получено: %s", reason)
			}
			if len(records) != 1 {
				var after []string
				for _, r := range records[1:] {
					msg, _ := r[slog.MessageKey].(string)
					after = append(after, msg)
				}
				t.Fatalf("после отказа стража старта main продолжил: записей за отказом %d (%q) — "+
					"процесс идёт к сборке, и ветвь предупреждения достижима в боевом режиме",
					len(after), after)
			}
			if code != 1 {
				t.Fatalf("код завершения %d, ожидался 1 — отказ старта обязан быть ненулевым; вывод: %s",
					code, raw)
			}
		})
	}
}

// runMainChild — исполняет `main` в дочернем процессе с окружением, в котором
// из настройки службы задано ровно overrides: унаследованные переменные с
// префиксом настройки сняты, иначе исход зависел бы от окружения запустившего.
// Возвращает записи журнала (строки JSON в stderr), код завершения и весь
// вывод для текста отказа.
func runMainChild(t *testing.T, overrides map[string]string) ([]map[string]any, int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSAKeyIssuanceWarning_ProductionRefusalStopsMainBeforeWiring$")
	env := []string{mainChildEnv + "=1"}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, config.EnvPrefix+"_") || strings.HasPrefix(kv, mainChildEnv+"=") {
			continue
		}
		env = append(env, kv)
	}
	for k, v := range overrides {
		env = append(env, k+"="+v)
	}
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("дочерний main не завершился за минуту — процесс пошёл дальше отказа стража; "+
			"stderr: %s", stderr.String())
	}
	code := 0
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	case err != nil:
		t.Fatalf("дочерний процесс не запустился: %v", err)
	}

	var records []map[string]any
	for _, line := range bytes.Split(stderr.Bytes(), []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var rec map[string]any
		if jerr := json.Unmarshal(line, &rec); jerr != nil {
			t.Fatalf("запись журнала дочернего main не разбирается: %v: %s", jerr, line)
		}
		records = append(records, rec)
	}
	return records, code, "stderr: " + stderr.String() + " stdout: " + stdout.String()
}

// TestSAKeyIssuanceWarning_SilentWhereIssuanceHasAnExecutor — законные
// близнецы: у выдачи есть исполнитель, и предупреждения нет. Каждый близнец
// поднимается и меняет против входа случая ровно один факт.
func TestSAKeyIssuanceWarning_SilentWhereIssuanceHasAnExecutor(t *testing.T) {
	t.Run("own со своим контуром выдачи", func(t *testing.T) {
		cfg := devOwnWithoutOwnSAKeyIssuance()
		cfg.AuthN.ClientToken.Enabled = true
		requireOneFactTwin(t, devOwnWithoutOwnSAKeyIssuance(), cfg, "AuthN.ClientToken.Enabled")
		requireStartableTwin(t, cfg)
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
		requireOneFactTwin(t, devOwnWithoutOwnSAKeyIssuance(), cfg, "AuthN.IdentityProvider")
		requireStartableTwin(t, cfg)
		if warns := saKeysWarnings(t, cfg); len(warns) != 0 {
			t.Fatalf("предупреждений %d там, где зеркало заводится у существующего поставщика: %v",
				len(warns), warns)
		}
	})
}
