// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/stretchr/testify/require"
)

// installationNativeWorld — настоящий путь F0→O→C→полная поставка. Его единственный
// вставленный Given — ранее утверждённые начальные пользователь/сессия/клиент. Помощники
// модели/посева/начальной настройки в тестовом процессе не выполняются: все эти шаги идут
// внутри зафиксированного нативного производственного файла с настоящей цепочкой слушателей.
type installationNativeWorld struct {
	given              *ceremonyWorld
	stand              *installruntime.NativeStand
	session            *installruntime.Session
	wire               *installruntime.Wire
	operator           *installruntime.VerifiedOperator
	creator            *installruntime.StandingCreator
	base               *installruntime.Process
	secrets            []string
	baseline           nativeBaseline
	tenantID           string
	credentialDigest   [32]byte
	lastPublic         nativePublicReceipt
	publicReadSequence int
	writerPlan         *installruntime.RegistrationWriterPlan
	stockLegacyGroup   json.RawMessage
	stockCatalog       json.RawMessage
}

func newInstallationNativeWorld(t *testing.T) *installationNativeWorld {
	return newInstallationNativeWorldLifetimes(t, 7200, "")
}

// Различаются только штатные заявленные сроки удостоверяющего материала; все политики допуска и полномочий
// сохраняются. Пустой accessTTL сохраняет профиль стенда.
func newInstallationNativeWorldLifetimes(t *testing.T, keyTTL int64, accessTTL string) *installationNativeWorld {
	return newInstallationNativeWorldProfile(t, keyTTL, accessTTL, false)
}

// Профиль записи готовит только существующие PKI/состав модуля. Окружение манифеста
// удаляется ниже: F0 и его проверки штатного состояния/отсутствия поставки сохраняются,
// а настоящий последующий полный serve выполняет первую установку.
func newInstallationNativeWorldProfile(t *testing.T, keyTTL int64, accessTTL string, moduleWriter bool) *installationNativeWorld {
	t.Helper()
	return newInstallationNativeWorldLifecycle(t, keyTTL, accessTTL, moduleWriter, moduleWriter)
}

// Ранний аудит жизненного цикла не зависит от необязательной PKI записи модуля.
// Существующие вызывающие сохраняют прежний профиль; RID08 включает раннюю очистку
// и настоящее наблюдение начального ключа без включения W или изменения F0/модели.
func newInstallationNativeWorldLifecycle(t *testing.T, keyTTL int64, accessTTL string, moduleWriter, earlyLifecycle bool) *installationNativeWorld {
	t.Helper()
	return newInstallationNativeWorldAccountCapacity(t, keyTTL, accessTTL, moduleWriter, earlyLifecycle, 0)
}

// Снимок перехода N3 -> N4 требует вместимости для четырёх одновременно принадлежащих
// учётных записей. Этот штатный заявленный предел количества отделён от неизменных
// трёх допусков за настоящий час. Ноль сохраняет каждый прежний профиль стенда;
// фикстура не переписывает строку политики БД или идентичность/носитель.
func newInstallationNativeWorldAccountCapacity(t *testing.T, keyTTL int64, accessTTL string, moduleWriter, earlyLifecycle bool, accountCapacity int64) *installationNativeWorld {
	t.Helper()
	require.True(t, accountCapacity == 0 || accountCapacity == 4, "only the explicit RID08 N4 count profile is permitted")
	// Объявляем согласованный краткоживущий производственный профиль до создания фикстуры PG.
	// Считыватель отзывов остаётся включённым; его штатное окно кеша
	// должно быть положительным и строго короче срока выданного токена.
	overrides := map[string]string{}
	if accountCapacity != 0 {
		overrides["KANAME_OWN_CEILINGS__ACCOUNTS_PER_IDENTITY"] = fmt.Sprint(accountCapacity)
	}
	if accessTTL != "" {
		ttl, err := time.ParseDuration(accessTTL)
		require.NoError(t, err)
		const revocationWindow = 5 * time.Second
		require.Greater(t, ttl, revocationWindow)
		require.LessOrEqual(t, ttl, tokenpolicy.MaxTokenTTL)
		require.Greater(t, time.Duration(keyTTL)*time.Second, ttl,
			"standing key must permit the declared full token lifetime")
		overrides["KANAME_AUTHN__CLIENT_TOKEN__TOKEN_TTL"] = accessTTL
		overrides["KANAME_AUTHN__PRESENTED_CREDENTIAL__REVOCATION_CACHE_TTL"] = revocationWindow.String()
	}
	requireNativeManifestPremise(t)
	deadline, ok := t.Deadline()
	require.True(t, ok, "bounded Go test deadline required for native lifecycle")
	ctx, cancelLifetime := context.WithDeadline(context.Background(), deadline)
	t.Cleanup(cancelLifetime)
	root, err := filepath.Abs("../..")
	require.NoError(t, err)
	evidenceRoot := os.Getenv("KANAME_RID_EVIDENCE")
	require.True(t, filepath.IsAbs(evidenceRoot), "FIXTURE_INCOMPLETE: private absolute RID evidence directory required")
	evidence, err := installruntime.EvidenceDirectory(evidenceRoot, t.Name())
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(evidenceRoot, 0700))
	stand := installruntime.PrepareNativeStand(t, ctx, root, evidence, moduleWriter)
	f := &installationNativeWorld{stand: stand, writerPlan: installruntime.EmptyRegistrationWriterPlan()}
	if earlyLifecycle {
		// Регистрируем до любого нативного Start, начальной настройки или выдачи ключа.
		// Замыкание допускает любой частично инициализированный мир и никогда не вызывает Fatal.
		t.Cleanup(func() { f.ridLifecycleCleanup(t) })
	}
	if moduleWriter {
		writerKey, keyErr := os.ReadFile(filepath.Join(evidence, "pki", "registry.key"))
		f.secrets = append(f.secrets, string(writerKey))
		require.NoError(t, keyErr)
	}
	identity, err := json.Marshal(map[string]string{"testIdentity": t.Name()})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(evidence, "test-identity.json"), identity, 0600))
	environment, err := stand.Environment(nil)
	require.NoError(t, err)
	require.NoError(t, stand.RunMigrator(ctx, os.Getenv("KANAME_RID_MIGRATOR"), environment))
	pool, err := coredb.NewPool(ctx, fmt.Sprintf("postgres://kaname:stand@127.0.0.1:%s/kaname?sslmode=require&options=-c%%20search_path%%3Dkaname%%2Cpublic&pool_max_conns=2", stand.PGPort))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	// Повторно используем ровно установленные помощники записи Given церемонии, не создавая её
	// внутрипроцессный интерфейс токенов, подписант, модель разрешений или начального администратора.
	w := &ceremonyWorld{t: t, id: "RID-NATIVE-F0", ctx: ctx, pool: pool, logs: &lockedBuffer{}, clientAudiences: []string{"https://kaname.local"}}
	w.requireStorePremise()
	if moduleWriter {
		stock := readRIDStockPremise(t, w)
		writeRIDStockPremise(t, evidence, "after-migrations", stock, nil)
		requireRIDNoDeliveredIdentities(t, stock, 0)
		f.stockCatalog = stock.Catalog
	}
	baseline := readNativeBaseline(t, w)
	require.Len(t, baseline.ServiceAccounts, 2, "stock bootstrap and gateway identities remain")
	require.Len(t, baseline.AdminGrants, 1, "stock bootstrap admin is part of F0")
	require.Contains(t, baseline.ServiceAccounts, "svab91854890de887e6d")
	require.Contains(t, baseline.ServiceAccounts, "sva3e9556e76be67f816")
	requireNativeAuthority(t, w, "service_account", "svab91854890de887e6d", 1)
	requireNativeNoDelivery(t, w)
	var tenantsBefore int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.accounts WHERE id<>$1`, baseline.SystemID).Scan(&tenantsBefore))
	require.Zero(t, tenantsBefore)
	writeNativeBaseline(t, evidence, baseline)
	w.seedPerson()
	w.markPerson()
	w.session = w.seedSession("2")
	w.ic1 = w.seedClient("rid-native-operator", domain.InteractiveClientActive, []string{lineA1R})
	baseline.requirePreserved(t, w, 0, 0)
	require.NotEqual(t, baseline.SystemOwner, string(w.user))
	requireNativeAuthority(t, w, "user", string(w.user), 0)
	requireNativeNoDelivery(t, w)
	var tenantID string
	require.NoError(t, pool.QueryRow(ctx, `SELECT id FROM kaname.accounts WHERE owner_user_id=$1`, string(w.user)).Scan(&tenantID))
	tenants, system, err := kanamepg.NewInstallationReader(pool).InstallationAccounts(ctx, "", 2)
	require.NoError(t, err)
	require.Equal(t, baseline.SystemID, string(system))
	require.Equal(t, []domain.AccountID{domain.AccountID(tenantID)}, tenants, "actual initial snapshot contains only O's tenant")
	// Адрес почты O и любой явный профиль сроков — штатные входы запуска.
	// Аудитория, издатель, полномочия и политика шлюза сохраняют профиль стенда.
	overrides["KANAME_BOOTSTRAP_ROOT_EMAIL"] = w.email
	environment, err = stand.Environment(overrides)
	require.NoError(t, err)
	if moduleWriter {
		filtered := environment[:0]
		for _, entry := range environment {
			name, _, _ := strings.Cut(entry, "=")
			if name != "KANAME_MANIFESTS__DIR" && name != "KANAME_MANIFESTS__REQUIRED" {
				filtered = append(filtered, entry)
			}
		}
		environment = filtered
	}
	stand.StartMailbox(t, ctx, environment)
	wire, err := installruntime.NewWire(filepath.Join(evidence, "pki"), "https://localhost:9098", "https://localhost:9096", "https://localhost:9097")
	require.NoError(t, err)
	t.Cleanup(wire.Close)
	session := &installruntime.Session{Binary: os.Getenv("KANAME_RID_BINARY"), BinarySHA256: os.Getenv("KANAME_RID_BINARY_SHA256"),
		Environment: environment, Root: evidence, Probe: wire.ProductionReady}
	f.given, f.session, f.wire = w, session, wire
	f.baseline, f.tenantID = baseline, tenantID
	f.secrets = append(f.secrets, w.ic1.secret, w.session.bearer.CookieValue())
	if !earlyLifecycle {
		t.Cleanup(func() {
			stop, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err := session.Stop(stop); err != nil {
				t.Errorf("native shutdown: %v", err)
			}
			for _, process := range session.History {
				require.NoError(t, process.CheckSecretAbsence(f.secrets...))
			}
		})
	}
	if moduleWriter {
		beforeBase := readRIDStockPremise(t, w)
		f.stockLegacyGroup = append(json.RawMessage{}, beforeBase.LegacyGroup...)
		writeRIDStockPremise(t, evidence, "before-base", beforeBase, nil)
		require.JSONEq(t, string(f.stockCatalog), string(beforeBase.Catalog), "Given must preserve the migration catalog")
		requireRIDNoDeliveredIdentities(t, beforeBase, 0)
		require.Equal(t, 1, beforeBase.AdminGrants, "O not bootstrapped before base")
	}
	base, err := session.StartBase(ctx, f.writerPlan)
	require.NoError(t, err)
	require.NoError(t, base.OwnsListeners(9090, 9091, 9095, 9096, 9097, 9098, 9099, 9100))
	f.base = base
	f.renewOperator(t, ctx)
	authority, cancelAuthority := context.WithTimeout(ctx, 60*time.Second)
	err = wire.AwaitOperatorAdmin(authority, f.operator)
	cancelAuthority()
	require.NoError(t, err, "actual asynchronous bootstrap must grant O before provisioning C")
	requireNativeAuthority(t, w, "user", string(w.user), 1)
	baseline.requirePreserved(t, w, 0, 1)
	requireNativeNoDelivery(t, w)
	if moduleWriter {
		f.requireRIDBasePremise(t, "base-before-C", 0)
	}
	if earlyLifecycle {
		f.creator, err = wire.ProvisionStandingCreatorWithKeyTTL(ctx, f.operator, string(system), filepath.Join(evidence, "standing-creator.json"), keyTTL, func(secret string) { f.secrets = append(f.secrets, secret) })
	} else {
		f.creator, err = wire.ProvisionStandingCreatorWithKeyTTL(ctx, f.operator, string(system), filepath.Join(evidence, "standing-creator.json"), keyTTL)
	}
	require.NoError(t, err)
	require.NoError(t, pool.QueryRow(ctx, `SELECT expires_at FROM kaname.service_account_oauth_clients WHERE id=$1 AND sva_id=$2`, f.creator.KeyID, f.creator.ID).Scan(&f.creator.ExpiresAt))
	f.secrets = append(f.secrets, f.creator.SecretMaterial()...)
	credential, err := os.ReadFile(f.creator.CredentialFile)
	require.NoError(t, err)
	f.credentialDigest = sha256.Sum256(credential)
	info, err := os.Stat(f.creator.CredentialFile)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	require.NotEqual(t, string(w.user), f.creator.ID)
	require.NotContains(t, baseline.ServiceAccounts, f.creator.ID)
	require.Equal(t, baseline.SystemID, f.creator.AccountID)
	requireNativeAuthority(t, w, "service_account", f.creator.ID, 1)
	baseline.requirePreserved(t, w, 1, 2)
	requireNativeNoDelivery(t, w)
	operations := []installruntime.Operation{f.creator.CreateOperation, f.creator.GrantOperation, f.creator.KeyOperation}
	seen := map[string]bool{}
	for _, op := range operations {
		require.NotEmpty(t, op.ID)
		require.False(t, seen[op.ID])
		seen[op.ID] = true
		require.True(t, op.Done)
		require.Nil(t, op.Error)
	}
	if moduleWriter {
		f.requireRIDBasePremise(t, "base-after-C", 1)
	}
	return f
}

func (f *installationNativeWorld) renewOperator(t *testing.T, ctx context.Context) {
	t.Helper()
	var err error
	f.operator, err = f.wire.ExchangeOperator(ctx, installruntime.OperatorGiven{UserID: string(f.given.user),
		SessionBearer: f.given.session.bearer.CookieValue(), ClientID: f.given.ic1.rec.ClientID,
		ClientSecret: f.given.ic1.secret, RedirectURI: lineA1R})
	require.NoError(t, err)
	f.secrets = append(f.secrets, f.operator.Bearer())
}

func (f *installationNativeWorld) apply(t *testing.T, input installruntime.DeliveryInput) *installruntime.Process {
	t.Helper()
	stop, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	require.NoError(t, f.session.Stop(stop))
	cancel()
	require.NoError(t, f.base.CheckSecretAbsence(append(f.creator.SecretMaterial(), f.operator.Bearer(), f.given.ic1.secret, f.given.session.bearer.CookieValue())...))
	process, err := f.session.StartDelivery(f.given.ctx, input)
	require.NoError(t, err)
	ready, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	require.NoError(t, process.AwaitReady(ready, f.wire.ProductionReady))
	require.NoError(t, process.OwnsListeners(9090, 9091, 9095, 9096, 9097, 9098, 9099, 9100))
	require.NoError(t, process.CheckSecretAbsence(append(f.creator.SecretMaterial(), f.operator.Bearer())...))
	f.writerPlan = installruntime.CloneRegistrationWriterPlan(input.RegistrationWriters)
	f.requireRegistrationWriterPlan(t, input.RegistrationWriters)
	rid08Write(t, filepath.Dir(process.StdoutPath), "registration-writer-input", map[string]any{"plan": input.RegistrationWriters, "planSHA256": rid01RedactionHash(input.RegistrationWriters), "fullStartupConfigSHA256": process.ConfigSHA256})
	return process
}

// Этот предикат проверяет только полный нативный путь установки. Последующие
// предикаты RID01 отдельно проверяют полные оси, истечение срока и близнецы отказов.
func ridNativeFirstInstall(t *testing.T) {
	f := newInstallationNativeWorld(t)
	public := rid01NewmanContext(t, f, "clean")
	rid01NewmanPhase(t, public, "CLEAN-BEFORE", nil)
	process := f.apply(t, installruntime.DeliveryInput{RegistrationWriters: f.writerPlan, Manifests: installruntime.NewRIDDeliveryFixture(), CredentialFile: f.creator.CredentialFile})
	results, err := process.Results()
	require.NoError(t, err)
	require.Len(t, results, 1, "actual full serve must publish exactly one structured installation result")
	var result installationResult
	require.NoError(t, json.Unmarshal(results[0], &result))
	require.Equal(t, "delegation", result.Stage)
	require.Equal(t, "OK", result.Code)
	require.Equal(t, 2, result.CompletedPairs)
	f.requireDeliveredPairs(t)
	rid01NewmanPhase(t, public, "CLEAN-INSTALLED", nil)
	credential, err := os.ReadFile(f.creator.CredentialFile)
	require.NoError(t, err)
	require.True(t, f.credentialDigest == sha256.Sum256(credential), "full serve retains the same standing credential")
	// Сохраняем настоящий процесс/состояние для проверок идентичности, доказывая,
	// что церемония O всё ещё работает после перезапуска с полной поставкой.
	f.renewOperator(t, t.Context())
}
