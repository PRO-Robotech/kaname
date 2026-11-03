// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/stretchr/testify/require"
)

// Эта квитанция содержит только стабильные идентичности и даты. Она не выгружает и не
// меняет удостоверяющий материал; строки повторов/аудита намеренно не считаются
// выдачей. Полные строки GD включают точные оси, создателя, ID и createdAt.
type nativeStableReceipt struct {
	Delegations     string
	Accounts        string
	ServiceAccounts string
	Admins          string
	Credentials     string
}

func (f *installationNativeWorld) stableReceipt(t *testing.T) nativeStableReceipt {
	t.Helper()
	var r nativeStableReceipt
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT
 COALESCE((SELECT jsonb_agg(to_jsonb(g) ORDER BY id)::text FROM kaname.grant_delegations g),'[]'),
 COALESCE((SELECT jsonb_agg(jsonb_build_array(id,created_at) ORDER BY id)::text FROM kaname.accounts),'[]'),
 COALESCE((SELECT jsonb_agg(jsonb_build_array(id,account_id,created_at) ORDER BY id)::text FROM kaname.service_accounts),'[]'),
 COALESCE((SELECT jsonb_agg(to_jsonb(g) ORDER BY id)::text FROM kaname.cluster_admin_grants g),'[]'),
 COALESCE((SELECT jsonb_agg(jsonb_build_array(id,sva_id,expires_at) ORDER BY id)::text FROM kaname.service_account_oauth_clients),'[]')`).Scan(&r.Delegations, &r.Accounts, &r.ServiceAccounts, &r.Admins, &r.Credentials))
	return r
}

func nativeSingleDelivery(f *installationNativeWorld) installruntime.DeliveryInput {
	m := installruntime.NewRIDDeliveryFixture()
	m.Second = nil
	return installruntime.DeliveryInput{Manifests: m, CredentialFile: f.creator.CredentialFile, TenantAccountID: &f.tenantID}
}

func requireNativeOK(t *testing.T, p *installruntime.Process, pairs int) {
	t.Helper()
	raw, err := p.Results()
	require.NoError(t, err)
	require.Len(t, raw, 1)
	var result installationResult
	require.NoError(t, json.Unmarshal(raw[0], &result))
	require.Equal(t, installationResult{Stage: "delegation", Code: "OK", CompletedPairs: pairs}, result)
}

func (f *installationNativeWorld) requireSameCredential(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile(f.creator.CredentialFile)
	require.NoError(t, err)
	require.True(t, f.credentialDigest == sha256.Sum256(raw), "same standing credential bytes")
	info, err := os.Stat(f.creator.CredentialFile)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func waitNativeWallClock(t *testing.T, ctx context.Context, until time.Time) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	require.True(t, ok)
	require.True(t, deadline.After(until.Add(90*time.Second)), "lease must include actual expiry plus restart/cleanup; no clock adjustment")
	remaining := time.Until(until)
	if remaining > 0 {
		timer := time.NewTimer(remaining)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			require.NoError(t, ctx.Err())
		}
	}
	require.False(t, time.Now().Before(until))
}

func ridNativeExactIdentityAxes(t *testing.T) {
	f := newInstallationNativeWorld(t)
	public := rid01NewmanContext(t, f, "identities")
	requireNativeOK(t, f.apply(t, nativeSingleDelivery(f)), 1)
	f.requireDeliveredPairs(t, "ridfirst")
	require.NotEqual(t, f.creator.ID, f.tenantID)
	var issuer string
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT delegate_id FROM kaname.grant_delegations WHERE account_id=$1`, f.tenantID).Scan(&issuer))
	require.NotEqual(t, issuer, f.tenantID)
	f.requireSameCredential(t)
	rid01NewmanPhase(t, public, "S1-EXACT-IDENTITIES", nil)
}

func ridNativeTokenRenewal(t *testing.T) {
	// Явный штатный профиль фикстуры; производственные значения по умолчанию не затронуты.
	f := newInstallationNativeWorldLifetimes(t, 300, "30s")
	in := nativeSingleDelivery(f)
	public := rid01NewmanContext(t, f, "renewal")
	requireNativeOK(t, f.apply(t, in), 1)
	f.requireDeliveredPairs(t, "ridfirst")
	before := f.stableReceipt(t)
	publicBefore := f.lastPublic
	first, err := f.wire.ExchangeStandingCreator(f.given.ctx, f.creator, "https://kaname.local", "https://kaname.local")
	require.NoError(t, err)
	f.secrets = append(f.secrets, first.Bearer, first.Assertion)
	require.LessOrEqual(t, first.ExpiresAt.Sub(first.IssuedAt), 30*time.Second)
	rid01NewmanPhase(t, public, "RENEWAL-BEFORE", nil)
	// Настоящий принятый токен истекает; включаем допуск рассогласования ПРЕДЪЯВЛЕНИЯ.
	waitNativeWallClock(t, f.given.ctx, first.ExpiresAt.Add(tokenpolicy.ClockSkew+time.Second))
	require.True(t, time.Now().Before(f.creator.ExpiresAt), "renewal key must still be live")
	code, err := f.wire.JSON(f.given.ctx, http.MethodGet, "/iam/v1/me", first.Bearer, nil, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, code)
	rid01NewmanPhase(t, public, "EXPIRED-ACCESS-TOKEN", map[string]any{"jwtRIDExpiredCreator": first.Bearer})
	requireNativeOK(t, f.apply(t, in), 1)
	next, err := f.wire.ExchangeStandingCreator(f.given.ctx, f.creator, "https://kaname.local", "https://kaname.local")
	require.NoError(t, err)
	f.secrets = append(f.secrets, next.Bearer, next.Assertion)
	require.True(t, first.Bearer != next.Bearer, "new actual credential, never print token values")
	require.NotEqual(t, first.JTI, next.JTI)
	require.NotEqual(t, first.AssertionJTI, next.AssertionJTI)
	require.True(t, next.IssuedAt.After(first.IssuedAt))
	require.True(t, next.ExpiresAt.After(first.ExpiresAt))
	require.Equal(t, before, f.stableReceipt(t))
	f.requireDeliveredPairs(t, "ridfirst")
	require.Equal(t, publicBefore, f.lastPublic, "independent O public List/Get identities dates axes remain stable after renewal/restart")
	f.requireSameCredential(t)
	rid01NewmanPhase(t, public, "RENEWAL-AFTER", map[string]any{"jwtRIDCreator": next.Bearer})
}

func ridNativeExpiredKeyTimeTwin(t *testing.T) {
	f := newInstallationNativeWorldLifetimes(t, 300, "30s")
	in := nativeSingleDelivery(f)
	public := rid01NewmanContext(t, f, "key")
	// СНАЧАЛА положительный близнец с теми же ключом, выдачей, поставкой и миром.
	requireNativeOK(t, f.apply(t, in), 1)
	f.requireDeliveredPairs(t, "ridfirst")
	before := f.stableReceipt(t)
	positive := f.wire.StartReadinessWatch(f.given.ctx).Stop()
	require.NotEmpty(t, positive)
	require.Equal(t, http.StatusOK, positive[0].HTTPStatus, "same observer must see valid twin production readiness")
	require.False(t, positive[0].TransportFailed)
	rid01NewmanPhase(t, public, "VALID-KEY-TWIN", nil)
	stop, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	require.NoError(t, f.session.Stop(stop))
	cancel()
	// Настоящие часы — единственный изменённый вход авторизации. Без перевыдачи ключа,
	// новой административной выдачи, старения SQL, поддельных часов или изменения файла удостоверяющего материала.
	waitNativeWallClock(t, f.given.ctx, f.creator.ExpiresAt.Add(tokenpolicy.ClockSkew+time.Second))
	require.Equal(t, before, f.stableReceipt(t))
	observer := f.wire.StartReadinessWatch(f.given.ctx)
	defer observer.Stop()
	spawnAt := time.Now().UTC()
	failed, err := f.session.StartDelivery(f.given.ctx, in)
	require.NoError(t, err)
	terminal, cancel := context.WithTimeout(f.given.ctx, 60*time.Second)
	defer cancel()
	err = failed.Wait(terminal)
	exitedAt := time.Now().UTC()
	samples := observer.Stop()
	evidence, marshalErr := json.Marshal(map[string]any{"spawnAt": spawnAt, "terminalObservedAt": exitedAt, "samples": samples, "positiveTwinSamples": positive})
	require.NoError(t, marshalErr)
	require.NoError(t, os.WriteFile(filepath.Join(f.session.Root, "expired-key-readiness.json"), evidence, 0600))
	require.NotEmpty(t, samples)
	require.False(t, samples[0].FinishedAt.After(spawnAt), "observer armed before process creation")
	require.True(t, samples[0].TransportFailed, "old process must be gone before negative startup")
	for _, sample := range samples {
		require.NotEqual(t, http.StatusOK, sample.HTTPStatus, "refused startup exposed production readiness during active lifetime observation")
	}
	var exit *exec.ExitError
	require.ErrorAs(t, err, &exit, "actual startup refusal, not timeout or harness setup failure")
	require.Equal(t, 1, exit.ExitCode(), "startup refusal must be exact exit1")
	raw, err := failed.Results()
	require.NoError(t, err)
	require.Len(t, raw, 1)
	var result installationResult
	require.NoError(t, json.Unmarshal(raw[0], &result))
	require.Equal(t, installationResult{Stage: "authentication", Code: "UNAUTHENTICATED"}, result)
	require.Equal(t, before, f.stableReceipt(t), "refused startup must retain previous IDs dates axes and counts")
	f.requireSameCredential(t)
	require.NoError(t, failed.CheckSecretAbsence(f.secrets...))
	// Session.Stop сообщает уже наблюдённый ожидаемый выход как ошибку. Его
	// вызов всё равно снимает владение; проверяем ровно этот наблюдённый выход, не скрывая
	// неожиданную ошибку очистки и не меняя производственную семантику Process.Stop.
	cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	cleanupErr := f.session.Stop(cleanup)
	cancel()
	require.ErrorIs(t, cleanupErr, failed.ExitError())
	if public != nil {
		rid01RequireRefusalBeforeRestore(t, public)
		rid01RestorePublicListeners(t, f, in, public)
		rid01NewmanPhase(t, public, "EXPIRED-KEY-REFUSAL", nil)
	}
}
