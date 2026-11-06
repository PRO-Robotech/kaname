// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ridProvisionCounts struct{ ServiceAccounts, AdminGrants, Keys int }

func (f *installationStandingWorld) provisionCounts(t *testing.T, ctx context.Context) ridProvisionCounts {
	t.Helper()
	var counts ridProvisionCounts
	require.NoError(t, f.world.pool.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM kaname.service_accounts),
 (SELECT count(*) FROM kaname.cluster_admin_grants),
 (SELECT count(*) FROM kaname.service_account_oauth_clients)`).Scan(&counts.ServiceAccounts, &counts.AdminGrants, &counts.Keys))
	return counts
}
func ridWaitUntil(t *testing.T, ctx context.Context, at time.Time) {
	t.Helper()
	if delay := time.Until(at); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatalf("real-time acceptance wait interrupted: %v", ctx.Err())
		}
	}
}

// ridStandingAuthentication покрывает внутренний живой механизм выдачи/кеша.
// Он НЕ заменяет отдельный предикат чистого полного serve/обновления RID01.
// Всё истёкшее время настоящее; оба ограничения частоты — запрошенные допустимые профили.
func ridStandingAuthentication(t *testing.T) {
	for _, pace := range []int{1, 5} {
		name := "pace1"
		if pace == 5 {
			name = "pace5"
		}
		t.Run(name, func(t *testing.T) {
			f := newInstallationStandingWorld(t, pace, 2*time.Second)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			before := f.provisionCounts(t, ctx)
			material, err := os.ReadFile(f.credentialFile)
			require.NoError(t, err)
			first := f.authentication.accessToken
			verified, err := f.authentication.Authenticate(ctx)
			require.NoError(t, err)
			require.NoError(t, authzguard.RequireClusterAdmin(verified, f.relations))
			require.True(t, first == f.authentication.accessToken, "immediate repeat reuses actual issued access credential")
			// Декодируем только истечение токена, уже принятого выше ШТАТНЫМ
			// считывателем. Это наблюдение не подставляет идентичность и не обходит проверку.
			claims := jwt.MapClaims{}
			_, _, err = new(jwt.Parser).ParseUnverified(first, claims)
			require.NoError(t, err)
			expiry, err := claims.GetExpirationTime()
			require.NoError(t, err)
			require.NotNil(t, expiry)
			ridWaitUntil(t, ctx, expiry.Time.Add(30*time.Millisecond))
			verified, err = f.authentication.Authenticate(ctx)
			require.NoError(t, err)
			require.True(t, first != f.authentication.accessToken, "actual expired access token must renew from the same key")
			p, ok := operations.PrincipalFromContextOK(verified)
			require.True(t, ok)
			require.Equal(t, string(f.creator), p.ID)
			for i := 0; i < 256; i++ {
				accepted, err := f.authentication.Authenticate(ctx)
				require.NoError(t, err)
				require.NoError(t, authzguard.RequireClusterAdmin(accepted, f.relations))
			}
			errors := make(chan error, 32)
			var workers sync.WaitGroup
			for i := 0; i < 32; i++ {
				workers.Add(1)
				go func() {
					defer workers.Done()
					accepted, err := f.authentication.Authenticate(ctx)
					if err == nil {
						err = authzguard.RequireClusterAdmin(accepted, f.relations)
					}
					errors <- err
				}()
			}
			workers.Wait()
			close(errors)
			for err := range errors {
				require.NoError(t, err)
			}
			// Исчерпываем НАСТОЯЩЕЕ ограничение частоты проверяющего для клиента настоящими свежими доказательствами.
			// Наблюдаем настоящий RetryAfter с достаточным остатком времени для отмены;
			// синтетический ограничитель или закрытый шлюз не используются.
			client, outcome, err := clientassertion.ResolveRegisteredClient(ctx, f.authentication.resolver, f.authentication.credential.ClientID)
			require.NoError(t, err, "registered standing client must resolve: %s", outcome)
			throttled := false
			for attempt := 0; attempt < 32; attempt++ {
				assertion, err := f.authentication.freshAssertion(client)
				require.NoError(t, err)
				result, err := f.authentication.verifier.Verify(ctx, tokenpolicy.ClientAssertionType, assertion)
				if result.Outcome == clientassertion.OutcomeClientPaceExceeded {
					require.Error(t, err)
					if result.RetryAfter > 100*time.Millisecond {
						throttled = true
						break
					}
					ridWaitUntil(t, ctx, time.Now().Add(result.RetryAfter+10*time.Millisecond))
					continue
				}
				require.NoError(t, err)
			}
			require.True(t, throttled, "real pace boundary was not reached; cancellation premise is unproven")
			cancelled, stop := context.WithTimeout(ctx, 20*time.Millisecond)
			_, _, err = f.authentication.exchange(cancelled)
			stop()
			require.Equal(t, codes.DeadlineExceeded, status.Code(err), "actual RetryAfter wait must honor cancellation")
			// Последующий настоящий обмен должен восстановиться со свежим утверждением/JTI.
			token, owner, err := f.authentication.exchange(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, token.AccessToken)
			require.Equal(t, string(f.creator), owner)
			require.Equal(t, before, f.provisionCounts(t, ctx), "renewal/retry must not provision SA/admin/key rows")
			after, err := os.ReadFile(f.credentialFile)
			require.NoError(t, err)
			require.True(t, bytes.Equal(material, after), "standing key bytes must be retained throughout renewal")
		})
	}
}
