// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package sa_keys

// revoke_race_integration_test.go — CVR-11 и CVR-08 на настоящей базе (приёмка
// `docs/engineering/acceptance/credential-verbs-refusal-outcomes.md`, задача
// kaname#522).
//
//   - CVR-11: N параллельных отзывов одного ключа — ровно один успех с
//     отметкой отзыва, каждый прочий получает синхронный `NOT_FOUND` либо
//     операцию, завершённую ошибкой с тем же кодом и текстом; строка снята
//     один раз, событие аудита одно. Успеха на строке, которую снял другой, не
//     бывает.
//   - CVR-08: чужой ключ — синхронный `NOT_FOUND`, ключ на месте. Здесь
//     сверка существования исполняется настоящим оператором чтения, суженным
//     владельцем.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/operations"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// issueLiveSAKey выдаёт учётке живой ключ настоящим глаголом и возвращает его
// идентификатор.
func issueLiveSAKey(ctx context.Context, t *testing.T, uc *IssueSAKeyUseCase, uid domain.UserID, svaID domain.ServiceAccountID, readID func() (string, error)) domain.SAOAuthClientID {
	t.Helper()
	_, err := uc.Execute(withSAKeyPrincipal(ctx, string(uid)), IssueInput{ServiceAccountID: svaID, CreatedByUserID: string(uid)})
	require.NoError(t, err)
	var keyID string
	require.Eventually(t, func() bool {
		id, rerr := readID()
		keyID = id
		return rerr == nil
	}, 5*time.Second, 20*time.Millisecond, "выданный ключ обязан лечь строкой")
	return domain.SAOAuthClientID(keyID)
}

// raceOutcome — исход одного отзыва гонки.
type raceOutcome struct {
	code    codes.Code
	msg     string
	revoked bool
}

func TestRevokeSAKey_CVR11_ConcurrentRevokesYieldOneSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupSAKeyTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid, svaID := seedSAKeyUserAndSA(t, ctx, pool, "cvr11")
	keyID := issueLiveSAKey(ctx, t, buildIssueUC(pool), uid, svaID, func() (string, error) {
		var id string
		err := pool.QueryRow(ctx, `SELECT id FROM kaname.service_account_oauth_clients WHERE sva_id = $1`, string(svaID)).Scan(&id)
		return id, err
	})

	opsRepo := operations.NewRepo(pool, "kaname")
	revokeUC := buildRevokeUC(pool)

	const n = 8
	var (
		start sync.WaitGroup
		done  sync.WaitGroup
		mu    sync.Mutex
		outs  []raceOutcome
	)
	start.Add(1)
	for i := 0; i < n; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			op, xerr := revokeUC.Execute(withSAKeyPrincipal(ctx, string(uid)), RevokeInput{ServiceAccountID: svaID, KeyID: keyID})
			var o raceOutcome
			if xerr != nil {
				st := grpcstatus.Convert(xerr)
				o = raceOutcome{code: st.Code(), msg: st.Message()}
			} else {
				var got *operations.Operation
				deadline := time.Now().Add(10 * time.Second)
				for time.Now().Before(deadline) {
					g, gerr := opsRepo.Get(ctx, op.ID)
					if gerr == nil && g.Done {
						got = g
						break
					}
					time.Sleep(20 * time.Millisecond)
				}
				switch {
				case got == nil:
					o = raceOutcome{code: codes.DeadlineExceeded, msg: "операция не завершилась"}
				case got.Error != nil:
					o = raceOutcome{code: codes.Code(got.Error.GetCode()), msg: got.Error.GetMessage()}
				default:
					var resp iamv1.RevokeSAKeyResponse
					if uerr := got.Response.UnmarshalTo(&resp); uerr != nil {
						o = raceOutcome{code: codes.Unknown, msg: uerr.Error()}
					} else {
						o = raceOutcome{code: codes.OK, revoked: resp.GetRevokedAt() != nil}
					}
				}
			}
			mu.Lock()
			outs = append(outs, o)
			mu.Unlock()
		}()
	}
	start.Done()
	done.Wait()

	require.Len(t, outs, n)
	wantMsg := fmt.Sprintf("SAKey %s not found", keyID)
	var successes int
	for _, o := range outs {
		switch {
		case o.code == codes.OK:
			successes++
			require.True(t, o.revoked, "успех без отметки отзыва")
		case o.code == codes.NotFound:
			require.Equal(t, wantMsg, o.msg, "проигравший гонку получил не тот текст")
		default:
			t.Fatalf("исход гонки вне двух законных: %v %q", o.code, o.msg)
		}
	}
	require.Equal(t, 1, successes, "ровно один отзыв из %d обязан завершиться успехом; исходы: %+v", n, outs)
	require.Len(t, sakeyAuditRows(ctx, t, pool, "iam.sa_key.revoked", string(keyID)), 1,
		"событие аудита отзыва — ровно одно")
	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.service_account_oauth_clients WHERE id = $1`, string(keyID)).Scan(&rows))
	require.Zero(t, rows, "строка ключа обязана быть снята")
}

func TestRevokeSAKey_CVR08_ForeignKeyIsTheAbsentRefusalOnTheRealStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupSAKeyTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid, svaS := seedSAKeyUserAndSA(t, ctx, pool, "cvr08a")
	uid2, svaS2 := seedSAKeyUserAndSA(t, ctx, pool, "cvr08b")
	foreignKey := issueLiveSAKey(ctx, t, buildIssueUC(pool), uid2, svaS2, func() (string, error) {
		var id string
		err := pool.QueryRow(ctx, `SELECT id FROM kaname.service_account_oauth_clients WHERE sva_id = $1`, string(svaS2)).Scan(&id)
		return id, err
	})

	op, err := buildRevokeUC(pool).Execute(withSAKeyPrincipal(ctx, string(uid)), RevokeInput{ServiceAccountID: svaS, KeyID: foreignKey})
	require.Nil(t, op, "отказ синхронный: операции не заводится")
	require.Equal(t, codes.NotFound, grpcstatus.Code(err), "чужой ключ: %v", err)
	require.Equal(t, fmt.Sprintf("SAKey %s not found", foreignKey), grpcstatus.Convert(err).Message())

	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.service_account_oauth_clients WHERE id = $1 AND sva_id = $2`,
		string(foreignKey), string(svaS2)).Scan(&rows))
	require.Equal(t, 1, rows, "чужой ключ обязан остаться на месте")
	require.Empty(t, sakeyAuditRows(ctx, t, pool, "iam.sa_key.revoked", string(foreignKey)))
}
