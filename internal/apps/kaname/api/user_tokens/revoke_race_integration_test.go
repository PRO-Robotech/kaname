// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user_tokens

// revoke_race_integration_test.go — CVR-11 и CVR-04 на настоящей базе (приёмка
// `docs/engineering/acceptance/credential-verbs-refusal-outcomes.md`, задача
// kaname#522).
//
//   - CVR-11: N параллельных отзывов одного удостоверения человека — ровно один
//     успех с отметкой отзыва, каждый прочий получает синхронный `NOT_FOUND`
//     либо операцию, завершённую ошибкой с тем же кодом и текстом; строка
//     снята один раз, событие аудита одно.
//   - CVR-04: чужое удостоверение — синхронный `NOT_FOUND`, строка на месте;
//     сверка существования исполняется настоящим оператором чтения, суженным
//     владельцем.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// seedTokenOwner заводит человека со своим аккаунтом.
func seedTokenOwner(ctx context.Context, t *testing.T, pool *pgxpool.Pool, suffix string) domain.UserID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		string(uid), string(accID), "ext-"+suffix+"-"+string(uid), "u-"+suffix+"@example.com", "Token Owner "+suffix)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID), fmt.Sprintf("ut-acc-%s-%s", suffix, accID[len(accID)-6:]), string(uid))
	require.NoError(t, err)
	seedWayIn(t, ctx, tx)
	require.NoError(t, tx.Commit(ctx))
	return uid
}

// insertLiveToken кладёт человеку живое удостоверение настоящим писателем.
func insertLiveToken(ctx context.Context, t *testing.T, pool *pgxpool.Pool, owner domain.UserID) domain.UserOAuthClientID {
	t.Helper()
	repo := kanamepg.NewUserOAuthClientRepo(pool)
	txb := kanamepg.NewPoolTxBeginner(pool)
	tx, err := txb.Begin(ctx)
	require.NoError(t, err)
	row, err := repo.Insert(ctx, tx, domain.UserOAuthClient{
		// Момент выдачи — обязательный вход записи (kaname#589).
		CreatedAt:       time.Now().UTC(),
		CredentialKind:  domain.CredentialKindKeypair,
		ID:              domain.UserOAuthClientID(ids.NewID(domain.PrefixUserOAuthClient)),
		UserID:          owner,
		Description:     "cvr race",
		CreatedByUserID: owner,
		PublicKeyPEM:    "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
		KeyAlgorithm:    "ES256",
	})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return row.ID
}

func buildRevokeTokenUC(pool *pgxpool.Pool) *RevokeUserTokenUseCase {
	return NewRevokeUserTokenUseCase(kanamepg.NewUserOAuthClientRepo(pool), kanamepg.NewPoolTxBeginner(pool),
		operations.NewRepo(pool, "kaname")).WithAuditEmitter(kanamepg.NewAuditOutboxEmitter(pool))
}

func tokenRevokedAudits(ctx context.Context, t *testing.T, pool *pgxpool.Pool, tokenID domain.UserOAuthClientID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.audit_outbox WHERE event_type = 'iam.user_token.revoked' AND event_payload->>'token_id' = $1`,
		string(tokenID)).Scan(&n))
	return n
}

func withTokenPrincipal(ctx context.Context, uid domain.UserID) context.Context {
	return operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: string(uid)})
}

type tokenRaceOutcome struct {
	code    codes.Code
	msg     string
	revoked bool
}

func TestRevoke_CVR11_ConcurrentRevokesYieldOneSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	owner := seedTokenOwner(ctx, t, pool, "cvr11")
	tokenID := insertLiveToken(ctx, t, pool, owner)
	opsRepo := operations.NewRepo(pool, "kaname")
	uc := buildRevokeTokenUC(pool)

	const n = 8
	var (
		start sync.WaitGroup
		done  sync.WaitGroup
		mu    sync.Mutex
		outs  []tokenRaceOutcome
	)
	start.Add(1)
	for i := 0; i < n; i++ {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			op, xerr := uc.Execute(withTokenPrincipal(ctx, owner), RevokeInput{UserID: owner, TokenID: tokenID})
			var o tokenRaceOutcome
			if xerr != nil {
				st := grpcstatus.Convert(xerr)
				o = tokenRaceOutcome{code: st.Code(), msg: st.Message()}
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
					o = tokenRaceOutcome{code: codes.DeadlineExceeded, msg: "операция не завершилась"}
				case got.Error != nil:
					o = tokenRaceOutcome{code: codes.Code(got.Error.GetCode()), msg: got.Error.GetMessage()}
				default:
					var resp iamv1.RevokeUserTokenResponse
					if uerr := got.Response.UnmarshalTo(&resp); uerr != nil {
						o = tokenRaceOutcome{code: codes.Unknown, msg: uerr.Error()}
					} else {
						o = tokenRaceOutcome{code: codes.OK, revoked: resp.GetRevokedAt() != nil}
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
	wantMsg := fmt.Sprintf("UserToken %s not found", tokenID)
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
	require.Equal(t, 1, tokenRevokedAudits(ctx, t, pool, tokenID), "событие аудита отзыва — ровно одно")
	var rows int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.user_oauth_clients WHERE id = $1`, string(tokenID)).Scan(&rows))
	require.Zero(t, rows, "строка удостоверения обязана быть снята")
}

func TestRevoke_CVR04_ForeignTokenIsTheAbsentRefusalOnTheRealStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	a := seedTokenOwner(ctx, t, pool, "cvr04a")
	b := seedTokenOwner(ctx, t, pool, "cvr04b")
	foreign := insertLiveToken(ctx, t, pool, b)

	op, err := buildRevokeTokenUC(pool).Execute(withTokenPrincipal(ctx, a), RevokeInput{UserID: a, TokenID: foreign})
	require.Nil(t, op, "отказ синхронный: операции не заводится")
	require.Equal(t, codes.NotFound, grpcstatus.Code(err), "чужое удостоверение: %v", err)
	require.Equal(t, fmt.Sprintf("UserToken %s not found", foreign), grpcstatus.Convert(err).Message())

	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.user_oauth_clients WHERE id = $1 AND user_id = $2`, string(foreign), string(b)).Scan(&rows))
	require.Equal(t, 1, rows, "чужое удостоверение обязано остаться на месте")
	require.Zero(t, tokenRevokedAudits(ctx, t, pool, foreign))
}
