// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Обычный InsertForActiveOwner, два настоящих индекса, quota trigger и запись
// аудита с заранее выбранным ID используют одно соединение и одну TX.
func TestUserTokenIssueStoragePublishesReservedAuditForInsertedCredential(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	pool, err := coredb.NewPool(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	defer pool.Close()
	bundle := nativeBoundaryBundle(t)
	for _, tc := range []struct {
		name         string
		kind         domain.CredentialKind
		rollbackKeys bool
	}{
		{"KEYPAIR", domain.CredentialKindKeypair, false}, {"SECRET", domain.CredentialKindSecret, false}, {"released savepoint", domain.CredentialKindSecret, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind := tc.kind
			tx, err := pool.Begin(ctx)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback(ctx) }()
			id := ids.NewID(domain.PrefixUser)
			_, err = tx.Exec(ctx, `INSERT INTO kaname.users(id,account_id,external_id,email,display_name,invite_status,email_verified_at)
SELECT $1,id,$1,$1||'@example.invalid',$1,'ACTIVE',clock_timestamp() FROM kaname.accounts ORDER BY id LIMIT 1`, id)
			require.NoError(t, err)
			principal := operations.Principal{Type: "user", ID: id}
			call := operations.WithPrincipal(ctx, principal)
			actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(id)}
			expiry := time.Now().UTC().Add(time.Hour)
			row := domain.UserOAuthClient{ID: domain.UserOAuthClientID(ids.NewID(domain.PrefixUserOAuthClient)), UserID: domain.UserID(id), CreatedByUserID: domain.UserID(id), CredentialKind: kind, CreatedAt: time.Now().UTC(), ExpiresAt: &expiry, Name: "fixture"}
			if kind == domain.CredentialKindKeypair {
				row.KeyAlgorithm = "ES256"
				row.PublicKeyPEM = "fixture-public-key"
			} else {
				row.SecretHash = bytes.Repeat([]byte{17}, 32)
			}
			a, err := prepareUserTokenIssueAuthority(call, bundle, actor, row.UserID, newNativePolicyQuestions())
			require.NoError(t, err)
			s, err := a.waitStorage(call, tx, &relverdict.AdministrativeReadBudget{}, row)
			require.NoError(t, err)
			require.NoError(t, s.audit.Validate())
			require.ErrorIs(t, s.emit(call), kaname.ErrInvalidAuthorityFencePlan)
			if tc.rollbackKeys {
				_, err = tx.Exec(ctx, `SAVEPOINT before_keys`)
				require.NoError(t, err)
			}
			require.NoError(t, s.reserveCredential(call))
			if tc.rollbackKeys {
				_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT before_keys`)
				require.NoError(t, err)
				var refused *pgconn.PgError
				require.ErrorAs(t, s.emit(call), &refused)
				require.Equal(t, "42501", refused.Code)
				return
			}
			require.ErrorIs(t, s.emit(call), kaname.ErrSourceUnconfirmed)
			_, err = NewUserOAuthClientRepo(pool).InsertForActiveOwner(call, tx, principal, row)
			require.NoError(t, err)
			require.NoError(t, s.emit(call))
			require.ErrorIs(t, s.emit(call), kaname.ErrInvalidAuthorityFencePlan)
			event := shared.UserTokenIssuedAuditEvent(id, row.UserID, row.ID, row.KeyAlgorithm)
			want, err := json.Marshal(event.Payload)
			require.NoError(t, err)
			var typ string
			var payload []byte
			require.NoError(t, tx.QueryRow(ctx, `SELECT event_type,event_payload FROM kaname.audit_outbox WHERE id=$1`, string(s.audit)).Scan(&typ, &payload))
			require.Equal(t, event.EventType, typ)
			require.JSONEq(t, string(want), string(payload))
			require.NoError(t, tx.Rollback(ctx))
			var remains bool
			require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS(SELECT FROM kaname.user_oauth_clients WHERE id=$1) OR EXISTS(SELECT FROM kaname.audit_outbox WHERE id=$2)`, string(row.ID), string(s.audit)).Scan(&remains))
			require.False(t, remains)
		})
	}
}
