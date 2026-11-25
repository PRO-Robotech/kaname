// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"bytes"
	"context"
	"crypto/sha256"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// На всю попытку берётся один ID события. Обе стадии и emit выполняются на
// захваченной TX. Полномочия и окончательные часы остаются у владельца writer.
type userTokenIssueStorage struct {
	tx                pgx.Tx
	budget            *relverdict.AdministrativeReadBudget
	actor             domain.Subject
	owner, creator    domain.UserID
	credential        domain.UserOAuthClientID
	kind              domain.CredentialKind
	algorithm         string
	digest            []byte
	audit             domain.AuditEventID
	reserved, emitted bool
}

func (a *userTokenIssueAuthority) waitStorage(ctx context.Context, tx pgx.Tx, budget *relverdict.AdministrativeReadBudget, row domain.UserOAuthClient) (*userTokenIssueStorage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if a == nil || tx == nil || a.bundle.Validate() != nil || a.owner != row.UserID || row.ID.Validate() != nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	subject, ok := authzguard.PrincipalSubject(ctx)
	if !ok || subject != string(a.actor.Type)+":"+string(a.actor.ID) {
		return nil, iamerr.ErrPermissionDenied
	}
	lane := shared.CreatedByLaneForUserToken(string(a.actor.ID), a.actor.Type == domain.SubjectTypeServiceAccount, string(row.UserID))
	if row.CreatedByUserID == "" || lane.ValidateRequested(string(row.CreatedByUserID)) != nil {
		return nil, iamerr.ErrPermissionDenied
	}
	switch row.CredentialKind {
	case domain.CredentialKindSecret:
		if len(row.SecretHash) != sha256.Size || row.KeyAlgorithm != "" {
			return nil, kaname.ErrInvalidAuthorityFencePlan
		}
	case domain.CredentialKindKeypair:
		if len(row.SecretHash) != 0 {
			return nil, kaname.ErrInvalidAuthorityFencePlan
		}
	default:
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	// Максимум две строки участников, потолок, счётчик и коллизия аудита.
	if err := chargeNativePolicyBudget(budget, 5, 10); err != nil {
		return nil, err
	}
	s := &userTokenIssueStorage{tx: tx, budget: budget, actor: a.actor, owner: row.UserID, creator: row.CreatedByUserID, credential: row.ID, kind: row.CredentialKind, algorithm: row.KeyAlgorithm, digest: bytes.Clone(row.SecretHash), audit: domain.AuditEventID(newAuditEventID())}
	if _, err := tx.Exec(ctx, `SELECT kaname._authority_user_token_issue_storage_wait_v1($1,$2,$3,$4)`, string(a.actor.Type), string(a.actor.ID), string(a.owner), string(s.audit)); err != nil {
		return nil, err
	}
	return s, nil
}

// Вызывается ПОСЛЕ блокирующих стадий и до final clock. Писатель получает
// 40001 на чужом ключе и перезапускает всю попытку, включая старые ожидания.
func (s *userTokenIssueStorage) reserveCredential(ctx context.Context) error {
	if s == nil || s.tx == nil || s.reserved {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	subject, ok := authzguard.PrincipalSubject(ctx)
	if !ok || subject != string(s.actor.Type)+":"+string(s.actor.ID) {
		return iamerr.ErrPermissionDenied
	}
	if err := chargeNativePolicyBudget(s.budget, 2, 5); err != nil {
		return err
	}
	_, err := s.tx.Exec(ctx, `SELECT kaname._authority_user_token_unique_reserve_v1($1,$2,$3)`, string(s.credential), string(s.kind), s.digest)
	if err == nil {
		s.reserved = true
	}
	return err
}

func (s *userTokenIssueStorage) emit(ctx context.Context) error {
	if s == nil || s.tx == nil || !s.reserved || s.emitted {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	subject, ok := authzguard.PrincipalSubject(ctx)
	if !ok || subject != string(s.actor.Type)+":"+string(s.actor.ID) {
		return iamerr.ErrPermissionDenied
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := chargeNativePolicyBudget(s.budget, 4, 7); err != nil {
		return err
	}
	// Rollback к savepoint мог освободить резервации, сохранив объект Go.
	// Проверяем реальные удержанные ключи до emit, без повторного захвата.
	if _, err := s.tx.Exec(ctx, `SELECT kaname._authority_resource_preheld_key_v2(space,key_value COLLATE "C",true)
FROM kaname._authority_user_token_unique_keys_v1($1,$2,$3)
UNION ALL SELECT kaname._authority_resource_preheld_key_v2(1262569298,$4,true)`, string(s.credential), string(s.kind), s.digest, string(s.audit)); err != nil {
		return err
	}
	// В начале резервации PK и digest были свободны; только эта TX могла
	// добавить строку с удержанным ID. Аудит сверяет именно результат INSERT.
	var inserted bool
	err := s.tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM ONLY kaname.user_oauth_clients
WHERE id=$1 AND xmin=pg_current_xact_id()::xid AND user_id=$2 AND created_by_user_id=$3 AND credential_kind=$4 AND key_algorithm=$5 AND secret_hash=coalesce($6::bytea,''::bytea))`, string(s.credential), string(s.owner), string(s.creator), string(s.kind), s.algorithm, s.digest).Scan(&inserted)
	if err != nil {
		return err
	}
	if !inserted {
		return kaname.ErrSourceUnconfirmed
	}
	event := shared.UserTokenIssuedAuditEvent(string(s.actor.ID), s.owner, s.credential, s.algorithm)
	if err = insertAuditEventWithIDTx(ctx, s.tx, event, s.audit); err != nil {
		return err
	}
	s.emitted = true
	return nil
}
