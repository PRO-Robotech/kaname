// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// authorization_ceremony_repo.go — хранилище церемонии OAuth 2.1
// `authorization_code` (под-фаза LINE-A-1, задача PRO-Robotech/kacho#2721).
// Порт — `internal/apps/kaname/api/ceremony`.
//
// # Каждый инвариант — оператор базы, а не проверка перед записью (ban #10)
//
//   - выдача кода — условная вставка: клиент `ACTIVE`, цель в его списке,
//     сессия жива — судятся ТЕМ ЖЕ оператором;
//   - потребление кода — один `UPDATE … WHERE consumed_at IS NULL AND
//     expires_at > now() AND <связка>`, заводящий авторизацию в том же
//     операторе; ноль строк — отказ; срок — часы базы;
//   - отзыв семейства по повтору кода — один `UPDATE` авторизации с условием
//     «код уже потреблён»;
//   - ротация — CAS `rotated_at IS NULL` под замком строки авторизации; одно
//     действующее удостоверение на семейство держит частичный уникальный
//     индекс.
//
// Отсечку предъявителей семейства пишет ТОТ ЖЕ оператор, что и
// `MintedTokenRevocationRepo.Revoke` (`mintedTokenRevokeSQL`): писатель
// таблицы отсечек один, путей к нему два — пул и транзакция вызывающего.

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/ceremony"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// ceremonyRevokedBy — кто решил отзыв семейства: церемония сама, по
// обнаруженному повтору. Не личность, а имя решающего механизма.
const ceremonyRevokedBy = "kaname-authorization-ceremony"

// AuthorizationCeremonyRepo — хранилище церемонии на пуле.
type AuthorizationCeremonyRepo struct {
	pool *pgxpool.Pool
}

// NewAuthorizationCeremonyRepo — адаптер поверх пула.
func NewAuthorizationCeremonyRepo(pool *pgxpool.Pool) *AuthorizationCeremonyRepo {
	return &AuthorizationCeremonyRepo{pool: pool}
}

// issueCodeSQL — условная вставка записи кода. Строка ложится, только если
// клиент `ACTIVE` и цель входит в его список ДОСЛОВНО, а сессия того же
// человека не снята и не истекла, — всё это судит один оператор.
const issueCodeSQL = `
	INSERT INTO authorization_codes
	       (code_digest, client_id, session_id, user_id, redirect_uri, scope, code_challenge, issued_at, expires_at)
	SELECT $1, c.id, s.id, s.user_id, $4, $5, $6, now(), now() + make_interval(secs => $7)
	  FROM interactive_clients c, human_sessions s
	 WHERE c.id = $2 AND c.status = 'ACTIVE' AND $4 = ANY (c.redirect_uris)
	   AND s.id = $3 AND s.user_id = $8 AND s.ended_at IS NULL AND s.expires_at > now()`

// IssueCode — см. порт.
func (r *AuthorizationCeremonyRepo) IssueCode(ctx context.Context, in ceremony.CodeIssue) (bool, error) {
	tag, err := r.pool.Exec(ctx, issueCodeSQL,
		string(in.Digest), string(in.Client), string(in.Session), in.RedirectURI, in.Scope, in.CodeChallenge,
		in.TTL.Seconds(), string(in.Subject))
	if err != nil {
		return false, mapErr(err, "AuthorizationCode.Issue", "")
	}
	return tag.RowsAffected() == 1, nil
}

// classifyCodeSQL — почему код не потреблён. Порядок причин несущий и
// совпадает с порядком условий оператора потребления.
const classifyCodeSQL = `
	SELECT c.consumed_at IS NOT NULL,
	       c.expires_at <= now(),
	       c.client_id = $2,
	       c.redirect_uri = $3,
	       c.code_challenge = $4,
	       EXISTS (SELECT 1 FROM human_sessions s
	                WHERE s.id = c.session_id AND s.ended_at IS NULL AND s.expires_at > now())
	  FROM authorization_codes c
	 WHERE c.code_digest = $1`

// ClassifyCode — см. порт.
func (r *AuthorizationCeremonyRepo) ClassifyCode(ctx context.Context, in ceremony.CodeRedemption) (ceremony.CodeRefusal, error) {
	var consumed, expired, sameClient, sameTarget, sameChallenge, sessionLive bool
	err := r.pool.QueryRow(ctx, classifyCodeSQL, string(in.Digest), string(in.Client), in.RedirectURI, in.Challenge).
		Scan(&consumed, &expired, &sameClient, &sameTarget, &sameChallenge, &sessionLive)
	if errors.Is(err, pgx.ErrNoRows) {
		return ceremony.CodeUnknown, nil
	}
	if err != nil {
		return "", mapErr(err, "AuthorizationCode.Classify", "")
	}
	switch {
	case consumed:
		return ceremony.CodeConsumed, nil
	case expired:
		return ceremony.CodeExpired, nil
	case !sameClient:
		return ceremony.CodeClientMismatch, nil
	case !sameTarget:
		return ceremony.CodeRedirectMismatch, nil
	case !sameChallenge:
		return ceremony.CodeVerifierMismatch, nil
	case !sessionLive:
		return ceremony.CodeSessionEnded, nil
	default:
		return ceremony.CodeUnknown, nil
	}
}

// ClientSecret — см. порт `ceremony.ClientRegistry`.
func (r *AuthorizationCeremonyRepo) ClientSecret(ctx context.Context, id domain.InteractiveClientID) (ceremony.ClientSecret, bool, error) {
	var (
		status   string
		verifier *string
	)
	err := r.pool.QueryRow(ctx, `SELECT status, secret_verifier FROM interactive_clients WHERE id = $1`, string(id)).
		Scan(&status, &verifier)
	if errors.Is(err, pgx.ErrNoRows) {
		return ceremony.ClientSecret{}, false, nil
	}
	if err != nil {
		return ceremony.ClientSecret{}, false, mapErr(err, "InteractiveClient.Secret", string(id))
	}
	out := ceremony.ClientSecret{Active: domain.InteractiveClientStatus(status) == domain.InteractiveClientActive}
	if verifier != nil && *verifier != "" {
		v, verr := domain.NewLoginVerifier(*verifier)
		if verr != nil {
			return ceremony.ClientSecret{}, false, iamerr.Wrapf(iamerr.ErrInternal, "interactive client secret verifier is unreadable")
		}
		out.Verifier = v
	}
	return out, true, nil
}

// SweepUnservableCodes — уборка записей кода, чей срок истёк раньше порога.
// Порог — окно узнавания повтора после срока (`grace`): раньше него запись
// ещё отзывает семейство по повторному предъявлению.
func (r *AuthorizationCeremonyRepo) SweepUnservableCodes(ctx context.Context, grace time.Duration, batch int) (int64, bool, error) {
	if batch <= 0 {
		return 0, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument batch: must be positive")
	}
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM authorization_codes
		 WHERE ctid IN (
		       SELECT ctid FROM authorization_codes
		        WHERE expires_at <= now() - make_interval(secs => $1)
		        ORDER BY expires_at
		        LIMIT $2
		        FOR UPDATE SKIP LOCKED)`, grace.Seconds(), batch)
	if err != nil {
		return 0, false, mapErr(err, "AuthorizationCode.Sweep", "")
	}
	n := tag.RowsAffected()
	return n, n == int64(batch), nil
}

// Writer — см. порт.
func (r *AuthorizationCeremonyRepo) Writer(ctx context.Context) (ceremony.Writer, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, mapErr(err, "AuthorizationCeremony.Writer", "")
	}
	return &ceremonyWriter{tx: tx}, nil
}

type ceremonyWriter struct{ tx pgx.Tx }

// redeemCodeSQL — потребление кода ОДНИМ оператором: условие «не потреблён,
// не истёк, тот же клиент, та же цель, тот же вызов PKCE, сессия жива», и в
// том же операторе — авторизация по нему. Ноль строк — отказ. Факты сессии,
// переносимые в предъявитель, читаются у записи сессии: второй их копии нет.
const redeemCodeSQL = `
	WITH consumed AS (
	    UPDATE authorization_codes c
	       SET consumed_at = now()
	     WHERE c.code_digest = $1
	       AND c.consumed_at IS NULL
	       AND c.expires_at > now()
	       AND c.client_id = $2
	       AND c.redirect_uri = $3
	       AND c.code_challenge = $4
	       AND EXISTS (SELECT 1 FROM human_sessions s
	                    WHERE s.id = c.session_id AND s.ended_at IS NULL AND s.expires_at > now())
	 RETURNING c.code_digest, c.client_id, c.session_id, c.user_id, c.scope
	), granted AS (
	    INSERT INTO authorization_grants (id, code_digest, client_id, session_id, user_id, scope)
	    SELECT $5, code_digest, client_id, session_id, user_id, scope FROM consumed
	 RETURNING id, client_id, session_id, user_id, scope
	)
	SELECT g.id, g.client_id, g.session_id, g.user_id, g.scope,
	       s.authenticated_at, s.assurance_level, s.expires_at
	  FROM granted g
	  JOIN human_sessions s ON s.id = g.session_id`

func (w *ceremonyWriter) RedeemCode(ctx context.Context, in ceremony.CodeRedemption) (ceremony.Grant, bool, error) {
	g, err := scanGrant(w.tx.QueryRow(ctx, redeemCodeSQL,
		string(in.Digest), string(in.Client), in.RedirectURI, in.Challenge, string(in.Grant)))
	if errors.Is(err, pgx.ErrNoRows) {
		return ceremony.Grant{}, false, nil
	}
	if err != nil {
		return ceremony.Grant{}, false, mapErr(err, "AuthorizationCode.Redeem", "")
	}
	return g, true, nil
}

// revokeFamilyOfCodeSQL — отзыв авторизации, выданной по УЖЕ потреблённому
// коду. Признак «потреблён» монотонен, поэтому условие не устаревает между
// чтением и записью.
const revokeFamilyOfCodeSQL = `
	UPDATE authorization_grants g
	   SET revoked_at = now(), revoked_reason = 'code-replay'
	 WHERE g.code_digest = $1
	   AND g.revoked_at IS NULL
	   AND EXISTS (SELECT 1 FROM authorization_codes c WHERE c.code_digest = $1 AND c.consumed_at IS NOT NULL)
	RETURNING g.id, g.client_id, g.session_id, g.user_id, g.scope`

func (w *ceremonyWriter) RevokeFamilyOfCode(ctx context.Context, digest domain.CeremonySecretDigest, before time.Time) (ceremony.Grant, bool, error) {
	var g ceremony.Grant
	err := w.tx.QueryRow(ctx, revokeFamilyOfCodeSQL, string(digest)).
		Scan(&g.ID, &g.Client, &g.Session, &g.Subject, &g.Scope)
	if errors.Is(err, pgx.ErrNoRows) {
		return ceremony.Grant{}, false, nil
	}
	if err != nil {
		return ceremony.Grant{}, false, mapErr(err, "AuthorizationGrant.RevokeOnCodeReplay", "")
	}
	if err := w.cutFamily(ctx, g.ID, before, ceremony.RevokedCodeReplay); err != nil {
		return ceremony.Grant{}, false, err
	}
	return g, true, nil
}

// lockGrantSQL — замок авторизации предъявленного удостоверения. Решения о
// семействе (ротация, повтор, отзыв) сериализуются им; состояние читается
// СЛЕДУЮЩИМ оператором, то есть уже после замка, свежим снимком.
const lockGrantSQL = `
	SELECT g.id FROM authorization_grants g
	 WHERE g.id = (SELECT rt.grant_id FROM authorization_refresh_tokens rt WHERE rt.token_digest = $1)
	   FOR UPDATE`

const refreshStateSQL = `
	SELECT g.id, g.client_id, g.session_id, g.user_id, g.scope,
	       s.authenticated_at, s.assurance_level, s.expires_at,
	       rt.rotated_at IS NOT NULL,
	       g.revoked_at IS NOT NULL,
	       (s.ended_at IS NULL AND s.expires_at > now()),
	       EXISTS (SELECT 1 FROM user_token_revocations c
	                WHERE c.user_id = g.user_id AND s.authenticated_at <= c.revoke_before)
	  FROM authorization_refresh_tokens rt
	  JOIN authorization_grants g ON g.id = rt.grant_id
	  JOIN human_sessions s ON s.id = g.session_id
	 WHERE rt.token_digest = $1`

func (w *ceremonyWriter) LockRefresh(ctx context.Context, digest domain.CeremonySecretDigest) (ceremony.RefreshState, error) {
	var locked string
	err := w.tx.QueryRow(ctx, lockGrantSQL, string(digest)).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return ceremony.RefreshState{}, nil
	}
	if err != nil {
		return ceremony.RefreshState{}, mapErr(err, "AuthorizationGrant.Lock", "")
	}
	var st ceremony.RefreshState
	err = w.tx.QueryRow(ctx, refreshStateSQL, string(digest)).Scan(
		&st.Grant.ID, &st.Grant.Client, &st.Grant.Session, &st.Grant.Subject, &st.Grant.Scope,
		&st.Grant.AuthenticatedAt, &st.Grant.Level, &st.Grant.SessionExpiresAt,
		&st.Rotated, &st.Revoked, &st.SessionLive, &st.CutOff)
	if errors.Is(err, pgx.ErrNoRows) {
		return ceremony.RefreshState{}, nil
	}
	if err != nil {
		return ceremony.RefreshState{}, mapErr(err, "RefreshToken.State", "")
	}
	st.Found = true
	return st, nil
}

func (w *ceremonyWriter) RotateRefresh(ctx context.Context, prev, next domain.CeremonySecretDigest, grant domain.AuthorizationGrantID) (bool, error) {
	tag, err := w.tx.Exec(ctx, `
		UPDATE authorization_refresh_tokens SET rotated_at = now()
		 WHERE token_digest = $1 AND grant_id = $2 AND rotated_at IS NULL`, string(prev), string(grant))
	if err != nil {
		return false, mapErr(err, "RefreshToken.Rotate", "")
	}
	if tag.RowsAffected() != 1 {
		return false, nil
	}
	if err := w.InsertRefresh(ctx, next, grant); err != nil {
		return false, err
	}
	return true, nil
}

func (w *ceremonyWriter) InsertRefresh(ctx context.Context, digest domain.CeremonySecretDigest, grant domain.AuthorizationGrantID) error {
	if _, err := w.tx.Exec(ctx,
		`INSERT INTO authorization_refresh_tokens (token_digest, grant_id) VALUES ($1, $2)`,
		string(digest), string(grant)); err != nil {
		return mapErr(err, "RefreshToken.Insert", "")
	}
	return nil
}

func (w *ceremonyWriter) RevokeFamily(ctx context.Context, in ceremony.FamilyRevocation) (bool, error) {
	tag, err := w.tx.Exec(ctx, `
		UPDATE authorization_grants SET revoked_at = now(), revoked_reason = $2
		 WHERE id = $1 AND revoked_at IS NULL`, string(in.Grant), string(in.Reason))
	if err != nil {
		return false, mapErr(err, "AuthorizationGrant.Revoke", "")
	}
	if err := w.cutFamily(ctx, in.Grant, in.Before, in.Reason); err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// cutFamily — отсечка предъявителей семейства по ключу
// `kaname_authorization_id`. Оператор — тот же, что у отзыва отчеканенного
// (`mintedTokenRevokeSQL`): монотонный, повтор не отодвигает границу назад.
func (w *ceremonyWriter) cutFamily(ctx context.Context, grant domain.AuthorizationGrantID, before time.Time, reason ceremony.RevocationReason) error {
	if _, err := w.tx.Exec(ctx, mintedTokenRevokeSQL,
		string(grant), before, "authorization family revoked: "+string(reason), ceremonyRevokedBy); err != nil {
		return mapErr(err, "TokenRevocation", string(grant))
	}
	return nil
}

func (w *ceremonyWriter) EmitAudit(ctx context.Context, ev outboxtypes.AuditEvent) error {
	return insertAuditEventTx(ctx, w.tx, ev)
}

func (w *ceremonyWriter) Commit(ctx context.Context) error {
	if err := w.tx.Commit(ctx); err != nil {
		return mapErr(err, "", "")
	}
	return nil
}

func (w *ceremonyWriter) Rollback(ctx context.Context) error {
	err := w.tx.Rollback(ctx)
	if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return err
	}
	return nil
}

func scanGrant(row pgx.Row) (ceremony.Grant, error) {
	var g ceremony.Grant
	err := row.Scan(&g.ID, &g.Client, &g.Session, &g.Subject, &g.Scope,
		&g.AuthenticatedAt, &g.Level, &g.SessionExpiresAt)
	return g, err
}

var (
	_ ceremony.Store  = (*AuthorizationCeremonyRepo)(nil)
	_ ceremony.Writer = (*ceremonyWriter)(nil)
)
