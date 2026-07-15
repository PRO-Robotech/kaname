// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// iam_extension_repos.go — repository for the non-core IAM extension
// service_account_oauth_clients (SAKey — Class A static keys via Hydra).
//
// Holds only SAOAuthClientRepo; the former federation / JIT-eligibility /
// access-binding-condition repos no longer exist.
package pg

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ───────────────────────────────────────────────────────────────────────────
// ServiceAccountOAuthClient repo
// ───────────────────────────────────────────────────────────────────────────

type SAOAuthClientRepo struct {
	pool *pgxpool.Pool
}

func NewSAOAuthClientRepo(pool *pgxpool.Pool) *SAOAuthClientRepo {
	return &SAOAuthClientRepo{pool: pool}
}

const socCols = `id, sva_id, hydra_client_id, description, created_by_user_id,
                 created_at, expires_at, last_used_at,
                 public_key_pem, key_algorithm, trusted_subjects, name, labels`

func (r *SAOAuthClientRepo) Get(ctx context.Context, id domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	row := r.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM service_account_oauth_clients WHERE id = $1`, socCols),
		string(id))
	out, err := scanSAOAuthClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ServiceAccountOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "SAOAuthClient %s not found", id)
	}
	if err != nil {
		return domain.ServiceAccountOAuthClient{}, mapErr(err, "", string(id))
	}
	return out, nil
}

// GetByOAuthClientID — reverse lookup for token-hook claim enrichment:
// Hydra hands kacho-iam the `client_id` (== hydra_client_id) of the OAuth
// client doing client_credentials; we need the owning ServiceAccount.
func (r *SAOAuthClientRepo) GetByOAuthClientID(ctx context.Context, hydraClientID domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	row := r.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM service_account_oauth_clients WHERE hydra_client_id = $1`, socCols),
		string(hydraClientID))
	out, err := scanSAOAuthClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ServiceAccountOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "SAOAuthClient with hydra_client_id %s not found", hydraClientID)
	}
	if err != nil {
		return domain.ServiceAccountOAuthClient{}, mapErr(err, "", string(hydraClientID))
	}
	return out, nil
}

// Insert persists a new SA-OAuth-client row in the caller's writer-tx. Accepts
// the opaque service.Tx (sa_keys use-case port) and recovers the concrete
// pgx.Tx via txAsPgx so pgx stays confined to repo/kacho/pg.
func (r *SAOAuthClientRepo) Insert(ctx context.Context, txh service.Tx, c domain.ServiceAccountOAuthClient) (domain.ServiceAccountOAuthClient, error) {
	tx := txAsPgx(txh)
	const q = `
		INSERT INTO service_account_oauth_clients (
		    id, sva_id, hydra_client_id, description, created_by_user_id,
		    created_at, expires_at, last_used_at,
		    public_key_pem, key_algorithm, trusted_subjects, name, labels
		) VALUES ($1, $2, $3, $4, $5, COALESCE($6, now()), $7, $8, $9, $10, $11::jsonb, $12, $13::jsonb)
		RETURNING ` + socCols
	tsJSON, err := marshalTrustedSubjects(c.TrustedSubjects)
	if err != nil {
		return domain.ServiceAccountOAuthClient{}, mapErr(err, "", string(c.ID))
	}
	labelsJSON, err := marshalLabels(c.Labels)
	if err != nil {
		return domain.ServiceAccountOAuthClient{}, mapErr(err, "", string(c.ID))
	}
	row := tx.QueryRow(ctx, q,
		string(c.ID), string(c.SvaID), string(c.OAuthClientID),
		string(c.Description), string(c.CreatedByUserID),
		nullableTime(c.CreatedAt), nullableTimePtr(c.ExpiresAt), nullableTimePtr(c.LastUsedAt),
		c.PublicKeyPEM, c.KeyAlgorithm, tsJSON, string(c.Name), labelsJSON,
	)
	out, err := scanSAOAuthClient(row)
	if err != nil {
		return domain.ServiceAccountOAuthClient{}, mapErr(err, "", string(c.ID))
	}
	return out, nil
}

// AccountForServiceAccount — resolves the owning account of a ServiceAccount by
// its id. Used to stamp `account_id` on Issue/Revoke SA-key Operation metadata so
// the account-scoped /iam/operations feed includes token operations. Missing SA →
// ErrNotFound (well-formed id, no such SA).
func (r *SAOAuthClientRepo) AccountForServiceAccount(ctx context.Context, id domain.ServiceAccountID) (domain.AccountID, error) {
	var accountID string
	err := r.pool.QueryRow(ctx,
		`SELECT account_id FROM service_accounts WHERE id = $1`, string(id)).Scan(&accountID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", iamerr.Wrapf(iamerr.ErrNotFound, "ServiceAccount %s not found", id)
	}
	if err != nil {
		return "", mapErr(err, "SAOAuthClient.AccountForServiceAccount", string(id))
	}
	return domain.AccountID(accountID), nil
}

// FindByExternalSubject — reverse lookup for federation IN: given an
// external OIDC (issuer, sub) tuple, return the SA-OAuth-client mapping whose
// `trusted_subjects` contains an entry with matching issuer AND a
// subject_pattern regex that matches `sub`. Returns ErrNotFound when nothing
// matches.
//
// Uses jsonb containment (`@>`) to narrow on issuer, then the Postgres `~`
// regex operator to validate the subject_pattern against the supplied sub.
// Indexes: jsonb is small per row (a handful of entries); a future GIN index
// on `trusted_subjects` is straightforward if cardinality grows.
func (r *SAOAuthClientRepo) FindByExternalSubject(ctx context.Context, issuer, sub string) (domain.ServiceAccountOAuthClient, error) {
	q := fmt.Sprintf(`
		SELECT %s
		  FROM service_account_oauth_clients
		 WHERE EXISTS (
		           SELECT 1
		             FROM jsonb_array_elements(trusted_subjects) AS ts
		            WHERE ts->>'issuer' = $1
		              AND $2 ~ (ts->>'subject_pattern')
		       )
		 LIMIT 1`, socCols)
	row := r.pool.QueryRow(ctx, q, issuer, sub)
	out, err := scanSAOAuthClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ServiceAccountOAuthClient{}, iamerr.Wrapf(iamerr.ErrNotFound,
			"SAOAuthClient with trusted_subject (issuer=%s, sub=%s) not found", issuer, sub)
	}
	if err != nil {
		return domain.ServiceAccountOAuthClient{}, mapErr(err, "SAOAuthClient.FindByExternalSubject", "")
	}
	return out, nil
}

func marshalTrustedSubjects(ts []domain.TrustedSubject) ([]byte, error) {
	if len(ts) == 0 {
		return []byte("[]"), nil
	}
	type wire struct {
		Issuer         string `json:"issuer"`
		SubjectPattern string `json:"subject_pattern"`
	}
	out := make([]wire, len(ts))
	for i, t := range ts {
		out[i] = wire{Issuer: t.Issuer, SubjectPattern: t.SubjectPattern}
	}
	return json.Marshal(out)
}

func unmarshalTrustedSubjects(body []byte) ([]domain.TrustedSubject, error) {
	if len(body) == 0 {
		return nil, nil
	}
	type wire struct {
		Issuer         string `json:"issuer"`
		SubjectPattern string `json:"subject_pattern"`
	}
	var in []wire
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, fmt.Errorf("unmarshal trusted_subjects: %w", err)
	}
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]domain.TrustedSubject, len(in))
	for i, w := range in {
		out[i] = domain.TrustedSubject{Issuer: w.Issuer, SubjectPattern: w.SubjectPattern}
	}
	return out, nil
}

// List returns OAuth clients owned by the given SA, paged by id ASC.
func (r *SAOAuthClientRepo) List(ctx context.Context, svaID domain.ServiceAccountID, pageToken string, pageSize int32) ([]domain.ServiceAccountOAuthClient, string, error) {
	if pageSize <= 0 || pageSize > 1000 {
		pageSize = 100
	}
	q := `SELECT ` + socCols + `
	        FROM service_account_oauth_clients
	       WHERE sva_id = $1 AND id > $2
	       ORDER BY id ASC
	       LIMIT $3`
	rows, err := r.pool.Query(ctx, q, string(svaID), pageToken, pageSize+1)
	if err != nil {
		return nil, "", mapErr(err, "SAOAuthClient.List", "")
	}
	defer rows.Close()
	var out []domain.ServiceAccountOAuthClient
	for rows.Next() {
		c, err := scanSAOAuthClient(rows)
		if err != nil {
			return nil, "", mapErr(err, "SAOAuthClient.List", "")
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "SAOAuthClient.List", "")
	}
	var nextToken string
	if safeconv.IntToInt32(len(out)) > pageSize {
		nextToken = string(out[pageSize-1].ID)
		out = out[:pageSize]
	}
	return out, nextToken, nil
}

// DeleteByID removes a single SA OAuth client row. Idempotent — returns
// ErrNotFound if missing. Accepts the opaque service.Tx (sa_keys use-case port)
// and recovers the concrete pgx.Tx via txAsPgx.
func (r *SAOAuthClientRepo) DeleteByID(ctx context.Context, txh service.Tx, id domain.SAOAuthClientID) error {
	tx := txAsPgx(txh)
	tag, err := tx.Exec(ctx, `DELETE FROM service_account_oauth_clients WHERE id = $1`, string(id))
	if err != nil {
		return mapErr(err, "SAOAuthClient.DeleteByID", string(id))
	}
	if tag.RowsAffected() == 0 {
		return iamerr.Wrapf(iamerr.ErrNotFound, "SAOAuthClient %s not found", id)
	}
	return nil
}

// TouchLastUsed — atomic update last_used_at (RETURNING для проверки exists).
func (r *SAOAuthClientRepo) TouchLastUsed(ctx context.Context, tx pgx.Tx, id domain.SAOAuthClientID, at time.Time) error {
	tag, err := tx.Exec(ctx,
		`UPDATE service_account_oauth_clients SET last_used_at = $2 WHERE id = $1`,
		string(id), at)
	if err != nil {
		return mapErr(err, "SAOAuthClient.TouchLastUsed", string(id))
	}
	if tag.RowsAffected() == 0 {
		return iamerr.Wrapf(iamerr.ErrNotFound, "SAOAuthClient %s not found", id)
	}
	return nil
}

func scanSAOAuthClient(row pgx.Row) (domain.ServiceAccountOAuthClient, error) {
	var (
		c          domain.ServiceAccountOAuthClient
		expiresAt  sql.NullTime
		lastUsedAt sql.NullTime
		tsBody     []byte
		labelsBody []byte
	)
	if err := row.Scan(
		(*string)(&c.ID), (*string)(&c.SvaID), (*string)(&c.OAuthClientID),
		(*string)(&c.Description), (*string)(&c.CreatedByUserID),
		&c.CreatedAt, &expiresAt, &lastUsedAt,
		&c.PublicKeyPEM, &c.KeyAlgorithm, &tsBody, (*string)(&c.Name), &labelsBody,
	); err != nil {
		return domain.ServiceAccountOAuthClient{}, err
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		c.ExpiresAt = &t
	}
	if lastUsedAt.Valid {
		t := lastUsedAt.Time
		c.LastUsedAt = &t
	}
	ts, err := unmarshalTrustedSubjects(tsBody)
	if err != nil {
		return domain.ServiceAccountOAuthClient{}, err
	}
	c.TrustedSubjects = ts
	labels, err := unmarshalLabels(labelsBody)
	if err != nil {
		return domain.ServiceAccountOAuthClient{}, err
	}
	c.Labels = labels
	return c, nil
}

// ───────────────────────────────────────────────────────────────────────────
