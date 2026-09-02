// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// interactive_client_repo.go — pgx adapter for the InteractiveClient resource
// (IAM-INT-1). Standalone reader/writer structs wired from the composition root,
// the same shape ClusterReader / ClusterAdminGrantWriter use — this resource is
// cluster-scoped admin surface and does not belong to the tenant CQRS root.

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// interactiveClientCols — the column list every read shares, so a column added
// to one query cannot silently go missing from another.
const interactiveClientCols = `id, created_at, name, description, labels,
	redirect_uris, post_logout_redirect_uris,
	client_id, audiences, grant_types, token_endpoint_auth_method, status`

// InteractiveClientRepo — reads and writes kacho_iam.interactive_clients.
type InteractiveClientRepo struct {
	pool *pgxpool.Pool
}

// NewInteractiveClientRepo — constructor. Composition root: cmd/kacho-iam/wiring.go.
func NewInteractiveClientRepo(pool *pgxpool.Pool) *InteractiveClientRepo {
	return &InteractiveClientRepo{pool: pool}
}

// Get — direct-read lane: this is iam's OWN resource, so a well-formed id with
// no row is NOT_FOUND with the contract tone, never a peer-lane code.
func (r *InteractiveClientRepo) Get(ctx context.Context, id domain.InteractiveClientID) (domain.InteractiveClient, error) {
	const q = `SELECT ` + interactiveClientCols + ` FROM interactive_clients WHERE id = $1`
	out, err := scanInteractiveClient(r.pool.QueryRow(ctx, q, string(id)))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.InteractiveClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "InteractiveClient %s not found", id)
	}
	if err != nil {
		return domain.InteractiveClient{}, mapErr(err, "", string(id))
	}
	return out, nil
}

// List — cursor page over (created_at, id) ASC, the platform ordering.
//
// The cursor CODEC stays here, in the adapter, rather than in the use-case: it
// is a storage detail (it encodes a row's sort key), and the platform already
// keeps one implementation of it in this package. Returning the next token from
// the same place that produced the rows also removes the failure mode where a
// caller re-derives the cursor from a page it has already truncated.
//
// A malformed token is INVALID_ARGUMENT and never an empty page: the use-case
// validates the format up front so the answer does not depend on grant state,
// and this decode is the authoritative backstop behind it.
func (r *InteractiveClientRepo) List(
	ctx context.Context, limit int, pageToken, nameFilter string,
) ([]domain.InteractiveClient, string, error) {
	var (
		afterTS time.Time
		afterID string
	)
	if pageToken != "" {
		ts, id, err := decodePageToken(pageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		afterTS, afterID = ts, id
	}

	const q = `SELECT ` + interactiveClientCols + ` FROM interactive_clients
		WHERE ($3::timestamptz IS NULL OR (created_at, id) > ($3, $4))
		  AND ($2 = '' OR name = $2)
		ORDER BY created_at ASC, id ASC
		LIMIT $1`
	var after any
	if !afterTS.IsZero() {
		after = afterTS
	}
	// limit+1: "is there a next page" is answered by the data, not by comparing
	// the returned slice with the bound it was just cut to.
	rows, err := r.pool.Query(ctx, q, limit+1, nameFilter, after, afterID)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	out := make([]domain.InteractiveClient, 0, limit+1)
	for rows.Next() {
		c, err := scanInteractiveClient(rows)
		if err != nil {
			return nil, "", mapErr(err, "", "")
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", "")
	}

	var next string
	if len(out) > limit {
		out = out[:limit]
		last := out[limit-1]
		next = encodePageToken(last.CreatedAt, string(last.ID))
	}
	return out, next, nil
}

// Insert — records a client whose provider-side registration succeeded.
//
// A 23505 on interactive_clients_name_uk becomes ALREADY_EXISTS: the uniqueness
// is the database's promise, so two concurrent Creates naming one client produce
// one row and one refusal rather than a second silent winner.
func (r *InteractiveClientRepo) Insert(ctx context.Context, c domain.InteractiveClient) (domain.InteractiveClient, error) {
	labels, err := json.Marshal(nonNilLabels(c.Labels))
	if err != nil {
		return domain.InteractiveClient{}, iamerr.Wrapf(iamerr.ErrInternal, "marshal labels")
	}
	const q = `INSERT INTO interactive_clients (
			id, name, description, labels,
			redirect_uris, post_logout_redirect_uris,
			client_id, audiences, grant_types, token_endpoint_auth_method, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING ` + interactiveClientCols
	out, err := scanInteractiveClient(r.pool.QueryRow(ctx, q,
		string(c.ID), string(c.Name), string(c.Description), labels,
		nonNilStrings(c.RedirectURIs), nonNilStrings(c.PostLogoutRedirectURIs),
		c.ClientID, nonNilStrings(c.Audiences), nonNilStrings(c.GrantTypes),
		c.TokenEndpointAuthMethod, string(c.Status),
	))
	if err != nil {
		return domain.InteractiveClient{}, mapErr(err, "InteractiveClient", string(c.Name))
	}
	return out, nil
}

// Update — applies the mutable fields. The statement is a single UPDATE …
// RETURNING so the "does it still exist" question and the write are one act; a
// zero-row result is the absence, not a race we lost after checking.
func (r *InteractiveClientRepo) Update(ctx context.Context, c domain.InteractiveClient) (domain.InteractiveClient, error) {
	labels, err := json.Marshal(nonNilLabels(c.Labels))
	if err != nil {
		return domain.InteractiveClient{}, iamerr.Wrapf(iamerr.ErrInternal, "marshal labels")
	}
	const q = `UPDATE interactive_clients
		SET name = $2, description = $3, labels = $4,
		    redirect_uris = $5, post_logout_redirect_uris = $6
		WHERE id = $1
		RETURNING ` + interactiveClientCols
	out, err := scanInteractiveClient(r.pool.QueryRow(ctx, q,
		string(c.ID), string(c.Name), string(c.Description), labels,
		nonNilStrings(c.RedirectURIs), nonNilStrings(c.PostLogoutRedirectURIs),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.InteractiveClient{}, iamerr.Wrapf(iamerr.ErrNotFound, "InteractiveClient %s not found", c.ID)
	}
	if err != nil {
		return domain.InteractiveClient{}, mapErr(err, "InteractiveClient", string(c.Name))
	}
	return out, nil
}

// Delete — removes the row and reports whether one was there.
//
// The boolean exists so the use-case can be idempotent WITHOUT the repo
// pretending: deleting an absent client is a success at the RPC level (scenario
// 09), and the caller still needs to know whether a provider-side removal is
// owed. Collapsing the two here would have made "already gone" and "just
// removed" indistinguishable to the only code that must tell them apart.
func (r *InteractiveClientRepo) Delete(ctx context.Context, id domain.InteractiveClientID) (domain.InteractiveClient, bool, error) {
	const q = `DELETE FROM interactive_clients WHERE id = $1 RETURNING ` + interactiveClientCols
	out, err := scanInteractiveClient(r.pool.QueryRow(ctx, q, string(id)))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.InteractiveClient{}, false, nil
	}
	if err != nil {
		return domain.InteractiveClient{}, false, mapErr(err, "InteractiveClient.Delete", string(id))
	}
	return out, true, nil
}

func scanInteractiveClient(row pgx.Row) (domain.InteractiveClient, error) {
	var (
		c      domain.InteractiveClient
		labels []byte
	)
	if err := row.Scan(
		(*string)(&c.ID), &c.CreatedAt, (*string)(&c.Name), (*string)(&c.Description), &labels,
		&c.RedirectURIs, &c.PostLogoutRedirectURIs,
		&c.ClientID, &c.Audiences, &c.GrantTypes, &c.TokenEndpointAuthMethod,
		(*string)(&c.Status),
	); err != nil {
		return domain.InteractiveClient{}, err
	}
	if len(labels) > 0 {
		m := domain.Labels{}
		if err := json.Unmarshal(labels, &m); err != nil {
			return domain.InteractiveClient{}, err
		}
		c.Labels = m
	}
	return c, nil
}

// nonNilStrings — pgx encodes a nil slice as NULL, and the columns are NOT NULL.
// An empty list is a legitimate value (no post-logout targets); NULL is not.
//
// The candidate narrowing of the visible-page lists (#645) uses it for the other
// direction — a `= ANY($N)` predicate. There `x = ANY(NULL)` is NULL, which a
// WHERE clause drops, so a nil slice would already refuse every row; that is the
// answer wanted, but it would be right by accident of three-valued logic. Passing
// an EMPTY array says the same thing on purpose: a set that contains nothing.
func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func nonNilLabels(l domain.Labels) domain.Labels {
	if l == nil {
		return domain.Labels{}
	}
	return l
}
