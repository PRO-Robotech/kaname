// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// InstallationReadFactory opens real primary database read transactions. Keeping
// the transaction boundary explicit permits callers to add deadline/telemetry/fault
// decorators without changing canonical snapshot or membership semantics.
type InstallationReadFactory interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

type InstallationPageFactory interface {
	BeginTx(context.Context, pgx.Tx, pgx.TxOptions) (pgx.Tx, error)
}

// NestedInstallationPages opens real savepoint scopes on the existing read-only,
// repeatable-read transaction; incompatible options are refused, never ignored.
type NestedInstallationPages struct{}

func (NestedInstallationPages) BeginTx(ctx context.Context, tx pgx.Tx, options pgx.TxOptions) (pgx.Tx, error) {
	if options != (pgx.TxOptions{AccessMode: pgx.ReadOnly, IsoLevel: pgx.RepeatableRead}) {
		return nil, fmt.Errorf("installation page requires read-only repeatable-read scope")
	}
	return tx.Begin(ctx)
}

type InstallationReader struct {
	factory InstallationReadFactory
	pages   InstallationPageFactory
}

func NewInstallationReader(factory InstallationReadFactory) *InstallationReader {
	return &InstallationReader{factory: factory, pages: NestedInstallationPages{}}
}

// WithPageFactory decorates real nested transaction creation without replacing
// canonical page SQL or membership. It does not create another connection.
func (r *InstallationReader) WithPageFactory(pages InstallationPageFactory) *InstallationReader {
	return &InstallationReader{factory: r.factory, pages: pages}
}

// InstallationAccounts captures complete canonical membership on the primary in
// one repeatable-read snapshot. Pages are ordered by ID and never caller-filtered.
func (r *InstallationReader) InstallationAccounts(ctx context.Context, target string, pageSize int) ([]domain.AccountID, domain.AccountID, error) {
	if pageSize < 1 {
		return nil, "", fmt.Errorf("installation account page size must be positive")
	}
	tx, err := r.factory.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly, IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback(ctx)
	sys, err := (moduleSeedWriter{tx: tx}).accountID(ctx, domain.SystemAccountName)
	if err != nil {
		return nil, "", err
	}
	if target == sys {
		return nil, "", status.Error(codes.InvalidArgument, "installation target account cannot be system")
	}
	if target != "" {
		account, err := (&accountReader{tx: tx}).Get(ctx, domain.AccountID(target))
		if err != nil {
			return nil, "", err
		}
		return []domain.AccountID{account.ID}, domain.AccountID(sys), nil
	}
	// All page scopes share this real repeatable-read membership snapshot.
	var ids []domain.AccountID
	after := ""
	for {
		page, err := r.installationAccountPage(ctx, tx, after, pageSize)
		if err != nil {
			return nil, "", err
		}
		for _, id := range page {
			after = string(id)
			if string(id) != sys && (target == "" || target == string(id)) {
				ids = append(ids, id)
			}
		}
		if len(page) < pageSize {
			break
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return ids, domain.AccountID(sys), nil
}

// InstallationReferences resolves the SAME seed identity spelling window and
// cluster role names used by the ordinary seed writer. It never creates identities.
func (r *InstallationReader) InstallationReferences(ctx context.Context, account, name string, roles []string) (domain.ServiceAccountID, []string, error) {
	tx, err := r.factory.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback(ctx)
	seed := moduleSeedWriter{tx: tx}
	delegate, err := seed.serviceAccountID(ctx, account, name)
	if err != nil {
		return "", nil, err
	}
	ids := make([]string, 0, len(roles))
	for _, name := range roles {
		id, err := seed.clusterRoleID(ctx, name)
		if err != nil {
			return "", nil, err
		}
		ids = append(ids, id)
	}
	return domain.ServiceAccountID(delegate), ids, nil
}

func (r *InstallationReader) installationAccountPage(ctx context.Context, coordinator pgx.Tx, after string, pageSize int) ([]domain.AccountID, error) {
	if r.pages == nil {
		return nil, fmt.Errorf("installation page factory is not wired")
	}
	tx, err := r.pages.BeginTx(ctx, coordinator, pgx.TxOptions{AccessMode: pgx.ReadOnly, IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id FROM kaname.accounts WHERE id > $1 ORDER BY id LIMIT $2`, after, pageSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []domain.AccountID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, domain.AccountID(id))
	}
	return ids, rows.Err()
}
