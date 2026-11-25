// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package authorityprotocol

import (
	"context"
	"errors"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FullContract is immutable and bound to one runtime pool and semantic identity.
// Context propagation selects code, never DB authority: every entry revalidates it.
type FullContract struct {
	pool                      *pgxpool.Pool
	model, catalog, projector string
	revision                  int64
	digest                    string
	enrolledPublicationCheck  bool
}
type fullContractContextKey struct{}

func NewFullContract(ctx context.Context, pool *pgxpool.Pool, model, catalog, projector string) (*FullContract, error) {
	return newFullContract(ctx, pool, model, catalog, projector, 0, "")
}

// NewPublishedFullContract закрепляет редакцию модели за всеми входами писателя.
func NewPublishedFullContract(ctx context.Context, pool *pgxpool.Pool, model, catalog, projector string, revision int64, digest string) (*FullContract, error) {
	if revision <= 0 || digest != "sha256:"+model {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	return newFullContract(ctx, pool, model, catalog, projector, revision, digest)
}

func newFullContract(ctx context.Context, pool *pgxpool.Pool, model, catalog, projector string, revision int64, digest string) (*FullContract, error) {
	if err := ValidateFullIdentity(ctx, pool, model, catalog, projector); err != nil {
		return nil, err
	}
	c := &FullContract{pool: pool, model: model, catalog: catalog, projector: projector, revision: revision, digest: digest}
	// Выбираем путь на этом пуле по прямой выдаче EXECUTE владельцем. Сам
	// предикат повторно подтверждает LOGIN и редакцию после каждого барьера.
	if err := pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT FROM pg_catalog.pg_proc p
		CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) acl
		JOIN pg_catalog.pg_roles login ON login.oid=acl.grantee
		WHERE p.oid=pg_catalog.to_regprocedure('kaname.authority_role_actor_publication_matches_v1(bigint,text,text)')
			AND login.rolname=session_user AND login.oid<>p.proowner AND acl.privilege_type='EXECUTE'
	)`).Scan(&c.enrolledPublicationCheck); err != nil {
		return nil, errors.Join(kaname.ErrSourceUnconfirmed, err)
	}
	if err := c.confirmPublication(ctx, pool.QueryRow); err != nil {
		return nil, err
	}
	return c, nil
}

// ValidateFullIdentity проверяет готовность базы для указанной семантики.
// Выбор писателя дополнительно закрепляет редакцию в конструкторе.
func ValidateFullIdentity(ctx context.Context, pool *pgxpool.Pool, model, catalog, projector string) error {
	if pool == nil || model == "" || catalog == "" || projector == "" {
		return kaname.ErrSemanticIdentityUnavailable
	}
	var ready bool
	if err := pool.QueryRow(ctx, `SELECT kaname.authority_full_contract_validate_v3($1,$2,$3)`, model, catalog, projector).Scan(&ready); err != nil {
		return err
	}
	if !ready {
		return kaname.ErrSemanticIdentityUnavailable
	}
	return ctx.Err()
}

// ConfirmPublication вызывается после получения барьера и до операций записи.
// Отдельный SELECT видит фиксацию публикации, завершившуюся до получения барьера.
func (c *FullContract) ConfirmPublication(ctx context.Context, tx pgx.Tx) error {
	if err := c.confirmPublication(ctx, tx.QueryRow); err != nil {
		return errors.Join(iamerr.ErrUnavailable, err)
	}
	return nil
}

func (c *FullContract) confirmPublication(ctx context.Context, query func(context.Context, string, ...any) pgx.Row) error {
	var same bool
	confirmation := `
		SELECT NOT pg_is_in_recovery() AND COALESCE((
			SELECT revision = $1 AND digest = $2 AND catalog_id = $3
			FROM kaname.publication_model_revision
			ORDER BY revision DESC LIMIT 1
		), $1 = 0)
	`
	if c.enrolledPublicationCheck {
		confirmation = `SELECT kaname.authority_role_actor_publication_matches_v1($1::bigint,$2::text,$3::text)`
	}
	err := query(ctx, confirmation, c.revision, c.digest, c.catalog).Scan(&same)
	if err != nil {
		return errors.Join(kaname.ErrSourceUnconfirmed, err)
	}
	if !same {
		return kaname.ErrSourceUnconfirmed
	}
	return ctx.Err()
}

func (c *FullContract) Matches(pool *pgxpool.Pool, model, catalog, projector string) bool {
	return c != nil && c.pool == pool && c.model == model && c.catalog == catalog && c.projector == projector
}

// MatchesPublication устанавливает, относится ли снимок к выбранному писателю.
func (c *FullContract) MatchesPublication(revision int64, digest string) bool {
	return c != nil && c.revision == revision && c.digest == digest
}

func (c *FullContract) UsesPool(pool *pgxpool.Pool) bool { return c != nil && c.pool == pool }
func (c *FullContract) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, fullContractContextKey{}, c)
}
func contractFromContext(ctx context.Context) (*FullContract, bool) {
	c, present := ctx.Value(fullContractContextKey{}).(*FullContract)
	return c, present
}
