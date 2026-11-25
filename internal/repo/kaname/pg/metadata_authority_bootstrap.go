// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

// Для первичной подготовки нужен пустой owner handoff и исходный контракт.
// Уже отозванная identity никогда не считается пустой установкой.
const metadataBootstrapStateSQL = `
	SELECT c.required_contract=1 AND c.staged_contract=1,
	       p.enforcement='compatibility' AND p.protocol_version=1
	       AND a.phase='uninitialized' AND a.protocol_version=0
	       AND a.model_id IS NULL AND a.catalog_id IS NULL AND a.projector_version IS NULL
	       AND NOT EXISTS (SELECT 1 FROM kaname.authority_bundle_handoff WHERE singleton)
	FROM kaname.authority_writer_contract c
	CROSS JOIN kaname.authority_writer_protocol p
	CROSS JOIN kaname.authority_semantic_identity a
	WHERE c.singleton AND p.singleton AND a.singleton`

type metadataBootstrapQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func metadataBootstrapState(ctx context.Context, q metadataBootstrapQueryer) (generationOne, initial bool, err error) {
	err = q.QueryRow(ctx, metadataBootstrapStateSQL).Scan(&generationOne, &initial)
	return
}

// MetadataAuthorityUninitialized подсказывает owner-команде, нужно ли
// применять каталог. Право на запись проверяется снова внутри транзакции.
func (r *Repository) MetadataAuthorityUninitialized(ctx context.Context) (bool, error) {
	genOne, initial, err := metadataBootstrapState(ctx, r.master)
	return genOne && initial, err
}

func metadataBootstrapRuntime(ctx context.Context, q metadataBootstrapQueryer, role string) (uint32, error) {
	var oid uint32
	err := q.QueryRow(ctx, `
		SELECT u.oid FROM pg_catalog.pg_roles u
		WHERE u.rolname=$1 AND u.rolcanlogin AND u.rolname<>current_user
		AND NOT (u.rolsuper OR u.rolcreatedb OR u.rolcreaterole OR u.rolreplication OR u.rolbypassrls OR u.rolinherit)
		AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=u.oid)`, role).Scan(&oid)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("metadata authority bootstrap: %w: требуется отдельный существующий runtime LOGIN", kaname.ErrSemanticIdentityUnavailable)
	}
	return oid, err
}

// ValidateMetadataBootstrapRuntime отказывает до применения initial catalog,
// если целевой LOGIN отсутствует или не отделён от migration owner.
func (r *Repository) ValidateMetadataBootstrapRuntime(ctx context.Context, role string) error {
	_, err := metadataBootstrapRuntime(ctx, r.master, role)
	return err
}

// BootstrapMetadataAuthority фиксирует первую модель поколения 1 и штатные
// ACL одного указанного LOGIN в той же owner-транзакции. Результат true
// означает создание handoff. Точное уже установленное состояние переиспользуется.
func (r *Repository) BootstrapMetadataAuthority(ctx context.Context, b *granteffect.Bundle, role string, editions ...kaname.AuthorityModuleEdition) (bool, error) {
	if err := b.Validate(); err != nil {
		return false, err
	}
	id := b.Identity()
	editions = append([]kaname.AuthorityModuleEdition(nil), editions...)
	created := false
	err := r.authorityLifecycle(ctx, func(ctx context.Context, tx pgx.Tx) error {
		created = false
		genOne, initial, err := metadataBootstrapState(ctx, tx)
		if err != nil {
			return err
		}
		if !genOne {
			return kaname.ErrSemanticIdentityUnavailable
		}
		if !initial {
			var same bool
			// read_bundle требует совместимую пару phase/enforcement и
			// согласованные identity/handoff, включая установленное strict.
			err = tx.QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM kaname.authority_protocol_read_bundle() r
				WHERE r.model_source=$1 AND r.catalog_json=$2
				  AND (r.model_id,r.catalog_id,r.projector_version)=($3,$4,$5))`,
				b.ModelSource(), b.CanonicalCatalog(), id.ModelID, id.CatalogID, id.ProjectorVersion).Scan(&same)
			if err != nil {
				return err
			}
			if !same {
				return kaname.ErrSemanticIdentityUnavailable
			}
		}
		if err := authorityCatalogMatches(ctx, tx, b); err != nil {
			return err
		}
		if err := authorityEditionsMatch(ctx, tx, editions); err != nil {
			return err
		}
		oid, err := metadataBootstrapRuntime(ctx, tx, role)
		if err != nil {
			return err
		}
		if initial {
			if _, err := tx.Exec(ctx, `SELECT kaname.authority_protocol_stage($1,$2,$3,$4,$5)`,
				b.ModelSource(), b.CanonicalCatalog(), id.ModelID, id.CatalogID, id.ProjectorVersion); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `SELECT kaname.authority_protocol_grant_runtime($1::oid::regrole)`, oid); err != nil {
			return err
		}
		created = initial
		return nil
	})
	return err == nil && created, err
}
