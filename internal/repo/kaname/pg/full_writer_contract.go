// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/authorityprotocol"
)

// FullWriterContract is a validated startup selection, not a policy allow result.
// A repository without it retains v2, including in an already running process.
type FullWriterContract struct {
	profile *authorityprotocol.FullContract
}

func NewFullWriterContract(ctx context.Context, repo *Repository, bundle *granteffect.Bundle) (*FullWriterContract, error) {
	return newFullWriterContract(ctx, repo, bundle, 0, "")
}

// NewPublishedFullWriterContract связывает выбранную семантику с редакцией.
func NewPublishedFullWriterContract(ctx context.Context, repo *Repository, publication PublicationAuthorityBundle) (*FullWriterContract, error) {
	if publication.Revision <= 0 || publication.Bundle.Validate() != nil ||
		publication.CatalogID != publication.Bundle.Identity().CatalogID {
		return nil, kaname.ErrSourceUnconfirmed
	}
	return newFullWriterContract(ctx, repo, publication.Bundle, publication.Revision, publication.Digest)
}

func newFullWriterContract(ctx context.Context, repo *Repository, bundle *granteffect.Bundle, revision int64, digest string) (*FullWriterContract, error) {
	if repo == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	if err := repo.ValidateAuthorityRuntime(ctx); err != nil {
		return nil, err
	}
	id := bundle.Identity()
	var profile *authorityprotocol.FullContract
	var err error
	if revision == 0 {
		profile, err = authorityprotocol.NewFullContract(ctx, repo.master, id.ModelID, id.CatalogID, id.ProjectorVersion)
	} else {
		profile, err = authorityprotocol.NewPublishedFullContract(ctx, repo.master, id.ModelID, id.CatalogID, id.ProjectorVersion, revision, digest)
	}
	if err != nil {
		return nil, err
	}
	return &FullWriterContract{profile: profile}, nil
}
func (r *Repository) WithFullWriterContract(contract *FullWriterContract) (*Repository, error) {
	if r == nil || contract == nil || !contract.profile.UsesPool(r.master) {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	copy := *r
	copy.fullContract = contract
	return &copy, nil
}
func (c *FullWriterContract) Context(ctx context.Context) context.Context {
	if c == nil {
		return (*authorityprotocol.FullContract)(nil).Context(ctx)
	}
	return c.profile.Context(ctx)
}
func (r *Repository) fullContractMatches(bundle *granteffect.Bundle) bool {
	if r == nil || r.fullContract == nil || bundle.Validate() != nil {
		return false
	}
	id := bundle.Identity()
	return r.fullContract.profile.Matches(r.master, id.ModelID, id.CatalogID, id.ProjectorVersion)
}
func (r *Repository) ValidateStagedWriterContract(ctx context.Context) error {
	if r == nil || r.master == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	var valid bool
	if err := r.master.QueryRow(ctx, `SELECT kaname.authority_staged_contract_validate_v3()`).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return kaname.ErrSemanticIdentityUnavailable
	}
	return ctx.Err()
}
func (r *Repository) ValidateFullAuthorityBundle(ctx context.Context, bundle *granteffect.Bundle) error {
	if r == nil || bundle.Validate() != nil {
		return kaname.ErrSemanticIdentityUnavailable
	}
	id := bundle.Identity()
	return authorityprotocol.ValidateFullIdentity(ctx, r.master, id.ModelID, id.CatalogID, id.ProjectorVersion)
}
