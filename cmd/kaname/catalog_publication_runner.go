// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	clusterapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/cluster"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5/pgxpool"
)

// publishedWriterGenerations выбирает неделимое поколение до входа в операцию.
// Выбранные участники остаются неизменными до commit или rollback.
type publishedWriterGenerations struct {
	pool     *pgxpool.Pool
	rolePool *pgxpool.Pool
	repo     *kanamepg.Repository
	store    *authzsnapshot.Store

	mu           sync.Mutex
	current      *publishedWriterGeneration
	resourceGate *authzguard.RelationWriteGate
}

type publishedWriterGeneration struct {
	snapshot      *authzsnapshot.Snapshot
	contract      *kanamepg.FullWriterContract
	repo          *kanamepg.Repository
	bundle        *granteffect.Bundle
	catalog       *kanamepg.CatalogWriteRepo
	cluster       *kanamepg.ClusterAdminParticipant
	invites       *kanamepg.InviteDecisions
	policy        *publishedPolicyParticipants
	metadata      *kanamepg.MetadataMutationWriters
	metadataPorts publishedMetadataPorts
	groupLabels   kaname.GroupAccessLabelsWriterFactory
	roles         publishedRoleWriters
	userLabels    kaname.UserAccessLabelsWriter
	state         *kanamepg.ServiceAccountStateWriters
	crud          *kanamepg.CRUDWriters
	admission     *kanamepg.HumanAdmissionParticipant
	groups        *reconcile.Reconciler
	resource      *kanamepg.ResourceDecisionRunner
}

func newPublishedWriterGenerations(pool *pgxpool.Pool, repo *kanamepg.Repository, store *authzsnapshot.Store) *publishedWriterGenerations {
	return &publishedWriterGenerations{pool: pool, repo: repo, store: store}
}

func (r *publishedWriterGenerations) RunInCatalogPublicationTx(ctx context.Context, fn func(context.Context, modulecatalog.CatalogPublicationWriter) error) error {
	pinned, generation, err := r.resolve(ctx)
	if err == nil {
		err = generation.catalog.RunInCatalogPublicationTx(pinned, fn)
	}
	if errors.Is(err, kaname.ErrSourceUnconfirmed) || errors.Is(err, kaname.ErrSemanticIdentityUnavailable) {
		return authzsnapshot.ErrUnconfirmed
	}
	return err
}

func (r *publishedWriterGenerations) resolve(ctx context.Context) (context.Context, *publishedWriterGeneration, error) {
	if err := ctx.Err(); err != nil {
		return ctx, nil, err
	}
	var err error
	if _, ok := authzsnapshot.FromContext(ctx); ok {
		err = r.store.ConfirmPin(ctx)
	} else {
		var pinned context.Context
		pinned, err = r.store.Pin(ctx)
		if err == nil {
			ctx = pinned
		}
	}
	if err != nil {
		return ctx, nil, errors.Join(iamerr.ErrUnavailable, err)
	}
	snapshot, _ := authzsnapshot.FromContext(ctx)
	generation, err := r.generationFor(ctx, snapshot)
	if errors.Is(err, kaname.ErrSourceUnconfirmed) || errors.Is(err, kaname.ErrSemanticIdentityUnavailable) ||
		errors.Is(err, authzsnapshot.ErrUnconfirmed) {
		return ctx, nil, errors.Join(iamerr.ErrUnavailable, err)
	}
	return ctx, generation, err
}

func (r *publishedWriterGenerations) generationFor(ctx context.Context, snapshot *authzsnapshot.Snapshot) (*publishedWriterGeneration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if current := r.current; current != nil {
		if snapshot.Revision < current.snapshot.Revision {
			return nil, errors.Join(iamerr.ErrUnavailable, authzsnapshot.ErrUnconfirmed)
		}
		if snapshot.Revision == current.snapshot.Revision {
			if snapshot.Digest != current.snapshot.Digest || snapshot.CatalogID != current.snapshot.CatalogID {
				return nil, errors.Join(iamerr.ErrUnavailable, authzsnapshot.ErrUnconfirmed)
			}
			if err := r.store.ConfirmPin(ctx); err != nil {
				return nil, errors.Join(iamerr.ErrUnavailable, err)
			}
			return current, nil
		}
	}
	publication, err := r.repo.LoadPublicationAuthorityBundle(ctx)
	if err != nil {
		return nil, err
	}
	if publication.Revision != snapshot.Revision || publication.Digest != snapshot.Digest ||
		publication.CatalogID != snapshot.CatalogID {
		return nil, errors.Join(iamerr.ErrUnavailable, authzsnapshot.ErrUnconfirmed)
	}
	contract, err := kanamepg.NewPublishedFullWriterContract(ctx, r.repo, publication)
	if err != nil {
		return nil, err
	}
	repo, err := r.repo.WithFullWriterContract(contract)
	if err != nil {
		return nil, err
	}
	catalog, err := kanamepg.NewCatalogWriteRepo(r.pool).WithFullWriterContract(contract)
	if err != nil {
		return nil, err
	}
	cluster, err := kanamepg.NewClusterAdminParticipant(ctx, repo, publication.Bundle)
	if err != nil {
		return nil, err
	}
	invites, err := kanamepg.NewInviteDecisionRunner(ctx, repo, publication.Bundle)
	if err != nil {
		return nil, err
	}
	policy, err := newPublishedPolicyParticipants(ctx, repo, publication.Bundle)
	if err != nil {
		return nil, err
	}
	metadata, err := kanamepg.NewMetadataMutationWriters(ctx, repo, publication.Bundle)
	if err != nil {
		return nil, err
	}
	var roles publishedRoleWriters = policy.writers
	var userLabels kaname.UserAccessLabelsWriter
	if r.rolePool != nil {
		roleRepo := kanamepg.New(r.rolePool, nil)
		roleContract, err := kanamepg.NewPublishedFullWriterContract(ctx, roleRepo, publication)
		if err != nil {
			return nil, err
		}
		roleRepo, err = roleRepo.WithFullWriterContract(roleContract)
		if err != nil {
			return nil, err
		}
		roleWriters, err := kanamepg.NewRolePolicyWriters(ctx, repo, roleRepo, publication.Bundle)
		if err != nil {
			return nil, err
		}
		roles = roleWriters
		userLabels, err = roleWriters.InstalledUserAccessLabels(ctx)
		if err != nil {
			return nil, err
		}
	}
	metadataPorts, err := metadata.WithInstalledAccessLabels(ctx)
	if err != nil {
		return nil, err
	}
	groupLabels, err := metadata.WithInstalledGroupAccessLabels(ctx)
	if err != nil {
		return nil, err
	}
	state, err := kanamepg.NewServiceAccountStateWriters(ctx, repo, publication.Bundle)
	if err != nil {
		return nil, err
	}
	crud, err := kanamepg.NewCRUDWriters(ctx, repo, publication.Bundle)
	if err != nil {
		return nil, err
	}
	admission, err := kanamepg.NewHumanAdmissionParticipant(ctx, repo, publication.Bundle)
	if err != nil {
		return nil, err
	}
	groups, err := policy.membership.NewGroupObjectReconciler(slog.Default())
	if err != nil {
		return nil, err
	}
	var resource *kanamepg.ResourceDecisionRunner
	if r.resourceGate != nil {
		resource, err = kanamepg.NewResourceDecisionRunner(ctx, repo, publication.Bundle, r.resourceGate)
		if err != nil {
			return nil, err
		}
	}
	if err := r.store.ConfirmPin(ctx); err != nil {
		return nil, errors.Join(iamerr.ErrUnavailable, err)
	}
	generation := &publishedWriterGeneration{
		snapshot: snapshot, contract: contract, repo: repo, bundle: publication.Bundle,
		catalog: catalog, cluster: cluster, invites: invites, policy: policy,
		metadata: metadata, metadataPorts: metadataPorts, groupLabels: groupLabels, roles: roles, userLabels: userLabels, state: state, crud: crud, admission: admission, groups: groups, resource: resource,
	}
	r.current = generation
	return generation, nil
}

func (r *publishedWriterGenerations) Begin(ctx context.Context) (service.Tx, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.cluster.Begin(pinned)
}

func (r *publishedWriterGenerations) RunAdminDecision(ctx context.Context, in clusterapp.AdminDecisionIntent,
	body func(context.Context, service.Tx) (domain.ClusterAdminGrant, error),
) (domain.ClusterAdminGrant, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return domain.ClusterAdminGrant{}, err
	}
	return generation.cluster.RunAdminDecision(pinned, in, body)
}

func (r *publishedWriterGenerations) RunInviteDecision(ctx context.Context, in kaname.InviteDecisionIntent,
	body func(context.Context, kaname.InviteMutationWriter, kaname.PreparedInvite) error,
) error {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return err
	}
	return generation.invites.RunInviteDecision(pinned, in, body)
}

var (
	_ modulecatalog.CatalogPublicationTxRunner = (*publishedWriterGenerations)(nil)
	_ service.TxBeginner                       = (*publishedWriterGenerations)(nil)
	_ clusterapp.AdminDecisionRunner           = (*publishedWriterGenerations)(nil)
	_ kaname.InviteDecisionRunner              = (*publishedWriterGenerations)(nil)
)
