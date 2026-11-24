// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgxpool"
)

type publishedStartupProfile struct {
	store    *authzsnapshot.Store
	snapshot *authzsnapshot.Snapshot
	halves   catalog.Halves
	rows     publishedCatalogSource
	poll     time.Duration
	writers  *publishedWriterGenerations
}

func preparePublishedFullStartup(ctx context.Context, pool *pgxpool.Pool, repository *kanamepg.Repository) (context.Context, *fullStartupProfile, error) {
	source := kanamepg.NewCatalogRepo(pool)
	window := catalogSnapshotRefreshPeriod()
	store, err := preparePublishedAuthorization(ctx, source, window/3, window)
	if err != nil {
		return ctx, nil, err
	}
	writers := newPublishedWriterGenerations(pool, repository, store)
	_, generation, err := writers.resolve(ctx)
	if err != nil {
		return ctx, nil, err
	}
	var halves catalog.Halves
	if err := json.Unmarshal(generation.bundle.CanonicalCatalog(), &halves); err != nil {
		return ctx, nil, fmt.Errorf("прочитать каталог принятой редакции: %w", err)
	}
	return generation.contract.Context(ctx), &fullStartupProfile{
		contract: generation.contract,
		primary:  generation.repo,
		bundle:   generation.bundle,
		model:    preparedModel{text: generation.bundle.ModelSource(), plans: generation.snapshot.Plans},
		publication: &publishedStartupProfile{
			store: store, snapshot: generation.snapshot, halves: halves, poll: window / 3, writers: writers,
			rows: publishedCatalogSource{store: store, repo: source},
		},
	}, nil
}

// publishedCatalogSource отдаёт обычным читателям только строки, совпавшие
// с подтверждённой редакцией. Pending-запись не обновляет их каталог.
type publishedCatalogSource struct {
	store *authzsnapshot.Store
	repo  *kanamepg.CatalogRepo
}

func (s publishedCatalogSource) ReadCatalogHalves(ctx context.Context) (catalog.Halves, error) {
	pinned, err := s.store.Pin(ctx)
	if err != nil {
		return catalog.Halves{}, err
	}
	snapshot, _ := authzsnapshot.FromContext(pinned)
	halves, err := s.repo.ReadCatalogHalves(pinned)
	if err != nil {
		return catalog.Halves{}, err
	}
	canonical, err := catalog.CanonicalJSON(halves)
	if err != nil {
		return catalog.Halves{}, err
	}
	if fmt.Sprintf("%x", sha256.Sum256(canonical)) != snapshot.CatalogID {
		return catalog.Halves{}, authzsnapshot.ErrUnconfirmed
	}
	if _, err := s.repo.ConfirmActivePublication(pinned, snapshot); err != nil {
		return catalog.Halves{}, err
	}
	return halves, s.store.ConfirmPin(pinned)
}
