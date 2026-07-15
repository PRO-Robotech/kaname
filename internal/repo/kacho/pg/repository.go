// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package pg — pgxpool implementation of [kacho.Repository].
//
// Composition: New(master, slave) → *Repository, поддерживающий Reader/Writer.
// slave-pool опционально, при nil — fallback на master.
//
// Этот пакет — единственное место, импортирующее pgx из repo-слоя.
// Use-case'ы (`internal/apps/kacho/api/*`) видят только iface'ы из родительского
// `internal/repo/kacho`.
package pg

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	kacho "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
)

// Repository — реализация kacho.Repository поверх pgxpool.
type Repository struct {
	master *pgxpool.Pool
	slave  *pgxpool.Pool // nil = fallback на master
}

// New собирает Repository. slave может быть nil — тогда Reader-TX идут на master
// (G.4 fallback).
func New(master, slave *pgxpool.Pool) *Repository {
	return &Repository{master: master, slave: slave}
}

// Reader открывает read-only TX на slave (если есть) или master.
func (r *Repository) Reader(ctx context.Context) (kacho.Reader, error) {
	tx, err := r.readPool().BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	return &readTx{tx: tx}, nil
}

// Writer открывает read-write TX на master.
func (r *Repository) Writer(ctx context.Context) (kacho.Writer, error) {
	tx, err := r.master.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	return &writeTx{readTx: readTx{tx: tx}}, nil
}

// Close — освобождает pgxpool.
func (r *Repository) Close() {
	if r.slave != nil {
		r.slave.Close()
	}
	r.master.Close()
}

// readPool — slave если есть, иначе master.
func (r *Repository) readPool() *pgxpool.Pool {
	if r.slave != nil {
		return r.slave
	}
	return r.master
}

// Compile-time guard.
var _ kacho.Repository = (*Repository)(nil)
