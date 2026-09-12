// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// assertion_admission_calls_injection_test.go — доказательство, что
// TestAssertionAdmissionIsASingleDatabaseCall способен упасть, и падает он на
// существе, а не на форме.
package check_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const admissionInjectedCheckThenAct = `package pg

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type ClientAssertionReplayRepo struct {
	pool    *pgxpool.Pool
	metrics *counter
}

func (r *ClientAssertionReplayRepo) Redeem(ctx context.Context, clientID, assertionID string, expiresAt time.Time) error {
	var seen bool
	if err := r.pool.QueryRow(ctx, ` + "`SELECT true FROM t WHERE id=$1`" + `, assertionID).Scan(&seen); err != nil {
		return err
	}
	if seen {
		return errReplayed
	}
	_, err := r.pool.Exec(ctx, ` + "`INSERT INTO t VALUES ($1)`" + `, assertionID)
	return err
}

func (r *ClientAssertionReplayRepo) Reap(ctx context.Context, now time.Time) (int64, error) {
	tag, err := r.pool.Exec(ctx, ` + "`DELETE FROM t WHERE expires_at <= $1`" + `, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
`

const admissionInjectedLawfulPair = `package pg

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type ClientAssertionReplayRepo struct {
	pool    *pgxpool.Pool
	metrics *counter
}

func (r *ClientAssertionReplayRepo) Redeem(ctx context.Context, clientID, assertionID string, expiresAt time.Time) error {
	if clientID == "" {
		return errNoClient
	}
	tag, err := r.pool.Exec(ctx, ` + "`INSERT INTO t VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`" + `, clientID, assertionID, expiresAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errReplayed
	}
	return nil
}

func (r *ClientAssertionReplayRepo) Reap(ctx context.Context, now time.Time) (int64, error) {
	tag, err := r.pool.Exec(ctx, ` + "`DELETE FROM t WHERE expires_at <= $1`" + `, now)
	if err != nil {
		return 0, err
	}
	var left int64
	if err := r.pool.QueryRow(ctx, ` + "`SELECT count(*) FROM t`" + `).Scan(&left); err != nil {
		return 0, err
	}
	_ = left
	return tag.RowsAffected(), nil
}

func (r *ClientAssertionReplayRepo) Observe(ctx context.Context) {
	r.metrics.Exec(ctx)
	_ = strings.QueryRow("noop")
}
`

// TestAdmissionScannerFindsTheReturnedCheckThenAct — сторона (а): внесённый
// дефект становится находкой, и она указывает на ДОПУСК, а не на сборщика.
func TestAdmissionScannerFindsTheReturnedCheckThenAct(t *testing.T) {
	t.Parallel()
	byFunc, census, err := check.ScanDatabaseCallsByFunction(
		"synthetic/pg/replay.go", []byte(admissionInjectedCheckThenAct))
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if census.Functions == 0 {
		t.Fatalf("осмотрено ноль функций — разбирается не то дерево")
	}

	redeem, ok := byFunc["ClientAssertionReplayRepo.Redeem"]
	if !ok {
		t.Fatalf("допуск не найден разбором; найдено: %v", check.SortedFuncNames(byFunc))
	}
	if len(redeem.Calls) != 2 {
		t.Fatalf("вызовов к базе у допуска насчитано %d, ожидалось 2: %+v", len(redeem.Calls), redeem.Calls)
	}
	if redeem.Calls[0].Line == redeem.Calls[1].Line {
		t.Errorf("оба вызова на одной строке (%d)", redeem.Calls[0].Line)
	}
	if len(redeem.Calls) == assertionAdmissionCallBudget {
		t.Fatalf("гейт на этом дефекте остался бы зелёным")
	}
}

// TestAdmissionScannerIsSilentOnTheReaper — сторона (б): законный близнец.
func TestAdmissionScannerIsSilentOnTheReaper(t *testing.T) {
	t.Parallel()
	byFunc, census, err := check.ScanDatabaseCallsByFunction(
		"synthetic/pg/replay.go", []byte(admissionInjectedLawfulPair))
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if census.Functions < 3 {
		t.Fatalf("осмотрено функций %d — разбирается не то дерево", census.Functions)
	}

	redeem, ok := byFunc["ClientAssertionReplayRepo.Redeem"]
	if !ok {
		t.Fatalf("допуск не найден разбором; найдено: %v", check.SortedFuncNames(byFunc))
	}
	if len(redeem.Calls) != assertionAdmissionCallBudget {
		t.Fatalf("у законного допуска насчитано %d вызовов при бюджете %d — гейт краснел бы "+
			"на исправной реализации: %+v", len(redeem.Calls), assertionAdmissionCallBudget, redeem.Calls)
	}

	reap, ok := byFunc["ClientAssertionReplayRepo.Reap"]
	if !ok {
		t.Fatalf("сборщик не найден разбором; найдено: %v", check.SortedFuncNames(byFunc))
	}
	if len(reap.Calls) != 2 {
		t.Fatalf("у двухвызовного сборщика насчитано %d вызовов, ожидалось 2", len(reap.Calls))
	}

	observe, ok := byFunc["ClientAssertionReplayRepo.Observe"]
	if !ok {
		t.Fatalf("соседняя функция не найдена разбором; найдено: %v", check.SortedFuncNames(byFunc))
	}
	if len(observe.Calls) != 0 {
		t.Fatalf("разбор объявил вызовом к базе чужой одноимённый метод/функцию: %+v", observe.Calls)
	}
}
