// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Дублёр задаёт состояния installation строк, но не ответ native авторизации.
// SQL-форму и настоящую выдачу проверяют отдельные PG сценарии полного runner.
type resourceInstallationRow struct {
	binding, state        string
	eligible, unsupported bool
	rows                  int
	err                   error
}

func (r resourceInstallationRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*string) = r.binding
	*dest[1].(*string) = r.state
	*dest[2].(*bool) = r.eligible
	*dest[3].(*int) = r.rows
	*dest[4].(*bool) = r.unsupported
	return nil
}

type resourceInstallationTx struct {
	pgx.Tx
	conn    *pgx.Conn
	records map[string]resourceInstallationRow
	keys    []string
	at      []time.Time
}

func (t *resourceInstallationTx) Conn() *pgx.Conn { return t.conn }
func (t *resourceInstallationTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if ctx.Err() != nil {
		return resourceInstallationRow{err: ctx.Err()}
	}
	if sql != resourceInstallationWitnessSQL || len(args) != 5 {
		return resourceInstallationRow{err: errors.New("unexpected installation SQL")}
	}
	key := args[2].(string)
	t.keys = append(t.keys, key)
	t.at = append(t.at, args[4].(time.Time))
	row, ok := t.records[key]
	if !ok {
		return resourceInstallationRow{err: pgx.ErrNoRows}
	}
	return row
}
func resourceInstallationFixture(t *testing.T) (*resourceInstallationCapture, *authorityWriteTx, *resourceInstallationTx) {
	t.Helper()
	raw := &resourceInstallationTx{conn: new(pgx.Conn), records: map[string]resourceInstallationRow{
		"assignment-a": {binding: "binding-a", state: "version-1", eligible: true, rows: 3},
	}}
	lifetime, err := newResourceAttemptLifetime(raw.conn, nativeBoundaryBundle(t))
	require.NoError(t, err)
	writer := &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: raw}}, fence: authorityFence{decisionAt: time.Now().UTC()}}
	require.NoError(t, lifetime.bind(writer))
	capture := &resourceInstallationCapture{lifetime: lifetime, bundle: lifetime.bundle, serviceName: "vpc", actor: "module-vpc",
		accounts: []domain.AccountID{"a"}, sources: map[domain.AccountID][]resourceInstallationWitness{"a": {{assignment: "assignment-a", binding: "binding-a", state: "version-1"}}}, budget: &relverdict.AdministrativeReadBudget{}}
	return capture, writer, raw
}

func TestResourceInstallationCurrentUsesOnlyCapturedKeysAndFinalClock(t *testing.T) {
	capture, writer, raw := resourceInstallationFixture(t)
	raw.records["new-foreign-assignment"] = resourceInstallationRow{binding: "new-binding", state: "new-version", eligible: true}
	ok, err := capture.current(context.Background(), writer, "a")
	require.NoError(t, err)
	require.True(t, ok, "проверяется только installation источник, не разрешение native")
	require.Equal(t, []string{"assignment-a"}, raw.keys)
	require.Equal(t, []time.Time{writer.fence.decisionAt}, raw.at)
}

func TestResourceInstallationChangedAndUnknownNeverProveCurrentSource(t *testing.T) {
	cases := []struct {
		name     string
		row      resourceInstallationRow
		missing  bool
		expected error
	}{
		{name: "revoked", row: resourceInstallationRow{binding: "binding-a", state: "version-2", eligible: false}, expected: kaname.ErrAuthorityClassificationChanged},
		{name: "ABA", row: resourceInstallationRow{binding: "binding-a", state: "same-visible-values-new-xmin-ctid", eligible: true}, expected: kaname.ErrAuthorityClassificationChanged},
		{name: "rebound", row: resourceInstallationRow{binding: "binding-b", state: "version-1", eligible: true}, expected: kaname.ErrAuthorityClassificationChanged},
		{name: "missing", missing: true, expected: kaname.ErrAuthorityClassificationChanged},
		{name: "unsupported-shape", row: resourceInstallationRow{binding: "binding-a", state: "version-1", eligible: true, unsupported: true}, expected: kaname.ErrSourceUnconfirmed},
		{name: "expired-at-final-clock", row: resourceInstallationRow{binding: "binding-a", state: "version-1", eligible: false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capture, writer, raw := resourceInstallationFixture(t)
			if tc.missing {
				delete(raw.records, "assignment-a")
			} else {
				raw.records["assignment-a"] = tc.row
			}
			ok, err := capture.current(context.Background(), writer, "a")
			require.False(t, ok)
			if tc.expected != nil {
				require.ErrorIs(t, err, tc.expected)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestResourceInstallationCurrentSharesBudgetAndHonorsCancellation(t *testing.T) {
	capture, writer, raw := resourceInstallationFixture(t)
	require.NoError(t, capture.budget.Charge(0, 4096))
	ok, err := capture.current(context.Background(), writer, "a")
	require.False(t, ok)
	require.Error(t, err)
	require.Empty(t, raw.keys, "исчерпанный бюджет не разрешает новое SQL чтение")
	capture, writer, raw = resourceInstallationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ok, err = capture.current(ctx, writer, "a")
	require.False(t, ok)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, raw.keys)
}

func TestResourceInstallationDoesNotStopAtFirstEligibleCapturedSource(t *testing.T) {
	capture, writer, raw := resourceInstallationFixture(t)
	capture.sources["a"] = append(capture.sources["a"], resourceInstallationWitness{assignment: "assignment-b", binding: "binding-b", state: "version-1"})
	raw.records["assignment-b"] = resourceInstallationRow{binding: "binding-b", state: "version-2", eligible: true}
	ok, err := capture.current(context.Background(), writer, "a")
	require.False(t, ok)
	require.ErrorIs(t, err, kaname.ErrAuthorityClassificationChanged)
	require.Equal(t, []string{"assignment-a", "assignment-b"}, raw.keys)
}

func TestResourceInstallationBudgetStopsBeforeAnotherWitnessSQL(t *testing.T) {
	capture, writer, raw := resourceInstallationFixture(t)
	require.NoError(t, capture.budget.Charge(100000-40, 0))
	ok, err := capture.current(context.Background(), writer, "a")
	require.False(t, ok)
	require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
	require.Empty(t, raw.keys, "остаток меньше максимального witness sentinel: нового SQL нет")
}
