// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

type resourceSourceRows struct {
	pgx.Rows
	rows []resourceSourceRow
	next int
}

func (r *resourceSourceRows) Next() bool {
	if r.next >= len(r.rows) {
		return false
	}
	r.next++
	return true
}
func (r *resourceSourceRows) Scan(dest ...any) error {
	*dest[0].(*string) = r.rows[r.next-1].state
	*dest[1].(*string) = string(r.rows[r.next-1].value)
	return nil
}
func (*resourceSourceRows) Close()     {}
func (*resourceSourceRows) Err() error { return nil }

type resourceSourceTx struct {
	pgx.Tx
	conn   *pgx.Conn
	rows   []resourceSourceRow
	limits []int
	err    error
}

func (t *resourceSourceTx) Conn() *pgx.Conn { return t.conn }
func (t *resourceSourceTx) Query(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
	t.limits = append(t.limits, args[len(args)-1].(int))
	if t.err != nil {
		return nil, t.err
	}
	return &resourceSourceRows{rows: t.rows}, nil
}
func resourceSourceFixture(t *testing.T) (*resourceSourceCapture, *resourceSourceTx, resourceSourceKey) {
	t.Helper()
	tx := &resourceSourceTx{conn: new(pgx.Conn)}
	lifetime, err := newResourceAttemptLifetime(tx.conn, nativeBoundaryBundle(t))
	require.NoError(t, err)
	capture, err := newResourceSourceCapture(tx, &relverdict.AdministrativeReadBudget{}, lifetime)
	require.NoError(t, err)
	return capture, tx, resourceSourceKey{kind: resourceSourceProject, typ: "project", id: "project-a"}
}
func resourceSourceWriter(t *testing.T, c *resourceSourceCapture, tx pgx.Tx) *authorityWriteTx {
	t.Helper()
	w := &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: tx}}}
	require.NoError(t, c.lifetime.prepare(w))
	return w
}
func TestResourceSourceCaptureRejectsAbsentToPresentAndABA(t *testing.T) {
	for _, initial := range []string{"", "xmin-1/ctid-1"} {
		t.Run(initial, func(t *testing.T) {
			c, tx, key := resourceSourceFixture(t)
			row := resourceSourceRow{state: initial, value: json.RawMessage(`{"id":"project-a","account_id":"a"}`)}
			if initial != "" {
				tx.rows = []resourceSourceRow{row}
			}
			_, err := c.read(context.Background(), tx, key)
			require.NoError(t, err)
			require.NoError(t, c.seal())
			row.state = "xmin-2/ctid-2"
			tx.rows = []resourceSourceRow{row}
			w := resourceSourceWriter(t, c, tx)
			require.ErrorIs(t, c.recheck(context.Background(), w), kaname.ErrAuthorityClassificationChanged, "одинаковые visible поля не скрывают ABA")
		})
	}
}
func TestResourceSourceCaptureIsNotTransferredToAnotherWriterOnSameConnection(t *testing.T) {
	c, tx, key := resourceSourceFixture(t)
	_, err := c.read(context.Background(), tx, key)
	require.NoError(t, err)
	require.NoError(t, c.seal())
	w := resourceSourceWriter(t, c, tx)
	require.NoError(t, c.recheck(context.Background(), w))
	before := len(tx.limits)
	other := &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: tx}}}
	require.ErrorIs(t, c.recheck(context.Background(), other), kaname.ErrSourceUnconfirmed)
	require.ErrorIs(t, c.lifetime.prepare(other), kaname.ErrSourceUnconfirmed)
	c.lifetime.close()
	require.ErrorIs(t, c.recheck(context.Background(), w), kaname.ErrSourceUnconfirmed)
	require.Len(t, tx.limits, before, "ошибка lifetime предшествует SQL")
}
func TestResourceSourceCaptureCannotGrowAfterRRSeal(t *testing.T) {
	c, tx, key := resourceSourceFixture(t)
	_, err := c.read(context.Background(), tx, key)
	require.NoError(t, err)
	require.NoError(t, c.seal())
	key.id = "new-foreign-project"
	_, err = c.read(context.Background(), tx, key)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.Len(t, tx.limits, 1)
}
func TestResourceSourceCaptureSharesRRAndRCBudgetAndNeverReturnsPrefix(t *testing.T) {
	c, tx, key := resourceSourceFixture(t)
	require.NoError(t, c.budget.Charge(99999, 0))
	tx.rows = []resourceSourceRow{{state: "one", value: json.RawMessage(`{"id":"project-a"}`)}, {state: "two", value: json.RawMessage(`{"id":"project-b"}`)}}
	got, err := c.read(context.Background(), tx, key)
	require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
	require.Nil(t, got)
	require.Empty(t, c.entries, "sentinel не превращается в успешный усечённый capture")
	require.Equal(t, []int{2}, tx.limits)
	c, tx, key = resourceSourceFixture(t)
	tx.rows = []resourceSourceRow{{state: "one", value: json.RawMessage(`{"id":"project-a"}`)}}
	_, err = c.read(context.Background(), tx, key)
	require.NoError(t, err)
	require.NoError(t, c.budget.Charge(99999, 0))
	require.NoError(t, c.seal())
	w := resourceSourceWriter(t, c, tx)
	require.ErrorIs(t, c.recheck(context.Background(), w), kaname.ErrSourceReadLimit)
	require.Len(t, tx.limits, 1, "RC не начинает новый бюджет")
}
func TestResourceSourceCaptureCancelAndBackendErrorPreserveFailure(t *testing.T) {
	c, tx, key := resourceSourceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.read(ctx, tx, key)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, tx.limits)
	backend := errors.New("source read unavailable")
	tx.err = backend
	_, err = c.read(context.Background(), tx, key)
	require.ErrorIs(t, err, backend)
	require.Empty(t, c.entries)
}

func TestResourceSourceCaptureRejectsDifferentRRTxOnSameConnection(t *testing.T) {
	c, tx, key := resourceSourceFixture(t)
	other := &resourceSourceTx{conn: tx.conn}
	_, err := c.read(context.Background(), other, key)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.Empty(t, other.limits)
}
