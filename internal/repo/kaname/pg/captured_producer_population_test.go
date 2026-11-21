// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Дублёр моделирует только строки источников и identity транзакции, но никогда не разрешение.
// Все тесты компиляции и доказательств ниже и в других местах используют настоящий допущенный bundle.
type arbitraryCapturedWrapper struct{ kaname.SemanticAuthorityWriter }

type capturedRows struct {
	pgx.Rows
	values [][2]string
	index  int
}

func (r *capturedRows) Next() bool { r.index++; return r.index <= len(r.values) }
func (r *capturedRows) Scan(v ...any) error {
	for i := range v {
		*v[i].(*string) = r.values[r.index-1][i]
	}
	return nil
}
func (r *capturedRows) Close()     {}
func (r *capturedRows) Err() error { return nil }

type capturedSettings struct{ isolation, readonly string }

func (r capturedSettings) Scan(v ...any) error {
	*v[0].(*string) = r.isolation
	*v[1].(*string) = r.readonly
	return nil
}

type capturedTx struct {
	pgx.Tx
	conn        *pgx.Conn
	current     map[producerReceiptKey]string
	settings    capturedSettings
	queries     int
	failQuery   int
	rowQueries  int
	commits     int
	commitError error
	selected    []producerReceiptKey
}

func (t *capturedTx) Conn() *pgx.Conn { return t.conn }
func (t *capturedTx) QueryRow(context.Context, string, ...any) pgx.Row {
	t.rowQueries++
	return t.settings
}
func (t *capturedTx) Commit(context.Context) error   { t.commits++; return t.commitError }
func (t *capturedTx) Rollback(context.Context) error { return nil }
func (t *capturedTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t.queries++
	if t.failQuery > 0 && t.queries == t.failQuery {
		return nil, fmt.Errorf("late captured census failure")
	}
	var values [][2]string
	switch sql {
	case captureProducerPopulationSQL:
		for key, state := range t.current {
			raw, _ := json.Marshal(key)
			if string(raw) > args[3].(string) {
				values = append(values, [2]string{string(raw), state})
			}
		}
		sort.Slice(values, func(i, j int) bool { return values[i][0] < values[j][0] })
		if len(values) > args[4].(int) {
			values = values[:args[4].(int)]
		}
	case rereadCapturedProducerSQL:
		var keys []producerReceiptKey
		if err := json.Unmarshal(args[0].([]byte), &keys); err != nil {
			return nil, err
		}
		t.selected = append(t.selected, keys...)
		for _, key := range keys {
			if state, ok := t.current[key]; ok {
				raw, _ := json.Marshal(key)
				values = append(values, [2]string{string(raw), state})
			}
		}
	default:
		return nil, fmt.Errorf("unexpected source SQL")
	}
	return &capturedRows{values: values}, nil
}
func capturedFixture(t *testing.T, count int) (*capturedTx, *producerPopulationCapture) {
	t.Helper()
	tx := &capturedTx{conn: &pgx.Conn{}, current: map[producerReceiptKey]string{}, settings: capturedSettings{"repeatable read", "on"}}
	for i := 0; i < count; i++ {
		tx.current[producerReceiptKey{"registration_owner", "iam", "account", fmt.Sprintf("acc_%04d", i), "owner", "user", "usr_native"}] = fmt.Sprintf("xmin=100,ctid=(1,%d),active=true", i)
	}
	capture, err := captureProducerPopulation(context.Background(), tx, nativeBoundaryBundle(t), nativeBoundaryActor(), &relverdict.AdministrativeReadBudget{})
	require.NoError(t, err)
	return tx, capture
}
func capturedWriter(tx *capturedTx, c *producerPopulationCapture) *semanticAuthorityWriteTx {
	w := &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: tx}}, fence: authorityFence{decisionAt: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)}}
	return &semanticAuthorityWriteTx{authorityWriteTx: w, bundle: c.bundle}
}
func TestCapturedProducerFullRRPagesBudgetAndCancellation(t *testing.T) {
	tx, c := capturedFixture(t, kaname.MaxCanonicalSourcePage+1)
	require.Len(t, c.receipts, kaname.MaxCanonicalSourcePage+1)
	require.Equal(t, 2, tx.queries)
	tx.queries = 0
	tx.failQuery = 2
	partial, lateErr := captureProducerPopulation(context.Background(), tx, c.bundle, c.actor, &relverdict.AdministrativeReadBudget{})
	require.ErrorContains(t, lateErr, "late captured census failure")
	require.Nil(t, partial)
	tx.failQuery = 0
	budget := &relverdict.AdministrativeReadBudget{}
	require.NoError(t, budget.Charge(99999, 0))
	c, err := captureProducerPopulation(context.Background(), tx, nativeBoundaryBundle(t), nativeBoundaryActor(), budget)
	require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
	require.Nil(t, c)
	tx.settings.readonly = "off"
	c, err = captureProducerPopulation(context.Background(), tx, nativeBoundaryBundle(t), nativeBoundaryActor(), &relverdict.AdministrativeReadBudget{})
	require.NoError(t, err)
	require.NotNil(t, c, "existing role temp-spool RR is admitted")
	tx.settings.isolation = "read committed"
	c, err = captureProducerPopulation(context.Background(), tx, nativeBoundaryBundle(t), nativeBoundaryActor(), &relverdict.AdministrativeReadBudget{})
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.Nil(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, err = captureProducerPopulation(ctx, tx, nativeBoundaryBundle(t), nativeBoundaryActor(), &relverdict.AdministrativeReadBudget{})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, c)
}
func TestCapturedProducerExactCurrentRereadIgnoresNewForeignReceipt(t *testing.T) {
	tx, c := capturedFixture(t, 2)
	foreign := producerReceiptKey{"registration_owner", "iam", "account", "foreign_new", "owner", "user", "usr_native"}
	tx.current[foreign] = "a new unlocked receipt"
	w := capturedWriter(tx, c)
	require.NoError(t, c.bind(w.authorityWriteTx, c.bundle, c.budget))
	var keys []producerReceiptKey
	for _, r := range c.receipts {
		keys = append(keys, r.key)
	}
	raw, err := json.Marshal(keys)
	require.NoError(t, err)
	cost, err := w.rereadCapturedProducerState(context.Background(), c.receipts, raw)
	require.NoError(t, err)
	require.Equal(t, kaname.SourceReadCost{Rows: 2, Reads: 1}, cost)
	require.ElementsMatch(t, keys, tx.selected)
	require.NotContains(t, tx.selected, foreign)
	require.Len(t, c.receipts, 2, "captured population did not become a current census")
	// Изменённое полное состояние ИЛИ воплощение строки, отсутствующие строки и перенесённые ключи
	// приводят к отказу валидации, а не к молчаливому отбрасыванию потенциально необходимого источника.
	for _, mode := range []string{"revoked", "ABA", "missing", "moved"} {
		t.Run(mode, func(t *testing.T) {
			tx, c := capturedFixture(t, 1)
			w := capturedWriter(tx, c)
			key := c.receipts[0].key
			switch mode {
			case "missing":
				delete(tx.current, key)
			case "moved":
				delete(tx.current, key)
				moved := key
				moved[3] = "another"
				tx.current[moved] = c.receipts[0].state
			default:
				tx.current[key] = mode + " changed row state/incarnation"
			}
			raw, _ := json.Marshal([]producerReceiptKey{key})
			_, err := w.rereadCapturedProducerState(context.Background(), c.receipts, raw)
			require.ErrorIs(t, err, kaname.ErrAuthorityClassificationChanged)
		})
	}
}
func TestCapturedProducerTokenCannotEscapeAttemptWriterOrFinalClock(t *testing.T) {
	tx, c := capturedFixture(t, 1)
	w := capturedWriter(tx, c)
	budget := c.budget
	require.ErrorIs(t, c.bind(w.authorityWriteTx, c.bundle, &relverdict.AdministrativeReadBudget{}), kaname.ErrSourceUnconfirmed, "capture budget cannot be replaced")
	require.NoError(t, c.bind(w.authorityWriteTx, c.bundle, budget))
	token, err := w.CapturedProducerPopulation(context.Background(), c.actor)
	require.NoError(t, err)
	require.NoError(t, token.Validate(w, c.actor, w.fence.decisionAt))
	require.NoError(t, token.Validate(&preparedRoleWriteTx{semanticAuthorityWriteTx: w}, c.actor, w.fence.decisionAt))
	require.ErrorIs(t, token.Validate(&arbitraryCapturedWrapper{w}, c.actor, w.fence.decisionAt), kaname.ErrSourceUnconfirmed)
	other := capturedWriter(tx, c)
	require.ErrorIs(t, token.Validate(other, c.actor, w.fence.decisionAt), kaname.ErrSourceUnconfirmed)
	require.ErrorIs(t, c.bind(other.authorityWriteTx, c.bundle, budget), kaname.ErrSourceUnconfirmed)
	actor := c.actor
	actor.ID = "another"
	require.ErrorIs(t, token.Validate(w, actor, w.fence.decisionAt), kaname.ErrSourceUnconfirmed)
	require.ErrorIs(t, token.Validate(w, c.actor, w.fence.decisionAt.Add(time.Second)), kaname.ErrSourceUnconfirmed)
	require.NoError(t, c.bind(w.authorityWriteTx, c.bundle, budget))
	require.ErrorIs(t, token.Validate(w, c.actor, w.fence.decisionAt), kaname.ErrSourceUnconfirmed, "same-time refresh still invalidates old evidence")
	token, err = w.CapturedProducerPopulation(context.Background(), c.actor)
	require.NoError(t, err)
	tx.conn = &pgx.Conn{}
	require.ErrorIs(t, token.Validate(w, c.actor, w.fence.decisionAt), kaname.ErrSourceUnconfirmed)
	tx.conn = c.conn
	require.NoError(t, w.Rollback(context.Background()))
	require.ErrorIs(t, token.Validate(w, c.actor, w.fence.decisionAt), kaname.ErrSourceUnconfirmed)
	_, err = w.CapturedProducerPopulation(context.Background(), c.actor)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}
func TestCapturedProducerPageRetainsLastSourceAndRejectsForeignCursor(t *testing.T) {
	_, c := capturedFixture(t, 3)
	first, next, err := c.page("", 2)
	require.NoError(t, err)
	require.Len(t, first, 2)
	require.NotEmpty(t, next)
	last, end, err := c.page(next, 2)
	require.NoError(t, err)
	require.Len(t, last, 1)
	require.Empty(t, end)
	require.NotEqual(t, first[0].key, last[0].key)
	_, _, err = c.page("untrusted", 2)
	require.ErrorIs(t, err, kaname.ErrCanonicalSourceInvalid)
}

// Builder задаёт настоящее обязательство prepared body: пока оно не применено,
// Commit отказывает до SQL и запрещает повторное использование proof.
type capturedRoleTuples struct{}

func (capturedRoleTuples) BuildRoleTuples(domain.AccessBinding, []domain.Subject, domain.Role) []ab.RelationTuple {
	return nil
}

func TestCapturedPreparedRoleCommitPreconditionsInvalidateEvidence(t *testing.T) {
	for _, closedLease := range []bool{false, true} {
		t.Run(fmt.Sprintf("closed-lease=%t", closedLease), func(t *testing.T) {
			tx, c := capturedFixture(t, 1)
			w := capturedWriter(tx, c)
			require.NoError(t, c.bind(w.authorityWriteTx, c.bundle, c.budget))
			prepared := &preparedRoleWriteTx{semanticAuthorityWriteTx: w, stage: &roleMutationStage{request: kaname.RoleMutationRequest{Tuples: capturedRoleTuples{}}}}
			if !closedLease {
				prepared.conn = &pgxpool.Conn{}
			}
			token, err := prepared.CapturedProducerPopulation(context.Background(), c.actor)
			require.NoError(t, err)
			require.NoError(t, token.Validate(prepared, c.actor, w.fence.decisionAt))
			err = prepared.Commit(context.Background())
			if closedLease {
				require.ErrorIs(t, err, pgx.ErrTxClosed)
			} else {
				require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
			}
			require.Zero(t, tx.commits, "precondition must precede physical Commit")
			require.ErrorIs(t, token.Validate(prepared, c.actor, w.fence.decisionAt), kaname.ErrSourceUnconfirmed)
			_, err = prepared.CapturedProducerPopulation(context.Background(), c.actor)
			require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
		})
	}
}
func TestCapturedPhysicalCommitFailureInvalidatesBothKnownWriterForms(t *testing.T) {
	for _, wrapper := range []bool{false, true} {
		tx, c := capturedFixture(t, 1)
		w := capturedWriter(tx, c)
		require.NoError(t, c.bind(w.authorityWriteTx, c.bundle, c.budget))
		token, err := w.CapturedProducerPopulation(context.Background(), c.actor)
		require.NoError(t, err)
		physicalFailure := errors.New("physical commit failure")
		tx.commitError = physicalFailure
		// Этот semantic Commit вызывает и известный wrapper после своих
		// предусловий. Освобождение его lease отдельно проверяется в PG.
		require.ErrorIs(t, w.Commit(context.Background()), physicalFailure)
		var allowed kaname.SemanticAuthorityWriter = w
		if wrapper {
			allowed = &preparedRoleWriteTx{semanticAuthorityWriteTx: w}
		}
		require.ErrorIs(t, token.Validate(allowed, c.actor, w.fence.decisionAt), kaname.ErrSourceUnconfirmed)
		require.Equal(t, 1, tx.commits)
	}
}
func TestCapturedUnboundNativeBudgetStopsBeforeAdmissionSQL(t *testing.T) {
	tx, c := capturedFixture(t, 1)
	w := capturedWriter(tx, c)
	require.NoError(t, c.bind(w.authorityWriteTx, c.bundle, c.budget))
	require.Nil(t, w.nativeRead, "GLOBAL Rules=nil / delegated path has no captured question boundary")
	require.NoError(t, c.budget.Charge(0, 4094)) // RR settings и capture page уже потратили два чтения
	before := tx.rowQueries
	for i := 0; i < 2; i++ {
		allowed, err := newLiveAdministrativeChecker(w.authorityWriteTx, c.bundle).Check(context.Background(), "user:"+string(c.actor.ID), "admin", "account:acc_a")
		require.False(t, allowed)
		require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
	}
	require.Equal(t, before, tx.rowQueries, "no existence/admission SQL after shared exhaustion")
}
