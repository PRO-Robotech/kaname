// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/multitracer"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Диагностика только fixture: максимум 24 событий, ограниченные поля, без SQL
// arguments/credentials. Первые ошибки сохраняются, последующие не вытесняют
// исходный SQLSTATE ошибкой aborted transaction или cleanup.
type roleMutationDiagnostic struct {
	mu      sync.Mutex
	events  []roleMutationDiagnosticEvent
	omitted int
}
type roleMutationDiagnosticEvent struct {
	Phase      string `json:"phase"`
	SQL        string `json:"sql,omitempty"`
	Error      string `json:"error,omitempty"`
	Code       string `json:"code,omitempty"`
	Constraint string `json:"constraint,omitempty"`
	Table      string `json:"table,omitempty"`
	Where      string `json:"where,omitempty"`
}

func roleDiagnosticBound(s string, n int) string {
	if len(s) > n {
		return s[:n] + " [truncated]"
	}
	return s
}
func (d *roleMutationDiagnostic) record(phase, sql string, err error) {
	event := roleMutationDiagnosticEvent{Phase: phase, SQL: roleDiagnosticBound(sql, 512)}
	if err != nil {
		event.Error = roleDiagnosticBound(fmt.Sprintf("%T: %v", err, err), 1024)
		var pe *pgconn.PgError
		if errors.As(err, &pe) {
			event.Code = pe.Code
			event.Constraint = roleDiagnosticBound(pe.ConstraintName, 128)
			event.Table = roleDiagnosticBound(pe.TableName, 128)
			event.Where = roleDiagnosticBound(pe.Where, 1536)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.events) == 24 {
		d.omitted++
		return
	}
	d.events = append(d.events, event)
}
func (d *roleMutationDiagnostic) snapshot() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	raw, err := json.Marshal(struct {
		Events  []roleMutationDiagnosticEvent `json:"events"`
		Omitted int                           `json:"omitted"`
	}{d.events, d.omitted})
	if err != nil {
		return err.Error()
	}
	return string(raw)
}

type roleDiagnosticSQLKey struct{}

func (d *roleMutationDiagnostic) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, roleDiagnosticSQLKey{}, roleDiagnosticBound(data.SQL, 512))
}
func (d *roleMutationDiagnostic) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if data.Err != nil {
		sql, _ := ctx.Value(roleDiagnosticSQLKey{}).(string)
		d.record("query", sql, data.Err)
	}
}
func (*roleMutationDiagnostic) TraceBatchStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	return ctx
}
func (d *roleMutationDiagnostic) TraceBatchQuery(_ context.Context, _ *pgx.Conn, data pgx.TraceBatchQueryData) {
	if data.Err != nil {
		d.record("batch-query", data.SQL, data.Err)
	}
}
func (d *roleMutationDiagnostic) TraceBatchEnd(_ context.Context, _ *pgx.Conn, data pgx.TraceBatchEndData) {
	if data.Err != nil {
		d.record("batch-end", "", data.Err)
	}
}
func (*roleMutationDiagnostic) TraceCopyFromStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceCopyFromStartData) context.Context {
	return context.WithValue(ctx, roleDiagnosticSQLKey{}, data.TableName.Sanitize())
}
func (d *roleMutationDiagnostic) TraceCopyFromEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceCopyFromEndData) {
	if data.Err != nil {
		table, _ := ctx.Value(roleDiagnosticSQLKey{}).(string)
		d.record("copy", table, data.Err)
	}
}

type roleMutationDiagnosticFactory struct {
	*kanamepg.GrantPolicyWriters
	diagnostic *roleMutationDiagnostic
}

func (f *roleMutationDiagnosticFactory) RoleMutationWriter(ctx context.Context, request kaname.RoleMutationRequest, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	f.diagnostic.record("factory-enter", "", nil)
	writer, err := f.GrantPolicyWriters.RoleMutationWriter(ctx, request, actor)
	f.diagnostic.record("factory-return", "", err)
	// Возвращается исходный concrete writer. Ни identity, ни optional promoted
	// ports, ни Commit/Rollback, ни policy decisions observer не подменяет.
	return writer, err
}
func newRoleMutationDiagnosticFactory(t *testing.T, w delegationUCWorld) (*roleMutationDiagnosticFactory, *roleMutationDiagnostic) {
	t.Helper()
	d := &roleMutationDiagnostic{}
	cfg := w.r.runtime.Config()
	if cfg.ConnConfig.Tracer == nil {
		cfg.ConnConfig.Tracer = d
	} else {
		cfg.ConnConfig.Tracer = multitracer.New(cfg.ConnConfig.Tracer, d)
	}
	pool, err := pgxpool.NewWithConfig(w.r.ctx, cfg)
	if pool != nil {
		t.Cleanup(pool.Close)
	}
	require.NoError(t, err)
	writers, err := kanamepg.NewGrantPolicyWriters(w.r.ctx, kanamepg.New(pool, nil), w.r.bundle)
	require.NoError(t, err, "writer construction diagnostic=%s", d.snapshot())
	return &roleMutationDiagnosticFactory{GrantPolicyWriters: writers, diagnostic: d}, d
}

var _ kaname.RoleMutationWriterFactory = (*roleMutationDiagnosticFactory)(nil)
var _ kaname.RoleAuthorityWriterFactory = (*roleMutationDiagnosticFactory)(nil)
var _ pgx.QueryTracer = (*roleMutationDiagnostic)(nil)
var _ pgx.BatchTracer = (*roleMutationDiagnostic)(nil)
var _ pgx.CopyFromTracer = (*roleMutationDiagnostic)(nil)
