// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Наблюдение ограничено контекстом исходного снятия. Настройка фикстуры,
// форвард и административные чтения не могут занять место первой ошибки.
// Оба интерфейса сохраняют выбор batch-пути; callback только копирует факт
// до mapErr/operation envelope, не выполняя SQL и не изменяя возвращаемую ошибку.
type raceFirstPGErrorKey struct{}
type raceFirstPGQueryKey struct{}

type raceFirstPGError struct {
	mu      sync.Mutex
	first   string
	cleanup string
}

func (p *raceFirstPGError) record(ctx context.Context, conn *pgx.Conn, sql string, err error) {
	if err == nil || ctx.Value(raceFirstPGErrorKey{}) != p {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// Ошибка rollback не выдаётся за первопричину операции. Её отдельный
	// снимок не затирает исходный отказ, если снятие соединения тоже не удалось.
	slot := &p.first
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(sql)), "ROLLBACK") {
		slot = &p.cleanup
	}
	if *slot != "" {
		return
	}
	*slot = fmt.Sprintf("backend=%d SQL=%q error=%T: %v", conn.PgConn().PID(), sql, err, err)
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		*slot += fmt.Sprintf(" SQLSTATE=%s constraint=%q message=%q detail=%q where=%q",
			pe.Code, pe.ConstraintName, pe.Message, pe.Detail, pe.Where)
	}
}

func (p *raceFirstPGError) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, raceFirstPGQueryKey{}, d.SQL)
}
func (p *raceFirstPGError) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, d pgx.TraceQueryEndData) {
	sql, _ := ctx.Value(raceFirstPGQueryKey{}).(string)
	p.record(ctx, conn, sql, d.Err)
}
func (*raceFirstPGError) TraceBatchStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	return ctx
}
func (p *raceFirstPGError) TraceBatchQuery(ctx context.Context, conn *pgx.Conn, d pgx.TraceBatchQueryData) {
	p.record(ctx, conn, d.SQL, d.Err)
}
func (p *raceFirstPGError) TraceBatchEnd(ctx context.Context, conn *pgx.Conn, d pgx.TraceBatchEndData) {
	p.record(ctx, conn, "<batch end>", d.Err)
}
func (p *raceFirstPGError) report(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.first == "" {
		t.Log("исходное снятие: pgx callback не наблюдал ошибки до cleanup; SQLSTATE не установлен")
	} else {
		t.Logf("первая ошибка исходного снятия до mapping: %s", p.first)
	}
	if p.cleanup != "" {
		t.Logf("отдельная ошибка cleanup исходного снятия: %s", p.cleanup)
	}
}

var _ pgx.QueryTracer = (*raceFirstPGError)(nil)
var _ pgx.BatchTracer = (*raceFirstPGError)(nil)
