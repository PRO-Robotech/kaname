// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/multitracer"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fullStartupDiagnosticScope struct{}
type fullStartupDiagnosticOperation struct{}
type fullStartupDiagnosticQuery struct{}

// Только наблюдение: PID и TxStatus читаются из клиента, без SQL/XID/новых locks.
// Счётчик запроса связывает START/END; это не номер product attempt или транзакции.
type fullStartupDiagnosticEvent struct {
	Sequence uint64 `json:"query_sequence"`
	ElapsedNS int64 `json:"elapsed_ns"`
	Phase string `json:"phase"`
	Operation string `json:"operation"`
	PID uint32 `json:"pid"`
	TxStatus string `json:"tx_status"`
	Family string `json:"family"`
	SQL string `json:"sql,omitempty"`
	SQLHash string `json:"sql_sha256"`
	ErrorType string `json:"error_type,omitempty"`
	Code string `json:"sqlstate,omitempty"`
	Message string `json:"message,omitempty"`
	MessageHash string `json:"message_sha256,omitempty"`
	Where []string `json:"where_frames,omitempty"`
	WhereHash string `json:"where_sha256,omitempty"`
	Routine string `json:"routine,omitempty"`
	Command string `json:"command,omitempty"`
}

type fullStartupDiagnostic struct {
	mu sync.Mutex
	started time.Time
	sequence uint64
	events [256]fullStartupDiagnosticEvent
	next uint64
	failures []fullStartupDiagnosticEvent
	failureCounts [3]uint64
	omittedErrors uint64
}

// multitracer сохраняет прежние callbacks. Его BatchTracer скрывается именно
// при прежнем Query-only tracer, чтобы не включить иной product batch route.
type fullStartupDiagnosticNonBatch interface {
	pgx.QueryTracer
	pgx.CopyFromTracer
	pgx.PrepareTracer
	pgx.ConnectTracer
	pgxpool.AcquireTracer
	pgxpool.ReleaseTracer
}
type fullStartupDiagnosticQueryOnly struct { fullStartupDiagnosticNonBatch }

func (q *fullStartupDiagnostic) combine(previous pgx.QueryTracer) pgx.QueryTracer {
	if previous == nil {
		return q
	}
	combined := multitracer.New(previous, q)
	if _, batch := previous.(pgx.BatchTracer); batch {
		return combined
	}
	return fullStartupDiagnosticQueryOnly{combined}
}

var fullStartupDiagnosticParameter = regexp.MustCompile(`\$[0-9]+`)
var fullStartupDiagnosticRoutine = regexp.MustCompile(`^[A-Za-z_][A-Za-z_0-9]{0,127}$`)

func fullStartupDiagnosticSQL(sql string) string {
	// Args вообще не читаются. Текст с literals/quoted identifiers/comments
	// оставляет только точный digest: SQL/Where могут содержать секретные значения.
	withoutParameters := fullStartupDiagnosticParameter.ReplaceAllString(sql, "?")
	if strings.ContainsAny(withoutParameters, "'\"$") || strings.Contains(sql, "--") || strings.Contains(sql, "/*") || len(sql) > 2048 {
		return "[text omitted; compare sql_sha256 with SOURCE]"
	}
	return sql
}

func (q *fullStartupDiagnostic) start(ctx context.Context, conn *pgx.Conn, sql, phase string) fullStartupDiagnosticEvent {
	operation, _ := ctx.Value(fullStartupDiagnosticOperation{}).(string)
	if operation != "disable" && operation != "enable" {
		operation = "unattributed"
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.sequence++
	e := fullStartupDiagnosticEvent{Sequence: q.sequence, Phase: phase, Operation: operation,
		ElapsedNS: time.Since(q.started).Nanoseconds(), PID: conn.PgConn().PID(),
		TxStatus: string([]byte{conn.PgConn().TxStatus()}), Family: resourceStartupFamily(sql),
		SQL: fullStartupDiagnosticSQL(sql), SQLHash: fmt.Sprintf("%x", sha256.Sum256([]byte(sql)))}
	q.events[q.next%uint64(len(q.events))] = e
	q.next++
	return e
}

func (q *fullStartupDiagnostic) finish(conn *pgx.Conn, e fullStartupDiagnosticEvent, err error, command, phase string) {
	e.Phase, e.Command = phase, command
	e.ElapsedNS = time.Since(q.started).Nanoseconds()
	e.TxStatus = string([]byte{conn.PgConn().TxStatus()})
	if err != nil {
		e.ErrorType = fmt.Sprintf("%T", err)
		var pgerr *pgconn.PgError
		if errors.As(err, &pgerr) {
			e.Code = pgerr.Code
			e.Message = resourceStartupSafeMessage(pgerr.Message)
			e.MessageHash = fmt.Sprintf("%x", sha256.Sum256([]byte(pgerr.Message)))
			e.WhereHash = fmt.Sprintf("%x", sha256.Sum256([]byte(pgerr.Where)))
			for _, frame := range resourceStartupWhereFrame.FindAllStringSubmatch(pgerr.Where, 8) {
				e.Where = append(e.Where, frame[1]+" line "+frame[2]+" at "+frame[3])
			}
			if fullStartupDiagnosticRoutine.MatchString(pgerr.Routine) {
				e.Routine = pgerr.Routine
			}
		}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.events[q.next%uint64(len(q.events))] = e
	q.next++
	// Первые 32 ошибки каждой метки сохраняются отдельно: setup и последующий
	// polling/rollback не вытеснят первичную ошибку Disable.
	if err != nil {
		bucket := 0
		if e.Operation == "disable" {
			bucket = 1
		} else if e.Operation == "enable" {
			bucket = 2
		}
		if q.failureCounts[bucket] < 32 {
			q.failureCounts[bucket]++
			q.failures = append(q.failures, e)
		} else {
			q.omittedErrors++
		}
	}
}

func (q *fullStartupDiagnostic) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, fullStartupDiagnosticQuery{}, q.start(ctx, conn, data.SQL, "query-start"))
}
func (q *fullStartupDiagnostic) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	if e, ok := ctx.Value(fullStartupDiagnosticQuery{}).(fullStartupDiagnosticEvent); ok {
		q.finish(conn, e, data.Err, data.CommandTag.String(), "query-end")
	}
}
func (q *fullStartupDiagnostic) TraceBatchStart(ctx context.Context, conn *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	return context.WithValue(ctx, fullStartupDiagnosticQuery{}, q.start(ctx, conn, "", "batch-start"))
}
func (q *fullStartupDiagnostic) TraceBatchQuery(ctx context.Context, conn *pgx.Conn, data pgx.TraceBatchQueryData) {
	// Это событие чтения результата batch, не момент начала исполнения его SQL.
	e := q.start(ctx, conn, data.SQL, "batch-result-observed")
	q.finish(conn, e, data.Err, data.CommandTag.String(), "batch-result")
}
func (q *fullStartupDiagnostic) TraceBatchEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceBatchEndData) {
	if e, ok := ctx.Value(fullStartupDiagnosticQuery{}).(fullStartupDiagnosticEvent); ok {
		q.finish(conn, e, data.Err, "", "batch-end")
	}
}

func (q *fullStartupDiagnostic) report(t *testing.T) {
	t.Helper()
	if !t.Failed() {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	first := uint64(0)
	if q.next > uint64(len(q.events)) {
		first = q.next - uint64(len(q.events))
	}
	t.Logf("FULL_STARTUP_SQL_DIAGNOSTIC events=%d ring_omitted=%d errors_omitted=%d; operation=ctx lineage, unattributed is not proof of detached callback; non-SQL errors invisible", q.next, first, q.omittedErrors)
	for _, e := range q.failures {
		payload, _ := json.Marshal(e)
		t.Logf("FULL_STARTUP_FIRST_SQL_ERROR %s", payload)
	}
	for i := first; i < q.next; i++ {
		payload, _ := json.Marshal(q.events[i%uint64(len(q.events))])
		t.Logf("FULL_STARTUP_SQL_EVENT %s", payload)
	}
}
