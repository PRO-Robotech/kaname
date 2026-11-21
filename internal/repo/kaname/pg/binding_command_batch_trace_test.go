// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

type fullMeasurementBatchKey struct{}
type fullMeasurementBatch struct {
	ID, Connection, Queued, Observed int
	Label, TxBefore, Error           string
	PID                              uint32
	Start, End                       time.Time
	queries                          []*fullMeasurementQuery
}

// У batch наблюдаем только общий интервал и реальные result callbacks.
// Получение клиентом очередного результата не является временем его SQL.
func (tr *fullMeasurementTrace) TraceBatchStart(ctx context.Context, conn *pgx.Conn, d pgx.TraceBatchStartData) context.Context {
	label, _ := ctx.Value(fullMeasurementLabel{}).(string)
	if label == "" {
		return ctx
	}
	b := &fullMeasurementBatch{Label: label, Start: time.Now(), PID: conn.PgConn().PID(), Queued: len(d.Batch.QueuedQueries), TxBefore: string([]byte{conn.PgConn().TxStatus()})}
	tr.mu.Lock()
	if tr.connections == nil {
		tr.connections = map[*pgx.Conn]int{}
	}
	id, exists := tr.connections[conn]
	if !exists {
		id = len(tr.connections) + 1
		tr.connections[conn] = id
	}
	b.Connection, b.ID = id, len(tr.batches)+1
	tr.batches = append(tr.batches, b)
	tr.mu.Unlock()
	return context.WithValue(ctx, fullMeasurementBatchKey{}, b)
}

func (tr *fullMeasurementTrace) TraceBatchQuery(ctx context.Context, conn *pgx.Conn, d pgx.TraceBatchQueryData) {
	b, _ := ctx.Value(fullMeasurementBatchKey{}).(*fullMeasurementBatch)
	if b == nil {
		return
	}
	args := append([]any(nil), d.Args...)
	for i, arg := range args {
		switch value := arg.(type) {
		case []byte:
			args[i] = append([]byte(nil), value...)
		case []string:
			args[i] = append([]string(nil), value...)
		}
	}
	q := &fullMeasurementQuery{Batch: b.ID, Label: b.Label, SQL: d.SQL, Args: args, PID: b.PID, Connection: b.Connection, TxBefore: b.TxBefore, conn: conn}
	tr.mu.Lock()
	b.Observed++
	b.queries = append(b.queries, q)
	tr.queries = append(tr.queries, q)
	tr.mu.Unlock()
	// Общая обработка actual CommandTag и исходного PgError; timestamp ниже
	// заменяется общим envelope и никогда не суммируется как SQL duration.
	tr.TraceQueryEnd(context.WithValue(ctx, fullMeasurementQueryKey{}, q), conn, pgx.TraceQueryEndData{CommandTag: d.CommandTag, Err: d.Err})
}

func (tr *fullMeasurementTrace) TraceBatchEnd(ctx context.Context, conn *pgx.Conn, d pgx.TraceBatchEndData) {
	b, _ := ctx.Value(fullMeasurementBatchKey{}).(*fullMeasurementBatch)
	if b == nil {
		return
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	b.End = time.Now()
	if d.Err != nil {
		b.Error = d.Err.Error()
	}
	for _, q := range b.queries {
		q.Start, q.End = b.Start, b.End
		q.TxAfter = string([]byte{conn.PgConn().TxStatus()})
	}
}

func (tr *fullMeasurementTrace) batchIntervals(label string) []fullMeasurementBatch {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	var out []fullMeasurementBatch
	for _, b := range tr.batches {
		if b.Label == label {
			out = append(out, *b)
		}
	}
	return out
}

var _ pgx.BatchTracer = (*fullMeasurementTrace)(nil)
