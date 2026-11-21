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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/multitracer"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

type resourceStartupTraceScope struct{}
type resourceStartupTraceQuery struct{}
type resourceStartupQueryMeta struct {
	Sequence uint64 `json:"sequence"`
	Backend  uint32 `json:"backend_pid"`
	Family   string `json:"query_family"`
	SQLHash  string `json:"sql_sha256"`
}
type resourceStartupQueryError struct {
	resourceStartupQueryMeta
	Code        string   `json:"sqlstate,omitempty"`
	ErrorType   string   `json:"error_type"`
	Message     string   `json:"message"`
	MessageHash string   `json:"message_sha256,omitempty"`
	Where       []string `json:"where_frames,omitempty"`
	WhereHash   string   `json:"where_sha256,omitempty"`
}
type resourceStartupCommandCount struct {
	Started           uint64 `json:"started"`
	Completed         uint64 `json:"completed"`
	Errors            uint64 `json:"errors"`
	CommitTagRollback uint64 `json:"commit_tag_rollback"`
}
type resourceStartupQueryTrace struct {
	mu           sync.Mutex
	Queries      uint64                                  `json:"queries_started"`
	Errors       uint64                                  `json:"query_errors_total"`
	Omitted      uint64                                  `json:"query_errors_omitted"`
	Transactions map[string]*resourceStartupCommandCount `json:"observed_transaction_commands"`
	Failures     []resourceStartupQueryError             `json:"query_errors"`
}

// Config() возвращает Copy: credentials, role, hooks и pool limits остаются
// прежними. Старый pool закрыт до открытия нового, параллельного owner fallback нет.
func resourceStartupObservedPool(t *testing.T, ctx context.Context, original *pgxpool.Pool) (*pgxpool.Pool, *resourceStartupQueryTrace) {
	t.Helper()
	cfg := original.Config()
	trace := &resourceStartupQueryTrace{Transactions: make(map[string]*resourceStartupCommandCount)}
	if previous := cfg.ConnConfig.Tracer; previous != nil {
		// pgx multitracer сохраняет также Batch/Copy/Prepare/Connect и pool interfaces.
		cfg.ConnConfig.Tracer = multitracer.New(previous, trace)
	} else {
		cfg.ConnConfig.Tracer = trace
	}
	original.Close()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool, trace
}

func resourceStartupFamily(sql string) string {
	normal := strings.ToLower(strings.TrimSpace(sql))
	if normal == "commit" || normal == "rollback" {
		return normal
	}
	fields := strings.Fields(normal)
	if len(fields) == 0 {
		return "other"
	}
	switch fields[0] {
	case "begin", "select", "insert", "update", "delete":
		return fields[0]
	default:
		return "other"
	}
}

func (q *resourceStartupQueryTrace) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if ctx.Value(resourceStartupTraceScope{}) != q {
		return ctx
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.Queries++
	meta := resourceStartupQueryMeta{Sequence: q.Queries, Backend: conn.PgConn().PID(),
		Family: resourceStartupFamily(data.SQL), SQLHash: fmt.Sprintf("%x", sha256.Sum256([]byte(data.SQL)))}
	if meta.Family == "begin" || meta.Family == "commit" || meta.Family == "rollback" {
		if q.Transactions[meta.Family] == nil {
			q.Transactions[meta.Family] = &resourceStartupCommandCount{}
		}
		q.Transactions[meta.Family].Started++
	}
	// SQL/Args не сохраняются и не печатаются. Context несёт только bounded metadata.
	return context.WithValue(ctx, resourceStartupTraceQuery{}, meta)
}

var resourceStartupWhereFrame = regexp.MustCompile(`(?m)^PL/pgSQL function ((?:kaname\.)?_?authority_[a-zA-Z0-9_]+)\([^\n]*\) line ([0-9]+) at ([A-Za-z ]+)$`)

func resourceStartupSafeMessage(message string) string {
	// Только дословные static diagnostics из текущего SQL; неизвестное сообщение
	// сопоставляется с SOURCE по digest без утечки подставленных значений.
	switch message {
	case "signed retained write requires prepared resource manifest",
		"resource private admission required", "resource private manifest missing",
		"resource private manifest mismatch", "resource producer requires body state",
		"authority transaction attestation required", "authority transaction attestation mismatch":
		return message
	default:
		return "[redacted; compare message_sha256 with SOURCE]"
	}
}

func (q *resourceStartupQueryTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	meta, ok := ctx.Value(resourceStartupTraceQuery{}).(resourceStartupQueryMeta)
	if !ok || ctx.Value(resourceStartupTraceScope{}) != q {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if count := q.Transactions[meta.Family]; count != nil {
		count.Completed++
		if data.Err != nil {
			count.Errors++
		}
		if meta.Family == "commit" && data.CommandTag.String() == "ROLLBACK" {
			count.CommitTagRollback++
		}
	}
	if data.Err == nil {
		return
	}
	q.Errors++
	if len(q.Failures) >= 16 {
		q.Omitted++
		return
	}
	failure := resourceStartupQueryError{resourceStartupQueryMeta: meta, ErrorType: fmt.Sprintf("%T", data.Err), Message: "[non-PG error text redacted]"}
	var pgerr *pgconn.PgError
	if errors.As(data.Err, &pgerr) {
		failure.Code = pgerr.Code
		failure.Message = resourceStartupSafeMessage(pgerr.Message)
		failure.MessageHash = fmt.Sprintf("%x", sha256.Sum256([]byte(pgerr.Message)))
		failure.WhereHash = fmt.Sprintf("%x", sha256.Sum256([]byte(pgerr.Where)))
		for _, frame := range resourceStartupWhereFrame.FindAllStringSubmatch(pgerr.Where, 8) {
			failure.Where = append(failure.Where, frame[1]+" line "+frame[2]+" at "+frame[3])
		}
	}
	q.Failures = append(q.Failures, failure)
}

func (q *resourceStartupQueryTrace) report(t *testing.T) {
	t.Helper()
	q.mu.Lock()
	defer q.mu.Unlock()
	// Один fixture public call не равен числу внутренних попыток. Здесь только
	// наблюдённые SQL begin/commit/rollback; inferred attempt count не выводится.
	payload, err := json.Marshal(q)
	if err != nil {
		t.Logf("RESOURCE_STARTUP_QUERY_TRACE encoding_error_type=%T", err)
		return
	}
	t.Logf("RESOURCE_STARTUP_QUERY_TRACE public_calls=1 %s", payload)
}
