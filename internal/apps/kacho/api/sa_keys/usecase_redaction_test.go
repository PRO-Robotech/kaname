// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package sa_keys

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

// panicRedactor — RedactResponseField паникует (эмулирует баг в adapter'е).
type panicRedactor struct{}

func (panicRedactor) RedactResponseField(context.Context, string, []string) error {
	panic("redactor boom")
}

// errRedactor — RedactResponseField возвращает ошибку (jsonb_set провалился).
type errRedactor struct{ err error }

func (e errRedactor) RedactResponseField(context.Context, string, []string) error {
	return e.err
}

// TestScheduleSecretRedact_PanicDoesNotCrashProcess — паника в detached
// redaction-goroutine не должна терминировать IAM-процесс (IAM на critical path
// каждого InternalIAMService.Check). recover-guard ловит панику и логирует ее.
func TestScheduleSecretRedact_PanicDoesNotCrashProcess(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError}))
	uc := &IssueSAKeyUseCase{
		opsRepo:  &stubOpsRepo{done: true},
		redactor: panicRedactor{},
		logger:   logger,
	}

	require.NotPanics(t, func() {
		uc.scheduleSecretRedact(context.Background(), "iop_x")
	}, "redaction-goroutine panic must be recovered, never crash the IAM process")
	require.Contains(t, buf.String(), "redaction", "recovered panic must be logged so the un-redacted key is detectable")
}

// TestScheduleSecretRedact_ErrorIsLogged — провал RedactResponseField оставляет
// plaintext private_key_pem в operation response; это обязано логироваться на
// Error (а не молча дискардиться), иначе застрявший секрет невидим.
func TestScheduleSecretRedact_ErrorIsLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError}))
	uc := &IssueSAKeyUseCase{
		opsRepo:  &stubOpsRepo{done: true},
		redactor: errRedactor{err: errors.New("jsonb_set failed")},
		logger:   logger,
	}

	uc.scheduleSecretRedact(context.Background(), "iop_x")
	require.Contains(t, buf.String(), "redaction failed",
		"redaction error must be logged on Error, not silently discarded")
}
