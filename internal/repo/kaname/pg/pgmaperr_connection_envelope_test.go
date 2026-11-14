// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// Драйвер сам строит закрытую оболочку ConnectError; DialFunc не открывает сеть.
func connectionEnvelope(t *testing.T, cause error) error {
	t.Helper()
	cfg, err := pgconn.ParseConfig("host=127.0.0.1 port=5432 user=private_login database=private_database sslmode=disable")
	require.NoError(t, err)
	calls := 0
	cfg.DialFunc = func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, cause
	}
	conn, err := pgconn.ConnectConfig(context.Background(), cfg)
	require.Nil(t, conn)
	require.Error(t, err)
	require.Positive(t, calls)
	var envelope *pgconn.ConnectError
	require.ErrorAs(t, err, &envelope)
	require.ErrorIs(t, err, cause)
	return fmt.Errorf("entry: %w", err)
}

func TestWrapPgErrConnectionEnvelopePrecedesSQLState(t *testing.T) {
	for _, code := range []string{"28000", "28P01", "23505", "42501"} {
		t.Run(code, func(t *testing.T) {
			cause := &pgconn.PgError{Code: code, Message: "private startup failure", TableName: "private_table"}
			raw := connectionEnvelope(t, cause)
			mapped := wrapPgErr(raw, "", "")
			require.ErrorIs(t, mapped, iamerr.ErrUnavailable)
			require.ErrorIs(t, mapped, raw)
			require.ErrorIs(t, mapped, cause)
			var recovered *pgconn.PgError
			require.ErrorAs(t, mapped, &recovered)
			require.Same(t, cause, recovered)
			require.Equal(t, "database unavailable", iamerr.StripSentinel(mapped))
			wire := status.Convert(shared.MapRepoErr(mapped))
			require.Equal(t, codes.Unavailable, wire.Code())
			require.Equal(t, shared.UnavailableMessage, wire.Message())
		})
	}
}

func TestWrapPgErrConnectionCauseAndStatementControls(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			mapped := wrapPgErr(connectionEnvelope(t, cause), "", "")
			require.ErrorIs(t, mapped, cause)
			require.ErrorIs(t, mapped, iamerr.ErrUnavailable)
			require.Equal(t, codes.Unavailable, status.Code(shared.MapRepoErr(mapped)))
			// Прямой конец вызова не теряется и не превращается во внутренний отказ.
			direct := wrapPgErr(fmt.Errorf("acquire: %w", cause), "", "")
			require.ErrorIs(t, direct, cause)
			require.Equal(t, shared.UnavailableMessage, status.Convert(shared.MapRepoErr(direct)).Message())
		})
	}
	for _, tc := range []struct {
		code string
		want error
	}{
		{"28000", iamerr.ErrInternal}, {"28P01", iamerr.ErrInternal},
		{"42501", iamerr.ErrInternal}, {"57014", iamerr.ErrInternal},
		{"23505", iamerr.ErrAlreadyExists}, {"40001", iamerr.ErrAborted},
	} {
		t.Run("statement_"+tc.code, func(t *testing.T) {
			mapped := wrapPgErr(&pgconn.PgError{Code: tc.code}, "", "")
			require.ErrorIs(t, mapped, tc.want)
			require.False(t, errors.Is(mapped, iamerr.ErrUnavailable))
		})
	}
	plain := errors.New("unexpected decoder failure")
	require.Same(t, plain, wrapPgErr(plain, "", ""))
	closed := fmt.Errorf("transport: %w", pgconn.ErrConnClosed)
	require.ErrorIs(t, wrapPgErr(closed, "", ""), pgconn.ErrConnClosed)
	require.ErrorIs(t, wrapPgErr(closed, "", ""), iamerr.ErrUnavailable)
}
