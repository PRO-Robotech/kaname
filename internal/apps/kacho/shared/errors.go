// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package shared — errors.go: единый sentinel → gRPC status mapping для всех
// api-слайсов (account / project / user / service_account / group / role /
// access_binding).
//
// Заменяет 7+ копий per-resource `mapRepoErr` (account/helpers.go,
// project/helpers.go, …). Все вызывающие должны
// маппить sentinel-ошибки именно через эти функции — единственный
// authoritative point of translation между internal-sentinels и gRPC-кодами,
// чтобы (а) не дрейфил mapping per-package, (б) добавление нового sentinel'а
// требовало правки одного места.
package shared

import (
	stderrors "errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// MapRepoErr — sentinel → gRPC status. Возвращает nil на nil-input.
//
// Полное покрытие 8 sentinel'ов (включая ErrPermissionDenied /
// ErrUnauthenticated, которых не было в per-resource копиях — leak'ало
// `codes.Internal` клиенту до этой консолидации).
//
// Fallback'и:
//   - если err уже несет gRPC status (не codes.Unknown) — пропускаем через;
//   - если err-текст начинается с "Illegal argument" — YC-style InvalidArgument
//     (parity с verbatim-формой error-сообщений);
//   - иначе — Internal с переданным err-текстом (StripSentinel снимает
//     sentinel-prefix чтобы клиент не увидел "not found: ...").
func MapRepoErr(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case stderrors.Is(err, iamerr.ErrNotFound):
		return status.Error(codes.NotFound, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrAlreadyExists):
		return status.Error(codes.AlreadyExists, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrPermissionDenied):
		return status.Error(codes.PermissionDenied, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrUnauthenticated):
		return status.Error(codes.Unauthenticated, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrFailedPrecondition):
		return status.Error(codes.FailedPrecondition, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrInvalidArg):
		return status.Error(codes.InvalidArgument, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrAborted):
		return status.Error(codes.Aborted, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrUnavailable):
		return status.Error(codes.Unavailable, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrInternal):
		// hardening-invariant #1: INTERNAL carries a FIXED opaque text, never the
		// wrapped detail (a wrapped ErrInternal may embed subject/principal ids,
		// row-counts or pgx/SQL text). Detail stays in the error chain for logs.
		return status.Error(codes.Internal, "internal error")
	}
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return err
	}
	if strings.HasPrefix(err.Error(), "Illegal argument") {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	// Defense-in-depth: an unexpected non-sentinel error must never surface its
	// raw text (could carry pgx/SQL detail) as the gRPC INTERNAL message
	// (api-conventions.md: INTERNAL = fixed text, no leak). The detail stays in
	// the error chain for server-side logging.
	return status.Error(codes.Internal, "internal error")
}

// MapValidationErr — обертка для результатов `domain.<Type>.Validate()`
// (cumulative multierr). Все sync-handler'ы вызывают ее на validation-stage
// перед эмитом Operation, чтобы InvalidArgument имел единую форму.
func MapValidationErr(err error) error {
	if err == nil {
		return nil
	}
	return status.Error(codes.InvalidArgument, err.Error())
}
