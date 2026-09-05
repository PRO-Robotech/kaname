// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// list_operations_classification_test.go — the per-resource ListOperations feed
// must report WHAT FAILED, not WHAT THE CALLER SENT.
//
// The operations store answers a caller-format problem as a gRPC InvalidArgument
// naming the field; anything else it returns is a store failure. Deciding
// between the two by "was a page_token supplied" mislabels both directions: a
// database outage becomes a malformed cursor, and an out-of-range page_size on
// the first page becomes an internal fault.
package shared_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	coreerrors "github.com/PRO-Robotech/kacho/pkg/errors"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	corevalidate "github.com/PRO-Robotech/kacho/pkg/validate"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
)

// storePageTokenErr / storePageSizeErr — byte-for-byte what pkg/operations
// returns for those two caller-format problems.
func storePageTokenErr() error {
	return coreerrors.InvalidArgument().
		AddFieldViolation("page_token", "page_token is invalid or malformed").
		Err()
}

func storePageSizeErr() error {
	_, err := corevalidate.PageSize("page_size", 5000)
	return err
}

// wellFormedPageToken — курсор в том виде, в каком его чеканит сам
// pkg/operations: base64url БЕЗ padding над "<unixnano>:<id>".
//
// Фикстура обязана быть именно такой. Тест утверждает «недоступное хранилище —
// это сбой хранилища, а не жалоба на курсор»; если курсор в фикстуре сам
// сломан, у вызова ДВА независимых дефекта сразу, и любой ответ подтверждает
// утверждение случайно. Прежняя строка ("Q3JlYXRlZEF0fGlvcDE=") курсором не
// была: padding, которого кодировка не даёт, и разделитель, которого декодер не
// знает.
func wellFormedPageToken() string {
	return base64.RawURLEncoding.EncodeToString([]byte("1700000000000000000:iop00000000000000001"))
}

func TestListOperations_StoreFailureWithPageToken_IsNotACursorError(t *testing.T) {
	repo := &recordingOpsRepo{listErr: errors.New("repo.List: dial tcp: connection refused")}
	uc := shared.NewListOperationsUseCase(repo)

	// Вызывающий назван: список операций суженный по владельцу, и безымянный
	// контекст до хранилища не доходит вовсе — тогда утверждение о том, КАК
	// отображается его сбой, было бы вакуумным.
	ctx := operations.WithPrincipal(context.Background(), sharedCaller)
	_, _, err := uc.Execute(ctx, "rol00000000000000001", 25, wellFormedPageToken())

	require.Error(t, err)
	assert.Equal(t, codes.Internal, grpcstatus.Code(err),
		"an unreachable store is a store failure; blaming the cursor sends the caller to fix nothing")
	assert.Equal(t, "list operations failed", grpcstatus.Convert(err).Message())
}

func TestListOperations_MalformedPageToken_InvalidArgument(t *testing.T) {
	repo := &recordingOpsRepo{listErr: storePageTokenErr()}
	uc := shared.NewListOperationsUseCase(repo)

	_, _, err := uc.Execute(context.Background(), "rol00000000000000001", 25, "not-a-cursor")

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, grpcstatus.Code(err))
}

func TestListOperations_PageSizeRejected_StaysInvalidArgument(t *testing.T) {
	repo := &recordingOpsRepo{listErr: storePageSizeErr()}
	uc := shared.NewListOperationsUseCase(repo)

	_, _, err := uc.Execute(context.Background(), "rol00000000000000001", 5000, "")

	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, grpcstatus.Code(err),
		"page_size out of range is the caller's error on the FIRST page too")
}
