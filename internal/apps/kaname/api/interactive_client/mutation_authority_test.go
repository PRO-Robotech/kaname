// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package interactiveclient

import (
	"context"
	"errors"
	"testing"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mutationChecker func(context.Context, string, string, string) (bool, error)

func (f mutationChecker) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	return f(ctx, subject, relation, object)
}

func TestInteractiveClientMutationRequiresClusterAdmin(t *testing.T) {
	h := NewHandler(nil, nil, &CreateUseCase{}, &UpdateUseCase{}, &DeleteUseCase{}, nil)
	for _, method := range []struct {
		name string
		call func(context.Context) (*operationpb.Operation, error)
	}{
		{"create", func(ctx context.Context) (*operationpb.Operation, error) {
			return h.Create(ctx, &iamv1.CreateInteractiveClientRequest{})
		}},
		{"update", func(ctx context.Context) (*operationpb.Operation, error) {
			return h.Update(ctx, &iamv1.UpdateInteractiveClientRequest{})
		}},
		{"delete", func(ctx context.Context) (*operationpb.Operation, error) {
			return h.Delete(ctx, &iamv1.DeleteInteractiveClientRequest{})
		}},
	} {
		t.Run(method.name, func(t *testing.T) {
			const userID = "usr00000000000000001"
			const adminSAID = "sva00000000000000001"
			const tenantID = "usr00000000000000002"
			user := operations.Principal{Type: "user", ID: userID}
			machine := operations.Principal{Type: "service_account", ID: adminSAID}
			tenant := operations.Principal{Type: "user", ID: tenantID}
			ask := func(principal operations.Principal, expected codes.Code) {
				out, err := method.call(operations.WithPrincipal(context.Background(), principal))
				require.Nil(t, out, "запрос не должен начать запись")
				require.Equal(t, expected, status.Code(err))
			}
			h.admin = nil
			ask(user, codes.PermissionDenied)

			var queried []string
			h.admin = mutationChecker(func(_ context.Context, subject, relation, object string) (bool, error) {
				require.Equal(t, "system_admin", relation)
				require.Equal(t, "cluster:"+domain.ClusterSingletonID, object)
				queried = append(queried, subject)
				return subject == "user:"+userID || subject == "service_account:"+adminSAID, nil
			})
			ask(operations.SystemPrincipal(), codes.PermissionDenied)
			ask(tenant, codes.PermissionDenied)
			// Администраторы доходят до проверки заведомо неполного запроса.
			ask(user, codes.InvalidArgument)
			ask(machine, codes.InvalidArgument)
			require.Equal(t, []string{"user:" + tenantID, "user:" + userID, "service_account:" + adminSAID}, queried)

			h.admin = mutationChecker(func(context.Context, string, string, string) (bool, error) {
				return false, errors.New("authorization unavailable")
			})
			ask(user, codes.Unavailable)
		})
	}
}
