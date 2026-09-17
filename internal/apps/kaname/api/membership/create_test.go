// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

// create_test.go — MembershipService.Create: транспорт разбирает запрос,
// отдаёт его порту создания и возвращает операцию. Решений здесь нет.
//
// ПОЧЕМУ ЭТОЙ ПРОБЕ НУЖЕН СВОЙ ДИСКРИМИНАТОР. Порождённый интерфейс сервера
// удовлетворяется вложенным `UnimplementedMembershipServiceServer`: метод
// обработчика с несовпадающей сигнатурой сборку НЕ роняет — он просто не
// перекрывает заглушку, и каждый вызов отвечает `Unimplemented`. Все слои ниже
// при этом зелены. Поэтому первая проба входит ЧЕРЕЗ транспорт и отличает
// «ответил обработчик» от «ответила заглушка» по коду и по тому, дошёл ли
// вызов до порта (kaname#181, IAM-ID-1 S3.2).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// countingCreator — дублёр порта создания. Он ЗАПОМИНАЕТ вход и считает вызовы:
// утверждение «обработчик разобрал запрос и отдал его порту» без этого
// зеленело бы на обработчике, который порт не зовёт вовсе.
type countingCreator struct {
	calls int
	got   CreateInput
	op    *operations.Operation
	err   error
}

func (c *countingCreator) CreateMembership(_ context.Context, in CreateInput) (*operations.Operation, error) {
	c.calls++
	c.got = in
	return c.op, c.err
}

// TestMembership_KAN181_HandlerServesCreate — обработчик ПЕРЕКРЫВАЕТ заглушку:
// вызов доходит до порта с разобранным входом, ответ — операция порта.
func TestMembership_KAN181_HandlerServesCreate(t *testing.T) {
	creator := &countingCreator{op: &operations.Operation{ID: "iop00000000000000181", Description: "d"}}
	var srv iamv1.MembershipServiceServer = NewHandler(nil, nil, creator)

	op, err := srv.Create(context.Background(), &iamv1.CreateMembershipRequest{
		AccountId:   goodAccount,
		Email:       "p@example.test",
		DisplayName: "P",
		ProjectId:   "prj00000000000000181",
		RoleId:      "rol00000000000000181",
	})
	if status.Code(err) == codes.Unimplemented {
		t.Fatalf("Create: ответила вложенная заглушка — обработчик метод не перекрывает; " +
			"глагол объявлен и маршрутизируется, а каждому вызывающему отвечал бы Unimplemented")
	}
	require.NoError(t, err)
	require.Equal(t, 1, creator.calls, "вызов обязан дойти до порта создания ровно один раз")
	require.Equal(t, CreateInput{
		AccountID:   domain.AccountID(goodAccount),
		Email:       domain.Email("p@example.test"),
		DisplayName: domain.DisplayName("P"),
		ProjectID:   domain.ProjectID("prj00000000000000181"),
		RoleID:      domain.RoleID("rol00000000000000181"),
	}, creator.got, "каждое поле запроса доезжает до порта под своим именем")
	require.NotNil(t, op)
	require.Equal(t, "iop00000000000000181", op.GetId(), "ответ — операция, которую вернул порт")
}

// TestMembership_KAN181_HandlerPassesRefusalThrough — отказ порта уходит
// вызывающему КАК ЕСТЬ: транспорт не переводит и не глотает кодов.
func TestMembership_KAN181_HandlerPassesRefusalThrough(t *testing.T) {
	creator := &countingCreator{err: status.Error(codes.InvalidArgument, "Illegal argument account_id: required")}
	var srv iamv1.MembershipServiceServer = NewHandler(nil, nil, creator)

	op, err := srv.Create(context.Background(), &iamv1.CreateMembershipRequest{Email: "p@example.test"})
	require.Nil(t, op)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Equal(t, "Illegal argument account_id: required", status.Convert(err).Message(),
		"текст отказа — часть контракта и доезжает дословно")
	require.Equal(t, 1, creator.calls)
}
