// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// account_scope_refusal_is_one_integration_test.go — отказ права на создании
// привязки доступа в области аккаунта один для существующего чужого и для
// несуществующего аккаунта (задача kaname#1052; приёмка
// `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`, редакция
// 7, sha256 a3dff53e…3e52, Р15: «путь, который решает обработчик, — PERMISSION_DENIED
// permission denied: промах области сводится к отказу права»; находка F1;
// сценарий AID-36, строка AccessBindingService/Create; полный обход — TestAccountID36_EveryPathAnswersAStrangerOnce).
//
// Вызывающий — человек без прав на кластере и без выдач, не владелец аккаунта;
// хранилище прав на каждый вопрос отвечает «нет». Утверждение — пара (код,
// сообщение) побайтово равна для области на существующий чужой аккаунт и на
// аккаунт, которого нет, и это отказ права. Иначе ответ отличает «такого нет» от
// «не твоё», и при идентификаторах, понятных людям, это перебор арендаторов.
//
// Положительный близнец — владелец того же аккаунта: отказа права нет.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// denyEveryRelation — хранилище прав, отвечающее «нет» на каждый вопрос.
type denyEveryRelation struct{}

func (denyEveryRelation) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}

var _ clients.RelationStore = denyEveryRelation{}

// systemViewRole — системная роль просмотра, посеянная миграцией (та же, что у
// кейсов `tests/newman/cases/iam-access-binding-account-scope.py`).
const systemViewRole = "rol1bda80f2be4d3658e"

func TestAccountID36_GrantOnAccountScopeRefusesAForeignAndAnAbsentAccountAlike(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool := poolFromDSN(t, setupTestDB(t))
	repo := kanamepg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kaname")
	// Воркер операции близнеца дожидается ДО закрытия пула (уборка — в обратном
	// порядке заведения).
	t.Cleanup(func() { _ = operations.Wait(context.Background()) })
	create := accessbindingapp.NewCreateAccessBindingUseCase(repo, opsRepo, catalogfixture.Source()).
		WithRelationStore(denyEveryRelation{}, nil)

	owner := mustSeedUser(t, ctx, pool, "f1owner")
	foreign := seedAccountByOwner(t, ctx, pool, "acc-f1", owner)
	stranger := mustSeedUser(t, ctx, pool, "f1stranger")
	member := mustSeedUser(t, ctx, pool, "f1member")
	absent := ids.NewID(domain.PrefixAccount)

	grantOn := func(caller domain.UserID, accID string) error {
		_, err := create.Execute(asUser(ctx, caller), domain.AccessBinding{
			SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
			RoleID: systemViewRole, ResourceType: "account", ResourceID: accID,
			Scope: domain.ScopeAccount,
		})
		return err
	}

	// Мир проверен до вопроса о предмете: чужой аккаунт есть, отсутствующего нет.
	var present, missing int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.accounts WHERE id = $1`, string(foreign)).Scan(&present))
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.accounts WHERE id = $1`, absent).Scan(&missing))
	require.Equal(t, 1, present, "«Дано»: чужой аккаунт не заведён")
	require.Zero(t, missing, "«Дано»: отсутствующий аккаунт существует")

	// Положительный близнец: владелец аккаунта отказа права не получает.
	if err := grantOn(owner, string(foreign)); err != nil {
		st, _ := status.FromError(err)
		require.NotEqual(t, codes.PermissionDenied, st.Code(), "владелец аккаунта получил отказ права: %v", err)
		require.NotEqual(t, codes.NotFound, st.Code(), "владелец аккаунта получил «нет такого»: %v", err)
	}

	errForeign := grantOn(stranger, string(foreign))
	errAbsent := grantOn(stranger, absent)
	require.Error(t, errForeign, "посторонний выдал право в чужом аккаунте")
	require.Error(t, errAbsent, "посторонний выдал право в несуществующем аккаунте")
	stForeign, ok := status.FromError(errForeign)
	require.True(t, ok, "ожидается статус gRPC: %v", errForeign)
	stAbsent, ok := status.FromError(errAbsent)
	require.True(t, ok, "ожидается статус gRPC: %v", errAbsent)

	require.Equal(t, codes.PermissionDenied, stForeign.Code(), "чужой аккаунт: %v", errForeign)
	require.Equal(t, "permission denied", stForeign.Message())
	require.Equal(t, [2]string{stForeign.Code().String(), stForeign.Message()},
		[2]string{stAbsent.Code().String(), stAbsent.Message()},
		"ответ постороннему отличает несуществующий аккаунт (%v) от чужого (%v)", errAbsent, errForeign)
}
