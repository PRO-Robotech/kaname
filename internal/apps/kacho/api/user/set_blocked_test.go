// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// set_blocked_test.go — контракт синхронной полосы Block / Unblock плюс то, что
// они пишут в след.
//
// Эти гварды отвечают ДО порождения Operation, поэтому проверяются на
// синхронном возврате Execute — Postgres не нужен. Наблюдаемый исход (выдача
// перестаёт отвечать «да») закреплён отдельно, чёрным ящиком на реальной базе:
// здесь закрепляется ФОРМА отказов, а именно она и уезжает тихо — malformed id,
// отвеченный NotFound; неаутентифицированный, доехавший до писателя; отказ на
// приглашении, у которого нет причины словами.
//
// Оба направления получают одни и те же кейсы намеренно. Асимметрия между
// Block и Unblock — не экономия, а дверь, которую оператор находит запертой в
// худший момент.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// blkExec — пара под тестом, адресуемая единообразно, чтобы каждый кейс шёл по
// обоим направлениям без переписывания. Типы РАЗНЫЕ (перестановка в
// композиционном корне обязана не компилироваться); эта карта существует, чтобы
// разделить кейсы, а не чтобы сделать направления взаимозаменяемыми.
func blkExec(repo Repo) map[string]func(context.Context, domain.UserID) (*operations.Operation, error) {
	return map[string]func(context.Context, domain.UserID) (*operations.Operation, error){
		"block":   NewBlockUserUseCase(repo, newUpdOpsRepo()).Execute,
		"unblock": NewUnblockUserUseCase(repo, newUpdOpsRepo()).Execute,
	}
}

// Анонимный → PermissionDenied, до любого касания репозитория. Приостановить
// участие человека по распоряжению, за которое некого назвать, не должен уметь
// никто; вернуть участие — тоже.
func TestSetInviteStatus_Sync_Anonymous(t *testing.T) {
	for name, exec := range blkExec(newUpdUserRepo()) {
		t.Run(name, func(t *testing.T) {
			op, err := exec(context.Background(), domain.UserID(updUserID))
			require.Error(t, err)
			assert.Nil(t, op)
			st, ok := status.FromError(err)
			require.True(t, ok, "ожидался gRPC status; получено %v", err)
			assert.Equal(t, codes.PermissionDenied, st.Code())
		})
	}
}

// Malformed id → InvalidArgument, и это терминально. Ответить здесь NotFound
// значило бы утверждать, что ресурса нет, про строку, которая ресурсом быть не
// может.
func TestSetInviteStatus_Sync_MalformedID(t *testing.T) {
	for name, exec := range blkExec(newUpdUserRepo()) {
		t.Run(name, func(t *testing.T) {
			op, err := exec(ownerCtx(), "not-a-valid-id")
			require.Error(t, err)
			assert.Nil(t, op)
			st, ok := status.FromError(err)
			require.True(t, ok, "ожидался gRPC status; получено %v", err)
			assert.Equal(t, codes.InvalidArgument, st.Code())
			assert.Contains(t, st.Message(), "invalid user id")
		})
	}
}

// Форма верна, строки нет → NotFound контракт-тоном. Это own-read полоса: id
// называет то, чем владеет этот сервис, и у него этого нет.
func TestSetInviteStatus_Sync_NotFound(t *testing.T) {
	const absent = "usr000000000000absnt"
	for name := range blkExec(newUpdUserRepo()) {
		t.Run(name, func(t *testing.T) {
			repo := newUpdUserRepo()
			repo.getErr = iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", absent)
			op, err := blkExec(repo)[name](ownerCtx(), domain.UserID(absent))
			require.Error(t, err)
			assert.Nil(t, op)
			st, ok := status.FromError(err)
			require.True(t, ok, "ожидался gRPC status; получено %v", err)
			assert.Equal(t, codes.NotFound, st.Code())
			assert.Contains(t, st.Message(), "User "+absent+" not found")
		})
	}
}

// Приглашение, которое ещё никто не подтвердил, не блокируется и не
// «разблокируется»: у такой строки нет внешней личности, и переводить её в
// действующую — это активация при первом входе, другой путь с другим предметом.
//
// Отказ СИНХРОННЫЙ и с причиной словами. Назвать его «заблокирован» значило бы
// отправить администратора снимать запрет, которого нет.
func TestSetInviteStatus_Sync_PendingRefused(t *testing.T) {
	for name := range blkExec(newUpdUserRepo()) {
		t.Run(name, func(t *testing.T) {
			repo := newUpdUserRepo()
			repo.user.InviteStatus = domain.InviteStatusPending
			repo.user.ExternalID = "" // как того требует DB-CHECK консистентности

			op, err := blkExec(repo)[name](ownerCtx(), domain.UserID(updUserID))
			require.Error(t, err)
			assert.Nil(t, op, "отказ до порождения Operation")
			st, ok := status.FromError(err)
			require.True(t, ok, "ожидался gRPC status; получено %v", err)
			assert.Equal(t, codes.FailedPrecondition, st.Code())
			assert.Contains(t, st.Message(), "User "+updUserID+" is not active")

			assert.Zero(t, repo.stateWrites(),
				"писатель не должен быть вызван вовсе — иначе отказ синхронным не является")
			assert.Empty(t, repo.auditSnapshot(),
				"отвергнутый вызов не оставляет записи о событии: событие — про то, что "+
					"произошло, а не про то, что попросили и отказали")
		})
	}
}

// Идемпотентность ПО СОСТОЯНИЮ: запрет уже запрещённого проходит и оставляет
// строку там же. Направление, делающее систему безопаснее, не может быть тем,
// которое падает на повторе.
//
// И след пишется НА ПОВТОРЕ тоже: кто-то, у кого есть право, попросил, и «кто
// пытался и когда» — ровно то, для чего след. Повтор без записи — повтор,
// которого никто не видит.
func TestSetInviteStatus_IdempotentByState_AndStillAudited(t *testing.T) {
	repo := newUpdUserRepo()
	repo.user.InviteStatus = domain.InviteStatusBlocked

	uc := NewBlockUserUseCase(repo, newUpdOpsRepo())
	op, err := uc.Execute(ownerCtx(), domain.UserID(updUserID))
	require.NoError(t, err, "аргумент — состояние, а не переход: повтор обязан проходить")
	require.NotNil(t, op)
	require.NoError(t, operations.Wait(context.Background()))

	assert.Equal(t, 1, repo.stateWrites())
	audits := repo.auditSnapshot()
	require.Len(t, audits, 1, "повтор тоже оставляет запись о событии")
	assert.Equal(t, "iam.user.blocked", audits[0].EventType)
	assert.Equal(t, string(domain.InviteStatusBlocked), audits[0].Payload["invite_status"])
}

// След называет КОГО и КОГО ИМЕННО, и не несёт персональных данных.
//
// Актор берётся из проверенной личности вызывающего, а не из тела запроса — тело
// его вообще не содержит. Ни почты, ни отображаемого имени: они изменяемы и
// персональны, а правдой через год остаётся id.
func TestSetInviteStatus_AuditNamesActorAndSubject_NoPII(t *testing.T) {
	for name, want := range map[string]string{
		"block":   "iam.user.blocked",
		"unblock": "iam.user.unblocked",
	} {
		t.Run(name, func(t *testing.T) {
			repo := newUpdUserRepo()
			op, err := blkExec(repo)[name](ownerCtx(), domain.UserID(updUserID))
			require.NoError(t, err)
			require.NotNil(t, op)
			require.NoError(t, operations.Wait(context.Background()))

			audits := repo.auditSnapshot()
			require.Len(t, audits, 1)
			ev := audits[0]

			assert.Equal(t, want, ev.EventType, "у каждого направления своё событие")
			assert.Equal(t, updAccountID, ev.TenantAccountID,
				"tenant_account_id — поле события, аккаунт строки членства")
			assert.Equal(t, updOwnerID, ev.Payload["actor"], "след называет КТО")
			assert.Equal(t, "user", ev.Payload["resource_type"])
			assert.Equal(t, updUserID, ev.Payload["resource_id"], "след называет КОГО")
			assert.Equal(t, updAccountID, ev.Payload["account_id"])
			assert.NotEmpty(t, ev.Payload["invite_status"], "и состояние, в котором строка осталась")

			for _, k := range []string{"email", "display_name", "displayName", "external_id"} {
				assert.NotContains(t, ev.Payload, k,
					"персональные и изменяемые поля в след не пишутся: %s", k)
			}
			assert.NotContains(t, ev.Payload, "name")
		})
	}
}

// Направление реально доезжает до писателя: Block оставляет строку
// запрещённой, Unblock — действующей. Проба существует потому, что общая
// реализация на два направления — ровно то место, где перепутанный аргумент
// делает контроль своей противоположностью, и ни один из кейсов выше этого не
// заметил бы.
func TestSetInviteStatus_EachDirectionWritesItsOwnState(t *testing.T) {
	t.Run("block", func(t *testing.T) {
		repo := newUpdUserRepo() // seeded ACTIVE
		_, err := NewBlockUserUseCase(repo, newUpdOpsRepo()).Execute(ownerCtx(), domain.UserID(updUserID))
		require.NoError(t, err)
		require.NoError(t, operations.Wait(context.Background()))
		assert.Equal(t, domain.InviteStatusBlocked, repo.user.InviteStatus)
	})
	t.Run("unblock", func(t *testing.T) {
		repo := newUpdUserRepo()
		repo.user.InviteStatus = domain.InviteStatusBlocked
		_, err := NewUnblockUserUseCase(repo, newUpdOpsRepo()).Execute(ownerCtx(), domain.UserID(updUserID))
		require.NoError(t, err)
		require.NoError(t, operations.Wait(context.Background()))
		assert.Equal(t, domain.InviteStatusActive, repo.user.InviteStatus)
	})
}
