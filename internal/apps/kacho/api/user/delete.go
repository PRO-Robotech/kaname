// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// delete.go — DeleteUserUseCase.
//
// FK SQLSTATE 23503 на accounts_owner_fk → FailedPrecondition
// "User <id> owns accounts and cannot be deleted" (через mapErr/errors/fkText).
// GroupMember + AccessBinding — soft-ref (нет FK), но atomic DELETE WHERE NOT EXISTS
// в user_repo.Delete ловит их (within-service refs защищены на DB-уровне).

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

type DeleteUserUseCase struct {
	repo    Repo
	opsRepo operations.Repo
}

func NewDeleteUserUseCase(r Repo, opsRepo operations.Repo) *DeleteUserUseCase {
	return &DeleteUserUseCase{repo: r, opsRepo: opsRepo}
}

func (uc *DeleteUserUseCase) Execute(ctx context.Context, id domain.UserID) (*operations.Operation, error) {
	// Sync 1: format validation (cheap, no DB / no leak).
	if err := shared.ValidateResourceID(string(id), domain.PrefixUser, "user"); err != nil {
		return nil, err
	}
	// Anti-anon + self-delete-only OR account-owner-delete.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	// Load user → determine if same as principal OR principal owns user's account.
	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	target, err := rd.Users().Get(ctx, id)
	if err != nil {
		_ = rd.Rollback(ctx)
		return nil, shared.MapRepoErr(err)
	}
	// КТО ВПРАВЕ СНЯТЬ СТРОКУ ЛИЧНОСТИ, РЕШАЕТ МОДЕЛЬ, а не этот use-case: край
	// спрашивает `identity_remover@iam_user:<user_id>` до того, как наберёт iam
	// (#1131). Отношение вычисляемое — `subject or super_admin from account`, —
	// то есть выдачей оно не резолвится НИ У КОГО: сюда доходит либо сам
	// человек, либо надзор облака.
	//
	// ЗДЕСЬ СТОЯЛА ПРОВЕРКА «не сам и без аккаунта → отказ», и она была снята
	// (#1174). Её довод — «у безаккаунтного нет области, против которой можно
	// написать выдачу» — потерял предмет вместе с уходом гейта с `v_delete`:
	// выдачи здесь не бывает ни при каком аккаунте. Что она делала вместо
	// заявленного: отказывала НАДЗОРУ ОБЛАКА в снятии осиротевшей личности,
	// оставляя её неудаляемой никем, — а человек, потерявший доступ, себя не
	// удалит. Класс — security.md §«Авторизация живёт в МОДЕЛИ, а не в
	// самодельных проверках»; тем же классом #1102 снял двенадцать мест.
	//
	// ЦЕНА ИЗМЕРЕНА, А НЕ ПРЕДПОЛОЖЕНА, и она в БУДУЩЕМ ВРЕМЕНИ. Ветка была
	// НЕДОСТИЖИМА на этом дереве: `users.account_id` объявлена NOT NULL и несёт
	// внешний ключ на `accounts(id)`, аккаунта с пустым идентификатором нет ни
	// одного, поэтому вставка с пустым аккаунтом отвергается (23503) — проверено
	// прогоном против настоящей базы, а не выведено. Осиротевшая личность
	// сегодня выражается СНЯТЫМ ЧЛЕНСТВОМ (#1127), а колонка остаётся легаси.
	// Значит проверка была не действующим отказом, а ВЗВЕДЁННЫМ: она сработала
	// бы в день снятия колонки — то самое направление, которое объявляет
	// миграция 944001, — и сработала бы молча, на каждой осиротевшей строке.
	//
	// СНЯТИЕ НИЧЕГО НЕ РАСШИРЯЕТ, и это утверждается вердиктом, а не доводом: у
	// строки БЕЗ ЗВЕНА ЦЕПИ к аккаунту (осиротевшей — той, у которой снято
	// членство) вывод даёт только `subject`, поэтому посторонний и владелец
	// прежнего аккаунта по-прежнему получают отказ на крае. Проба —
	// `internal/service/removing_the_identity_integration_test.go`
	// (TestRemovingAnIdentityWithNoAccountScopeReachesOnlyTheCloud).
	_ = rd.Rollback(ctx)
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Delete user %s", id),
		// account_id from the loaded target (target.AccountID; "" for account-less
		// users → corelib writes SQL NULL → excluded from account-scoped list, D-8).
		&iamv1.DeleteUserMetadata{UserId: string(id), AccountId: string(target.AccountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}
	actor := authzguard.PrincipalUserID(ctx)
	accountID := string(target.AccountID)
	operations.Run(ctx, uc.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return uc.doDelete(ctx, id, actor, accountID)
	})
	return &op, nil
}

// identityTuplesForRemoval — кортежи МОДЕЛИ ПРАВ, чей объект есть объект
// личности: они заводятся вместе с человеком и обязаны уходить вместе с ним.
//
// Зеркалит суженный до объекта личности набор `bootstrapTuples`:
//
//	iam_user:<u> # subject @ user:<u>        — «прочитать себя» (flat-model D-4);
//	iam_user:<u> # account @ account:<A>     — указатель принадлежности, от
//	                                           которого выводится админ-уровень.
//
// Прочие кортежи создания (владение аккаунтом, админ проекта, указатели
// кластера) объектом личности НЕ являются и здесь не перечисляются: аккаунт и
// проект переживают человека. Кортеж владения к тому же недостижим по этому
// пути — `accounts_owner_fk` отвергает снятие владеющего человека немедленно.
//
// Пустой аккаунт кортежа НЕ порождает: строка вида `account: # account @ …`
// адресовала бы аккаунт, которого никто не называл. Строка человека без
// аккаунта уже существует в этом коде как отдельный случай (см. пробу про
// пустой account_id в метаданных операции).
func identityTuplesForRemoval(id domain.UserID, accountID string) []service.RelationTuple {
	tuples := []service.RelationTuple{
		{
			User:     fmt.Sprintf("user:%s", id),
			Relation: "subject",
			Object:   fmt.Sprintf("iam_user:%s", id),
		},
	}
	if accountID != "" {
		tuples = append(tuples, service.RelationTuple{
			User:     fmt.Sprintf("account:%s", accountID),
			Relation: "account",
			Object:   fmt.Sprintf("iam_user:%s", id),
		})
	}
	return tuples
}

func (uc *DeleteUserUseCase) doDelete(ctx context.Context, id domain.UserID, actor, accountID string) (*anypb.Any, error) {
	if err := shared.DoWithWriteTxVoid(ctx, uc.repo,
		func(ctx context.Context, w Writer) error {
			if derr := w.UsersW().Delete(ctx, id); derr != nil {
				return derr
			}
			// Снятие кортежей — намерением в ТОЙ ЖЕ транзакции, что и снятие
			// строки (at-least-once дренаж, идемпотентно). Не post-commit
			// best-effort: процесс, умерший между коммитом и вызовом, оставил бы
			// в модели прав утверждения о человеке, которого уже нет, и заметить
			// это было бы нечем.
			if terr := w.EmitFGARelationDelete(ctx, identityTuplesForRemoval(id, accountID)); terr != nil {
				return terr
			}
			ev := service.AuditEvent{
				EventType: auditEventUserDeleted,
				Payload: map[string]any{
					"actor":         actor,
					"resource_type": "user",
					"resource_id":   string(id),
				},
			}
			if accountID != "" {
				ev.TenantAccountID = accountID
				ev.Payload["account_id"] = accountID
			}
			return w.EmitAuditEvent(ctx, ev)
		}); err != nil {
		return nil, err
	}
	return anypb.New(&emptypb.Empty{})
}
