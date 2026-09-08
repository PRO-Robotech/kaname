// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// remove_from_account.go — RemoveFromAccountUseCase: человек перестаёт состоять
// в НАЗВАННОМ аккаунте, оставаясь тем же человеком везде остальном (#1127).
//
// # Предмет — вторая строка таблицы областей директивы владельца (2026-08-23)
//
// «Тот кто пригласил может только удалить/добавить права». Три области развели
// так: собственные поля человека — его; запрет ЛИЧНОСТИ на платформе — облака
// (`identity_suspender`, #1102); снятие самой строки — тоже не аккаунта
// (`identity_remover`, #1131). Кто участвует в МОЁМ аккаунте — аккаунта, и до
// этого изменения у этой строки не было действия вовсе: у членства нет ни
// состояния приостановки, ни глагола снятия, поэтому «исключить» выражалось
// снятием выдач.
//
// Снятие выдач — НЕ исключение, и разница наблюдаема: членство оставалось,
// человек оставался в списке людей аккаунта (`UserService.List` сужается
// членствами), а предел приёма продолжал его считать.
//
// # Что этот путь НЕ делает — это граница, а не пожелание
//
// Ни одного поля строки `iam_user` он не читает на запись и не пишет. Человек,
// исключённый из аккаунта A, продолжает работать в аккаунте B с той же записью:
// тот же идентификатор, та же почта, то же состояние, те же метки. Проверяется
// вердиктом по закоммиченным строкам и пробой репозитория, а не обещанием.
//
// # Порядок «сперва права, потом участие» держит БАЗА
//
// Отложенный триггер `membership_carrying_rights_is_kept` (миграция 472002)
// отвергает снятие членства, несущего живую выдачу в этом аккаунте. Значит
// порядок — конструкция, а не дисциплина вызывающего (ban #10), а отказ приходит
// НА КОММИТЕ и отображается в FAILED_PRECONDITION с контракт-тоном
// (`repo/kaname/pg/pgmaperr.go`, ветвь 23000).
//
// # Идемпотентность — свойство предмета, а не приём
//
// Аргумент — ОТСУТСТВИЕ членства, а не переход. Исключение того, кого в аккаунте
// нет, проходит и сообщает, что его там нет. Направление, делающее систему
// строже, не может падать на повторе.
//
// # Указатель области снимается вместе с членством
//
// Заведение человека пишет в журнал прав структурный кортеж
// `iam_user:<u> # account @ account:<A>` — по нему `super_admin from account`
// доводит распорядителя аккаунта до строки личности. Оставить его после
// исключения значило бы: членства нет, человека нет в списке, а власть над его
// строкой у аккаунта осталась. Снятие идёт НАМЕРЕНИЕМ в той же транзакции, что и
// снятие строки членства (at-least-once дренаж, идемпотентно), — не post-commit
// best-effort: процесс, умерший между коммитом и вызовом, оставил бы в модели
// прав утверждение о связи, которой больше нет.

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// RemoveFromAccountUseCase — исключение человека из аккаунта.
type RemoveFromAccountUseCase struct {
	repo    Repo
	opsRepo operations.Repo
}

// NewRemoveFromAccountUseCase — конструктор.
func NewRemoveFromAccountUseCase(r Repo, opsRepo operations.Repo) *RemoveFromAccountUseCase {
	return &RemoveFromAccountUseCase{repo: r, opsRepo: opsRepo}
}

// Execute — сформировать операцию и запустить снятие членства.
func (uc *RemoveFromAccountUseCase) Execute(ctx context.Context, userID domain.UserID, accountID domain.AccountID) (*operations.Operation, error) {
	// Пол против анонима — и только он. КТО вправе исключать, решает МОДЕЛЬ:
	// край спрашивает `member_remover@account:<account_id>` до того, как наберёт
	// iam (`security.md` §«Авторизация живёт в МОДЕЛИ, а не в самодельных
	// проверках»). Вторая, рукописная проверка здесь не выдавалась бы, не
	// ограничивалась областью, не отзывалась и не понимала бы машинных
	// принципалов.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	// Формат — первым делом и по ОБОИМ идентификаторам. Оба названы вызывающим,
	// оба обязательны по форме запроса, и мусор в любом из них есть
	// синхронный INVALID_ARGUMENT, а не операция, исход которой надо потом идти
	// толковать.
	if err := shared.ValidateResourceID(string(userID), domain.PrefixUser, "user"); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(accountID), domain.PrefixAccount, "account"); err != nil {
		return nil, err
	}

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Remove user %s from account %s", userID, accountID),
		&iamv1.RemoveUserFromAccountMetadata{UserId: string(userID), AccountId: string(accountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}

	actor := authzguard.PrincipalUserID(ctx)
	operations.Run(ctx, uc.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return uc.doRemove(ctx, userID, accountID, actor)
	})
	return &op, nil
}

// membershipScopeTuple — структурный указатель «эта личность относится к этому
// аккаунту», по которому цепь областей доводит распорядителя аккаунта до строки
// человека. Форма байт-идентична той, что пишет заведение человека
// (`invite.go` / `internal_upsert.go`) и снимает удаление строки
// (`identityTuplesForRemoval`): один предмет — одна форма, иначе снятие не
// попадает в то, что записали.
func membershipScopeTuple(userID domain.UserID, accountID domain.AccountID) service.RelationTuple {
	return service.RelationTuple{
		User:     fmt.Sprintf("account:%s", accountID),
		Relation: "account",
		Object:   fmt.Sprintf("iam_user:%s", userID),
	}
}

func (uc *RemoveFromAccountUseCase) doRemove(ctx context.Context, userID domain.UserID, accountID domain.AccountID, actor string) (*anypb.Any, error) {
	if err := shared.DoWithWriteTxVoid(ctx, uc.repo,
		func(ctx context.Context, w Writer) error {
			removed, derr := w.UsersW().RemoveMembership(ctx, userID, accountID)
			if derr != nil {
				return derr
			}
			if !removed {
				// Членства не было: цель достигнута, и писать в журналы нечего.
				// Запись «исключил» о действии, которого не было, сделала бы
				// журнал прав и аудит утверждающими неправду — а отличить эти два
				// исхода потом было бы нечем.
				return nil
			}
			if terr := w.EmitFGARelationDelete(ctx,
				[]service.RelationTuple{membershipScopeTuple(userID, accountID)}); terr != nil {
				return terr
			}
			return w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventUserRemovedFromAccount,
				TenantAccountID: string(accountID),
				Payload: map[string]any{
					"actor":         actor,
					"resource_type": "user",
					"resource_id":   string(userID),
					"account_id":    string(accountID),
				},
			})
		}); err != nil {
		return nil, uc.nameBlockingGrants(ctx, err, userID, accountID)
	}
	return anypb.New(&emptypb.Empty{})
}

// nameBlockingGrants дополняет отказ «членство несёт права» перечнем выдач,
// которые его держат (задача продукта #1686).
//
// # Почему это ЗДЕСЬ, а не там, где формируется текст
//
// Триггер отложенный: отказ приходит на КОММИТЕ, и к этому моменту транзакция
// мертва — спросить у неё, что помешало, нельзя ни одним запросом. Отображение
// ошибок (`repo/kaname/pg/pgmaperr.go`) соединения не имеет вовсе и назвать может
// только то, что писатель оставил в подсказке: человека и аккаунт. Перечень
// добывается ОТДЕЛЬНЫМ чтением, и место, где есть и репозиторий, и уже
// полученный отказ, — здесь.
//
// # Это НЕ проверка-перед-снятием (ban #10)
//
// Решает по-прежнему база. Чтение идёт ПОСЛЕ отказа и только затем, чтобы отказ
// назвал предмет. Гонка между отказом и чтением законна и разрешена в сторону
// молчания: выдачи успели отозвать — перечень пуст, и отказ остаётся прежним, а
// не превращается в утверждение «мешающих выдач ноль», которого база не делала.
//
// # Отказ дочитывания не подменяет собой отказ исключения
//
// База не ответила на второе чтение — возвращается ПЕРВЫЙ отказ как есть.
// Подменить его ошибкой чтения значило бы сказать клиенту «сервис сломан» там,
// где сервис работает верно и всего лишь не смог украсить сообщение.
func (uc *RemoveFromAccountUseCase) nameBlockingGrants(
	ctx context.Context, refusal error, userID domain.UserID, accountID domain.AccountID,
) error {
	if !shared.IsMembershipCarriesRights(refusal) {
		return refusal
	}
	r, rerr := uc.repo.Reader(ctx)
	if rerr != nil {
		return refusal
	}
	defer func() { _ = r.Rollback(ctx) }()

	ids, total, lerr := r.AccessBindings().ListActiveHoldingMembership(
		ctx, userID, accountID, shared.MaxNamedBlockingGrants)
	if lerr != nil {
		return refusal
	}
	return shared.NameBlockingGrants(refusal, ids, total)
}
