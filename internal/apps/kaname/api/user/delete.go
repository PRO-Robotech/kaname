// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// delete.go — DeleteUserUseCase.
//
// Порядок снятия «аккаунт → личность» (kaname#664, приёмка
// `own-account-and-identity-are-removed-in-order.md`): владеющий аккаунтом
// человек получает FailedPrecondition "User <id> owns accounts and cannot be
// deleted" — шаг назван, снять аккаунт; после снятия аккаунта колонка дома пуста
// (`users_account_fk ON DELETE SET NULL`), и снятие личности проходит.
// Действующие выдачи и членство в группах отвергаются atomic DELETE WHERE NOT
// EXISTS в user_repo.Delete (within-service refs защищены на DB-уровне);
// отозванная выдача — история и снятия не держит (Р10).
//
// Транзакция снятия, по порядку: замок строки и перечень членств (Р6) →
// отсечка субъекта (Р5) → снятие строки (каскад сессий, способов входа,
// ключей, кодов, личных токенов, членств) → намерения снятия кортежей объекта
// личности, включая указатели ВСЕХ членств → событие реконсайла → аудит.

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/service"
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
	// (kacho#1131). Отношение вычисляемое — `subject or super_admin from account`, —
	// то есть выдачей оно не резолвится НИ У КОГО: сюда доходит либо сам
	// человек, либо надзор облака.
	//
	// ЗДЕСЬ СТОЯЛА ПРОВЕРКА «не сам и без аккаунта → отказ», и она была снята
	// (kacho#1174). Её довод — «у безаккаунтного нет области, против которой можно
	// написать выдачу» — потерял предмет вместе с уходом гейта с `v_delete`:
	// выдачи здесь не бывает ни при каком аккаунте. Что она делала вместо
	// заявленного: отказывала НАДЗОРУ ОБЛАКА в снятии осиротевшей личности,
	// оставляя её неудаляемой никем, — а человек, потерявший доступ, себя не
	// удалит. Класс — §«Авторизация живёт в МОДЕЛИ, а не в
	// самодельных проверках»; тем же классом kacho#1102 снял двенадцать мест.
	//
	// ЦЕНА БЫЛА В БУДУЩЕМ ВРЕМЕНИ — и это время наступило. Пока
	// `users.account_id` была NOT NULL с ключом RESTRICT, строка без дома была
	// непредставима, и снятая проверка была взведённой, а не действующей. С
	// kaname#664 колонка допускает NULL, а ключ — `ON DELETE SET NULL`: снятие
	// аккаунта оставляет его участников без дома, и надзор облака снимает такую
	// личность (KN664-39) — ровно тот путь, который проверка бы закрыла.
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
//	                                           которого выводится админ-уровень,
//	                                           — для КАЖДОГО членства человека.
//
// Указатели снимаются по перечню членств, прочитанному под замком строки
// (`LockForRemoval`), а не по колонке дома: колонка называет один аккаунт из
// многих, и указатели прочих членств переживали бы человека (kaname#664, Р6).
//
// Прочие кортежи создания (владение аккаунтом, админ проекта, указатели
// кластера) объектом личности НЕ являются и здесь не перечисляются: аккаунт и
// проект переживают человека. Кортеж владения к тому же недостижим по этому
// пути — `accounts_owner_fk` отвергает снятие владеющего человека немедленно.
//
// Пустой аккаунт кортежа НЕ порождает: строка вида `account: # account @ …`
// адресовала бы аккаунт, которого никто не называл. Человек без членств (и без
// дома) снимает только самокортеж.
func identityTuplesForRemoval(id domain.UserID, memberOf []domain.AccountID) []service.RelationTuple {
	tuples := []service.RelationTuple{
		{
			User:     fmt.Sprintf("user:%s", id),
			Relation: "subject",
			Object:   fmt.Sprintf("iam_user:%s", id),
		},
	}
	for _, acc := range memberOf {
		if acc == "" {
			continue
		}
		tuples = append(tuples, shared.MembershipPointer(id, acc))
	}
	return tuples
}

func (uc *DeleteUserUseCase) doDelete(ctx context.Context, id domain.UserID, actor, accountID string) (*anypb.Any, error) {
	if err := shared.DoWithWriteTxVoid(ctx, uc.repo,
		func(ctx context.Context, w Writer) error {
			// ПЕРВЫЙ ОПЕРАТОР — замок строки человека и перечень его членств
			// (Р6): новое членство ссылается на строку внешним ключом и потому
			// либо ждёт фиксации снятия, либо уже в перечне.
			memberOf, lerr := w.UsersW().LockForRemoval(ctx, id)
			if lerr != nil {
				return lerr
			}
			// Отсечка субъекта (Р5) — до снятия строки: первая запись держится
			// ключом на человека и уходит каскадом ниже, вторая переживает его и
			// отвергает на предъявлении всё, выданное до этого момента. Отказ
			// снятия ниже откатывает и её — отвергнутое снятие ничего не обрывает.
			//
			// Момент — часы базы этой транзакции после замка строки, тем же
			// источником, что у сбросов: неустановленный момент — отказ
			// UNAVAILABLE с фиксированным текстом, а не нулевая отсечка (нулевая
			// не отсекла бы ничего).
			at, merr := revocationpolicy.Moment(ctx, w.UsersW())
			if merr != nil {
				slog.ErrorContext(ctx, "DeleteUser: cutoff moment unavailable",
					"step", "cutoff-moment", "class", revocationpolicy.MomentFailureClass(merr))
				return status.Error(codes.Unavailable, shared.MomentUnavailableMessage)
			}
			revokedBy := domain.UserID(actor)
			if cerr := w.UsersW().CutOffForRemoval(ctx, domain.UserTokenRevocation{
				UserID: id, RevokeBefore: at, Reason: domain.RevokeReasonIdentityRemoved, RevokedBy: revokedBy,
			}, revokedBy); cerr != nil {
				return cerr
			}
			if derr := w.UsersW().Delete(ctx, id); derr != nil {
				return derr
			}
			// Снятие кортежей — намерением в ТОЙ ЖЕ транзакции, что и снятие
			// строки (at-least-once дренаж, идемпотентно). Не post-commit
			// best-effort: процесс, умерший между коммитом и вызовом, оставил бы
			// в модели прав утверждения о человеке, которого уже нет, и заметить
			// это было бы нечем.
			if terr := w.EmitFGARelationDelete(ctx, identityTuplesForRemoval(id, memberOf)); terr != nil {
				return terr
			}
			// Симметрия созданию (kacho#2055): создание со-коммитит событие
			// реконсайла, которым материализуется пообъектный кортеж владельца,
			// — снятие обязано со-коммитить ОТЗЫВ в ту же writer-tx. Каскад
			// `ON DELETE` его не заменяет: он ключуется по идентификатору
			// ПРИВЯЗКИ, а не снятого объекта. Воркер на событие зовёт
			// `ReconcileObject`, а тот на отсутствующем объекте получает пустой
			// желаемый набор — что и есть отзыв.
			// Снятие названных кортежей личности выше — НЕ то же самое: оно
			// снимает выписанный набор, а событие отзывает пообъектные кортежи,
			// которые материализовали ПРИВЯЗКИ на этом объекте.
			if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventDelete, "iam.user", string(id)); rerr != nil {
				return rerr
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
