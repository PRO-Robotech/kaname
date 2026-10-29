// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

// delete.go — DeleteAccountUseCase.
//
// Atomic DELETE-WHERE-NOT-EXISTS на уровне repo (см. accountWriter.Delete) —
// within-service инвариант на DB-уровне (запрет #10). Worker async, как и Create.

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// DeleteAccountUseCase.
type DeleteAccountUseCase struct {
	repo    Repo
	opsRepo operations.Repo
}

// NewDeleteAccountUseCase.
func NewDeleteAccountUseCase(r Repo, opsRepo operations.Repo) *DeleteAccountUseCase {
	return &DeleteAccountUseCase{repo: r, opsRepo: opsRepo}
}

// Execute — sync id-validate + create Operation + worker doDelete.
func (u *DeleteAccountUseCase) Execute(ctx context.Context, id domain.AccountID) (*operations.Operation, error) {
	// Anti-anon floor (defence-in-depth against a mis-wired listener). WHO may
	// delete this account is decided by the MODEL, not here: the api-gateway
	// resolves account_id and Checks `v_delete@account:<id>` before iam is
	// dialed (permission catalog). The former in-service
	// `RequireOwnerMatchesPrincipal(existing.OwnerUserID)` re-decided that from
	// a DB column — narrower than the model, unrevocable, invisible to audit,
	// and unsatisfiable by any machine principal — see
	// §«Авторизация живёт в МОДЕЛИ, а не в самодельных проверках».
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(id), domain.PrefixAccount, "account"); err != nil {
		return nil, err
	}
	// Existence pre-check (NOT authz): a well-formed-but-absent id resolves to a
	// sync NotFound here instead of an async Operation error (api-conventions:
	// well-formed-но-нет → NotFound через repo.Get).
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	_, err = rd.Accounts().Get(ctx, id)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Delete account %s", id),
		&iamv1.DeleteAccountMetadata{AccountId: string(id)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}

	actor := authzguard.PrincipalUserID(ctx)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doDelete(ctx, id, actor)
	})
	return &op, nil
}

func (u *DeleteAccountUseCase) doDelete(ctx context.Context, id domain.AccountID, actor string) (*anypb.Any, error) {
	if err := shared.DoWithWriteTxVoid(ctx, u.repo,
		func(ctx context.Context, w Writer) error {
			// ПЕРВЫЙ ОПЕРАТОР — замок строки аккаунта и перечень его участников
			// (kaname#664, Р6). Членства уходят каскадом ключа
			// `memberships_account_fk`, а их указатели в модели прав — нет:
			// каскад снимает строки, не кортежи. Перечень читается под замком,
			// поэтому членство, зафиксированное конкурентно, либо ждёт снятия,
			// либо уже в перечне.
			members, lerr := w.AccountsW().LockForRemoval(ctx, id)
			if lerr != nil {
				return lerr
			}
			// Выдачи области аккаунта снимаются ЯВНО и ДО удаления его строки: у
			// выдач нет внешнего ключа на аккаунт, и удаление строки не уносит ни
			// выдачу владельца, ни её реестр выпущенного, — без отзыва бывший
			// владелец сохранил бы `admin … or owner` на снятом аккаунте. Реестр
			// читается до удаления выдач; строки снятия по нему ложатся журналом
			// ниже, одним оператором транзакции.
			fgaDeletes, rerr := revokeAccountOwnerTuples(ctx, w, id)
			if rerr != nil {
				return rerr
			}
			if derr := w.AccountsW().Delete(ctx, id); derr != nil {
				return derr
			}
			// Колонка дома участников пустеет действием ключа `users_account_fk`
			// (`ON DELETE SET NULL`, kaname#664, Р3) той же транзакцией; их
			// указатели членства снимаются намерениями здесь же.
			//
			// ЖУРНАЛ — ОДНИМ ОПЕРАТОРОМ (kaname#617): снятия выдач области,
			// указатель кластера и указатели участников ложатся одним вызовом, после
			// удаления выдач и строки аккаунта. Между операторами журнала замки строк
			// факта берутся порядком вызовов, а не общим порядком свёртки.
			fgaDeletes = append(fgaDeletes, membershipPointersOf(id, members)...)
			if perr := w.EmitFGARelationDelete(ctx, fgaDeletes); perr != nil {
				return shared.MapRepoErr(perr)
			}
			// Симметрия созданию (kacho#2055): создание со-коммитит событие реконсайла,
			// которым материализуется пообъектный кортеж владельца, — снятие обязано
			// со-коммитить ОТЗЫВ в ту же writer-tx. Каскад `ON DELETE` его не заменяет:
			// он ключуется по идентификатору ПРИВЯЗКИ, а не снятого объекта. Воркер на
			// событие зовёт `ReconcileObject`, а тот на отсутствующем объекте получает
			// пустой желаемый набор — что и есть отзыв.
			if rerr := w.EmitReconcileEvent(ctx, shared.ReconcileEventDelete, "iam.account", string(id)); rerr != nil {
				return rerr
			}
			// Audit row atomic with the DELETE (запрет #10): a rolled-back
			// delete leaves no audit row claiming the account was removed.
			return w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventAccountDeleted,
				TenantAccountID: string(id),
				Payload: map[string]any{
					"actor":         actor,
					"resource_type": "account",
					"resource_id":   string(id),
				},
			})
		}); err != nil {
		return nil, err
	}
	// DeleteOperation.response = Empty (parity с services/vpc/internal/apps/.../delete.go).
	return anypb.New(&emptypb.Empty{})
}

// membershipPointersOf — указатели членства всех участников снимаемого аккаунта
// (`iam_user:<u>#account@account:<A>`), формой снимающих (`shared.MembershipPointer`).
func membershipPointersOf(id domain.AccountID, members []domain.UserID) []service.RelationTuple {
	out := make([]service.RelationTuple, 0, len(members))
	for _, uid := range members {
		out = append(out, shared.MembershipPointer(uid, id))
	}
	return out
}

// revokeAccountOwnerTuples performs the symmetric FGA-tuple revoke for an account
// being deleted, all inside the caller's writer-tx (atomic with the account
// DELETE, ban #10):
//
//  1. For every account-scoped AccessBinding (resource_type='account',
//     resource_id=<A>) — the owner-binding co-committed by Account.Create plus any
//     other binding granted directly on the account — read its PERSISTED emitted-
//     tuple ledger (SelectEmittedTuples) and collect EXACTLY that set for revoke,
//     then DELETE the binding row (so the ledger rows cascade-drop). This is
//     the SAME byte-symmetric revoke AccessBinding.Delete performs, applied to every
//     binding the deleted account anchors.
//  2. Collect the delete of the cluster pointer
//     (cluster:cluster_root#cluster@account:<A>) — an ACCOUNT-lifecycle tuple
//     deliberately excluded from the owner-binding ledger (it must survive an
//     owner-binding revoke) but which MUST go when the account itself is deleted.
//
// FGA tuple deletes are idempotent (the drainer maps cannot_delete→success), so a
// re-run (at-least-once drain) is safe. Reads run BEFORE the account DELETE and the
// binding DELETE so the ledger rows are still present.
//
// Step 1 reads PAGES until the scope is empty. Тело дренажа живёт в
// `shared.RevokeBindingsInScope` — там же разобрано, почему каждый проход
// перечитывает ПЕРВУЮ страницу вместо следования за курсором и почему потолок
// проходов даёт отказ, а не частичную работу. Здесь эта механика намеренно не
// пересказывается: два места об одном предмете разошлись бы молча.

// accountBindingRevokePageSize — размер страницы дренажа. Оставлен здесь
// ИМЕНЕМ, а не значением: на него ссылается проба
// `delete_reconcile_test.go`, воспроизводящая область больше одной страницы.
// Значение — общее с проектом, из `shared`, чтобы два носителя области не
// разъехались границами дренажа молча.
const accountBindingRevokePageSize = shared.ScopeBindingRevokePageSize

// Строк снятия функция НЕ кладёт: набор возвращается вызывающему, который кладёт
// журнал транзакции снятия одним оператором вместе с указателями участников
// (kaname#617).
func revokeAccountOwnerTuples(ctx context.Context, w Writer, id domain.AccountID) ([]service.RelationTuple, error) {
	// Дренаж выдач области — ОБЩИЙ с проектом (`shared.RevokeBindingsInScope`):
	// страницами до опустошения, симметрично по ведомости, с громким отказом
	// вместо тихой частичной работы. Тело параметрично ровно по паре (вид
	// области, id), и второй его экземпляр разошёлся бы с первым молча.
	fgaDeletes, _, err := shared.RevokeBindingsInScope(
		ctx, w, domain.ResourceType("account"), string(id), "Account")
	if err != nil {
		return nil, err
	}
	// Указатель на кластер — кортеж жизненного цикла АККАУНТА: он намеренно не
	// значится в ведомости ни одной выдачи (обязан пережить снятие
	// owner-выдачи), но обязан уйти вместе с самим аккаунтом. Поэтому он
	// добавляется здесь, а не приходит из общего дренажа.
	fgaDeletes = append(fgaDeletes, service.RelationTuple{
		User:     "cluster:" + domain.ClusterSingletonID,
		Relation: "cluster",
		Object:   "account:" + string(id),
	})
	return fgaDeletes, nil
}
