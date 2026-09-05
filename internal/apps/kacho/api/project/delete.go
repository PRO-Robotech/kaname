// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package project

// delete.go — DeleteProjectUseCase. Future: peer-callback'и для проверки
// «нет ресурсов в Project'е» (vpc/compute/loadbalancer ссылаются на project_id);
// пока — просто DELETE FROM projects.

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

type DeleteProjectUseCase struct {
	repo    Repo
	opsRepo operations.Repo
}

func NewDeleteProjectUseCase(r Repo, opsRepo operations.Repo) *DeleteProjectUseCase {
	return &DeleteProjectUseCase{repo: r, opsRepo: opsRepo}
}

func (u *DeleteProjectUseCase) Execute(ctx context.Context, id domain.ProjectID) (*operations.Operation, error) {
	// Anti-anon floor only. WHO may delete this project is decided by the MODEL:
	// the api-gateway Checks `v_delete@project:<id>` before iam is dialed. The
	// former in-service owner-equality check against the OWNING ACCOUNT's
	// owner_user_id was both coarser than that per-object relation and
	// unsatisfiable by any machine principal — security.md «Авторизация живёт в
	// МОДЕЛИ, а не в самодельных проверках».
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(id), domain.PrefixProject, "project"); err != nil {
		return nil, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	proj, err := rd.Projects().Get(ctx, id)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Delete project %s", id),
		// account_id from the loaded project (proj.AccountID in scope) → the
		// account-scoped module list surfaces this Delete op (D-8).
		&iamv1.DeleteProjectMetadata{ProjectId: string(id), AccountId: string(proj.AccountID)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}

	actor := authzguard.PrincipalUserID(ctx)
	accountID := string(proj.AccountID)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doDelete(ctx, id, actor, accountID)
	})
	return &op, nil
}

// doDelete снимает проект ЦЕЛИКОМ — строку, СДЕЛАННЫЕ НА НЕГО ВЫДАЧИ и обе
// половины его присутствия в графе прав, — одной транзакцией.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ВЫДАЧИ СНИМАЮТСЯ ЗДЕСЬ, А НЕ «УЙДУТ КАСКАДОМ»
//
// У `access_bindings` нет внешнего ключа на `projects` (ссылка мягкая,
// межресурсная — это оговорено и в `account/delete.go`), поэтому база за нас
// ничего не доделывает: строка выдачи переживает удаление проекта в состоянии
// ACTIVE, её кортежи остаются в движке, а периодический реконсайлер продолжает
// их материализовать. Доступ живёт на объект, которого нет, и снять его штатным
// путём нельзя — область, через которую привязку нашли бы, удалена.
//
// Замер на стенде в день заведения (#792): из 193 выдач, сделанных на проекты,
// 145 висели на удалённых, все ACTIVE, все на людей; под этими проектами лежало
// 80 живых объектов зеркала. Парный контроль на соседнем пути — 0 из 239 у
// аккаунта, потому что `Account.Delete` свои выдачи дренирует.
//
// Тело дренажа — ОБЩЕЕ с аккаунтом (`shared.RevokeBindingsInScope`): страницами
// до опустошения, симметрично по ведомости выпущенных кортежей, с громким
// отказом вместо тихой частичной работы. Второй экземпляр того же перечня
// разошёлся бы с первым молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СНЯТИЕ КОРТЕЖЕЙ ЖИВЁТ ЗДЕСЬ, А НЕ «ДОДЕЛАЕТСЯ САМО»
//
// Создание проекта СО-КОММИТИТ два структурных кортежа (`create.go`,
// `projectStructuralTuples`): указатель на аккаунт и указатель на кластер. Ни
// один из них не выводится из строки `projects` и ни один не снимается ничем
// внешним: реконсайлер выводит ГЛАГОЛЫ из выдач, а указатели — прямой факт,
// который кладут и снимают явно. Значит либо снимает этот код, либо не снимает
// никто.
//
// Не снимал никто. Следствие ровно то, ради чего указатель и заведён, только
// наоборот: цепь областей берёт предка проекта из проекции журнала
// (миграция 781001), поэтому выдача, сделанная на аккаунт, продолжает доходить
// до объектов под проектом, которого больше нет, а администратор облака
// продолжает видеть его через указатель на кластер. Права переживают свой
// предмет — тот же класс, что уцелевшая цепь рёбер после снятия регистрации
// (`resource_mirror.DeleteTx`) и уцелевший `owner`
// (`internal_iam/unregister_resource_residual_owner_test.go`).
//
// Снятие СИММЕТРИЧНО постановке дословно — тот же `projectStructuralTuples` от
// той же строки, а не свой перечень: второй перечень разошёлся бы с первым при
// заведении следующего звена, и разошёлся бы молча.
//
// В ТОЙ ЖЕ транзакции, что и `DELETE` (запрет #10): откатившееся удаление не
// вправе оставить снятыми права живого проекта, а удавшееся — оставить права
// снятого.
func (u *DeleteProjectUseCase) doDelete(ctx context.Context, id domain.ProjectID, actor, accountID string) (*anypb.Any, error) {
	if err := shared.DoWithWriteTxVoid(ctx, u.repo,
		func(ctx context.Context, w Writer) error {
			// Снятие ВЫДАЧ идёт ПЕРЕД удалением строки: ведомость выпущенных
			// кортежей читается, пока строки выдач ещё на месте. Отказ дренажа
			// (область сверх потолка) роняет всю транзакцию — проект остаётся
			// целым вместе со своими выдачами, а не наполовину снятым.
			bindingDeletes, _, rerr := shared.RevokeBindingsInScope(
				ctx, w, domain.ResourceType("project"), string(id), "Project")
			if rerr != nil {
				return rerr
			}
			if derr := w.ProjectsW().Delete(ctx, id); derr != nil {
				return derr
			}
			// Структурные указатели проекта в ведомости выдач по построению не
			// значатся — они кладутся создателем напрямую, поэтому снимаются
			// здесь, а не приходят из дренажа.
			fgaDeletes := append(bindingDeletes, projectStructuralTuples(domain.Project{
				ID: id, AccountID: domain.AccountID(accountID),
			})...)
			if ferr := w.EmitFGARelationDelete(ctx, fgaDeletes); ferr != nil {
				return ferr
			}
			return w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventProjectDeleted,
				TenantAccountID: accountID,
				Payload: map[string]any{
					"actor":         actor,
					"resource_type": "project",
					"resource_id":   string(id),
					"account_id":    accountID,
				},
			})
		}); err != nil {
		return nil, err
	}
	return anypb.New(&emptypb.Empty{})
}
