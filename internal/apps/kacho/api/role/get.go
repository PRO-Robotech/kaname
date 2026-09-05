// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

// get.go — GetRoleUseCase.
//
// The Role catalog has TWO visibility layers:
//   - SYSTEM roles (is_system) are the tenant-wide reference catalog floor: every
//     authenticated caller may Get them (deterministic seed ids, not tenant-secret).
//     They are NOT subject to the per-object filter: the contract declares
//     RoleService.Get `scope_filtered` (and says why NOT exempt —
//     role_service.proto), so the gateway asks no per-object question at all and
//     the whole decision, floor included, is taken here.
//   - CUSTOM roles are tenant-secret. Get enforces per-object via the SAME FGA
//     `viewer ∪ v_list` question that drives RoleService.List (read==enforce,
//     single source of truth — resolveVisibleRoleIDs), asked DIRECTLY on the one
//     role being read rather than by membership in a server-capped ListObjects
//     enumeration (internal/authzfilter). The
//     `viewer` tier cascades from the account tier so a role's creator /
//     account-admin resolves their own roles; a custom role the caller has no
//     viewer grant on (incl. a foreign account's role) → NOT_FOUND "Role <id> not
//     found" (NOT PermissionDenied — no existence leak). This makes
//     {role: Get(role) success} == {role: role ∈ List} for custom roles (parity).
//
// Why enforce in the use-case (not the interceptor): the RPC is declared
// `scope_filtered`, which is precisely the statement that the per-object
// decision belongs to the service. The gateway therefore resolves nothing here,
// and both halves — the system-role floor and the custom-role gate — live in
// this use-case, mirroring list.go.
//
// Fail-closed (security.md): a nil FGA port or an FGA error on a CUSTOM
// role Get → Unavailable; the role body (rules[] — a snapshot of another
// account's policy) is NEVER returned on the deny/error path.

import (
	"context"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

type GetRoleUseCase struct {
	repo Repo
	// cat — ЖИВЫЕ строки каталога: набор глаголов типа для превью роли (#1994).
	// Приходит ОБЯЗАТЕЛЬНЫМ параметром, а не опцией: непровязанный источник даёт
	// роль без набора, а проекция такую роль отвергает — то есть чтение отказало
	// бы целиком и в рантайме. Компилятор ловит это раньше.
	cat catalog.Source

	// relationQueries — FGA ListObjects port resolving the caller's readable-role
	// (`viewer` tier) set on iam_role. Required for CUSTOM-role Get; when nil
	// a custom-role Get fails closed (Unavailable). System-role Get never needs it.
	relationQueries clients.RelationQueries
}

func NewGetRoleUseCase(r Repo, cat catalog.Source) *GetRoleUseCase {
	return &GetRoleUseCase{repo: r, cat: cat}
}

// WithRelationStore wires the FGA ListObjects client used to enforce per-object
// visibility of CUSTOM roles (read==enforce with RoleService.List). Mirrors
// ListRolesUseCase.WithRelationStore. Without it, a custom-role Get fails closed.
func (u *GetRoleUseCase) WithRelationStore(relations clients.RelationQueries) *GetRoleUseCase {
	u.relationQueries = relations
	return u
}

func (u *GetRoleUseCase) Execute(ctx context.Context, id domain.RoleID) (domain.Role, error) {
	// malformed id → sync InvalidArgument first (before repo/FGA work).
	if err := shared.ValidateResourceID(string(id), domain.PrefixRole, "role"); err != nil {
		return domain.Role{}, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return domain.Role{}, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	out, err := rd.Roles().Get(ctx, id)
	if err != nil {
		return domain.Role{}, shared.MapRepoErr(err)
	}

	// РЕШЕНИЕ О ДОСТУПЕ — ОДНО, И УСПЕШНЫЙ ВОЗВРАТ ТОЖЕ ОДИН.
	//
	// Здесь стояли ДВА успешных возврата: системная роль выходила РАНЬШЕ, не
	// спрашивая модель вовсе. Пока у чтения не было производного поля, это было
	// безразлично; с появлением целости (#1035) оно стало ловушкой — помощник,
	// поставленный после резолва видимости, на системном пути не исполнился бы
	// НИКОГДА. Цена промаха была бы ровно мимо предмета: двенадцать ролей
	// инцидента 513001 — СИСТЕМНЫЕ, и путь снятия каталога их не задевает
	// (переселение ограничено `is_system = false`), то есть форма 513001 —
	// единственный их путь к деградации и единственный, который такая
	// расстановка глушит.
	//
	// Сведение к одному возврату делает пропущенный путь НЕПРЕДСТАВИМЫМ, а не
	// запрещённым комментарием. Решения не меняются ни на одно: системная роль
	// по-прежнему пол каталога и модель о ней не спрашивается.
	authorized := out.IsSystem
	if !authorized {
		// CUSTOM role → per-object enforce via the SAME FGA grant-set as List.
		// id ∉ set → NOT_FOUND (no existence leak); FGA error/nil port →
		// Unavailable (fail-closed).
		principal := operations.PrincipalFromContext(ctx)
		visible, verr := resolveVisibleRoleIDs(ctx, u.relationQueries, principal, []string{string(id)})
		if verr != nil {
			return domain.Role{}, verr // already a fail-closed Unavailable status
		}
		authorized = visible[string(id)]
	}
	if !authorized {
		// Ungranted custom role: same NOT_FOUND text as a non-existent role — the
		// caller cannot distinguish "exists but not yours" from "does not exist".
		return domain.Role{}, shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrNotFound, "Role %s not found", id))
	}

	// Целость считается ПОСЛЕ решения о доступе и на отказном пути не считается
	// вовсе: значение не производится для роли, которую вызывающий читать не
	// вправе.
	page := []domain.Role{out}
	if ierr := attachIntegrity(ctx, rd, u.cat, page); ierr != nil {
		return domain.Role{}, ierr
	}
	return page[0], nil
}
