// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"regexp"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

var grantCapabilityFP = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ReplaceGrantCapabilities заменяет обе проекции в текущей транзакции записи.
// Полномочия, видимость и жизненный цикл здесь не проверяются.
// При любой ошибке вызывающий обязан откатить всю транзакцию, как и для
// остальных Replace* портов; метод не фиксирует и не открывает транзакцию.
func (w *roleWriter) ReplaceGrantCapabilities(ctx context.Context, ownerRoleID domain.RoleID, specs []domain.GrantCapabilityRule) error {
	// Проверяем весь ввод до удаления проекций. Неизвестный вид отклоняется,
	// даже если его содержимое дало бы пустую проекцию.
	var creates, bindFPs, bindRoles []string
	seen := make(map[domain.GrantCapabilityRule]struct{}, len(specs))
	for _, spec := range specs {
		switch spec.Kind {
		case domain.GrantCapabilityCreateBinding:
			if spec.BoundRoleID != "" {
				return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument grant capabilities: create-binding cannot name a role")
			}
		case domain.GrantCapabilityBindRole:
			if spec.BoundRoleID == "" || spec.BoundRoleID == "*" {
				return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument grant capabilities: bind-role requires an explicit role")
			}
		default:
			return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument grant capabilities: unknown kind")
		}
		if !grantCapabilityFP.MatchString(spec.RuleFP) {
			return iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument grant capabilities: invalid rule fingerprint")
		}
		if _, exists := seen[spec]; exists {
			continue
		}
		seen[spec] = struct{}{}
		if spec.Kind == domain.GrantCapabilityCreateBinding {
			creates = append(creates, spec.RuleFP)
		} else {
			bindFPs = append(bindFPs, spec.RuleFP)
			bindRoles = append(bindRoles, string(spec.BoundRoleID))
		}
	}
	if _, err := w.tx.Exec(ctx, `DELETE FROM kaname.role_create_binding_rule WHERE role_id = $1`, string(ownerRoleID)); err != nil {
		return mapErr(err, "", "")
	}
	if _, err := w.tx.Exec(ctx, `DELETE FROM kaname.role_bind_role_rule WHERE role_id = $1`, string(ownerRoleID)); err != nil {
		return mapErr(err, "", "")
	}
	// Пакетная запись ограничивает размер одного SQL-запроса. Дубликаты
	// сохраняют семантику логического объединения.
	const chunkSize = 512
	for start := 0; start < len(creates); start += chunkSize {
		end := min(start+chunkSize, len(creates))
		if _, err := w.tx.Exec(ctx, `INSERT INTO kaname.role_create_binding_rule (role_id, rule_fp)
            SELECT $1, fp FROM unnest($2::text[]) AS u(fp)
            ON CONFLICT DO NOTHING`, string(ownerRoleID), creates[start:end]); err != nil {
			return mapErr(err, "", "")
		}
	}
	for start := 0; start < len(bindFPs); start += chunkSize {
		end := min(start+chunkSize, len(bindFPs))
		if _, err := w.tx.Exec(ctx, `INSERT INTO kaname.role_bind_role_rule (role_id, rule_fp, bound_role_id)
            SELECT $1, fp, target FROM unnest($2::text[], $3::text[]) AS u(fp, target)
            ON CONFLICT DO NOTHING`, string(ownerRoleID), bindFPs[start:end], bindRoles[start:end]); err != nil {
			// Для обоих FK действует существующая непрозрачная ошибка ссылки.
			// Идентификаторы и диагностика pgx не попадают в подсказки.
			return mapErr(err, "", "")
		}
	}
	return nil
}
