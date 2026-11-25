// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5"
)

// AccessLabelDeclaration задаёт одну координату в аккаунте или его проекте.
type AccessLabelDeclaration struct {
	Account, Project string
	Module, Resource string
	Key              string
	Values           []string
}

type AccessLabelDeclarationResult struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
}

// AddAccessLabelValues добавляет значения под тем же drain, что и установка
// authority bundle. Значения, отсутствующие во входе, остаются разрешёнными.
func (r *Repository) AddAccessLabelValues(ctx context.Context, d AccessLabelDeclaration) (AccessLabelDeclarationResult, error) {
	var result AccessLabelDeclarationResult
	if d.Account == "" || d.Module == "" || d.Resource == "" || len(d.Values) == 0 {
		return result, errors.New("для объявления нужны аккаунт, модуль, ресурс и хотя бы одно допустимое значение")
	}
	if err := domain.LabelKey(d.Key).Validate(); err != nil {
		return result, err
	}
	for _, v := range d.Values {
		if err := domain.LabelVal(v).Validate(); err != nil {
			return result, err
		}
	}
	scope, id := "account", d.Account
	if d.Project != "" {
		scope, id = "project", d.Project
	}
	err := r.authorityLifecycle(ctx, func(ctx context.Context, tx pgx.Tx) error {
		// Удерживаем родителя и живую координату каталога до фиксации.
		var one int
		err := tx.QueryRow(ctx, `SELECT 1 FROM ONLY kaname.accounts a WHERE a.id=$1
 AND ($2::text='' OR EXISTS (SELECT FROM ONLY kaname.projects p WHERE p.id=$2 AND p.account_id=a.id FOR SHARE OF p))
 FOR SHARE OF a`, d.Account, d.Project).Scan(&one)
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("аккаунт или принадлежащий ему проект не найден")
		}
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT 1 FROM kaname.catalog_module m JOIN kaname.catalog_resource r USING(module)
 WHERE m.module=$1 AND r.resource=$2 AND m.live AND r.live FOR SHARE OF m,r`, d.Module, d.Resource).Scan(&one)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("ресурс %s.%s отсутствует в действующем каталоге", d.Module, d.Resource)
		}
		if err != nil {
			return err
		}
		// Проверка изменения метки требует ровно одного применимого определения.
		// Удерживаем отсутствие второго определения до commit, включая вставки
		// владельца из других транзакций.
		if _, err := tx.Exec(ctx, `LOCK TABLE kaname.authority_access_label_definition IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return err
		}
		var overlap bool
		err = tx.QueryRow(ctx, `SELECT EXISTS (SELECT FROM kaname.authority_access_label_definition d
 WHERE (d.module,d.resource,d.label_key)=($1,$2,$3)
 AND ((d.scope_kind='cluster')
   OR ($5::text<>'' AND d.scope_kind='account' AND d.scope_id=$4)
   OR ($5='' AND d.scope_kind='project' AND EXISTS (
       SELECT FROM ONLY kaname.projects p WHERE p.account_id=$4 AND p.id=d.scope_id))))`,
			d.Module, d.Resource, d.Key, d.Account, d.Project).Scan(&overlap)
		if err != nil {
			return err
		}
		if overlap {
			return errors.New("у ключа уже есть определение в пересекающейся области")
		}
		_, err = tx.Exec(ctx, `INSERT INTO kaname.authority_access_label_definition(scope_kind,scope_id,module,resource,label_key)
 VALUES ($1,$2,$3,$4,$5) ON CONFLICT (scope_kind,scope_id,module,resource,label_key) DO NOTHING`, scope, id, d.Module, d.Resource, d.Key)
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT id::text FROM kaname.authority_access_label_definition
 WHERE (scope_kind,scope_id,module,resource,label_key)=($1,$2,$3,$4,$5) FOR UPDATE`, scope, id, d.Module, d.Resource, d.Key).Scan(&result.ID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO kaname.authority_access_label_value(definition_id,label_value)
 SELECT $1::uuid, v FROM unnest($2::text[]) AS v ON CONFLICT (definition_id,label_value) DO NOTHING`, result.ID, d.Values)
		if err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT revision FROM kaname.authority_access_label_definition WHERE id=$1::uuid`, result.ID).Scan(&result.Revision)
	})
	if err != nil {
		return AccessLabelDeclarationResult{}, err
	}
	return result, nil
}
