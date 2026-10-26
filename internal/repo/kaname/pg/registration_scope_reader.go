// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// registration_scope_reader.go — pg-адаптер чтений вывода родителя
// регистрируемого объекта (задача PRO-Robotech/kaname#982, приёмка
// `kaname-derives-the-parent-of-a-registered-object.md`, Р4, Р5, Р12).
//
// Kaname выводит родителя объекта из своих данных: проект — строкой
// `kaname.projects`, объект-контейнер — его строкой зеркала и цепью, опору записи
// сверх указателя — фактом указателя объекта. Все три чтения исполняются на
// транзакции вызывающего, той же, что пишет регистрацию, — по первичным ключам
// (`projects_pkey`, `resource_mirror_pkey`, `resource_parent_edge_pkey`,
// префикс `relation_fact_pkey`), — и НИКОГДА на соединении пула: вывод и запись
// лежат в одном снимке.
package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// RegistrationScopeReader — адаптер порта чтений вывода родителя. Без состояния.
type RegistrationScopeReader struct{}

// NewRegistrationScopeReader — конструктор композиционного корня.
func NewRegistrationScopeReader() *RegistrationScopeReader { return &RegistrationScopeReader{} }

// ProjectAccountTx — аккаунт проекта; ok=false — строки проекта нет.
func (RegistrationScopeReader) ProjectAccountTx(ctx context.Context, tx service.Tx, projectID string) (string, bool, error) {
	var acc string
	err := txAsPgx(tx).QueryRow(ctx,
		`SELECT account_id FROM kaname.projects WHERE id = $1`, projectID).Scan(&acc)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("projects: аккаунт проекта: %w", err)
	}
	return acc, true, nil
}

// ContainerScopeTx — ЗАПИСАННАЯ область зарегистрированного объекта-контейнера
// (Р5): проект его строки зеркала, при пустом — ближайшее звено `project` его
// цепи, и аккаунт этого проекта по `kaname.projects`.
//
// Читается именно записанная область, а не факт указателя контейнера: ребёнок не
// бывает в области шире, чем записана у его контейнера (DP-14). Строки зеркала
// нет — `Registered=false`: контейнер не зарегистрирован, иерархии нет.
//
// Строка зеркала названа словарём каталога, цепь — словарём модели; переход —
// через строку каталога (живая предпочитается снятой, как у
// [CatalogTypeReader.DottedTypeTx]).
func (RegistrationScopeReader) ContainerScopeTx(
	ctx context.Context, tx service.Tx, modelType, id string,
) (domain.ContainerScope, error) {
	var scope domain.ContainerScope
	err := txAsPgx(tx).QueryRow(ctx, `
		SELECT s.project, coalesce(p.account_id, '')
		  FROM (SELECT coalesce(nullif(m.parent_project_id, ''),
		                        (SELECT e.parent_id
		                           FROM kaname.resource_parent_edge e
		                          WHERE e.object_type = $1 AND e.object_id = $2
		                            AND e.parent_type = 'project'
		                          ORDER BY e.depth
		                          LIMIT 1),
		                        '') AS project
		          FROM kaname.catalog_resource c
		          JOIN kaname.resource_mirror m ON m.object_type = c.dotted AND m.object_id = $2
		         WHERE c.object_type = $1
		         ORDER BY c.live DESC
		         LIMIT 1) s
		  LEFT JOIN kaname.projects p ON p.id = s.project`,
		modelType, id).Scan(&scope.ProjectID, &scope.AccountID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return domain.ContainerScope{}, nil
	case err != nil:
		return domain.ContainerScope{}, fmt.Errorf("resource_mirror: область контейнера %s:%s: %w", modelType, id, err)
	}
	scope.Registered = true
	return scope, nil
}

// PointerSubjectsTx — субъекты фактов указателя объекта (Р4): отношение — одно из
// имён указателей типа. Факт указателя ложится только регистрацией указателем,
// поэтому каждый субъект здесь — родитель, уже выведенный kaname. Порядок —
// по субъекту: исход не зависит от плана запроса.
func (RegistrationScopeReader) PointerSubjectsTx(
	ctx context.Context, tx service.Tx, modelType, id string, pointers []string,
) ([]string, error) {
	if len(pointers) == 0 {
		return nil, nil
	}
	rows, err := txAsPgx(tx).Query(ctx, `
		SELECT subject FROM kaname.relation_fact
		 WHERE object_type = $1 AND object_id = $2 AND relation = ANY ($3)
		 ORDER BY subject`, modelType, id, pointers)
	if err != nil {
		return nil, fmt.Errorf("relation_fact: факты указателя %s:%s: %w", modelType, id, err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("relation_fact: факты указателя %s:%s: %w", modelType, id, err)
	}
	return out, nil
}
