// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// system_class_repo.go — чтения и страж записи, которые нужны выдаче
// системному классу (приёмка anonymous-and-authenticated-are-subject-classes.md,
// kaname#829): окно свежести выдающего (SC-25) и правило «роль, выданная
// классу, только читает» на правке роли (SC-22).

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// roleBoundToSystemClassQ — роль выдана системному классу НЕОТОЗВАННОЙ выдачей.
// Истёкшая, но не отозванная выдача считается: её снимет развёртка срока, а до
// того она — выдача (решать «уже не действует» за неё значило бы открыть окно,
// в котором правка роли проходит, а выдача ещё отвечает).
const roleBoundToSystemClassQ = `
SELECT EXISTS (
    SELECT 1
      FROM access_binding_subjects bs
      JOIN access_bindings b ON b.id = bs.binding_id
     WHERE b.role_id = $1
       AND bs.subject_type = 'system_class'
       AND b.revoked_at IS NULL
       AND b.status <> 'REVOKED')`

// BoundToSystemClass — см. role.ReaderIface.
func (r *roleReader) BoundToSystemClass(ctx context.Context, id domain.RoleID) (bool, error) {
	var bound bool
	if err := r.tx.QueryRow(ctx, roleBoundToSystemClassQ, string(id)).Scan(&bound); err != nil {
		return false, mapErr(err, "", string(id))
	}
	return bound, nil
}

// GuardSystemClassReads — последнее слово правки роли о системном классе (Р4,
// SC-22, разбор CE-17).
//
// Строка роли берётся под `FOR NO KEY UPDATE` ДО вопроса о выдачах. Это и есть
// сериализация с выдачей классу: страж выдачи
// (`kaname.access_binding_subject_class_reads_only`) берёт ту же строку под
// `FOR SHARE`, а два этих замка несовместимы. Поэтому из двух параллельных
// сторон вторая ждёт первую и видит её итог: правка — выдачу (вопрос ниже
// задаётся новым оператором и в READ COMMITTED берёт свежий снимок), выдача —
// новые правила роли. Проходит ровно одна.
//
// `FOR NO KEY UPDATE`, а не `FOR UPDATE`: внешний ключ выдачи на роль держит
// `FOR KEY SHARE`, и более сильный замок здесь ждал бы его, пока выдача сама
// ждёт этот — взаимное ожидание вместо очереди.
//
// readsOnly — новые правила роли только читают ([domain.Role.GrantsReadsOnly]);
// тогда правка законна при любых выдачах, и вопрос не задаётся.
func (w *roleWriter) GuardSystemClassReads(ctx context.Context, id domain.RoleID, readsOnly bool) error {
	var one int
	err := w.tx.QueryRow(ctx, `SELECT 1 FROM roles WHERE id = $1 FOR NO KEY UPDATE`, string(id)).Scan(&one)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return iamerr.Wrapf(iamerr.ErrNotFound, "Role %s not found", id)
		}
		return mapErr(err, "", string(id))
	}
	if readsOnly {
		return nil
	}
	var bound bool
	if err := w.tx.QueryRow(ctx, roleBoundToSystemClassQ, string(id)).Scan(&bound); err != nil {
		return mapErr(err, "", string(id))
	}
	if bound {
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "%s", domain.RoleBoundToSystemClassText(id))
	}
	return nil
}

// GrantorLastPresentedAt — см. access_binding.ReaderIface.
func (r *abReader) GrantorLastPresentedAt(ctx context.Context, userID domain.UserID) (time.Time, bool, error) {
	var at *time.Time
	err := r.tx.QueryRow(ctx, `
		SELECT max(last_presented_at) FROM human_sessions
		 WHERE user_id = $1 AND ended_at IS NULL AND expires_at > now()`, string(userID)).Scan(&at)
	if err != nil {
		return time.Time{}, false, mapErr(err, "", "")
	}
	if at == nil {
		return time.Time{}, false, nil
	}
	return at.UTC(), true, nil
}

// publicReadContainerQ — признак контейнера у живой строки типа и живые типы,
// чей указатель называет его тип модели. Строки детей берутся тем же отбором
// `live`, каким определено живое множество каталога.
const publicReadContainerQ = `
SELECT c.public_read_to_children,
       coalesce(array_agg(ch.dotted ORDER BY ch.dotted) FILTER (WHERE ch.dotted IS NOT NULL), '{}')
  FROM kaname.catalog_resource c
  LEFT JOIN kaname.catalog_resource ch
         ON ch.live AND c.object_type = ANY (ch.parent_types)
 WHERE c.dotted = $1 AND c.live
 GROUP BY c.public_read_to_children`

// classGrantsKeyedModulesQ — живые модули с ключом S7 и их живые типы (kaname#950).
//
// LEFT JOIN намеренно: модуль с ключом без единого живого типа — законная строка
// ответа, и его тип цели, которого каталог не знает, ворота обязаны отвергнуть,
// а не пропустить за неимением строки. Порядок назначает домен
// (`ClassGrantsKeyedModules.Sorted`), а не сравнение строк СУБД: порядок имён —
// часть текста отказа.
const classGrantsKeyedModulesQ = `
SELECT m.module, r.resource, r.public_read_to_children
  FROM kaname.catalog_module m
  LEFT JOIN kaname.catalog_resource r
         ON r.module = m.module AND r.live
 WHERE m.live AND m.class_grants_only_on_containers`

// ClassGrantsKeyedModules — см. access_binding.ReaderIface.
func (r *abReader) ClassGrantsKeyedModules(ctx context.Context) (domain.ClassGrantsKeyedModules, error) {
	rows, err := r.tx.Query(ctx, classGrantsKeyedModulesQ)
	if err != nil {
		return nil, mapErr(err, "", "")
	}
	defer rows.Close()
	out := domain.ClassGrantsKeyedModules{}
	for rows.Next() {
		var (
			module    string
			resource  *string
			container *bool
		)
		if err := rows.Scan(&module, &resource, &container); err != nil {
			return nil, mapErr(err, "", "")
		}
		types := out[module]
		if resource != nil {
			types = append(types, domain.ClassGrantsModuleType{Resource: *resource, Container: container != nil && *container})
		}
		out[module] = types
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", "")
	}
	return out.Sorted(), nil
}

// PublicReadContainer — см. access_binding.ReaderIface.
func (r *abReader) PublicReadContainer(ctx context.Context, dottedType string) (domain.PublicReadContainer, error) {
	// Тип, о котором ответ, едет в ответе (kaname#874): по нему ворота находят
	// вложенные правила, стоящие под ЭТИМ типом. Тип вне каталога — ответ «не
	// объявлен» о том же типе, а не пустой.
	out := domain.PublicReadContainer{Type: dottedType}
	err := r.tx.QueryRow(ctx, publicReadContainerQ, dottedType).Scan(&out.Declared, &out.ChildTypes)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.PublicReadContainer{Type: dottedType}, nil
	}
	if err != nil {
		return domain.PublicReadContainer{}, mapErr(err, "", "")
	}
	return out, nil
}
