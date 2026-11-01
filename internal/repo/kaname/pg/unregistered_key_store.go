// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// unregistered_key_store.go — хранилище отзыва по снятию регистрации объекта
// (kaname#963, приёмка `unregistration-revokes-its-grants.md`, Р1, Р6, Р7).
//
// Все операторы исполняются в транзакции СНЯТИЯ (её открывает
// `RegisterResourceUseCase.Unregister`): отзыв, сужение выдачи и сужение роли
// фиксируются вместе со снятием строки зеркала или не фиксируются вовсе (Р1).
// Решения — какую выдачу отозвать, какую сузить, что стало с правилами роли —
// принимает use-case; здесь только чтения под замком и записи.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// UnregisteredKeyStore — pg-хранилище отзыва по снятию регистрации. Без
// состояния: каждый оператор идёт в транзакции вызывающего.
type UnregisteredKeyStore struct{}

// NewUnregisteredKeyStore — композиционный корень.
func NewUnregisteredKeyStore() *UnregisteredKeyStore { return &UnregisteredKeyStore{} }

// WriterOn — писатель хранилища поверх УЖЕ ОТКРЫТОЙ транзакции снятия. Ни
// фиксировать, ни откатывать её вызывающий через него не вправе: транзакцией
// владеет снятие.
func (s *UnregisteredKeyStore) WriterOn(tx service.Tx) kanamerepo.Writer {
	return &writeTx{readTx: readTx{tx: txAsPgx(tx)}}
}

// liveBinding — ОДНО условие «выдача не отозвана» для отбора и для CAS отзыва и
// сужения. Отбор и CAS на разных условиях пропускали бы молча строку, которая
// проходит одно и не проходит другое. Условие — `revoked_at IS NULL`: схема держит
// его равносильным «статус PENDING или ACTIVE» (`access_bindings_revoked_consistency_ck`),
// поэтому ожидающая выдача на снятый ключ отзывается так же, как действующая, — она
// называет объект, которого нет. Второго сравнения со статусом нет намеренно: оно
// дало бы планировщику индекс по статусу, и поиск ушёл бы с частичного индекса
// `access_bindings_target_resources_live_idx`, чьё условие — ровно это (замер —
// `TestUnregistrationLookupUsesIndexes` на операторе хранилища).
const liveBinding = `revoked_at IS NULL`

// BindingsNamingKeySQL — оператор поиска выдач по снятому ключу ($1 — тип, $2 — id).
// Экспортирован ради пробы плана (`TestUnregistrationLookupUsesIndexes`): она судит
// этот самый текст, а не свою копию.
//
// `FOR UPDATE`, а не `FOR NO KEY UPDATE` — намеренно (kaname#963, F1): только этот
// режим конфликтует с `FOR KEY SHARE`, под которым проход материализации после
// создания читает выдачу (`abReader.GetForKeyShare`). Слабее — и проход, прочитавший
// выдачу ACTIVE, писал бы член, реестр выпущенного и факт после этого отзыва. Цена —
// на время снятия встают вставки, берущие на этих строках `FOR KEY SHARE`; строк —
// только выдачи, называющие снятый ключ.
const BindingsNamingKeySQL = `SELECT id FROM kaname.access_bindings
		  WHERE ` + liveBinding + `
		    AND target -> 'resources' @> jsonb_build_array(jsonb_build_object('type', $1::text, 'id', $2::text))
		  ORDER BY id
		    FOR UPDATE`

// ActiveBindingsNamingKey — действующие выдачи, цель которых называет ключ, под
// `FOR UPDATE`, в порядке id (два снятия одного набора выдач берут замки в одном
// порядке, URG-28). Поиск — индексом `access_bindings_target_resources_live_idx`.
func (s *UnregisteredKeyStore) ActiveBindingsNamingKey(ctx context.Context, tx service.Tx, key domain.ResourceRef) ([]domain.AccessBindingID, error) {
	rows, err := txAsPgx(tx).Query(ctx, BindingsNamingKeySQL, key.Type, key.ID)
	if err != nil {
		return nil, mapErr(err, "", key.ID)
	}
	defer rows.Close()
	var out []domain.AccessBindingID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, mapErr(err, "", key.ID)
		}
		out = append(out, domain.AccessBindingID(id))
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", key.ID)
	}
	return out, nil
}

// BindingsNamingKeysSQL — замок выдач, цель которых называет ЛЮБОЙ из ключей
// ($1 — типы, $2 — id, попарно), одним оператором в порядке id (kaname#1019).
// Режим тот же, что у BindingsNamingKeySQL, — `FOR UPDATE` (kaname#963, F1).
// Поиск по каждому ключу — тем же условием и тем же частичным индексом
// `access_bindings_target_resources_live_idx`, что у одиночного оператора
// (боковое подзапросное соединение, по ключу — свой проход индекса); замок берёт
// внешний выбор, поэтому порядок замков — порядок id по всему набору, а не по
// ключам. Экспортирован ради пробы плана, как BindingsNamingKeySQL.
const BindingsNamingKeysSQL = `SELECT b.id FROM kaname.access_bindings b
		  WHERE b.` + liveBinding + `
		    AND b.id IN (
		        SELECT n.id
		          FROM unnest($1::text[], $2::text[]) AS k(type, id)
		          CROSS JOIN LATERAL (
		                SELECT x.id FROM kaname.access_bindings x
		                 WHERE x.` + liveBinding + `
		                   AND x.target -> 'resources' @> jsonb_build_array(jsonb_build_object('type', k.type, 'id', k.id))) n)
		  ORDER BY b.id
		    FOR UPDATE OF b`

// RolesNamingKeysSQL — замок ролей, правило которых называет ЛЮБОЙ из ключей в
// `resourceNames`, одним оператором в порядке id (kaname#1019); режим и индекс —
// те же, что у RolesNamingKeySQL.
const RolesNamingKeysSQL = `SELECT r.id FROM kaname.roles r
		  WHERE r.id IN (
		        SELECT s.role_id
		          FROM unnest($1::text[], $2::text[]) AS k(type, id)
		          JOIN kaname.role_rule_selectors s
		            ON s.resource_names @> ARRAY[k.id] AND k.type = ANY (s.object_types))
		  ORDER BY r.id
		    FOR UPDATE OF r`

// keyColumns — типы и id ключей двумя параллельными массивами (параметры
// BindingsNamingKeysSQL и RolesNamingKeysSQL).
func keyColumns(keys []domain.ResourceRef) (types, ids []string) {
	types, ids = make([]string, len(keys)), make([]string, len(keys))
	for i, k := range keys {
		types[i], ids[i] = k.Type, k.ID
	}
	return types, ids
}

// LockBindingsNamingKeys — замок выдач, называющих любой из ключей (kaname#1019).
func (s *UnregisteredKeyStore) LockBindingsNamingKeys(ctx context.Context, tx service.Tx, keys []domain.ResourceRef) error {
	// Каталог и регистрация входят в тот же fence до строк каталога/зеркала.
	// Он нужен до выдач и ролей: применение каталога затем проверяет FK ролей.
	if _, err := txAsPgx(tx).Exec(ctx, registrationWriterLockSQL); err != nil {
		return mapErr(err, "", "")
	}
	types, ids := keyColumns(keys)
	if _, err := txAsPgx(tx).Exec(ctx, BindingsNamingKeysSQL, types, ids); err != nil {
		return mapErr(err, "", "")
	}
	return nil
}

// LockRolesNamingKeys — замок ролей, называющих любой из ключей (kaname#1019).
func (s *UnregisteredKeyStore) LockRolesNamingKeys(ctx context.Context, tx service.Tx, keys []domain.ResourceRef) error {
	types, ids := keyColumns(keys)
	if _, err := txAsPgx(tx).Exec(ctx, RolesNamingKeysSQL, types, ids); err != nil {
		return mapErr(err, "", "")
	}
	return nil
}

// RevokeForUnregistered — отзыв по снятию регистрации: `REVOKED`, `revoked_at`,
// причина `RESOURCE_UNREGISTERED`, `revoked_by_user_id` пуст (отозвал не
// человек). Защита от удаления не условие (Р1 (в)): она — от удаления и отзыва
// пользователем, а не от жизненного цикла объекта. CAS по `liveBinding` — том же
// условии, что у отбора: параллельный отзыв глаголом, выигравший строку, делает
// этот оператор пустым (ok=false, URG-27).
func (s *UnregisteredKeyStore) RevokeForUnregistered(ctx context.Context, tx service.Tx, id domain.AccessBindingID) (bool, error) {
	tag, err := txAsPgx(tx).Exec(ctx,
		`UPDATE kaname.access_bindings
		    SET status = 'REVOKED', revoked_at = now(), revocation_reason = 'RESOURCE_UNREGISTERED'
		  WHERE id = $1 AND `+liveBinding, string(id))
	if err != nil {
		return false, mapErr(err, "AccessBinding.RevokeForUnregistered", string(id))
	}
	return tag.RowsAffected() == 1, nil
}

// NarrowTarget — сужение цели действующей выдачи (Р1 (б)): новая цель, её
// отпечаток и отметка сужения, по которой индекс уникальности суженную выдачу
// не судит (Д4). Опустевшую цель сюда не передают (Д3) — это отзыв.
func (s *UnregisteredKeyStore) NarrowTarget(ctx context.Context, tx service.Tx, id domain.AccessBindingID, target domain.AccessTarget) (bool, error) {
	if len(target.Resources) == 0 {
		return false, iamerr.Wrapf(iamerr.ErrInternal, "narrowing access binding %s to an empty target", id)
	}
	targetJSON, err := relverdict.EncodeTarget(target)
	if err != nil {
		return false, fmt.Errorf("narrow target %s: %w", id, err)
	}
	tag, err := txAsPgx(tx).Exec(ctx,
		`UPDATE kaname.access_bindings
		    SET target = $2::jsonb, target_digest = $3, narrowed_at = now()
		  WHERE id = $1 AND `+liveBinding, string(id), targetJSON, target.Digest())
	if err != nil {
		return false, mapErr(err, "AccessBinding.NarrowTarget", string(id))
	}
	return tag.RowsAffected() == 1, nil
}

// RolesNamingKeySQL — оператор поиска ролей по снятому ключу ($1 — тип, $2 — id);
// экспортирован ради пробы плана, как BindingsNamingKeySQL.
//
// `FOR UPDATE`, а не `FOR NO KEY UPDATE` — намеренно (kaname#963, F4): проходы
// материализации читают роль под `FOR KEY SHARE` (`loadRolesWithLifecycle`), и только
// этот режим с ним конфликтует. Слабее — и проход, прочитавший правило с именем до
// фиксации снятия, писал бы член и факт по снятому ключу после неё, а пост-фиксационный
// проход снятия незафиксированной записи не видит. Цена — на время снятия встают
// вставки, берущие на этих строках ролей `FOR KEY SHARE` (члены и выдачи); ролей —
// только называющие снятый ключ.
const RolesNamingKeySQL = `SELECT r.id FROM kaname.roles r
		  WHERE r.id IN (SELECT s.role_id FROM kaname.role_rule_selectors s
		                  WHERE s.resource_names @> ARRAY[$2::text]
		                    AND $1::text = ANY (s.object_types))
		  ORDER BY r.id
		    FOR UPDATE`

// RolesNamingKey — роли, правило (или вложенное правило) которых называет ключ в
// `resourceNames`, под `FOR UPDATE`, в порядке id. Поиск — по строкам отбора
// (`role_rule_selectors_resource_names_idx`): у вложенного правила строка несёт
// его собственные имена и его типы.
func (s *UnregisteredKeyStore) RolesNamingKey(ctx context.Context, tx service.Tx, key domain.ResourceRef) ([]domain.RoleID, error) {
	rows, err := txAsPgx(tx).Query(ctx, RolesNamingKeySQL, key.Type, key.ID)
	if err != nil {
		return nil, mapErr(err, "", key.ID)
	}
	defer rows.Close()
	var out []domain.RoleID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, mapErr(err, "", key.ID)
		}
		out = append(out, domain.RoleID(id))
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", key.ID)
	}
	return out, nil
}

// RewriteRoleRules — правила роли и их скомпилированная проекция после снятия
// имени. Пустой набор правил кладётся с пустым `permissions` (Р6): роль, все
// правила которой потеряли адресатов, не даёт ничего.
func (s *UnregisteredKeyStore) RewriteRoleRules(ctx context.Context, tx service.Tx, id domain.RoleID, rules domain.Rules, perms domain.Permissions) error {
	rulesJSON, err := rulesToJSON(rules)
	if err != nil {
		return fmt.Errorf("rewrite role rules %s: %w", id, err)
	}
	permsJSON, err := json.Marshal(stringSlice(perms))
	if err != nil {
		return fmt.Errorf("rewrite role permissions %s: %w", id, err)
	}
	if _, err := txAsPgx(tx).Exec(ctx,
		`UPDATE kaname.roles SET rules = $2::jsonb, permissions = $3::jsonb, updated_at = now() WHERE id = $1`,
		string(id), rulesJSON, permsJSON); err != nil {
		return mapErr(err, "Role.RewriteRules", string(id))
	}
	return nil
}
