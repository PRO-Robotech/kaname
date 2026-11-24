// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/service"
)

// SaveRegistrationPointerTx вызывается только после полного допуска и вердикта
// зеркала, в той же транзакции, что записывает факт. История переживает снятие
// типа и policy shrink; из старых фактов или нынешней policy её не заполняем.
// Режим текущего holder отделён от монотонного ordered watermark: отсутствие
// версии допускается явно, но не понижает историю и не снимает ordered fence.
func (RegistrationScopeReader) SaveRegistrationPointerTx(ctx context.Context, tx service.Tx, module string, tuple service.RelationTuple, version time.Time) (bool, error) {
	typ, id, _ := strings.Cut(tuple.Object, ":")
	tag, err := txAsPgx(tx).Exec(ctx, `INSERT INTO kaname.resource_registration_pointer(module,object_type,object_id,relation,subject,source_version,versionless)
 VALUES($1,$2,$3,$4,$5,$6,$7)
 ON CONFLICT(module,object_type,object_id,relation,subject) DO UPDATE SET source_version=greatest(resource_registration_pointer.source_version,EXCLUDED.source_version),active=true,versionless=EXCLUDED.versionless
 WHERE EXCLUDED.versionless OR resource_registration_pointer.source_version < EXCLUDED.source_version
    OR (resource_registration_pointer.source_version = EXCLUDED.source_version AND resource_registration_pointer.active AND NOT resource_registration_pointer.versionless)`,
		module, typ, id, tuple.Relation, tuple.User, ownerVersionOrMinusInfinity(version), version.IsZero())
	if err != nil {
		return false, fmt.Errorf("save registration pointer: %w", err)
	}
	return tag.RowsAffected() != 0, nil
}

func (RegistrationScopeReader) RegistrationPointersTx(ctx context.Context, tx service.Tx, module, object string) ([]service.RelationTuple, error) {
	typ, id, _ := strings.Cut(object, ":")
	rows, err := txAsPgx(tx).Query(ctx, `SELECT subject,relation,object_type || ':' || object_id FROM kaname.resource_registration_pointer WHERE module=$1 AND object_type=$2 AND object_id=$3 ORDER BY relation COLLATE "C",subject COLLATE "C"`, module, typ, id)
	if err != nil {
		return nil, fmt.Errorf("read registration pointers: %w", err)
	}
	defer rows.Close()
	var out []service.RelationTuple
	for rows.Next() {
		var tuple service.RelationTuple
		if err := rows.Scan(&tuple.User, &tuple.Relation, &tuple.Object); err != nil {
			return nil, err
		}
		out = append(out, tuple)
	}
	return out, rows.Err()
}

// RetireRegistrationPointersTx снимает только своё владение, не чужую выдачу.
// Свёртка журнала отдельно запирает факт и читает всех оставшихся держателей.
// Старое надгробие не меняет владение более новой упорядоченной регистрации.
// Отсутствие входной версии не понижает watermark. Конечный replay текущего
// zero holder дополнительно отвергается use-case ДО изменений зеркала.
func (RegistrationScopeReader) RetireRegistrationPointersTx(ctx context.Context, tx service.Tx, module, object string, version time.Time) error {
	typ, id, _ := strings.Cut(object, ":")
	_, err := txAsPgx(tx).Exec(ctx, `UPDATE kaname.resource_registration_pointer SET active=false,source_version=greatest(source_version,$4::timestamptz)
 WHERE module=$1 AND object_type=$2 AND object_id=$3 AND ($4::timestamptz IS NULL OR source_version < $4 OR (source_version = $4 AND (NOT versionless OR NOT active)))`, module, typ, id, nullableRegistrationTombstone(version))
	if err != nil {
		return fmt.Errorf("retire registration pointers: %w", err)
	}
	return nil
}

func nullableRegistrationTombstone(version time.Time) any {
	if version.IsZero() {
		return nil
	}
	return version
}

// PrepareRegistrationWithdrawalTx берёт прежний writer fence в прежнем порядке:
// binding/role уже взяты use-case, зеркало/claims/facts ещё не изменены. Отдельное
// чтение ПОСЛЕ ожидания видит закончившийся versionless Register.
func (RegistrationScopeReader) PrepareRegistrationWithdrawalTx(ctx context.Context, tx service.Tx, module, object string, version time.Time) (bool, bool, error) {
	ptx := txAsPgx(tx)
	if _, err := ptx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('kaname.resource_registration_writers',0))`); err != nil {
		return false, false, err
	}
	typ, id, _ := strings.Cut(object, ":")
	var refused, active bool
	err := ptx.QueryRow(ctx, `SELECT coalesce(bool_or(active AND versionless AND $4::timestamptz IS NOT NULL AND source_version >= $4),false),coalesce(bool_or(active),false)
 FROM kaname.resource_registration_pointer WHERE module=$1 AND object_type=$2 AND object_id=$3`, module, typ, id, nullableRegistrationTombstone(version)).Scan(&refused, &active)
	return !refused, active, err
}

// RetireDescendantRegistrationPointersTx вызывается только после доказанного
// удаления текущей child mirror. Это структурное снятие, не внешний replay:
// свой watermark сохраняется, а текущий zero mode даёт неупорядоченную строку.
func (RegistrationScopeReader) RetireDescendantRegistrationPointersTx(ctx context.Context, tx service.Tx, module, object string, version time.Time) ([]service.VersionedRelationTuple, error) {
	typ, id, _ := strings.Cut(object, ":")
	rows, err := txAsPgx(tx).Query(ctx, `UPDATE kaname.resource_registration_pointer SET active=false,source_version=greatest(source_version,$4::timestamptz)
 WHERE module=$1 AND object_type=$2 AND object_id=$3 RETURNING subject,relation,object_type || ':' || object_id,versionless`, module, typ, id, nullableRegistrationTombstone(version))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []service.VersionedRelationTuple
	for rows.Next() {
		var row service.VersionedRelationTuple
		var legacy bool
		if err := rows.Scan(&row.Tuple.User, &row.Tuple.Relation, &row.Tuple.Object, &legacy); err != nil {
			return nil, err
		}
		if !legacy {
			row.SourceVersion = version
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
