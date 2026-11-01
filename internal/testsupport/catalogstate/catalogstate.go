// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package catalogstate — наблюдения проб над живой базой каталога модулей:
// отпечаток шести таблиц применителя (P12 приёмки
// `module-manifest-revision-only-moves-forward.md`), признак контейнера,
// применённая пара редакции и число записей следа применения.
//
// Одно объявление на все пакеты проб: отпечаток читают пробы адаптера
// (`internal/repo/kaname/pg`), последовательность старта (`cmd/kaname`) и
// глаголы (`internal/apps/kaname/api/module`). Копия в каждом разошлась бы
// составом колонок молча — и разошлась бы ровно там, где проба утверждает
// «ничего не изменилось».
package catalogstate

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Fingerprint — отпечаток ВСЕХ таблиц, которых применитель касается.
//
// Шесть таблиц, а не три: применитель пишет каталог и переселяет проекции, и
// «ничего не изменилось» обязано покрывать обе половины. Отпечаток строится из
// содержимого строк, а не из их числа.
//
// Колонки строки каталога — ВСЕ, которые пишет применитель (условие CE-18,
// kaname#865): кроме живости и причины снятия — имя типа модели, указатели,
// признак контейнера публичного чтения и применённая пара редакции. Отпечаток
// без них не видел бы младшей редакции, записавшей одну колонку: «отпечаток
// равен» означал бы «равны колонки, которые отпечаток читает». Состав держит
// проба `TestFingerprintSeesEveryColumnTheApplierWrites`
// (`internal/repo/kaname/pg`): снятая из запроса колонка краснит её строку.
func Fingerprint(t testing.TB, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var fp string
	if err := pool.QueryRow(ctx, `
		SELECT md5(coalesce(string_agg(x, '|' ORDER BY x), '')) FROM (
		  SELECT 'm:' || module || ':' || live::text ||
		         ':' || coalesce(retired_reason, '') ||
		         ':' || coalesce(applied_revision::text, '-') ||
		         ':' || coalesce(applied_digest, '-') AS x
		    FROM kaname.catalog_module
		  UNION ALL
		  SELECT 'r:' || dotted || ':' || live::text ||
		         ':' || coalesce(retired_reason, '') ||
		         ':' || object_type ||
		         ':' || array_to_string(parent_types, ',') ||
		         ':' || array_to_string(parent_names, ',') ||
		         ':' || array_to_string(writes, ',') ||
		         ':' || public_read_to_children::text ||
		         ':' || permanent_project::text
		    FROM kaname.catalog_resource
		  UNION ALL
		  SELECT 'v:' || module || '.' || resource || '.' || verb || ':' || live::text ||
		         ':' || per_object::text || ':' || coalesce(retired_reason, '')
		    FROM kaname.catalog_verb
		  UNION ALL
		  SELECT 'rr:' || role_id || ':' || module || '.' || resource ||
		         ':' || coalesce(verb, '')
		    FROM kaname.role_rule_ref
		  UNION ALL
		  SELECT 'rv:' || role_id || ':' || object_type || ':' || verb
		    FROM kaname.role_verb
		  UNION ALL
		  SELECT 'or:' || role_id || ':' || object_type || ':' || verb || ':' || source
		    FROM kaname.role_grant_orphan
		) s`).Scan(&fp); err != nil {
		t.Fatalf("отпечаток шести таблиц не снят: %v", err)
	}
	return fp
}

// ContainerFlag — признак контейнера публичного чтения строки
// `(module, resource)`.
func ContainerFlag(t testing.TB, ctx context.Context, pool *pgxpool.Pool, module, resource string) bool {
	t.Helper()
	var flag bool
	if err := pool.QueryRow(ctx,
		`SELECT public_read_to_children FROM kaname.catalog_resource WHERE module = $1 AND resource = $2`,
		module, resource).Scan(&flag); err != nil {
		t.Fatalf("признак контейнера %s.%s не прочитан: %v", module, resource, err)
	}
	return flag
}

// Applied — применённая пара модуля как её держат колонки: номер и отпечаток,
// оба nil — пусто. Строки модуля нет — отказ пробы: утверждать пару нечего.
func Applied(t testing.TB, ctx context.Context, pool *pgxpool.Pool, module string) (*int64, *string) {
	t.Helper()
	var (
		rev    *int64
		digest *string
	)
	err := pool.QueryRow(ctx,
		`SELECT applied_revision, applied_digest FROM kaname.catalog_module WHERE module = $1`, module).
		Scan(&rev, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("строки модуля %s нет — утверждать применённую редакцию нечего", module)
	}
	if err != nil {
		t.Fatalf("применённая редакция модуля %s не прочитана: %v", module, err)
	}
	return rev, digest
}

// AppliedTraces — число записей следа применения каталога по модулю.
func AppliedTraces(t testing.TB, ctx context.Context, pool *pgxpool.Pool, eventType, module string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.audit_outbox WHERE event_type = $1 AND event_payload->>'module' = $2`,
		eventType, module).Scan(&n); err != nil {
		t.Fatalf("записи следа применения модуля %s не сосчитаны: %v", module, err)
	}
	return n
}
