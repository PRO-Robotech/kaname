// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// catalog_repo.go — ЕДИНСТВЕННЫЙ читатель живых строк каталога модуля
// (`kacho_iam.catalog_module` / `catalog_resource` / `catalog_verb`).
//
// # Почему читатель ОДИН
//
// Живое множество спрашивают двое: страж старта, сверяющий его с литералом
// (`seed.AssertCatalogParity`), и снимок каталога, которым отвечают читатели на
// пути запроса (`internal/catalog`). Дай каждому свой запрос — получишь два
// места об одном предмете, и разойдутся они молча: у стража множество одно, у
// снимка другое, а согласие между ними никто не проверяет. Поэтому запрос здесь
// один, а вызывающих у него двое.
//
// Отсюда и величина, которую утверждает проба `IAM-CT-2-01`: за время старта к
// таблицам каталога уходит РОВНО СТОЛЬКО операторов, сколько шлёт сам страж, —
// своего чтения снимок не заводит.
//
// # Почему ПУЛ, а не читающая сторона
//
// Читающая сторона предпочитает реплику, а страж исполняется на старте, когда
// отставание реплики наиболее вероятно. Прочитанный оттуда пустой каталог дал бы
// отказ старта на исправной службе — то есть контроль отказал бы по причине,
// которой в предмете контроля нет.

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/catalog"
)

// CatalogRepo — реализация порта `catalog.RowSource` поверх пула.
type CatalogRepo struct {
	pool *pgxpool.Pool
}

// NewCatalogRepo — конструктор порта чтения каталога.
func NewCatalogRepo(pool *pgxpool.Pool) *CatalogRepo { return &CatalogRepo{pool: pool} }

// ReadLiveCatalog читает ЖИВОЕ множество каталога.
//
// Три оператора — по одному на таблицу, — и это величина, а не константа кода:
// проба `-01` её ИЗМЕРЯЕТ и сверяет с тем, сколько уходит за время старта.
// Свернут их когда-нибудь в один — утверждение пробы останется верным без
// правки.
//
// Отбор `WHERE live` — тот же, каким живое множество определено в схеме: `live`
// есть производная `retired_at IS NULL`, и согласие этих двух держит проверка
// колонки, а не читатель.
func (r *CatalogRepo) ReadLiveCatalog(ctx context.Context) (catalog.Rows, error) {
	var out catalog.Rows

	modRows, err := r.pool.Query(ctx, `SELECT module FROM kacho_iam.catalog_module WHERE live`)
	if err != nil {
		return out, fmt.Errorf("прочитать каталог модулей: %w", err)
	}
	for modRows.Next() {
		var m string
		if serr := modRows.Scan(&m); serr != nil {
			modRows.Close()
			return out, fmt.Errorf("прочитать каталог модулей: %w", serr)
		}
		out.Modules = append(out.Modules, m)
	}
	modRows.Close()
	if err = modRows.Err(); err != nil {
		return out, fmt.Errorf("прочитать каталог модулей: %w", err)
	}

	resRows, err := r.pool.Query(ctx,
		`SELECT module, resource FROM kacho_iam.catalog_resource WHERE live`)
	if err != nil {
		return out, fmt.Errorf("прочитать каталог ресурсов: %w", err)
	}
	for resRows.Next() {
		var row catalog.ResourceRow
		if serr := resRows.Scan(&row.Module, &row.Resource); serr != nil {
			resRows.Close()
			return out, fmt.Errorf("прочитать каталог ресурсов: %w", serr)
		}
		out.Resources = append(out.Resources, row)
	}
	resRows.Close()
	if err = resRows.Err(); err != nil {
		return out, fmt.Errorf("прочитать каталог ресурсов: %w", err)
	}

	// `per_object` читается ВМЕСТЕ со строкой, а не выводится читателем: словарей
	// два (пообъектный и авторский), и признак — единственное, чем строка одного
	// отличается от строки другого. Прочитать строку без него значило бы вернуть
	// набору типа глаголы, которые кортежа не производят (#1863).
	verbRows, err := r.pool.Query(ctx,
		`SELECT module, resource, verb, per_object FROM kacho_iam.catalog_verb WHERE live`)
	if err != nil {
		return out, fmt.Errorf("прочитать каталог глаголов: %w", err)
	}
	for verbRows.Next() {
		var row catalog.VerbRow
		if serr := verbRows.Scan(&row.Module, &row.Resource, &row.Verb, &row.PerObject); serr != nil {
			verbRows.Close()
			return out, fmt.Errorf("прочитать каталог глаголов: %w", serr)
		}
		out.Verbs = append(out.Verbs, row)
	}
	verbRows.Close()
	if err = verbRows.Err(); err != nil {
		return out, fmt.Errorf("прочитать каталог глаголов: %w", err)
	}

	return out, nil
}
