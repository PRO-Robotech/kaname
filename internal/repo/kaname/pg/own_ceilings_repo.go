// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// own_ceilings_repo.go — ПРОЕКЦИЯ ПОСАДКИ В СХЕМУ: величины трёх собственных
// потолков уезжают из файла настроек туда, откуда их читает списание.
//
// # Почему величина обязана лежать в базе
//
// Списание — единственный атомарный оператор, и он в той же транзакции, что
// вставка строки ресурса (ban #10: инвариант держит база, а не проверка-перед-
// записью). Триггер не читает настройку процесса ни при каком построении, значит
// величина обязана лежать рядом со строками, которые ограничивает.
//
// # Почему пишет ТОЛЬКО пуск
//
// Внешнего глагола у этих величин нет и не заводится: единственный способ
// изменить потолок — посадка службы, то есть перезапуск с новым значением. Это и
// есть содержание `П25`: величина принадлежит тому, кто ставит службу.
//
// # Перекатка: последний пущенный выигрывает, и это ТО ЖЕ, что «перезапуск»
//
// Пишет только тот, кто ПОДНИМАЕТСЯ; уже поднятые не перезаписывают ничего.
// Значит во время перекатки действует величина последнего пущенного пода, а по
// её завершении — величина новой посадки у всех. Спора двух писателей нет by
// construction, и «последний пущенный» есть буквальное прочтение слова
// «перезапуск с новым значением».

// OwnCeilingRepo — писатель проекции посадки.
type OwnCeilingRepo struct {
	pool *pgxpool.Pool
}

// NewOwnCeilingRepo — constructor. Composition root: cmd/kaname/serve.go.
func NewOwnCeilingRepo(pool *pgxpool.Pool) *OwnCeilingRepo {
	return &OwnCeilingRepo{pool: pool}
}

// OwnCeilingProjection — перепись одного применения. Печатается ВСЕГДА:
// «объявлено три, записано ноль» и «объявлено ноль» — разные утверждения о
// посадке, а молчание у них одно.
type OwnCeilingProjection struct {
	// Stated — сколько величин объявила посадка.
	Stated int
	// Written — сколько строк проекции приведено к объявленному.
	Written int
	// Removed — сколько строк снято как не объявленные посадкой.
	Removed int
	// Kinds — виды в порядке объявления, для журнала старта.
	Kinds []string
}

// Apply приводит проекцию к тому, что объявила посадка — ЦЕЛИКОМ и в одной
// транзакции.
//
// «Целиком» несущее: проекция обязана БЫТЬ посадкой, а не содержать её. Строка,
// чей вид посадка больше не объявляет, продолжала бы ограничивать создание
// величиной, которую никто не называл, — то есть переживала бы своё основание.
// Поэтому лишнее снимается тем же оператором, что записывает объявленное.
//
// Пустое объявление отвергается: страж старта до этого не допускает, и молчаливое
// «нечего применять» здесь означало бы, что проекция осталась прежней, а посадка
// думает иначе.
func (r *OwnCeilingRepo) Apply(
	ctx context.Context, stated map[domain.LimitKind]int64,
) (OwnCeilingProjection, error) {
	census := OwnCeilingProjection{Stated: len(stated)}
	if len(stated) == 0 {
		return census, fmt.Errorf("проекция собственных потолков: посадка не объявила ни одной " +
			"величины — применять нечего, а прежняя проекция продолжала бы действовать")
	}

	kinds := make([]string, 0, len(stated))
	for k := range stated {
		kinds = append(kinds, string(k))
	}
	sort.Strings(kinds)
	census.Kinds = kinds

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return census, fmt.Errorf("проекция собственных потолков: начать транзакцию: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, kind := range kinds {
		tag, uerr := tx.Exec(ctx, `
			INSERT INTO kaname.own_ceilings (kind, limit_value, stated_at)
			VALUES ($1, $2, now())
			ON CONFLICT (kind) DO UPDATE
			   SET limit_value = EXCLUDED.limit_value, stated_at = now()`,
			kind, stated[domain.LimitKind(kind)])
		if uerr != nil {
			return census, fmt.Errorf("проекция собственных потолков: вид %s: %w", kind, uerr)
		}
		census.Written += int(tag.RowsAffected())
	}

	tag, derr := tx.Exec(ctx,
		`DELETE FROM kaname.own_ceilings WHERE kind <> ALL ($1::text[])`, kinds)
	if derr != nil {
		return census, fmt.Errorf("проекция собственных потолков: снятие необъявленного: %w", derr)
	}
	census.Removed = int(tag.RowsAffected())

	if cerr := tx.Commit(ctx); cerr != nil {
		return census, fmt.Errorf("проекция собственных потолков: фиксация: %w", cerr)
	}
	return census, nil
}

// statedOwnCeiling — величина проекции по виду. Второй результат — ложь, если
// посадка вид не объявляла.
//
// Отдельным глаголом, а не полем ответа: читающий путь спрашивает про ОДИН вид, и
// возвращать ему всю проекцию значило бы дать повод выбрать из неё не тот.
func statedOwnCeiling(
	ctx context.Context, q interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	}, kind string,
) (int64, bool, error) {
	var value int64
	err := q.QueryRow(ctx,
		`SELECT limit_value FROM kaname.own_ceilings WHERE kind = $1`, kind).Scan(&value)
	switch {
	case err == nil:
		return value, true, nil
	case errors.Is(err, pgx.ErrNoRows):
		return 0, false, nil
	default:
		return 0, false, fmt.Errorf("read stated own ceiling for %s: %w", kind, err)
	}
}
