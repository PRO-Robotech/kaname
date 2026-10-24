// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// registered_keys.go — гонка «принято до снятия регистрации, записано после»
// (kaname#963, приёмка `unregistration-revokes-its-grants.md`, Р8, Д6, URG-24,
// URG-26).
//
// Регистрация объекта — строка зеркала `kaname.resource_mirror`; снятие
// регистрации её удаляет. Две половины одного решения:
//
//   - на ПРИЁМЕ выдачи (роли) спрашивается, какие из названных ключей сейчас
//     зарегистрированы (`RegisteredKeys.RegisteredOf`). Ключ, свободный на приёме,
//     — ключ по ATC-03 («graceful-dangling»), судить его нечем;
//   - на ЗАПИСИ по каждому ключу, зарегистрированному на приёме, берётся
//     `FOR KEY SHARE` строки зеркала (`holdRegisteredKeys`). Снятие удаляет строку
//     и с этим замком конфликтует: пока запись не зафиксирована, снятие ждёт, а
//     после — видит записанное и отзывает его (исход (ii)). Строки уже нет —
//     снятие зафиксировано раньше записи, и запись отказывает (исход (i), Т1/Т2).
//
// Живой выдачи на снятый ключ не остаётся ни в одном порядке.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// registeredKeysCallTimeout — свой срок одного чтения регистраций на приёме
// (`arch-per-call-deadline`): чтение — один оператор по первичному ключу зеркала на
// ключи одного запроса и идёт на пути ответа клиенту, поэтому ждать его дольше секунд
// значит держать запрос на занятом пуле, а не читать.
const registeredKeysCallTimeout = 5 * time.Second

// RegisteredKeys — чтение «какие ключи сейчас зарегистрированы» на приёме.
type RegisteredKeys struct {
	pool *pgxpool.Pool
}

// NewRegisteredKeys — композиционный корень.
func NewRegisteredKeys(pool *pgxpool.Pool) *RegisteredKeys {
	return &RegisteredKeys{pool: pool}
}

// RegisteredOf возвращает ключи из `keys`, у которых есть строка регистрации, в
// порядке подачи (повторы схлопываются).
func (r *RegisteredKeys) RegisteredOf(ctx context.Context, keys []domain.ResourceRef) ([]domain.ResourceRef, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	types := make([]string, len(keys))
	ids := make([]string, len(keys))
	for i, k := range keys {
		types[i], ids[i] = k.Type, k.ID
	}
	ctx, cancel := context.WithTimeout(ctx, registeredKeysCallTimeout)
	defer cancel()
	rows, err := r.pool.Query(ctx,
		`SELECT m.object_type, m.object_id
		   FROM unnest($1::text[], $2::text[]) AS k(object_type, object_id)
		   JOIN kaname.resource_mirror m USING (object_type, object_id)`, types, ids)
	if err != nil {
		return nil, mapErr(err, "", "")
	}
	defer rows.Close()
	present := map[domain.ResourceRef]struct{}{}
	for rows.Next() {
		var k domain.ResourceRef
		if err := rows.Scan(&k.Type, &k.ID); err != nil {
			return nil, mapErr(err, "", "")
		}
		present[k] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", "")
	}
	var out []domain.ResourceRef
	seen := map[domain.ResourceRef]struct{}{}
	for _, k := range keys {
		if _, ok := present[k]; !ok {
			continue
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out, nil
}

// holdRegisteredKeys берёт `FOR KEY SHARE` строки регистрации каждого ключа в
// транзакции записи — в порядке ключей (тип, id), чтобы два писателя одного
// набора не встали друг против друга. Ключа нет — `refuse(ключ)`: снятие
// зафиксировано раньше записи.
func holdRegisteredKeys(ctx context.Context, tx pgx.Tx, keys []domain.ResourceRef, refuse func(domain.ResourceRef) error) error {
	for _, k := range sortedRefs(keys) {
		var one int
		err := tx.QueryRow(ctx,
			`SELECT 1 FROM kaname.resource_mirror
			  WHERE object_type = $1 AND object_id = $2
			    FOR KEY SHARE`, k.Type, k.ID).Scan(&one)
		if errors.Is(err, pgx.ErrNoRows) {
			return refuse(k)
		}
		if err != nil {
			return mapErr(err, "", fmt.Sprintf("%s %s", k.Type, k.ID))
		}
	}
	return nil
}

// sortedRefs — ключи без повторов в порядке (тип, id).
func sortedRefs(keys []domain.ResourceRef) []domain.ResourceRef {
	seen := map[domain.ResourceRef]struct{}{}
	out := make([]domain.ResourceRef, 0, len(keys))
	for _, k := range keys {
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return refLess(out[i], out[j]) })
	return out
}

func refLess(a, b domain.ResourceRef) bool {
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	return a.ID < b.ID
}

// holdRoleNames — `holdRegisteredKeys` для ключей, названных правилами роли:
// отказ называет правило (Т2 приёмки).
func holdRoleNames(ctx context.Context, tx pgx.Tx, holds []domain.RuleNameHold) error {
	if len(holds) == 0 {
		return nil
	}
	refs := make([]domain.ResourceRef, 0, len(holds))
	ruleOf := make(map[domain.ResourceRef]int, len(holds))
	for _, h := range holds {
		if _, seen := ruleOf[h.Ref]; !seen {
			ruleOf[h.Ref] = h.Rule
		}
		refs = append(refs, h.Ref)
	}
	return holdRegisteredKeys(ctx, tx, refs, func(ref domain.ResourceRef) error {
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"rules[%d].resourceNames: resource %s was unregistered before the role was written", ruleOf[ref], ref.ID)
	})
}
