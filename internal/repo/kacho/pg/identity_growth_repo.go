// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Чтение НАКОПИТЕЛЬНОГО журнала личностей.
//
// # Зачем отдельная величина
//
// Потолок на число аккаунтов у личности обходится заведением личностей:
// регистрация самообслуживаемая. Потолок темпа удорожает автоматизацию, но не
// ловит медленное накопление. Остаётся увидеть рост — и это страховка, а не
// мера: отказ по такому порогу пришёл бы СЛЕДУЮЩЕМУ честному человеку, поэтому
// величина сначала наблюдается, а решение об отказе принимается отдельно.
//
// # Почему журнал, а не счёт по строкам пользователей
//
// `count(DISTINCT external_id)` мгновенен и немонотонен: строку пользователя
// удаляют, и величина падает. На падающем ряде рост не определён — `increase()`
// молчит там, где рост и был, — а «личностей ноль» перестаёт быть утверждением о
// всей жизни платформы. Журнал не снимает рядов никогда, поэтому величина
// монотонна by construction и годится счётчиком в смысле витрины.

// IdentityGrowthRepo — читатель накопительного журнала личностей.
type IdentityGrowthRepo struct {
	pool *pgxpool.Pool
}

// NewIdentityGrowthRepo — constructor. Composition root: cmd/kacho-iam/serve.go.
func NewIdentityGrowthRepo(pool *pgxpool.Pool) *IdentityGrowthRepo {
	return &IdentityGrowthRepo{pool: pool}
}

// IdentitiesEverSeen — сколько личностей платформа видела за всё время.
//
// Считаются РЯДЫ ЖУРНАЛА, а не строки пользователей. Разница не стилистическая:
// строк пользователей у одной личности столько, сколько у неё членств, и они
// исчезают вместе с ней. Запрос по ним вернул бы правдоподобное число и вернул
// бы вместе с ним ту самую немонотонность, ради ухода от которой журнал заведён.
func (r *IdentityGrowthRepo) IdentitiesEverSeen(ctx context.Context) (int64, error) {
	const q = `SELECT count(*) FROM kacho_iam.identity_journal`
	var total int64
	if err := r.pool.QueryRow(ctx, q).Scan(&total); err != nil {
		return 0, fmt.Errorf("count identities ever seen: %w", err)
	}
	return total, nil
}
