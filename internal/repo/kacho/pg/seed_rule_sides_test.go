// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// seed_rule_sides_test.go — обе стороны правила системной роли, как их сеет старт.
//
// # Зачем помощник, а не прямой вызов досева селекторов
//
// У правила роли ДВЕ стороны: селекторы отвечают «подходит ли объект», проекция
// глаголов — «разрешено ли действие». Пересеивают их РАЗНЫЕ полосы: у пересчёта
// проекции свой вход (порт записи), своя зернистость (транзакция на роль) и своя
// полоса отказа в композиционном корне, поэтому досев селекторов его больше не
// зовёт — иначе на старте пересчёт шёл бы дважды, а его отказ приезжал бы
// обёрнутым в чужую ошибку.
//
// Проба, которой нужны ОБЕ стороны, обязана позвать обе. Роль с одними
// селекторами адресует объект и не разрешает на нём ничего: вердикт по её выдаче
// — отказ, причём МОЛЧАЛИВЫЙ.

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/testsupport/catalogfixture"
)

// bootSeedRuleSides сеет обе стороны правила системной роли в том же порядке, в
// каком их зовёт композиционный корень.
func bootSeedRuleSides(ctx context.Context, pool *pgxpool.Pool) error {
	if err := seed.SyncAllSystemRoleSelectors(ctx, pool); err != nil {
		return err
	}
	_, err := seed.ReseedSystemRoleVerbs(ctx, kachopg.New(pool, nil), pool, catalogfixture.Facts(), nil)
	return err
}
