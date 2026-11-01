// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package registrationscene — проект, под которым пробы регистрируют объекты
// модуля (kaname#982, приёмка kaname-derives-the-parent-of-a-registered-object.md).
//
// # Зачем отдельный пакет
//
// Родителя регистрируемого объекта kaname выводит из своих данных и сверяет с ним
// сведения модуля: регистрация под проектом, которого в kaname нет, отвергается
// (Р4, Р8). «Дано» проб, регистрирующих объект указателем `project`, обязано
// поэтому нести настоящую строку проекта в настоящем аккаунте. Пробы трёх пакетов
// (internal_iam, pg, access_binding) строили бы её каждая своей копией — три
// места об одном предмете, разошедшиеся бы на первой правке схемы.
package registrationscene

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
)

// Scene — проект и его аккаунт в базе пробы.
type Scene struct {
	Project string
	Account string
}

// ProjectChain — цепь предков объекта под проектом сцены: `[project:P, account:A]`.
func (s Scene) ProjectChain() []string {
	return []string{"project:" + s.Project, "account:" + s.Account}
}

// Seed заводит человека, его аккаунт и проект в аккаунте одной транзакцией.
// Человек и аккаунт ссылаются друг на друга отложенными ключами, поэтому обе
// строки ложатся вместе; строка пароля человека — тем же посевом, что у прочих
// фикстур (kaname#608).
func Seed(t testing.TB, ctx context.Context, pool *pgxpool.Pool) Scene {
	t.Helper()
	uid := ids.NewID(domain.PrefixUser)
	acc := ids.NewID(domain.PrefixAccount)
	prj := ids.NewID(domain.PrefixProject)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status, email_verified_at)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE', now())`,
		uid, acc, "ext-"+uid, fmt.Sprintf("u-%s@example.com", uid), "Registration Scene Owner")
	require.NoError(t, err, "сцена регистрации: человек")
	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.accounts (id, name, owner_user_id, labels) VALUES ($1, $2, $3, '{}'::jsonb)`,
		acc, "scene-acc-"+acc[len(acc)-6:], uid)
	require.NoError(t, err, "сцена регистрации: аккаунт")
	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.projects (id, account_id, name, labels) VALUES ($1, $2, $3, '{}'::jsonb)`,
		prj, acc, "scene-prj-"+prj[len(prj)-6:])
	require.NoError(t, err, "сцена регистрации: проект")
	activewayin.Seed(t, ctx, tx)
	require.NoError(t, tx.Commit(ctx), "сцена регистрации: фиксация")
	return Scene{Project: prj, Account: acc}
}
