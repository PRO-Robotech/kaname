// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/nameformdb"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// TestIntegration_IAM_NameFormConstraintIsEnforced — задача #1279.
//
// iam пришёл к единственной форме имени последним из семи схем: до этого его
// таблицы несли СВОЮ форму (`^[a-z][-a-z0-9]{2,62}$`), расходившуюся с каноном
// в обе стороны — она была уже канона по началу имени и его длине и ШИРЕ канона
// по хвостовому дефису.
//
// «Миграция применилась» и «ограничение отвергает негодную строку» — разные
// утверждения; здесь доказывается второе. Разбор класса, перечень значений и
// почему положительный контроль обязателен — `pkg/nameformdb`.
func TestIntegration_IAM_NameFormConstraintIsEnforced(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ: отложенное `pool.Close()` ждёт соединение, которое
	// проба, упавшая внутри открытой транзакции, не вернёт никогда, — и уносит
	// с собой вердикт всего пакета (гейт `TestPoolCloseInTestsIsBounded`).
	pgtest.ClosePoolAtEnd(t, pool)

	// Владелец аккаунта — настоящая строка `users`: внешний ключ
	// `accounts_owner_fk` иначе отверг бы вставку 23503, и положительный
	// контроль падал бы по чужой причине.
	//
	// Владельцев ЗАВЕДОМО БОЛЬШЕ, чем вставок, и каждая вставка берёт своего.
	// Причина не в аккуратности: схема ограничивает ТЕМП заведения аккаунтов
	// одной личностью, и на общем владельце положительный контроль падал бы с
	// «превышен темп» — то есть по чужой причине, ровно так, как этот же
	// перечень значений и предостерегает.
	const ownersNeeded = 12
	owners := make([]domain.UserID, 0, ownersNeeded)
	for i := 0; i < ownersNeeded; i++ {
		owners = append(owners, mustSeedUser(t, ctx, pool, fmt.Sprintf("nameform%d", i)))
	}
	nextOwner := 0

	// Аккаунт-носитель для проекта, группы и служебной учётки — по той же
	// причине (`*_account_fk`). Имя аккаунта здесь каноничное и уникальное:
	// `accounts_name_unique` уникален по имени на ВЕСЬ кластер.
	acc := seedNameFormAccount(t, ctx, pool, owners[0])
	nextOwner++

	nameformdb.Probe{
		Schema: "kacho_iam",
		Tables: []nameformdb.Table{
			{
				Name: "accounts",
				Row: func(name string, seq int) (string, []any) {
					o := owners[nextOwner%len(owners)]
					nextOwner++
					return `INSERT INTO kacho_iam.accounts (id, name, owner_user_id)
					        VALUES ($1, $2, $3)`,
						[]any{fmt.Sprintf("acc%017d", seq), name, string(o)}
				},
			},
			{
				Name: "projects",
				Row: func(name string, seq int) (string, []any) {
					return `INSERT INTO kacho_iam.projects (id, account_id, name)
					        VALUES ($1, $2, $3)`,
						[]any{fmt.Sprintf("prj%017d", seq), acc, name}
				},
			},
			{
				Name: "groups",
				Row: func(name string, seq int) (string, []any) {
					return `INSERT INTO kacho_iam.groups (id, account_id, name)
					        VALUES ($1, $2, $3)`,
						[]any{fmt.Sprintf("grp%017d", seq), acc, name}
				},
			},
			{
				Name: "service_accounts",
				Row: func(name string, seq int) (string, []any) {
					return `INSERT INTO kacho_iam.service_accounts (id, account_id, name)
					        VALUES ($1, $2, $3)`,
						[]any{fmt.Sprintf("sva%017d", seq), acc, name}
				},
			},
			{
				Name: "interactive_clients",
				Row: func(name string, seq int) (string, []any) {
					// id обязан отвечать `^ic-[0-9a-hjkmnp-tv-z]{17}$`, список
					// адресов возврата — быть непустым и https: обе проверки
					// стоят рядом с формой имени, и строка, спотыкающаяся о них,
					// до неё бы не дошла.
					return `INSERT INTO kacho_iam.interactive_clients
					            (id, client_id, name, redirect_uris)
					        VALUES ($1, $2, $3, ARRAY['https://console.example/cb'])`,
						[]any{
							fmt.Sprintf("ic-%017d", seq),
							fmt.Sprintf("hydra-ic-%d", seq),
							name,
						}
				},
			},
		},
		// Таблицы схемы со столбцом имени, которым форма НЕ ставится осознанно.
		Excluded: map[string]string{
			"service_account_oauth_clients": "имя ключа судит только доменный тип; дубля формы в базе " +
				"у этой таблицы не было и не заводится этой правкой",
			"user_oauth_clients": "имя токена судит только доменный тип; дубля формы в базе " +
				"у этой таблицы не было и не заводится этой правкой",
		},
		// Таблицы, несущие форму имени НАМЕРЕННО ДРУГУЮ.
		OtherForm: map[string]string{
			"roles": "идентификатор роли (`roles/vpc.admin`), а не косметическая метка: " +
				"на него ссылаются привязки — записанное решение владельца (#715)",
			"clusters": "кластер — посевной синглтон, глагола создания у него нет; " +
				"имя приходит одной строкой миграции",
		},
	}.Run(ctx, t, pool)
}

// seedNameFormAccount заводит аккаунт-носитель для дочерних таблиц.
func seedNameFormAccount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, owner domain.UserID) string {
	t.Helper()
	const id = "acc00000000000nmfrm"
	_, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		id, "nameform-carrier", string(owner))
	require.NoError(t, err, "фикстура: аккаунт-носитель не завёлся — дочерние вставки недостижимы")
	return id
}
