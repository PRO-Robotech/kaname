// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// noncanonical_bindings_census_integration_test.go — IAM-ID-1-36 (задача
// kacho#472): неканонические привязки переписаны поимённо.
//
// # Предмет
//
// Выдача резолвит субъекта в КАНОНИЧЕСКУЮ строку личности — старейшую ACTIVE по
// почте, ту самую, в которую край резолвит токен. Но резолв best-effort, и
// ошибка чтения там НЕ ОТЛИЧАЕТСЯ от «активных ноль»: обе ветки возвращают
// пер-аккаунтную строку. Значит в базе МОГУТ лежать привязки, выданные не на
// каноническую строку, — ровно те права, которые потерялись бы молча при
// схлопывании строк.
//
// Перепись П3 из §3 приёмки отвечает, сколько их. Это число входит в сценарии
// группы E и обязано быть снято ДО любого шага, опирающегося на «субъект не
// меняется».
//
// # Почему проба НЕ ПАДАЕТ на нуле
//
// Пустая перепись — это ЦЕЛЬ, а не поломка. Проба, падающая на достижении своей
// цели, подталкивает держать находку ради зелёного (`testing.md` §«Гейт на
// класс» п. 5, IAM-ID-1-36 дословно: «при П3 = 0 сценарий проходит, объявляя
// перепись „записей 0“»).
//
// Поэтому способность переписи НАХОДИТЬ доказывается отдельно — синтетической
// неканонической привязкой, которую она обязана назвать поимённо. Без этой
// половины «ноль находок» было бы неотличимо от «предикат сломан».

package pg_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// nonCanonicalBindingCensus — П3: привязки рода «пользователь», чей субъект НЕ
// есть каноническая (старейшая ACTIVE по своей почте) строка личности.
//
// Возвращает найденные идентификаторы привязок и число ОСМОТРЕННЫХ привязок:
// «ноль находок» обязано быть отличимо от «ноль прочитанного».
func nonCanonicalBindingCensus(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (found []string, examined int) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.access_bindings
		 WHERE subject_type = 'user'`).Scan(&examined))

	rows, err := pool.Query(ctx, `
		SELECT b.id
		  FROM kacho_iam.access_bindings b
		  JOIN kacho_iam.users subj ON subj.id = b.subject_id
		 WHERE b.subject_type = 'user'
		   AND b.subject_id <> (
			   SELECT canon.id
				 FROM kacho_iam.users canon
				WHERE lower(canon.email) = lower(subj.email)
				  AND canon.invite_status = 'ACTIVE'
				ORDER BY canon.created_at, canon.id
				LIMIT 1)
		 ORDER BY b.id`)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		found = append(found, id)
	}
	require.NoError(t, rows.Err())
	return found, examined
}

func TestIntegration_NonCanonicalBindingCensus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.New(pool, nil)

	canonUser, canonAcc := bootstrapAdmin(t, ctx, repo, "nc1")
	role := anyRoleID(t, ctx, pool)

	// ── перепись на здоровом дереве: находок ноль, и это НЕ отказ ────────────
	found, examined := nonCanonicalBindingCensus(t, ctx, pool)
	t.Logf("перепись П3: осмотрено привязок рода «пользователь» %d, неканонических %d",
		examined, len(found))
	require.Empty(t, found,
		"на здоровом дереве неканонических привязок нет — и проба это ОБЪЯВЛЯЕТ, а не падает: "+
			"пустая перепись есть цель, а не поломка")

	// ── положительный контроль: перепись обязана НАХОДИТЬ ───────────────────
	// Вторая строка той же почты в другом аккаунте — состояние, которое сегодня
	// допустимо (уникальность почты пер-аккаунтная), и выдача на неё как раз и
	// есть неканоническая привязка.
	var canonEmail string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT email FROM kacho_iam.users WHERE id = $1`, string(canonUser)).Scan(&canonEmail))

	shadowUser := domain.UserID(ids.NewID(domain.PrefixUser))
	shadowAcc := domain.AccountID(ids.NewID(domain.PrefixAccount))
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		_, err = w.UsersW().InsertActive(ctx, domain.User{
			ID:           shadowUser,
			AccountID:    shadowAcc,
			ExternalID:   domain.ExternalSubject("ext-nc1-shadow"),
			Email:        domain.Email(canonEmail), // ТА ЖЕ почта, другой аккаунт
			DisplayName:  "Shadow",
			InviteStatus: domain.InviteStatusActive,
		})
		require.NoError(t, err)
		_, err = w.AccountsW().Insert(ctx, domain.Account{
			ID:          shadowAcc,
			Name:        domain.AccountName("acc-nc1-shadow"),
			OwnerUserID: shadowUser,
			Labels:      domain.Labels{},
		})
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
	}

	// Предпосылка контроля: канонической осталась ПЕРВАЯ строка, а не теневая.
	var canonical string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT id FROM kacho_iam.users
		 WHERE lower(email) = lower($1) AND invite_status = 'ACTIVE'
		 ORDER BY created_at, id LIMIT 1`, canonEmail).Scan(&canonical))
	require.Equal(t, string(canonUser), canonical,
		"ПРЕДПОСЫЛКА: канонической обязана быть старейшая строка — иначе контроль ниже "+
			"проверяет не то, что называет")

	shadowBinding := grantAccountScoped(t, ctx, pool, shadowUser, shadowAcc, role)
	// Контроль-близнец: выдача на КАНОНИЧЕСКУЮ строку находкой быть не должна.
	_ = grantAccountScoped(t, ctx, pool, canonUser, canonAcc, role)

	found, examined = nonCanonicalBindingCensus(t, ctx, pool)
	t.Logf("перепись П3 после посева: осмотрено %d, неканонических %d — %v",
		examined, len(found), found)

	require.Equal(t, []string{shadowBinding}, found,
		"перепись обязана НАЗВАТЬ неканоническую привязку поимённо — и только её: "+
			"молчание здесь означало бы, что предыдущий ноль ничего не доказывал, "+
			"а лишний идентификатор — что она считает законные выдачи находками")
	require.Positive(t, examined)
}
