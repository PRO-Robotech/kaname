// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// visibility_scope_owner_integration_test.go — «мои аккаунты» включают тот,
// которым человек ВЛАДЕЕТ, даже когда членства в нём у него нет
// (задача kacho#610, линия release:identity).
//
// # Предмет и почему он появился
//
// Решение владельца по #610 — **владеть ≠ состоять**. Инвариант «владелец
// состоит в своём аккаунте» отвергнут и снят из приёмки IAM-ID-1 вместе со
// своими сценариями: он отверг бы штатный ввод (создание второго аккаунта
// существующим человеком) и сделал бы выход из аккаунта невозможным — «создал»
// стало бы «вступил навсегда».
//
// Из решения следует ровно одно требование к продукту, и оно здесь и
// закрепляется: видимость «мои аккаунты» = **владею ∪ состою**. Половина
// «владею» обязана держаться САМА, не опираясь ни на членство, ни на
// материализацию привязок.
//
// # Почему проба стоит здесь, а не на use-case
//
// Половин у видимости две, и держатся они разными механизмами:
//
//	кандидат  — `ScopeOf` читает `accounts.owner_user_id` (ветка 'own' запроса);
//	вердикт   — модель прав, где `define v_list: … or owner or super_admin`.
//
// Вторая половина уже закреплена структурным замком
// (`internal/authzmap/account_owner_structural_test.go`), и здесь она НЕ
// переутверждается: два места об одном предмете расходятся молча. Не закреплена
// была первая — у `visibility_repo.go` не было ни одной интеграционной пробы,
// при том что его запрос выбирает кандидатов для КАЖДОЙ списочной поверхности
// сервиса.
//
// # Почему проба приходит в ствол ОТДЕЛЬНО от своей линии
//
// Она была написана на линии `release/identity-decoupling` и в ствол не
// доехала: линия влита, а этот коммит вливанием не поглощён — проба
// существовала В ОДНОМ ЭКЗЕМПЛЯРЕ и была бы уничтожена первой же чисткой
// веток (kacho#1760). Сдаётся сама проба, а не линия: та отстала от ствола на
// сотни коммитов.
//
// Задача #610, к которой возводит себя предмет, при этом ЗАКРЫТА, и её
// заголовок утверждает обратное — «список аккаунтов человека строится только
// по членствам». Разрешается это так, и разрешение здесь записано, чтобы
// следующий читатель не разрешал его заново:
//
//   - заголовок #610 — её ПОСЫЛКА, и она опровергнута замером по стволу:
//     `ListAccountsForUser` (`user_repo.go`) объединяет ТРИ источника, и
//     второй из них — владение (`SELECT id FROM accounts WHERE
//     owner_user_id = $1`). Задача закрыта опровержением посылки;
//   - продуктовое РЕШЕНИЕ, которое #610 просила принять, принято и
//     зафиксировано: **владеть ≠ состоять**. Инварианты IAM-ID-1-09 и
//     IAM-ID-1-10 приёмки `sub-phase-IAM-ID-1` сняты кругом 3, приёмка
//     APPROVED на круге 5. Действует именно это утверждение;
//   - предмет ЭТОЙ пробы — ДРУГОЙ читатель. #610 мерила `ListAccountsForUser`;
//     здесь закрепляется `ScopeOf` (`visibility_repo.go`), из которого
//     строится сужение КАЖДОЙ списочной поверхности сервиса. Интеграционных
//     проб, зовущих `Visibility()`, в стволе до этой — ноль.
//
// Стадия S3 при этом уже частью посажена: миграция
// `944001_identity_scope_comes_from_membership.sql` перевела на членство
// представление `resource_scope_edge`. Ветку 'own' ЭТОГО запроса она не
// трогала — она по-прежнему читает `accounts.owner_user_id`, и именно этот
// непереведённый читатель проба и стережёт.
//
// # Что эта проба стережёт вперёд
//
// Стадия S3 переводит читателей принадлежности на членство. Ровно там ветку
// 'own' естественно захотеть выразить через `memberships` — и тогда владелец
// аккаунта, в котором он не состоит, тихо выпадет из кандидатов, а страница
// ответит `200` с пустым массивом при живом праве. Проба на это краснеет.
//
// Способность упасть доказана инъекцией: ветка 'own' переведена на join с
// `memberships` → проба краснеет и называет выпавший аккаунт; возвращена →
// молчит. Одного положительного утверждения было бы мало — запрос, отдающий ВСЕ
// аккаунты подряд, удовлетворил бы его тоже, поэтому рядом стоит посторонний
// (владеет своим, не владеет чужим) и перепись осмотренного.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/visibility"
)

// scopeOfUser — ScopeOf через ТОТ ЖЕ путь чтения, которым ходит use-case:
// Repository → Reader-TX → Visibility(). Собственная копия запроса здесь была бы
// вторым кодеком, который разойдётся с первым молча.
func scopeOfUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID string) visibility.Scope {
	t.Helper()
	rd, err := kachopg.New(pool, nil).Reader(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rd.Rollback(ctx) })

	scope, err := rd.Visibility().ScopeOf(ctx, visibility.Subject{Type: "user", ID: userID})
	require.NoError(t, err)
	return scope
}

func TestIntegration_Issue610_OwnedAccountWithoutMembershipStaysCandidate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx, pool := kac127Setup(t)

	// Человек и его личный аккаунт. Зеркало S1 заводит членство (U, A) триггером
	// на строке пользователя — это и есть «состою».
	owner, personal := kac127SeedUserAndAccount(t, ctx, pool, "own610")

	// Второй аккаунт того же человека. Триггер зеркала висит на `users`, а не на
	// `accounts`, поэтому членства (U, B) не возникает — и это НЕ дефект
	// фикстуры, а ровно то состояние, которое узаконило решение владельца.
	second := padOrTrim20("acc_610second")
	_, err := pool.Exec(ctx,
		`INSERT INTO accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		second, "acc-610-second", owner)
	require.NoError(t, err)

	// Посторонний: владеет СВОИМ аккаунтом и не владеет чужими. Он здесь затем,
	// чтобы «владелец видит свой» не удовлетворялось запросом, отдающим всё.
	stranger, strangerAcct := kac127SeedUserAndAccount(t, ctx, pool, "str610")

	// ── Предусловия. «Членства нет» и «строк не ноль» утверждаются ЯВНО:
	// оба утверждения ниже истинны тождественно на пустой таблице.
	var membershipsOfSecond int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.memberships WHERE user_id = $1 AND account_id = $2`,
		owner, second).Scan(&membershipsOfSecond))
	require.Zero(t, membershipsOfSecond,
		"предусловие пробы: во втором аккаунте членства у владельца быть не должно — "+
			"иначе она проверяет «состою», а не «владею»")

	var membershipsOfPersonal int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.memberships WHERE user_id = $1 AND account_id = $2`,
		owner, personal).Scan(&membershipsOfPersonal))
	require.Equal(t, 1, membershipsOfPersonal,
		"перепись: зеркало S1 обязано было завести членство в личном аккаунте — "+
			"если его нет, проба сравнивает две пустоты")

	var accountsSeen int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.accounts`).Scan(&accountsSeen))
	require.GreaterOrEqual(t, accountsSeen, 3,
		"перепись осмотренного: «посторонний не видит чужого» на пустой таблице "+
			"истинно тождественно (осмотрено аккаунтов: %d)", accountsSeen)

	// ── Утверждение #610: владею ⇒ кандидат, независимо от членства.
	scope := scopeOfUser(t, ctx, pool, owner)

	require.Contains(t, scope.OwnedAccounts, second,
		"аккаунт %s принадлежит %s, членства в нём нет — и он обязан остаться "+
			"кандидатом его списка: владеть ≠ состоять (kacho#610)", second, owner)
	require.Contains(t, scope.ScopedAccounts, second,
		"владеемый аккаунт обязан попасть и в ScopedAccounts — из них строится "+
			"сужение страницы; в OwnedAccounts без ScopedAccounts он невидим")
	require.True(t, scope.Owns(second),
		"Owns() — этажный пол владения, спрашиваемый на строку страницы")

	// Личный аккаунт виден по обеим половинам сразу: это положительный контроль
	// на то, что членство видимости НЕ мешает.
	require.Contains(t, scope.OwnedAccounts, personal)

	require.False(t, scope.Unrestricted,
		"владение не делает субъекта неограниченным — иначе сужения нет вовсе")

	// ── Отрицание в паре с положительным: посторонний видит своё и не видит чужого.
	strangerScope := scopeOfUser(t, ctx, pool, stranger)

	require.Contains(t, strangerScope.OwnedAccounts, strangerAcct,
		"положительный контроль: посторонний обязан видеть СВОЙ аккаунт — "+
			"иначе следующее утверждение зеленело бы на сломанном запросе")
	require.NotContains(t, strangerScope.OwnedAccounts, second,
		"посторонний не владеет чужим аккаунтом и не вправе получить его в кандидаты")
	require.NotContains(t, strangerScope.ScopedAccounts, second,
		"то же по ScopedAccounts: сужение не должно быть шире модели")
}
