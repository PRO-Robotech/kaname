// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// assertion_client_audience_integration_test.go — сужение адресатов доезжает от
// записи ключа до полосы выпуска (задача #1136).
//
// # Что здесь измеряется, чего не измеряют пробы уровня use-case
//
// Те подают сужение ВХОДОМ и спрашивают про решение. Здесь спрашивается
// ЦЕПОЧКА: значение записывается настоящим писателем, лежит в настоящей
// колонке и приезжает настоящим чтением полосы аутентификации. Обрыв в любом
// звене этой цепочки невидим сверху — величина просто оказывается пустой, а
// пустая означает «сужения не объявлено», то есть выглядит законным состоянием.
//
// # Почему форма значения проверяется ОГРАНИЧЕНИЕМ, а не писателем
//
// Писатель сегодня один. Ограничение переживает появление второго — и переживает
// молча, тогда как проверка в писателе не переживает вовсе.
package pg_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// insertSAKey — запись строки ключа НАСТОЯЩИМ писателем, в своей транзакции.
func insertSAKey(t *testing.T, f assertionFixture, c domain.ServiceAccountOAuthClient) domain.ServiceAccountOAuthClient {
	t.Helper()
	ctx := context.Background()
	repo := kachopg.NewSAOAuthClientRepo(f.pool)
	tx, err := kachopg.NewPoolTxBeginner(f.pool).Begin(ctx)
	require.NoError(t, err)
	out, err := repo.Insert(ctx, tx, c)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return out
}

// saKeyRow — минимальная строка ключа с ключевым материалом.
func saKeyRow(f assertionFixture, id, mirror string, audiences []string) domain.ServiceAccountOAuthClient {
	return domain.ServiceAccountOAuthClient{
		// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
		// словарь таблицы отвергает строку, вида не назвавшую.
		CredentialKind:    domain.CredentialKindKeypair,
		ID:                domain.SAOAuthClientID(id),
		SvaID:             domain.ServiceAccountID(f.sva),
		OAuthClientID:     domain.OAuthClientID(mirror),
		CreatedByUserID:   domain.UserID(f.user),
		PublicKeyPEM:      testPublicKeyPEM,
		KeyAlgorithm:      "ES256",
		DeclaredAudiences: audiences,
	}
}

// TestSAKeyDeclaredAudiencesReachTheAssertionLane — сужение доезжает от записи
// до чтения полосы выпуска, и ключ без сужения от него отличим.
func TestSAKeyDeclaredAudiencesReachTheAssertionLane(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	f := newAssertionFixture(t)
	repo := kachopg.NewSAOAuthClientRepo(f.pool)

	const narrowed = "soc_ddddddddddddddddd"
	const wide = "soc_eeeeeeeeeeeeeeeee"
	want := []string{"registry.kacho.local", "https://sts.example.com"}

	persisted := insertSAKey(t, f, saKeyRow(f, narrowed, "mirror-narrowed", want))
	require.Equal(t, want, persisted.DeclaredAudiences,
		"писатель обязан вернуть записанное — иначе вызывающий строит ответ на том, что послал, а не на том, что легло")

	got, err := repo.Get(ctx, domain.SAOAuthClientID(narrowed))
	require.NoError(t, err)
	require.Equal(t, want, got.DeclaredAudiences, "чтение ресурса обязано вернуть записанное сужение")

	// ГЛАВНОЕ ЗВЕНО: полоса аутентификации читает СВОИМ оператором, и колонка
	// обязана участвовать именно в нём. Разойдись два чтения — решение о выдаче
	// принималось бы по величине, которой в строке нет.
	client, err := f.repo.ResolveAssertionClient(ctx, narrowed)
	require.NoError(t, err)
	require.Equal(t, domain.AssertionClientServiceAccount, client.Kind)
	require.Equal(t, want, client.DeclaredAudiences)

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: ключ без сужения приезжает пустым, а не с чужим.
	insertSAKey(t, f, saKeyRow(f, wide, "mirror-wide", nil))
	client, err = f.repo.ResolveAssertionClient(ctx, wide)
	require.NoError(t, err)
	require.Empty(t, client.DeclaredAudiences,
		"ключ, сужения не объявлявший, обязан приезжать пустым: иначе «не объявлено» неотличимо от чужого перечня")

	// ВТОРОЙ ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: клиент пользовательского токена. Автора
	// перечня у него нет by construction, и ветка объединения обязана отдавать
	// пусто, а не срываться на несуществующей колонке.
	const userClient = "uoc_ddddddddddddddddd"
	f.seedUserClient(t, userClient, "mirror-user", testPublicKeyPEM, "ES256", nil)
	client, err = f.repo.ResolveAssertionClient(ctx, userClient)
	require.NoError(t, err)
	require.Equal(t, domain.AssertionClientUser, client.Kind)
	require.Empty(t, client.DeclaredAudiences)
}

// TestSAKeyDeclaredAudiencesSchemaRefusesUnusableElements — форму значения
// держит ограничение таблицы.
//
// Оба отвергаемых входа — не «некрасивые», а НЕИСПОЛНИМЫЕ: пустую строку нельзя
// заказать ничем, а элемент сверх потолка контракта не пройдёт проверку входа и
// потому не появится ни в одном законном запросе. Приняв их, таблица хранила бы
// сужение, которое ключ никогда не удовлетворит, — то есть тихо обездвижила бы
// ключ.
func TestSAKeyDeclaredAudiencesSchemaRefusesUnusableElements(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	f := newAssertionFixture(t)

	seed := func(id string, audiences []string) error {
		_, err := f.pool.Exec(ctx,
			`INSERT INTO kacho_iam.service_account_oauth_clients
			   (id, sva_id, hydra_client_id, created_by_user_id, public_key_pem, key_algorithm, declared_audiences,
			    credential_kind)
			 VALUES ($1,$2,$3,$4,$5,'ES256',$6::text[],'KEYPAIR')`,
			id, f.sva, "mirror-"+id, f.user, testPublicKeyPEM, audiences)
		return err
	}

	require.Error(t, seed("soc_fffffffffffffffff", []string{"registry.kacho.local", ""}),
		"пустой элемент обязан отвергаться: заказать его нельзя ничем, и ключ с ним недостижим")
	require.Error(t, seed("soc_ggggggggggggggggg", []string{strings.Repeat("a", 513)}),
		"элемент сверх потолка контракта обязан отвергаться таблицей, а не только проверкой входа")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ по каждой оси: ограничение отвергает названное, а
	// не всё подряд. Без него обе строки выше зелены на таблице, не принимающей
	// ни одного перечня.
	require.NoError(t, seed("soc_hhhhhhhhhhhhhhhhh", []string{strings.Repeat("a", 512)}),
		"ровно потолок контракта обязан приниматься (граница включительная)")
	require.NoError(t, seed("soc_jjjjjjjjjjjjjjjjj", []string{}),
		"пустой перечень — законное состояние: «сужения не объявлено»")
}
