// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Чтение ОКНА ПРЕЖНЕГО ИЗДАТЕЛЯ — строк удостоверений, чьё зеркало клиента у
// внешнего OAuth-сервера ещё предъявимо (эпик kacho#2564, линия B).
//
// # Зачем отдельная величина
//
// Снятие прежнего издателя открывается, когда «окно предъявленного закрыто
// счётом, а не сроком». Счёт здесь — запрос к базе, и до этого читателя его
// исполнял только тот, кто о нём вспомнил: предикат стоял прозой в шапке
// use-case токенов пользователя. Ряд на витрине делает величину свойством
// стенда, а не памяти дежурного.
//
// # Что считается зеркалом — по таблице, и разница несущая
//
// У ключей служебной учётки колонка `hydra_client_id` непуста и на переведённом
// контуре: там она несёт НАШЕ имя клиента, равное идентификатору строки
// (`sa_keys.nameClient`), а ограничение схемы требует её непустой у
// KEYPAIR/FEDERATED. Зеркало — то, что от нашего имени ОТЛИЧАЕТСЯ. У токенов
// пользователя переведённый контур зеркала не пишет вовсе (пусто → NULL), и
// непустая колонка есть строка прежнего выпуска.
//
// Считать обе таблицы одним предикатом нельзя: `IS NOT NULL` у служебных учёток
// считал бы КАЖДЫЙ наш ключ зеркалом, и окно не закрылось бы никогда; `<> id` у
// пользователей молчало бы на строке прежнего выпуска, чьё зеркало случайно
// совпало бы с идентификатором, — состояние невозможное по форме имён, но
// предикат обязан быть верным by construction, а не по совпадению.

// ProviderMirrorRepo — читатель окна прежнего издателя.
type ProviderMirrorRepo struct {
	pool *pgxpool.Pool
}

// NewProviderMirrorRepo — constructor. Composition root: cmd/kaname/serve.go.
func NewProviderMirrorRepo(pool *pgxpool.Pool) *ProviderMirrorRepo {
	return &ProviderMirrorRepo{pool: pool}
}

// ProviderMirrorRows — строки с зеркалом по таблицам.
type ProviderMirrorRows struct {
	ServiceAccountKeys int64
	UserTokens         int64
}

// Count — сколько строк ещё несут зеркало у прежнего издателя, по таблице.
//
// Один запрос на обе таблицы, чтобы величины были сняты в одном снимке: две
// величины из двух транзакций могли бы разойтись на строке, снятой между ними,
// и ноль в одной не говорил бы ничего о другой.
func (r *ProviderMirrorRepo) Count(ctx context.Context) (ProviderMirrorRows, error) {
	const q = `
		SELECT
		  (SELECT count(*) FROM kaname.service_account_oauth_clients
		    WHERE hydra_client_id IS NOT NULL AND hydra_client_id <> id),
		  (SELECT count(*) FROM kaname.user_oauth_clients
		    WHERE hydra_client_id IS NOT NULL)`
	var rows ProviderMirrorRows
	if err := r.pool.QueryRow(ctx, q).Scan(&rows.ServiceAccountKeys, &rows.UserTokens); err != nil {
		return ProviderMirrorRows{}, fmt.Errorf("count provider mirror rows: %w", err)
	}
	return rows, nil
}
