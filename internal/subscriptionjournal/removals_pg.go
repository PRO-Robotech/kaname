// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package subscriptionjournal

// removals_pg.go — адаптер порта [RemovalScopes] поверх журнала.
//
// # Почему СВЕЖАЯ строка, а не «есть ли снятие вообще»
//
// Идентификатор неизменяем и глобально уникален by construction, поэтому
// воскрешения предмета не бывает. Но строк по нему несколько — создание, правки,
// снятие, — и предметом вопроса является ПОСЛЕДНЯЯ: только она говорит, каково
// состояние предмета сейчас. Предикат «есть ли где-нибудь строка со снятием»
// отвечал бы то же самое лишь до тех пор, пока это верно, и перестал бы молча.
//
// # Почему один запрос на вид, а не на предмет
//
// Партия сужателя — до сотни идентификаторов одного вида. Вопрос на предмет
// сделал бы стоимость партии растущей с её размером, тогда как она обязана
// принадлежать ЗАПРОСУ.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolRemovalScopes — чтение журнала из пула.
//
// Пул, а не выделенное соединение подписки: то занято `LISTEN` всё время жизни
// потока, и читать им значило бы делить одно соединение между ожиданием
// пробуждения и вопросом.
type PoolRemovalScopes struct {
	pool *pgxpool.Pool
}

// NewPoolRemovalScopes — сборка из композиционного корня.
func NewPoolRemovalScopes(pool *pgxpool.Pool) *PoolRemovalScopes {
	return &PoolRemovalScopes{pool: pool}
}

// CapturedScopes — области ТОЛЬКО тех предметов, чья свежая строка есть снятие.
//
// Предмет, у которого свежая строка не снятие, в ответе отсутствует: наличие
// ключа и есть признак «снят». Пустая карта — законный ответ, а не сбой.
func (a *PoolRemovalScopes) CapturedScopes(
	ctx context.Context, kind string, ids []string,
) (map[string][]Scope, error) {
	out := make(map[string][]Scope)
	if a == nil || a.pool == nil || kind == "" || len(ids) == 0 {
		return out, nil
	}

	const q = `
		SELECT DISTINCT ON (j.resource_id) j.resource_id, j.event_type, j.scope
		  FROM kaname.resource_journal j
		 WHERE j.resource_kind = $1 AND j.resource_id = ANY($2::text[])
		 ORDER BY j.resource_id, j.sequence_no DESC`

	rows, err := a.pool.Query(ctx, q, kind, ids)
	if err != nil {
		return nil, fmt.Errorf("subscriptionjournal: чтение снятий журнала: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id    string
			event string
			raw   []byte
		)
		if err := rows.Scan(&id, &event, &raw); err != nil {
			return nil, fmt.Errorf("subscriptionjournal: разбор строки журнала: %w", err)
		}
		if event != changeDeleted {
			continue
		}
		var captured []struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		}
		if err := json.Unmarshal(raw, &captured); err != nil {
			// Разбор не удался — это «ответа нет», а не «областей нет»: пустой
			// набор здесь означал бы, что снятие не доедет никому, и означал бы
			// это молча.
			return nil, fmt.Errorf(
				"subscriptionjournal: разбор захваченных областей (%s %s): %w",
				kind, id, err)
		}
		scopes := make([]Scope, 0, len(captured))
		for _, c := range captured {
			scopes = append(scopes, Scope{Type: c.Type, ID: c.ID})
		}
		out[id] = scopes
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("subscriptionjournal: чтение снятий журнала: %w", err)
	}
	return out, nil
}

// Compile-time assertion.
var _ RemovalScopes = (*PoolRemovalScopes)(nil)
