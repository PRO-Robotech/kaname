// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// oauth_ceremony_issuance_rule.go — читатель правила выдачи на пути церемонии
// (задача PRO-Robotech/kaname#456, Р5б).
//
// Порт выпуска церемонии (`ceremonyport.AccessTokens`) спрашивает правило
// выдачи между погашением кода (либо захватом предъявленного токена
// обновления) и подписью. В этом окне транзакция запроса обмена либо единицы
// работы оборота держит связь пула (`oauth_ceremony_vaults.go`, шапка): второе
// взятие связи при пуле, занятом такими же обменами, ждало бы само себя до
// срока вызова порта. Поэтому оба вопроса правила — отсечка человека и отметка
// адреса — читаются в ТОЙ ЖЕ транзакции, если контекст её несёт, и пулом вне
// неё. Операторы — те же единственные тексты (`revokedBeforeSQL`,
// `personmarks.Read`): своего чтения у пути церемонии нет.

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
)

// ceremonyQuerier — соединение, на котором читает путь церемонии: транзакция
// единицы работы, иначе транзакция запроса обмена, иначе пул.
type ceremonyQuerier interface {
	rowQuerier
	personmarks.Querier
}

// CeremonyIssuanceRule — читатель правила выдачи для порта выпуска церемонии;
// реализует `revocationpolicy.Lookup`.
type CeremonyIssuanceRule struct{ pool *pgxpool.Pool }

// NewCeremonyIssuanceRule — читатель над пулом службы.
func NewCeremonyIssuanceRule(pool *pgxpool.Pool) *CeremonyIssuanceRule {
	return &CeremonyIssuanceRule{pool: pool}
}

func (r *CeremonyIssuanceRule) querier(ctx context.Context) ceremonyQuerier {
	if u, ok := unitFrom(ctx); ok && u.tx != nil {
		return u.tx
	}
	if tx, ok := requestTx(ctx); ok {
		return tx
	}
	return r.pool
}

// UserRevokedBefore — отсечка человека (тот же оператор, что у остальных её
// читателей).
func (r *CeremonyIssuanceRule) UserRevokedBefore(ctx context.Context, userID string) (time.Time, bool, error) {
	return revokedBeforeQ(ctx, r.querier(ctx), userID)
}

// PersonMarks — отметки адреса (`admission.Marks`) единственным оператором
// чтения отметки.
func (r *CeremonyIssuanceRule) PersonMarks(ctx context.Context, ids []string) (map[string]bool, error) {
	return personmarks.Read(ctx, r.querier(ctx), ids)
}
