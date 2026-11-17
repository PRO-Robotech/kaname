// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
)

// retiredSeedRunner строит только исторический дом MRW-16, до миграции
// 20260916150000. Современный ModuleSeedWriteRepo требует authority entry,
// которого эта схема ещё не содержит. Сохраняем настоящий Applier и его TX
// на модуль, но записываем прежние SA/членство/журнал SQL-контрактом той эпохи.
// Прямой relation_fact по-прежнему создаёт реальный триггер журнала.
// Группы, выдачи и иные области намеренно отвергаются: это не compatibility
// fallback продукта и не универсальный второй применитель.
type retiredSeedRunner struct{ db *sql.DB }

func (r retiredSeedRunner) RunInWriteTx(ctx context.Context, fn func(context.Context, moduleseed.Writer) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(ctx, retiredSeedWriter{tx: tx}); err != nil {
		return err
	}
	return tx.Commit()
}

type retiredSeedWriter struct{ tx *sql.Tx }

func (w retiredSeedWriter) UpsertServiceAccount(ctx context.Context, account, name, description string) (bool, error) {
	if account != "system" {
		return false, fmt.Errorf("исторический дом MRW-16 не поддерживает аккаунт %q", account)
	}
	var accountID string
	if err := w.tx.QueryRowContext(ctx, `SELECT id FROM kaname.accounts WHERE name=$1`, account).Scan(&accountID); err != nil {
		return false, err
	}
	res, err := w.tx.ExecContext(ctx, `
 INSERT INTO kaname.service_accounts(id,account_id,name,description,created_at,enabled,labels)
 VALUES ('sva' || substr(md5($2),1,17),$1,$2,$3,now(),true,'{}')
 ON CONFLICT(id) DO UPDATE SET description=EXCLUDED.description
 WHERE kaname.service_accounts.description IS DISTINCT FROM EXCLUDED.description`, accountID, name, description)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (w retiredSeedWriter) JoinGroup(ctx context.Context, saAccount, saName, groupAccount, groupName string) (bool, error) {
	if saAccount != "system" || groupAccount != "system" || groupName != quotaReadersGroupName {
		return false, fmt.Errorf("вступление вне исторического дома MRW-16: %s/%s в %s/%s", saAccount, saName, groupAccount, groupName)
	}
	var saID, groupID string
	if err := w.tx.QueryRowContext(ctx, `SELECT s.id FROM kaname.service_accounts s
 JOIN kaname.accounts a ON a.id=s.account_id WHERE a.name=$1 AND s.name=$2`, saAccount, saName).Scan(&saID); err != nil {
		return false, err
	}
	if err := w.tx.QueryRowContext(ctx, `SELECT g.id FROM kaname.groups g
 JOIN kaname.accounts a ON a.id=g.account_id WHERE a.name=$1 AND g.name=$2`, groupAccount, groupName).Scan(&groupID); err != nil {
		return false, err
	}
	res, err := w.tx.ExecContext(ctx, `INSERT INTO kaname.group_members(group_id,member_type,member_id,added_at)
 VALUES ($1,'service_account',$2,now()) ON CONFLICT DO NOTHING`, groupID, saID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	_, err = w.tx.ExecContext(ctx, `INSERT INTO kaname.fga_outbox(event_type,payload,created_at)
 VALUES ('fga.tuple.write',jsonb_build_object('user',$1::text,'object',$2::text,'relation','member'),now())`,
		"service_account:"+saID, "group:"+groupID)
	return err == nil, err
}

func (w retiredSeedWriter) UpsertGroup(context.Context, string, string, string) (bool, error) {
	return false, fmt.Errorf("исторический дом MRW-16 не создаёт группы")
}

func (w retiredSeedWriter) GrantRelation(context.Context, moduleseed.Subject, string, string, string) (bool, error) {
	return false, fmt.Errorf("исторический дом MRW-16 не выдаёт отношения")
}

func (w retiredSeedWriter) GrantRole(context.Context, moduleseed.Subject, string, string, string) (bool, error) {
	return false, fmt.Errorf("исторический дом MRW-16 не выдаёт роли")
}
