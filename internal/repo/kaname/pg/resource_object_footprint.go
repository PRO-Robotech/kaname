// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Области объектного OUTPUT не являются installation-требованиями: модуль
// проверяется только на OLD+NEW владельцах собственной регистрации. Здесь
// участвуют текущий объект и retained canonical scopes уже удалённого mirror.
// Ни субъект ledger, ни домашний аккаунт module SA не заменяют этот источник.
func (c *resourceOutputCapture) addObjectScopes(ctx context.Context, parents *resourceParentCapture, f *resourceFootprint) error {
	if c == nil || parents == nil || parents.source == nil || parents.source.sealed || f == nil {
		return kaname.ErrSourceUnconfirmed
	}
	object, present, err := parents.captureObjectProjection(ctx, c.object.Type, c.object.ID)
	if err != nil {
		return err
	}
	accounts := map[string]bool{}
	if present {
		for _, account := range object.ParentAccountIDs {
			accounts[account] = true
		}
	}
	// Retained scope содержит именно OLD account. Исчезновение project не
	// заставляет угадывать его прежнего владельца через новое дерево проектов.
	if domain.FeedSourceForType(c.object.Type) != domain.FeedIAMDirect {
		rows, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceRegistrationScopes, typ: c.modelType, id: c.object.ID})
		if err != nil {
			return err
		}
		for _, captured := range rows {
			var row struct {
				Type    string `json:"object_type"`
				ID      string `json:"object_id"`
				Account string `json:"account_id"`
				Project string `json:"project_id"`
			}
			if json.Unmarshal(captured.value, &row) != nil || row.Type != c.modelType || row.ID != c.object.ID || !nativeQuestionToken(row.Account) || (row.Project != "" && !nativeQuestionToken(row.Project)) {
				return kaname.ErrSourceUnconfirmed
			}
			accounts[row.Account] = true
		}
	}
	for _, account := range resourceSortedSet(accounts) {
		if err = parents.captureAccount(ctx, account); err != nil {
			return err
		}
		if err = f.addMutationAccount(domain.AccountID(account)); err != nil {
			return err
		}
	}
	return nil
}
