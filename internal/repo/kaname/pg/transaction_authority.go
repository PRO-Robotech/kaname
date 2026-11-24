// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// TransactionRelationChecker сохраняет производственный вердикт и допуск
// человека, пользуясь удерживаемой транзакцией вместо нового чтения из пула.
func (w *writeTx) TransactionRelationChecker(plans *authzmodel.Plans) (kanamerepo.RelationChecker, error) {
	if plans == nil || w.tx == nil {
		return nil, authzguard.AuthzBackendUnavailable()
	}
	return authzcascade.WrapAdmitted(relverdict.NewTransactionAsker(w.tx, plans), personmarks.NewTransaction(w.tx)), nil
}
