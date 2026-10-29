// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

// journal_one_statement_test.go — создание и снятие аккаунта кладут журнал прав
// ОДНИМ оператором на транзакцию (kaname#617).
//
// Между операторами журнала одной транзакции замки строк прямого факта берутся
// порядком вызовов писателя, а не общим порядком (объект, субъект), который
// свёртка держит лишь внутри оператора. Транзакция с двумя операторами сходится в
// кольцо с любым писателем, берущим те же факты в общем порядке (40P01). Здесь
// утверждается число операторов, а кортежи — предпосылкой: их набор не меняется.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestCreate_JournalIsOneStatement(t *testing.T) {
	repo := newFakeRepo()
	uc := NewCreateAccountUseCase(repo, newFakeOpsRepo())

	op, err := uc.Execute(operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000000a617"}), domain.Account{Name: "acme-journal-617"})
	require.NoError(t, err)
	require.NotNil(t, op)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))

	var owner, cluster, project, hierarchy bool
	for _, tup := range repo.fgaTuples() {
		switch {
		case tup.Relation == "owner" && strings.HasPrefix(tup.Object, "account:"):
			owner = true
		case tup.Relation == "cluster" && strings.HasPrefix(tup.Object, "account:"):
			cluster = true
		case strings.HasPrefix(tup.Object, "project:"):
			project = true
		case strings.HasPrefix(tup.Object, "iam_access_binding:"):
			hierarchy = true
		}
	}
	require.True(t, owner && cluster && project && hierarchy,
		"предпосылка: создание выпустило владельца, указатель кластера, кортежи проекта и указатель выдачи владельца (%v)", repo.fgaTuples())

	repo.mu.Lock()
	calls := repo.fgaJournalCalls
	repo.mu.Unlock()
	assert.Equal(t, 1, calls, "создание аккаунта кладёт журнал прав одним оператором")
}

func TestDelete_JournalIsOneStatement(t *testing.T) {
	repo := newDelFakeRepo()
	repo.seedOwnerBinding()
	repo.members = []domain.UserID{"usr0000000000000m617"}

	op, err := NewDeleteAccountUseCase(repo, newFakeOpsRepo()).Execute(operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: delTestOwner}), domain.AccountID(delTestAcct))
	require.NoError(t, err)
	require.NotNil(t, op)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(ctx))

	var owner, cluster, member bool
	for _, tp := range repo.fgaDeleted() {
		switch {
		case tp.Relation == "owner" && tp.Object == "account:"+delTestAcct:
			owner = true
		case tp.Relation == "cluster" && tp.Object == "account:"+delTestAcct:
			cluster = true
		case tp.Relation == "account" && tp.Object == "iam_user:usr0000000000000m617":
			member = true
		}
	}
	require.True(t, owner && cluster && member,
		"предпосылка: снятие отозвало владельца, указатель кластера и указатель участника (%v)", repo.fgaDeleted())
	assert.Equal(t, 1, repo.fgaDelStatements, "снятие аккаунта кладёт журнал прав одним оператором")
}
