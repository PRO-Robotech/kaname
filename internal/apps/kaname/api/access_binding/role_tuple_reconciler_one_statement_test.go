// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// role_tuple_reconciler_one_statement_test.go — сверка кортежей выдач роли кладёт
// журнал прав ОДНИМ оператором на транзакцию (kaname#617, SD-942-617-1).
//
// Между операторами журнала порядок замков строк факта — порядок вызовов
// писателя; встречные смены ролей сходятся в кольцо (40P01, проба
// `TestRoleUpdatesOfOneSubjectCommitWhenTheirFanoutsMeetCrosswise`). Здесь
// утверждается причина, а не симптом: сколько операторов журнала положила одна
// сверка. Смена яруса — снятие прежнего и выдача нового — один оператор;
// близнец — ярус не менялся, операторов ноль на любой ревизии.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	ab_repo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// journalStatements — сколько операторов журнала прав записал след транзакции.
func journalStatements(trace []string) int {
	n := 0
	for _, op := range trace {
		if strings.HasPrefix(op, "emit_relation_") {
			n++
		}
	}
	return n
}

func TestRoleTupleReconcile_TierChangeIsOneJournalStatement(t *testing.T) {
	const roleID = "rol00000000000rtr617"
	readPerms := domain.Permissions{"iam.role.read"}
	writePerms := domain.Permissions{"iam.role.read", "iam.role.write"}
	userA := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_rtr617_a--------"}
	userB := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_rtr617_b--------"}
	repo := rtrMultiSubjectGrant(t, roleID, readPerms, userA, userB)
	repo.drainFGAWritten()
	repo.resetTxOpTrace()

	rtrReconcile(t, repo, roleID, writePerms)

	trace := repo.txOpTrace()
	written, deleted := repo.drainFGAWritten(), repo.drainFGADeleted()
	for _, s := range []domain.Subject{userA, userB} {
		require.Contains(t, deleted, ab_repo.RelationTuple{User: "user:" + string(s.ID), Relation: "viewer", Object: "account:acc_rtr_account-----"},
			"предпосылка: прежний ярус субъекта %s снят", s.ID)
		require.Contains(t, written, ab_repo.RelationTuple{User: "user:" + string(s.ID), Relation: "editor", Object: "account:acc_rtr_account-----"},
			"предпосылка: новый ярус субъекта %s выпущен", s.ID)
	}
	assert.Equal(t, 1, journalStatements(trace),
		"смена яруса кладёт снятия и выдачи веера одним оператором журнала; след транзакции: %v", trace)
}

func TestRoleTupleReconcile_UnchangedTierWritesNoJournal(t *testing.T) {
	const roleID = "rol00000000000rtr618"
	perms := domain.Permissions{"iam.role.read"}
	userA := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_rtr618_a--------"}
	repo := rtrMultiSubjectGrant(t, roleID, perms, userA)
	repo.resetTxOpTrace()

	rtrReconcile(t, repo, roleID, perms)

	assert.Zero(t, journalStatements(repo.txOpTrace()), "ярус не менялся — операторов журнала нет")
}
