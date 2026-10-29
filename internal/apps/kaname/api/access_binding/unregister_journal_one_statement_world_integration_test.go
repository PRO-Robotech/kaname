// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// unregister_journal_one_statement_world_integration_test.go — снятие
// регистрации родителя с потомками кладёт журнал прав ОДНИМ оператором
// (kaname#617, перепись писателей журнала SD-942-617-1; dropDescendants).
//
// ПРЕДМЕТ. Транзакция снятия регистрации пишет журнал многими путями: надгробие
// кортежей самого объекта, отзыв выдач, называющих его, — и на каждого потомка
// (kaname#1002) надгробие его кортежей, отзыв выдач на него и снятие его
// публикации. Оператором на каждый путь она брала замки строк факта порядком
// этих путей — родитель, затем потомки по одному, — а не общим порядком
// (объект, субъект, отношение), который свёртка держит лишь внутри оператора.
// Такая транзакция сходится в кольцо (40P01) с любым писателем, берущим те же
// факты в общем порядке, — например, с отзывом выдачи, чей реестр стоит на
// нескольких потомках.
//
// Число операторов считает триггер счётчика в базе пробы (journalstmt).
//
// БЛИЗНЕЦ — регистрация репозитория в том же мире: один кортеж на транзакцию,
// один оператор на любой ревизии.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/testsupport/journalstmt"
)

func TestUnregister_ParentWithDescendantsLaysItsJournalInOneStatement(t *testing.T) {
	w := newCascadeWorld(t)
	probe := journalstmt.Install(t, w.ctx, w.pool)
	probe.Reset(t, w.ctx)

	w.withdrawX()

	c := probe.Count(t, w.ctx)
	t.Logf("перепись журнала: транзакций %d, операторов %d, наибольшее на транзакцию %d", c.Transactions, c.Statements, c.MaxPerTx)
	require.Positive(t, c.Statements, "ПРЕДПОСЫЛКА: снятие регистрации писало журнал")
	assert.Equal(t, 1, c.MaxPerTx,
		"снятие родителя с потомками кладёт надгробия, отзыв выдач и снятие публикаций одним оператором журнала")
	w.assertDescendantGone(pcrXApp, w.grantXApp, "kaname#617: снятие одним оператором")
	w.assertDescendantGone(pcrXWeb, w.grantXWeb, "kaname#617: снятие одним оператором")
	w.assertAlive(pcrRepoType, pcrYApp, w.grantYApp, "kaname#617: потомок соседнего реестра")
}

func TestRegister_RepositoryLaysOneStatement(t *testing.T) {
	w := newCascadeWorld(t)
	probe := journalstmt.Install(t, w.ctx, w.pool)
	probe.Reset(t, w.ctx)

	w.registerRepository(pcrX, "j617")

	c := probe.Count(t, w.ctx)
	require.Positive(t, c.Statements, "ПРЕДПОСЫЛКА: регистрация писала журнал")
	assert.Equal(t, 1, c.MaxPerTx, "близнец: регистрация — один оператор на любой ревизии")
}
