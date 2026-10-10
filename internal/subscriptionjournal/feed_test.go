// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package subscriptionjournal

// feed_test.go — объявление журнала при включённом флаге почты несёт ключ ленты
// ровно в той форме, которую требует писатель фундамента, и только его сверх
// объявления без флага (замысел issue-2917 З2, З17; приёмка NTF-2 Р1, CX2-27).
//
// Ожидаемое выводится ИЗ ДЕРЕВА: словарь видов — из ограничения миграции,
// принявшей ключ ленты; тип объекта — из канонической модели прав; форма вида —
// отказом самого писателя фундамента (`feed.JournalSignal`), а не вторым
// списком условий здесь.

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/notify/feed"
	"github.com/PRO-Robotech/corelib/subscription"

	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// feedSignalMigration — миграция, принявшая ключ ленты в словарь видов журнала.
const feedSignalMigration = "../migrations/20261010031946_resource_journal_admits_the_feed_signal.sql"

// TestFeedJournalKindsAgreeWithTheFeedSignalMigration — словарь видов
// объявления при включённом флаге и словарь, закрытый ограничением миграции
// ключа ленты, суть ОДИН словарь.
func TestFeedJournalKindsAgreeWithTheFeedSignalMigration(t *testing.T) {
	src, err := os.ReadFile(filepath.Clean(feedSignalMigration))
	require.NoError(t, err, "миграция ключа ленты обязана лежать по названному пути")

	declared := kindsIn(t, src, "resource_journal_resource_kind_check")
	require.NotEmpty(t, declared, "перепись пуста: ограничение прочитано не то")

	var own []string
	for kind := range FeedJournal().Mapping.Kinds {
		own = append(own, kind)
	}
	sort.Strings(own)

	assert.Equal(t, declared, own,
		"вид, закрытый базой и не объявленный владельцем, недоставляем; "+
			"объявленный и не закрытый базой — строка, которой не будет")
}

// TestFeedJournalDiffersFromTheFlagOffJournalByTheFeedKeyAlone — объявление при
// включённом флаге = объявление без флага + ключ ленты, и ничего больше; без
// флага ключа нет (З2: при выключенном флаге ключ не объявляется).
func TestFeedJournalDiffersFromTheFlagOffJournalByTheFeedKeyAlone(t *testing.T) {
	off, on := Journal(), FeedJournal()

	_, offHasKey := off.Mapping.Kinds[feed.JournalKey]
	assert.False(t, offHasKey, "без флага почты ключ %q не объявляется (З2)", feed.JournalKey)

	require.Contains(t, on.Mapping.Kinds, feed.JournalKey,
		"при флаге почты ключ ленты объявлен — иначе писатель строки сигнала не собирается")
	require.Len(t, on.Mapping.Kinds, len(off.Mapping.Kinds)+1,
		"сверх ключа ленты объявление не расширяется")
	for k, v := range off.Mapping.Kinds {
		assert.Equal(t, v, on.Mapping.Kinds[k], "вид %q обязан совпасть в обоих объявлениях", k)
	}
	assert.Equal(t, off.Storage, on.Storage, "журнал один: хранилище не расходится")
	assert.Equal(t, off.Channel, on.Channel, "журнал один: канал не расходится")
	assert.Equal(t, off.Mapping.Changes, on.Mapping.Changes, "журнал один: словарь рода не расходится")

	require.NoError(t, on.Validate(),
		"объявление обязано проходить суждение механизма — иначе сервер потока не поднимется")
}

// TestFeedKindIsTheClusterLevelFeedObject — вид ключа ленты — объект
// `notification_feed` уровня кластера без имени: так его требует писатель
// фундамента, и так его судит модель прав.
func TestFeedKindIsTheClusterLevelFeedObject(t *testing.T) {
	k := FeedJournal().Mapping.Kinds[feed.JournalKey]
	assert.Equal(t, "notification_feed", k.ObjectType)
	assert.Equal(t, subscription.ScopeCluster, k.Scope)
	assert.Equal(t, subscription.NameFormNone, k.NameForm)
	assert.NotEmpty(t, k.Action, "действие несётся в записи вида, а не наследуется")
}

// TestFeedSignalIsBuiltOverTheOwnersDeclaration — порт журнала ленты
// собирается писателем фундамента над объявлением владельца; над объявлением
// без флага тот же писатель отказывает, называя ключ — это и есть пара.
func TestFeedSignalIsBuiltOverTheOwnersDeclaration(t *testing.T) {
	sig, err := FeedSignal()
	require.NoError(t, err)
	require.NotNil(t, sig)

	_, err = feed.JournalSignal(Journal(), manifest.AccessServiceFeed, changeUpdated)
	require.Error(t, err, "близнец: без ключа ленты писатель строки сигнала не собирается")
	assert.Contains(t, err.Error(), feed.JournalKey)
}

// TestFeedStateIsUnavailableByWord — состояние строки сигнала — словом
// `state_unavailable` (NOT_PRODUCED), а не пустой нагрузкой (CX2-27).
func TestFeedStateIsUnavailableByWord(t *testing.T) {
	st, absence, err := FeedJournal().Mapping.State(subscription.Row{Kind: feed.JournalKey, ID: manifest.AccessServiceFeed})
	require.NoError(t, err)
	assert.Nil(t, st)
	assert.Equal(t, subscription.StateNotProduced, absence)
}
