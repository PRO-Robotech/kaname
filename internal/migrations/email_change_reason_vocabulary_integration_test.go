// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// email_change_reason_vocabulary_integration_test.go — МИГРАЦИЯ СМЕНЫ АДРЕСА
// НЕ ТЕРЯЕТ ЗНАЧЕНИЙ СОСЕДА в словаре причин снятия сессии (kaname#635,
// приёмка `email-change-is-confirmed-from-the-new-address.md`, Р8 п. 4; ревью
// схемы волны 6, критическое 1).
//
// Словарь `human_sessions_ended_reason_check` переобъявляется целиком: каждая
// миграция снимает ограничение и ставит его заново полным списком. Две полосы
// одной волны (kaname#634 — `ended-from-another-session`, kaname#635 —
// `email-changed`) пишут свои миграции независимо, и SQL сливается без
// конфликта: младшая по номеру вводит своё слово, старшая — если её список
// составлен без соседа — молча его снимает. На базе, где сосед уже снимал
// сессии, накат старшей тогда падает на проверке лежащих строк, а её откат
// ставит словарь, отвергающий законные строки соседа.
//
// Проба держит обе стороны на ЛЕЖАЩИХ строках: строка с причиной соседа
// переживает накат и откат миграции смены адреса, а снятие с причиной соседа
// принимается и после наката, и после отката. Версии названы номерами: обе
// миграции уже в каталоге, а вопрос — именно об их паре.
package migrations_test

import (
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// ecOwnSessionsVersion — миграция kaname#634, вводящая причину соседа.
	ecOwnSessionsVersion int64 = 20261007104910
	// ecEmailChangeVersion — миграция kaname#635, вводящая `email-changed`.
	ecEmailChangeVersion int64 = 20261007150000
	// ecNeighbourReason — причина соседа, дословно (домен, kaname#634).
	ecNeighbourReason = "ended-from-another-session"
	// ecOwnReason — причина смены адреса, дословно (домен, kaname#635).
	ecOwnReason = "email-changed"
)

// TestEmailChangeMigration_EC_DB_01_NeighbourReasonSurvivesUpAndDown — строка,
// снятая с причиной соседа до наката, переживает накат и откат миграции смены
// адреса; снятие с причиной соседа принимается на обеих сторонах; строка,
// снятая сменой адреса, после отката становится `logout`.
func TestEmailChangeMigration_EC_DB_01_NeighbourReasonSurvivesUpAndDown(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	// Дано: база на версии соседа, его слово уже лежит в строке.
	db := serOpenAt(t, ecOwnSessionsVersion)
	person := serSeedPerson(t, db, "ecdb1")
	const lying, own, afterUp, afterDown = "hss-ecdb1-a", "hss-ecdb1-b", "hss-ecdb1-c", "hss-ecdb1-d"
	for i, id := range []string{lying, own, afterUp, afterDown} {
		serLiveRow(t, db, person, id, 0x100+i)
	}
	at := serMoment()
	require.NoError(t, serEnd(db, lying, at, ecNeighbourReason), "Дано: на версии соседа строка снята с %q", ecNeighbourReason)
	before := serReadRow(t, db, lying)

	// Когда: накат миграции смены адреса.
	require.NoError(t, goose.UpTo(db, ".", ecEmailChangeVersion),
		"накат до %d обязан проходить на базе, где лежит причина соседа", ecEmailChangeVersion)
	assert.Equal(t, before.String(), serReadRow(t, db, lying).String(), "строка соседа накатом не тронута")
	assert.NoError(t, serEnd(db, afterUp, at, ecNeighbourReason),
		"после наката снятие с %q принимается", ecNeighbourReason)
	require.NoError(t, serEnd(db, own, at, ecOwnReason), "после наката снятие с %q принимается", ecOwnReason)

	// Когда: откат миграции смены адреса — до версии соседа.
	require.NoError(t, goose.DownTo(db, ".", ecOwnSessionsVersion),
		"откат до %d обязан проходить", ecOwnSessionsVersion)
	assert.Equal(t, before.String(), serReadRow(t, db, lying).String(), "строка соседа откатом не тронута")
	if r := serReadRow(t, db, own).reason; assert.NotNil(t, r, "у снятой сменой адреса причина есть") {
		assert.Equal(t, "logout", *r, "снятая сменой адреса после отката — `logout`")
	}
	assert.NoError(t, serEnd(db, afterDown, at, ecNeighbourReason),
		"после отката снятие с %q принимается", ecNeighbourReason)

	// И: повторный накат сходится.
	require.NoError(t, goose.UpTo(db, ".", ecEmailChangeVersion), "повторный накат")
}
