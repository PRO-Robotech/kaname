// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Доказательство способности гейта §20 УПАСТЬ — и СМОЛЧАТЬ.
//
// Гейт рядом зелен на настоящем дереве, и это не говорит ничего о том, умеет ли
// он краснеть. Здесь ему подаются СИНТЕТИЧЕСКИЕ тексты: по одному дефекту на
// каждую половину, и рядом с каждым — законный близнец, на котором гейт обязан
// молчать. Инъекция снимает РОВНО одно свойство: вторая половина в каждой пробе
// остаётся целой, иначе красное приходило бы от соседнего требования и про
// снятое не говорило бы ничего.

const (
	// synthQueueMigration — миграция, объявляющая очередь вместе с колонкой.
	synthQueueMigration = "CREATE TABLE kaname.invite_mail_outbox (\n" +
		"    id bigserial PRIMARY KEY,\n" +
		"    sent_at timestamptz\n);\n"
	// synthOtherMigration — соседняя миграция без предмета.
	synthOtherMigration = "ALTER TABLE kaname.users ADD COLUMN nickname text;\n"
	// synthWiring — провязка уборки для этой очереди.
	synthWiring = "outbox.StartQueueRetentionSweep(ctx, pool, outbox.QueueRetentionConfig{\n" +
		"\tTable: clients.InviteMailTable,\n})\n"
)

// synthContracts — контракт БЕЗ поля времени сдачи (законное состояние).
func synthContracts() map[string]string {
	return map[string]string{
		"user.proto":       "message InviteUserMetadata {\n  string user_id = 1;\n}\n",
		"membership.proto": "message Membership {\n  string id = 1;\n}\n",
	}
}

func synthMigrations() map[string]string {
	return map[string]string{
		"20260831114500_invite_mail_outbox.sql": synthQueueMigration,
		"0001_users.sql":                        synthOtherMigration,
	}
}

// TestSendTimeGateIsSilentOnTheLawfulTree — положительный контроль.
// Без него отрицания ниже зеленели бы на чём угодно.
func TestSendTimeGateIsSilentOnTheLawfulTree(t *testing.T) {
	findings, c := auditSendTime(synthMigrations(), synthContracts(), synthWiring)
	require.Empty(t, findings, "гейт краснеет на законном дереве — отрицания ниже ничего не докажут")
	require.Equal(t, 1, c.queueDecls, "предмет записи обязан быть найден")
	require.Equal(t, 1, c.sweepWirings, "провязка уборки обязана быть найдена")
	require.Zero(t, c.contractHits)
}

// TestSendTimeGateRedsWhenTheQueueColumnIsGone — ПОЛОЖИТЕЛЬНАЯ половина.
// Снят предмет записи: гейт обязан позвать к себе, а не замолчать.
func TestSendTimeGateRedsWhenTheQueueColumnIsGone(t *testing.T) {
	migrations := synthMigrations()
	migrations["20260831114500_invite_mail_outbox.sql"] = synthOtherMigration // очереди больше нет

	findings, c := auditSendTime(migrations, synthContracts(), synthWiring)

	require.NotEmpty(t, findings, "исчезнувший предмет записи оставил гейт зелёным — это и есть замолкание")
	require.Contains(t, findings[0], "ПОЛОЖИТЕЛЬНАЯ ПОЛОВИНА")
	require.Zero(t, c.queueDecls)
	// Вторая половина цела: красное пришло РОВНО от снятого.
	require.Equal(t, 1, c.sweepWirings)
	require.Len(t, findings, 1)
}

// TestSendTimeGateRedsWhenTheSweepIsUnwired — ПОЛОЖИТЕЛЬНАЯ половина, вторая ось.
// Уборка и есть довод об эфемерности; без неё довод §20 отпадает.
func TestSendTimeGateRedsWhenTheSweepIsUnwired(t *testing.T) {
	findings, c := auditSendTime(synthMigrations(), synthContracts(), "// уборка снята\n")

	require.NotEmpty(t, findings)
	require.Contains(t, findings[0], "уборка доставленных")
	require.Zero(t, c.sweepWirings)
	require.Equal(t, 1, c.queueDecls, "предмет цел: красное пришло от снятой уборки")
	require.Len(t, findings, 1)
}

// TestSendTimeGateRedsWhenTheContractGainsTheField — ОТРИЦАТЕЛЬНАЯ половина.
// Величина доехала до контракта: §20 стала ложью в тот же коммит.
func TestSendTimeGateRedsWhenTheContractGainsTheField(t *testing.T) {
	contracts := synthContracts()
	contracts["membership.proto"] = "message Membership {\n  string id = 1;\n" +
		"  google.protobuf.Timestamp sent_at = 9;\n}\n"

	findings, c := auditSendTime(synthMigrations(), contracts, synthWiring)

	require.NotEmpty(t, findings)
	require.Contains(t, findings[0], "ОТРИЦАТЕЛЬНАЯ ПОЛОВИНА")
	require.Equal(t, 1, c.contractHits)
	require.Len(t, findings, 1)
}

// TestSendTimeGateIsSilentOnTheFieldNamedOnlyInProse — ЗАКОННЫЙ БЛИЗНЕЦ.
//
// Имя величины законно стоит в прозе контракта: объяснение, почему поля нет, —
// не поле. Гейт, судящий по подстроке, краснел бы на собственном объяснении.
func TestSendTimeGateIsSilentOnTheFieldNamedOnlyInProse(t *testing.T) {
	contracts := synthContracts()
	contracts["membership.proto"] = "message Membership {\n" +
		"  // Времени сдачи письма здесь нет: `sent_at` живёт в очереди и\n" +
		"  // эфемерен — см. known-divergences.md §20.\n" +
		"  // string sent_at = 9;\n" +
		"  string id = 1;\n}\n"

	findings, c := auditSendTime(synthMigrations(), contracts, synthWiring)

	require.Empty(t, findings, "имя в комментарии принято за объявление поля — гейт судит подстроку, а не узел")
	require.Zero(t, c.contractHits)
}
