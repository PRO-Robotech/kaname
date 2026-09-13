// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Инъекция гейта «машинерия, названная контрактом, существует» — В ОБЕ СТОРОНЫ.
//
// Разбор вынесен в `AuditMachineryClaims` именно затем, чтобы способность падать
// доказывалась ПОДАЧЕЙ ВХОДА, а не чтением: настоящий набор контрактов и
// синтетический мир проходят одну функцию, поэтому доказанное на втором верно
// для первого.
//
// У КАЖДОЙ оси — свой дефект и свой ЗАКОННЫЙ БЛИЗНЕЦ, и близнец отличается от
// дефекта РОВНО ОДНИМ фактом:
//
//	таблица          снятая очередь ⇄ живая очередь того же вида
//	канал            снятый канал ⇄ живой канал того же вида
//	контракт         имя без файла ⇄ имя с файлом
//	маркер           имя БЕЗ маркера — не заявление вовсе
//	исполняемая часть имя в строке контракта, а не в комментарии
//	перенос строки   имя, отделённое от маркера переносом
//	пустой обход     заявлений ноль — перепись обязана это назвать
package check_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// liveWorld — факты дерева, в котором очередь и канал ЖИВЫ, а соседний контракт
// существует. Все близнецы ниже судятся против него.
func liveWorld(sources map[string]string) check.MachineryFacts {
	return check.MachineryFacts{
		Sources:   sources,
		Tables:    map[string]struct{}{"audit_outbox": {}, "session_revocations": {}},
		Channels:  map[string]struct{}{"kaname_invite_mail_outbox": {}},
		Contracts: map[string]struct{}{"user_service.proto": {}},
	}
}

func namesOf(found []check.MachineryClaim) []string {
	out := make([]string, 0, len(found))
	for _, c := range found {
		out = append(out, string(c.Kind)+":"+c.Name)
	}
	return out
}

// ─────────────────────────────────────── ось ТАБЛИЦА

func TestMachineryInjection_RetiredOutboxIsSeen(t *testing.T) {
	t.Parallel()
	found, census := check.AuditMachineryClaims(liveWorld(map[string]string{
		"a.proto": "// writes a `caep_outbox` row so downstream RPs get notified\nservice S {}\n",
	}))
	require.Equal(t, 1, census.ByKind[check.MachineryTable], "заявление обязано быть распознано")
	require.Equal(t, []string{"таблица:caep_outbox"}, namesOf(found),
		"снятая очередь обязана быть НАЗВАНА: интегратор читает это как действующий механизм")
	require.Zero(t, census.Resolved, "резолвиться здесь нечему")
}

// TestMachineryInjection_LiveOutboxIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ предыдущего:
// дельта миров ОДИН факт — имя очереди, и оно живое.
func TestMachineryInjection_LiveOutboxIsSilent(t *testing.T) {
	t.Parallel()
	found, census := check.AuditMachineryClaims(liveWorld(map[string]string{
		"a.proto": "// writes a `audit_outbox` row so downstream RPs get notified\nservice S {}\n",
	}))
	require.Equal(t, 1, census.ByKind[check.MachineryTable])
	require.Emptyf(t, found, "живая очередь находкой не является — иначе гейт краснел бы "+
		"на исправном дереве и его выключили бы первым")
	require.Equal(t, 1, census.Resolved)
}

func TestMachineryInjection_TableWordMarksAClaim(t *testing.T) {
	t.Parallel()
	found, _ := check.AuditMachineryClaims(liveWorld(map[string]string{
		"a.proto": "// All revocations write to the same `caep_events` table (PK = jti).\nservice S {}\n",
	}))
	require.Equal(t, []string{"таблица:caep_events"}, namesOf(found),
		"слово `table` сразу за именем — маркер: комментарий сам назвал имя таблицей")
}

// ─────────────────────────────────────── ось КАНАЛ

func TestMachineryInjection_RetiredChannelIsSeen(t *testing.T) {
	t.Parallel()
	found, census := check.AuditMachineryClaims(liveWorld(map[string]string{
		"a.proto": "// worker NOTIFY-es `session_revoked` channel.\nservice S {}\n",
	}))
	require.Equal(t, 1, census.ByKind[check.MachineryChannel])
	require.Equal(t, []string{"канал:session_revoked"}, namesOf(found))
}

// TestMachineryInjection_LiveChannelIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ: та же фраза,
// живое имя.
func TestMachineryInjection_LiveChannelIsSilent(t *testing.T) {
	t.Parallel()
	found, census := check.AuditMachineryClaims(liveWorld(map[string]string{
		"a.proto": "// worker NOTIFY-es `kaname_invite_mail_outbox` channel.\nservice S {}\n",
	}))
	require.Equal(t, 1, census.ByKind[check.MachineryChannel])
	require.Empty(t, found)
}

// TestMachineryInjection_ChannelNameWrappedToTheNextLineIsSeen — перенос строки
// не прячет заявление.
//
// Ось заведена не умозрительно: именно в такой обёртке стояло одно из двух
// заявлений о снятом канале, и построчный разбор его терял.
func TestMachineryInjection_ChannelNameWrappedToTheNextLineIsSeen(t *testing.T) {
	t.Parallel()
	found, _ := check.AuditMachineryClaims(liveWorld(map[string]string{
		"a.proto": "// pre-loaded via ListByUser + a LISTEN/NOTIFY subscription on\n" +
			"// `session_revoked`. IsRevoked is the slow-path fallback\nservice S {}\n",
	}))
	require.Equal(t, []string{"канал:session_revoked"}, namesOf(found),
		"имя перенесено на следующую строку комментария — блок сводится в один текст "+
			"именно затем, чтобы обёртка не выводила заявление из-под наблюдения")
}

// ─────────────────────────────────────── ось СОСЕДНИЙ КОНТРАКТ

func TestMachineryInjection_DanglingContractReferenceIsSeen(t *testing.T) {
	t.Parallel()
	found, census := check.AuditMachineryClaims(liveWorld(map[string]string{
		"a.proto": "//   - Back-channel logout (see back_channel_logout_service.proto).\nservice S {}\n",
	}))
	require.Equal(t, 1, census.ByKind[check.MachineryContract])
	require.Equal(t, []string{"контракт:back_channel_logout_service.proto"}, namesOf(found))
}

// TestMachineryInjection_ExistingContractReferenceIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ.
func TestMachineryInjection_ExistingContractReferenceIsSilent(t *testing.T) {
	t.Parallel()
	found, census := check.AuditMachineryClaims(liveWorld(map[string]string{
		"a.proto": "//   - User logout (see user_service.proto).\nservice S {}\n",
	}))
	require.Equal(t, 1, census.ByKind[check.MachineryContract])
	require.Empty(t, found)
}

// TestMachineryInjection_ForeignRepoPathIsNotJudged — ссылка С КАТАЛОГОМ под ось
// не подпадает.
//
// Это решение, а не пропуск (шапка предиката): файл платформы в этом модуле
// отсутствует by construction, и предикат ЭТОГО дерева о чужом не высказывается.
func TestMachineryInjection_ForeignRepoPathIsNotJudged(t *testing.T) {
	t.Parallel()
	found, census := check.AuditMachineryClaims(liveWorld(map[string]string{
		"a.proto": "// ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ, А НЕ ПРАВКА kacho/cloud/validation.proto\nservice S {}\n",
	}))
	require.Zerof(t, census.ByKind[check.MachineryContract],
		"ссылка с каталогом адресует чужой репозиторий: судя её, гейт начал бы с ложных "+
			"находок и потребовал бы ведомости прощений — исключения, выданного вперёд")
	require.Empty(t, found)
}

// ─────────────────────────────────────── ось МАРКЕР и ИСПОЛНЯЕМАЯ ЧАСТЬ

// TestMachineryInjection_NameWithoutAMarkerIsNotAClaim — имя без маркера
// заявлением не является.
//
// Без этой оси предикат вернулся бы к голому «слово в обратных кавычках», у
// которого на дереве службы 66 % ложных находок.
func TestMachineryInjection_NameWithoutAMarkerIsNotAClaim(t *testing.T) {
	t.Parallel()
	found, census := check.AuditMachineryClaims(liveWorld(map[string]string{
		"a.proto": "// Idempotent on `token_jti`, and `page_size` is capped at 1000.\nservice S {}\n",
	}))
	require.Zero(t, census.Claims, "ни `token_jti`, ни `page_size` комментарий "+
		"таблицей или каналом не называл")
	require.Empty(t, found)
}

// TestMachineryInjection_NameInTheContractBodyIsNotAComment — гейт читает
// комментарий, а не текст файла.
func TestMachineryInjection_NameInTheContractBodyIsNotAComment(t *testing.T) {
	t.Parallel()
	found, census := check.AuditMachineryClaims(liveWorld(map[string]string{
		"a.proto": "service S {\n  option (x) = \"`caep_outbox` table\";\n}\n",
	}))
	require.Zerof(t, census.Claims, "строка контракта комментарием не является: гейт, "+
		"читающий сырой текст, судил бы значения опций наравне с прозой")
	require.Empty(t, found)
}

// ─────────────────────────────────────── ось ПУСТОЙ ОБХОД

// TestMachineryInjection_EmptyCorpusIsNamedByTheCensus — «ноль находок» обязано
// быть отличимо от «ноль прочитанного».
func TestMachineryInjection_EmptyCorpusIsNamedByTheCensus(t *testing.T) {
	t.Parallel()
	found, census := check.AuditMachineryClaims(liveWorld(map[string]string{}))
	require.Empty(t, found)
	require.Zerof(t, census.Files, "перепись обязана назвать пустой обход: гейты выше "+
		"роняют прогон именно по ней, а не по отсутствию находок")
	require.Zero(t, census.CommentBlocks)
	require.Zero(t, census.Claims)
}

// TestMachineryInjection_CensusCountsWhatItRead — перепись считает осмотренное, а
// не найденное.
func TestMachineryInjection_CensusCountsWhatItRead(t *testing.T) {
	t.Parallel()
	_, census := check.AuditMachineryClaims(liveWorld(map[string]string{
		"a.proto": "// one `audit_outbox` row\nservice A {}\n// and a `caep_outbox` row\nservice B {}\n",
		"b.proto": "// see user_service.proto\nservice C {}\n",
	}))
	require.Equal(t, 2, census.Files)
	require.Equal(t, 3, census.CommentBlocks)
	require.Equal(t, 3, census.Claims)
	require.Equal(t, 2, census.Resolved, "резолвятся живая очередь и существующий контракт")
}
