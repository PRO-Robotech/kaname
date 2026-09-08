// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// notify_channel_consumer_injection_test.go — доказательство, что гейт
// потребителя СПОСОБЕН упасть, и падает на предмете, а не на его виде.
//
// Инъекция гоняет ТЕ ЖЕ функции, что и гейт (`channelNamesBoundIn`,
// `notifyChannelsProducedBy`), а не их пересказ: копия разбора разошлась бы с
// оригиналом молча — и разошлась бы именно там, где расхождение не видно, потому
// что на законном входе обе отвечают одинаково.
//
// Оси инъекции названы поимённо, потому что распознаватель обязан знать ВСЕ
// законные формы записи предмета, а форма, о которой он не знает, не даёт ни
// красного, ни зелёного — она молчит:
//
//	(1) объявление, чьё имя оканчивается на Channel  — каноничная форма дерева;
//	(2) поле `Channel` составного литерала           — форма, которой пользуется дренаж;
//	(3) то же имя ТОЛЬКО в комментарии               — законный близнец, обязан молчать;
//	(4) литерал, не связанный как имя канала         — законный близнец, обязан молчать;
//	(5) живой триггер на канал, которого никто не называет — красное на схеме.
package migrations_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChannelNamesBoundIn_FindsEveryLegitimateForm — ось (1) и (2): формы, в
// которых это дерево связывает имя канала, обязаны находиться ОБЕ.
//
// Без этой пары гейт объявил бы беспотребительским канал с живым потребителем —
// то есть краснел бы на исправном, а гейт, краснеющий на исправном, отключают
// первым.
func TestChannelNamesBoundIn_FindsEveryLegitimateForm(t *testing.T) {
	const src = `package x

const reconcileOutboxChannel = "kaname_resource_reconcile_outbox"

var ProviderCompensationChannel = "kaname_provider_compensation_outbox"

func wire() any {
	return drainer.Config{
		Table:   "kaname.provider_compensation_outbox",
		Channel: "kacho_iam_inline_named_channel",
	}
}
`
	names, literals, err := channelNamesBoundIn("synthetic.go", []byte(src))
	require.NoError(t, err)
	require.NotZero(t, literals, "литералов осмотрено ноль — разбор не увидел предмет вовсе")

	for _, want := range []string{
		"kaname_resource_reconcile_outbox",    // (1) const
		"kaname_provider_compensation_outbox", // (1) var
		"kacho_iam_inline_named_channel",      // (2) поле Channel
	} {
		assert.Contains(t, names, want,
			"форма связывания имени канала не распознана — всё, записанное в ней, "+
				"осталось бы вне наблюдения гейта")
	}
}

// TestChannelNamesBoundIn_IsSilentOnLegitimateTwins — оси (3) и (4): гейт молчит
// там, где предмета нет.
//
// Ось (3) несущая, и она не умозрительная: у соседнего канала
// (`kaname_fga_outbox`) ОБА вхождения имени в не-тестовых файлах Go — именно
// комментарии. Предикат по подстроке объявил бы у него потребителя, которого нет,
// то есть промолчал бы ровно на предмете гейта.
func TestChannelNamesBoundIn_IsSilentOnLegitimateTwins(t *testing.T) {
	const src = `package x

// Пример объявления в шапке — имя канала стоит здесь ПРОЗОЙ:
//
//	drainer.Config{
//	    Channel: "kaname_fga_outbox",
//	}
type Config struct {
	// Channel — имя LISTEN-канала, e.g. "kaname_fga_outbox".
	Channel string
}

const outboxTable = "kaname.fga_outbox"

func label() string { return "kaname_fga_outbox_pending" }
`
	names, literals, err := channelNamesBoundIn("synthetic.go", []byte(src))
	require.NoError(t, err)
	require.NotZero(t, literals,
		"литералов осмотрено ноль — тогда молчание сказано ни о чём, а не о предмете")

	assert.NotContains(t, names, "kaname_fga_outbox",
		"имя канала связано из КОММЕНТАРИЯ — разбор судит текст, а не узел, и объявит "+
			"потребителя там, где его нет")
	assert.NotContains(t, names, "kaname.fga_outbox",
		"имя ТАБЛИЦЫ принято за имя канала: объявление названо не на Channel")
	assert.NotContains(t, names, "kaname_fga_outbox_pending",
		"посторонний литерал принят за имя канала — он ничем не связан как имя канала")
}

// TestChannelNamesBoundIn_RefusesUnparsableInput — файл, который не разбирается,
// не считается прочитанным.
//
// Иначе объём осмотренного завысился бы, и «ноль имён на 1806 файлах» означало бы
// «ноль имён на 1806 файлах, из которых половина не разобралась».
func TestChannelNamesBoundIn_RefusesUnparsableInput(t *testing.T) {
	names, literals, err := channelNamesBoundIn("broken.go", []byte("package x\nfunc ("))

	require.Error(t, err, "негодный файл обязан быть отказом, а не пустым успехом")
	assert.Empty(t, names)
	assert.Zero(t, literals)
}

// TestIntegration_ProducedChannelWithoutAConsumerIsFound — ось (5): та же пара
// функций, что и у гейта, на ЖИВОЙ схеме.
//
// Инъекция снимает ТОЛЬКО проверяемое свойство: заводится один триггер на канал,
// которого прод-код не называет. Рядом — законный близнец: второй триггер на
// канал, у которого потребитель ЕСТЬ. Без близнеца «нашёл» было бы неотличимо от
// «находит всякий добавленный триггер».
func TestIntegration_ProducedChannelWithoutAConsumerIsFound(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	named, files, _ := notifyChannelNamesInProdGo(t)
	require.NotZero(t, files, "дерево не прочитано — вердикт был бы сказан ни о чём")

	// Контроль ДО инъекции: на нетронутой схеме беспотребительских каналов вне
	// ведомости нет. Без него красное ниже могло бы прийти от чужого предмета.
	require.Empty(t, unpairedChannels(uniqueSorted(notifyChannelsProducedBy(t, db)), named),
		"на нетронутой схеме уже есть беспотребительский канал — инъекция ниже "+
			"доказывала бы не себя")

	const injected = "kaname_channel_nobody_names"
	for _, stmt := range []string{
		`CREATE FUNCTION kaname.injected_notify() RETURNS trigger LANGUAGE plpgsql AS $$
		 BEGIN PERFORM pg_notify('` + injected + `', ''); RETURN NEW; END; $$`,
		// Законный близнец: тот же вид триггера, но канал с потребителем.
		`CREATE FUNCTION kaname.injected_twin_notify() RETURNS trigger LANGUAGE plpgsql AS $$
		 BEGIN PERFORM pg_notify('` + notifyChannelWithAProvenConsumer + `', ''); RETURN NEW; END; $$`,
		`CREATE TRIGGER injected_notify_trg AFTER INSERT ON kaname.subject_change_outbox
		   FOR EACH ROW EXECUTE FUNCTION kaname.injected_notify()`,
		`CREATE TRIGGER injected_twin_notify_trg AFTER INSERT ON kaname.subject_change_outbox
		   FOR EACH ROW EXECUTE FUNCTION kaname.injected_twin_notify()`,
	} {
		_, err := db.Exec(stmt)
		require.NoError(t, err, "инъекция не встала: %s", stmt)
	}

	unpaired := unpairedChannels(uniqueSorted(notifyChannelsProducedBy(t, db)), named)

	assert.Equal(t, []string{injected}, unpaired,
		"гейт обязан назвать ровно внесённый беспотребительский канал: близнец с "+
			"потребителем в находку не попадает, иначе проверка ловит форму, а не предмет")
	assert.NotContains(t, strings.Join(unpaired, " "), notifyChannelWithAProvenConsumer,
		"законный близнец объявлен находкой — гейт краснеет на исправном")
}

// unpairedChannels — производимые каналы без потребителя, за вычетом прощённых.
//
// Вынесена сюда, а не повторена в инъекции, потому что инъекция обязана гонять ТУ
// ЖЕ логику отбора, что и гейт: своя копия отвечала бы одинаково на законном входе
// и разошлась бы ровно на спорном.
func unpairedChannels(produced []string, named map[string]bool) []string {
	var out []string
	for _, ch := range produced {
		if _, forgiven := notifyChannelConsumerExemptions[ch]; forgiven {
			continue
		}
		if !named[ch] {
			out = append(out, ch)
		}
	}
	return out
}
