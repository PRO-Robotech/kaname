// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clients_test

// invite_mail_lane_test.go — свойства ПОЛОСЫ до почтового узла, которые обязаны
// держаться построением, а не соглашением.
//
// Каждая проба здесь названа в комментарии того кода, который она держит: имя
// пробы в комментарии, за которым пробы нет, — то самое «обещание проверки»,
// которое корпус ловит в чужом коде.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/invite_mail_outbox"
)

// Test_ParseMailTLSMode_NeverYieldsThePlaintextMode — ban #16 построением, а не
// обещанием.
//
// Незащищённая полоса существует как значение Go ради in-process фикстур, но
// РАЗБОР ОБЪЯВЛЕНИЯ её не производит НИ ПРИ КАКОМ входе: значит оператор не
// может выбрать её, как бы он ни написал настройку. Отрицание идёт в паре с
// положительным контролем — иначе оно зеленело бы на разборе, отвергающем всё.
func Test_ParseMailTLSMode_NeverYieldsThePlaintextMode(t *testing.T) {
	t.Parallel()

	// Вход подобран так, чтобы включить каждую форму, которой оператор мог бы
	// попытаться выключить шифрование, — включая имена самого значения Go.
	for _, attempt := range []string{
		"none", "plaintext", "disabled", "off", "insecure", "no", "false", "0",
		"disabledfortest", "MailTLSDisabledForTest", "cleartext", "plain",
		" none ", "NONE", "starttls-optional", "opportunistic",
	} {
		mode, err := clients.ParseMailTLSMode(attempt)
		require.Error(t, err,
			"разбор обязан ОТВЕРГНУТЬ %q: полоса до почтового узла шифрована на всяком стенде", attempt)
		assert.NotEqual(t, clients.MailTLSDisabledForTest, mode,
			"отвергнутый вход не вправе дать незащищённую полосу даже возвращаемым значением")
	}

	// Положительный контроль: два законных имени принимаются и дают РАЗНЫЕ
	// посадки. Без него проба зеленела бы на разборе, который отвергает всё.
	for name, want := range map[string]clients.MailTLSMode{
		"":          clients.MailTLSStartTLS,
		"starttls":  clients.MailTLSStartTLS,
		"STARTTLS":  clients.MailTLSStartTLS,
		" implicit": clients.MailTLSImplicit,
		"tls":       clients.MailTLSImplicit,
	} {
		mode, err := clients.ParseMailTLSMode(name)
		require.NoError(t, err, "законное имя %q обязано приниматься", name)
		assert.Equal(t, want, mode, "имя %q обязано давать объявленную посадку", name)
	}
}

// Test_InviteMailTableIsNamedOnce — координата очереди объявлена в ДВУХ пакетах
// (writer в слое хранилища и применитель в слое клиентов), потому что слои не
// вправе импортировать друг друга. Значит она обязана СОВПАДАТЬ, и совпадение
// держит эта проба, а не внимание: разойдясь, две половины стали бы писать в
// одну таблицу, а читать из другой — и молчали бы обе.
func Test_InviteMailTableIsNamedOnce(t *testing.T) {
	t.Parallel()

	assert.Equal(t, clients.InviteMailTable, invite_mail_outbox.Table,
		"writer и применитель обязаны называть ОДНУ таблицу")
	assert.Equal(t, clients.EventInviteMailSend, invite_mail_outbox.EventSend,
		"writer и применитель обязаны называть ОДИН вид события")

	// Канал выводится из имени таблицы по форме дерева (`схема.таблица` →
	// `схема_таблица`): триггер миграции шлёт именно туда, и разойдись имя —
	// дренаж спал бы до опроса, а не просыпался по событию.
	assert.Equal(t, strings.ReplaceAll(clients.InviteMailTable, ".", "_"), clients.InviteMailChannel,
		"канал обязан выводиться из имени таблицы — так его шлёт триггер миграции")
}
