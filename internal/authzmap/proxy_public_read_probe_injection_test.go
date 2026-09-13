// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// proxy_public_read_probe_injection_test.go — ЗОНД ПУБЛИКУЕМОСТИ РАЗЛИЧАЕТ, А НЕ
// СОГЛАШАЕТСЯ (kacho#1830).
//
// Соседний гейт (`TestPublicReadObjectTypesAreInTheCatalog`) сверяет ОБЪЯВЛЕННЫЙ
// перечень публикуемых типов с тем, что путь записи разрешает НА САМОМ ДЕЛЕ.
// Такое утверждение стоит ровно столько, сколько стоит зонд: зонд, который
// разрешает всё, дал бы 32 типа против одного и покраснел бы — а вот зонд,
// который отвергает всё ПО ПОСТОРОННЕЙ ПРИЧИНЕ, дал бы пустое множество и тоже
// покраснел. Ни то, ни другое не доказывает, что зонд различает ИМЕННО
// публикуемость.
//
// Поэтому здесь обе стороны на одной оси, и дельта между ними — РОВНО ОДИН
// факт:
//
//	тип из перечня, публичный субъект   → допущено
//	тип ВНЕ перечня, тот же субъект     → отказ (различает ТИП)
//	тип из перечня, ИМЕНОВАННЫЙ субъект → отказ (различает СУБЪЕКТА)
//
// Третья строка отделяет «этот ресурс бывает публичным» от «этому получателю
// можно» — то самое различение, ради которого перечень и закрыт: без него
// публикация выродилась бы в выдачу чтения названному получателю.
package authzmap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/authz/proxytuple"
)

func TestPublicReadProbe_DiscriminatesTypeAndSubject(t *testing.T) {
	declared := proxytuple.PublicReadObjectTypes()
	require.NotEmptyf(t, declared, "перечень пуст — контролям не на чем стоять")
	publishable := declared[0]

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: без него отрицания ниже зеленели бы на зонде,
	// который отвергает вообще всё.
	require.NoErrorf(t,
		proxytuple.ValidateTuple(callerDomainOf(publishable), proxytuple.PublicReadSubject,
			string(proxytuple.PublicReadRelation), publishable+":x"),
		"тип %q объявлен публикуемым — зонд обязан его ДОПУСТИТЬ, иначе он меряет "+
			"не публикуемость, а какую-то соседнюю оговорку", publishable)

	// ОТРИЦАНИЕ ПО ТИПУ: тот же субъект, то же отношение, ДРУГОЙ тип.
	const notPublishable = "vpc_network"
	require.NotContainsf(t, declared, notPublishable,
		"близнец обязан быть ВНЕ перечня, иначе он не близнец")
	require.Errorf(t,
		proxytuple.ValidateTuple(callerDomainOf(notPublishable), proxytuple.PublicReadSubject,
			string(proxytuple.PublicReadRelation), notPublishable+":x"),
		"«любой читает мою сеть» возможностью продукта не является: приняв это, зонд "+
			"согласился бы с любым перечнем и сверка стала бы тождеством")

	// ОТРИЦАНИЕ ПО СУБЪЕКТУ: тот же публикуемый тип, ИМЕНОВАННЫЙ получатель.
	require.Errorf(t,
		proxytuple.ValidateTuple(callerDomainOf(publishable), "user:usr1",
			string(proxytuple.PublicReadRelation), publishable+":x"),
		"публикация и выдача чтения названному получателю — разные вещи; зонд, их не "+
			"различающий, называл бы публикуемым всякий тип, у которого есть чтение")
}
