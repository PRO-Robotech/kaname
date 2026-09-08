// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// object_type_form_agrees_with_domain_test.go — ФОРМА имени типа объекта:
// ограничение базы и объявление Go обязаны быть ОДНИМ образцом (задача #2015).
//
// # Почему это стало предметом только сейчас
//
// Пока таблица типов была ЗАКРЫТА, форму имени никто не судил в Go: загрузчик
// манифеста спрашивал ЧЛЕНСТВО, а всякий член порождённой сборкой таблицы годен
// по форме by construction, и разойтись двум местам было не на чем. Таблица
// разомкнута — оператор чужого облака объявляет свой ресурс доставкой, — и
// форма стала ЕДИНСТВЕННЫМ, что стоит между его файлом и колонкой каталога.
//
// # Цена расхождения — отказ ЧУЖОЙ полосой
//
// Будь образец Go шире ограничения базы, манифест приняли бы, а строку отвергла
// бы вставка: автор искал бы дефект в базе, читая фразу Postgres про имя
// ограничения, а не в своём файле. Будь он уже — оператор получал бы отказ на
// имени, которое платформа на самом деле принимает, и починить это он не мог бы
// ничем.
//
// # Почему сверяется ТЕКСТ ограничения, а не поведение
//
// Поведение потребовало бы живой базы, то есть эта проба стала бы
// интеграционной и не исполнялась бы в коротком прогоне — там, где правку
// образца и делают. Текст же читается из ТОГО ЖЕ каталога миграций, который
// применяется в бою, и другого источника у ограничения нет.

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// reObjectTypeFormCheck — объявление ограничения формы имени типа в миграции.
//
// Образец берётся из ОДИНАРНЫХ кавычек SQL целиком, без разбора: сверять надо
// побайтово, а всякая нормализация здесь была бы вторым правилом о том, что
// считать «тем же образцом».
var reObjectTypeFormCheck = regexp.MustCompile(
	`CONSTRAINT\s+catalog_resource_object_type_form\s+CHECK\s*\(\s*\(?\s*object_type\s*~\s*'([^']*)'`)

// TestObjectTypeFormOfTheCatalogColumnEqualsTheDomainGrammar — ограничение базы
// и объявление домена суть один образец.
func TestObjectTypeFormOfTheCatalogColumnEqualsTheDomainGrammar(t *testing.T) {
	bodies, read := iamMigrationCorpus(t)

	found := map[string]string{}
	for name, body := range bodies {
		for _, m := range reObjectTypeFormCheck.FindAllStringSubmatch(body, -1) {
			found[name] = m[1]
		}
	}
	require.NotEmptyf(t, found, "ограничение формы имени типа не найдено ни в одной из %d "+
		"прочитанных миграций — «ноль находок» здесь означало бы «ноль прочитанного», "+
		"а сверять образец было бы не с чем", read)

	want := domain.ObjectTypeNameGrammar()
	for name, got := range found {
		require.Equalf(t, want, got,
			"%s: ограничение базы держит образец %q, домен объявляет %q — манифест, "+
				"принятый одним, отверг бы другой, и отказ пришёл бы ЧУЖОЙ полосой",
			name, got, want)
	}
	t.Logf("перепись: миграций прочитано %d, объявлений ограничения найдено %d, "+
		"образец %q — сошлось", read, len(found), want)

	// Контроль в обратную сторону: распознаватель обязан УМЕТЬ увидеть другой
	// образец. Без него равенство выше зеленело бы и на пустом разборе — то есть
	// на регулярном выражении, которое перестало совпадать вовсе.
	const injected = `    CONSTRAINT catalog_resource_object_type_form CHECK ((object_type ~ '^[A-Z]+$'::text)),`
	m := reObjectTypeFormCheck.FindStringSubmatch(injected)
	require.Lenf(t, m, 2, "распознаватель не видит объявления с ДРУГИМ образцом — "+
		"он совпадал бы только с сегодняшним текстом и молчал бы на его правке")
	require.NotEqual(t, want, m[1])

	// И вторая сторона того же контроля: законный близнец — то же объявление с
	// сегодняшним образцом — распознаётся и равен домену.
	legit := strings.Replace(injected, `^[A-Z]+$`, want, 1)
	lm := reObjectTypeFormCheck.FindStringSubmatch(legit)
	require.Len(t, lm, 2)
	require.Equal(t, want, lm[1])
}
