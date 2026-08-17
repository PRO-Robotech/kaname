// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// Носитель «личность» назван ОДИНАКОВО в трёх местах, и это проверено, а не
// подразумевается.
//
// Три места: каталог видов (доменная константа), адаптер (литерал, которым он
// адресует строки) и схема (предикат триггера и ограничение столбца). Значение
// принадлежит СХЕМЕ — оно стоит в `carrier_type`, — поэтому у адаптера свой
// литерал, а не ссылка на доменную константу: адаптер обязан называть то, что
// лежит в базе, даже если домен однажды назовёт это иначе.
//
// Цена расхождения асимметрична и потому неочевидна. Разойдись они — списание
// писало бы строки под одним носителем, а чтение спрашивало под другим:
// потребление арендатору показывалось бы нулевым при полном потолке, а отказ
// приходил бы «на пустом месте». Ни сборка, ни одна из сторон по отдельности
// этого не заметят.
func TestIdentityCarrierIsNamedTheSameEverywhere(t *testing.T) {
	t.Parallel()

	require.Equal(t, string(domain.CarrierIdentity), kachopg.CarrierIdentity,
		"каталог видов и адаптер называют носителя по-разному: списание и чтение "+
			"разойдутся по строкам, и ни одна сторона этого не увидит")

	// Схема — третье место, и оно решающее: именно её значение оказывается в
	// столбце. Читается ФАЙЛ миграции, а не память об оном.
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	require.NoError(t, err)
	path := filepath.Join(root, "internal", "migrations",
		"484002_account_quota_identity_carrier.sql")
	raw, err := os.ReadFile(path) // #nosec G304 -- путь собран из констант этого файла
	require.NoErrorf(t, err, "миграция носителя не прочитана: без неё проба ничего не утверждает")

	body := string(raw)
	require.Containsf(t, body, "'"+kachopg.CarrierIdentity+"'",
		"схема не называет носителя %q ни разу — адаптер адресует строки значением, "+
			"которого в базе нет", kachopg.CarrierIdentity)
	require.Truef(t,
		strings.Contains(body, "carrier_type IN ('project', 'account', '"+kachopg.CarrierIdentity+"')"),
		"ограничение столбца не перечисляет носителя %q: строка учёта личности "+
			"не вставится вовсе, и потолок молча перестанет действовать", kachopg.CarrierIdentity)
}

// Вид `iam.account` объявлен с носителем «личность» — и это утверждение о
// КАТАЛОГЕ, а не о константе.
//
// Отрицание рядом с положительным: у соседнего вида того же домена носитель
// ДРУГОЙ. Без него проба зеленела бы и на каталоге, где носитель у всех один.
func TestAccountKindIsCarriedByTheIdentity(t *testing.T) {
	t.Parallel()

	carrier, ok := domain.CarrierOfKind("iam.account")
	require.True(t, ok, "вида `iam.account` в каталоге нет: потолка над аккаунтом не существует")
	require.Equal(t, domain.CarrierIdentity, carrier,
		"аккаунт считается не в личности: носитель обязан быть ВНЕШНИМ по отношению "+
			"к предмету счёта, а проект и аккаунт этому не удовлетворяют by construction")

	neighbour, ok := domain.CarrierOfKind("iam.project")
	require.True(t, ok)
	require.Equal(t, domain.CarrierAccount, neighbour,
		"положительный контроль: у соседнего вида того же домена носитель другой, "+
			"поэтому совпадение выше — свойство записи, а не одинаковость каталога")
}
