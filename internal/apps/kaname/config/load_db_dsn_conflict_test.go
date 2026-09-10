// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// СТРОКА ПОДКЛЮЧЕНИЯ ВЫРАЗИМА РОВНО ОДНИМ СПОСОБОМ (задача #2475).
//
// У адреса базы два документированных входа: полный DSN одной строкой
// (`KANAME_REPOSITORY__POSTGRES__URL`) и расщеплённые ручки по полям
// (`KANAME_DB_HOST/PORT/USER/NAME`). Оба объявляет клиентская страница
// настройки, и главного из них не называла ни она, ни установка.
//
// Класс — «значение выразимо ровно одним способом» (`code-authoring`): два
// пути к одной величине, приоритет нигде не решён. Разрешать его молчаливым
// старшинством нельзя ни в одну сторону, и это не вкус:
//
//   - расщеплённые перебивают DSN — оператор теряет из объявленной строки
//     всё, кроме четырёх полей, включая параметры запроса. Отказ посадки
//     потом называет ровно ту величину, которую оператор как раз задал;
//   - DSN перебивает расщеплённые — те приняты и выброшены, а это отдельно
//     запрещённый класс «принято-и-проигнорировано»: возможность объявлена,
//     параметр не применён, вызывающий об этом не узнаёт.
//
// Поэтому исход — ЯВНЫЙ ОТКАЗ с именами ОБЕИХ ручек: он не выбирает за
// оператора и восстанавливает следующий шаг («уберите одну из двух»).
//
// Отрицание идёт В ПАРЕ с двумя положительными контролями ниже: без них
// проба зеленела бы на загрузке, отказывающей вообще всему.
func TestPostgresDSN_DeclaringBothFormsIsRefused(t *testing.T) {
	const dsn = "postgres://u:p@pg.example:5432/kaname?sslmode=require&application_name=kaname"

	t.Setenv("KANAME_REPOSITORY__POSTGRES__URL", dsn)
	t.Setenv("KANAME_DB_HOST", "pg.example")

	_, err := config.Load("")
	require.Error(t, err,
		"объявлены обе формы адреса базы — загрузка обязана отказать, "+
			"а не выбирать старшинство молча")

	msg := err.Error()
	require.Contains(t, msg, "KANAME_REPOSITORY__POSTGRES__URL",
		"отказ обязан назвать ручку полного DSN — иначе оператор не знает, "+
			"какие две настройки спорят: %q", msg)
	require.Contains(t, msg, "KANAME_DB_HOST",
		"отказ обязан назвать заданную расщеплённую ручку поимённо: %q", msg)
}

// Отказ называет ВСЕ заданные расщеплённые ручки, а не первую попавшуюся:
// оператор, убравший названную, не должен получать тот же отказ второй раз.
func TestPostgresDSN_RefusalNamesEverySplitKnobThatIsSet(t *testing.T) {
	t.Setenv("KANAME_REPOSITORY__POSTGRES__URL", "postgres://u@pg:5432/kaname")
	t.Setenv("KANAME_DB_HOST", "pg.example")
	t.Setenv("KANAME_DB_PORT", "5433")
	t.Setenv("KANAME_DB_NAME", "other")

	_, err := config.Load("")
	require.Error(t, err)

	msg := err.Error()
	for _, name := range []string{"KANAME_DB_HOST", "KANAME_DB_PORT", "KANAME_DB_NAME"} {
		require.Contains(t, msg, name,
			"отказ обязан перечислить все заданные расщеплённые ручки, "+
				"не найдена %s: %q", name, msg)
	}
	require.NotContains(t, msg, "KANAME_DB_USER",
		"незаданная ручка в отказе не называется — иначе оператор ищет то, "+
			"чего не задавал: %q", msg)
}

// Все четыре заданные — все четыре названы. Случай отдельный от соседнего:
// он ловит ручку, которую сборка читает, а перечень отказа не называет, —
// расхождение, невидимое, пока хоть одна ручка оставлена незаданной.
func TestPostgresDSN_RefusalNamesAllFourWhenAllFourAreSet(t *testing.T) {
	t.Setenv("KANAME_REPOSITORY__POSTGRES__URL", "postgres://u@pg:5432/kaname")
	t.Setenv("KANAME_DB_HOST", "pg.example")
	t.Setenv("KANAME_DB_PORT", "5433")
	t.Setenv("KANAME_DB_USER", "kaname")
	t.Setenv("KANAME_DB_NAME", "kanamedb")

	_, err := config.Load("")
	require.Error(t, err)

	msg := err.Error()
	for _, name := range []string{
		"KANAME_DB_HOST", "KANAME_DB_PORT", "KANAME_DB_USER", "KANAME_DB_NAME",
	} {
		require.Contains(t, msg, name,
			"отказ обязан назвать каждую ручку, которую читает сборка; "+
				"не найдена %s: %q", name, msg)
	}
}

// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 1: одна только объявленная строка проходит и
// доезжает до поля ДОСЛОВНО — вместе с параметрами запроса, которые
// расщеплённая сборка выразить не умеет вовсе.
func TestPostgresDSN_DeclaredURLAloneSurvivesVerbatim(t *testing.T) {
	const dsn = "postgres://u:p@pg.example:5432/kaname?sslmode=require&application_name=kaname"

	t.Setenv("KANAME_REPOSITORY__POSTGRES__URL", dsn)

	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, dsn, cfg.Repository.Postgres.URL,
		"объявленная строка — единственный источник адреса, и она обязана "+
			"дойти до поля без потерь")
}

// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 2: расщеплённые ручки БЕЗ объявленной строки
// по-прежнему собирают DSN. Их читатель не снимается — снимается только
// молчаливое старшинство, поэтому документированная форма остаётся рабочей.
func TestPostgresDSN_SplitKnobsAloneStillCompose(t *testing.T) {
	t.Setenv("KANAME_DB_HOST", "pg.example")
	t.Setenv("KANAME_DB_PORT", "5433")
	t.Setenv("KANAME_DB_USER", "kaname")
	t.Setenv("KANAME_DB_NAME", "kanamedb")

	cfg, err := config.Load("")
	require.NoError(t, err)
	require.Equal(t, "postgres://kaname@pg.example:5433/kanamedb", cfg.Repository.Postgres.URL,
		"расщеплённая форма без объявленной строки собирает адрес, как и прежде")
}

// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 3: спорят ДВЕ ПЕРЕМЕННЫЕ, а не переменная с файлом.
// Файл — уровень ниже окружения по объявленному порядку загрузки, и
// перекрытие файла переменной documented-поведение, а не спор.
func TestPostgresDSN_FileValueIsNotAConflict(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.yaml"
	require.NoError(t, writeFile(path, strings.Join([]string{
		"repository:",
		"  postgres:",
		"    url: postgres://from-file@pg:5432/kaname",
		"",
	}, "\n")))

	t.Setenv("KANAME_DB_HOST", "pg.example")

	cfg, err := config.Load(path)
	require.NoError(t, err,
		"переменная поверх файла — объявленный порядок загрузки, а не спор двух ручек")
	require.Equal(t, "postgres://iam@pg.example:5432/kaname", cfg.Repository.Postgres.URL)
}
