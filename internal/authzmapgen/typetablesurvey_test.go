// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzmapgen_test

// typetablesurvey_test.go — СКОЛЬКО ТАБЛИЦ ТИПОВ ПОРОЖДАЕТСЯ, И ЭТО ЧИСЛО
// ПЕЧАТАЕТСЯ, А НЕ ОБЪЯВЛЯЕТСЯ ПРОЗОЙ (задача #1092).
//
// # Зачем гейт на число, которое и так написано в шапке
//
// Шапка `tables_gen.go` говорит «вторая таблица здесь НЕ порождается». Это
// утверждение о ДЕРЕВЕ в настоящем времени, и у него нет предиката рядом —
// то есть ровно тот класс, который корпус ловит перепиской: оно переживёт свой
// предмет молча, как только вторая таблица будет выведена (#1930), и следующий
// читатель узнает из шапки неправду.
//
// Здесь число ИЗМЕРЯЕТСЯ обходом пакета и сверяется с объявленным остатком.
// Когда остаток станет нулём, гейт покраснеет — и правка шапки перестанет
// зависеть от чьей-то памяти.
//
// # Почему разбор, а не поиск по имени
//
// Имя `objectTypes` стоит и в комментариях, объясняющих сам остаток. Гейт,
// судящий подстроку, краснел бы на собственном объяснении, а после вывода
// второй таблицы продолжал бы находить её имя в разборе причины. Поэтому
// таблица опознаётся ПО СОСТАВУ: package-level карта, все ключи ЛИБО все
// значения которой суть типы модели, объявленные манифестами.

import (
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmapgen"
)

// authzmapPackageDir — каталог продукта от корня репозитория.
const authzmapPackageDir = "services/iam/internal/authzmap"

// handWrittenTypeTablesRemaining — СКОЛЬКО таблиц типов ещё рукописны.
//
// НОЛЬ: обе таблицы пакета выводятся из манифестов. Вторая — `objectTypes` —
// уехала после того, как круг с загрузчиком манифеста был разорван сменой
// референта проверки (#1930): проход, порождающий таблицу, судит существование
// типа КАНОНОМ, а не ею же.
//
// Остаток остаётся ОБЪЯВЛЕННЫМ, а не выброшенным вместе с предметом, потому что
// он читается теперь в ДРУГУЮ сторону: рукописная таблица типов, вернувшаяся в
// пакет, краснеет здесь со своим именем. Вывод перестал бы быть единственным
// источником молча — два места об одном предмете расходятся без единого отказа.
const handWrittenTypeTablesRemaining = 0

// TestTypeTablesGeneratedCountIsMeasuredNotClaimed — #1092: «порождено две из
// двух» есть ИЗМЕРЕНИЕ, и вот оно.
func TestTypeTablesGeneratedCountIsMeasuredNotClaimed(t *testing.T) {
	tables, err := authzmapgen.Collect(repoRoot)
	if err != nil {
		t.Fatalf("обход манифестов не состоялся (%v) — предпосылка гейта исчезла, "+
			"а не дерево стало чистым", err)
	}

	survey, err := authzmapgen.SurveyTypeTables(
		filepath.Join(repoRoot, filepath.FromSlash(authzmapPackageDir)), tables.ObjectTypeSet())
	if err != nil {
		t.Fatalf("обход пакета продукта: %v", err)
	}

	t.Logf("перепись: файлов пакета прочитано %d, package-level карт %d, "+
		"из них таблиц типов %d — порождено %d, рукописно %d %v",
		survey.FilesRead, survey.MapsRead, survey.Generated+survey.HandWritten,
		survey.Generated, survey.HandWritten, survey.HandWrittenNames)

	if survey.FilesRead == 0 || survey.MapsRead == 0 {
		t.Fatalf("обход пакета пуст (файлов %d, карт %d) — вердикт относился бы "+
			"к непрочитанному", survey.FilesRead, survey.MapsRead)
	}
	if survey.Generated == 0 {
		t.Fatal("порождённых таблиц типов ноль — предмет вывода исчез, и «остаток» " +
			"ниже считался бы от пустоты")
	}
	if survey.HandWritten != handWrittenTypeTablesRemaining {
		t.Fatalf("рукописных таблиц типов %d при объявленном остатке %d: %v\n\n"+
			"Стало БОЛЬШЕ — в пакет вернулась рукописная таблица типов, и вывод "+
			"перестал быть единственным источником: два места об одном предмете "+
			"расходятся молча.\n"+
			"Стало МЕНЬШЕ нуля быть не может; отрицательный остаток означал бы, что "+
			"перепись считает не то.",
			survey.HandWritten, handWrittenTypeTablesRemaining, survey.HandWrittenNames)
	}
}
