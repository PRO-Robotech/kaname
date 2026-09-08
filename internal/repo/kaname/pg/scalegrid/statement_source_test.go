// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// statement_source_test.go — посевщик сетки берёт стейтменты У ПРОИЗВОДИТЕЛЯ, а
// не держит их копию.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Шапка посевщика утверждала: «подаются ДОСЛОВНО те же стейтменты, что выпускает
// производитель, — не их редакция». Держалось это утверждение ПРОЗОЙ:
// производителя у него не было ни одного, а названная рядом сверка
// (`TestScaleGridSeeder_RowForRowMatchesTheProducer`) тождества ТЕКСТА не
// утверждает — она сажает один набор двумя путями и сравнивает строки
// результата.
//
// Расхождение было живым, а не гипотетическим (#1890). На день правки копии
// разошлись по ДВУМ осям сразу:
//
//   - у полосы версионного сдвига производитель нёс условие приёма
//     (`EXISTS … catalog_resource … live`), копия — нет: посевщик сдвигал версию
//     на типе, снятом с платформы, то есть мерил стоимость операции, которой
//     продукт не выпускает;
//   - у полосы вставки производитель возвращал ТРИ значения (принят ли тип, имя
//     типа в словаре модели, число применённых строк), копия — два: имя типа
//     появилось у производителя задачей #1982 и до копии не доехало.
//
// Обе оси проходили молча: сверка строк результата на живом типе даёт одно и то
// же, а прибор порядков при этом мерил не тот запрос.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕМ ЭТО ДЕРЖИТСЯ ТЕПЕРЬ — ПОСТРОЕНИЕМ
//
// Оба стейтмента объявлены ОДИН раз, у производителя, экспортируемыми
// константами; посевщик подаёт в пачку ИХ. Расхождение стало невыразимо, и
// сверять больше нечего — гейт ниже стережёт только то, чтобы копия не завелась
// снова.
//
// Пачку это не трогает: посевщик по-прежнему шлёт стейтменты пачкой (в этом и
// состоит предмет замера — миллион объектов за сто секунд вместо семи минут),
// меняется лишь то, ОТКУДА берётся текст.
package scalegrid_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// mirrorTableToken — имя таблицы зеркала.
const mirrorTableToken = "kaname.resource_mirror"

// mirrorWriteForms — формы, которыми в зеркало ПИШУТ. Предмет гейта — они, а не
// всякое упоминание таблицы.
//
// Различие несущее, и законный близнец живёт в том же каталоге: перепись
// посевщика читает `SELECT count(*) FROM kaname.resource_mirror` — это ЕГО
// собственный вопрос («сколько строк легло»), у производителя такого стейтмента
// нет вовсе, и требовать его оттуда значило бы требовать чужого. Пишущий же
// стейтмент принадлежит производителю: копия расходится с ним молча.
var mirrorWriteForms = []string{
	"INSERT INTO " + mirrorTableToken,
	"UPDATE " + mirrorTableToken,
}

// mirrorWriteLiterals — строковые литералы файла, ПИШУЩИЕ в зеркало.
//
// Судится УЗЕЛ разбора, а не текст: имя таблицы стоит и в комментариях (в этом
// файле — не раз), и в шапке посевщика. Гейт по подстроке краснел бы на
// собственном объяснении.
func mirrorWriteLiterals(path string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		for _, form := range mirrorWriteForms {
			if !strings.Contains(collapseSpace(lit.Value), form) {
				continue
			}
			out = append(out, filepath.Base(path)+":"+
				strconvItoa(fset.Position(lit.Pos()).Line))
			break
		}
		return true
	})
	return out, nil
}

// collapseSpace — свёртка пробелов и переводов строк: стейтмент записан с
// отступами, и форма «INSERT INTO <таблица>» переносится через строку.
func collapseSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// strconvItoa — короткая запись числа: тянуть strconv ради одной строки дороже,
// чем назвать это здесь.
func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// goFilesOf — не-тестовые исходники каталога.
func goFilesOf(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("каталог %s не прочитан: %v — это отказ предпосылки", dir, err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	sort.Strings(out)
	return out
}

// TestSeederTakesStatementsFromTheProducer — у посевщика своей копии стейтментов
// зеркала нет.
//
// Утверждение ОДНОСТОРОННЕЕ без второй половины: «ноль литералов у посевщика»
// выполняется и тогда, когда стейтментов не стало вовсе. Поэтому рядом —
// контроль: у производителя их непустое число.
func TestSeederTakesStatementsFromTheProducer(t *testing.T) {
	const producerDir = "../resource_mirror"

	var seederHits []string
	seederFiles := goFilesOf(t, ".")
	for _, path := range seederFiles {
		hits, err := mirrorWriteLiterals(path)
		if err != nil {
			t.Fatalf("%s не разобран: %v", path, err)
		}
		seederHits = append(seederHits, hits...)
	}

	var producerHits []string
	producerFiles := goFilesOf(t, producerDir)
	for _, path := range producerFiles {
		hits, err := mirrorWriteLiterals(path)
		if err != nil {
			t.Fatalf("%s не разобран: %v", path, err)
		}
		producerHits = append(producerHits, hits...)
	}

	t.Logf("перепись: исходников посевщика %d · пишущих в %s литералов у него %d · "+
		"исходников производителя %d · пишущих литералов у него %d "+
		"(читающие переписи посевщика — его собственный вопрос и под гейт не подпадают)",
		len(seederFiles), mirrorTableToken, len(seederHits),
		len(producerFiles), len(producerHits))

	// КОНТРОЛЬ: без него «ноль у посевщика» зеленело бы на дереве, где
	// стейтментов нет ни у кого — то есть на снятом предмете.
	if len(producerHits) == 0 {
		t.Fatalf("обход пуст: у производителя (%s) не найдено ни одного ПИШУЩЕГО в %s "+
			"литерала — предмет снят либо разбор его не видит, и утверждение "+
			"ниже беспредметно", producerDir, mirrorTableToken)
	}

	if len(seederHits) > 0 {
		t.Errorf("посевщик держит СВОЮ копию стейтментов зеркала — %d литерал(ов): %s.\n"+
			"Копия расходится с производителем молча: сверка строк результата на живом типе "+
			"даёт одно и то же, а прибор порядков мерит запрос, которого продукт не выпускает.\n"+
			"Объяви стейтмент один раз в %s экспортируемой константой и подавай в пачку ЕЁ — "+
			"тогда расхождение невыразимо, и сверять нечего.",
			len(seederHits), strings.Join(seederHits, ", "), producerDir)
	}
}
