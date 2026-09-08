// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// package_qualifier_injection_test.go — доказательство того, что проверка
// квалификатора СПОСОБНА упасть, и того, что она молчит на законных близнецах.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СИНТЕТИЧЕСКИЙ КОРЕНЬ, А НЕ ПРАВКА ДЕРЕВА
//
// Проверка читает дерево службы, которое читают и соседние сессии. Внести в него
// дефект ради доказательства значило бы править общее состояние. Поэтому разбор
// вынесен в чистую функцию над ПРОИЗВОЛЬНЫМ корнем, а сюда подаётся корень,
// собранный в каталоге прогона.
//
// ─────────────────────────────────────────────────────────────────────────────
// КАЖДАЯ ИНЪЕКЦИЯ МЕНЯЕТ РОВНО ОДИН ФАКТ ПРОТИВ КОНТРОЛЯ
//
// Контроль стоит первым и обязан МОЛЧАТЬ. Дальше по одной оси меняется ровно
// один факт: иначе красное могло бы прийти от соседа, а проверка осталась бы
// вакуумной, не показав этого ничем.
//
// Ось «краснеет» здесь ОДНА — она и есть предмет. Осей «молчит» пять, и они
// несущие: без них проверка ловила бы СЛОВО `kacho`, а не квалификатор пакета,
// и первый же ложный срабат на пакете контракта, на имени DNS или на конце
// предложения её бы отключил.
//
// У полосы самой проверки стоит ПАРА: «в перечне — молчит» и «та же проза вне
// перечня — находка». Без второй половины пропуск был бы маской, а не полосой.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// qualRootWith собирает корень из перечисленных файлов с заданным содержимым.
// Файлов ровно столько, сколько подано: перепись тогда прямо называет, что
// прочитано ровно то, что подано.
func qualRootWith(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o750))
		require.NoError(t, os.WriteFile(full, []byte(body), 0o600))
	}
	return root
}

// soundQualifierTree — законный близнец: и объявление, и проза называют пакет
// каноническим именем. Проверка обязана молчать, а положительный контроль —
// выполниться.
func soundQualifierTree() map[string]string {
	return map[string]string{
		"internal/repo/kaname/iface.go": "" +
			"// Reader — читательская транзакция; см. `kaname.Reader`.\n" +
			"package kaname\n",
		"internal/repo/kaname/pg/tx.go": "" +
			"// readTx — kaname.Reader поверх pgx.Tx.\n" +
			"package pg\n",
	}
}

// ── Контроль: годный корень молчит ──────────────────────────────────────────

func TestQualInjectionControl_CanonicalRootIsSilent(t *testing.T) {
	census, findings, err := scanPackageQualifiers(syntheticCorpus(t, qualRootWith(t, soundQualifierTree())))
	require.NoError(t, err)
	require.Empty(t, findings, "годный корень объявлен нарушением: проверка ловит форму, а не существо")
	require.Equal(t, 2, census.filesRead, "контроль беспредметен: прочитано не то число файлов")
	require.Equal(t, 2, census.canonicalQuals, "контроль беспредметен: канонического квалификатора не распознано")
	require.Zero(t, census.retiredQuals)
	require.Zero(t, census.skippedLowercase, "строчная полоса сработала там, где строчных форм нет")
}

// ── Ось «краснеет»: отставленный квалификатор — НАХОДКА с координатой ───────

func TestQualInjection_RetiredQualifierIsFound(t *testing.T) {
	files := soundQualifierTree()
	files["internal/repo/kaname/pg/repository.go"] = "" +
		"// Repository — реализация kacho.Repository поверх pgxpool.\n" +
		"package pg\n"
	census, findings, err := scanPackageQualifiers(syntheticCorpus(t, qualRootWith(t, files)))
	require.NoError(t, err)
	require.Len(t, findings, 1, "отставленный квалификатор не найден — проверка вакуумна")
	require.Equal(t, 1, census.retiredQuals)
	require.Contains(t, findings[0].String(), "internal/repo/kaname/pg/repository.go:1",
		"находка не называет координату: читатель ищет её глазами")
	require.Contains(t, findings[0].String(), "kacho.Repository",
		"находка не называет само вхождение")
}

// ── Молчит: строчные словари — контракт, DNS, отношение, домен ──────────────
//
// Все они продолжаются строчной буквой, и это НЕ край, а обычная форма записи:
// на дереве службы их почти тысяча против одиннадцати квалификаторов.

func TestQualInjection_LowercaseDictionariesStaySilent(t *testing.T) {
	files := soundQualifierTree()
	files["internal/apps/kaname/api/wire.go"] = "" +
		"// пакет контракта — kacho.cloud.iam.v1; стенд отвечает на kacho.local\n" +
		"// отношение модели — kacho.view, домен каталога — kacho.storage\n" +
		"package api\n"
	census, findings, err := scanPackageQualifiers(syntheticCorpus(t, qualRootWith(t, files)))
	require.NoError(t, err)
	require.Empty(t, findings,
		"строчный словарь объявлен квалификатором: проверка судит слово, а не форму")
	require.Equal(t, 4, census.skippedLowercase,
		"строчная полоса не сосчитана: «ноль находок» неотличимо от «строчных не искали»")
}

// ── Молчит: конец предложения — между точкой и заглавной стоит пробел ───────

func TestQualInjection_SentenceEndStaysSilent(t *testing.T) {
	files := soundQualifierTree()
	files["docs/overview.md"] = "Прежде пакет звался kacho. Реализация с тех пор переехала.\n"
	census, findings, err := scanPackageQualifiers(syntheticCorpus(t, qualRootWith(t, files)))
	require.NoError(t, err)
	require.Empty(t, findings, "конец предложения объявлен квалификатором: «сразу после точки» не проверяется")
	require.Zero(t, census.retiredQuals)
}

// ── Молчит: заглавная НЕ латинская ──────────────────────────────────────────

func TestQualInjection_NonLatinCapitalStaysSilent(t *testing.T) {
	files := soundQualifierTree()
	files["docs/overview.md"] = "сокращение kacho.Реестр квалификатором Go быть не может\n"
	_, findings, err := scanPackageQualifiers(syntheticCorpus(t, qualRootWith(t, files)))
	require.NoError(t, err)
	require.Empty(t, findings, "кириллическая заглавная засчитана экспортируемым именем Go")
}

// ── Молчит: имя, продолжающееся слева ───────────────────────────────────────

func TestQualInjection_LongerIdentifierOnTheLeftStaysSilent(t *testing.T) {
	files := soundQualifierTree()
	files["docs/overview.md"] = "чужой пакет mykacho.Reader нашим не является\n"
	_, findings, err := scanPackageQualifiers(syntheticCorpus(t, qualRootWith(t, files)))
	require.NoError(t, err)
	require.Empty(t, findings, "`mykacho.Reader` объявлен нашим пакетом: левая граница не проверяется")
}

// ── Полоса самой проверки: молчит В перечне, находка ВНЕ него ──────────────

func TestQualInjection_TheCheckDoesNotJudgeItsOwnDeclaration(t *testing.T) {
	files := soundQualifierTree()
	files["internal/supplyhygiene/package_qualifier_test.go"] =
		"// запрещено: `kacho.Reader`, `kacho.Writer`, `kacho.Repository`\n"
	census, findings, err := scanPackageQualifiers(syntheticCorpus(t, qualRootWith(t, files)))
	require.NoError(t, err)
	require.Empty(t, findings, "проверка краснеет на собственном объяснении")
	require.Equal(t, 1, census.filesOwn)
	require.Equal(t, 3, census.skippedOwn, "пропуск самой проверки не сосчитан")
}

func TestQualInjection_TheSameDeclarationOutsideTheListIsFound(t *testing.T) {
	files := soundQualifierTree()
	files["internal/supplyhygiene/other_test.go"] =
		"// запрещено: `kacho.Reader`, `kacho.Writer`, `kacho.Repository`\n"
	census, findings, err := scanPackageQualifiers(syntheticCorpus(t, qualRootWith(t, files)))
	require.NoError(t, err)
	// Находка одна — по строке, а вхождений в ней три: перепись считает
	// вхождения, перечень находок адресует читателя к строке.
	require.Len(t, findings, 1, "файл вне перечня обязан судиться как любой другой")
	require.Equal(t, 3, census.retiredQuals, "все три вхождения строки обязаны быть сосчитаны")
	require.Zero(t, census.skippedOwn, "файл вне перечня зачтён в полосу самой проверки")
}

// ── Пустой обход отличим от нуля находок ───────────────────────────────────

func TestQualInjection_EmptyWalkIsDistinguishableFromZeroFindings(t *testing.T) {
	_, _, err := scanPackageQualifiers(syntheticCorpus(t, t.TempDir()))
	require.Error(t, err, "пустой обход выдан за зелёный прогон")
	require.Contains(t, err.Error(), "обход пуст")
}

// ── Положительный контроль не выполняется чем попало ───────────────────────

func TestQualInjection_CanonicalInsideALongerIdentifierDoesNotSatisfyTheControl(t *testing.T) {
	census, _, err := scanPackageQualifiers(syntheticCorpus(t, qualRootWith(t, map[string]string{
		"internal/repo/other/iface.go": "" +
			"// чужие `xkaname.Reader` и `kanamex.Reader` нашим пакетом не являются\n" +
			"package other\n",
	})))
	require.NoError(t, err)
	require.Zero(t, census.canonicalQuals,
		"чужое имя засчитано каноническим квалификатором: контроль выполнился чем угодно")
}
