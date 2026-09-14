// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// contract_schema_qualifier_injection_test.go — доказательство того, что сверка
// схемы контракта СПОСОБНА упасть, и того, что она молчит на законных близнецах.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СИНТЕТИЧЕСКИЙ КОРЕНЬ, А НЕ ПРАВКА ДЕРЕВА
//
// Проверка читает дерево службы, которое читают и соседние сессии. Внести в
// него дефект ради доказательства значило бы править общее состояние. Поэтому
// разбор вынесен в чистую функцию над ПРОИЗВОЛЬНЫМ корнем, а сюда подаётся
// корень, собранный в каталоге прогона.
//
// ─────────────────────────────────────────────────────────────────────────────
// ИМЕНА СИНТЕТИКИ — СВОИ, И ЭТО РЕШЕНИЕ
//
// Схема зовётся `ledger`, таблица — `entries`, неверная схема — `elsewhere`.
// Ни одно из трёх не встречается в дереве службы, поэтому доказательство не
// тащит в файл ни канонического имени схемы, ни отставленного: соседняя
// проверка (`schema_name_test.go`) обходит всё дерево по отставленному имени, и
// литерал здесь потребовал бы от неё освобождения — послабления, заведённого
// ради доказательства, а не ради предмета.
//
// ─────────────────────────────────────────────────────────────────────────────
// КАЖДАЯ ИНЪЕКЦИЯ МЕНЯЕТ РОВНО ОДИН ФАКТ ПРОТИВ КОНТРОЛЯ
//
// Контроль стоит первым и обязан МОЛЧАТЬ. Дальше по одной оси меняется ровно
// один факт: иначе красное могло бы прийти от соседа, а проверка осталась бы
// вакуумной, не показав этого ничем.
//
// Осей две породы, и обе обязательны. «Находка» доказывает способность упасть и
// назвать координату; «молчание» доказывает, что распознаватель судит ПРЕДМЕТ,
// а не форму «слово точка слово», — без неё первая же законная проза отключила
// бы проверку целиком.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/stretchr/testify/require"
)

// ── Постройка синтетического корня ──────────────────────────────────────────

// syntheticMigration — производитель истины синтетического мира: схема и одна
// таблица в ней. Ровно те два оператора, которые разбирает проверка.
const syntheticMigration = "CREATE SCHEMA ledger;\n" +
	"CREATE TABLE ledger.entries (id text PRIMARY KEY);\n"

// soundContract — законный близнец: комментарий называет таблицу схемой,
// которую объявили миграции. Проверка обязана молчать.
const soundContract = "syntax = \"proto3\";\n" +
	"package ledger.v1;\n" +
	"\n" +
	"// Handler reads `ledger.entries` on the request path.\n" +
	"message Entry {\n" +
	"  string id = 1;\n" +
	"}\n"

// contractSchemaTree собирает корень из перечисленных файлов. Перечень задаётся
// целиком: всякая проба ниже строит свой мир из годного и меняет ровно один
// факт, и подмена факта видна прямо в теле пробы.
func contractSchemaTree(t *testing.T, files map[string]string) *treecorpus.Tree {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
	return syntheticCorpus(t, root)
}

// soundWorld — годный мир: миграции плюс один собственный контракт.
func soundWorld(contract string) map[string]string {
	return map[string]string{
		"internal/migrations/0001_initial.sql": syntheticMigration,
		"proto/ledger/v1/sample.proto":         contract,
	}
}

// ── Контроль: годный мир молчит ─────────────────────────────────────────────

func TestContractSchemaControl_SoundWorldIsSilent(t *testing.T) {
	census, findings, err := scanContractSchemaQualifiers(contractSchemaTree(t, soundWorld(soundContract)))
	require.NoError(t, err)
	require.Empty(t, findings, "годный мир объявлен нарушением: проверка ловит форму, а не существо")
	require.Equal(t, 1, census.migrationsRead, "контроль беспредметен: миграций не прочитано")
	require.Equal(t, 1, census.tablesDeclared, "контроль беспредметен: реестр таблиц пуст")
	require.Equal(t, 1, census.contractsOwn, "контроль беспредметен: контрактов не прочитано")
	require.Equal(t, 1, census.qualified, "квалифицированная ссылка не распознана — проверка слепа")
	require.Equal(t, 1, census.matching, "ссылка не засчитана совпавшей со схемой миграций")
}

// ── Ось 1: чужая схема в комментарии — НАХОДКА, называющая координату ───────

func TestContractSchemaInjection_ForeignQualifierIsFound(t *testing.T) {
	world := soundWorld(strings.Replace(soundContract, "ledger.entries", "elsewhere.entries", 1))

	census, findings, err := scanContractSchemaQualifiers(contractSchemaTree(t, world))
	require.NoError(t, err)
	require.Len(t, findings, 1, "чужая схема не найдена — проверка не способна упасть")
	require.Equal(t, "proto/ledger/v1/sample.proto", findings[0].file, "находка не называет файл")
	require.Equal(t, 4, findings[0].line, "находка не называет строку")
	require.Equal(t, "elsewhere", findings[0].named, "находка не называет схему, которую написали")
	require.Equal(t, "ledger", findings[0].want, "находка не называет схему, которую объявили миграции")
	require.Zero(t, census.matching)
}

// ── Ось 2: ПЕРЕИМЕНОВАНИЕ СХЕМЫ — тот самый дефект, ради которого гейт ──────
//
// Мир отличается от контроля ровно одним фактом: миграции объявляют схему под
// новым именем. Комментарий не менялся — и стал ложью. Это и есть класс: не
// «кто-то написал не то», а «схему переименовали, а координата осталась».

func TestContractSchemaInjection_RenamedSchemaLeavesTheCommentFalse(t *testing.T) {
	world := soundWorld(soundContract)
	world["internal/migrations/0001_initial.sql"] = "CREATE SCHEMA renamed;\n" +
		"CREATE TABLE renamed.entries (id text PRIMARY KEY);\n"

	_, findings, err := scanContractSchemaQualifiers(contractSchemaTree(t, world))
	require.NoError(t, err)
	require.Len(t, findings, 1,
		"переименование схемы не отразилось на вердикте: проверка сверяет контракт с памятью, "+
			"а не с производителем истины")
	require.Equal(t, "renamed", findings[0].want,
		"находка не называет НЫНЕШНЮЮ схему — читателю нечем починить координату")
}

// ── Ось 3: ХВОСТОВОЙ комментарий после кода — читается ──────────────────────

func TestContractSchemaInjection_TrailingCommentIsJudged(t *testing.T) {
	contract := strings.Replace(soundContract,
		"  string id = 1;\n",
		"  string id = 1; // mirrored from elsewhere.entries\n", 1)

	_, findings, err := scanContractSchemaQualifiers(contractSchemaTree(t, soundWorld(contract)))
	require.NoError(t, err)
	require.Len(t, findings, 1,
		"хвостовой комментарий не прочитан: форма, о которой распознаватель не знает, "+
			"даёт не красное и не зелёное, а молчание")
}

// ── Ось 4: БЛОЧНЫЙ комментарий — читается, и координата называет СВОЮ строку ─

func TestContractSchemaInjection_BlockCommentIsJudgedAtItsOwnLine(t *testing.T) {
	contract := soundContract + "\n/* заметка о хранении:\n   строка живёт в elsewhere.entries\n*/\n"

	_, findings, err := scanContractSchemaQualifiers(contractSchemaTree(t, soundWorld(contract)))
	require.NoError(t, err)
	require.Len(t, findings, 1, "блочный комментарий не прочитан")
	require.Equal(t, 10, findings[0].line,
		"координата названа по строке ОТКРЫТИЯ комментария, а не по строке ссылки — "+
			"читателя пошлют не в то место")
}

// ── Ось 5: СТРОКОВЫЙ ЛИТЕРАЛ комментарием не является ───────────────────────
//
// Двойная косая черта живёт внутри всякого адреса. Разбор, не знающий кавычек,
// прочёл бы хвост адреса как комментарий — то есть судил бы КОД, притом наугад.

func TestContractSchemaInjection_StringLiteralIsNotAComment(t *testing.T) {
	contract := soundContract +
		"\nservice S {\n  rpc Get(Entry) returns (Entry) {\n" +
		"    option (google.api.http) = { get: \"https://host//elsewhere.entries\" };\n" +
		"  }\n}\n"

	_, findings, err := scanContractSchemaQualifiers(contractSchemaTree(t, contract2world(contract)))
	require.NoError(t, err)
	require.Empty(t, findings,
		"хвост адреса в строковом литерале прочитан как комментарий: разбор не знает кавычек")
}

// Близнец: ТОТ ЖЕ текст вне кавычек, комментарием, — находка. Различие ровно
// одно: кавычки. Без этой пары молчание оси 5 было бы неотличимо от слепоты.
func TestContractSchemaInjection_TheSameTextAsACommentIsFound(t *testing.T) {
	contract := soundContract + "\n// https://host//elsewhere.entries\n"

	_, findings, err := scanContractSchemaQualifiers(contractSchemaTree(t, contract2world(contract)))
	require.NoError(t, err)
	require.Len(t, findings, 1,
		"тот же текст комментарием пропущен: молчание оси 5 приходит не от кавычек, а от слепоты")
}

// contract2world — годный мир с заданным контрактом. Вынесено ради того, чтобы
// пара выше отличалась ОДНИМ фактом, а не двумя вызовами разной формы.
func contract2world(contract string) map[string]string { return soundWorld(contract) }

// ── Ось 6: ПРАВО КАТАЛОГА — три сегмента, не квалификатор ───────────────────

func TestContractSchemaInjection_ThreeSegmentPermissionStaysSilent(t *testing.T) {
	contract := soundContract + "\n// admin must hold `iam.entries.forceLogout` on the account.\n"

	census, findings, err := scanContractSchemaQualifiers(contractSchemaTree(t, soundWorld(contract)))
	require.NoError(t, err)
	require.Empty(t, findings,
		"право каталога объявлено квалификатором схемы: проверка судит форму «слово точка слово», "+
			"а квалификатор схемы состоит РОВНО из двух сегментов")
	require.Equal(t, 1, census.skippedDotted,
		"сегменты длинного пути не сосчитаны — «пропущено 0» стало бы неотличимо от "+
			"«полоса не рассматривалась»")
}

// Левый сосед той же формы: ссылка есть ХВОСТ более длинного пути (домен
// издателя, пакет контракта). Различие с осью 6 — с какой стороны лишний
// сегмент; распознаватель, знающий одну сторону, пропустил бы вторую молча.
func TestContractSchemaInjection_DottedPathTailStaysSilent(t *testing.T) {
	contract := soundContract + "\n// issuer domain is iam.ledger.entries in the token band.\n"

	census, findings, err := scanContractSchemaQualifiers(contractSchemaTree(t, soundWorld(contract)))
	require.NoError(t, err)
	require.Empty(t, findings, "хвост длинного пути объявлен квалификатором схемы")
	require.Equal(t, 1, census.skippedDotted)
}

// ── Ось 7: ПРОЗА, где точка кончает предложение ─────────────────────────────

func TestContractSchemaInjection_ProseEndingInTheSchemaNameStaysSilent(t *testing.T) {
	contract := soundContract + "\n// Rows are persisted by ledger. Until the gateway learns this,\n" +
		"// the caller sees the raw id.\n"

	census, findings, err := scanContractSchemaQualifiers(contractSchemaTree(t, soundWorld(contract)))
	require.NoError(t, err)
	require.Empty(t, findings,
		"проза, где точка кончает предложение, объявлена квалификатором: гейт краснел бы на "+
			"собственном объяснении")
	require.Equal(t, 1, census.qualified, "положительный контроль потерян вместе с прозой")
}

// ── Ось 8: ТАБЛИЦА БЕЗ КВАЛИФИКАТОРА — законный исход 2 задачи ──────────────

func TestContractSchemaInjection_UnqualifiedTableStaysSilent(t *testing.T) {
	contract := soundContract + "\n// The handler appends one row to `entries`.\n"

	census, findings, err := scanContractSchemaQualifiers(contractSchemaTree(t, soundWorld(contract)))
	require.NoError(t, err)
	require.Empty(t, findings,
		"таблица без квалификатора объявлена нарушением: снятие квалификатора — законный исход, "+
			"а не дефект")
	require.Equal(t, 1, census.qualified)
}

// ── Ось 9: ВХОДНОЙ контракт судится ЧУЖИМ реестром — пропуск ────────────────
//
// Соседний контракт лежит в дереве потому, что оператор `import` резолвится
// файлом. Свою схему он называет законно, и наш реестр таблиц ему не судья.

// ledgerFor — ведомость входов, объявляющая один чужой контракт.
const ledgerFor = "inputs:\n" +
	"  - path: foreign/v1/other.proto\n" +
	"    sha256: 00\n" +
	"    stubs: example.com/foreign\n"

func TestContractSchemaInjection_InputContractIsSkipped(t *testing.T) {
	world := soundWorld(soundContract)
	world["proto/inputs.yaml"] = ledgerFor
	world["proto/foreign/v1/other.proto"] = "// rows live in elsewhere.entries\n"

	census, findings, err := scanContractSchemaQualifiers(contractSchemaTree(t, world))
	require.NoError(t, err)
	require.Empty(t, findings,
		"чужой контракт осуждён нашим реестром таблиц: его схема — правда его дерева, "+
			"а не находка нашего")
	require.Equal(t, 1, census.contractsInput, "входные контракты не сосчитаны")
	require.Equal(t, 1, census.ledgerEntries, "ведомость входов не прочитана")
}

// Близнец: ТОТ ЖЕ файл с тем же текстом, но ведомостью не объявленный. Различие
// ровно одно — запись в ведомости. Без этой пары пропуск был бы послаблением
// без доказательства, и «чужих ноль» стало бы неотличимо от «судится ничто».
func TestContractSchemaInjection_TheSameFileOutsideTheLedgerIsFound(t *testing.T) {
	world := soundWorld(soundContract)
	world["proto/inputs.yaml"] = "inputs:\n  - path: some/other/file.proto\n    sha256: 00\n"
	world["proto/foreign/v1/other.proto"] = "// rows live in elsewhere.entries\n"

	census, findings, err := scanContractSchemaQualifiers(contractSchemaTree(t, world))
	require.NoError(t, err)
	require.Len(t, findings, 1,
		"пропуск роздан по КАТАЛОГУ, а не по ведомости: тогда всякий контракт, положенный "+
			"рядом, вышел бы из-под наблюдения")
	require.Zero(t, census.contractsInput)
}

// ── Ось 10: ПОЛОСА — файл вне `proto/` не судится ───────────────────────────
//
// Это то, чем снят класс «гейт краснеет на собственном объяснении»: объяснение
// живёт в файле `.go` под `internal/`, а судятся `.proto` под `proto/`.
// Освобождения нет — нет и пересечения.

func TestContractSchemaInjection_FileOutsideTheContractBandStaysSilent(t *testing.T) {
	world := soundWorld(soundContract)
	world["internal/sample/sample.go"] = "package sample\n\n// пример неверной координаты: elsewhere.entries\n"

	census, findings, err := scanContractSchemaQualifiers(contractSchemaTree(t, world))
	require.NoError(t, err)
	require.Empty(t, findings,
		"файл вне полосы контракта осуждён: тогда объяснение самой проверки стало бы её находкой")
	require.Equal(t, 1, census.contractsOwn, "полоса собственного контракта сосчитана неверно")
}

// ── Ось 11: ТАБЛИЦА, ОБЪЯВЛЕННАЯ В ДВУХ СХЕМАХ, — обе законны ──────────────
//
// Реестр хранит МНОЖЕСТВО схем на таблицу, а не одну: мир, где одноимённая
// таблица заведена дважды, законен, и проверка, знающая одну схему, объявила бы
// находкой вторую.

func TestContractSchemaInjection_TableDeclaredInTwoSchemasAcceptsBoth(t *testing.T) {
	world := soundWorld(strings.Replace(soundContract, "ledger.entries", "archive.entries", 1))
	world["internal/migrations/0001_initial.sql"] = syntheticMigration +
		"CREATE SCHEMA archive;\nCREATE TABLE archive.entries (id text PRIMARY KEY);\n"

	census, findings, err := scanContractSchemaQualifiers(contractSchemaTree(t, world))
	require.NoError(t, err)
	require.Empty(t, findings, "вторая схема той же таблицы объявлена находкой")
	require.Equal(t, 2, census.schemasDeclared)
	require.Equal(t, 1, census.tablesDeclared)
}

// ── Ось 12: ЧЕТЫРЕ ВИДА ПУСТОТЫ — каждый отличим от «ноль находок» ──────────

func TestContractSchemaInjection_NoMigrationsIsRefused(t *testing.T) {
	_, _, err := scanContractSchemaQualifiers(contractSchemaTree(t, map[string]string{
		"proto/ledger/v1/sample.proto": soundContract,
	}))
	require.Error(t, err, "мир без миграций прошёл успехом: сверять было не с чем")
	require.Contains(t, err.Error(), "миграций не прочитано")
}

func TestContractSchemaInjection_MigrationsWithoutASchemaAreRefused(t *testing.T) {
	world := soundWorld(soundContract)
	world["internal/migrations/0001_initial.sql"] = "ALTER TABLE ledger.entries ADD COLUMN note text;\n"

	_, _, err := scanContractSchemaQualifiers(contractSchemaTree(t, world))
	require.Error(t, err, "мир без объявления схемы прошёл успехом")
	require.Contains(t, err.Error(), "не объявляют ни одной схемы")
}

func TestContractSchemaInjection_EmptyTableRosterIsRefused(t *testing.T) {
	world := soundWorld(soundContract)
	world["internal/migrations/0001_initial.sql"] = "CREATE SCHEMA ledger;\n"

	_, _, err := scanContractSchemaQualifiers(contractSchemaTree(t, world))
	require.Error(t, err,
		"пустой реестр таблиц прошёл успехом: распознаватель слеп by construction, "+
			"и вердикт был бы о молчании, а не о дереве")
	require.Contains(t, err.Error(), "реестр таблиц пуст")
}

func TestContractSchemaInjection_NoOwnContractIsRefused(t *testing.T) {
	_, _, err := scanContractSchemaQualifiers(contractSchemaTree(t, map[string]string{
		"internal/migrations/0001_initial.sql": syntheticMigration,
	}))
	require.Error(t, err, "мир без собственных контрактов прошёл успехом")
	require.Contains(t, err.Error(), "собственных контрактов не прочитано")
}

// Контракт без единого комментария: обход состоялся, а читать оказалось нечего.
// Это не «ноль находок», а «ноль прочитанного», и вердикта у него нет.
func TestContractSchemaInjection_ContractWithoutCommentsIsRefused(t *testing.T) {
	world := soundWorld("syntax = \"proto3\";\npackage ledger.v1;\n\nmessage Entry {\n  string id = 1;\n}\n")

	_, _, err := scanContractSchemaQualifiers(contractSchemaTree(t, world))
	require.Error(t, err, "контракт без комментариев прошёл успехом: распознаватель мог ослепнуть")
	require.Contains(t, err.Error(), "обход комментариев пуст")
}
