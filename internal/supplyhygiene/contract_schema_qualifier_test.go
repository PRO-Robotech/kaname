// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// contract_schema_qualifier_test.go — схема, названная КОНТРАКТОМ, обязана быть
// той, что объявляют МИГРАЦИИ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Комментарии контракта называют координату хранилища квалификатором схемы —
// `kaname.users`, `kaname.fga_outbox`, `kaname.catalog_verb`. Контракт
// ДОСТАВЛЯЕТСЯ: вместе с порождёнными заглушками он уезжает тому, у кого нашего
// дерева нет вовсе, и проверить координату он не может ничем. Значит ложная
// координата там дороже ложной координаты в нашем собственном файле: у первой
// нет читателя, способного её опровергнуть.
//
// Класс уже сработал один раз. Схема службы получила имя своего продукта, а пять
// файлов контракта продолжали называть прежнюю; нашлось это не проверкой, а
// разбором эпика. Приведение координаты к факту (kacho#2128) сделало комментарии
// верными ТЕМ ЖЕ ПОСТРОЕНИЕМ: в контракте снова написано имя схемы, и снова его
// никто не сверяет. Следующее переименование оставит те же комментарии ложными,
// и заметить это будет так же нечем.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕМ ЭТА ПРОВЕРКА ОТЛИЧАЕТСЯ ОТ СОСЕДНЕЙ (schema_name_test.go)
//
// Соседняя судит ОТСТАВЛЕННОЕ имя: его в дереве быть не должно. Её полосы стоят
// сегодня на нуле — предмет снят, и это правильный ноль. Но об имени НЫНЕШНЕМ
// она не утверждает ничего: переименуй схему завтра — и `kaname.users` в
// контракте станет ложью, к которой у неё нет входа, потому что её вход есть
// имя вчерашнее.
//
// Здесь вход другой и он ЖИВОЙ: производителем истины назначены миграции. Что
// они объявили оператором `CREATE SCHEMA` и квалификатором `CREATE TABLE`, то
// контракт и обязан называть. Переименование схемы двигает обе стороны разом,
// поэтому проверка переживает его by construction — ей нечего обновлять.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ДЕРЖАТЕЛЬ ЗДЕСЬ, А НЕ В ДЕРЕВЕ ПЛАТФОРМЫ
//
// Задача называла домом `internal/repohygiene` платформы — адрес, верный, пока
// служба жила внутри монорепо. Сегодня обе стороны сверки живут ЗДЕСЬ: и
// контракт (`proto/kaname/**`), и миграции (`internal/migrations/*.sql`).
// Держатель в чужом дереве не увидел бы ни одной из них: сверка возможна только
// там, где видны оба операнда.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЛОСА ВЫВОДИТСЯ, А НЕ ВЫПИСЫВАЕТСЯ — обе её стороны
//
//   - СЛЕВА (что судится): контракты под `proto/`, КРОМЕ перечисленных
//     ведомостью входов `proto/inputs.yaml`. Чужой контракт лежит в дереве
//     потому, что оператор `import` резолвится файлом, и свою схему он называет
//     законно; судить его нашим реестром значило бы объявить находкой чужую
//     правду. Ведомость читается той же функцией, что и у соседних проверок, —
//     литерал разошёлся бы с нею молча;
//   - СПРАВА (с чем сверяется): реестр таблиц и схем, разобранный из миграций.
//     Рукописного перечня таблиц нет: он устарел бы на первой же миграции, и
//     устаревание было бы МОЛЧАЛИВЫМ — распознаватель просто перестал бы
//     узнавать новые таблицы.
//
// ─────────────────────────────────────────────────────────────────────────────
// РАСПОЗНАВАТЕЛЬ ОБЯЗАН ЗНАТЬ ВСЕ ЗАКОННЫЕ ФОРМЫ — иначе он МОЛЧИТ
//
// Форма, о которой распознаватель не знает, даёт не красное и не зелёное:
// написанное в ней выходит из-под наблюдения, и по вердикту это неотличимо от
// исправного дерева. Формы перечислены и доказаны инъекцией по каждой.
//
// ЧИТАЕТСЯ (комментарий контракта, три записи одного предмета):
//
//	// `kaname.users` — строка целиком комментарий
//	string x = 1; // `kaname.users` — хвостовой комментарий после кода
//	/* `kaname.users` */ — блочный комментарий, в том числе многострочный
//
// НЕ ЧИТАЕТСЯ, и это решение, а не упущение:
//
//   - СТРОКОВЫЙ ЛИТЕРАЛ. Двойная косая черта живёт внутри всякого адреса
//     (`"https://…"`), и разбор, не знающий кавычек, принял бы хвост адреса за
//     комментарий. Литерал есть КОД, его судит компиляция контракта;
//   - тело контракта вне комментариев: координаты хранилища там нет by
//     construction — имена полей и опций не квалифицируются схемой.
//
// МОЛЧИТ НА СОСЕДЯХ, делящих с квалификатором форму «слово точка слово»:
//
//	kaname.cloud.iam.v1   пакет контракта — справа `cloud`, таблицы такой нет
//	iam.kaname.cloud      домен издателя — то же
//	iam.users.forceLogout право каталога: три сегмента, а квалификатор схемы —
//	                      ровно два. Сегмент, за которым идёт ещё один, не
//	                      квалификатор, и пропуск считается ОТДЕЛЬНЫМ числом
//	persisted by kaname.  проза, где точка кончает предложение
//	`users`               таблица без квалификатора — законный исход 2 задачи
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТА ПРОВЕРКА НЕ МОЖЕТ СУДИТЬ СЕБЯ
//
// Гейт, ищущий имя схемы подстрокой по всему дереву, краснеет на СОБСТВЕННОМ
// объяснении: чтобы объяснить, что запрещено, он обязан это назвать. Здесь
// класс снят не освобождением, а ПОЛОСОЙ: судятся файлы `.proto` под `proto/`,
// а объяснение живёт в файле `.go` под `internal/`. Освобождать нечего —
// пересечения нет by construction, и это доказано инъекцией (тот же текст в
// файле вне полосы молчит).
//
// По той же причине в этом файле и в его доказательстве НЕТ отставленного имени
// схемы ни одним литералом: инъекция обходится синтетическими именами, поэтому
// перечень освобождений соседней проверки не растёт на нас.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗНАЧИТ КРАСНОЕ «квалификаторов ноль»
//
// Ноль квалифицированных ссылок роняет прогон намеренно — это положительный
// контроль: без него отрицание выполнялось бы на дереве, где комментарии
// вычистили или где распознаватель ослеп от переноса строки.
//
// Задача kacho#2291 называла вторым законным исходом снятие квалификатора из
// прозы контракта («комментарий называет таблицу без схемы»). Исход остаётся
// законным, и красное здесь его НЕ запрещает — оно требует, чтобы он был принят
// ЯВНО: утверждение снимается вместе со своим предметом, одним изменением, а не
// вырождается в молчание.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПОЛОСА — КОНТРАКТ, А НЕ ВСЁ ДЕРЕВО
//
// Квалификатор схемы стоит в дереве службы 4286 раз вне контракта, и почти весь
// этот объём — операторы SQL в прод-коде. У них ДЕРЖАТЕЛЬ ЕСТЬ, и он сильнее
// всякого гейта: неверная схема там не компилируется в отказ, а роняет запрос на
// живой базе. Расширять полосу на них значило бы платить ложными находками
// (алиас `a.roles` в запросе, поле `body.users` в пробе) за свойство, которое уже
// держится тем, что продукт работает.
//
// У комментария контракта держателя нет НИ ОДНОГО, и он при этом ДОСТАВЛЯЕТСЯ.
// Это и есть точка, где цена ошибки максимальна, а стоимость проверки — нулевая:
// в прозе контракта алиасов SQL не бывает, поэтому распознаватель здесь точен.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОВЕРКА НЕ ЗАКРЫВАЕТ — сказано прямо, числами
//
//   - ПОРОЖДЁННЫЕ ЗАГЛУШКИ (`pkg/api/**`) несут те же комментарии и уезжают
//     клиенту вместе с контрактом. Здесь они не судятся: они ВЫХОД генерации,
//     а их сходимость со входом держит `make proto-gen-diff` в конвейере.
//     Ложная координата доедет до них только через контракт, и здесь она будет
//     остановлена;
//   - ОДОБРЕННЫЕ ПРИЁМКИ называют квалификатор 240 раз, и правке они не
//     подлежат: вердикт одобрения привязан к точному содержимому, а записи
//     замеров внутри привязаны к прошлому состоянию дерева. Это осознанно вне
//     полосы, а не упущение;
//   - ПРОЧАЯ инженерная проза документации — 85 вхождений — держателя не имеет.
//     Полоса её не берёт по той же причине, по какой берёт контракт: проза не
//     доставляется, и у её читателя дерево есть;
//   - КЛИЕНТСКАЯ документация (`docs/content/**`) квалификатора не называет НИ
//     РАЗУ — предикат даёт ноль, и это проверено, а не предположено. Появится
//     там координата — полосу надо расширять на неё первой: она доставляется;
//   - ПРАВДИВОСТЬ самого утверждения комментария («эта строка действительно
//     читается тем RPC») не проверяется ничем: судится координата, а не факт.
package supplyhygiene

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/stretchr/testify/require"
)

// contractProtoDir — дом контрактов службы. Под ним лежат и свои, и входные:
// сужает полосу ведомость входов, а не этот путь.
const contractProtoDir = "proto/"

// createSchemaRe / createTableRe — операторы миграций, объявляющие имена. Разбор
// намеренно узкий: он ловит ОБЪЯВЛЕНИЕ, а не всякое упоминание, иначе реестр
// наполнился бы таблицами, которых служба не заводит.
var (
	createSchemaRe = regexp.MustCompile(`(?is)\bCREATE\s+SCHEMA\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([a-z_][a-z0-9_]*)"?`)
	createTableRe  = regexp.MustCompile(`(?is)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"?([a-z_][a-z0-9_]*)"?\s*\.\s*"?([a-z_][a-z0-9_]*)"?`)
)

// contractSchemaCensus — объём осмотренного. Печатается ВСЕГДА, включая зелёный
// прогон: «ноль находок» обязано быть отличимо от «ноль прочитанного», а у этой
// проверки таких «ноль» четыре — миграции, реестр, контракты, комментарии.
type contractSchemaCensus struct {
	migrationsRead  int // файлов миграций прочитано
	schemasDeclared int // схем объявлено оператором CREATE SCHEMA
	tablesDeclared  int // таблиц в реестре — вход распознавателя
	ledgerEntries   int // записей ведомости входных контрактов
	contractsOwn    int // собственных контрактов прочитано
	contractsInput  int // входных контрактов пропущено (ведомость)
	commentLines    int // строк комментария прочитано
	qualified       int // ссылок вида <схема>.<таблица реестра>
	matching        int // из них назвали схему, которую объявляют миграции
	skippedDotted   int // пропущено: сегмент длинного пути (право каталога, пакет)
}

// contractSchemaFinding — одна ссылка контракта, назвавшая не ту схему.
type contractSchemaFinding struct {
	file  string
	line  int
	named string // схема, которую назвал комментарий
	table string
	want  string // схемы, которые объявляют эту таблицу
	text  string
}

func (f contractSchemaFinding) String() string {
	return fmt.Sprintf("%s:%d: названо %s.%s, миграции объявляют таблицу в схеме %s — %s",
		f.file, f.line, f.named, f.table, f.want, strings.TrimSpace(f.text))
}

// protoCommentSpan — один отрезок комментария со своей строкой. Блочный
// комментарий раскладывается по строкам, чтобы координата находки называла ту
// строку, где стоит ссылка, а не ту, где открылся комментарий.
type protoCommentSpan struct {
	line int
	text string
}

// protoCommentSpans выделяет из текста контракта РОВНО комментарии, зная три
// формы записи и умея не принять за комментарий строковый литерал.
//
// Кавычки разбираются не педантизма ради: двойная косая черта стоит внутри
// всякого адреса, и разбор, их не знающий, читал бы хвост адреса как
// комментарий — то есть судил бы КОД, притом наугад.
func protoCommentSpans(src string) []protoCommentSpan {
	var out []protoCommentSpan
	line, i, n := 1, 0, len(src)

	for i < n {
		switch c := src[i]; {
		case c == '\n':
			line++
			i++

		case c == '"' || c == '\'':
			quote := c
			for i++; i < n; i++ {
				if src[i] == '\\' && i+1 < n {
					i++
					continue
				}
				if src[i] == '\n' {
					line++ // незакрытый литерал: не теряем счёт строк
					continue
				}
				if src[i] == quote {
					i++
					break
				}
			}

		case c == '/' && i+1 < n && src[i+1] == '/':
			end := strings.IndexByte(src[i:], '\n')
			if end < 0 {
				out = append(out, protoCommentSpan{line, src[i:]})
				i = n
				continue
			}
			out = append(out, protoCommentSpan{line, src[i : i+end]})
			i += end

		case c == '/' && i+1 < n && src[i+1] == '*':
			opened := line
			i += 2
			begin := i
			for i < n && !(src[i] == '*' && i+1 < n && src[i+1] == '/') {
				if src[i] == '\n' {
					line++
				}
				i++
			}
			body := src[begin:i]
			if i < n {
				i += 2
			}
			for k, part := range strings.Split(body, "\n") {
				out = append(out, protoCommentSpan{opened + k, part})
			}

		default:
			i++
		}
	}
	return out
}

// isSchemaIdentByte — байт, продолжающий идентификатор Postgres.
func isSchemaIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// tableRef — одна ссылка `<слово>.<таблица>`, найденная в комментарии.
type tableRef struct {
	schema string
	table  string
	dotted bool // за ссылкой идёт ещё один сегмент: это путь, а не квалификатор
}

// tableRefsIn находит в отрезке комментария ссылки на таблицы реестра.
//
// Квалификатор схемы состоит РОВНО из двух сегментов. Всё, у чего сегментов
// больше, — другой предмет: право каталога (`iam.users.forceLogout`), пакет
// контракта (`kaname.cloud.iam.v1`), домен издателя. Такие вхождения не
// отбрасываются молча, а считаются отдельным числом переписи: «пропущено 0»
// обязано быть отличимо от «полоса не рассматривалась».
func tableRefsIn(text string, roster map[string]map[string]bool) []tableRef {
	var out []tableRef

	for at := 0; ; {
		dot := strings.IndexByte(text[at:], '.')
		if dot < 0 {
			return out
		}
		abs := at + dot
		at = abs + 1

		// Левый сегмент: идентификатор, упирающийся в точку.
		left := abs
		for left > 0 && isSchemaIdentByte(text[left-1]) {
			left--
		}
		if left == abs {
			continue // точке слева ничего не предшествует
		}
		// Правый сегмент.
		right := abs + 1
		for right < len(text) && isSchemaIdentByte(text[right]) {
			right++
		}
		if right == abs+1 {
			continue // точка кончает предложение либо за ней не идентификатор
		}
		table := text[abs+1 : right]
		if _, known := roster[table]; !known {
			continue
		}
		// Точка слева от левого сегмента: ссылка есть хвост более длинного пути.
		// Байт идентификатора здесь невозможен by construction — цикл выше их
		// уже съел, — поэтому ветви на него нет.
		if left > 0 && text[left-1] == '.' {
			out = append(out, tableRef{schema: text[left:abs], table: table, dotted: true})
			at = right
			continue
		}
		dotted := right < len(text) && text[right] == '.' &&
			right+1 < len(text) && isSchemaIdentByte(text[right+1])

		out = append(out, tableRef{schema: text[left:abs], table: table, dotted: dotted})
		at = right
	}
}

// readMigrationRoster разбирает миграции службы: какие схемы они объявляют и
// какая схема владеет какой таблицей. Это ПРОИЗВОДИТЕЛЬ истины для сверки —
// единственный в дереве, и потому рукописного дубля у него нет.
func readMigrationRoster(root string, tree *treecorpus.Tree) (
	schemas map[string]bool, roster map[string]map[string]bool, filesRead int, err error,
) {
	schemas = map[string]bool{}
	roster = map[string]map[string]bool{}

	for _, rel := range tree.SortedFiles() {
		slash := filepath.ToSlash(rel)
		if !strings.HasPrefix(slash, appliedMigrationDir) || !strings.HasSuffix(slash, ".sql") {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if readErr != nil {
			return nil, nil, 0, fmt.Errorf("миграция %s не прочитана: %w", slash, readErr)
		}
		filesRead++
		text := string(raw)

		for _, m := range createSchemaRe.FindAllStringSubmatch(text, -1) {
			schemas[m[1]] = true
		}
		for _, m := range createTableRe.FindAllStringSubmatch(text, -1) {
			schemas[m[1]] = true
			if roster[m[2]] == nil {
				roster[m[2]] = map[string]bool{}
			}
			roster[m[2]][m[1]] = true
		}
	}
	return schemas, roster, filesRead, nil
}

// scanContractSchemaQualifiers разбирает ПРОИЗВОЛЬНЫЙ корень: настоящее дерево
// службы и синтетический корень инъекции проходят одну и ту же функцию, поэтому
// доказанное на втором верно для первого.
func scanContractSchemaQualifiers(tree *treecorpus.Tree) (
	contractSchemaCensus, []contractSchemaFinding, error,
) {
	var census contractSchemaCensus
	var findings []contractSchemaFinding

	root := tree.Root()

	schemas, roster, migrationsRead, err := readMigrationRoster(root, tree)
	if err != nil {
		return census, nil, err
	}
	census.migrationsRead = migrationsRead
	census.schemasDeclared = len(schemas)
	census.tablesDeclared = len(roster)

	if migrationsRead == 0 {
		return census, nil, fmt.Errorf(
			"схема контракта: миграций не прочитано (%s под корнем %q) — производителя истины нет, "+
				"и сверять контракт не с чем", appliedMigrationDir, root)
	}
	if len(schemas) == 0 {
		return census, nil, fmt.Errorf(
			"схема контракта: миграции не объявляют ни одной схемы — сверять не с чем, " +
				"и вердикт был бы вакуумным")
	}
	if len(roster) == 0 {
		return census, nil, fmt.Errorf(
			"схема контракта: реестр таблиц пуст — распознаватель слеп by construction: " +
				"он узнаёт ссылку по имени таблицы, а имён у него нет")
	}

	inputs, err := contractInputPaths(root)
	if err != nil {
		return census, nil, err
	}
	census.ledgerEntries = len(inputs)

	for _, rel := range tree.SortedFiles() {
		slash := filepath.ToSlash(rel)
		if !strings.HasPrefix(slash, contractProtoDir) || !strings.HasSuffix(slash, ".proto") {
			continue
		}
		if inputs[slash] {
			census.contractsInput++
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if readErr != nil {
			return census, nil, fmt.Errorf("контракт %s не прочитан: %w", slash, readErr)
		}
		census.contractsOwn++

		for _, span := range protoCommentSpans(string(raw)) {
			census.commentLines++
			for _, ref := range tableRefsIn(span.text, roster) {
				if ref.dotted {
					census.skippedDotted++
					continue
				}
				census.qualified++
				if roster[ref.table][ref.schema] {
					census.matching++
					continue
				}
				findings = append(findings, contractSchemaFinding{
					file: slash, line: span.line, named: ref.schema, table: ref.table,
					want: strings.Join(sortedKeys(roster[ref.table]), ", "), text: span.text,
				})
			}
		}
	}

	if census.contractsOwn == 0 {
		return census, nil, fmt.Errorf(
			"схема контракта: собственных контрактов не прочитано (корень %q) — "+
				"вердикт беспредметен", root)
	}
	if census.commentLines == 0 {
		return census, nil, fmt.Errorf(
			"схема контракта: обход комментариев пуст при %d прочитанных контрактах — "+
				"распознаватель комментариев не нашёл ни одного, и «ноль находок» означало бы "+
				"«ноль прочитанного»", census.contractsOwn)
	}
	return census, findings, nil
}

// sortedKeys — имена множества в устойчивом порядке: текст находки не должен
// меняться от прогона к прогону.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestContractNamesTheSchemaItsMigrationsDeclare — гейт класса.
func TestContractNamesTheSchemaItsMigrationsDeclare(t *testing.T) {
	tree, err := treecorpus.NewTree(serviceRoot)
	require.NoError(t, err, "состав дерева службы не собран — вердикт беспредметен")

	census, findings, err := scanContractSchemaQualifiers(tree)
	require.NoError(t, err)

	t.Logf("перепись: миграций прочитано %d · схем объявлено %d · таблиц в реестре %d · "+
		"ведомость входов %d записей · контрактов своих %d, входных пропущено %d · "+
		"строк комментария %d · квалифицированных ссылок %d (совпали со схемой миграций %d) · "+
		"пропущено сегментов длинного пути %d",
		census.migrationsRead, census.schemasDeclared, census.tablesDeclared,
		census.ledgerEntries, census.contractsOwn, census.contractsInput,
		census.commentLines, census.qualified, census.matching, census.skippedDotted)

	require.NotZero(t, census.ledgerEntries,
		"ведомость входных контрактов (%s) пуста: полоса собственного контракта не сужена, "+
			"и чужой контракт судился бы нашим реестром таблиц", contractInputLedger)

	require.NotZero(t, census.qualified,
		"положительный контроль пуст: в комментариях контракта нет НИ ОДНОЙ ссылки вида "+
			"<схема>.<таблица> — отрицание ниже выполнилось бы и на дереве, где распознаватель "+
			"ослеп (перенос строки внутри квалификатора, смена формы комментария). "+
			"Если квалификаторы сняты из прозы намеренно (исход 2 задачи kacho#2291) — "+
			"снимайте это утверждение ВМЕСТЕ с его предметом, одним изменением, а не молчанием")

	if len(findings) > 0 {
		shown := findings
		if len(shown) > 20 {
			shown = shown[:20]
		}
		var b strings.Builder
		for _, f := range shown {
			b.WriteString("\n  " + f.String())
		}
		t.Fatalf("контракт называет схему, которой миграции не объявляли, в %d местах "+
			"(показаны первые %d):%s\n\nконтракт ДОСТАВЛЯЕТСЯ вместе с заглушками: у того, кто "+
			"его читает, нашего дерева нет, и опровергнуть координату ему нечем. Производитель "+
			"истины — миграции службы (%s): что объявлено там, то и называет комментарий",
			len(findings), len(shown), b.String(), appliedMigrationDir)
	}
}
