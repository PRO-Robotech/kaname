// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_vendor_schema_history.go — ЗАКОННАЯ ФОРМА СНЯТИЯ для гейта
// `retired_vendor_bindings.go`: строка истории схемы, называющая идентификатор,
// который сама история сняла, — не привязка (задача #323, сборка #483).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ФОРМА НУЖНА
//
// Столбец, названный по снимаемому провайдеру, снимается миграцией, и миграция
// обязана назвать его: `DROP COLUMN` без имени не пишется, предохранитель
// наката спрашивает строки по нему же, откат восстанавливает его под тем же
// именем, проба миграции засевает прежнее состояние и спрашивает столбец после
// отката. Судья, считающий каждую такую строку привязкой, объявлял снятие
// РОСТОМ: миграция снятия столбца `hydra_client_id` (#362) дала ему 29 строк
// в двух новых файлах, и зелёное на сборке #483 было получено подъёмом
// ведомости — ровно той правкой, которую гейт различить не может (граница 4
// его шапки). Эта форма делает подъём ненужным: снятие столбца снижает
// ведомость, в том числе у свода, который столбец завёл.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРАВИЛО
//
// Идентификатор СНЯТ ИСТОРИЕЙ, когда выполнены все четыре условия:
//
//  1. накат (секция до `-- +goose Down`) какой-либо миграции каталога его
//     снимает оператором `DROP COLUMN | CONSTRAINT | INDEX | TABLE` — в
//     исполняемом тексте: снятие в комментарии или в строковом литерале снятием
//     не является;
//  2. после последнего такого снятия тот же накат его не называет;
//  3. ни одна миграция с бóльшей версией его не называет — ни накатом, ни
//     откатом;
//  4. снятий не меньше, чем заведений во всех накатах: имя, заведённое в двух
//     таблицах и снятое в одной, живо.
//
// Строка ФАЙЛА КАТАЛОГА ИСТОРИИ (миграция либо файл Go рядом с ней — проба
// миграции) не привязка, когда КАЖДОЕ имя провайдера в ней — часть снятого
// историей идентификатора. Такие строки считаются переписью отдельно и
// печатаются числом, как проза и комментарии.
//
// Идентификатор — наибольший отрезок `[a-z0-9_]` вокруг вхождения метки, в
// нижнем регистре, без схемы и кавычек: `kaname.t.hydra_client_id` даёт
// `hydra_client_id`, а `t_hydra_client_id_check` — самостоятельное имя со
// своими снятием и заведением.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ФОРМА НЕ ПРОЩАЕТ — И ЧЕМ ЭТО ДОКАЗАНО
//
// Строка вне каталога истории (репозиторий, край, чарт) — привязка, даже если
// называет снятый столбец: код, читающий снятый столбец, — дефект, а не
// история. Вложенный каталог — не история. Путь файла — своя ось, и история её
// не прощает. Метка пути образа идентификатором SQL не бывает и не прощается
// никогда. Каждое из этого и каждое из четырёх условий выше гоняется
// инъекцией: `retired_vendor_schema_history_injection_test.go`.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦЫ, НАЗВАННЫЕ ВСЛУХ
//
// Все они падают в сторону ПОДСЧЁТА — незнакомая форма даёт привязку, видимую
// ростом, а не молчание:
//
//   - снятие столбца без слова `COLUMN` (`ALTER TABLE t DROP x`) не узнаётся;
//   - `DROP TABLE a, b` узнаёт только первое имя;
//   - заведение считается формами `CREATE [UNIQUE] INDEX`, `CONSTRAINT x`
//     (кроме `DROP CONSTRAINT`), `ADD [COLUMN]`, `CREATE TABLE`, `RENAME … TO`
//     и определением столбца в начале строки; лишнее совпадение (строка
//     условия, начатая именем столбца) досчитывает заведения и падает в
//     сторону подсчёта.
//
// ЕДИНСТВЕННАЯ граница, падающая в сторону ПРОЩЕНИЯ: заведение формой, которой
// распознаватель не знает (`CREATE TABLE … AS`, `LIKE`, наследование),
// недосчитывает заведения. После снятия — в том же накате или в поздней
// миграции — её держат условия 2 и 3: такая форма имя называет. ДО снятия —
// то же имя во второй таблице, заведённое незнакомой формой, пережило бы
// снятие в первой, и строки истории о нём прощались бы. Код, читающий такой
// столбец, лежит вне каталога истории и судится как всякая привязка; прощаются
// только строки самой истории.
package check

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// RetiredVendorSchemaHistoryDir — каталог истории схемы службы: её миграции и
// их пробы. Судятся только прямые его файлы.
const RetiredVendorSchemaHistoryDir = "internal/migrations/"

// retiredVendorDropRe — оператор снятия в исполняемом тексте наката. Имя —
// последний сегмент, схема и кавычки отбрасываются.
var retiredVendorDropRe = regexp.MustCompile(
	`(?i)\bDROP\s+(?:COLUMN|CONSTRAINT|INDEX|TABLE)\s+(?:CONCURRENTLY\s+)?(?:IF\s+EXISTS\s+)?` +
		`((?:"?[A-Za-z0-9_]+"?\s*\.\s*)*"?([A-Za-z0-9_]+)"?)`)

// retiredVendorMigration — миграция каталога истории: версия, путь и
// исполняемые тексты (комментарии и содержимое литералов забелены).
type retiredVendorMigration struct {
	version uint64
	rel     string
	up      string // накат
	all     string // файл целиком
}

// retiredVendorSchemaHistory — снятые историей идентификаторы и число
// прочитанных миграций.
type retiredVendorSchemaHistory struct {
	removed    map[string]bool
	migrations int
}

// retiredVendorInHistoryDir — прямой файл каталога истории.
func retiredVendorInHistoryDir(rel string) bool {
	rest, ok := strings.CutPrefix(rel, RetiredVendorSchemaHistoryDir)
	return ok && rest != "" && !strings.Contains(rest, "/")
}

// retiredVendorMigrationVersion — версия миграции по имени файла
// `<цифры>_<имя>.sql`; false — файл не миграция.
func retiredVendorMigrationVersion(rel string) (uint64, bool) {
	if !retiredVendorInHistoryDir(rel) || !strings.HasSuffix(rel, ".sql") {
		return 0, false
	}
	base := strings.TrimPrefix(rel, RetiredVendorSchemaHistoryDir)
	digits, _, ok := strings.Cut(base, "_")
	if !ok || digits == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// retiredVendorExecutable — исполняемый текст SQL: комментарии и содержимое
// строковых литералов забелены, длина и переводы строк сохранены. Разрез
// секций и забеливание — у единственного владельца разбора.
func retiredVendorExecutable(s string) string {
	return migrations.SQLBlankStrings(migrations.SQLBlankComments(s))
}

// buildRetiredVendorSchemaHistory — снятые историей идентификаторы по корпусу.
func buildRetiredVendorSchemaHistory(corpus TreeCorpus) retiredVendorSchemaHistory {
	var ms []retiredVendorMigration
	for _, rel := range corpus.Rels() {
		v, ok := retiredVendorMigrationVersion(rel)
		if !ok {
			continue
		}
		body := corpus[rel]
		ms = append(ms, retiredVendorMigration{
			version: v,
			rel:     rel,
			up:      retiredVendorASCIILower(migrations.SQLBlankStrings(migrations.MigrationUpSection(body))),
			all:     retiredVendorASCIILower(retiredVendorExecutable(body)),
		})
	}
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].version != ms[j].version {
			return ms[i].version < ms[j].version
		}
		return ms[i].rel < ms[j].rel
	})
	h := retiredVendorSchemaHistory{removed: map[string]bool{}, migrations: len(ms)}

	// Условие 1: снятия накатом, с позицией последнего снятия.
	type lastDrop struct {
		migration int
		end       int
	}
	drops := map[string]int{}
	last := map[string]lastDrop{}
	for i, m := range ms {
		for _, loc := range retiredVendorDropRe.FindAllStringSubmatchIndex(m.up, -1) {
			name := m.up[loc[4]:loc[5]]
			if !retiredVendorCarries(name) {
				continue
			}
			drops[name]++
			last[name] = lastDrop{migration: i, end: loc[1]}
		}
	}

	for name, at := range last {
		// Условие 2: после последнего снятия тот же накат имени не называет.
		if retiredVendorNamesIdent(ms[at.migration].up[at.end:], name) {
			continue
		}
		// Условие 3: поздние миграции имени не называют.
		later := false
		for _, m := range ms[at.migration+1:] {
			if retiredVendorNamesIdent(m.all, name) {
				later = true
				break
			}
		}
		if later {
			continue
		}
		// Условие 4: снятий не меньше заведений.
		forms := newRetiredVendorCreationForms(name)
		created := 0
		for _, m := range ms {
			created += forms.count(m.up)
		}
		if drops[name] < created {
			continue
		}
		h.removed[name] = true
	}
	return h
}

// removedSorted — снятые идентификаторы по возрастанию.
func (h retiredVendorSchemaHistory) removedSorted() []string {
	out := make([]string, 0, len(h.removed))
	for name := range h.removed {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// retiredVendorIdentByte — байт идентификатора SQL/Go в нижнем регистре.
func retiredVendorIdentByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

// retiredVendorIdentAt — наибольший отрезок идентификатора, содержащий байт i.
func retiredVendorIdentAt(lower string, i int) string {
	lo, hi := i, i
	for lo > 0 && retiredVendorIdentByte(lower[lo-1]) {
		lo--
	}
	for hi < len(lower) && retiredVendorIdentByte(lower[hi]) {
		hi++
	}
	return lower[lo:hi]
}

// retiredVendorNamesIdent — текст (в нижнем регистре) называет идентификатор
// целиком, а не частью другого имени.
func retiredVendorNamesIdent(lower, name string) bool {
	for off := 0; ; {
		i := strings.Index(lower[off:], name)
		if i < 0 {
			return false
		}
		i += off
		if retiredVendorIdentAt(lower, i) == name {
			return true
		}
		off = i + 1
	}
}

// retiredVendorCreationForms — распознаватели заведения одного
// идентификатора в исполняемом тексте наката (в нижнем регистре). Формы
// перечислены в шапке файла; `CONSTRAINT x` — последним, отдельно: он же
// стоит в `DROP CONSTRAINT x`, и снятие заведением не считается.
type retiredVendorCreationForms struct {
	plain      []*regexp.Regexp
	constraint *regexp.Regexp
}

func newRetiredVendorCreationForms(name string) retiredVendorCreationForms {
	id := `"?` + regexp.QuoteMeta(name) + `"?(?:[^a-z0-9_"]|$)`
	return retiredVendorCreationForms{
		plain: []*regexp.Regexp{
			regexp.MustCompile(`\bcreate\s+(?:unique\s+)?index\s+(?:concurrently\s+)?(?:if\s+not\s+exists\s+)?` + id),
			regexp.MustCompile(`\badd\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?` + id),
			regexp.MustCompile(`\bcreate\s+(?:(?:unlogged|temp|temporary)\s+)?table\s+(?:if\s+not\s+exists\s+)?` +
				`(?:"?[a-z0-9_]+"?\s*\.\s*)?` + id),
			regexp.MustCompile(`\brename\s+(?:(?:column|constraint)\s+)?(?:"?[a-z0-9_]+"?\s+)?to\s+` + id),
			regexp.MustCompile(`(?m)^[ \t]*` + id + `[ \t]*[a-z]`),
		},
		constraint: regexp.MustCompile(`(\bdrop\s+)?\bconstraint\s+(?:if\s+exists\s+)?` + id),
	}
}

// count — заведений в тексте.
func (f retiredVendorCreationForms) count(up string) int {
	n := 0
	for _, re := range f.plain {
		n += len(re.FindAllStringIndex(up, -1))
	}
	for _, m := range f.constraint.FindAllStringSubmatch(up, -1) {
		if m[1] == "" {
			n++
		}
	}
	return n
}

// isHistoryLine — строка файла каталога истории, каждое имя провайдера в
// которой — часть снятого историей идентификатора.
func (h retiredVendorSchemaHistory) isHistoryLine(rel, line string) bool {
	if len(h.removed) == 0 || !retiredVendorInHistoryDir(rel) {
		return false
	}
	lower := retiredVendorASCIILower(line)
	found := false
	for _, m := range RetiredVendorMarks {
		for off := 0; ; {
			i := strings.Index(lower[off:], m)
			if i < 0 {
				break
			}
			i += off
			if !h.removed[retiredVendorIdentAt(lower, i)] {
				return false
			}
			found = true
			off = i + len(m)
		}
	}
	return found
}
