// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// migration_version_monotonic.go — РАЗБОР И ПРЕДИКАТ одного класса: НОВАЯ
// миграция обязана получить номер строго больше каждого уже применённого в
// своём каталоге.
//
// # Почему класс, а не перечень форм
//
// Перечень форм стареет молча: он выписан один раз, каталог меняется, и
// распознаватель, знающий три формы, на четвёртой не находит НИЧЕГО — то есть
// молчит вместо того, чтобы судить. Так уже было в платформе: редакция знала
// четырнадцать и шесть знаков, а всё, названное ЧЕТЫРЬМЯ, было вне наблюдения —
// не нарушением, которое гейт разрешил, а предметом, которого он не видел.
//
// Поэтому здесь ДВА разных предмета и два разных распознавателя:
//
//   - [MigrationVersionOf] читает числовой префикс ЛЮБОЙ ширины. Он отвечает на
//     вопрос «упорядочиваемо ли имя», и ширина возвращается ВМЕСТЕ со значением:
//     по ней отличают метку времени от унаследованного номера, а сравнивать их
//     можно и так — четырнадцать знаков больше четырёх при любом содержании;
//   - [AcceptedMigrationForm] говорит, какая форма ПРИНИМАЕТСЯ у нового файла.
//
// Перечень форм, которые в каталоге ЛЕЖАТ, не выписывается здесь вовсе: его
// выводит обход — [MigrationVersionCensus.Widths]. Смена состава каталога видна
// числом на каждом прогоне, а не правкой этого файла.
//
// # Почему судится ЗНАЧЕНИЕ, а не только форма
//
// Посылка формы — «часы идут вперёд, поэтому метка больше любого лежащего
// номера» — на живом каталоге НЕ ВЫПОЛНЯЕТСЯ: метка, взятая не в UTC,
// оказывается ниже уже лежащей. В этом дереве так вышло ПЯТЬ раз (перепись —
// в пробе гейта). Совпадение двух номеров до секунды ловит уникальность номера;
// немонотонность не ловило ничто.
//
// # Три исхода, и «нет предмета» — исход
//
// Гейт, молчащий потому, что обход ничего не нашёл, неотличим от гейта,
// которому нечего сказать. Поэтому вердикт возвращается ВМЕСТЕ с исходом
// ([MigrationVersionOutcome]) и знаменателем обхода ([MigrationVersionCensus]):
// «находок ноль» здесь никогда не приходит само по себе.

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// migrationVersionAny — числовой префикс имени файла ЛЮБОЙ ширины.
//
// Ширина НЕ закреплена намеренно: иначе унаследованный номер другой ширины
// выпал бы из наблюдения молча — он не стал бы находкой, он перестал бы быть
// предметом.
var migrationVersionAny = regexp.MustCompile(`^(\d+)_`)

// AcceptedMigrationForm — ПРИНИМАЮЩАЯ форма имени новой миграции.
//
// Отличается от [migrationVersionAny] ПРЕДМЕТОМ, а не строгостью: тот читает
// номер любой ширины (чтобы видеть унаследованное), эта говорит, что
// принимается у добавленного.
//
// Объявление формы для ЧЕЛОВЕКА живёт в одном месте —
// `docs/engineering/architecture/migration-version-namespace.md`; здесь стоит
// её машинное представление, и документ на него ссылается, а не повторяет.
func AcceptedMigrationForm() *regexp.Regexp {
	return regexp.MustCompile(`^\d{14}_`)
}

// AcceptedMigrationFormLayout — форма имени словами. Одна строка на всё дерево:
// вторая редакция того же расходится молча.
const AcceptedMigrationFormLayout = "YYYYMMDDHHMMSS_<что_делает>.sql"

// MigrationVersion — номер миграции и ширина его записи.
type MigrationVersion struct {
	// Value — числовое значение номера. Порядок применения — числовой,
	// мигратор берёт его так же.
	Value int64
	// Width — сколько знаков занимает номер. Несущее различие: 14 — метка
	// времени заведения, меньше — унаследованный номер прежней эры.
	Width int
}

// MigrationVersionOf — номер из имени файла.
//
// Второй результат — «имя упорядочиваемо». Файл, у которого номера нет,
// не «нулевой версии»: о его месте в цепочке не известно НИЧЕГО, и подставить
// сюда ноль значило бы выдать незнание за знание.
func MigrationVersionOf(name string) (MigrationVersion, bool) {
	m := migrationVersionAny.FindStringSubmatch(name)
	if m == nil {
		return MigrationVersion{}, false
	}
	v, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return MigrationVersion{}, false
	}
	return MigrationVersion{Value: v, Width: len(m[1])}, true
}

// IsMigrationFile — путь принадлежит дому миграций службы и несёт текст
// миграции.
//
// Файл в том же каталоге, миграцией не являющийся (README, Go, ведомость
// дропов), предметом гейта НЕ является и находкой стать не может — но он
// ВХОДИТ В ЗНАМЕНАТЕЛЬ обхода: «рассмотрено 32 из 96» говорит, что обход видел
// каталог целиком, а не наткнулся на один файл.
func IsMigrationFile(rel string) bool {
	return strings.HasPrefix(rel, MigrationsDirRel+"/") && strings.HasSuffix(rel, ".sql")
}

// MigrationVersionOutcome — ЧТО СЛУЧИЛОСЬ с обходом. Печатается всегда.
type MigrationVersionOutcome string

const (
	// MigrationVersionNoCorpus — обход не дал НИ ОДНОЙ миграции. Это не
	// «нарушений нет»: судить было нечего.
	MigrationVersionNoCorpus MigrationVersionOutcome = "НЕТ ПРЕДМЕТА: обход не дал ни одного файла миграции"
	// MigrationVersionNothingAdded — миграции есть, добавленных относительно
	// ствола нет. Класс говорит о НОВОЙ миграции, и новой здесь не появилось.
	MigrationVersionNothingAdded MigrationVersionOutcome = "НЕТ ПРЕДМЕТА: относительно ствола не добавлено ни одной миграции"
	// MigrationVersionNoPeer — добавленное есть, а сравнивать его не с чем:
	// применённых миграций в каталоге нет. Законное состояние нового домена — и
	// ровно тот случай, ради которого одно число «добавлено N» не годится.
	MigrationVersionNoPeer MigrationVersionOutcome = "НЕТ ПРЕДМЕТА: добавленному не с чем сравниться — применённых миграций в каталоге нет"
	// MigrationVersionJudged — вердикт вынесен: хотя бы одно добавленное имя
	// сопоставлено с каноном формы или со старшей применённой.
	MigrationVersionJudged MigrationVersionOutcome = "ВЕРДИКТ ВЫНЕСЕН"
)

// MigrationVersionCensus — ЗНАМЕНАТЕЛЬ ОБХОДА и его состав.
//
// Величин несколько, и это обязательно: одно число «добавлено N» скрывает
// ровно тот случай, ради которого гейт заведён, — добавленное есть, а
// сравнивать его не с чем.
type MigrationVersionCensus struct {
	// DirFiles — файлов каталога рассмотрено ВСЕГО (знаменатель).
	DirFiles int
	// SQL — из них признано миграциями.
	SQL int
	// Versioned — из миграций те, чьё имя упорядочиваемо.
	Versioned int
	// Widths — ПЕРЕПИСЬ ФОРМ, выведенная обходом: ширина номера → сколько
	// файлов. Перечень форм в коде не выписан: он читается отсюда.
	Widths map[int]int
	// Unordered — миграции, номер которых не разобран. Не молчание и не
	// находка сама по себе: их место в цепочке неизвестно.
	Unordered []string
	// Applied — миграции, уже лежащие в стволе (всё, кроме добавленного).
	Applied int
	// Added — миграции, добавленные относительно ствола.
	Added int
	// Compared — из добавленного то, что БЫЛО сопоставлено со старшей
	// применённой. Отличается от Added ровно на случай «сравнивать не с чем».
	Compared int
	// HighestApplied, HighestValue — старшая применённая каталога.
	HighestApplied string
	HighestValue   int64
}

// Forms — перечень форм, ВЫВЕДЕННЫЙ обходом, в устойчивом порядке.
func (c MigrationVersionCensus) Forms() []string {
	widths := make([]int, 0, len(c.Widths))
	for w := range c.Widths {
		widths = append(widths, w)
	}
	sort.Ints(widths)
	out := make([]string, 0, len(widths))
	for _, w := range widths {
		out = append(out, fmt.Sprintf("номер в %d знак(ов) — %d файл(ов)", w, c.Widths[w]))
	}
	if len(out) == 0 {
		out = append(out, "упорядочиваемых имён обход не нашёл")
	}
	return out
}

// String — перепись одной строкой.
func (c MigrationVersionCensus) String() string {
	top := "применённых с номером нет"
	if c.HighestApplied != "" {
		top = fmt.Sprintf("старшая применённая %s (%d)", c.HighestApplied, c.HighestValue)
	}
	return fmt.Sprintf(
		"рассмотрено файлов каталога %d, из них миграций %d, из них упорядочиваемых %d "+
			"(формы обходом: %s); применённых %d, добавлено %d, сравнено %d; %s",
		c.DirFiles, c.SQL, c.Versioned, strings.Join(c.Forms(), " · "),
		c.Applied, c.Added, c.Compared, top)
}

// MigrationVersionAudit — вердикт вместе с исходом и знаменателем.
//
// Находки отдельно от исхода намеренно: «находок ноль» без исхода неотличимо
// от «обход ничего не принёс», и читатель прогона не обязан догадываться.
type MigrationVersionAudit struct {
	Outcome  MigrationVersionOutcome
	Census   MigrationVersionCensus
	Findings []string
}

// AuditMigrationVersions — предмет гейта, взятый ЧИСТОЙ функцией.
//
// `dirFiles` — ВСЕ пути каталога миграций (знаменатель обхода), `added` — пути,
// добавленные относительно ствола. Применённым считается всё, что в каталоге
// есть и добавленным не является: сравнивать новое с самим собой нечего.
//
// Чистой она вынесена, чтобы инъекция судила ТОТ ЖЕ предикат на синтетическом
// входе, не трогая живое дерево и не заводя своей копии правила.
func AuditMigrationVersions(dirFiles, added []string) MigrationVersionAudit {
	census := MigrationVersionCensus{Widths: map[int]int{}}
	isAdded := make(map[string]bool, len(added))
	for _, rel := range added {
		isAdded[rel] = true
	}

	sqlRels := make([]string, 0, len(dirFiles))
	for _, rel := range dirFiles {
		census.DirFiles++
		if !IsMigrationFile(rel) {
			continue
		}
		census.SQL++
		sqlRels = append(sqlRels, rel)
	}
	sort.Strings(sqlRels)

	// Старшая применённая — ПО КАТАЛОГУ, за вычетом добавленного.
	var haveTop bool
	for _, rel := range sqlRels {
		name := path.Base(rel)
		mv, ok := MigrationVersionOf(name)
		if !ok {
			census.Unordered = append(census.Unordered, rel)
			continue
		}
		census.Versioned++
		census.Widths[mv.Width]++
		if isAdded[rel] {
			continue
		}
		census.Applied++
		if !haveTop || mv.Value > census.HighestValue {
			census.HighestValue, census.HighestApplied, haveTop = mv.Value, name, true
		}
	}

	accepted := AcceptedMigrationForm()
	var findings []string
	for _, rel := range sqlRels {
		if !isAdded[rel] {
			continue
		}
		census.Added++
		name := path.Base(rel)

		mv, ok := MigrationVersionOf(name)
		if !ok {
			findings = append(findings, fmt.Sprintf(
				"%s — номер НЕ РАЗОБРАН: о месте файла в цепочке не известно ничего, "+
					"и упорядочить его нечем. Имя новой миграции — %s",
				rel, AcceptedMigrationFormLayout))
			continue
		}
		if !accepted.MatchString(name) {
			findings = append(findings, fmt.Sprintf(
				"%s — номер %0*d записан %d знак(ами) и меткой времени заведения не является. "+
					"Номер, выведенный не из часов, берётся не по возрастанию и встаёт НИЖЕ "+
					"применённого: мигратор такую версию не применит и уронит старт. "+
					"Имя новой миграции — %s",
				rel, mv.Width, mv.Value, mv.Width, AcceptedMigrationFormLayout))
			continue
		}
		if !haveTop {
			// Сравнивать не с чем by construction — и это названо исходом, а не
			// выдано за проверенное.
			continue
		}
		census.Compared++
		if mv.Value > census.HighestValue {
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"%s — номер %d НЕ БОЛЬШЕ уже применённого %s (%d) в том же каталоге. "+
				"Мигратор такую версию не применит и уронит старт: «found N missing "+
				"migrations before current version»; с приёмом пропущенных она применится "+
				"ПОСЛЕ старшей, и свежая база получит другой порядок — схемы разойдутся "+
				"молча. Метка обязана быть строго больше старшей применённой; часы дают "+
				"её не всегда (метка не в UTC оказывается ниже уже лежащей) — возьмите "+
				"номер на секунду выше старшей и назовите отступление в шапке миграции",
			rel, mv.Value, census.HighestApplied, census.HighestValue))
	}

	switch {
	case census.SQL == 0:
		return MigrationVersionAudit{Outcome: MigrationVersionNoCorpus, Census: census}
	case census.Added == 0:
		return MigrationVersionAudit{Outcome: MigrationVersionNothingAdded, Census: census}
	case census.Compared == 0 && len(findings) == 0:
		return MigrationVersionAudit{Outcome: MigrationVersionNoPeer, Census: census}
	default:
		return MigrationVersionAudit{
			Outcome:  MigrationVersionJudged,
			Census:   census,
			Findings: findings,
		}
	}
}
