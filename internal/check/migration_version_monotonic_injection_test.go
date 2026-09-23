// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// migration_version_monotonic_injection_test.go — доказательство, что гейт
// СПОСОБЕН покраснеть и СПОСОБЕН смолчать.
//
// Инъекция зовёт ТУ ЖЕ функцию, что и гейт ([check.AuditMigrationVersions]), а
// не свою копию правила: копия расходится с оригиналом молча, и расходится
// именно та, которую не считали.
//
// # Пары ОДНОФАКТНЫЕ, и полярность в факт не входит
//
// У каждой оси рядом с находкой стоит вход той же формы, на котором гейт обязан
// МОЛЧАТЬ, и отличается он РОВНО ОДНИМ фактом:
//
//	значение     · 20260917220500 против 20260917221500 — те же 14 знаков,
//	               разные секунды;
//	форма        · 202609180000000 против 20260918000000 — один лишний знак,
//	               значение у обоих ВЫШЕ применённого, поэтому ось значения
//	               разницу объяснить не может;
//	упорядочен   · имя без числового префикса против того же имени с ним;
//	предмет      · тот же дефектный номер с расширением .sql и с .md;
//	добавленность· тот же дефектный файл, добавленный и уже лежащий (запрет #5).
//
// # Исход «нет предмета» отличается от зелёного ВЫВОДОМ, а не числом находок
//
// У пустого каталога находок ноль и у здорового дерева находок ноль. Поэтому
// последняя проба судит ИСХОД, а не длину перечня: если бы их различало только
// число находок, гейт, потерявший каталог, читался бы как зелёный.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// injAppliedTop — старшая ПРИМЕНЁННАЯ каталога во всех пробах ниже. Одна на
// файл: разные пробы, спорящие о разной базе, сравнивать было бы нечем.
const injAppliedTop = check.MigrationsDirRel + "/20260917221000_access_keys_are_our_record.sql"

// injAppliedBaseline — унаследованный номер прежней эры. Лежит применённым и
// остаётся как есть: правило действует вперёд.
const injAppliedBaseline = check.MigrationsDirRel + "/0001_initial.sql"

// injNotAMigration — файл того же каталога, миграцией не являющийся.
const injNotAMigration = check.MigrationsDirRel + "/README.md"

// injApplied — каталог до правки: две применённые миграции и документ.
func injApplied() []string {
	return []string{injAppliedBaseline, injAppliedTop, injNotAMigration}
}

func TestMigrationMonotonicGate_ValueBelowAppliedIsRed(t *testing.T) {
	t.Parallel()

	const (
		// Отличаются РОВНО ОДНИМ фактом — значением метки. Ширина, каталог,
		// расширение и описательный хвост совпадают дословно.
		below = check.MigrationsDirRel + "/20260917220500_access_key_rows_carry_a_label.sql"
		above = check.MigrationsDirRel + "/20260917221500_access_key_rows_carry_a_label.sql"
	)

	red := check.AuditMigrationVersions(append(injApplied(), below), []string{below})
	if red.Outcome != check.MigrationVersionJudged {
		t.Fatalf("исход %q — вердикта не вынесено там, где предмет есть", red.Outcome)
	}
	if len(red.Findings) != 1 {
		t.Fatalf("находок %d, ждали 1: метка НИЖЕ применённой прошла молча — мигратор "+
			"обнаружил бы её в момент наката, а не в момент правки. Перепись: %s",
			len(red.Findings), red.Census)
	}
	if !strings.Contains(red.Findings[0], below) {
		t.Fatalf("находка не назвала координату: %s", red.Findings[0])
	}
	if red.Census.Compared != 1 {
		t.Fatalf("сравнено %d, ждали 1 — находка вынесена не сравнением", red.Census.Compared)
	}

	green := check.AuditMigrationVersions(append(injApplied(), above), []string{above})
	if green.Outcome != check.MigrationVersionJudged {
		t.Fatalf("законный близнец: исход %q — гейт не судил его вовсе, и его молчание "+
			"сказано ни о чём", green.Outcome)
	}
	if len(green.Findings) != 0 {
		t.Fatalf("законный близнец покраснел (%d находок): %s — гейт красит по факту "+
			"добавления, а не по номеру", len(green.Findings), strings.Join(green.Findings, "; "))
	}
	if green.Census.Compared != 1 {
		t.Fatalf("законный близнец: сравнено %d, ждали 1 — молчание получено потому, "+
			"что сравнения НЕ БЫЛО", green.Census.Compared)
	}
}

func TestMigrationMonotonicGate_FormIsJudgedApartFromValue(t *testing.T) {
	t.Parallel()

	const (
		// Один лишний знак — единственное различие. Значение у ОБОИХ выше
		// применённого, поэтому ось значения разницу объяснить не может.
		wide  = check.MigrationsDirRel + "/202609180000000_access_key_rows_carry_a_label.sql"
		exact = check.MigrationsDirRel + "/20260918000000_access_key_rows_carry_a_label.sql"
	)

	red := check.AuditMigrationVersions(append(injApplied(), wide), []string{wide})
	if len(red.Findings) != 1 || !strings.Contains(red.Findings[0], "меткой времени заведения не является") {
		t.Fatalf("номер в 15 знаков принят: находок %d (%s) — форма имени вне наблюдения, "+
			"и «правило одно» держалось бы только чтением", len(red.Findings),
			strings.Join(red.Findings, "; "))
	}

	green := check.AuditMigrationVersions(append(injApplied(), exact), []string{exact})
	if len(green.Findings) != 0 {
		t.Fatalf("законный близнец покраснел: %s", strings.Join(green.Findings, "; "))
	}
}

func TestMigrationMonotonicGate_UnorderableNameIsRed(t *testing.T) {
	t.Parallel()

	const (
		// Единственное различие — наличие числового префикса.
		bare     = check.MigrationsDirRel + "/access_key_rows_carry_a_label.sql"
		numbered = check.MigrationsDirRel + "/20260918000000_access_key_rows_carry_a_label.sql"
	)

	red := check.AuditMigrationVersions(append(injApplied(), bare), []string{bare})
	if len(red.Findings) != 1 || !strings.Contains(red.Findings[0], "НЕ РАЗОБРАН") {
		t.Fatalf("имя без номера прошло: находок %d (%s) — о месте файла в цепочке не "+
			"известно ничего, и молчание здесь выдаёт незнание за знание",
			len(red.Findings), strings.Join(red.Findings, "; "))
	}

	green := check.AuditMigrationVersions(append(injApplied(), numbered), []string{numbered})
	if len(green.Findings) != 0 {
		t.Fatalf("законный близнец покраснел: %s", strings.Join(green.Findings, "; "))
	}
}

func TestMigrationMonotonicGate_NonMigrationInTheSameDirIsSilentButCounted(t *testing.T) {
	t.Parallel()

	const (
		// Единственное различие — расширение. Номер у обоих дефектный.
		doc = check.MigrationsDirRel + "/0033_access_key_rows_carry_a_label.md"
		mig = check.MigrationsDirRel + "/0033_access_key_rows_carry_a_label.sql"
	)

	silent := check.AuditMigrationVersions(append(injApplied(), doc), []string{doc})
	if len(silent.Findings) != 0 {
		t.Fatalf("файл, миграцией не являющийся, стал находкой: %s — тогда находкой "+
			"станет любой документ каталога", strings.Join(silent.Findings, "; "))
	}
	if silent.Outcome != check.MigrationVersionNothingAdded {
		t.Fatalf("исход %q — ждали «добавленных миграций нет»: добавлен документ, "+
			"а не миграция", silent.Outcome)
	}
	// Он ВИДЕН знаменателем: обход прошёл каталог целиком, а не наткнулся на
	// один файл.
	if silent.Census.DirFiles != 4 || silent.Census.SQL != 2 {
		t.Fatalf("знаменатель: рассмотрено %d, миграций %d — ждали 4 и 2. Файл вне "+
			"предмета обязан входить в знаменатель, иначе «рассмотрено 2 из 2» скроет, "+
			"что каталог больше", silent.Census.DirFiles, silent.Census.SQL)
	}

	red := check.AuditMigrationVersions(append(injApplied(), mig), []string{mig})
	if len(red.Findings) != 1 {
		t.Fatalf("тот же номер с расширением .sql прошёл молча: находок %d — различие "+
			"между документом и миграцией не проведено", len(red.Findings))
	}
}

func TestMigrationMonotonicGate_AppliedDefectIsNotAFinding(t *testing.T) {
	t.Parallel()

	// Единственное различие — добавлен файл или уже лежит. Имя дословно одно.
	const defect = check.MigrationsDirRel + "/20260917220500_access_key_rows_carry_a_label.sql"

	dir := append(injApplied(), defect)

	red := check.AuditMigrationVersions(dir, []string{defect})
	if len(red.Findings) != 1 {
		t.Fatalf("добавленный дефект не найден: находок %d", len(red.Findings))
	}

	// Тот же файл, уже лежащий: применённую миграцию не переименовывают (запрет
	// #5), и требовать её починки значило бы держать ствол красным за прошлое,
	// которого правкой не изменить.
	silent := check.AuditMigrationVersions(dir, nil)
	if len(silent.Findings) != 0 {
		t.Fatalf("применённая миграция стала находкой: %s — ствол краснел бы за прошлое, "+
			"которого правкой не изменить", strings.Join(silent.Findings, "; "))
	}
	if silent.Outcome != check.MigrationVersionNothingAdded {
		t.Fatalf("исход %q — ждали «добавленных нет»", silent.Outcome)
	}
}

// TestMigrationMonotonicGate_NoSubjectIsNotGreen — ИСХОД различает то, чего не
// различает число находок.
//
// У всех четырёх входов ниже перечень находок пуст. Если бы гейт печатал только
// его длину, потерянный каталог читался бы как здоровое дерево.
func TestMigrationMonotonicGate_NoSubjectIsNotGreen(t *testing.T) {
	t.Parallel()

	const fresh = check.MigrationsDirRel + "/20260918000000_access_key_rows_carry_a_label.sql"

	for _, c := range []struct {
		name    string
		dir     []string
		added   []string
		outcome check.MigrationVersionOutcome
		why     string
	}{
		{
			name:    "каталог пуст",
			dir:     nil,
			added:   nil,
			outcome: check.MigrationVersionNoCorpus,
			why:     "обход не дал ни одного файла — судить было нечего",
		},
		{
			name:    "каталог есть, миграций в нём нет",
			dir:     []string{injNotAMigration},
			added:   []string{injNotAMigration},
			outcome: check.MigrationVersionNoCorpus,
			why:     "дом миграций остался, миграции из него ушли",
		},
		{
			name:    "миграции есть, добавленных нет",
			dir:     injApplied(),
			added:   nil,
			outcome: check.MigrationVersionNothingAdded,
			why:     "класс говорит о НОВОЙ миграции, а новой не появилось",
		},
		{
			name:    "добавленное есть, сравнивать не с чем",
			dir:     []string{injNotAMigration, fresh},
			added:   []string{fresh},
			outcome: check.MigrationVersionNoPeer,
			why:     "новый домен без применённых: одно число «добавлено 1» скрыло бы ровно этот случай",
		},
	} {
		got := check.AuditMigrationVersions(c.dir, c.added)
		if len(got.Findings) != 0 {
			t.Fatalf("%s: находок %d — проба построена неверно, различать нечего",
				c.name, len(got.Findings))
		}
		if got.Outcome != c.outcome {
			t.Fatalf("%s: исход %q, ждали %q (%s)", c.name, got.Outcome, c.outcome, c.why)
		}
		if got.Outcome == check.MigrationVersionJudged {
			t.Fatalf("%s: исход прочитан как вынесенный вердикт", c.name)
		}
	}

	// Здоровое дерево: находок столько же — НОЛЬ, — а исход другой.
	green := check.AuditMigrationVersions(append(injApplied(), fresh), []string{fresh})
	if len(green.Findings) != 0 || green.Outcome != check.MigrationVersionJudged {
		t.Fatalf("здоровое дерево: находок %d, исход %q — ждали 0 и вынесенный вердикт",
			len(green.Findings), green.Outcome)
	}
}

// TestMigrationMonotonicGate_FormsAreDerivedByTraversal — перечень форм
// ВЫВОДИТСЯ обходом, а не выписан в коде.
//
// Ось несущая: распознаватель, знающий закрытый перечень форм, на форме вне
// перечня не находит ничего — то есть молчит вместо того, чтобы судить, и его
// молчание неотличимо от согласия.
func TestMigrationMonotonicGate_FormsAreDerivedByTraversal(t *testing.T) {
	t.Parallel()

	const exotic = check.MigrationsDirRel + "/777777_a_width_the_code_never_heard_of.sql"

	got := check.AuditMigrationVersions(append(injApplied(), exotic), nil)
	if got.Census.Widths[6] != 1 {
		t.Fatalf("ширина в 6 знаков не попала в перепись: %v — форма вне наблюдения "+
			"не является ни находкой, ни молчанием, она является невидимостью",
			got.Census.Widths)
	}
	if got.Census.Widths[4] != 1 || got.Census.Widths[14] != 1 {
		t.Fatalf("перепись форм %v — обход не пересчитал каталог", got.Census.Widths)
	}
	forms := strings.Join(got.Census.Forms(), " · ")
	for _, want := range []string{"4 знак", "6 знак", "14 знак"} {
		if !strings.Contains(forms, want) {
			t.Fatalf("перечень форм %q не назвал %q", forms, want)
		}
	}
}
