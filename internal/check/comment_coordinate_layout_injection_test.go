// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// comment_coordinate_layout_injection_test.go — доказательство способности гейта
// упасть И смолчать.
//
// Инъекция подаёт НАСТОЯЩИЙ вход — строки, как они лежали на стволе до правки
// (kaname#117): координата приёмки и координата инструмента с приставкой
// каталога платформы. Законные близнецы — те формы, которые после переезда
// остались верными и обязаны остаться.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// layoutDefectSrc — дословно со ствола: приставка перед координатой, которая
// лежит в ЭТОМ дереве.
const layoutDefectSrc = `package modulecatalog

// Приёмка ` + "`services/iam/docs/engineering/acceptance/plan-confirms-what-apply-withdraws.md`" + `,
// страж списочных методов (` + "`services/iam/tools/auditlistfilter`" + `).
func apply() {}
`

// layoutLegalSrc — законные близнецы, каждый своей осью:
//
//	(а) приставка БЕЗ хвоста — указатель области в ЧУЖОМ дереве;
//	(б) приставка БЕЗ хвоста — проза о самом переезде;
//	(в) хвост-многоточие — форма записи класса путей, а не координата;
//	(г) хвост, которого в дереве нет, — другой предмет;
//	(д) координата БЕЗ приставки — то, чем починка и выглядит.
const layoutLegalSrc = `package check

// Предикат: ` + "`git grep -l Foo -- services/iam`" + ` — область в дереве платформы.
// Изменилось: путь без префикса ` + "`services/iam/`" + ` — в kaname код службы и есть корень.
// Класс путей: ` + "`services/iam/internal/…`" + ` целиком.
// Снятое: ` + "`services/iam/internal/testsupport/fgatest`" + ` — его здесь нет.
// Починенное: ` + "`docs/engineering/acceptance/plan-confirms-what-apply-withdraws.md`" + `.
func check() {}
`

// layoutStringLiteralSrc — законный близнец ОСОБОГО рода: та же приставка в
// СТРОКОВОМ ЛИТЕРАЛЕ. Это действующая форма — `treeposture` резолвит координату
// платформы в обеих посадках, — и гейт обязан её не видеть, иначе он потребовал
// бы снять работающий механизм.
const layoutStringLiteralSrc = `package scalegrid

const verdictDir = "services/iam/internal/repo/kaname/pg/relverdict"

func dir() string { return verdictDir }
`

// resolvesFixture — резолюция хвоста для инъекции: своё дерево, а не настоящее.
// Иначе инъекция зависела бы от состава репозитория и меняла бы вердикт при
// правке, к ней отношения не имеющей.
func resolvesFixture(known ...string) func(string) bool {
	set := map[string]bool{}
	for _, k := range known {
		set[k] = true
	}
	return func(tail string) bool { return set[tail] }
}

// TestCommentCoordinateGateRedsOnAForeignLayoutAddress — инъекция настоящим
// дефектом.
func TestCommentCoordinateGateRedsOnAForeignLayoutAddress(t *testing.T) {
	const rel = "internal/apps/kaname/modulecatalog/plan.go"
	coords, census, err := check.ScanCommentCoordinates(rel, []byte(layoutDefectSrc))
	if err != nil {
		t.Fatalf("разбор инъекции: %v", err)
	}
	if census.WithTail != 2 {
		t.Fatalf("координат с хвостом прочитано %d из двух: %+v", census.WithTail, census)
	}
	findings := commentCoordFindings(coords, resolvesFixture(
		"docs/engineering/acceptance/plan-confirms-what-apply-withdraws.md",
		"tools/auditlistfilter"))
	if len(findings) != 2 {
		t.Fatalf("координаты чужой раскладки НЕ стали находками: их %d при переписи %+v\n"+
			"Гейт, не краснеющий на дефекте, из которого он выведен, не удерживает ничего",
			len(findings), census)
	}
	for _, f := range findings {
		if !strings.Contains(f, rel) || !strings.Contains(f, check.PlatformLayoutPrefix) {
			t.Errorf("находка не называет координату целиком: %q", f)
		}
	}
}

// TestCommentCoordinateGateStaysSilentOnLegalForms — гейт обязан молчать там,
// где форма законна. Без этого он краснел бы на объяснении собственного предмета.
func TestCommentCoordinateGateStaysSilentOnLegalForms(t *testing.T) {
	coords, census, err := check.ScanCommentCoordinates("internal/check/x.go", []byte(layoutLegalSrc))
	if err != nil {
		t.Fatalf("разбор близнеца: %v", err)
	}
	if census.Mentions < 4 {
		t.Fatalf("упоминаний приставки прочитано %d — близнец проверен ни на чём: %+v",
			census.Mentions, census)
	}
	// Хвост есть только у двух из пяти: многоточие и снятый путь. Обе формы
	// резолюции не проходят, а приставка без хвоста в перечень не попадает вовсе.
	if f := commentCoordFindings(coords, resolvesFixture(
		"docs/engineering/acceptance/plan-confirms-what-apply-withdraws.md")); len(f) != 0 {
		t.Fatalf("законная форма объявлена находкой: %v", f)
	}
}

// TestCommentCoordinateGateIgnoresStringLiterals — координата в строке остаётся
// невидимой: это действующий механизм, а не пережиток.
func TestCommentCoordinateGateIgnoresStringLiterals(t *testing.T) {
	coords, census, err := check.ScanCommentCoordinates("internal/repo/x.go",
		[]byte(layoutStringLiteralSrc))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if census.Mentions != 0 || len(coords) != 0 {
		t.Fatalf("приставка в СТРОКОВОМ литерале прочитана как координата комментария "+
			"(%d упоминаний): гейт потребовал бы снять работающий резолвер обеих "+
			"посадок — %+v", census.Mentions, census)
	}
}

// TestCommentCoordinateWalkExcludesProbesAndGenerated — отбор гейта. Проверяется
// ТОТ ЖЕ предикат, которым судит гейт.
func TestCommentCoordinateWalkExcludesProbesAndGenerated(t *testing.T) {
	if !commentCoordWalkable("internal/apps/kaname/modulecatalog/plan.go") {
		t.Fatalf("отбор гейта не берёт прод-файл — тогда осматривать нечего")
	}
	for _, rel := range []string{
		// фикстура инъекции соседнего гейта: дурная форма там и есть предмет
		"internal/check/recipe_call_coordinate_injection_test.go",
		"pkg/api/kaname/cloud/iam/v1/account.pb.go",
	} {
		if commentCoordWalkable(rel) {
			t.Errorf("отбор гейта берёт %s — предмет там не его", rel)
		}
	}
}
