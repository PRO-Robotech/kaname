// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// refusal_text_is_fixed_injection_test.go — доказательство, что гейт СПОСОБЕН
// упасть и способен смолчать.
//
// Инъекция подаётся НАСТОЯЩЕЙ формой из дерева: `status.Error(codes.Unavailable,
// iamerr.StripSentinel(err))` — ровно то, что стояло у четырёх переводчиков до
// задачи #2464. Рядом стоит ЗАКОННЫЙ БЛИЗНЕЦ: та же конструкция с текстом,
// взятым у канонического переводчика, и та же форма на СОСЕДНЕЙ полосе, где
// текст адресован вызывающему и обязан доехать.
//
// Каждая подача меняет РОВНО ОДИН факт против контрольной: инъекция, попутно
// нарушающая что-то ещё, доказательством не является — красное пришло бы от
// соседа.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// fixtureHeader — общая шапка синтетического файла. Импорты канонические;
// подача с псевдонимом объявляет свои.
const fixtureHeader = `package fixture

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"example.test/shared"
	iamerr "example.test/errors"
)

var _ = shared.UnavailableMessage
var _ = iamerr.StripSentinel
`

// producerFile — ЧУЖОЙ пакет, объявляющий текст контракта. Стоит отдельным
// файлом, потому что имя разрешается по КОРПУСУ: без него законный близнец
// «текст взят у канонического переводчика» проверить нечем.
const producerFile = `package shared

const UnavailableMessage = "service unavailable"
`

func writeFixture(t *testing.T, body string, extra map[string]string) []string {
	t.Helper()
	dir := t.TempDir()
	paths := []string{}
	write := func(name, content string) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: запись %s: %v", name, err)
		}
		paths = append(paths, p)
	}
	write("producer.go", producerFile)
	write("fixture.go", body)
	for name, content := range extra {
		write(name, content)
	}
	return paths
}

// scan — прогон ЯДРА, того же, что гоняет гейт дерева. Проба, повторяющая
// разбор своей копией, доказывала бы свойство копии.
func scan(t *testing.T, files []string) (check.RefusalTextCensus, []check.RefusalTextFinding) {
	t.Helper()
	census, findings, err := check.ScanFixedRefusalTexts(filepath.Dir(files[0]), files)
	if err != nil {
		t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	return census, findings
}

func TestRefusalTextGateInjection(t *testing.T) {
	cases := []struct {
		name string
		body string
		// wantFinding — ожидается ли находка, и что она обязана назвать.
		wantFinding bool
		wantExpr    string
		// why — что именно утверждает подача. Без него перечень читается как
		// набор совпадений, а не как перечень свойств.
		why string
	}{
		{
			name: "КОНТРОЛЬ: литерал и константа чужого пакета — молчание",
			body: fixtureHeader + `
func a(err error) error { return status.Error(codes.Unavailable, shared.UnavailableMessage) }
func b(err error) error { return status.Error(codes.Internal, "internal error") }
func c(err error) error { return status.Error(codes.Internal, "internal " + "worker " + "error") }
`,
			wantFinding: false,
			why:         "положительный контроль: без него любая находка ниже могла бы прийти от соседа",
		},
		{
			name: "ИНЪЕКЦИЯ: разбор цепочки на признаке недоступности",
			body: fixtureHeader + `
func a(err error) error { return status.Error(codes.Unavailable, shared.UnavailableMessage) }
func d(err error) error { return status.Error(codes.Unavailable, iamerr.StripSentinel(err)) }
`,
			wantFinding: true,
			wantExpr:    "iamerr.StripSentinel(err)",
			why:         "настоящая дофиксовая форма четырёх переводчиков",
		},
		{
			name: "ИНЪЕКЦИЯ: текст полученной ошибки на внутреннем отказе",
			body: fixtureHeader + `
func a(err error) error { return status.Error(codes.Unavailable, shared.UnavailableMessage) }
func d(err error) error { return status.Error(codes.Internal, err.Error()) }
`,
			wantFinding: true,
			wantExpr:    "err.Error()",
			why:         "вторая законная форма эха — та, что живёт на соседних полосах дерева",
		},
		{
			name: "ИНЪЕКЦИЯ: подстановка в формат",
			body: fixtureHeader + `
func a(err error) error { return status.Error(codes.Unavailable, shared.UnavailableMessage) }
func d(err error) error { return status.Errorf(codes.Unavailable, "peer: %v", err) }
`,
			wantFinding: true,
			wantExpr:    `"peer: %v", err`,
			why:         "формат с подстановкой есть вычисление по определению",
		},
		{
			name: "ИНЪЕКЦИЯ: переменная, о которой перечень-запрет не знал бы",
			body: fixtureHeader + `
func a(err error) error { return status.Error(codes.Unavailable, shared.UnavailableMessage) }
func d(err error) error {
	msg := err.Error()
	return status.Error(codes.Unavailable, msg)
}
`,
			wantFinding: true,
			wantExpr:    "msg",
			why: "ГЛАВНАЯ подача: запрет по перечню известных форм эха эту пропустил бы " +
				"молча — ни красным, ни зелёным. Требование фиксированности слепой зоны не имеет",
		},
		{
			name: "ИНЪЕКЦИЯ: псевдоним импорта не выводит форму из-под наблюдения",
			body: `package fixture

import (
	c "google.golang.org/grpc/codes"
	st "google.golang.org/grpc/status"

	iamerr "example.test/errors"
)

var _ = iamerr.StripSentinel

func d(err error) error { return st.Error(c.Unavailable, iamerr.StripSentinel(err)) }
`,
			wantFinding: true,
			wantExpr:    "iamerr.StripSentinel(err)",
			why:         "гейт, знающий только каноническое написание, эту форму не увидел бы",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: та же форма на СОСЕДНЕЙ полосе — молчание",
			body: fixtureHeader + `
func a(err error) error { return status.Error(codes.Unavailable, shared.UnavailableMessage) }
func e(err error) error { return status.Error(codes.NotFound, iamerr.StripSentinel(err)) }
func f(err error) error { return status.Errorf(codes.InvalidArgument, "Illegal argument %s", "x") }
`,
			wantFinding: false,
			why: "текст «Project X not found» производит САМА служба, он адресован вызывающему " +
				"и является контрактом; запрет здесь отобрал бы у отказа его предмет",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: константа СВОЕГО пакета — молчание",
			body: fixtureHeader + `
const localFixed = "authorization backend unavailable"

func a(err error) error { return status.Error(codes.Unavailable, localFixed) }
`,
			wantFinding: false,
			why:         "форма, которой пользуется полоса решателя прав в дереве",
		},
		{
			name: "ИНЪЕКЦИЯ: константа, объявленная НЕ литералом — индекс не врёт",
			body: fixtureHeader + `
var raw = "x"

const localFixed = "ok"

func a(err error) error { return status.Error(codes.Unavailable, shared.UnavailableMessage) }
func g(err error) error { return status.Error(codes.Unavailable, raw) }
`,
			wantFinding: true,
			wantExpr:    "raw",
			why:         "переменная не константа: её значение сменит первое же присваивание",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := writeFixture(t, tc.body, nil)
			census, findings := scan(t, files)
			t.Log(census.String())

			if census.Population == 0 {
				t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: популяция пуста — %s", census.String())
			}
			if tc.wantFinding {
				if len(findings) != 1 {
					t.Fatalf("находок %d, ожидалась ровно 1 (%s)", len(findings), tc.why)
				}
				f := findings[0]
				if !strings.Contains(f.Expr, tc.wantExpr) {
					t.Errorf("находка называет текст %q, ожидалось вхождение %q — "+
						"находка, не называющая ЧТО она нашла, посылает читателя искать не там",
						f.Expr, tc.wantExpr)
				}
				if f.Line == 0 || f.File == "" {
					t.Errorf("находка не называет координату: %+v", f)
				}
				return
			}
			if len(findings) != 0 {
				t.Errorf("гейт краснеет на ЗАКОННОЙ форме (%d находок): %+v — %s",
					len(findings), findings, tc.why)
			}
		})
	}
}

// TestRefusalTextGateEmptyWalkIsNotCleanTree — пустой обход НЕ является чистым
// деревом. Ядро о пустоте не судит (пороги у гейта и у инъекции разные), но
// обязано отдать перепись, по которой вызывающий это увидит.
func TestRefusalTextGateEmptyWalkIsNotCleanTree(t *testing.T) {
	census, findings, err := check.ScanFixedRefusalTexts(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("на пустом обходе найдено %d — обход пуст, находкам взяться неоткуда", len(findings))
	}
	if census.Files != 0 || census.Population != 0 {
		t.Fatalf("перепись пустого обхода непуста: %s", census.String())
	}
	t.Log("пустой обход отличим по переписи: " + census.String())
}

// TestRefusalTextGateSkipsTestFiles — пробы под гейт НЕ подпадают: они
// намеренно строят отказы, которых в проде быть не должно, и красное на них
// было бы находкой о самой проверке.
func TestRefusalTextGateSkipsTestFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "leak_test.go")
	body := fixtureHeader + `
func d(err error) error { return status.Error(codes.Unavailable, iamerr.StripSentinel(err)) }
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	census, findings, err := check.ScanFixedRefusalTexts(dir, []string{p})
	if err != nil {
		t.Fatalf("подача НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if len(findings) != 0 || census.Files != 0 {
		t.Fatalf("проба попала в популяцию: находок %d, %s", len(findings), census.String())
	}
}
