// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Доказательство, что адъюдикатор СПОСОБЕН упасть и способен смолчать.
//
// ИНЪЕКЦИЯ ИДЁТ НА НАСТОЯЩЕМ ВЫВОДЕ buf, А НЕ НА СИНТЕТИЧЕСКОЙ СТРОКЕ.
// Фикстура `testdata/buf-breaking-real.jsonl` снята прогоном `buf breaking
// 1.72.0` по СОБСТВЕННЫМ контрактам этого дерева: в копии `proto/` снят один RPC,
// одно поле и один файл целиком, и вывод сохранён как есть. Синтетическая строка
// доказывала бы, что разбор понимает СЕБЯ, а не buf: форма сообщения — чужая
// предпосылка, и проверять её надо на чужом производителе.
//
// Три класса в одной фикстуре нужны порознь: у снятия ФАЙЛА поля пути нет
// ВОВСЕ — путь приходится восстанавливать из сообщения, — и именно эта ветвь
// молчала бы, проверяй мы только снятие RPC.
package declaredbreak_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/tools/declaredbreak"
)

const realOutput = "testdata/buf-breaking-real.jsonl"

func realFindings(t *testing.T) []declaredbreak.Finding {
	t.Helper()
	f, err := os.Open(realOutput)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: фикстура настоящего вывода buf не прочитана: %v", err)
	}
	defer func() { _ = f.Close() }()
	got, err := declaredbreak.ParseFindings(f)
	if err != nil {
		t.Fatalf("настоящий вывод buf не разобран: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("фикстура пуста — инъекция беспредметна, и её молчание неотличимо от её смерти")
	}
	return got
}

// TestPremise_RealBufOutputCarriesAllThreeShapes — ПРЕДПОСЫЛКА, на которой стоит
// весь разбор. Форма сообщения принадлежит buf; изменится она — эта проба
// покраснеет ПЕРВОЙ и назовёт, что именно перестало быть верным.
func TestPremise_RealBufOutputCarriesAllThreeShapes(t *testing.T) {
	got := realFindings(t)
	byRule := map[string]declaredbreak.Finding{}
	for _, f := range got {
		byRule[f.Type] = f
	}
	t.Logf("настоящий вывод buf: находок %d, правил %d — %v", len(got), len(byRule), keys(byRule))

	for _, rule := range []string{"RPC_NO_DELETE", "FIELD_NO_DELETE", "FILE_NO_DELETE"} {
		f, ok := byRule[rule]
		if !ok {
			t.Fatalf("фикстура не несёт класса %s — ветвь его разбора не проверена ничем", rule)
		}
		if f.Path == "" {
			t.Errorf("%s: путь не восстановлен", rule)
		}
		if f.Symbol() == "" {
			t.Errorf("%s: имя символа не извлечено из сообщения", rule)
		}
	}
	// У снятия файла путь приходит ИЗ СООБЩЕНИЯ, и это надо утверждать отдельно:
	// иначе ветвь восстановления молчит, а проба выглядит зелёной.
	fd := byRule["FILE_NO_DELETE"]
	if fd.Path != fd.Symbol() {
		t.Errorf("у снятия файла путь и символ обязаны совпадать: %q vs %q", fd.Path, fd.Symbol())
	}
	if !strings.HasSuffix(fd.Path, ".proto") {
		t.Errorf("путь снятого файла восстановлен неверно: %q", fd.Path)
	}
}

func keys(m map[string]declaredbreak.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func declFor(f declaredbreak.Finding) declaredbreak.Declaration {
	return declaredbreak.Declaration{
		Rule: f.Type, Path: f.Path, Symbol: f.Symbol(),
		Reason: "полоса снята целиком вместе со своим предметом, потребителей ноль",
		Issue:  "kaname#35",
	}
}

// TestUndeclaredBreakIsRed — ИНЪЕКЦИЯ: разрыв вне перечня.
func TestUndeclaredBreakIsRed(t *testing.T) {
	got := realFindings(t)
	res := declaredbreak.Adjudicate(got, nil)
	if res.Clean() {
		t.Fatal("разрывы вне перечня оставили гейт зелёным")
	}
	if len(res.Undeclared) != len(got) {
		t.Fatalf("не все разрывы названы: %d из %d", len(res.Undeclared), len(got))
	}
	rep := res.Report()
	for _, f := range got {
		if !strings.Contains(rep, f.Coordinate()) {
			t.Errorf("находка не названа координатой: %s", f.Coordinate())
		}
	}
}

// TestDeclaredBreakIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ: каждый разрыв объявлен.
func TestDeclaredBreakIsSilent(t *testing.T) {
	got := realFindings(t)
	var decls []declaredbreak.Declaration
	for _, f := range got {
		decls = append(decls, declFor(f))
	}
	res := declaredbreak.Adjudicate(got, decls)
	if !res.Clean() {
		t.Fatalf("гейт краснеет на полностью объявленных разрывах:\n%s", res.Report())
	}
	if res.Matched != len(got) {
		t.Fatalf("сопоставлено %d из %d", res.Matched, len(got))
	}
}

// TestDeclarationWithoutItsBreakIsRed — ВТОРАЯ ПОЛОВИНА, то есть самоистечение.
//
// Без неё перечень пережил бы свой предмет и остался бы слепой зоной, выданной
// вперёд: разрыв стал историей после вливания, а запись продолжает прощать.
func TestDeclarationWithoutItsBreakIsRed(t *testing.T) {
	got := realFindings(t)
	decls := []declaredbreak.Declaration{declFor(got[0]), {
		Rule: "RPC_NO_DELETE", Path: "kaname/cloud/iam/v1/nothing.proto", Symbol: "GoneLongAgo",
		Reason: "этого разрыва в дереве нет — запись пережила свой предмет",
		Issue:  "kaname#35",
	}}
	res := declaredbreak.Adjudicate(got[:1], decls)
	if res.Clean() {
		t.Fatal("запись, которой нечего прощать, оставила гейт зелёным")
	}
	if len(res.Expired) != 1 {
		t.Fatalf("истёкшая запись не названа: %+v", res.Expired)
	}
	if !strings.Contains(res.Report(), "ЗАПИСИ НЕЧЕГО ПРОЩАТЬ") {
		t.Fatalf("находка не названа словами:\n%s", res.Report())
	}
}

// TestEmptyLedgerOnACleanTreeIsGreen — ПУСТОЙ ПЕРЕЧЕНЬ ЕСТЬ ЦЕЛЬ, А НЕ ПОЛОМКА.
//
// Отказ на достижении цели подталкивал бы держать запись ради зелёного — ровно
// то послабление, которое перечень и призван не допускать.
func TestEmptyLedgerOnACleanTreeIsGreen(t *testing.T) {
	res := declaredbreak.Adjudicate(nil, nil)
	if !res.Clean() {
		t.Fatalf("пустой перечень на дереве без разрывов объявлен находкой:\n%s", res.Report())
	}
	if !strings.Contains(res.Report(), "находок разобрано 0") {
		t.Fatalf("перепись не напечатала объём осмотренного:\n%s", res.Report())
	}
}

// TestDeclarationMustBeSpecific — запись, сопоставимая с чем угодно, не годится.
func TestDeclarationMustBeSpecific(t *testing.T) {
	cases := map[string]declaredbreak.Declaration{
		"без правила": {Path: "a.proto", Symbol: "X", Reason: strings.Repeat("я", 30), Issue: "kaname#35"},
		"без пути":    {Rule: "RPC_NO_DELETE", Symbol: "X", Reason: strings.Repeat("я", 30), Issue: "kaname#35"},
		"без символа": {Rule: "RPC_NO_DELETE", Path: "a.proto", Reason: strings.Repeat("я", 30), Issue: "kaname#35"},
		"причина-заполнитель": {Rule: "RPC_NO_DELETE", Path: "a.proto", Symbol: "X",
			Reason: "так надо", Issue: "kaname#35"},
		"ссылка неразрешима": {Rule: "RPC_NO_DELETE", Path: "a.proto", Symbol: "X",
			Reason: strings.Repeat("я", 30), Issue: "#35"},
		"снятие файла с разными path и symbol": {Rule: "FILE_NO_DELETE", Path: "a.proto",
			Symbol: "X", Reason: strings.Repeat("я", 30), Issue: "kaname#35"},
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			if bad := d.Validate(); len(bad) == 0 {
				t.Fatal("негодная запись принята — объявление прощало бы не то, что называет")
			}
			res := declaredbreak.Adjudicate(nil, []declaredbreak.Declaration{d})
			if res.Clean() {
				t.Fatal("негодная запись не уронила адъюдикацию")
			}
		})
	}
	// ЗАКОННЫЙ БЛИЗНЕЦ: полная запись принимается.
	good := declaredbreak.Declaration{Rule: "RPC_NO_DELETE", Path: "a.proto", Symbol: "X",
		Reason: "глагол снят вместе со своим предметом, потребителей ноль", Issue: "kaname#35"}
	if bad := good.Validate(); len(bad) != 0 {
		t.Fatalf("годная запись отвергнута: %v", bad)
	}
}

// TestUnparsableOutputIsTheThirdCategory — вывод, который не разбирается, есть
// «гейт не сделал своей работы», а НЕ «разрывов нет».
func TestUnparsableOutputIsTheThirdCategory(t *testing.T) {
	for name, in := range map[string]string{
		"проза вместо json": "Failure: failed to fetch the against input\n",
		"битый json":        "{\"type\":\"RPC_NO_DELETE\"\n",
		"нет пути и нет файла в кавычках": `{"type":"FILE_NO_DELETE","message":"something was deleted."}` + "\n",
		"два файла в кавычках": `{"type":"FILE_NO_DELETE","message":"files "` +
			`\"a.proto\" and \"b.proto\" were deleted."}` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := declaredbreak.ParseFindings(strings.NewReader(in)); err == nil {
				t.Fatal("неразбираемый вывод принят за «разрывов нет» — сетевой отказ " +
					"читался бы как чистое дерево")
			}
		})
	}
	// ЗАКОННЫЙ БЛИЗНЕЦ: пустой вывод — это честные «разрывов нет».
	got, err := declaredbreak.ParseFindings(strings.NewReader("\n\n"))
	if err != nil || len(got) != 0 {
		t.Fatalf("пустой вывод обязан означать «разрывов нет»: %v %v", got, err)
	}
}

// TestLedgerOfThisTreeIsEmpty — НОРМАЛЬНОЕ СОСТОЯНИЕ ПЕРЕЧНЯ НА СТВОЛЕ.
//
// Проба НЕ требует пустоты как инварианта: в ветке с объявленным разрывом
// перечень законно непуст. Она требует, чтобы перечень ЧИТАЛСЯ и каждая его
// запись была годной — иначе негодная запись обнаружилась бы только в тот
// прогон, когда у неё появится предмет.
func TestLedgerOfThisTreeIsReadableAndEveryEntryIsValid(t *testing.T) {
	decls, err := declaredbreak.LoadDeclarations("../../proto/declared-breaks.yaml")
	if err != nil {
		t.Fatalf("перечень этого дерева не прочитан: %v", err)
	}
	t.Logf("перечень объявленных разрывов: записей %d", len(decls))
	for i, d := range decls {
		if bad := d.Validate(); len(bad) != 0 {
			t.Errorf("запись %d негодна: %v", i+1, bad)
		}
	}
}

// TestMissingLedgerIsTheThirdCategory — отсутствие файла перечня не есть пустой
// перечень: схлопни их, и удаление файла стало бы способом снять проверку.
func TestMissingLedgerIsTheThirdCategory(t *testing.T) {
	if _, err := declaredbreak.LoadDeclarations("../../proto/no-such-file.yaml"); err == nil {
		t.Fatal("отсутствие перечня принято за пустой перечень")
	}
}
