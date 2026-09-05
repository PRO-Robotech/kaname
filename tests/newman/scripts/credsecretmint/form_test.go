// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// form_test.go — ОБЪЯВЛЕНИЕ ФОРМЫ базового удостоверения, которым пользуется
// сквозная проба, сверяется с тем, что ЧЕКАНИТ ПРОДУКТ (задача #1253).
//
// # Предмет
//
// Сквозной кейс `cases/basic-access-token.py` утверждает форму секрета образцом.
// Пока образец выписан в кейсе руками, он — ВТОРАЯ КОПИЯ предиката, и разойтись
// с продуктом она может молча. Один раз уже разошлась: образец ждал разделитель
// после префикса (`kacho_uoc_…`), тогда как `ids.NewID` чеканит префикс СЛИТНО с
// телом. Совпасть такое утверждение не могло НИ ПРИ КАКОМ ответе — а незаметно
// это было потому, что положительного прохода не существовало вовсе: первым
// отвечал отказ в правах, и до утверждения о форме дело не доходило.
//
// # Что здесь проверяется
//
// Объявление формы живёт в ОДНОМ месте — `credential-secret-form.json`, — и его
// читают обе стороны: генератор кейса подставляет вид и вставляет образец в
// порождаемый скрипт, а эта проба подставляет ОБА вида и сверяет образец с
// ЧЕКАНКОЙ ПРОДУКТА. Не с текстом чужого исходника (это была бы третья копия
// предиката, и она разошлась бы так же), а с ЗНАЧЕНИЕМ, которое `credsecret.Mint`
// производит для идентификатора от `ids.NewID` — теми же вызовами, что стоят на
// пути выдачи (`services/iam/internal/apps/kacho/api/user_tokens/usecases.go`,
// `.../sa_keys/usecases.go`).
//
// Марка, длина хвоста и префиксы видов сверяются с ЭКСПОРТИРОВАННЫМИ величинами
// продукта, поэтому их переименование или снятие роняет СБОРКУ, а не только
// прогон.
//
// # Пара на каждой оси
//
// Одного «чеканное совпадает» мало: образец `^.*$` совпал бы тоже. Поэтому рядом
// стоят подделки, и каждая обязана быть ОТВЕРГНУТА; первая воспроизводит
// исторический дефект дословно. Плюс перекрёстный контроль: образец одного вида
// не принимает секрет другого — иначе «вид назван» было бы пустым словом.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho/pkg/credsecret"
	"github.com/PRO-Robotech/kacho/pkg/ids"
)

// declarationPath — единственное объявление формы. Путь относительный: проба
// живёт рядом с ним в одном дереве, и абсолютный сделал бы её непереносимой
// между рабочими копиями.
const declarationPath = "../../credential-secret-form.json"

// kindPlaceholder — место в образце, куда подставляется префикс вида. Ровно
// одно: два места разъехались бы, а подстановка в одно проверяется здесь.
const kindPlaceholder = "<KIND_PREFIX>"

// formDeclaration — то, что объявление обязано нести. Поля читаются ВСЕ: поле,
// которого никто не читает, разошлось бы с продуктом незамеченным — ровно тот
// класс, ради которого проба и заведена.
type formDeclaration struct {
	Mark              string            `json:"mark"`
	TailLen           int               `json:"tailLen"`
	IDPrefixByKind    map[string]string `json:"idPrefixByKind"`
	JSPatternTemplate string            `json:"jsPatternTemplate"`
	Why               string            `json:"why"`
}

// pattern подставляет вид и отдаёт образец этого вида.
func (d formDeclaration) pattern(kindPrefix string) string {
	return strings.ReplaceAll(d.JSPatternTemplate, kindPlaceholder, kindPrefix)
}

// mintedSamples — сколько НАСТОЯЩИХ значений чеканится на каждый вид. Одного
// мало: тело идентификатора и хвост случайны, и знак, который образец ошибочно
// не принимает, встретится не в первой выборке.
const mintedSamples = 64

func readDeclaration(t *testing.T) formDeclaration {
	t.Helper()
	raw, err := os.ReadFile(declarationPath)
	if err != nil {
		abs, _ := filepath.Abs(declarationPath)
		t.Fatalf("объявление формы базового удостоверения не прочитано (%s): %v\n"+
			"Это ЕДИНСТВЕННОЕ место, где форма объявлена; без него сквозной кейс "+
			"утверждал бы её собственной копией образца — тем, из-за чего задача #1253 "+
			"и заведена", abs, err)
	}
	var decl formDeclaration
	if err := json.Unmarshal(raw, &decl); err != nil {
		t.Fatalf("объявление формы не разбирается как JSON (%s): %v", declarationPath, err)
	}
	return decl
}

// TestDeclaredPartsComeFromTheProduct — марка, длина хвоста и префиксы видов
// объявления равны величинам продукта. Сверка идёт со ЗНАЧЕНИЯМИ, а не с
// текстом: продукт переразмерит — здесь не сойдётся число, снимет — не
// соберётся пакет.
func TestDeclaredPartsComeFromTheProduct(t *testing.T) {
	decl := readDeclaration(t)

	if decl.Mark != credsecret.Mark {
		t.Errorf("марка объявления %q против марки продукта %q (credsecret.Mark)",
			decl.Mark, credsecret.Mark)
	}
	wantTail := credsecret.SecretPartLen + credsecret.ChecksumLen
	if decl.TailLen != wantTail {
		t.Errorf("длина хвоста объявления %d против длины продукта %d "+
			"(credsecret.SecretPartLen %d + ChecksumLen %d)",
			decl.TailLen, wantTail, credsecret.SecretPartLen, credsecret.ChecksumLen)
	}

	// Виды, которые чеканят секрет, — оба, и оба названы константами продукта.
	wantKinds := map[string]string{
		"userToken":         domain.PrefixUserOAuthClient,
		"serviceAccountKey": domain.PrefixSAOAuthClient,
	}
	for kind, want := range wantKinds {
		got, ok := decl.IDPrefixByKind[kind]
		if !ok {
			t.Errorf("объявление не называет вид %q — секрет этого вида остался бы "+
				"вне всякого утверждения о форме", kind)
			continue
		}
		if got != want {
			t.Errorf("вид %q: объявление %q против константы продукта %q", kind, got, want)
		}
	}
	for kind := range decl.IDPrefixByKind {
		if _, ok := wantKinds[kind]; !ok {
			t.Errorf("объявление называет вид %q, которого продукт не чеканит — "+
				"запись, потерявшая предмет", kind)
		}
	}

	// Образец обязан нести ровно одно место подстановки и начинаться маркой:
	// иначе «подставили вид» и «сверили марку» были бы разными утверждениями о
	// разных строках.
	if strings.Count(decl.JSPatternTemplate, kindPlaceholder) != 1 {
		t.Errorf("образец обязан нести РОВНО ОДНО место подстановки %s, найдено %d: %s",
			kindPlaceholder, strings.Count(decl.JSPatternTemplate, kindPlaceholder),
			decl.JSPatternTemplate)
	}
	if !strings.HasPrefix(decl.JSPatternTemplate, "^"+credsecret.Mark) {
		t.Errorf("образец обязан начинаться якорем и маркой продукта %q: %s",
			credsecret.Mark, decl.JSPatternTemplate)
	}
	if !strings.HasSuffix(decl.JSPatternTemplate, "$") {
		t.Errorf("образец обязан кончаться якорем — без него он утверждал бы о ЧАСТИ "+
			"строки, и хвост произвольной длины прошёл бы: %s", decl.JSPatternTemplate)
	}
	if strings.TrimSpace(decl.Why) == "" {
		t.Error("объявление не называет ПРИЧИНУ своего существования: следующий читатель " +
			"снимет непонятный файл, и вторая копия образца вернётся")
	}
	t.Logf("перепись: марка %q · хвост %d знаков · видов %d · образец %d знаков",
		decl.Mark, decl.TailLen, len(decl.IDPrefixByKind), len(decl.JSPatternTemplate))
}

// TestDeclaredPatternAcceptsWhatTheProductMints — ПОЛОЖИТЕЛЬНАЯ сторона.
// Значения чеканит код продукта теми же вызовами, что стоят на пути выдачи;
// образец своего вида обязан принять КАЖДОЕ.
func TestDeclaredPatternAcceptsWhatTheProductMints(t *testing.T) {
	decl := readDeclaration(t)

	checked := 0
	for kind, prefix := range decl.IDPrefixByKind {
		re := mustCompile(t, decl.pattern(prefix))
		for i := 0; i < mintedSamples; i++ {
			credentialID := ids.NewID(prefix)
			secret, hash, err := credsecret.Mint(credentialID)
			if err != nil {
				t.Fatalf("чеканка продукта отказала на %s: %v", credentialID, err)
			}
			if len(hash) == 0 {
				t.Fatalf("чеканка вернула пустой хеш на %s — хранить было бы нечего", credentialID)
			}
			if !re.MatchString(secret) {
				t.Fatalf("образец объявления НЕ ПРИНЯЛ значение, отчеканенное продуктом.\n"+
					"  вид:      %s (%s)\n  образец:  %s\n  значение: %s\n"+
					"Это ровно тот класс, что жил в кейсе до #1253: утверждение о форме, "+
					"которое не совпало бы ни при каком ответе.",
					kind, prefix, decl.pattern(prefix), secret)
			}
			// Обратная сверка на том же значении: принятое образцом обязано
			// разбираться ПРОДУКТОМ и называть ТО ЖЕ удостоверение.
			parsed, err := credsecret.Parse(secret)
			if err != nil {
				t.Fatalf("продукт не разобрал собственное чеканное значение %s: %v", secret, err)
			}
			if parsed.CredentialID != credentialID {
				t.Fatalf("разбор назвал другое удостоверение: %q против %q",
					parsed.CredentialID, credentialID)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("осмотрено НОЛЬ значений — проба не проверила ничего")
	}
	t.Logf("перепись: значений отчеканено и принято образцом %d (видов %d по %d)",
		checked, len(decl.IDPrefixByKind), mintedSamples)
}

// TestDeclaredPatternRejectsForgeries — ОТРИЦАТЕЛЬНАЯ сторона, без которой
// положительная зеленела бы на образце `^.*$`. Первый случай воспроизводит
// исторический дефект дословно.
func TestDeclaredPatternRejectsForgeries(t *testing.T) {
	decl := readDeclaration(t)
	prefix := decl.IDPrefixByKind["userToken"]
	if prefix == "" {
		t.Fatal("объявление не называет вид userToken — предпосылка пробы не выполнена")
	}
	re := mustCompile(t, decl.pattern(prefix))

	credentialID := ids.NewID(prefix)
	good, _, err := credsecret.Mint(credentialID)
	if err != nil {
		t.Fatalf("чеканка продукта отказала: %v", err)
	}
	tail := good[strings.LastIndexByte(good, '_')+1:]
	head := good[:len(good)-len(tail)]

	forgeries := []struct {
		name  string
		value string
	}{
		{
			// ИСТОРИЧЕСКИЙ ДЕФЕКТ: образец ждал разделитель после трёхзначного
			// префикса. `ids.NewID` чеканит префикс СЛИТНО с телом, поэтому
			// такой строки продукт не производит никогда.
			name:  "разделитель после префикса — форма, которой продукт не чеканит",
			value: credsecret.Mark + credentialID[:3] + "_" + credentialID[3:] + "_" + tail,
		},
		{name: "хвост короче объявленного на знак", value: good[:len(good)-1]},
		{name: "хвост длиннее объявленного на знак", value: good + "0"},
		{name: "знак вне крокфордова алфавита в хвосте", value: good[:len(good)-1] + "u"},
		{name: "чужая марка", value: "notkacho_" + good[len(credsecret.Mark):]},
		{name: "марки нет вовсе", value: good[len(credsecret.Mark):]},
		{name: "идентификатора нет — один хвост", value: credsecret.Mark + "_" + tail},
		{name: "пустая строка", value: ""},
		{name: "хвост в верхнем регистре", value: head + strings.ToUpper(tail)},
		{name: "приписка после хвоста", value: good + "&admin"},
		{name: "приписка перед маркой", value: "x" + good},
	}

	for _, f := range forgeries {
		if re.MatchString(f.value) {
			t.Errorf("образец ПРИНЯЛ подделку (%s): %s\nобразец: %s",
				f.name, f.value, decl.pattern(prefix))
		}
	}
	t.Logf("перепись: подделок предъявлено и отвергнуто %d", len(forgeries))
}

// TestPatternOfOneKindRejectsAnother — перекрёстный контроль: образец называет
// ВИД, и это не украшение. Без него «вид назван» было бы пустым словом, а
// секрет служебной учётки прошёл бы там, где кейс утверждает персональный.
func TestPatternOfOneKindRejectsAnother(t *testing.T) {
	decl := readDeclaration(t)
	userPrefix := decl.IDPrefixByKind["userToken"]
	keyPrefix := decl.IDPrefixByKind["serviceAccountKey"]
	if userPrefix == "" || keyPrefix == "" || userPrefix == keyPrefix {
		t.Fatalf("предпосылка не выполнена: виды обязаны быть названы и различаться, "+
			"получено userToken=%q serviceAccountKey=%q", userPrefix, keyPrefix)
	}

	userRe := mustCompile(t, decl.pattern(userPrefix))
	keySecret, _, err := credsecret.Mint(ids.NewID(keyPrefix))
	if err != nil {
		t.Fatalf("чеканка продукта отказала: %v", err)
	}
	if userRe.MatchString(keySecret) {
		t.Errorf("образец вида userToken принял секрет вида serviceAccountKey: %s", keySecret)
	}

	// Положительный контроль к тому же отрицанию: свой вид образец принимает —
	// иначе строка выше зеленела бы и на образце, отвергающем всё.
	userSecret, _, err := credsecret.Mint(ids.NewID(userPrefix))
	if err != nil {
		t.Fatalf("чеканка продукта отказала: %v", err)
	}
	if !userRe.MatchString(userSecret) {
		t.Errorf("образец вида userToken не принял секрет СВОЕГО вида: %s", userSecret)
	}
}

// mustCompile — образец объявления обязан быть годным выражением. Негодный дал
// бы порождаемый скрипт, который не исполняется вовсе: newman пишет такое в
// `testScripts`, а не в упавшие утверждения, то есть кейс перестал бы проверять
// что-либо и продолжал отчитываться зелёным по этой величине.
func mustCompile(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("образец объявления не компилируется: %v\nобразец: %s", err, pattern)
	}
	return re
}
