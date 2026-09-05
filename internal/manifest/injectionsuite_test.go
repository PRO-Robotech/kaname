// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// injectionsuite_test.go — НАБОР ИНЪЕКЦИЙ, исполняемый обычным `go test` без
// единого аргумента (приёмка §9.1, §9.2, §9.3; сценарий MOD-MF-27).
//
// # Что этот набор утверждает, чего не утверждают пробы по сценариям
//
// Пробы MOD-MF-01…26 утверждают КАЖДАЯ СВОЙ отказ дословно: вид ошибки, путь,
// номер строки, текст. Набор утверждает другое — свойство САМОГО НАБОРА: что
// число ИСПОЛНЕННЫХ утверждений равно числу ОБЪЯВЛЕННЫХ, а утверждение, чей
// вход произвести не удалось, попадает в «не выполнилось» ГРОМКО и роняет
// прогон, а не пропадает из счёта.
//
// # Предмет измерен, а не предположен
//
// Питонов набор черновика (kacho-workspace/docs/manifest-dcl), запущенный без
// аргументов, давал «утверждений: 38 · прошло: 0 · провалено: 38»: он копировал
// исходник по пути, которого нет, — имя файла манифеста в дереве другое. Ни одно
// из тридцати восьми утверждений не исполнилось, и это подавалось КРАСНЫМ, то
// есть третья категория выдавалась за вердикт о предмете. Перенесённый как есть,
// набор дал бы ложное красное на первом же прогоне; приёмка (§9.3) поэтому решает
// переписать наборы на Go — тогда они исполняются тем же `go test`, что и
// остальной корпус, и попадают под те же гейты дерева.
//
// Свойство переживает носителя, и держателем ему служит MOD-MF-27, а не
// обещание: обещание без держателя не отличается от невыполненного.
//
// # Почему вход обязан быть ПРОИЗВЕДЁН, а не просто объявлен
//
// Инъекция здесь — замена образца в фикстуре. Образец, переставший встречаться
// (поле переименовали, отступ изменился), делает «испорченный» документ дословно
// равным годному: утверждение «загрузчик краснеет» проверяло бы тогда законный
// вход, а утверждение «законный близнец молчит» — проходило бы даром. Обе беды
// ТИХИ, и обе уже наблюдались в этом корпусе. Поэтому каждая строка объявляет,
// сколько раз её образец обязан встретиться, и расхождение есть НАХОДКА.
package manifest

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

// injection — одно утверждение набора.
//
// Порча описывается ЗАМЕНОЙ ОБРАЗЦА, а не готовым документом: готовый документ
// разошёлся бы с фикстурой молча при первой же её правке, и набор проверял бы
// свою копию вместо предмета.
type injection struct {
	// name — что испорчено либо что законно; попадает в текст находки.
	name string
	// old — образец в фикстуре; пусто означает «фикстура как есть» (контроль).
	old string
	// occurrences — сколько раз образец обязан встретиться. Ноль читается как
	// один: инъекция портит РОВНО ОДНО место, и это умолчание, а не догадка.
	occurrences int
	// replacement — чем образец заменяется.
	replacement string
	// wantErr — вид ожидаемого отказа; nil означает, что загрузчик обязан
	// МОЛЧАТЬ (законный близнец).
	wantErr error
	// mustNotBe — вид отказа, которого на этом входе быть НЕ должно.
	//
	// Нужен там, где законный близнец не молчит целиком, а лишь перестаёт
	// задевать проверяемое свойство: ключ, взятый в кавычки, ключом-нестрокой
	// быть перестаёт, но остаётся полем, которого форма не знает. Утверждать
	// тут «отказа нет» значило бы утверждать неправду.
	mustNotBe error
	// needle — что обязан назвать текст отказа: координата либо предмет.
	// «Связность нарушена» — не отказ, а его отсутствие.
	needle string
}

// injectionRun — исход прогона набора: перепись плюс два РАЗНЫХ перечня.
//
// «Не выполнилось» и «исполнилось и не сошлось» разведены намеренно: первое
// говорит о наборе, второе — о предмете, и смешать их значит выдать третью
// категорию за вердикт. Ровно это и делал набор черновика.
type injectionRun struct {
	Declared       int
	InputsProduced int
	Executed       int
	NotRun         []string
	Failures       []string
}

// executeInjections исполняет набор над фикстурой и возвращает исход.
//
// Функция НЕ трогает *testing.T намеренно: только так способность самого набора
// покраснеть доказывается на синтетике, не роняя прогон
// (`testing.md` §«Гейт на класс», п. 2).
func executeInjections(fixture string, set []injection) injectionRun {
	run := injectionRun{Declared: len(set)}

	for _, in := range set {
		doc := fixture
		if in.old != "" {
			want := in.occurrences
			if want == 0 {
				want = 1
			}
			if got := strings.Count(fixture, in.old); got != want {
				run.NotRun = append(run.NotRun, in.name+
					": вход НЕ ПРОИЗВЕДЁН — образец "+quote(in.old)+" встречается "+
					strconv.Itoa(got)+" раз при объявленных "+strconv.Itoa(want)+
					"; испорченный документ равен годному, и утверждение проверяло бы не то, что объявляет")
				continue
			}
			doc = strings.Replace(fixture, in.old, in.replacement, 1)
			if doc == fixture {
				run.NotRun = append(run.NotRun, in.name+
					": вход НЕ ПРОИЗВЕДЁН — замена ничего не изменила в документе")
				continue
			}
		}
		run.InputsProduced++

		_, err := Load([]byte(doc))
		run.Executed++

		switch {
		case in.wantErr == nil && err != nil:
			run.Failures = append(run.Failures, in.name+
				": законный близнец обязан пройти, получен отказ: "+err.Error())
		case in.wantErr != nil && err == nil:
			run.Failures = append(run.Failures, in.name+
				": ожидался отказ вида "+in.wantErr.Error()+", загрузчик промолчал")
		case in.wantErr != nil && !errors.Is(err, in.wantErr):
			run.Failures = append(run.Failures, in.name+
				": отказ не того вида; ожидался "+in.wantErr.Error()+", получен: "+err.Error())
		}
		if in.mustNotBe != nil && err != nil && errors.Is(err, in.mustNotBe) {
			run.Failures = append(run.Failures, in.name+
				": отказ вида "+in.mustNotBe.Error()+" на этом входе быть НЕ должен: "+err.Error())
		}
		if in.needle != "" {
			if err == nil {
				run.Failures = append(run.Failures, in.name+
					": отказ обязан назвать "+quote(in.needle)+", но отказа нет вовсе")
			} else if !strings.Contains(err.Error(), in.needle) {
				run.Failures = append(run.Failures, in.name+
					": отказ не называет "+quote(in.needle)+": "+err.Error())
			}
		}
	}
	return run
}

func quote(s string) string { return "«" + strings.TrimSpace(s) + "»" }

// resourcesSection / resourceEntry — раздел `resources` с одним ресурсом и
// приписка к нему второго.
//
// Собираются функцией, а не константой: у оси типа пять утверждений, и каждое
// отличается от соседа РОВНО ОДНИМ фактом — именем ресурса либо именем типа.
// Пять выписанных документов разошлись бы между собой в чём-нибудь ещё, и
// красное перестало бы говорить, который факт его дал.
func resourcesSection(name, objectType string) string {
	return "\nresources:\n" + resourceEntry(name, objectType)
}

func resourceEntry(name, objectType string) string {
	return "  - name: " + name + "\n" +
		"    objectType: " + objectType + "\n" +
		"    parents: [project]\n" +
		"    producer: derived\n" +
		"    verbs: [get]\n"
}

// nonStringKeyInjection — ключ-нестрока, вписанный первым ключом раздела `seed`.
//
// Место выбрано не случайно: тип ключа судится ДО приведения к типизированной
// цели, поэтому отказ приходит именно от него, а не от неизвестного поля.
func nonStringKeyInjection(name, literal string, quoted bool) injection {
	key := literal
	want := ErrNonStringKey
	var notBe error
	if quoted {
		key = `"` + literal + `"`
		// Взятый в кавычки, ключ становится строкой и проверку типа ключа
		// проходит; полем объявленной формы он при этом не становится, и отказ
		// приходит от РАЗБОРА, а не от проверки типа. Утверждать здесь «отказа
		// нет» значило бы утверждать неправду.
		want = ErrShape
		notBe = ErrNonStringKey
	}
	needle := literal
	if quoted {
		needle = ""
	}
	return injection{
		name:        name,
		old:         "\nseed:\n",
		replacement: "\nseed:\n  " + key + ": x\n",
		wantErr:     want,
		mustNotBe:   notBe,
		needle:      needle,
	}
}

// rolesSectionOnlyFirst — раздел `roles`, объявляющий ТОЛЬКО первую из двух
// ролей фикстуры: вторая выдача повисает на необъявленной.
//
// Раздел вносится ИНЪЕКЦИЕЙ, а не дописывается к фикстуре: у оси `module`
// образец `module: vpc` обязан встречаться в документе ровно один раз, а всякое
// правило выдачи называет свой модуль. Дописав раздел к фикстуре, набор отнял бы
// вход у двух чужих утверждений — и сказал бы об этом третьей категорией, а не
// вердиктом.
//
// До #1778 раздел вносить было НЕЛЬЗЯ вовсе: он отвергался разбором, и перечень
// ролей подавался валидатору полем набора. Послабление истекло вместе с
// описанием раздела; поле снято.
const rolesSectionOnlyFirst = `
roles:
  - id: vpc.internal_consumer
    description: Ходит в vpc на пути запроса — аллокация адресов и ссылки.
    tier: {tierType: iam.project, tierId: prj000000000000000}
    rules:
      - {module: vpc, resources: [address], classes: [get, list]}
`

// manifestInjections — набор целиком. Оси — из §9.2 приёмки; у каждой РЕД-строки
// в наборе есть законный близнец либо контроль неиспорченной фикстуры.
func manifestInjections() []injection {
	return []injection{
		// ── контроль: ничего не испорчено ──────────────────────────────────
		{name: "контроль: неиспорченная фикстура", wantErr: nil},

		// ── неизвестный ключ ───────────────────────────────────────────────
		{
			name: "неизвестный ключ верхнего уровня", old: "\nseed:\n",
			replacement: "\nseedz:\n", wantErr: ErrShape, needle: "seedz",
		},
		{
			name: "неизвестный ключ на глубине", old: "      roleId: vpc.internal_consumer",
			replacement: "      rolelD: vpc.internal_consumer", wantErr: ErrShape, needle: "rolelD",
		},

		// ── оболочка ───────────────────────────────────────────────────────
		{
			name: "версия оболочки вне поддерживаемых", old: "apiVersion: iam/v1",
			replacement: "apiVersion: iam/v2", wantErr: ErrUnsupportedAPIVersion, needle: "iam/v1",
		},
		// Ось «имя модуля» переписана вместе со своим предметом: набор
		// РАЗОМКНУТ (moduleset.go), и отказ по канону образа невыразим. Судится
		// теперь ФОРМА имени, а два законных близнеца разводят два разных
		// утверждения — «другое имя ИЗ таблицы образа» и «имя ВНЕ неё».
		{
			name: "имя модуля не той формы", old: "module: vpc",
			replacement: "module: Vpc", wantErr: ErrMalformedModule, needle: "Vpc",
		},
		{
			name: "законный близнец: другой модуль ИЗ порождённой таблицы", old: "module: vpc",
			replacement: "module: loadbalancer", wantErr: nil,
		},
		{
			name: "законный близнец: модуль ВНЕ порождённой таблицы", old: "module: vpc",
			replacement: "module: acme", wantErr: nil,
		},

		// ── ТИП ОБЪЕКТА: форма, владение, столкновение (#2015) ─────────────
		//
		// Ось заведена вместе с размыканием таблицы типов. У неё ТРИ отрицания
		// и ДВА законных близнеца, и близнецы несущие: без первого «отказ есть»
		// означало бы «загрузчик отвергает всякий тип, которого нет в образе» —
		// то есть снятый предмет; без второго — «отвергает всякий тип образа».
		//
		// Раздел вносится ИНЪЕКЦИЕЙ, а не дописывается к фикстуре: фикстура
		// раздела `resources` не несёт, и дописав его, набор отнял бы вход у
		// самих этих утверждений.
		{
			name: "законный близнец: НОВЫЙ тип модуля принимается", old: "\nseed:\n",
			replacement: resourcesSection("widget", "vpc_widget") + "\nseed:\n", wantErr: nil,
		},
		{
			name: "законный близнец: тип ОБРАЗА у ЕГО ЖЕ строки", old: "\nseed:\n",
			replacement: resourcesSection("network", "vpc_network") + "\nseed:\n", wantErr: nil,
		},
		{
			name: "имя типа не той формы", old: "\nseed:\n",
			replacement: resourcesSection("widget", "vpc-widget") + "\nseed:\n",
			wantErr:     ErrObjectTypeMalformed, needle: "vpc-widget",
		},
		{
			name: "тип ОБРАЗА присвоен ЧУЖОЙ строке", old: "\nseed:\n",
			replacement: resourcesSection("widget", "vpc_network") + "\nseed:\n",
			wantErr:     ErrObjectTypeRedefinesImage, needle: "vpc.network",
		},
		{
			name: "один тип объявлен ДВУМЯ ресурсами документа", old: "\nseed:\n",
			replacement: resourcesSection("widget", "vpc_widget") +
				resourceEntry("gadget", "vpc_widget") + "\nseed:\n",
			wantErr: ErrObjectTypeCollision, needle: "resources[1]",
		},

		// ── ключ-нестрока: шесть форм и шесть кавычечных близнецов ──────────
		nonStringKeyInjection("ключ-нестрока: true", "true", false),
		nonStringKeyInjection("ключ-нестрока: false", "false", false),
		nonStringKeyInjection("ключ-нестрока: null", "null", false),
		nonStringKeyInjection("ключ-нестрока: ~", "~", false),
		nonStringKeyInjection("ключ-нестрока: 123", "123", false),
		nonStringKeyInjection("ключ-нестрока: 0x1f", "0x1f", false),
		nonStringKeyInjection("законный близнец в кавычках: true", "true", true),
		nonStringKeyInjection("законный близнец в кавычках: false", "false", true),
		nonStringKeyInjection("законный близнец в кавычках: null", "null", true),
		nonStringKeyInjection("законный близнец в кавычках: ~", "~", true),
		nonStringKeyInjection("законный близнец в кавычках: 123", "123", true),
		nonStringKeyInjection("законный близнец в кавычках: 0x1f", "0x1f", true),

		// ── «не ловушка»: булевоподобные слова YAML 1.1 остаются строками ──
		{
			name: "не ловушка: on/off/yes/no и их регистры — строки, а не булевы",
			old:  "\nseed:\n",
			replacement: "\nseed:\n  on: 1\n  off: 1\n  yes: 1\n  no: 1\n  y: 1\n  n: 1\n" +
				"  On: 1\n  OFF: 1\n  Yes: 1\n  NO: 1\n",
			wantErr: ErrShape, mustNotBe: ErrNonStringKey,
		},

		// ── связность ВЫДАЧ ────────────────────────────────────────────────
		{
			name: "roleId выдачи не объявлен разделом ролей",
			old:  "\nseed:\n", replacement: rolesSectionOnlyFirst + "\nseed:\n",
			wantErr: ErrRoleNotDeclared, needle: "seed.accessBindings[1].roleId",
		},
		{
			name: "законный близнец: обе роли объявлены разделом",
			old:  "\nseed:\n", replacement: declaredRolesSection + "\nseed:\n", wantErr: nil,
		},
		{
			name: "субъект выдачи не заведён этим посевом",
			old:  "        - {type: group, name: vpc-internal-consumers}\n",
			replacement: "        - {type: group, name: vpc-internal-consumers}\n" +
				"        - {type: group, name: vpc-never-seeded}\n",
			wantErr: ErrSubjectNotSeeded, needle: "vpc-never-seeded",
		},
		{
			name: "заведённая группа без единой выдачи", old: "  groups:\n",
			replacement: "  groups:\n    - {name: vpc-orphan-group, account: system, description: заведена без выдачи намеренно}\n",
			wantErr:     ErrGroupNeverGranted, needle: "vpc-orphan-group",
		},

		// ── НЕИЗВЕСТНЫЙ раздел ─────────────────────────────────────────────
		// До #1778 здесь стоял «известный, но ещё не описанный раздел»: три
		// раздела отвергались по имени, называя задачу номером. Разделы описаны,
		// предмет того утверждения исчез — и оно заменено, а не снято: раздел,
		// которого форма не знает, обязан отвергаться и после, называя ключ.
		{
			name: "неизвестный раздел отвергается с именем ключа", old: "\nseed:\n",
			replacement: "\nservices: {}\nseed:\n", wantErr: ErrShape,
			needle: "services",
		},
		{
			name:        "законный близнец: описанный раздел принимается",
			old:         "\nseed:\n",
			replacement: "\ndeprecatedVerbs:\n  read: {class: get, since: \"2026-08-23\", reason: синоним чтения из прежней грамматики, removeWhen: выдач с таким правом ноль}\nseed:\n",
			wantErr:     nil,
		},

		// ── связность ВСТУПЛЕНИЙ ───────────────────────────────────────────
		{
			name:        "вступает запись, которой посев не заводит",
			old:         "serviceAccount: {account: system, name: kacho-vpc}",
			replacement: "serviceAccount: {account: system, name: kacho-vpc-other}",
			wantErr:     ErrJoinServiceAccountNotSeeded, needle: "kacho-vpc-other",
		},
		{
			// САМЫЙ ВАЖНЫЙ отрицательный контроль набора: группа вступления
			// чужая BY CONSTRUCTION, и правило «субъект заведён этим посевом» к
			// ней не применяется. Валидатор, написанный единообразно, покраснел
			// бы здесь — на законном манифесте.
			name:        "законный близнец: ЛЮБАЯ чужая группа вступления не отвергается",
			old:         "name: module-quota-readers}",
			replacement: "name: some-other-foreign-group}", wantErr: nil,
		},
		{
			name: "вступление без причины", old: "      why: читает пределы квот на пути мутации, перед списанием",
			replacement: "      why: коротко", wantErr: ErrJoinReasonMissing, needle: "seed.joins[0].why",
		},
		{
			name:        "законный близнец: причина названа иначе, но названа",
			old:         "      why: читает пределы квот на пути мутации, перед списанием",
			replacement: "      why: списывает пределы квот перед мутацией", wantErr: nil,
		},
		{
			name:        "сторона вступления адресована не парой",
			old:         "group:          {account: system, name: module-quota-readers}",
			replacement: "group:          {name: module-quota-readers}",
			wantErr:     ErrRefNotAPair, needle: "seed.joins[0].group",
		},
	}
}

// TestMODMF27InjectionSuiteExecutesEveryDeclaredAssertion — набор, запущенный
// обычным `go test` без единого аргумента, исполняет ВСЕ свои утверждения.
//
// Число исполненных равно числу объявленных, «не выполнилось» — ноль. Это и
// есть держатель свойства, у которого до сих пор держателя не было.
func TestMODMF27InjectionSuiteExecutesEveryDeclaredAssertion(t *testing.T) {
	set := manifestInjections()
	if len(set) == 0 {
		t.Fatal("набор пуст — обход беспредметен, «ноль находок» получено даром")
	}

	run := executeInjections(string(mustReadFixture(t)), set)

	for _, m := range run.NotRun {
		t.Errorf("НЕ ВЫПОЛНИЛОСЬ: %s", m)
	}
	for _, m := range run.Failures {
		t.Errorf("не сошлось: %s", m)
	}
	if run.Executed != run.Declared {
		t.Errorf("исполнено %d утверждений из %d объявленных: разница есть третья категория, "+
			"и в вердикт она не засчитывается", run.Executed, run.Declared)
	}
	t.Logf("перепись набора: объявлено %d · вход произведён %d · исполнено %d · "+
		"не выполнилось %d · не сошлось %d",
		run.Declared, run.InputsProduced, run.Executed, len(run.NotRun), len(run.Failures))
}

// TestMODMF27SuiteGoesRedWhenAnAssertionLosesItsInput — парный отрицательный:
// изъятие входа у ОДНОГО утверждения делает прогон КРАСНЫМ, а не пустым.
//
// Ровно эта беда была у набора черновика: путь к исходнику не совпал с именем
// файла, и все тридцать восемь утверждений остались неисполненными, отчитавшись
// как проваленные. Доказательство ставится на синтетике: настоящий набор при
// этом не трогается.
func TestMODMF27SuiteGoesRedWhenAnAssertionLosesItsInput(t *testing.T) {
	fixture := string(mustReadFixture(t))

	set := []injection{
		{name: "законное утверждение", old: "module: vpc", replacement: "module: Vpc", wantErr: ErrMalformedModule},
		{name: "утверждение без входа", old: "образца-которого-нет", replacement: "неважно", wantErr: ErrShape},
	}
	run := executeInjections(fixture, set)

	if len(run.NotRun) != 1 {
		t.Fatalf("«не выполнилось» %d при одном изъятом входе: %v", len(run.NotRun), run.NotRun)
	}
	if !strings.Contains(run.NotRun[0], "утверждение без входа") {
		t.Errorf("находка не называет утверждения, чей вход изъят: %q", run.NotRun[0])
	}
	if run.Executed != 1 || run.Declared != 2 {
		t.Errorf("исполнено %d из объявленных %d — прогон обязан быть красным по РАЗНИЦЕ, "+
			"а не пустым", run.Executed, run.Declared)
	}
	if len(run.Failures) != 0 {
		t.Errorf("законное утверждение не сошлось, хотя вход у него есть: %v", run.Failures)
	}

	// Положительный контроль рядом: без него «не выполнилось 1» зеленело бы и на
	// наборе, который не исполняет НИЧЕГО.
	whole := executeInjections(fixture, []injection{set[0]})
	if len(whole.NotRun) != 0 || whole.Executed != 1 {
		t.Errorf("законный близнец: исполнено %d, не выполнилось %d — набор с целым входом "+
			"обязан исполняться весь", whole.Executed, len(whole.NotRun))
	}
}

// TestMODMF27SuiteCoversBothDirectionsOnEveryAxis — набор, состоящий из одних
// отрицаний, доказательством не является: он зеленел бы на загрузчике,
// отвергающем ВСЁ.
func TestMODMF27SuiteCoversBothDirectionsOnEveryAxis(t *testing.T) {
	var red, green int
	for _, in := range manifestInjections() {
		if in.wantErr == nil {
			green++
		} else {
			red++
		}
	}
	if red == 0 || green == 0 {
		t.Fatalf("набор односторонен: краснеющих утверждений %d, молчащих %d", red, green)
	}
	t.Logf("перепись направлений: краснеющих %d · молчащих %d", red, green)
}
