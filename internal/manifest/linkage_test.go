// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// linkage_test.go — СВЯЗНОСТЬ разобранного манифеста: то, что форма выразить не
// способна (задача #1088, приёмка §5.4 и §5.7, сценарии MOD-MF-13…16 и 23…26).
//
// Форма отвечает на вопрос «так ли написано»; связность — на вопрос «есть ли у
// написанного предмет». Замер приёмки (§2.3): опубликованная схема на всех трёх
// свойствах выдач МОЛЧИТ, а на четвёртом краснеет ложным диагнозом. Значит их
// держит валидатор, и держит он их на разобранной структуре, а не на тексте.
//
// # Каждое отрицание портит РОВНО ОДНО свойство
//
// Инъекция, роняющая не то, доказательством не является (приёмка §9.1, п. 2в).
// Поэтому «субъект не заведён» вносится ДОБАВЛЕНИЕМ второго субъекта, а не
// переименованием единственного: переименование заодно оставило бы группу без
// выдачи и уронило бы вторую проверку — красное пришло бы от соседа.
//
// # Самая важная проба файла — отрицательный контроль MOD-MF-24
//
// Правило `joins` асимметрично ПО ПОСТРОЕНИЮ: вступают в ЧУЖУЮ группу,
// объявленную другим манифестом. Валидатор, написанный единообразно, покраснел
// бы на неиспорченном манифесте — и его красное прочли бы как дефект данных.
// MOD-MF-24 утверждает молчание вместе с доказательством, что молчит не мёртвая
// проверка: то же самое имя группы, поставленное субъектом ВЫДАЧИ, отвергается.
package manifest_test

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// replaceOnce — порча документа ровно в одном месте.
//
// Проба падает, если образец не найден либо встречается дважды: обе беды делают
// инъекцию не тем, чем она объявлена, и обе тихи. Первая оставила бы документ
// неиспорченным (проверка «краснеет» проверяла бы законный вход), вторая
// испортила бы два места вместо одного.
func replaceOnce(t *testing.T, doc, old, replacement string) string {
	t.Helper()
	if n := strings.Count(doc, old); n != 1 {
		t.Fatalf("образец %q встречается в документе %d раз, инъекция требует ровно одного", old, n)
	}
	return strings.Replace(doc, old, replacement, 1)
}

// namesSubject — отказ обязан назвать ПРЕДМЕТ: путь до места и то, чем оно
// негодно. «Связность нарушена» — не отказ, а его отсутствие.
func namesSubject(t *testing.T, err error, kind error, path string, mentions ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("ожидался отказ на пути %q; получен nil", path)
	}
	if !errors.Is(err, kind) {
		t.Errorf("отказ не относится к виду %v: %v", kind, err)
	}
	msg := err.Error()
	if !strings.Contains(msg, path) {
		t.Errorf("отказ не называет места %q: %s", path, msg)
	}
	for _, m := range mentions {
		if !strings.Contains(msg, m) {
			t.Errorf("отказ не называет %q: %s", m, msg)
		}
	}
}

// ── MOD-MF-16 · контроль связности ──────────────────────────────────────────

// TestMODMF16LinkageIsSilentOnTheRealManifestAndNamesTheVolume — положительный
// контроль ВСЕГО файла: неиспорченный раздел `seed` черновика проходит, и
// валидатор называет объём осмотренного.
//
// Без переписи «ноль находок» неотличимо от «ноль прочитанного»: валидатор,
// не заглянувший ни в одну выдачу, молчит ровно так же уверенно, как
// проверивший все.
func TestMODMF16LinkageIsSilentOnTheRealManifestAndNamesTheVolume(t *testing.T) {
	data, err := os.ReadFile("testdata/vpc.seed-fixture.yaml")
	if err != nil {
		t.Fatalf("чтение фикстуры: %v", err)
	}

	m, err := manifest.Load(data)
	if err != nil {
		t.Fatalf("неиспорченный манифест отвергнут валидатором связности: %v", err)
	}

	c := m.Linkage()
	t.Logf("перепись связности: %s", c)

	if c.BindingsRead != 2 {
		t.Errorf("выдач прочитано %d, черновик несёт 2", c.BindingsRead)
	}
	if c.SubjectsResolved != 2 {
		t.Errorf("субъектов разрешено %d, черновик несёт по одному на каждую из двух выдач", c.SubjectsResolved)
	}
	if c.GroupsDeclared != 2 {
		t.Errorf("групп заведено %d, черновик несёт 2", c.GroupsDeclared)
	}
	if c.JoinsRead != 1 {
		t.Errorf("вступлений прочитано %d, черновик несёт 1", c.JoinsRead)
	}
	if c.RoleRefsRead != 2 {
		t.Errorf("ссылок на роль прочитано %d, выдач в черновике 2", c.RoleRefsRead)
	}

	// Перепись обязана печатать ОБЕ величины по каждой оси: одно число скрывает
	// ровно тот случай, ради которого перепись заведена.
	for _, want := range []string{"выдач прочитано 2", "субъектов разрешено 2"} {
		if !strings.Contains(c.String(), want) {
			t.Errorf("перепись не называет %q: %s", want, c)
		}
	}
}

// TestLinkageOfAManifestWithoutSeedIsEmptyAndSilent — модуль, ничего не сеющий,
// законен: проверять нечего, и перепись это говорит нулями, а не молчанием.
func TestLinkageOfAManifestWithoutSeedIsEmptyAndSilent(t *testing.T) {
	m, err := manifest.Load([]byte("apiVersion: iam/v1\nmodule: iam\n"))
	if err != nil {
		t.Fatalf("манифест без посева отвергнут: %v", err)
	}
	c := m.Linkage()
	if c.BindingsRead != 0 || c.GroupsDeclared != 0 || c.JoinsRead != 0 {
		t.Errorf("посева нет, а перепись насчитала: %s", c)
	}
	t.Logf("перепись связности без посева: %s", c)
}

// ── MOD-MF-14 · субъект выдачи заведён ЭТИМ ЖЕ посевом ──────────────────────

// TestMODMF14BindingSubjectMustBeSeededByThisSeed — субъект годной формы,
// которого посев не заводит, отвергается; заведённый — проходит.
//
// Порча — ДОБАВЛЕНИЕ второго субъекта, а не переименование единственного:
// переименование оставило бы группу без выдачи и уронило бы MOD-MF-15, то есть
// красное пришло бы не от проверяемого свойства.
func TestMODMF14BindingSubjectMustBeSeededByThisSeed(t *testing.T) {
	const anchor = "        - {type: group, name: vpc-internal-consumers}\n"

	broken := replaceOnce(t, compactManifest, anchor,
		anchor+"        - {type: serviceAccount, name: kacho-nosuch}\n")
	_, err := manifest.Load([]byte(broken))
	namesSubject(t, err, manifest.ErrSubjectNotSeeded,
		"seed.accessBindings[0].subjects[1]", "kacho-nosuch", "serviceAccounts")
	if err != nil {
		if line := lineOf(t, broken, "kacho-nosuch"); !containsLine(err, line) {
			t.Errorf("отказ не называет строки %d: %v", line, err)
		}
	}

	// Парный положительный: тот же документ, тот же второй субъект — но
	// заведённый посевом.
	ok := replaceOnce(t, compactManifest, anchor,
		anchor+"        - {type: serviceAccount, name: kacho-vpc}\n")
	m, err := manifest.Load([]byte(ok))
	if err != nil {
		t.Fatalf("заведённый посевом субъект отвергнут: %v", err)
	}
	if got := m.Linkage().SubjectsResolved; got != 2 {
		t.Errorf("субъектов разрешено %d, документ несёт 2", got)
	}
}

// TestMODMF14SubjectOutsideSeedableTypesIsRefused — посев модуля заводит
// служебные записи и группы, и только их.
//
// Человек установкой модуля не заводится, поэтому субъект-человек посевом не
// заведён НИ ПРИ КАКОМ входе — это тот же отказ MOD-MF-14, а не второе правило.
// Молча пропустить его нельзя: тогда у проверки появляется вид, для которого
// она не делает ничего, и типовая опечатка уезжает в выдачу.
func TestMODMF14SubjectOutsideSeedableTypesIsRefused(t *testing.T) {
	const anchor = "        - {type: group, name: vpc-internal-consumers}\n"

	for _, tc := range []struct{ name, subject, mention string }{
		{"человек", "{type: user, name: alice}", "user"},
		{"вид вне набора", "{type: robot, name: r2}", "robot"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			broken := replaceOnce(t, compactManifest, anchor, anchor+"        - "+tc.subject+"\n")
			_, err := manifest.Load([]byte(broken))
			namesSubject(t, err, manifest.ErrSubjectNotSeeded,
				"seed.accessBindings[0].subjects[1]", tc.mention)
		})
	}

	// Парный положительный: заведённый посевом вид субъекта проходит.
	ok := replaceOnce(t, compactManifest, anchor,
		anchor+"        - {type: serviceAccount, name: kacho-vpc}\n")
	if _, err := manifest.Load([]byte(ok)); err != nil {
		t.Fatalf("законный вид субъекта отвергнут: %v", err)
	}
}

// ── MOD-MF-15 · заведённая группа обязана быть кому-то выдана ───────────────

// TestMODMF15SeededGroupWithoutAGrantIsRefused — группа без выдачи есть
// объявление без следствия: она заводится посевом, живёт и не даёт ничего.
func TestMODMF15SeededGroupWithoutAGrantIsRefused(t *testing.T) {
	const anchor = "      description: Смежные модули, ходящие в vpc на пути запроса.\n"
	const extraGroup = "    - name: cloud-network-admins\n" +
		"      account: system\n" +
		"      description: Администраторы адресного пространства облака.\n"

	broken := replaceOnce(t, compactManifest, anchor, anchor+extraGroup)
	_, err := manifest.Load([]byte(broken))
	namesSubject(t, err, manifest.ErrGroupNeverGranted,
		"seed.groups[1]", "cloud-network-admins")
	if err != nil {
		if line := lineOf(t, broken, "- name: cloud-network-admins"); !containsLine(err, line) {
			t.Errorf("отказ не называет строки %d: %v", line, err)
		}
	}

	// Парный положительный: та же группа, названная в выдаче, — ошибок нет.
	const grantAnchor = "        - {type: group, name: vpc-internal-consumers}\n"
	ok := replaceOnce(t, broken, grantAnchor,
		grantAnchor+"        - {type: group, name: cloud-network-admins}\n")
	m, err := manifest.Load([]byte(ok))
	if err != nil {
		t.Fatalf("выданная группа отвергнута: %v", err)
	}
	if got := m.Linkage().GroupsDeclared; got != 2 {
		t.Errorf("групп заведено %d, документ несёт 2", got)
	}
}

// ── MOD-MF-23 · служебная запись вступления заведена ЭТИМ посевом ───────────

// TestMODMF23JoinServiceAccountMustBeSeededByThisSeed — вступает СВОЯ запись, и
// адресуется она парой: имя без аккаунта не адресует (уникальность в продукте
// держит `service_accounts_account_name_unique`).
func TestMODMF23JoinServiceAccountMustBeSeededByThisSeed(t *testing.T) {
	t.Run("имени нет в посеве", func(t *testing.T) {
		broken := replaceOnce(t, compactManifest,
			"    - serviceAccount: {account: system, name: kacho-vpc}",
			"    - serviceAccount: {account: system, name: kacho-nosuch}")
		_, err := manifest.Load([]byte(broken))
		namesSubject(t, err, manifest.ErrJoinServiceAccountNotSeeded,
			"seed.joins[0].serviceAccount", "kacho-nosuch", "serviceAccounts")
	})

	t.Run("имя то же, аккаунт чужой", func(t *testing.T) {
		broken := replaceOnce(t, compactManifest,
			"    - serviceAccount: {account: system, name: kacho-vpc}",
			"    - serviceAccount: {account: tenant-1, name: kacho-vpc}")
		_, err := manifest.Load([]byte(broken))
		namesSubject(t, err, manifest.ErrJoinServiceAccountNotSeeded,
			"seed.joins[0].serviceAccount", "tenant-1")
	})

	// Парный положительный: запись из seed.serviceAccounts — ошибок нет.
	m, err := manifest.Load([]byte(compactManifest))
	if err != nil {
		t.Fatalf("вступление своей записи отвергнуто: %v", err)
	}
	if got := m.Linkage().JoinsRead; got != 1 {
		t.Errorf("вступлений прочитано %d, документ несёт 1", got)
	}
}

// ── MOD-MF-24 · ЧУЖАЯ группа вступления не отвергается ──────────────────────

// TestMODMF24ForeignJoinGroupIsNotRefusedAndTheRuleIsAliveElsewhere — самый
// важный отрицательный контроль раздела.
//
// `compactManifest` вступает в группу `module-quota-readers`, которой в
// `seed.groups` НЕТ, и это законно: членство заявляет вступающий, а владелец
// группы своих потребителей не знает и знать не должен. Валидатор, написанный
// единообразно, покраснел бы здесь — на неиспорченном манифесте.
//
// Молчания мало: мёртвая проверка молчит точно так же. Поэтому вторая половина
// пробы ставит ТО ЖЕ имя группы субъектом ВЫДАЧИ и требует отказа — так видно,
// что молчит не отсутствие правила, а его граница.
func TestMODMF24ForeignJoinGroupIsNotRefusedAndTheRuleIsAliveElsewhere(t *testing.T) {
	m, err := manifest.Load([]byte(compactManifest))
	if err != nil {
		t.Fatalf("вступление в чужую группу отвергнуто, хотя объявляет её другой манифест: %v", err)
	}
	if len(m.Seed.Joins) != 1 || m.Seed.Joins[0].Group.Name != "module-quota-readers" {
		t.Fatalf("фикстура и проба разошлись: вступления %+v", m.Seed.Joins)
	}
	// Группа вступления не заведена посевом — иначе утверждение вакуумно.
	for _, g := range m.Seed.Groups {
		if g.Name == m.Seed.Joins[0].Group.Name {
			t.Fatalf("группа вступления %q заведена посевом — проба перестала быть об асимметрии", g.Name)
		}
	}

	// То же имя субъектом выдачи — отвергается. Правило живо, у него просто
	// другая сторона.
	const anchor = "        - {type: group, name: vpc-internal-consumers}\n"
	broken := replaceOnce(t, compactManifest, anchor,
		anchor+"        - {type: group, name: module-quota-readers}\n")
	_, err = manifest.Load([]byte(broken))
	namesSubject(t, err, manifest.ErrSubjectNotSeeded,
		"seed.accessBindings[0].subjects[1]", "module-quota-readers")
}

// ── MOD-MF-25 · вступление без причины ──────────────────────────────────────

// TestMODMF25JoinWithoutAReasonIsRefused — причина обязательна и имеет
// объявленный предел длины.
//
// Членство без причины некому снять: следующий не знает, действует ли ещё
// основание. Предел меряется в ЗНАКАХ, а не в байтах, — иначе кириллическая
// причина проходила бы вдвое более короткой, чем латинская.
func TestMODMF25JoinWithoutAReasonIsRefused(t *testing.T) {
	const reason = "      why: читает пределы квот на пути мутации, перед списанием\n"

	t.Run("ключа why нет", func(t *testing.T) {
		broken := replaceOnce(t, compactManifest, reason, "")
		_, err := manifest.Load([]byte(broken))
		namesSubject(t, err, manifest.ErrJoinReasonMissing, "seed.joins[0]", "`why`")
	})

	t.Run("причина короче предела", func(t *testing.T) {
		broken := replaceOnce(t, compactManifest, reason, "      why: квоты\n")
		_, err := manifest.Load([]byte(broken))
		namesSubject(t, err, manifest.ErrJoinReasonMissing, "seed.joins[0].why", "12")
	})

	t.Run("предел меряется знаками, а не байтами", func(t *testing.T) {
		// Двенадцать кириллических знаков — это 24 байта. Проверка по длине в
		// байтах пропустила бы вдвое более короткую причину, и заметить это
		// нельзя ничем, кроме такого входа.
		short := strings.Repeat("я", 11)
		broken := replaceOnce(t, compactManifest, reason, "      why: "+short+"\n")
		if _, err := manifest.Load([]byte(broken)); err == nil {
			t.Fatalf("причина из 11 знаков (%d байт) принята, объявленный предел — 12 знаков", len(short))
		}
		exact := strings.Repeat("я", 12)
		okDoc := replaceOnce(t, compactManifest, reason, "      why: "+exact+"\n")
		if _, err := manifest.Load([]byte(okDoc)); err != nil {
			t.Fatalf("причина ровно в предел (%d знаков) отвергнута: %v", len([]rune(exact)), err)
		}
	})

	// Парный положительный: то же вступление с причиной — ошибок нет.
	if _, err := manifest.Load([]byte(compactManifest)); err != nil {
		t.Fatalf("вступление с причиной отвергнуто: %v", err)
	}
}

// ── MOD-MF-26 · обе стороны вступления адресуются ПАРОЙ ─────────────────────

// TestMODMF26JoinSidesAreAddressedByAPair — одно имя не адресует ни группу, ни
// запись: уникальность в продукте держат `groups_account_name_unique` и
// `service_accounts_account_name_unique`, то есть ПАРА.
func TestMODMF26JoinSidesAreAddressedByAPair(t *testing.T) {
	for _, tc := range []struct {
		name, old, replacement, path, missing string
	}{
		{
			name:        "у записи нет аккаунта",
			old:         "serviceAccount: {account: system, name: kacho-vpc}",
			replacement: "serviceAccount: {name: kacho-vpc}",
			path:        "seed.joins[0].serviceAccount",
			missing:     "`account`",
		},
		{
			name:        "у записи нет имени",
			old:         "serviceAccount: {account: system, name: kacho-vpc}",
			replacement: "serviceAccount: {account: system}",
			path:        "seed.joins[0].serviceAccount",
			missing:     "`name`",
		},
		{
			name:        "у группы нет аккаунта",
			old:         "group: {account: system, name: module-quota-readers}",
			replacement: "group: {name: module-quota-readers}",
			path:        "seed.joins[0].group",
			missing:     "`account`",
		},
		{
			name:        "у группы нет имени",
			old:         "group: {account: system, name: module-quota-readers}",
			replacement: "group: {account: system}",
			path:        "seed.joins[0].group",
			missing:     "`name`",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			broken := replaceOnce(t, compactManifest, tc.old, tc.replacement)
			_, err := manifest.Load([]byte(broken))
			namesSubject(t, err, manifest.ErrRefNotAPair, tc.path, tc.missing)
		})
	}

	// Сторона, записанная ОДНОЙ СТРОКОЙ, отвергается ступенью раньше — формой:
	// строка на месте отображения не ложится на объявленный тип. Отказ приходит
	// из разбора, называет строку, и до валидатора связности такой вход не
	// доходит вовсе (приёмка §2.7). Утверждается это здесь, а не в файле формы,
	// чтобы граница правила была видна там, где правило написано.
	t.Run("сторона записана одной строкой", func(t *testing.T) {
		broken := replaceOnce(t, compactManifest,
			"serviceAccount: {account: system, name: kacho-vpc}",
			"serviceAccount: kacho-vpc")
		_, err := manifest.Load([]byte(broken))
		if !errors.Is(err, manifest.ErrShape) {
			t.Fatalf("сторона одной строкой: ожидался отказ формы, получено %v", err)
		}
		if len(reportedLines(err)) == 0 {
			t.Errorf("отказ формы не называет строки: %v", err)
		}
	})

	// Парный положительный: обе стороны парами — ошибок нет.
	if _, err := manifest.Load([]byte(compactManifest)); err != nil {
		t.Fatalf("обе стороны парами отвергнуты: %v", err)
	}
}

// ── Все находки, а не первая ────────────────────────────────────────────────

// TestLinkageNamesEveryFaultNotJustTheFirst — валидатор собирает ВСЕ находки.
//
// Назвав первую, он заставил бы автора манифеста чинить их по одной, по кругу
// прогона на каждую; и, что хуже, скрыл бы, сколько их всего.
func TestLinkageNamesEveryFaultNotJustTheFirst(t *testing.T) {
	broken := replaceOnce(t, compactManifest,
		"      why: читает пределы квот на пути мутации, перед списанием\n", "")
	broken = replaceOnce(t, broken,
		"        - {type: group, name: vpc-internal-consumers}\n",
		"        - {type: group, name: vpc-internal-consumers}\n"+
			"        - {type: serviceAccount, name: kacho-nosuch}\n")

	_, err := manifest.Load([]byte(broken))
	if err == nil {
		t.Fatalf("документ с двумя нарушениями принят")
	}
	if !errors.Is(err, manifest.ErrJoinReasonMissing) || !errors.Is(err, manifest.ErrSubjectNotSeeded) {
		t.Errorf("названы не оба вида находок: %v", err)
	}
	for _, want := range []string{"kacho-nosuch", "seed.joins[0]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}
}

// containsLine — назвал ли отказ эту строку документа.
func containsLine(err error, line int) bool {
	for _, got := range reportedLines(err) {
		if got == line {
			return true
		}
	}
	return false
}
