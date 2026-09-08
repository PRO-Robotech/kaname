// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// scopechaincoverage_gate_test.go — ГЕЙТ Г1: у КАЖДОГО типа, чей структурный
// предок объявлен выводимым, цепь областей имеет звено.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЭТОТ ГЕЙТ ДЕРЖИТ (приёмка R7-4, сценарий 05, §7 Г1)
//
// Свойство дерева, а не одного объекта: класс приходит ТИПОМ. #740 показал его
// на двух типах сразу, #785 — на пяти. Поэтому единица проверки — тип, а
// перечень типов ВЫВОДИТСЯ из `authzcascade.DerivableTypes`. Выписанный рядом
// перечень не сдвинулся бы от нового типа и продолжал бы сторожить прежние —
// то есть молчал бы ровно про тот тип, ради которого его пришлось бы править.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ГЕЙТ ИСПОЛНЯЕТ SQL, А НЕ ЧИТАЕТ ТЕКСТ МИГРАЦИИ
//
// Рассматривались обе формы; выбрана исполняющая, и вот на каком основании.
//
// Текстовый предикат над миграцией проверяет НАЛИЧИЕ СЛОВА, а не работу ветви.
// Он молчит на ветви, которая есть и не даёт ничего: не та колонка, не то имя
// типа, отбор, который не выполняется никогда, — то есть ровно на тех отказах,
// которые «неотличимы от честного» и ради которых под-фаза и делается. Вдобавок
// его пришлось бы учить отличать исполняемый SQL от прозы: собственная шапка
// миграции 785001 называет все пять имён типов десятки раз, поэтому предикат по
// подстроке зеленел бы НА СОБСТВЕННОМ ОБЪЯСНЕНИИ миграции — тот же класс, что
// «гейт нашёл слово в комментарии, объясняющем эту же защиту».
//
// Здесь гейт заводит ПО ОДНОМУ объекту каждого объявленного типа и спрашивает у
// цепи его предка. Тип, у которого гейт не умеет завести объект, — тоже находка
// (`НЕЧЕМ ПОСЕЯТЬ`), а не тихий пропуск: именно так гейт замечает тип, ДОБАВЛЕННЫЙ
// в перечень выводимых после него.
//
// Возражение приёмки «проба на данных зелена ровно до того типа, который в
// фикстуру не попал» здесь снято по построению: фикстура строится ПО ПЕРЕЧНЮ, а
// не наоборот, и тип без фикстуры роняет гейт с именем типа.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ГЕЙТ НЕ ДЕРЖИТ — сказано прямо
//
//	· ПРАВИЛЬНОСТЬ содержания звена (тот ли предок, та ли область) держат
//	  сценарии группы B — `scopechain_iamtypes_integration_test.go`. Гейт
//	  утверждает, что звено ЕСТЬ, а не что оно верное;
//	· ЖИВОСТЬ ДАННЫХ — объект, чья колонка области пуста, предка не получает, и
//	  это законный исход (Р8), а не дефект вывода. Гейт сеет объекты с непустой
//	  областью намеренно: его предмет — ветвь, а не содержимое чужих строк;
//	· ПРОЕКТНУЮ ВЕТВЬ РОЛИ. У роли ветвей две и они взаимоисключающи по
//	  `roles_definition_tier_xor`; гейт сеет аккаунтную. Проектную держит
//	  R7-4-07, где она и является предметом.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/authzcascade"
)

// ─────────────────────────────────────────────────────────────────────────────
// Механизм гейта
// ─────────────────────────────────────────────────────────────────────────────

// r74Coverage — что гейт увидел. Объём осмотренного здесь ПОЛЕ, а не строка
// журнала: «ноль находок» обязано быть отличимо от «ноль прочитанного», а
// отличить их можно только числом.
type r74Coverage struct {
	// Declared — сколько типов объявлено выводимыми.
	Declared int
	// Examined — сколько типов гейт действительно осмотрел (посеял объект и
	// спросил цепь).
	Examined int
	// WithEdge — типы, у которых звено нашлось.
	WithEdge []string
	// NoEdge — НАХОДКА: объект заведён, область у него непуста, а цепь предка не
	// назвала. Это и есть отсутствующая ветвь.
	NoEdge []string
	// NoSeeder — НАХОДКА: тип объявлен выводимым, а завести его объект гейт не
	// умеет. Так гейт замечает тип, добавленный в перечень после него.
	NoSeeder []string
}

// Findings — все находки одним перечнем, каждая С ИМЕНЕМ ТИПА и причиной.
func (c r74Coverage) Findings() []string {
	out := make([]string, 0, len(c.NoEdge)+len(c.NoSeeder))
	for _, ty := range c.NoEdge {
		out = append(out, ty+" — НЕТ ЗВЕНА: объект заведён, область непуста, цепь предка не назвала")
	}
	for _, ty := range c.NoSeeder {
		out = append(out, ty+" — НЕЧЕМ ПОСЕЯТЬ: тип объявлен выводимым, а завести его объект гейт не умеет")
	}
	sort.Strings(out)
	return out
}

// r74Seeder — как завести ОДИН объект типа, у которого область непуста.
// Возвращает идентификатор заведённого объекта.
type r74Seeder func(t *testing.T, ctx context.Context, tx pgx.Tx) string

// r74DerivableSeeders — посев по одному объекту на тип.
//
// Ключ — тип В СЛОВАРЕ МОДЕЛИ, тот же, каким назван `DerivableTypes` и каким
// приходит вопрос о доступе. Перечень здесь НЕ является источником истины: он
// сверяется с объявленным множеством, и расхождение в любую сторону — находка.
var r74DerivableSeeders = map[string]r74Seeder{
	// Аккаунт — предок кластер, ветвь из схемы (740001).
	"account": func(t *testing.T, ctx context.Context, tx pgx.Tx) string {
		r74SeedCluster(t, ctx, tx)
		exec(t, ctx, tx,
			`INSERT INTO kaname.accounts (id, name, owner_user_id)
			 VALUES ('acc-cov', 'coverage-account', 'usr-1')`)
		return "acc-cov"
	},
	// Проект — предок аккаунт, ветвь из ПРОЕКЦИИ ЖУРНАЛА (781001). Указатель
	// кладётся её единственным производителем.
	"project": func(t *testing.T, ctx context.Context, tx pgx.Tx) string {
		exec(t, ctx, tx,
			`INSERT INTO kaname.projects (id, account_id, name)
			 VALUES ('prj-cov', 'acc-1', 'coverage-project')`)
		pointerThroughJournal(t, ctx, tx, "project", "prj-cov", "account", "account:acc-1")
		return "prj-cov"
	},
	"iam_user": func(t *testing.T, ctx context.Context, tx pgx.Tx) string {
		exec(t, ctx, tx,
			`INSERT INTO kaname.users (id, external_id, email, account_id)
			 VALUES ('usr-cov', 'ext-cov', 'cov@kacho.local', 'acc-1')`)
		return "usr-cov"
	},
	"iam_group": func(t *testing.T, ctx context.Context, tx pgx.Tx) string {
		exec(t, ctx, tx,
			`INSERT INTO kaname.groups (id, account_id, name) VALUES ('grp-cov', 'acc-1', 'grp-cov')`)
		return "grp-cov"
	},
	"iam_service_account": func(t *testing.T, ctx context.Context, tx pgx.Tx) string {
		exec(t, ctx, tx,
			`INSERT INTO kaname.service_accounts (id, account_id, name)
			 VALUES ('sac-cov', 'acc-1', 'sac-cov')`)
		return "sac-cov"
	},
	"iam_role": func(t *testing.T, ctx context.Context, tx pgx.Tx) string {
		exec(t, ctx, tx,
			`INSERT INTO kaname.roles (id, name, permissions, rules, account_id)
			 VALUES ('rol-cov', 'coverage_role', '[]'::jsonb,
			         jsonb_build_array(jsonb_build_object(
			             'module',    'test',
			             'resources', jsonb_build_array('*'),
			             'verbs',     jsonb_build_array('get'))),
			         'acc-1')`)
		return "rol-cov"
	},
	"iam_access_binding": func(t *testing.T, ctx context.Context, tx pgx.Tx) string {
		r74SeedInertRole(t, ctx, tx)
		r74SeedBinding(t, ctx, tx, "acb-cov", "usr-1", r74InertRole, "account", "acc-1")
		return "acb-cov"
	},
}

// r74DeclaredDerivable — объявленное множество выводимых типов, В ПОРЯДКЕ,
// пригодном для отчёта. Читается у пакета, а не выписывается.
func r74DeclaredDerivable() []string {
	out := make([]string, 0, len(authzcascade.DerivableTypes))
	for ty := range authzcascade.DerivableTypes {
		out = append(out, ty)
	}
	sort.Strings(out)
	return out
}

// r74ChainCoverage — ядро гейта.
//
// `declared` — перечень типов, о которых гейт обязан высказаться. `suppress` —
// типы, чьи рёбра скрыты от чтения; это ИНЪЕКЦИЯ «у типа нет ветви», и на
// пустом срезе выражение тождественно обычному чтению цепи.
//
// ПРОВЕРКА СОБСТВЕННОЙ ПРЕДПОСЫЛКИ: пустой перечень объявленных — ОТКАЗ, а не
// успех. Гейт, которому нечего осматривать, обязан сказать это вслух, иначе
// «ноль находок» неотличимо от «ноль прочитанного» — и первая же ошибка в том,
// откуда берётся перечень, сделает гейт вечно зелёным.
func r74ChainCoverage(t *testing.T, ctx context.Context, tx pgx.Tx,
	declared []string, suppress []string) (r74Coverage, error) {
	t.Helper()
	c := r74Coverage{Declared: len(declared)}
	if len(declared) == 0 {
		return c, fmt.Errorf("перечень выводимых типов ПУСТ — гейту нечего осматривать, и его " +
			"молчание означало бы «ноль прочитанного», а не «ноль находок»")
	}
	sorted := append([]string(nil), declared...)
	sort.Strings(sorted)
	for _, ty := range sorted {
		seed, ok := r74DerivableSeeders[ty]
		if !ok {
			c.NoSeeder = append(c.NoSeeder, ty)
			continue
		}
		id := seed(t, ctx, tx)
		c.Examined++
		if parents := r74ChainParents(t, ctx, tx, ty, id, suppress); len(parents) == 0 {
			c.NoEdge = append(c.NoEdge, ty)
		} else {
			c.WithEdge = append(c.WithEdge, ty)
		}
	}
	return c, nil
}

// r74ReportCoverage печатает объём осмотренного. Отдельным утверждением, а не
// припиской к вердикту: число, которого не видно, ничего не удостоверяет.
func r74ReportCoverage(t *testing.T, c r74Coverage) {
	t.Helper()
	t.Logf("осмотрено: типов объявлено выводимыми %d, осмотрено %d, звено найдено у %d (%s), "+
		"находок %d", c.Declared, c.Examined, len(c.WithEdge), strings.Join(c.WithEdge, ", "),
		len(c.Findings()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Сам гейт
// ─────────────────────────────────────────────────────────────────────────────

// TestR7_4_05_EveryDerivableTypeHasAChainBranch — R7-4-05, гейт Г1.
//
// # Почему проба красна ДО правки
//
// До 785001 цепь знает три ветви: присланные рёбра, предок проекта из проекции
// журнала, предок аккаунта из схемы. Пяти собственным типам iam она не даёт
// НИЧЕГО, и присланного ребра у них не бывает — их не регистрирует ни один
// производитель. Гейт называет пять находок поимённо, а `account` и `project`
// остаются зелёными: их ветви завела #740/#781. Именно эта форма отчёта —
// «два из семи покрыты, пять названы» — и была предметом под-фазы.
func TestR7_4_05_EveryDerivableTypeHasAChainBranch(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)

		declared := r74DeclaredDerivable()
		c, err := r74ChainCoverage(t, ctx, tx, declared, nil)
		if err != nil {
			t.Fatalf("предпосылка гейта не выполнена: %v", err)
		}
		r74ReportCoverage(t, c)

		if c.Examined != c.Declared {
			t.Errorf("объявлено выводимыми %d типов, осмотрено %d — о разнице гейт не высказался, "+
				"и его молчание о ней неотличимо от отсутствия находок", c.Declared, c.Examined)
		}
		for _, f := range c.Findings() {
			t.Errorf("НАХОДКА: %s. Тип, чей структурный предок объявлен выводимым, обязан иметь "+
				"звено в цепи областей: без него выдача на аккаунт или проект до его объектов не "+
				"доходит, а отказ НЕОТЛИЧИМ ОТ ЧЕСТНОГО (#785, приёмка R7-4 §7 Г1)", f)
		}
	})
}

// TestR7_4_05_CoverageGateRedensWhenABranchIsMissing — ИНЪЕКЦИЯ, сторона «обязан
// покраснеть».
//
// Дефект возвращается на уровне ДАННЫХ, а не текста: рёбра пяти типов скрыты от
// чтения — ровно то, что даёт отсутствующая ветвь. Гейт обязан покраснеть и
// НАЗВАТЬ КАЖДЫЙ тип: находка без координаты заставляет искать её заново.
//
// Рядом — законный близнец В ТОМ ЖЕ ПРОГОНЕ: `account` и `project`, чьи рёбра не
// скрыты, находкой не становятся. Без него инъекция доказывала бы лишь, что
// гейт умеет краснеть, а не что он различает.
func TestR7_4_05_CoverageGateRedensWhenABranchIsMissing(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)

		hidden := []string{"iam_user", "iam_group", "iam_service_account", "iam_role", "iam_access_binding"}
		c, err := r74ChainCoverage(t, ctx, tx, r74DeclaredDerivable(), hidden)
		if err != nil {
			t.Fatalf("предпосылка инъекции не выполнена: %v", err)
		}
		r74ReportCoverage(t, c)

		missing := map[string]bool{}
		for _, ty := range c.NoEdge {
			missing[ty] = true
		}
		for _, ty := range hidden {
			if !missing[ty] {
				t.Errorf("инъекция скрыла рёбра типа %q, а гейт находкой его не назвал — значит "+
					"на настоящем отсутствии ветви он тоже промолчит", ty)
			}
		}
		if len(c.Findings()) != len(hidden) {
			t.Errorf("находок %d при %d скрытых типах: %v — гейт считает не то, что скрыто",
				len(c.Findings()), len(hidden), c.Findings())
		}
		// ЗАКОННЫЙ БЛИЗНЕЦ в том же прогоне.
		for _, ty := range []string{"account", "project"} {
			if missing[ty] {
				t.Errorf("гейт назвал находкой тип %q, чьи рёбра НЕ скрывались — он краснеет на "+
					"форме, а не на существе, и первый же ложный срабат его выключит", ty)
			}
		}
	})
}

// TestR7_4_05_CoverageGateRefusesATypeItCannotExamine — ИНЪЕКЦИЯ «тип добавлен в
// перечень выводимых, а звена нет».
//
// Так выглядит завтрашний день: кто-то объявил выводимым новый тип. Гейт обязан
// покраснеть С ИМЕНЕМ ТИПА, а не пройти молча, «осмотрев» шесть из семи, —
// иначе перечень растёт, а сторожит гейт по-прежнему прежние типы.
//
// `iam_condition` взят не наугад: это НАСТОЯЩИЙ тип модели прав, который сегодня
// выводимым НЕ объявлен и звена в цепи не имеет. Синтетическое имя проверило бы
// разбор строки, а не свойство.
func TestR7_4_05_CoverageGateRefusesATypeItCannotExamine(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)

		const newcomer = "iam_condition"
		if _, declared := authzcascade.DerivableTypes[newcomer]; declared {
			t.Fatalf("тип %q уже объявлен выводимым — предпосылка инъекции исчезла, и она "+
				"проверяла бы обычный путь вместо появления нового типа", newcomer)
		}
		c, err := r74ChainCoverage(t, ctx, tx, append(r74DeclaredDerivable(), newcomer), nil)
		if err != nil {
			t.Fatalf("предпосылка инъекции не выполнена: %v", err)
		}
		r74ReportCoverage(t, c)

		named := false
		for _, f := range c.Findings() {
			if strings.HasPrefix(f, newcomer+" ") {
				named = true
			}
		}
		if !named {
			t.Errorf("тип %q объявлен выводимым, гейт его не осмотрел и находкой не назвал: %v. "+
				"Тогда добавление типа в перечень проходит молча, и гейт сторожит вчерашнее дерево",
				newcomer, c.Findings())
		}
		if c.Examined >= c.Declared {
			t.Errorf("осмотрено %d из %d объявленных — гейт считает неосмотренный тип осмотренным, "+
				"и объём осмотренного перестаёт быть проверкой предпосылки", c.Examined, c.Declared)
		}
	})
}

// TestR7_4_05_CoverageGateStaysSilentOnATypeNotDeclaredDerivable — ИНЪЕКЦИЯ,
// сторона «обязан молчать».
//
// Типов без звена в дереве много и это НОРМА: объект чужого домена получает
// ребро от своего владельца регистрацией, субъектный тип и `iam_fgaproxy` в
// иерархию не входят вовсе. Гейт, считающий это находкой, красен на верной
// реализации — и будет выключен первым же читателем.
//
// Утверждается не «мы такого не пишем», а исход: объект типа, не объявленного
// выводимым, лежит рядом БЕЗ предка, и гейт по объявленному перечню молчит.
func TestR7_4_05_CoverageGateStaysSilentOnATypeNotDeclaredDerivable(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)

		// Объект ЧУЖОГО домена, чью регистрацию владелец не прислал: предка у
		// него нет, и это законно.
		exec(t, ctx, tx,
			`INSERT INTO kaname.resource_mirror (object_type, object_id)
			 VALUES ($1, 'net-nowhere')`, catalogFormOf(t, "vpc_network"))
		for _, ty := range []string{"vpc_network", "iam_fgaproxy", "user"} {
			if _, declared := authzcascade.DerivableTypes[ty]; declared {
				t.Fatalf("тип %q объявлен выводимым — он не годится в законные близнецы, и "+
					"проба утверждала бы обратное тому, что заявляет", ty)
			}
		}
		if parents := r74ChainParents(t, ctx, tx, "vpc_network", "net-nowhere", nil); len(parents) != 0 {
			t.Fatalf("у незарегистрированного объекта чужого домена нашёлся предок %v — предмет "+
				"близнеца исчез: он изображал бы объект со звеном", parents)
		}

		c, err := r74ChainCoverage(t, ctx, tx, r74DeclaredDerivable(), nil)
		if err != nil {
			t.Fatalf("предпосылка близнеца не выполнена: %v", err)
		}
		r74ReportCoverage(t, c)
		if len(c.Findings()) != 0 {
			t.Errorf("гейт нашёл %v при живом объекте типа, НЕ объявленного выводимым. Отсутствие "+
				"звена у такого типа — норма, а не находка; гейт, краснеющий на ней, красен на "+
				"верной реализации", c.Findings())
		}
	})
}

// TestR7_4_05_CoverageGateRefusesAnEmptyDeclaredSet — ПРОВЕРКА ПРЕДПОСЫЛКИ.
//
// Пустой перечень выводимых типов — отказ, а не успех. Без этого гейт, у
// которого сломался источник перечня, отвечал бы «находок нет» и был бы вечно
// зелёным именно тогда, когда перестал что-либо читать.
func TestR7_4_05_CoverageGateRefusesAnEmptyDeclaredSet(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		c, err := r74ChainCoverage(t, ctx, tx, nil, nil)
		if err == nil {
			t.Fatalf("гейт принял ПУСТОЙ перечень выводимых типов и вернул %+v — «ноль находок» "+
				"стало неотличимо от «ноль прочитанного»", c)
		}
		t.Logf("предпосылка держится: пустой перечень отвергнут — %v", err)

		// Пара к отказу: НЕПУСТОЙ перечень отказом не является. Без неё «отказ
		// на пустом» зеленел бы на гейте, который отвергает всё подряд.
		seedTenant(t, ctx, tx)
		if _, err := r74ChainCoverage(t, ctx, tx, r74DeclaredDerivable(), nil); err != nil {
			t.Fatalf("гейт отверг НЕПУСТОЙ объявленный перечень: %v — тогда его отказ выше "+
				"ничего не говорит о пустоте", err)
		}
	})
}
