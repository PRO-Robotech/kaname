// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// seed_rule_verb_resolvability_integration_test.go — гейт на класс «посеянная
// роль называет ГЛАГОЛ, которого объявивший её тип не несёт».
//
// # Близнец по второй половине сегмента
//
// Правило роли адресует объект тремя сегментами — модуль, ресурс, глагол.
// Ресурсную половину стережёт TestSeededRoleRulesResolveOrArePinned
// (seed_rule_resolvability_integration_test.go); здесь судится ГЛАГОЛ. Гейта на
// эту половину не было вовсе, и цена измерена: двадцать троек «роль × тип ×
// глагол» посева не резолвились ни в одно право платформы (kacho#1815, приёмка
// services/iam/docs/engineering/acceptance/system-role-segments-resolve.md).
//
// # Почему это находка, а не стиль
//
// Отказ молчаливый. `authzmap.GrantedVerbs` фильтрует авторские глаголы
// функцией домена «объявляет ли ТИП этот глагол»
// (`services/iam/internal/domain/rule_verbs.go`) и глагол вне набора ТИПА
// отбрасывает — кортеж не эмитится, строка проекции вердикта не появляется, а
// правило продолжает объявлять право. Арендатор, читающий роль, видит в ней глагол; вердикт по её
// выдаче отвечает через другой. Право действует не потому, что названо, а
// потому что рядом названо другое; роль, где такой глагол оказался бы
// единственным, не дала бы ничего.
//
// # Почему полос ДВЕ, и почему их нельзя схлопывать
//
// У конкретной пары `модуль.ресурс` спрашивается набор ЭТОГО типа
// (`authzmap.VerbsOfType`). У полной подстановки `*.*` типа нет вовсе, поэтому
// спрашивается ОБЪЕДИНЕНИЕ платформы (`authzmap.AllVerbVocabulary`).
// Схлопнуть в первую нельзя — у `*.*` набора не у кого спросить, и все её
// глаголы стали бы находками. Схлопнуть во вторую нельзя — тогда `addTargets`
// на `vpc.network` прошёл бы законным, потому что его объявляет соседний тип.
// Обе ошибки проверяются инъекцией (IAM-SV-1-09, IAM-SV-1-13).
//
// # Чем гейт СРАВНИВАЕТ
//
// Тем же инструментом, каким сравнивает эмиссия: функцией домена «объявляет ли
// ТИП этот глагол» — она приводит регистр ОБЕИХ сторон единственной точкой
// приведения имени глагола (`services/iam/internal/domain/rule_verbs.go`).
// Вызов стоит НИЖЕ, в теле предиката, и читать инструмент надо там.
//
// Имена этих двух функций здесь намеренно НЕ написаны: гейт дерева
// `TestCommentsNamingAGuardHaveItInScope` требует, чтобы названная комментарием
// защита вызывалась в ПРОД-коде своего пакета, а у файла-гейта прод-половины нет
// by construction. Граница гейта названа задачей продукта #1831; до её решения
// правдивое имя инструмента живёт в вызове, а не в комментарии.
//
// Дословное сравнение здесь дало бы красное на законных
// `addTargets`/`removeTargets`: правила говорят верблюжьим (решение посева 0031 —
// «VERBATIM»), а каталог хранит строчное. Приёмка §2.3.1 и `Н2-D` круга 2
// называют это прямо.
//
// # Что гейт НЕ утверждает
//
// Он не утверждает, что резолвящийся глагол материализуется: это решают ещё
// область привязки и набор типа. Проверяется одно звено — то, которое
// отказывает молча. Он не заменяет ключ `role_rule_ref_verb_fk`: ключ судит
// путь ПОЛЬЗОВАТЕЛЬСКОЙ роли в момент записи, гейт — состояние посева в дереве;
// подстановочную полосу ключ не судит by construction (строк проекции у неё
// нет). И он не судит пару «модуль.ресурс»: пара, которой закрытая таблица не
// несёт, — предмет гейта-близнеца, и повторять его здесь значило бы завести
// второе место об одном предмете.
package pg_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// knownUnresolvableSeedVerbs — глаголы ДЕЙСТВУЮЩЕГО посева, которых объявивший
// их тип не несёт, вместе с причиной. Ключ — точечная форма
// «модуль.ресурс.глагол» (для полной подстановки — `*.*.<глагол>`), глагол в
// приведённой форме.
//
// Перечень ПИНИТ цену уже принятых решений и не выдаёт разрешения на новые: он
// самоистекает (запись без предмета — находка), поэтому приведённый к словарю
// глагол обязан быть отсюда снят.
//
// Сегодня перечень ПУСТ, и это цель, а не поломка: двадцать троек посева сняты
// миграцией 20260902… (kacho#1815). Пустой перечень обязан проходить — гейт,
// падающий на достижении своей цели, толкает держать запись ради зелёного.
var knownUnresolvableSeedVerbs = map[string]string{}

// seedVerbFindingKind — почему глагол назван находкой. Вид входит в текст
// вердикта: «вне набора типа» и «вне словаря платформы» приходят из РАЗНЫХ
// полос, и различить их обязан читатель находки, а не автор гейта.
type seedVerbFindingKind string

const (
	// verbOutsideTypeSet — полоса конкретной пары: тип резолвится, глагола у него нет.
	verbOutsideTypeSet seedVerbFindingKind = "глагол вне набора типа"
	// verbOutsideVocabulary — полоса полной подстановки: глагола нет ни у одного типа.
	verbOutsideVocabulary seedVerbFindingKind = "глагол вне словаря платформы"
	// ruleWithoutVerbs — правило без единого глагола: не даёт ничего целиком.
	ruleWithoutVerbs seedVerbFindingKind = "правило без глаголов"
	// ruleHalfWildcard — полуподстановка: ни полосы набора типа, ни полосы объединения.
	ruleHalfWildcard seedVerbFindingKind = "полуподстановка"
)

// seedVerbFinding — одна находка гейта. Несёт роль, пару и глагол: находка,
// называющая только глагол, посылает читателя искать по всему посеву.
type seedVerbFinding struct {
	Role     string
	Module   string
	Resource string
	Verb     string
	Kind     seedVerbFindingKind
}

// pinKey — ключ записи перечня пинов.
func (f seedVerbFinding) pinKey() string {
	return f.Module + "." + f.Resource + "." + domain.NormalizeVerb(f.Verb)
}

func (f seedVerbFinding) String() string {
	return fmt.Sprintf("%s: роль %q, пара %s.%s, глагол %q",
		f.Kind, f.Role, f.Module, f.Resource, f.Verb)
}

// seedRuleVerbCensus — объём осмотренного. Печатается ДО вердикта: «ноль
// находок» обязано быть отличимо от «ноль прочитанного».
type seedRuleVerbCensus struct {
	Rules         int
	ConcretePairs int
	WildcardRules int
	Verbs         int
	Anchors       int
}

// seedRuleVerbFindings — ЕДИНСТВЕННЫЙ предикат гейта. Его же зовут инъекции,
// поэтому «краснеет на дефекте» и «молчит на законном» утверждаются об одном и
// том же коде, а не о двух похожих.
func seedRuleVerbFindings(role string, rules domain.Rules) ([]seedVerbFinding, seedRuleVerbCensus) {
	var (
		out    []seedVerbFinding
		census seedRuleVerbCensus
	)
	for _, r := range rules {
		census.Rules++

		wildResources, concreteResources := 0, 0
		for _, res := range r.Resources {
			if res == "*" {
				wildResources++
				continue
			}
			concreteResources++
		}

		concreteLane := r.Module != "*" && wildResources == 0 && concreteResources > 0
		wildcardLane := r.Module == "*" && concreteResources == 0 && wildResources > 0

		if len(r.Verbs) == 0 {
			// Правило без глаголов не даёт ничего целиком — и это ДРУГОЙ предмет,
			// чем нерезолвящийся глагол: судьбу такого правила решает не приведение
			// к словарю. Форма CHECK `roles_rules_valid` его отвергает (1..16), но
			// гейт судит СОСТОЯНИЕ дерева, а не путь записи.
			out = append(out, seedVerbFinding{
				Role: role, Module: r.Module,
				Resource: strings.Join(r.Resources, ","),
				Kind:     ruleWithoutVerbs,
			})
			continue
		}

		if !concreteLane && !wildcardLane {
			// Полуподстановка (`*.конкретное` либо `конкретное.*`, а также смесь
			// подстановки и имени в одном правиле): у неё нет ни полосы набора
			// типа, ни полосы объединения. Молча выбрать одну значило бы принять
			// решение, которого никто не принимал.
			out = append(out, seedVerbFinding{
				Role: role, Module: r.Module,
				Resource: strings.Join(r.Resources, ","),
				Kind:     ruleHalfWildcard,
			})
			continue
		}

		if wildcardLane {
			census.WildcardRules++
			vocabulary := authzmap.AllVerbVocabulary()
			for _, v := range r.Verbs {
				if v == "*" {
					census.Anchors++
					continue
				}
				census.Verbs++
				if domain.IsVerbOfType(v, vocabulary) {
					continue
				}
				out = append(out, seedVerbFinding{
					Role: role, Module: "*", Resource: "*", Verb: v,
					Kind: verbOutsideVocabulary,
				})
			}
			continue
		}

		for _, res := range r.Resources {
			fgaType, ok := authzmap.ObjectType(r.Module, res)
			if !ok {
				// Пара вне закрытой таблицы — предмет гейта-близнеца
				// (TestSeededRoleRulesResolveOrArePinned). Спрашивать у неё набор
				// глаголов не у кого, и объявлять глагол находкой значило бы
				// сообщать о ЧУЖОМ дефекте вторым голосом.
				continue
			}
			census.ConcretePairs++
			typeVerbs := authzmap.VerbsOfType(fgaType)
			for _, v := range r.Verbs {
				if v == "*" {
					census.Anchors++
					continue
				}
				census.Verbs++
				if domain.IsVerbOfType(v, typeVerbs) {
					continue
				}
				out = append(out, seedVerbFinding{
					Role: role, Module: r.Module, Resource: res, Verb: v,
					Kind: verbOutsideTypeSet,
				})
			}
		}
	}
	return out, census
}

// TestSeededRoleRuleVerbsAreDeclaredByTheType — IAM-SV-1-02 и IAM-SV-1-03:
// каждый авторский глагол действующего посева либо объявлен типом, на который
// правило адресовано (конкретная пара), либо объявлен хоть одним типом
// (полная подстановка), либо перечислен с причиной.
func TestSeededRoleRuleVerbsAreDeclaredByTheType(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	rows, err := pool.Query(ctx, `SELECT id, name, rules FROM kacho_iam.roles ORDER BY id`)
	require.NoError(t, err)

	var (
		roles    int
		census   seedRuleVerbCensus
		findings []seedVerbFinding
	)
	for rows.Next() {
		var id, name string
		var raw []byte
		require.NoError(t, rows.Scan(&id, &name, &raw))
		roles++
		if len(raw) == 0 {
			continue
		}
		rules, derr := domain.DecodeRules(raw)
		require.NoErrorf(t, derr, "роль %s (%s): rules не декодируются: %v", id, name, derr)

		f, c := seedRuleVerbFindings(name, rules)
		findings = append(findings, f...)
		census.Rules += c.Rules
		census.ConcretePairs += c.ConcretePairs
		census.WildcardRules += c.WildcardRules
		census.Verbs += c.Verbs
		census.Anchors += c.Anchors
	}
	require.NoError(t, rows.Err())

	// Перепись — ДО вердикта.
	t.Logf("осмотрено: ролей=%d, правил=%d, конкретных пар=%d, подстановочных правил=%d, "+
		"глаголов=%d, якорей=%d, записей пина=%d",
		roles, census.Rules, census.ConcretePairs, census.WildcardRules,
		census.Verbs, census.Anchors, len(knownUnresolvableSeedVerbs))

	// Предпосылки гейта — в обе стороны. Пустая выборка, пустой словарь и посев
	// без единого глагола дали бы «ноль находок» даром.
	require.NotZerof(t, roles, "предпосылка гейта нарушена: в посеве нет ни одной роли")
	require.NotZerof(t, census.Rules, "предпосылка гейта нарушена: прочитано %d ролей, но ни одного правила", roles)
	require.NotZerof(t, census.Verbs, "предпосылка гейта нарушена: правил %d, но ни одного названного глагола — "+
		"предикат «глагол объявлен типом» больше ничего не проверяет", census.Rules)
	require.NotEmpty(t, authzmap.AllVerbVocabulary(),
		"предпосылка гейта нарушена: объединение глаголов платформы пусто — «не объявлен» получено даром")
	require.NotEmpty(t, authzmap.Catalog(),
		"предпосылка гейта нарушена: закрытая таблица типов пуста")

	seen := map[string]bool{}
	var unpinned []seedVerbFinding
	for _, f := range findings {
		key := f.pinKey()
		seen[key] = true
		if _, pinned := knownUnresolvableSeedVerbs[key]; pinned {
			continue
		}
		unpinned = append(unpinned, f)
	}
	sort.Slice(unpinned, func(i, j int) bool { return unpinned[i].String() < unpinned[j].String() })
	for _, f := range unpinned {
		t.Errorf("%s.\n"+
			"Эмиссия фильтрует авторские глаголы через domain.IsVerbOfType и этот отбросит — "+
			"кортеж не появится, строка проекции вердикта не появится, а правило продолжит "+
			"объявлять право, которого не даёт.\n"+
			"Приведи глагол к словарю платформы, сними его из правила, либо внеси в "+
			"knownUnresolvableSeedVerbs с причиной.", f)
	}

	// Самоистечение: запись пина, которой больше нечего описывать, — находка.
	// Разбор ОБЩИЙ с гейтом-близнецом (seed_pin_self_expiry_test.go): вторая
	// реализация разошлась бы с первой молча — обе дают «ноль находок» на честном
	// перечне, и различие видно только на том входе, ради которого они написаны.
	// Там же живёт доказательство её способности упасть и смолчать.
	for _, f := range stalePinFindings("knownUnresolvableSeedVerbs",
		"нерезолвящегося глагола", knownUnresolvableSeedVerbs, seen) {
		t.Error(f)
	}
}

// TestSeededRoleRuleVerbPredicate_Injections — способность предиката упасть и
// смолчать, доказанная НА ОДНОЙ функции с гейтом выше (сценарии IAM-SV-1-08 …
// IAM-SV-1-11 и IAM-SV-1-13 приёмки system-role-segments-resolve.md).
//
// Постгрес здесь не нужен и не должен быть: предмет — предикат, а не выборка.
// Каждая инъекция стоит рядом со своим ЗАКОННЫМ близнецом: отрицание без
// положительного контроля зеленеет на предикате, отвергающем всё.
func TestSeededRoleRuleVerbPredicate_Injections(t *testing.T) {
	rule := func(module string, resources, verbs []string) domain.Rules {
		return domain.Rules{{Module: module, Resources: resources, Verbs: verbs}}
	}
	kinds := func(f []seedVerbFinding) []string {
		out := make([]string, 0, len(f))
		for _, x := range f {
			out = append(out, string(x.Kind))
		}
		return out
	}

	t.Run("IAM-SV-1-08 возвращённый read на конкретной паре — находка", func(t *testing.T) {
		got, c := seedRuleVerbFindings("inj", rule("vpc", []string{"network"}, []string{"read", "get"}))
		require.Len(t, got, 1, "ждали одну находку, получили %v (осмотрено глаголов %d)", kinds(got), c.Verbs)
		require.Equal(t, verbOutsideTypeSet, got[0].Kind)
		require.Equal(t, "read", got[0].Verb)
		require.Equal(t, "vpc", got[0].Module)
		require.Equal(t, "network", got[0].Resource)
		require.Equal(t, "inj", got[0].Role, "находка обязана называть роль")
	})
	t.Run("IAM-SV-1-08 контроль: только канонический глагол — молчит", func(t *testing.T) {
		got, c := seedRuleVerbFindings("inj", rule("vpc", []string{"network"}, []string{"get"}))
		require.Empty(t, got, "предикат отвергает законный вход: %v", kinds(got))
		require.NotZero(t, c.Verbs, "контроль вакуумен: предикат не осмотрел ни одного глагола")
	})

	t.Run("IAM-SV-1-09 глагол ЧУЖОГО типа — находка", func(t *testing.T) {
		got, _ := seedRuleVerbFindings("inj", rule("vpc", []string{"network"}, []string{"addTargets"}))
		require.Len(t, got, 1, "addTargets принадлежит объединению платформы, но не набору vpc_network — "+
			"молчание здесь означало бы, что конкретная полоса спрашивает ОБЪЕДИНЕНИЕ")
		require.Equal(t, verbOutsideTypeSet, got[0].Kind)
	})
	t.Run("IAM-SV-1-09 контроль: тот же глагол у СВОЕГО типа — молчит", func(t *testing.T) {
		got, c := seedRuleVerbFindings("inj",
			rule("loadbalancer", []string{"targetGroups"}, []string{"addTargets", "removeTargets"}))
		require.Empty(t, got, "предикат отвергает глагол, объявленный этим типом: %v", kinds(got))
		require.Equal(t, 2, c.Verbs)
	})

	t.Run("IAM-SV-1-10 пустой набор глаголов — находка", func(t *testing.T) {
		got, _ := seedRuleVerbFindings("inj", rule("vpc", []string{"network"}, nil))
		require.Len(t, got, 1)
		require.Equal(t, ruleWithoutVerbs, got[0].Kind)
		require.Equal(t, "inj", got[0].Role, "находка обязана называть роль")
	})
	t.Run("IAM-SV-1-10 контроль: набор из одного канонического — молчит", func(t *testing.T) {
		got, _ := seedRuleVerbFindings("inj", rule("vpc", []string{"network"}, []string{"get"}))
		require.Empty(t, got)
	})

	t.Run("IAM-SV-1-11 якорь * глаголом не считается — молчит", func(t *testing.T) {
		got, c := seedRuleVerbFindings("inj", rule("vpc", []string{"network"}, []string{"*"}))
		require.Empty(t, got, "распознаватель, не знающий формы якоря, объявил бы нарушителями "+
			"все *.admin-роли разом: %v", kinds(got))
		require.Equal(t, 1, c.Anchors, "якорь обязан быть ОСМОТРЕН и отнесён к якорям, а не пропущен молча")
		require.Zero(t, c.Verbs)
	})
	t.Run("IAM-SV-1-11 отрицание к тому же контролю: выдуманный глагол — находка", func(t *testing.T) {
		got, _ := seedRuleVerbFindings("inj", rule("vpc", []string{"network"}, []string{"frobnicate"}))
		require.Len(t, got, 1)
		require.Equal(t, verbOutsideTypeSet, got[0].Kind)
	})

	t.Run("IAM-SV-1-03 подстановка *.*: глагол вне объединения — находка", func(t *testing.T) {
		got, _ := seedRuleVerbFindings("inj", rule("*", []string{"*"}, []string{"frobnicate"}))
		require.Len(t, got, 1)
		require.Equal(t, verbOutsideVocabulary, got[0].Kind)
		require.Equal(t, "*", got[0].Module)
		require.Equal(t, "*", got[0].Resource)
	})
	t.Run("IAM-SV-1-13 контроль: read на *.* — тоже находка, get — молчит", func(t *testing.T) {
		bad, _ := seedRuleVerbFindings("inj", rule("*", []string{"*"}, []string{"read", "list", "get"}))
		require.Len(t, bad, 1, "read не принадлежит объединению платформы")
		require.Equal(t, "read", bad[0].Verb)

		good, c := seedRuleVerbFindings("inj", rule("*", []string{"*"}, []string{"get", "list"}))
		require.Empty(t, good, "предикат отвергает законную подстановку: %v", kinds(good))
		require.Equal(t, 1, c.WildcardRules)
		require.Equal(t, 2, c.Verbs)
	})

	t.Run("полуподстановка не судится молча ни одной полосой — находка", func(t *testing.T) {
		half, _ := seedRuleVerbFindings("inj", rule("vpc", []string{"*"}, []string{"read", "get"}))
		require.Len(t, half, 1, "у `конкретное.*` нет ни полосы набора типа, ни полосы объединения")
		require.Equal(t, ruleHalfWildcard, half[0].Kind)

		full, _ := seedRuleVerbFindings("inj", rule("*", []string{"*"}, []string{"get"}))
		require.Empty(t, full, "контроль: полная подстановка судится полосой объединения и молчит")
	})

	t.Run("пара вне закрытой таблицы — предмет ГЕЙТА-БЛИЗНЕЦА, здесь молчание", func(t *testing.T) {
		got, c := seedRuleVerbFindings("inj", rule("vpc", []string{"nonesuch"}, []string{"frobnicate"}))
		require.Empty(t, got, "о нерезолвящейся ПАРЕ отвечает TestSeededRoleRulesResolveOrArePinned; "+
			"второй голос об одном предмете разойдётся с первым молча: %v", kinds(got))
		require.Zero(t, c.ConcretePairs, "перепись обязана показать, что пара НЕ осмотрена, — "+
			"иначе молчание неотличимо от «осмотрено и чисто»")
	})
}

// TestSeedRuleVerbPredicate_HasAControlBothWays — контроль самих словарей, на
// которых стоит предикат. Односторонняя проверка зеленеет сильнее всего именно
// тогда, когда словарь пуст или отвечает всем одинаково.
func TestSeedRuleVerbPredicate_HasAControlBothWays(t *testing.T) {
	vpcNetwork := authzmap.VerbsOfType("vpc_network")
	require.NotEmpty(t, vpcNetwork, "контроль: тип vpc_network обязан объявлять глаголы — "+
		"на пустом наборе «глагол не объявлен» получено даром")
	require.True(t, domain.IsVerbOfType("get", vpcNetwork),
		"контроль: набор не признал глагол, который обязан признавать (get у vpc_network)")
	require.False(t, domain.IsVerbOfType("read", vpcNetwork),
		"контроль: набор признал глагол, которого не несёт (read у vpc_network) — предикат не различает")

	vocabulary := authzmap.AllVerbVocabulary()
	require.True(t, domain.IsVerbOfType("addtargets", vocabulary),
		"контроль: объединение не признало глагол, объявленный хоть одним типом")
	require.False(t, domain.IsVerbOfType("read", vocabulary),
		"контроль: объединение признало read — тогда полоса подстановки ничего не сужает")

	// Приведение регистра — свойство инструмента сравнения, а не соглашение.
	// Дословное сравнение сняло бы у loadbalancer.target_manager ДВА живых
	// глагола: правила говорят верблюжьим, каталог хранит строчное.
	tg := authzmap.VerbsOfType("nlb_target_group")
	require.True(t, domain.IsVerbOfType("addTargets", tg),
		"контроль приведения: верблюжье написание обязано находиться в наборе типа")
	require.True(t, domain.IsVerbOfType("removeTargets", tg),
		"контроль приведения: верблюжье написание обязано находиться в наборе типа")
}
