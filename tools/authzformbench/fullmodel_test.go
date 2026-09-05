// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzformbench

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Разбор боевой модели и его перепись — без контейнеров.
//
// Проба быстрая намеренно: она держит предпосылку, на которой стоит всё
// остальное, и обязана падать раньше, чем поднимется хоть один контейнер. Если
// разбор перестал понимать модель, доказательство эквивалентности не «покраснеет
// на паре вопросов» — оно станет утверждением о другом предмете.

func parseCanonical(t *testing.T) *Model {
	t.Helper()
	path, canon, err := ResolveCanonicalModel()
	require.NoError(t, err)
	require.NotEmpty(t, canon, "канонический файл модели пуст: %s", path)
	m, err := ParseModel(string(canon))
	require.NoError(t, err, "разбор канонической модели %s", path)
	return m
}

// TestCanonicalModelIsParsedWhole — перепись разобранного против переписи файла.
//
// Обе стороны считаются РАЗНЫМИ способами: слева дерево разбора, справа строки
// файла. Совпадение означает, что разбор не потерял объявлений молча; расхождение
// назовёт, сколько именно потеряно. Без правой стороны «разобралось» было бы
// неотличимо от «разобралась половина».
func TestWorldIsBuiltFromTheModelAndIsNotDegenerate(t *testing.T) {
	m := parseCanonical(t)
	w, err := buildWorld(m)
	require.NoError(t, err)

	byType := map[string][]fmObject{}
	tenants := map[fmTenant]int{}
	for _, o := range w.Objects {
		byType[o.Type] = append(byType[o.Type], o)
		tenants[o.Tenant]++
	}
	for _, ty := range m.Types {
		if len(ty.Verbs()) == 0 {
			continue
		}
		require.NotEmptyf(t, byType[ty.Name], "у типа %q с глаголами нет ни одного объекта — "+
			"его глаголы не были бы спрошены ни разу", ty.Name)
	}
	require.Positive(t, tenants[tenantHome])
	require.Positivef(t, tenants[tenantForeign],
		"в мире один арендатор — конъюнкт области тождественно истинен, и доказательство вырождено")
	require.Positivef(t, tenants[tenantCluster],
		"в мире нет объекта вне арендаторов — привязка к кластеру не была бы отличима от привязки к проекту")

	mat := w.materialize()
	require.NotEmptyf(t, mat, "реконсайлер не развернул ни одного кортежа — положительная половина "+
		"вопросника была бы пуста, а отказ на всё совпал бы у обеих форм")

	// Развёрнутый состав обязан НЕ накрывать чужого арендатора для своего субъекта
	// и накрывать своего — иначе «совпало» держится на том, что не выдано ничего.
	var home, foreign int
	for _, tup := range mat {
		if tup.User != fmSubjDirect {
			continue
		}
		if strings.Contains(tup.Object, "foreign") {
			foreign++
		} else {
			home++
		}
	}
	require.Positive(t, home, "субъект своей привязки не получил ни одного объекта")
	require.Zerof(t, foreign, "субъект своей привязки получил объект ЧУЖОГО арендатора — "+
		"развёртка области неверна, и вопросник сравнивал бы две ошибки")

	t.Logf("мир: %s", strings.TrimSpace(w.describeWorld()))
	t.Logf("вопросов в полном вопроснике: %d", len(w.Questions()))
}

// TestQuestionSetCoversEveryVerbOfEveryType — вопросник СТРОИТСЯ из модели, и
// это проверяется перечислением, а не доверием.
//
// Выписанный вопросник покрыл бы то, что автор помнит. Здесь требуется, чтобы
// каждый глагол каждого типа был спрошен, и чтобы у типа, ПРИНАДЛЕЖАЩЕГО
// арендатору, был вопрос и про свой объект, и про чужой: без второго отказ
// неотличим от «спросили не про то».
//
// Требование «оба арендатора» намеренно не предъявляется типу, привязанному к
// КЛАСТЕРУ: у такого типа чужого арендатора нет by construction — его объект не
// лежит ни в одном аккаунте, — и требование к нему было бы требованием
// сконструировать состояние, которого модель не допускает. Ему предъявляется
// другое, проверяемое: не меньше двух различных объектов, чтобы вопрос не
// держался на единственной строке.
func TestQuestionSetCoversEveryVerbOfEveryType(t *testing.T) {
	m := parseCanonical(t)
	w, err := buildWorld(m)
	require.NoError(t, err)

	byRef := map[string]fmObject{}
	tenantsOfType := map[string]map[fmTenant]bool{}
	for _, o := range w.Objects {
		byRef[o.Ref()] = o
		if tenantsOfType[o.Type] == nil {
			tenantsOfType[o.Type] = map[fmTenant]bool{}
		}
		tenantsOfType[o.Type][o.Tenant] = true
	}

	seenTenants := map[string]map[fmTenant]bool{}
	seenObjects := map[string]map[string]bool{}
	for _, q := range w.Questions() {
		if !q.IsVerb {
			continue
		}
		k := q.Type + "." + q.Relation
		if seenTenants[k] == nil {
			seenTenants[k] = map[fmTenant]bool{}
			seenObjects[k] = map[string]bool{}
		}
		seenTenants[k][byRef[q.Object].Tenant] = true
		seenObjects[k][q.Object] = true
	}

	var missing []string
	verbs, clusterAnchored := 0, 0
	for _, ty := range m.Types {
		tenantScoped := tenantsOfType[ty.Name][tenantHome] || tenantsOfType[ty.Name][tenantForeign]
		if len(ty.Verbs()) > 0 && !tenantScoped {
			clusterAnchored++
		}
		for _, v := range ty.Verbs() {
			verbs++
			k := ty.Name + "." + v
			switch {
			case seenTenants[k] == nil:
				missing = append(missing, k+" — не спрошен ни разу")
			case len(seenObjects[k]) < 2:
				missing = append(missing, k+" — спрошен про единственный объект")
			case tenantScoped && !(seenTenants[k][tenantHome] && seenTenants[k][tenantForeign]):
				missing = append(missing, k+" — тип принадлежит арендатору, но спрошен не у обоих")
			}
		}
	}
	require.Emptyf(t, missing, "вопросник не покрывает модель:\n%s", strings.Join(missing, "\n"))
	require.Positive(t, verbs)
	t.Logf("покрыто глаголов: %d у %d типов; из них привязанных к кластеру (чужого арендатора "+
		"нет by construction): %d", verbs, len(seenTenants), clusterAnchored)
}

// ── ЗДЕСЬ БЫЛО доказательство согласия двух сторон на полной модели ───────────
//
// Снято вместе с движком отношений (S6). Что именно снято и почему это не
// «упрощение тестов»:
//
//   - проба СОГЛАСИЯ ВЕРДИКТОВ задавала ОБЕИМ сторонам вопросник по каждому
//     глаголу каждого типа канонической модели и требовала совпадения вердиктов,
//     называя каждое расхождение поимённо. Она же следила, чтобы совпадение не было
//     вырожденным: отношение, на котором движок отказывал ВСЕМ, совпало бы с любой
//     формой, отвечающей «нет», — поэтому доля разрешений печаталась и проверялась;
//   - её ИНЪЕКЦИЯ в обе стороны отнимала у формы E источник вердикта и требовала,
//     чтобы проба покраснела и НАЗВАЛА координату. Без неё согласие сторон было бы
//     утверждением о двух реализациях, ни одна из которых не показана способной
//     разойтись;
//   - проба УСЛОВНОГО КОРТЕЖА доказывала исход (в) полной переписи:
//     отношение С УСЛОВИЕМ на кортеже (свежесть подтверждения личности)
//     движок различал, а форма E — нет, потому что строка не может отвечать
//     по-разному на два одинаковых запроса. Предмет доказательства был не в
//     приборе, а в ПРОДУКТЕ, и он никуда не делся: форма E по-прежнему этого не
//     выражает. Доказать это здесь больше нечем — вторая сторона была
//     единственным способом показать, ЧТО ИМЕННО не выражается;
//   - проба КОНЪЮНКТА ФАКТА НА ПРЕДКЕ строила крошечную модель с самовложением и
//     сравнивала ТРИ ответа: движка, формы E с конъюнктом и формы E без него. Её
//     собственная шапка говорила, почему левый ответ несущий: без него это было бы
//     сравнение двух своих реализаций между собой.
//
// Уцелевшее ниже — то, у чего обе стороны свои: две реализации формы E, узкая и
// полномодельная, обязаны отвечать одинаково на сценарии, чьи числа опубликованы.

// TestNarrowAndFullFormEAgreeOnTheBenchScenario связывает две реализации формы E.
//
// Измеренная в XC-10 (`relational.go`) выражена под один тип и её числа
// опубликованы; полномодельная собирается из разбора. Две реализации одного
// предмета расходятся молча — поэтому на сценарии, который измерялся, обе обязаны
// отвечать одинаково. Без этой пробы полномодельная форма могла бы быть верной, а
// опубликованные числа — относиться к другому поведению.
func TestNarrowAndFullFormEAgreeOnTheBenchScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("поднимает контейнеры; -short")
	}
	ctx := t.Context()
	stack, canon := bootForTest(ctx, t)
	m, err := ParseModel(canon)
	require.NoError(t, err)

	sc := NewScenario(6, 3, 3, "editor", DefaultVerbs())
	cfg := DefaultConfig()
	cfg.Ns = []int{sc.N}
	cfg.Verbs = sc.Verbs
	r := NewRunner(stack, cfg)
	narrow, err := r.NewSeededStore(ctx, FormE, sc, true, "narrow-vs-full")
	require.NoError(t, err)
	defer func() { _ = narrow.Teardown(ctx) }()

	// Полномодельная форма засевается ТЕМ ЖЕ сценарием, переведённым в её схему.
	full, err := newFullRelStore(ctx, stack.DSN, "fm_narrow_vs_full", m)
	require.NoError(t, err)
	defer func() { _ = full.Close(ctx) }()
	require.NoError(t, full.Seed(ctx, benchScenarioRows(sc)))

	qs := questionSet(sc, "granted")
	var mismatch []string
	for _, q := range qs {
		wantNarrow, _, cerr := narrow.Check(ctx, q.Subject, q.Verb, q.Object)
		require.NoError(t, cerr)
		ot, oid, serr := splitObject(q.Object)
		require.NoError(t, serr)
		got, gerr := full.Allowed(ctx, q.Subject, q.Verb, ot, []string{oid})
		require.NoErrorf(t, gerr, "полномодельная форма на %s", q.Name)
		if got[oid] != wantNarrow {
			mismatch = append(mismatch, fmt.Sprintf("%s: измеренная %v, полномодельная %v",
				q.Name, wantNarrow, got[oid]))
		}
		require.Equalf(t, q.Want, wantNarrow, "измеренная форма E разошлась с намерением фикстуры на %s", q.Name)
	}
	require.Emptyf(t, mismatch, "две реализации формы E разошлись на измерявшемся сценарии:\n%s",
		strings.Join(mismatch, "\n"))
	t.Logf("сверено вопросов сценария XC-10: %d", len(qs))
}

// benchScenarioRows переводит сценарий XC-10 в строки полномодельной схемы.
func benchScenarioRows(sc Scenario) relRows {
	labels := fmt.Sprintf(`{%q:%q}`, "authzformbench", "in-set")
	var r relRows
	obj := func(ref string, l string, ptr, parentRef string) {
		ot, oid, err := splitObject(ref)
		if err != nil {
			panic(err)
		}
		r.Mirror = append(r.Mirror, [3]string{ot, oid, l})
		if ptr != "" {
			pt, pid, perr := splitObject(parentRef)
			if perr != nil {
				panic(perr)
			}
			r.Edges = append(r.Edges, [5]string{ot, oid, ptr, pt, pid})
		}
	}
	obj(clusterObj, "{}", "", "")
	obj(accountObj, "{}", "cluster", clusterObj)
	obj(otherAccountObj, "{}", "cluster", clusterObj)
	obj(projectObj, "{}", "account", accountObj)
	obj(otherProjectObj, "{}", "account", otherAccountObj)
	for i := 0; i < sc.N+sc.Spare; i++ {
		l := "{}"
		if i < sc.N {
			l = labels
		}
		obj(sc.Object(i), l, "project", projectObj)
	}
	obj(sc.ForeignObject(), labels, "project", otherProjectObj)

	r.Bindings = append(r.Bindings, [4]string{"ab-bench", "project", strings.TrimPrefix(projectObj, "project:"), sc.Role})
	for _, s := range sc.Subjects {
		r.BindSubj = append(r.BindSubj, [2]string{"ab-bench", s})
	}
	r.Selectors = append(r.Selectors, [3]string{"ab-bench", BenchType, labels})
	for _, v := range sc.Verbs {
		r.RoleVerbs = append(r.RoleVerbs, [2]string{sc.Role, v})
	}
	return r
}

// ── вопросник сценария, переехавший из снятой пробы эквивалентности ───────────

// Question — один вопрос к форме.
type Question struct {
	Name    string
	Subject string
	Verb    string
	Object  string
	Want    bool
}

// questionSet строит вопросы к форме на сценарии замера.
//
// ОТРИЦАНИЯ — та половина, которая решает. Форма, которая только ДОБАВЛЯЕТ,
// зелена на каждом положительном и неверна ровно на той операции, ради которой
// существует отзыв (та же асимметрия, что .claude/rules/testing.md записывает про
// аддитивный быстрый путь). Поэтому: посторонний, объект вне набора, объект
// ЧУЖОГО арендатора.
//
// Последний — самый содержательный. Он единственный, где у формы E выполнены ВСЕ
// конъюнкты вердикта, кроме области: субъект назван в привязке, роль даёт
// спрошенный глагол, метка объекта попадает под селектор — и отказать обязана
// ровно транзитивная вложенность области. Инъекция «снять проверку области»
// оставляла зелёными все прочие вопросы, поэтому этот стоит здесь поимённо.
//
// Набор переехал сюда из снятой вместе с движком пробы эквивалентности: там он
// задавался ШЕСТИ формам и требовал одинаковых векторов ответов. Здесь он
// задаётся двум реализациям одной формы и, отдельным утверждением, сверяется с
// намерением фикстуры — то есть отвечает не «совпали ли», а «верно ли».
func questionSet(sc Scenario, phase string) []Question {
	var qs []Question
	inSet := sc.Object(0)
	inSet2 := sc.Object(sc.N - 1)
	outSet := sc.Object(sc.N)     // запасной — никогда не выдавался
	foreign := sc.ForeignObject() // помечен меткой набора, но лежит у чужого арендатора
	granted := map[string]bool{}
	for _, v := range sc.Verbs {
		granted[v] = true
	}

	member := sc.Subjects[0]
	other := sc.Subjects[len(sc.Subjects)-1]
	stranger := "user:stranger-not-in-any-binding"

	for _, v := range DefaultVerbs() {
		want := granted[v]
		qs = append(qs,
			Question{fmt.Sprintf("%s/member/%s/in-set-first", phase, v), member, v, inSet, want},
			Question{fmt.Sprintf("%s/member/%s/in-set-last", phase, v), member, v, inSet2, want},
			Question{fmt.Sprintf("%s/other/%s/in-set-first", phase, v), other, v, inSet, want},
			Question{fmt.Sprintf("%s/member/%s/out-of-set", phase, v), member, v, outSet, false},
			Question{fmt.Sprintf("%s/member/%s/foreign-tenant", phase, v), member, v, foreign, false},
			Question{fmt.Sprintf("%s/stranger/%s/in-set", phase, v), stranger, v, inSet, false},
		)
	}
	return qs
}
