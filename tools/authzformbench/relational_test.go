// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzformbench

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// ЗДЕСЬ БЫЛА проба конструктора моделей — снята вместе с движком (S6).
//
// Конструктор прогона готовил модель авторизации для КАЖДОЙ формы и гнал её через
// внешний преобразователь. Форме E модель не требуется, и «не требуется» было
// ЗАКОННЫМ ответом, отделённым от ошибки «неизвестная форма» намеренно: иначе
// первое покрывало бы опечатку во втором, и форма заводилась бы из любой строки.
// Проба держала эту пару — положительное с отрицательным, потому что одиночное
// «для формы E ошибки нет» зеленело бы и в конструкторе, переставшем отвечать
// ошибкой вообще.
//
// Моделей больше не готовит никто: готовить их было для кого, а не для чего.
// Вместе с ответом-сентинелом снята и его проба — держать её было бы не за что.

// TestFormEIsNamedInEveryPlaceTheMatrixCounts — форма заведена в СЛОВАРЯХ, а не
// только в реализации.
//
// Ячейка, которой нет в словаре операций, не входит в сумму категорий и не
// печатается: отчёт был бы полон по своему собственному счёту и молчал бы о том,
// ради чего замер и делается.
func TestFormEIsNamedInEveryPlaceTheMatrixCounts(t *testing.T) {
	require.Contains(t, AllForms, FormE, "измеряемая форма не попала в перечень форм")

	for _, op := range []Op{OpInlineGrant, OpInlineRevoke, OpCascade} {
		require.Containsf(t, opsAll, op, "операция %s не заведена в словаре — её ячейка не печатается", op)
	}
	require.Len(t, opsAll, len(opsWrite)+len(opsRead),
		"словарь операций разошёлся с полосами записи и чтения — какая-то ячейка не будет снята")

	sc := NewScenario(10, 3, 4, "editor", DefaultVerbs())
	require.Equal(t, len(sc.Subjects)+2, ExpectedGrantTuples(FormE, sc),
		"объявленная арифметика выдачи формы E — привязка, её субъекты и селектор")
	require.Len(t, Grant(FormE, sc), ExpectedGrantTuples(FormE, sc),
		"произведённое намерение разошлось с объявленной до прогона арифметикой")
	require.Len(t, RevokeSubject(FormE, sc, sc.Subjects[0]), 1)
	require.Len(t, RelabelOne(FormE, sc, sc.Object(sc.N)), 1)
}

// TestStmtProducersPassControlInBothDirections — производитель величины `StmtSQL`
// на КАЖДОМ месте снятия, проверенный исполнением.
//
// Обе половины обязательны и по отдельности бессмысленны: счётчик, который
// двигается сам по себе, мерит фон; счётчик, который не двигается на заведомом
// стейтменте, мерит что-то другое. Величина, у входа которой нет производителя,
// печатается нулём, неотличимым от измеренного, — поэтому исход контроля
// печатается в отчёте всегда, а не только при провале.
func TestStmtProducersPassControlInBothDirections(t *testing.T) {
	if testing.Short() {
		t.Skip("поднимает контейнеры")
	}
	ctx := t.Context()
	stack, _ := bootForTest(ctx, t)

	// Мест снятия было ДВА, и у каждого свой производитель: у движка отношений —
	// дельта его собственной статистики стейтментов (у него нет хука трассировки),
	// у формы E — трассировщик на своём пуле (у него нет расширения статистики).
	// Первое место снято вместе с движком, и здесь перепроверялся его контроль —
	// независимо от подъёма стека, потому что исход, взятый из чужого поля, не
	// является проверкой.
	//
	// Осталось одно место и один производитель. Контроль прогоняется при открытии КАЖДОГО хранилища и
	// роняет открытие; здесь проверяется, что он именно исполняется, а не объявлен.
	cfg := DefaultConfig()
	cfg.Forms = []Form{FormE}
	r := NewRunner(stack, cfg)
	sc := NewScenario(5, 2, 2, "editor", DefaultVerbs())
	st, err := r.NewSeededStore(ctx, FormE, sc, true, "stmt-control-E")
	require.NoError(t, err)
	defer func() { _ = st.Teardown(ctx) }()

	require.True(t, st.StmtProducer().OK)
	require.Empty(t, stmtNote(st))

	// Один вопрос — один стейтмент: вердикт формы E обязан быть ОДНИМ запросом,
	// и колонка обязана это показывать. Пообъектный обход страницы прошёл бы все
	// утверждения о вердиктах и провалился бы здесь.
	_, c, err := st.Check(ctx, sc.Subjects[0], "v_get", sc.Object(0))
	require.NoError(t, err)
	require.Equal(t, 1, c.StmtSQL, "одиночная проверка формы E стоила не один стейтмент")

	page := sc.Objects()
	_, parts, pc, err := st.CheckPage(ctx, sc.Subjects[0], "v_get", page, 50, 8)
	require.NoError(t, err)
	require.Equal(t, 1, parts, "страница формы E разложена не на одну часть")
	require.Equal(t, 1, pc.StmtSQL,
		"страница формы E стоила больше одного стейтмента — предикат применяется к странице "+
			"идентификаторов ОДНИМ запросом, иначе меряется способ вызова, а не форма")
}

// TestFormEInlineTransactionIsMeasuredAndGrantTakesEffect — выдача, написанная в
// ОДНОЙ транзакции с предметом выдачи.
//
// Здесь была вторая половина, и она была содержательнее первой: тот же вызов у
// движка отношений возвращал «неприменимо by construction» — общей транзакции
// между БД предмета выдачи и чужим хранилищем не бывает, — и это была
// единственная ячейка, где разница форм измерялась не в скорости. Половина снята
// вместе с движком; операция осталась ВЫРАЗИМОЙ, и теперь про неё утверждается
// абсолютное: она делает работу и эта работа ДЕЙСТВУЕТ.
//
// Второе утверждение несущее: без него «выдача в одной транзакции» подтверждалась
// бы одним лишь счётчиком стейтментов, то есть отчётом операции о работе, которой
// она могла не сделать.
func TestFormEInlineTransactionIsMeasuredAndGrantTakesEffect(t *testing.T) {
	if testing.Short() {
		t.Skip("поднимает контейнеры")
	}
	ctx := t.Context()
	stack, _ := bootForTest(ctx, t)

	cfg := DefaultConfig()
	cfg.Forms = []Form{FormE}
	r := NewRunner(stack, cfg)
	sc := NewScenario(5, 3, 2, "editor", DefaultVerbs())
	obj := sc.Object(sc.N + sc.Spare) // за пределами засева: объект заводится самой транзакцией
	data, grant := InlineIntent(sc, obj)

	stE, err := r.NewSeededStore(ctx, FormE, sc, true, "inline-E")
	require.NoError(t, err)
	defer func() { _ = stE.Teardown(ctx) }()
	cnt, err := stE.InlineGrant(ctx, data, grant)
	require.NoError(t, err, "у формы E выдача в транзакции писателя — обычная запись")
	require.Positive(t, cnt.StmtSQL)

	// И право, выданное этой транзакцией, ДЕЙСТВУЕТ: иначе «неприменимо у соседа»
	// сравнивалось бы с операцией, которая ничего не сделала.
	ok, _, err := stE.Check(ctx, sc.Subjects[0], "v_get", obj)
	require.NoError(t, err)
	require.True(t, ok, "объект, заведённый вместе с выдачей, не разрешён — встраиваемая "+
		"операция отчиталась о работе, которой не сделала")

}

// TestCascadeHoldsWithEmptyMaterialization — аварийный путь не зависит от того,
// прошла ли материализация.
//
// Три верхних уровня доступа разрешаются каскадом намеренно: если бы права
// администратора облака материализовались, то при отставшем конвейере человек,
// обязанный чинить аварию, сам остался бы без прав — именно тогда, когда он
// нужен. Независимость каскада от конвейера — свойство ДЕЙСТВУЮЩЕЙ формы, уже
// закреплённое в продукте. Проба заводилась как утверждение о ПАРИТЕТЕ, а не о
// преимуществе: замер, объявляющий преимуществом одной формы то, что есть у обеих,
// замером не является. Второй стороны нет, и утверждение стало абсолютным — но
// снимать его нельзя, оно про то, ради чего каскад и выбран.
//
// Состояние «материализация не проходила» здесь конструируется прямо: хранилище
// засеяно структурно и БЕЗ единой строки выдачи.
func TestCascadeHoldsWithEmptyMaterialization(t *testing.T) {
	if testing.Short() {
		t.Skip("поднимает контейнеры")
	}
	ctx := t.Context()
	stack, _ := bootForTest(ctx, t)

	cfg := DefaultConfig()
	cfg.Forms = []Form{FormE}
	r := NewRunner(stack, cfg)
	sc := NewScenario(6, 2, 3, "editor", DefaultVerbs())

	for _, f := range []Form{FormE} {
		st, err := r.NewSeededStore(ctx, f, sc, false, "cascade-empty-"+string(f))
		require.NoErrorf(t, err, "засев %s", f)
		_, err = st.Write(ctx, CascadeSeed(f, sc))
		require.NoErrorf(t, err, "каскадный принципал %s", f)

		allowed, _, err := st.Check(ctx, cascadeAdmin, "v_get", sc.Object(0))
		require.NoErrorf(t, err, "каскадный вопрос %s", f)
		require.Truef(t, allowed,
			"форма %s отказала каскадному принципалу на непройденной материализации — "+
				"аварийный путь у неё зависит от конвейера, а у соседа нет", f)

		// Парный отрицательный на КАЖДОЙ форме: без него «разрешено каскадному»
		// неотличимо от «разрешено всем».
		denied, _, err := st.Check(ctx, sc.Subjects[0], "v_get", sc.Object(0))
		require.NoErrorf(t, err, "контрольный вопрос %s", f)
		require.Falsef(t, denied,
			"форма %s разрешила обычному арендатору при пустой выдаче — тогда её каскад "+
				"ничего не сужает и утверждение о паритете вакуумно", f)

		// Второй отрицательный, и он про ДРУГОЕ: первый отличает каскадного
		// принципала от обычного арендатора, этот — «администратор ЭТОГО аккаунта»
		// от «администратора любого». Пока в фикстуре был один аккаунт, различить их
		// было нечем: корреляция аккаунта в каскадной ветви снималась без единой
		// красной пробы, и обе формы отвечали бы одинаково правильно по случайности.
		foreign, _, err := st.Check(ctx, cascadeAdmin, "v_get", sc.ForeignObject())
		require.NoErrorf(t, err, "кросс-аккаунтный каскадный вопрос %s", f)
		require.Falsef(t, foreign,
			"форма %s разрешила администратору аккаунта объект ЧУЖОГО аккаунта — её каскад "+
				"не сверяет аккаунт, то есть даёт доступ ко всему кластеру уровнем ниже кластера", f)

		require.NoError(t, st.Teardown(ctx))
	}
}

// TestAccountScopedGrantReachesObjectsOfItsProjects — вложенность области
// транзитивна, и второй родительский указатель зеркала имеет читателя.
//
// Колонка, которую не читает ни один запрос, — мёртвый вес, который тем не менее
// попадёт в объём и польстит соседу; колонка, которую читает запрос без пробы, —
// ветвь, о которой замер молчит. Здесь проверяется, что аккаунтная выдача
// накрывает объекты проектов аккаунта, а посторонний по-прежнему получает отказ.
func TestAccountScopedGrantReachesObjectsOfItsProjects(t *testing.T) {
	if testing.Short() {
		t.Skip("поднимает контейнеры")
	}
	ctx := t.Context()
	stack, _ := bootForTest(ctx, t)

	cfg := DefaultConfig()
	cfg.Forms = []Form{FormE}
	r := NewRunner(stack, cfg)
	sc := NewScenario(5, 2, 2, "editor", DefaultVerbs())

	st, err := r.NewSeededStore(ctx, FormE, sc, false, "scope-account-E")
	require.NoError(t, err)
	defer func() { _ = st.Teardown(ctx) }()

	_, err = st.Write(ctx, GrantScoped(sc, accountObj))
	require.NoError(t, err)

	ok, _, err := st.Check(ctx, sc.Subjects[0], "v_get", sc.Object(0))
	require.NoError(t, err)
	require.True(t, ok, "аккаунтная выдача не накрыла объект проекта этого аккаунта — "+
		"вложенность области не транзитивна, и родительский указатель аккаунта ничего не решает")

	ok, _, err = st.Check(ctx, "user:stranger-not-in-any-binding", "v_get", sc.Object(0))
	require.NoError(t, err)
	require.False(t, ok, "аккаунтная выдача разрешила постороннему — она не сужает ничего")

	ok, _, err = st.Check(ctx, sc.Subjects[0], "v_get", sc.Object(sc.N))
	require.NoError(t, err)
	require.False(t, ok, "аккаунтная выдача накрыла объект ВНЕ набора — правило-селектор "+
		"не сужает, и метка перестала что-либо значить")

	// Аккаунтный близнец кросс-арендного вопроса вопросника — и единственное
	// утверждение, от которого зависит КОРРЕЛЯЦИЯ области в аккаунтной ветви.
	//
	// Два предыдущих отрицания её не держат: первое снимает субъект, второе метку,
	// и оба остаются красными при `b.scope_id = m.parent_account_id`, замененном на
	// истину. Здесь выполнено всё, кроме принадлежности аккаунту: тот же субъект,
	// тот же глагол, та же метка — и другой аккаунт.
	//
	// У форм A–BCD аккаунтной области нет вовсе: их выдача материализуется на
	// объекты, и «чужой объект» у них отказывает отсутствием кортежа — спрашивать
	// у них тут нечего, что и делает эту пробу пробой ФОРМЫ E, а не сравнением.
	ok, _, err = st.Check(ctx, sc.Subjects[0], "v_get", sc.ForeignObject())
	require.NoError(t, err)
	require.False(t, ok, "аккаунтная выдача накрыла помеченный объект проекта ЧУЖОГО аккаунта — "+
		"область не сужает ничего, и выдача одного арендатора действует у соседа")
}

// TestFormERefusesIntentItDoesNotUnderstand — общий словарь не может расходиться
// молча.
//
// Перевод намерения живёт на стороне формы E, и молча проглоченная строка дала бы
// форму, выигравшую запись тем, что она её не сделала. Отрицание идёт в паре с
// положительным: одиночное «неизвестное отношение отвергнуто» зеленело бы и у
// формы, отвергающей всё.
func TestFormERefusesIntentItDoesNotUnderstand(t *testing.T) {
	if testing.Short() {
		t.Skip("поднимает контейнеры")
	}
	ctx := t.Context()
	stack, _ := bootForTest(ctx, t)

	cfg := DefaultConfig()
	cfg.Forms = []Form{FormE}
	r := NewRunner(stack, cfg)
	sc := NewScenario(4, 2, 2, "editor", DefaultVerbs())

	st, err := r.NewSeededStore(ctx, FormE, sc, false, "vocabulary-E")
	require.NoError(t, err)
	defer func() { _ = st.Teardown(ctx) }()

	// Положительный: словарь, который форма понимает, применяется и МЕНЯЕТ вердикт.
	before, _, err := st.Check(ctx, sc.Subjects[0], "v_get", sc.Object(0))
	require.NoError(t, err)
	require.False(t, before)
	_, err = st.Write(ctx, Grant(FormE, sc))
	require.NoError(t, err)
	after, _, err := st.Check(ctx, sc.Subjects[0], "v_get", sc.Object(0))
	require.NoError(t, err)
	require.True(t, after, "понятное намерение не изменило ни одного вердикта — "+
		"отрицание ниже утверждало бы про форму, которая не делает ничего")

	// Отрицательный: чужое отношение — ошибка, а не пропуск.
	_, err = st.Write(ctx, []Tuple{{User: "user:x", Relation: "no_such_relation", Object: bindingObj}})
	require.Error(t, err, "неизвестное отношение проглочено молча — намерение, которого форма "+
		"не поняла, засчиталось бы ей как выполненная работа")
	// Прежде здесь стояло ещё два отрицания: что ошибка не выдана за «неприменимо
	// by construction» и не за «модель не требуется». Оба сентинела сняты вместе с
	// движком, и разница, которую они стерегли, исчезла с ними: расхождение словаря
	// — дефект перевода, а те два были результатами замера. Отличать больше не от
	// чего, поэтому отрицания сняты, а не переписаны на другой предмет.
	require.NotEqualf(t, "", err.Error(), "ошибка без текста — вызывающий не узнает, "+
		"что именно форма не поняла")
}
