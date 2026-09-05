// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

// batchcheck_storequestions_test.go — ПАРТИЯ СТОИТ СТОЛЬКО ЖЕ ВОПРОСОВ, СКОЛЬКО
// ОДИН ПУНКТ.
//
// # Предмет
//
// `BatchCheck` — дверь, в которую входит фильтр списка КАЖДОГО сервиса-соседа:
// vpc, compute, nlb, storage, registry режут свою страницу на партии по сто и
// отдают их сюда. Внутри партия переставала быть партией: каждый идентификатор
// уезжал в хранилище ОТДЕЛЬНЫМ вопросом, а на отказе — ещё и вторым, за хвостом
// текста отказа. Страница договора в тысячу объектов стоила тысячи вопросов там,
// где собственный список iam обходится десятками.
//
// # Почему это дороже, чем «немного медленнее»
//
// Бюджет вызывающего принадлежит ЗАПРОСУ, а не пункту: сосед даёт партии одну
// секунду. Пообъектная полоса тратит её при ответе хранилища около семидесяти
// миллисекунд, пакетная — при полусекунде. То есть деградация хранилища
// превращала здоровый ПОЛОЖИТЕЛЬНЫЙ список в отказ `UNAVAILABLE` в разы раньше,
// чем должна бы.
//
// # Предикат — САМОКАЛИБРУЮЩИЙСЯ, а не число из воздуха
//
// Утверждается не «мало вопросов», а «партия из ста не дороже партии из одного»:
// обе величины снимаются в этом же прогоне, на той же посадке, и сравниваются
// между собой. Число, объявленное константой, устарело бы вместе с формой;
// отношение — нет.
//
// # Отрицание в паре с положительным контролем
//
// «Вопросов не больше» выполняется тождественно для двери, которая не спрашивает
// вовсе. Поэтому рядом стоят два контроля: партия из одного ОБЯЗАНА задать хотя
// бы один вопрос, и СОСТАВ ответа партии обязан совпасть с ответом того же
// вопроса, заданного по одному, — включая текст отказа, а не только «да/нет».

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

// countingRelations — дверь решения, считающая вопросы ПО ПОЛОСАМ.
//
// Полос четыре, а не одна, потому что они отвечают на разные вопросы: сколько
// раз спрошено о ВЕРДИКТЕ (пообъектно и партией) и сколько раз — о ХВОСТЕ ТЕКСТА
// ОТКАЗА (пообъектно и партией). Одно общее число не отличило бы «партия
// отвечена одним вопросом» от «партия не спросила вовсе».
type countingRelations struct {
	// allowed — какие объекты доступны. Ключ — «тип:идентификатор».
	allowed map[string]bool
	// direct — прямые отношения субъекта на объекте, для хвоста текста отказа.
	direct map[string][]string

	mu            sync.Mutex
	perObject     int
	batched       int
	diagPerObject int
	diagBatched   int
}

func (c *countingRelations) CheckWithContext(_ context.Context, _, _, object string,
	_ map[string]any) (bool, error) {
	c.mu.Lock()
	c.perObject++
	c.mu.Unlock()
	return c.allowed[object], nil
}

func (c *countingRelations) BatchCheckWithContext(_ context.Context, _, _ string,
	objects []string, _ map[string]any) ([]bool, error) {
	c.mu.Lock()
	c.batched++
	c.mu.Unlock()
	out := make([]bool, len(objects))
	for i, o := range objects {
		out[i] = c.allowed[o]
	}
	return out, nil
}

func (c *countingRelations) ListSubjects(context.Context, string, string, string, int, string) (
	[]string, string, error) {
	return nil, "", nil
}

func (c *countingRelations) Sources(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func (c *countingRelations) DirectRelations(_ context.Context, _, objectType, objectID string,
	_ int) ([]string, error) {
	c.mu.Lock()
	c.diagPerObject++
	c.mu.Unlock()
	return c.direct[objectType+":"+objectID], nil
}

func (c *countingRelations) DirectRelationsMany(_ context.Context, _, objectType string,
	objectIDs []string, _ int) (map[string][]string, error) {
	c.mu.Lock()
	c.diagBatched++
	c.mu.Unlock()
	out := make(map[string][]string, len(objectIDs))
	for _, id := range objectIDs {
		if rels := c.direct[objectType+":"+id]; len(rels) > 0 {
			out[id] = rels
		}
	}
	return out, nil
}

// questions — сколько ВСЕГО раз дверь была спрошена. Именно эта величина и есть
// предмет: она не зависит от того, какой полосой воспользовались.
func (c *countingRelations) questions() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.perObject + c.batched + c.diagPerObject + c.diagBatched
}

func (c *countingRelations) lanes() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return fmt.Sprintf("вердикт: пообъектно %d, партией %d; хвост отказа: пообъектно %d, партией %d",
		c.perObject, c.batched, c.diagPerObject, c.diagBatched)
}

func (c *countingRelations) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.perObject, c.batched, c.diagPerObject, c.diagBatched = 0, 0, 0, 0
}

// mixedPage — страница, какой её присылает фильтр списка соседа: один субъект,
// одно отношение, один тип, различаются только идентификаторы.
//
// Доступна ЧЕТВЕРТЬ объектов, и вперемежку: страница, где сначала все «да», а
// потом все «нет», зеленела бы и на реализации, потерявшей соответствие позиций.
func mixedPage(n int) ([]CheckRequest, *countingRelations) {
	reqs := make([]CheckRequest, n)
	store := &countingRelations{
		allowed: make(map[string]bool, n),
		direct:  make(map[string][]string, n),
	}
	for i := range reqs {
		id := fmt.Sprintf("net-%03d", i)
		reqs[i] = CheckRequest{
			Subject:          "user:usr_tenant",
			Resource:         ResourceRef{Type: "vpc_network", ID: id},
			Action:           "vpc.networks.get",
			RequiredRelation: "v_get",
		}
		object := "vpc_network:" + id
		store.allowed[object] = i%4 == 0
		if i%3 == 0 {
			store.direct[object] = []string{"viewer"}
		}
	}
	return reqs, store
}

// TestBatchCheck_AHundredCostsWhatOneCosts — партия из ста обращается к двери
// решения не чаще, чем партия из одного.
func TestBatchCheck_AHundredCostsWhatOneCosts(t *testing.T) {
	const page = 100

	reqs, store := mixedPage(page)
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: store})

	// Положительный контроль: партия из ОДНОГО. Без него «не больше» зеленело бы
	// на двери, которую не спрашивают вовсе.
	if _, err := svc.BatchCheck(context.Background(), reqs[1:2]); err != nil {
		t.Fatalf("партия из одного: %v", err)
	}
	one := store.questions()
	oneLanes := store.lanes()
	if one == 0 {
		t.Fatalf("партия из одного не спросила дверь ни разу: предмета замера нет, и "+
			"сравнение ниже выполнялось бы тождественно (%s)", oneLanes)
	}

	store.reset()
	results, err := svc.BatchCheck(context.Background(), reqs)
	if err != nil {
		t.Fatalf("партия из %d: %v", page, err)
	}
	many := store.questions()

	t.Logf("вопросов к двери решения: партия из 1 — %d (%s); партия из %d — %d (%s)",
		one, oneLanes, page, many, store.lanes())

	if len(results) != page {
		t.Fatalf("ответ на партию из %d имеет длину %d", page, len(results))
	}
	// Обе стороны разбиения обязаны быть непусты: страница, где разрешены все либо
	// никто, проверяла бы одну ветвь и молчала о другой.
	allowedCount := 0
	for _, r := range results {
		if r.Allowed {
			allowedCount++
		}
	}
	if allowedCount == 0 || allowedCount == page {
		t.Fatalf("на странице разрешено %d из %d — сверяется только одна ветвь", allowedCount, page)
	}

	if many > one {
		t.Fatalf("партия из %d стоит %d вопросов к двери, партия из одного — %d.\n"+
			"  Партия существует по форме и отсутствует по существу: каждый идентификатор "+
			"уезжает отдельным вопросом, а на отказе — ещё и вторым, за хвостом текста отказа.\n"+
			"  Набор однороден by construction (один субъект, тип, отношение), и обе полосы "+
			"отвечаются одним вопросом каждая.\n"+
			"  полосы партии: %s", page, many, one, store.lanes())
	}
}

// TestBatchCheck_PageAnswersTheSameAsOneByOne — СОСТАВ ответа не изменился.
//
// Число вопросов ничего не стоит, если ответ на них поменялся. Сверяется не
// только «да/нет», но и ТЕКСТ отказа: хвост текста берётся из прямых отношений
// субъекта на объекте, то есть ровно из той диагностики, которую партия
// спрашивает иначе, — и расхождение здесь было бы невидимо по одному «да/нет».
func TestBatchCheck_PageAnswersTheSameAsOneByOne(t *testing.T) {
	const page = 40

	reqs, store := mixedPage(page)
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: store})

	batch, err := svc.BatchCheck(context.Background(), reqs)
	if err != nil {
		t.Fatalf("партия: %v", err)
	}
	if len(batch) != page {
		t.Fatalf("длина ответа %d при %d пунктах", len(batch), page)
	}

	var mismatched []string
	denied, withTail := 0, 0
	for i, req := range reqs {
		one, cerr := svc.Check(context.Background(), req)
		if cerr != nil {
			t.Fatalf("одиночный вопрос %d: %v", i, cerr)
		}
		if !one.Allowed {
			denied++
		}
		if len(one.DenyReasons) == 1 && strings.Contains(one.DenyReasons[0], "current direct relations") {
			withTail++
		}
		if one.Allowed != batch[i].Allowed {
			mismatched = append(mismatched, fmt.Sprintf("%s: партия=%v, по одному=%v",
				req.Resource.ID, batch[i].Allowed, one.Allowed))
			continue
		}
		if !equalReasons(one.DenyReasons, batch[i].DenyReasons) {
			mismatched = append(mismatched, fmt.Sprintf("%s: текст отказа партии %q, по одному %q",
				req.Resource.ID, batch[i].DenyReasons, one.DenyReasons))
		}
	}

	t.Logf("объектов %d, отказано %d, из них с хвостом прямых отношений %d", page, denied, withTail)

	// Предпосылка сверки: если ни один отказ не нёс хвоста, то диагностика не
	// проверена вовсе, и равенство текстов держалось бы на пустоте.
	if denied == 0 || withTail == 0 {
		t.Fatalf("отказов %d, из них с хвостом прямых отношений %d — сверять текст отказа не на чем",
			denied, withTail)
	}
	if len(mismatched) > 0 {
		sort.Strings(mismatched)
		t.Fatalf("партия отвечает не то же, что одиночный вопрос:\n  %s",
			strings.Join(mismatched, "\n  "))
	}
}

func equalReasons(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// condRecordingRelations — дверь, которая ЗАПОМИНАЕТ, с какими доводами условий
// её спросили о каждом объекте, и отвечает по ним.
//
// Существует ради одного: доводы условий — часть ВОПРОСА, и пункт, отвеченный по
// чужим доводам, получил бы вердикт, которого о нём никто не выносил.
type condRecordingRelations struct {
	// want — какой довод обязан прийти вместе с объектом, чтобы ответ был «да».
	//
	// Хранится СЫРЫМ значением, а сверяется `reflect.DeepEqual`. Прежняя редакция
	// сводила довод к `fmt.Sprintf("%v", …)` — то есть меряла его ровно тем
	// печатанием, чья неоднозначность и есть предмет соседней пробы: составные
	// доводы `["prod","eu"]` и `["prod eu"]` дают одну строку, поэтому дублёр
	// объявил бы «дошёл свой довод» в обоих случаях и подмену не показал.
	want map[string]any

	mu    sync.Mutex
	calls int
	seen  map[string]any
}

func (c *condRecordingRelations) record(object string, condCtx map[string]any) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]any{}
	}
	got := condCtx["a_note"]
	c.seen[object] = got
	return reflect.DeepEqual(c.want[object], got)
}

func (c *condRecordingRelations) CheckWithContext(_ context.Context, _, _, object string,
	condCtx map[string]any) (bool, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.record(object, condCtx), nil
}

func (c *condRecordingRelations) BatchCheckWithContext(_ context.Context, _, _ string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	out := make([]bool, len(objects))
	for i, object := range objects {
		out[i] = c.record(object, condCtx)
	}
	return out, nil
}

func (c *condRecordingRelations) ListSubjects(context.Context, string, string, string, int, string) (
	[]string, string, error) {
	return nil, "", nil
}

func (c *condRecordingRelations) Sources(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func (c *condRecordingRelations) DirectRelations(context.Context, string, string, string, int) (
	[]string, error) {
	return nil, nil
}

func (c *condRecordingRelations) DirectRelationsMany(context.Context, string, string, []string, int) (
	map[string][]string, error) {
	return nil, nil
}

// TestBatchCheck_ItemsWithDifferentConditionContextsAreNotMerged — пункт
// отвечается СВОИМИ доводами условий, а не соседскими; здесь столкновение
// подбирается на СКЛЕЙКЕ частей ключа.
//
// Парная ей проба ниже подбирает столкновение на САМОМ ЗНАЧЕНИИ. Две пробы, а не
// одна, потому что уровня два и закрываются они разными средствами: склейка —
// длиной части, значение — канонической кодировкой. Первая редакция закрыла
// только склейку и объявила предмет исчерпанным; вторую нашёл рецензент.
//
// # Почему это проба безопасности, а не аккуратности
//
// В прогон сводятся пункты, у которых вопрос один; доводы условий — часть
// вопроса. Ключ прогона строится из них, и часть доводов приходит ИЗ ТЕЛА
// ЗАПРОСА, то есть от арендатора. Ключ, склеенный разделителем, арендатор умеет
// столкнуть: положив разделитель внутрь своего значения, он делает два РАЗНЫХ
// набора доводов неотличимыми, и один пункт оказывается отвечен доводами другого.
//
// Пара ниже — ровно такая: при склейке через `%s=%v` с нулевым байтом их ключи
// совпадают побайтово. Кодировка длиной делает столкновение невозможным by
// construction, и проба это утверждает исходом, а не осмотром ключа.
func TestBatchCheck_ItemsWithDifferentConditionContextsAreNotMerged(t *testing.T) {
	const (
		subject = "user:usr_tenant"
		objA    = "net-a"
		objB    = "net-b"
	)
	// Доводы, СТАЛКИВАЮЩИЕСЯ при склейке разделителем: у первого значение несёт
	// внутри себя разделитель и имя второго довода.
	//
	// Имена выбраны так, что первый довод по алфавиту идёт ПЕРЕД вторым: значение
	// первого тогда «проглатывает» второй, и при склейке ключи совпадают дословно
	// (сам разделитель — нулевой байт — тоже внутри значения). Совпадение
	// проверено инъекцией: на склеенной кодировке эта проба краснеет.
	ctxA := map[string]any{"a_note": "x\x00b_extra=y"}
	ctxB := map[string]any{"a_note": "x", "b_extra": "y"}

	store := &condRecordingRelations{want: map[string]any{
		"vpc_network:" + objA: "x\x00b_extra=y",
		"vpc_network:" + objB: "x",
	}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: store})

	reqs := []CheckRequest{
		{Subject: subject, Resource: ResourceRef{Type: "vpc_network", ID: objA},
			Action: "vpc.networks.get", RequiredRelation: "v_get", Context: ctxA},
		{Subject: subject, Resource: ResourceRef{Type: "vpc_network", ID: objB},
			Action: "vpc.networks.get", RequiredRelation: "v_get", Context: ctxB},
	}
	results, err := svc.BatchCheck(context.Background(), reqs)
	if err != nil {
		t.Fatalf("партия: %v", err)
	}

	store.mu.Lock()
	calls, seen := store.calls, store.seen
	store.mu.Unlock()
	t.Logf("вопросов к двери %d; доводы, дошедшие до объектов: %#v", calls, seen)

	// Предпосылка: дверь спрошена, иначе всё ниже выполнялось бы тождественно.
	if calls == 0 {
		t.Fatalf("дверь не спрошена ни разу — предмета замера нет")
	}
	for i, r := range results {
		if !r.Allowed {
			t.Fatalf("пункт %d (%s) отвечен отказом: до него доехали доводы %#v вместо своих — "+
				"два разных набора доводов слились в один прогон, и вердикт вынесен по чужому "+
				"вопросу", i, reqs[i].Resource.ID, seen["vpc_network:"+reqs[i].Resource.ID])
		}
	}
	// Прогонов обязано быть ДВА: слить их в один — значит ответить одному пункту
	// доводами другого, и «оба разрешены» тогда получилось бы случайно.
	if calls < 2 {
		t.Fatalf("дверь спрошена %d раз(а) на два РАЗНЫХ набора доводов: они сведены в один "+
			"прогон, и совпадение ответов ничего не доказывает", calls)
	}
}

// TestBatchCheck_ItemsWithDifferentCompositeConditionsAreNotMerged — столкновение
// подбирается на САМОМ ЗНАЧЕНИИ довода, а не на склейке частей ключа.
//
// # Почему одной соседней пробы не хватило — и это тот же класс, что она ловит
//
// Соседняя проба закрывает СКЛЕЙКУ: длина перед каждой частью делает «имя=значение»
// неподделываемым. Она строит пару из СКАЛЯРНЫХ строк, поэтому живёт вне
// пространства составных значений — и класс, который здесь, прошёл мимо неё
// незамеченным. Закрыть уровень и объявить предмет исчерпанным, не проверив
// второй, — ровно то, за чем этот корпус и следит.
//
// # Составной довод — законный вход, а не выдумка пробы
//
// Тело запроса несёт `google.protobuf.Struct`, и его разбор (`AsMap`) отдаёт
// `[]any` и `map[string]any`. То есть арендатор кладёт список и отображение по
// контракту, а не в обход него.
//
// # Три пары, каждая печатается через `%v` ОДИНАКОВО
//
//	["prod","eu"]        и  ["prod eu"]
//	{"a":"b","c":"d"}    и  {"a":"b c:d"}
//	{"x": 1.0}           и  {"x": "1"}
//
// Проба берёт первую и доводит до НАБЛЮДАЕМОГО исхода: слияние прогонов означает,
// что второй пункт отвечен доводами первого, а не что «ключи похожи».
//
// # Опасность сегодня названа честно, и она НЕ повод не чинить
//
// Единственное зарегистрированное условие читает четыре скалярных довода, и все
// четыре сервер переставляет сам, одинаковыми на всю партию, — значит вердикт
// сегодня не меняется. Чинится потому, что: класс ЗАВЕДЁН сведением партии в
// прогоны (до него сводить было нечего); защита сработает наоборот в тот день,
// когда условие прочитает сквозной довод; а сквозные доводы объявлены законными
// прямо в разборе запроса.
func TestBatchCheck_ItemsWithDifferentCompositeConditionsAreNotMerged(t *testing.T) {
	const (
		subject = "user:usr_tenant"
		objA    = "net-a"
		objB    = "net-b"
	)
	// Составные доводы, НЕРАЗЛИЧИМЫЕ печатанием `%v`: список из двух элементов и
	// список из одного, склеенного пробелом. Оба печатаются как `[prod eu]`.
	ctxA := map[string]any{"a_note": []any{"prod", "eu"}}
	ctxB := map[string]any{"a_note": []any{"prod eu"}}

	// Предпосылка пробы: пара и вправду неразличима тем печатанием, чью
	// неоднозначность она проверяет. Без этого проба зеленела бы на паре, которую
	// различает даже негодная кодировка, и ничего не утверждала бы.
	if fmt.Sprintf("%T=%v", ctxA["a_note"], ctxA["a_note"]) !=
		fmt.Sprintf("%T=%v", ctxB["a_note"], ctxB["a_note"]) {
		t.Fatalf("предпосылка нарушена: пара доводов различима печатанием %%v (%v против %v) — "+
			"столкновение не подобрано, и проба ничего не проверяет",
			ctxA["a_note"], ctxB["a_note"])
	}

	store := &condRecordingRelations{want: map[string]any{
		"vpc_network:" + objA: []any{"prod", "eu"},
		"vpc_network:" + objB: []any{"prod eu"},
	}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: store})

	reqs := []CheckRequest{
		{Subject: subject, Resource: ResourceRef{Type: "vpc_network", ID: objA},
			Action: "vpc.networks.get", RequiredRelation: "v_get", Context: ctxA},
		{Subject: subject, Resource: ResourceRef{Type: "vpc_network", ID: objB},
			Action: "vpc.networks.get", RequiredRelation: "v_get", Context: ctxB},
	}
	results, err := svc.BatchCheck(context.Background(), reqs)
	if err != nil {
		t.Fatalf("партия: %v", err)
	}

	store.mu.Lock()
	calls, seen := store.calls, store.seen
	store.mu.Unlock()
	t.Logf("вопросов к двери %d; доводы, дошедшие до объектов: %#v", calls, seen)

	if calls == 0 {
		t.Fatalf("дверь не спрошена ни разу — предмета замера нет")
	}
	for i, r := range results {
		if !r.Allowed {
			t.Fatalf("пункт %d (%s) отвечен отказом: до него доехали доводы %#v вместо своих — "+
				"два составных довода, неразличимых печатанием, слились в один прогон, и вердикт "+
				"вынесен по чужому вопросу", i, reqs[i].Resource.ID, seen["vpc_network:"+reqs[i].Resource.ID])
		}
	}
	if calls < 2 {
		t.Fatalf("дверь спрошена %d раз(а) на два РАЗНЫХ составных довода: они сведены в один "+
			"прогон, и совпадение ответов ничего не доказывает", calls)
	}
}
