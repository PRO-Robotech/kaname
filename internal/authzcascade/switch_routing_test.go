// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// switch_routing_test.go — МАРШРУТИЗАЦИЯ дверей решения при переключённом типе.
//
// Предмет — ИСХОД у вызывающего и то, кого спросили НА ПУТИ ЗАПРОСА. «Форма
// вызвана» исходом не является: вызвать форму и вернуть ответ движка — это и
// есть молчаливый возврат к движку, который здесь запрещён.
//
// Поэтому дублёр движка записывает каждый свой вызов, а проба утверждает, что
// на пути запроса его НЕ спрашивали: теневой вопрос уходит вне пути и приходит
// позже, поэтому «спрошен» и «спрошен вовремя» надо различать по времени
// наблюдения, а не по факту вызова.

package authzcascade

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// switchingComparator — сравнение, у которого рубильник переключён на названные
// типы. Отвечает ЗАДАННЫМ вердиктом формы и записывает, спросили ли движок.
type switchingComparator struct {
	stubComparator

	formAllows map[string]bool // objectType:objectID -> вердикт формы
	formErr    error
	switched   map[string]bool

	mu          sync.Mutex
	verdicts    []string // "<subject>|<type>|<id>|<relation>"
	engineAsked int
}

func (s *switchingComparator) Decides(objectType string) bool { return s.switched[objectType] }

func (s *switchingComparator) Verdict(
	ctx context.Context, subject, objectType, objectID, relation string,
	_ map[string]any, askEngine func(context.Context) (bool, bool),
) (bool, error) {
	s.mu.Lock()
	s.verdicts = append(s.verdicts, subject+"|"+objectType+"|"+objectID+"|"+relation)
	s.mu.Unlock()
	if s.formErr != nil {
		return false, s.formErr
	}
	// Движок спрашивается РЯДОМ — здесь синхронно, чтобы проба могла утверждать
	// сам факт; в бою этот вызов уходит вне пути запроса (см. switch.go).
	if askEngine != nil {
		askEngine(ctx)
		s.mu.Lock()
		s.engineAsked++
		s.mu.Unlock()
	}
	return s.formAllows[objectType+":"+objectID], nil
}

func (s *switchingComparator) seen() ([]string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.verdicts...), s.engineAsked
}

func switchedClient(t *testing.T, engineAllows bool, formAllows map[string]bool, types ...string) (*Client, *stubRelations, *switchingComparator) {
	t.Helper()
	engine := &stubRelations{allow: engineAllows}
	cmp := &switchingComparator{formAllows: formAllows, switched: map[string]bool{}}
	for _, ty := range types {
		cmp.switched[ty] = true
	}
	return Wrap(engine, nil).WithComparator(cmp), engine, cmp
}

// ДВЕРЬ `Check` на переключённом типе отдаёт вердикт ФОРМЫ.
//
// Ответы намеренно противоположны: совпадающие сделали бы утверждение
// тождественно истинным — оно зеленело бы и при неработающей маршрутизации.
func TestCheckOnSwitchedTypeReturnsTheFormsVerdict(t *testing.T) {
	c, engine, cmp := switchedClient(t, false,
		map[string]bool{"iam_group:grp-1": true}, "iam_group")

	allowed, err := c.Check(context.Background(), "user:u1", "v_get", "iam_group:grp-1")

	require.NoError(t, err)
	require.True(t, allowed, "вернулся ответ движка — источник вердикта не переключён")

	verdicts, _ := cmp.seen()
	require.Equal(t, []string{"user:u1|iam_group|grp-1|v_get"}, verdicts,
		"вопрос формы обязан нести те же субъект, тип, идентификатор и отношение")
	require.Empty(t, cmp.questions,
		"на переключённом типе решение не предъявляется как ДВИЖКОВОЕ: это второй счёт того же решения")
	_ = engine
}

// Зеркальная половина: форма отказывает — вызывающий получает отказ, хотя
// движок разрешает.
func TestCheckOnSwitchedTypeReturnsTheFormsDenial(t *testing.T) {
	c, _, _ := switchedClient(t, true, map[string]bool{}, "iam_group")

	allowed, err := c.Check(context.Background(), "user:u1", "v_get", "iam_group:grp-1")

	require.NoError(t, err)
	require.False(t, allowed, "вернулся ответ движка вместо отказа формы")
}

// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: НЕ переключённый тип идёт прежним путём — решает
// движок, форма спрашивается рядом. Без него проба выше зеленела бы на
// рубильнике, переключающем всё разом.
func TestCheckOnUnswitchedTypeStillGoesToTheEngine(t *testing.T) {
	c, engine, cmp := switchedClient(t, true, map[string]bool{}, "iam_group")

	allowed, err := c.Check(context.Background(), "user:u1", "v_get", "iam_role:rol-1")

	require.NoError(t, err)
	require.True(t, allowed, "не переключённый тип обязан отвечаться движком")
	require.NotEmpty(t, engine.asked, "движок обязан быть спрошен НА ПУТИ ЗАПРОСА")

	verdicts, _ := cmp.seen()
	require.Empty(t, verdicts, "форма не вправе решать по не названному типу")
	require.Len(t, cmp.questions, 1, "решение движка обязано быть предъявлено сравнению")
}

// ОТКАЗ ФОРМЫ — недоступность, а не отказ в доступе и не поход к движку.
func TestFormFailureOnSwitchedTypeSurfacesAsAnErrorNotADenial(t *testing.T) {
	boom := errors.New("форма не ответила")
	c, engine, _ := switchedClient(t, true, map[string]bool{}, "iam_group")
	c.compare.(*switchingComparator).formErr = boom

	allowed, err := c.Check(context.Background(), "user:u1", "v_get", "iam_group:grp-1")

	require.Error(t, err, "отказ формы обязан доехать до вызывающего")
	require.False(t, allowed)
	require.Empty(t, engine.asked,
		"движок спрошен на пути запроса — это молчаливый возврат к нему, запрещённый решением Р5")
}

// `CheckWithContext` — та же дверь и та же маршрутизация. Дверей у обёртки
// несколько, и появлялись они в разное время: пробы перечисляют их по одной.
func TestCheckWithContextOnSwitchedTypeReturnsTheFormsVerdict(t *testing.T) {
	c, _, cmp := switchedClient(t, false,
		map[string]bool{"iam_group:grp-1": true}, "iam_group")

	allowed, err := c.CheckWithContext(context.Background(), "user:u1", "v_get", "iam_group:grp-1", nil)

	require.NoError(t, err)
	require.True(t, allowed)

	verdicts, _ := cmp.seen()
	require.Len(t, verdicts, 1)
}

// ВЕСЬ КРУГ ОТКАТА: переключить · убедиться · откатить · убедиться.
//
// Утверждается совпадение с ИСХОДНЫМ состоянием, а не «откат отработал»:
// половина круга зеленела бы и на рубильнике, который ничего не менял.
func TestFullCircleSwitchAndRollBack(t *testing.T) {
	engine := &stubRelations{allow: true}
	cmp := &switchingComparator{formAllows: map[string]bool{}, switched: map[string]bool{}}
	c := Wrap(engine, nil).WithComparator(cmp)

	before, err := c.Check(context.Background(), "user:u1", "v_get", "iam_group:grp-1")
	require.NoError(t, err)
	require.True(t, before, "исходное состояние: решает движок")

	cmp.switched["iam_group"] = true
	during, err := c.Check(context.Background(), "user:u1", "v_get", "iam_group:grp-1")
	require.NoError(t, err)
	require.False(t, during, "после переключения решает форма — ответы обязаны разойтись")

	delete(cmp.switched, "iam_group")
	after, err := c.Check(context.Background(), "user:u1", "v_get", "iam_group:grp-1")
	require.NoError(t, err)
	require.Equal(t, before, after,
		"после отката ответ обязан дословно совпасть с исходным — иначе это не откат")
}

// Вопрос, тип которого не разобран, НЕ переключается ни при каком рубильнике:
// форме его задать нечем, и он остаётся решением движка со своей причиной.
func TestUnparseableObjectIsNeverRoutedToTheForm(t *testing.T) {
	c, engine, cmp := switchedClient(t, true, map[string]bool{}, "iam_group")

	_, err := c.Check(context.Background(), "user:u1", "v_get", "не-объект")
	require.NoError(t, err)

	verdicts, _ := cmp.seen()
	require.Empty(t, verdicts)
	require.NotEmpty(t, engine.asked)
	_, unaskable := cmp.snapshot()
	require.NotEmpty(t, unaskable, "решение обязано остаться в знаменателе со своей причиной")
}

// ─────────────────────────────────────────────────────────────────────────────
// БАТЧЕВАЯ ДВЕРЬ
//
// Фильтр списка спрашивает страницу целиком. Если переключение типа её не
// накрывает, то у переключённого типа остаётся полоса, где решает движок, —
// и «отзыв действует с коммита» перестаёт быть верным ровно для списков, то
// есть для самого частого чтения.
// ─────────────────────────────────────────────────────────────────────────────

func (s *switchingComparator) VerdictMany(
	ctx context.Context, subject, objectType string, objectIDs []string, relation string,
	_ map[string]any, askEngine func(context.Context) ([]bool, bool),
) ([]bool, error) {
	s.mu.Lock()
	for _, id := range objectIDs {
		s.verdicts = append(s.verdicts, subject+"|"+objectType+"|"+id+"|"+relation)
	}
	s.mu.Unlock()
	if s.formErr != nil {
		return nil, s.formErr
	}
	if askEngine != nil {
		askEngine(ctx)
		s.mu.Lock()
		s.engineAsked++
		s.mu.Unlock()
	}
	out := make([]bool, len(objectIDs))
	for i, id := range objectIDs {
		out[i] = s.formAllows[objectType+":"+id]
	}
	return out, nil
}

// Страница переключённого типа отвечается ФОРМОЙ целиком, и ответ приходит в
// порядке вызывающего: верный, но переставленный ответ фильтрует страницу
// чужим вердиктом.
func TestBatchPageOfSwitchedTypeIsDecidedByTheForm(t *testing.T) {
	c, _, cmp := switchedClient(t, false, map[string]bool{
		"iam_group:grp-1": true,
		"iam_group:grp-3": true,
	}, "iam_group")

	out, err := c.BatchCheckWithContext(context.Background(), "user:u1", "v_get",
		[]string{"iam_group:grp-1", "iam_group:grp-2", "iam_group:grp-3"}, nil)

	require.NoError(t, err)
	require.Equal(t, []bool{true, false, true}, out,
		"страница переключённого типа обязана отвечаться формой и в порядке вызывающего")

	verdicts, _ := cmp.seen()
	require.Len(t, verdicts, 3, "форму обязаны спросить о КАЖДОМ объекте страницы")
}

// СМЕШАННАЯ страница: часть объектов переключённого типа, часть — нет. Каждая
// половина уходит своему источнику, а ответ собирается в порядке вызывающего.
//
// Молчаливое взятие типа первого элемента здесь дало бы страницу, отвеченную
// одним источником за оба типа, — и заявление о переключении стало бы ложным
// для половины страницы.
func TestMixedBatchPageRoutesEachTypeToItsOwnSource(t *testing.T) {
	c, engine, cmp := switchedClient(t, true, map[string]bool{}, "iam_group")

	out, err := c.BatchCheckWithContext(context.Background(), "user:u1", "v_get",
		[]string{"iam_group:grp-1", "iam_role:rol-1", "iam_group:grp-2"}, nil)

	require.NoError(t, err)
	require.Equal(t, []bool{false, true, false}, out,
		"переключённый тип отвечает форма (отказ), не переключённый — движок (разрешение)")

	verdicts, engineShadowCalls := cmp.seen()
	require.Len(t, verdicts, 2, "форму спрашивают только о переключённых объектах")

	// Движок видит ВСЮ страницу — и это не дефект маршрутизации, а её предмет:
	// один объект он решает (не переключён), о двух спрошен ТЕНЬЮ. Дублёр
	// сравнения зовёт теневой вопрос синхронно, чтобы проба могла его увидеть;
	// в бою он уходит вне пути запроса.
	require.Len(t, engine.asked, 3,
		"движок обязан увидеть и свою часть страницы, и переключённую — второе тенью")
	require.Equal(t, 1, engineShadowCalls,
		"переключённая часть страницы обязана уходить движку ОДНИМ батчевым вопросом, а не по объекту")
}

// Отказ формы на странице — недоступность, а не «страница пуста».
func TestFormFailureOnBatchPageSurfacesAsAnError(t *testing.T) {
	c, _, cmp := switchedClient(t, true, map[string]bool{}, "iam_group")
	cmp.formErr = errors.New("форма не ответила")

	out, err := c.BatchCheckWithContext(context.Background(), "user:u1", "v_get",
		[]string{"iam_group:grp-1"}, nil)

	require.Error(t, err, "отказ формы обязан доехать до вызывающего, а не стать пустой страницей")
	require.Nil(t, out)
}
