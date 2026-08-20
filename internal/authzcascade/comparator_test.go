// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// comparator_test.go — поведение единой точки: каждое решение о доступе, взятое
// через обёртку, предъявляется сравнению.
//
// Проба поведенческая, а не структурная: она не спрашивает «есть ли в теле вызов»,
// она подаёт в обёртку настоящий вопрос и требует, чтобы сравнение его увидело —
// с тем же субъектом, типом, идентификатором и отношением, с какими его получил
// движок, и со сведением исхода, который движок вернул.
//
// Почему это отдельно от инвентаря полос (who_asks_the_store_test.go): инвентарь
// отвечает на «кто спрашивает хранилище», а здесь — «доходит ли спрошенное до
// сравнения». Инвентарь был зелёным всё то время, пока пятнадцать мест решали
// доступ мимо компаратора.

package authzcascade

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
)

// ── дублёры ───────────────────────────────────────────────────────────────────

// stubRelations — движок с заранее известным ответом.
//
// Встроенный `Relations` намеренно nil: метод, которого проба не ожидала, даст
// панику с именем, а не тихий нулевой ответ. Дублёр, отвечающий на то, о чём его
// не спрашивали, скрывает именно тот вызов, ради которого его и подставляют.
type stubRelations struct {
	Relations
	allow bool
	err   error

	mu    sync.Mutex
	asked []string // "<door> <subject> <relation> <object>"
}

func (s *stubRelations) record(door, subject, relation, object string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked = append(s.asked, door+" "+subject+" "+relation+" "+object)
}

func (s *stubRelations) Check(_ context.Context, subject, relation, object string) (bool, error) {
	s.record("check", subject, relation, object)
	return s.allow, s.err
}

func (s *stubRelations) CheckWithContext(
	_ context.Context, subject, relation, object string, _ map[string]any,
) (bool, error) {
	s.record("checkctx", subject, relation, object)
	return s.allow, s.err
}

func (s *stubRelations) CheckWithContextualTuples(
	_ context.Context, subject, relation, object string,
	_ map[string]any, _ []authztypes.TupleKey,
) (bool, error) {
	s.record("checkfacts", subject, relation, object)
	return s.allow, s.err
}

func (s *stubRelations) BatchCheckWithContext(
	_ context.Context, subject, relation string, objects []string, _ map[string]any,
) ([]bool, error) {
	out := make([]bool, len(objects))
	for i, o := range objects {
		s.record("batch", subject, relation, o)
		out[i] = s.allow
	}
	return out, s.err
}

// askedQuestion — что сравнение увидело.
type askedQuestion struct {
	Subject, ObjectType, ObjectID, Relation string
	EngineAllowed, EngineAnswered           bool
	Settled                                 bool
}

// stubComparator — сравнение, которое только записывает.
type stubComparator struct {
	mu        sync.Mutex
	questions []*askedQuestion
	unaskable []string // "<reason>|<objectType>|<relation>"
}

func (s *stubComparator) Ask(_ context.Context, subject, objectType, objectID, relation string,
	_ map[string]any,
) func(bool, bool) {
	q := &askedQuestion{Subject: subject, ObjectType: objectType, ObjectID: objectID, Relation: relation}
	s.mu.Lock()
	s.questions = append(s.questions, q)
	s.mu.Unlock()
	return func(engineAllowed, engineAnswered bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		q.EngineAllowed, q.EngineAnswered, q.Settled = engineAllowed, engineAnswered, true
	}
}

// Decides / Verdict — рубильник, стоящий в позиции «движок» по КАЖДОМУ типу.
//
// Это положительный контроль по умолчанию: пробы этого файла утверждают прежний
// путь, и он обязан остаться прежним, пока тип не назван переключённым. `Verdict`
// на таком дублёре — ошибка сборки пробы, а не тихий ответ: вызов, которого
// проба не ожидала, обязан назвать себя, а не вернуть ноль.
func (s *stubComparator) Decides(string) bool { return false }

func (s *stubComparator) VerdictMany(
	context.Context, string, string, []string, string,
	map[string]any, func(context.Context) ([]bool, bool),
) ([]bool, error) {
	panic("stubComparator: вердикт формы о странице спрошен там, где рубильник стоит в позиции «движок»")
}

func (s *stubComparator) Verdict(
	context.Context, string, string, string, string,
	map[string]any, func(context.Context) (bool, bool),
) (bool, error) {
	panic("stubComparator: вердикт формы спрошен там, где рубильник стоит в позиции «движок»")
}

func (s *stubComparator) Unaskable(reason, objectType, relation string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unaskable = append(s.unaskable, reason+"|"+objectType+"|"+relation)
}

func (s *stubComparator) snapshot() ([]*askedQuestion, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*askedQuestion(nil), s.questions...), append([]string(nil), s.unaskable...)
}

// ── пробы ─────────────────────────────────────────────────────────────────────

// TestEveryDoorOfTheWrappedClientPresentsItsQuestionToTheComparator — несущее
// утверждение под-фазы: у обёртки нет двери, за которой решение уходит движку
// не предъявленным сравнению.
//
// Двери перечислены ЯВНО и по одной. Табличная форма здесь не украшение: дверей
// три, они появлялись в разное время, и та, что появилась последней (батчевая),
// была невидима предикату приёмки — он искал `.BatchCheck(`, а вызов идёт как
// `BatchCheckWithContext`.
func TestEveryDoorOfTheWrappedClientPresentsItsQuestionToTheComparator(t *testing.T) {
	for _, tc := range []struct {
		door string
		call func(c *Client) error
	}{
		{
			door: "Check",
			call: func(c *Client) error {
				_, err := c.Check(context.Background(), "user:u1", "v_get", "iam_group:grp-1")
				return err
			},
		},
		{
			door: "CheckWithContext",
			call: func(c *Client) error {
				_, err := c.CheckWithContext(context.Background(), "user:u1", "v_get", "iam_group:grp-1", nil)
				return err
			},
		},
		{
			door: "BatchCheckWithContext",
			call: func(c *Client) error {
				_, err := c.BatchCheckWithContext(context.Background(), "user:u1", "v_get",
					[]string{"iam_group:grp-1"}, nil)
				return err
			},
		},
	} {
		t.Run(tc.door, func(t *testing.T) {
			cmp := &stubComparator{}
			c := Wrap(&stubRelations{allow: true}, nil).WithComparator(cmp)

			require.NoError(t, tc.call(c))

			questions, _ := cmp.snapshot()
			require.Len(t, questions, 1,
				"дверь %q приняла решение о доступе и не предъявила его сравнению. "+
					"Пока хоть одна дверь так делает, потиповое переключение источника вердикта "+
					"даёт два действующих источника истины на один вопрос: один отвечает новой "+
					"формой, другой прежним движком, и сравнение их не видит", tc.door)

			q := questions[0]
			require.Equal(t, "user:u1", q.Subject)
			require.Equal(t, "iam_group", q.ObjectType, "тип объекта разбирается из строки вопроса")
			require.Equal(t, "grp-1", q.ObjectID)
			require.Equal(t, "v_get", q.Relation)
			require.True(t, q.Settled,
				"исход не сведён: несведённый вопрос оставляет висеть теневой вызов и его срок")
			require.True(t, q.EngineAnswered, "движок ответил — исход обязан попасть в сравнение, а не в «не выполнилось»")
			require.True(t, q.EngineAllowed, "сведён не тот вердикт, который движок вернул")
		})
	}
}

// TestAnEngineOutageIsSettledAsUnanswered — «движок не ответил» и «движок сказал
// нет» обязаны остаться разными фактами.
//
// Без этого отказ хранилища засчитывался бы в согласие форм: обе «сказали нет»,
// и мера сходимости росла бы ровно на отказах.
func TestAnEngineOutageIsSettledAsUnanswered(t *testing.T) {
	cmp := &stubComparator{}
	boom := errors.New("relation store unreachable")
	c := Wrap(&stubRelations{err: boom}, nil).WithComparator(cmp)

	_, err := c.Check(context.Background(), "user:u1", "v_get", "iam_group:grp-1")
	require.ErrorIs(t, err, boom)

	questions, _ := cmp.snapshot()
	require.Len(t, questions, 1)
	require.True(t, questions[0].Settled)
	require.False(t, questions[0].EngineAnswered,
		"отказ движка сведён как ответ: тогда «оба сказали нет» засчитывается в согласие, "+
			"и доля сходимости растёт от каждой недоступности")
}

// TestAQuestionTheFormCannotBeAskedIsCountedNotDropped — знаменатель.
//
// Решение, о котором сравнение не спросили, обязано попасть в число решений.
// Молчаливый пропуск делает долю сравнённого лучше, ничего не улучшив.
func TestAQuestionTheFormCannotBeAskedIsCountedNotDropped(t *testing.T) {
	cmp := &stubComparator{}
	c := Wrap(&stubRelations{allow: true}, nil).WithComparator(cmp)

	// Объект без разделителя типа: разобрать вопрос для формы E нельзя.
	_, err := c.Check(context.Background(), "user:u1", "v_get", "cluster_kacho_root")
	require.NoError(t, err)

	questions, unaskable := cmp.snapshot()
	require.Empty(t, questions, "неразобранный объект нельзя задать форме E как вопрос")
	require.Len(t, unaskable, 1,
		"решение, о котором форму не спросили, выпало из знаменателя — доля сравнённого "+
			"считалась бы от того подмножества, где сравнение и так удавалось")
}

// TestABatchPresentsEveryItemAsADecision — страница не вправе быть дешевле
// знаменателя.
//
// Батчевая дверь несёт СТОЛЬКО ЖЕ решений, сколько объектов: одно сообщение —
// не одно решение. Сверяется ограниченная выборка (сверять поштучно значило бы
// открыть по транзакции формы E на каждый объект страницы и изменить то, что
// измеряешь), но КАЖДЫЙ объект обязан попасть в число решений — сравнённым либо
// незаданным с причиной.
func TestABatchPresentsEveryItemAsADecision(t *testing.T) {
	cmp := &stubComparator{}
	c := Wrap(&stubRelations{allow: true}, nil).WithComparator(cmp)

	const page = 10
	objects := make([]string, page)
	for i := range objects {
		objects[i] = "iam_group:grp-" + string(rune('a'+i))
	}

	_, err := c.BatchCheckWithContext(context.Background(), "user:u1", "v_get", objects, nil)
	require.NoError(t, err)

	questions, unaskable := cmp.snapshot()
	require.Equal(t, page, len(questions)+len(unaskable),
		"страница из %d объектов предъявила сравнению %d решений: объекты, о которых "+
			"не спросили и которые не назвали незаданными, исчезают из знаменателя, и доля "+
			"сравнённого начинает описывать не тот поток решений",
		page, len(questions)+len(unaskable))
	require.LessOrEqual(t, len(questions), BatchCompareBudget,
		"сверка страницы вышла за бюджет: сравнение обязано быть дешевле решения, иначе оно "+
			"меняет то, что измеряет")
	require.NotEmpty(t, questions, "бюджет израсходован на ноль вопросов — сверять страницу перестали вовсе")
}

// TestTheBatchFallbackDoesNotCountTheSameDecisionTwice — внутренний путь не
// удваивает знаменатель.
//
// Батчевая дверь на промахе памятки доспрашивает объекты поштучно. Если этот
// внутренний доспрос идёт через ПУБЛИЧНУЮ дверь, каждое такое решение попадает
// в сравнение дважды — и доля сходимости считается от выдуманного знаменателя.
func TestTheBatchFallbackDoesNotCountTheSameDecisionTwice(t *testing.T) {
	cmp := &stubComparator{}
	c := Wrap(&stubRelations{allow: true}, nil).WithComparator(cmp)

	objects := []string{"iam_group:grp-1", "iam_group:grp-2", "iam_group:grp-3"}
	_, err := c.BatchCheckWithContext(context.Background(), "user:u1", "v_get", objects, nil)
	require.NoError(t, err)

	questions, unaskable := cmp.snapshot()
	require.Equal(t, len(objects), len(questions)+len(unaskable),
		"решений предъявлено %d на %d объектов — внутренний доспрос прошёл через публичную "+
			"дверь и посчитался вторично", len(questions)+len(unaskable), len(objects))
}

// TestAnUnwiredComparatorIsANoOpAndNeverAnAnswer — непровязанное сравнение
// остаётся дешёвым и на ответ вызывающему не влияет.
//
// Это цена, которую платит модульная проба и любая сборка без формы E; и это же
// то, что делает провязку в композиционном корне обязательной проверкой
// (иначе «сравнение включено» держалось бы на памяти).
func TestAnUnwiredComparatorIsANoOpAndNeverAnAnswer(t *testing.T) {
	c := Wrap(&stubRelations{allow: true}, nil)
	allowed, err := c.Check(context.Background(), "user:u1", "v_get", "iam_group:grp-1")
	require.NoError(t, err)
	require.True(t, allowed, "непровязанное сравнение изменило ответ вызывающему")
}
