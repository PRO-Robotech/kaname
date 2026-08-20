// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package shadowverdict

// shadow_test.go — сравнение считает три исхода раздельно и не влияет на ответ.
//
// # Почему инъекция ПОДЛОЖНЫМ расхождением обязательна
//
// Сравнитель, который всегда молчит, выглядит ровно как сравнитель, у которого
// нет расхождений. Отличить их можно единственным способом: подсунуть форму,
// заведомо отвечающую иначе, и увидеть, что счётчик расхождений вырос, а запись
// в журнале назвала вопрос. Без этого «ноль расхождений» — утверждение о тишине,
// а не о согласии.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubAsker — форма E с заданным ответом.
type stubAsker struct {
	mu    sync.Mutex
	allow bool
	err   error
	delay time.Duration
	calls int
	// set/complete — ответ формы E на перечислительные вопросы.
	set      []string
	complete bool
}

func (s *stubAsker) Allowed(ctx context.Context, _, _, _, _ string, _ map[string]any) (bool, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	return s.allow, s.err
}

// AllowedMany — тот же ответ, что и `Allowed`, по каждому объекту страницы.
//
// Дублёр обязан выполнять контракт настоящего: страничный вопрос, отвечающий
// снисходительнее точечного, скрыл бы ровно тот дефект, ради которого его
// подставляют.
func (s *stubAsker) AllowedMany(ctx context.Context, subject, objectType string,
	objectIDs []string, relation string, condCtx map[string]any,
) ([]bool, error) {
	out := make([]bool, len(objectIDs))
	for i, id := range objectIDs {
		allowed, err := s.Allowed(ctx, subject, objectType, id, relation, condCtx)
		if err != nil {
			return nil, err
		}
		out[i] = allowed
	}
	return out, nil
}

// Перечислительные вопросы формы E. Отвечают ЗАДАННЫМ множеством: проба о
// прямом вердикте про них ничего не утверждает, но подставить форму, которая их
// не умеет, нельзя — порт один.
func (s *stubAsker) Objects(_ context.Context, _, _ string, _ []string, _ int) ([]string, bool, error) {
	return s.set, s.complete, s.err
}

func (s *stubAsker) Subjects(_ context.Context, _, _, _ string, _ int) ([]string, bool, error) {
	return s.set, s.complete, s.err
}

func (s *stubAsker) Sources(_ context.Context, _, _, _ string) ([]string, error) {
	return s.set, s.err
}

func quiet() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// settled / logOf — наблюдение ПОСЛЕ того, как теневая работа кончилась.
//
// Сведение исхода ушло с пути живого запроса (см. offpath_test.go), поэтому
// «вопрос задан» и «сравнение состоялось» перестали быть одним мгновением.
// Утверждения проб от этого НЕ изменились ни одним значением — сместилась только
// точка наблюдения: раньше сравнение успевало произойти внутри `settle`, теперь
// его надо дождаться. Читать счётчики без ожидания значило бы мерить скорость
// планировщика.
func settled(c *Comparator) *Comparator {
	c.Wait()
	return c
}

func logOf(c *Comparator, buf *bytes.Buffer) string {
	c.Wait()
	return buf.String()
}

// Согласие: счётчик сравнений растёт, расхождений — нет.
func TestCompare_AgreementCountsAsComparedOnly(t *testing.T) {
	c := New(&stubAsker{allow: true}, quiet())
	c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "get", nil)(true, true)

	got := settled(c).Counters()
	if got.Compared != 1 || got.Diverged != 0 || got.Unfinished != 0 {
		t.Fatalf("счётчики = %+v, ожидалось сравнений 1, расхождений 0, невыполненных 0", got)
	}
}

// ИНЪЕКЦИЯ: форма отвечает иначе — расхождение обязано быть посчитано.
//
// Это направление и доказывает, что сравнитель вообще способен покраснеть.
func TestCompare_InjectedDivergenceIsCounted(t *testing.T) {
	c := New(&stubAsker{allow: false}, quiet())
	c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "get", nil)(true, true)

	got := settled(c).Counters()
	if got.Diverged != 1 {
		t.Fatalf("подложное расхождение не посчитано: %+v — сравнитель, который всегда "+
			"молчит, неотличим от сравнителя без расхождений", got)
	}
	if got.Compared != 1 {
		t.Errorf("расхождение обязано считаться и как СРАВНЕНИЕ: %+v — иначе доля "+
			"расхождений не вычислима", got)
	}
}

// Ошибка формы — третья корзина, ни согласие, ни расхождение.
func TestCompare_ErrorIsItsOwnBucket(t *testing.T) {
	c := New(&stubAsker{err: errors.New("БД недоступна")}, quiet())
	c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "get", nil)(true, true)

	got := settled(c).Counters()
	if got.Unfinished != 1 {
		t.Fatalf("ошибка не попала в свою корзину: %+v", got)
	}
	if got.Compared != 0 || got.Diverged != 0 {
		t.Errorf("ошибка засчитана сравнением или расхождением: %+v — первое объявляет "+
			"сравнение состоявшимся там, где его не было; второе топит настоящие "+
			"расхождения в шуме недоступной БД", got)
	}
}

// Исчерпание СВОЕГО срока — исход «не выполнилось», а не расхождение и не согласие.
//
// Здесь прежде стояла проба `TestCompare_OwnDeadlineDoesNotHoldTheCaller`, и её
// заголовок был шире тела: при сроке сверки 20 мс она утверждала «вызывающего
// держали не дольше 150 мс», то есть оставалась зелёной при ЛЮБОМ сроке ниже
// порога — включая боевые 50 мс, ровно на том дефекте, ради которого писалась.
// Утверждение о МЕСТЕ сравнения перенесено в offpath_test.go, где оно
// логическое, а не по часам; здесь остаётся то, что проба действительно
// проверяла, — корзина исхода.
func TestCompare_ExpiredOwnDeadlineGoesToTheUnfinishedBucket(t *testing.T) {
	form := &stubAsker{allow: true, delay: 200 * time.Millisecond}
	c := New(form, quiet()).WithTimeout(5 * time.Millisecond)

	c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "get", nil)(true, true)

	got := settled(c).Counters()
	if got.Unfinished != 1 {
		t.Errorf("исчерпание срока не попало в корзину «не выполнилось»: %+v", got)
	}
	if got.Compared != 0 || got.Diverged != 0 {
		t.Errorf("неполученный ответ формы E засчитан сравнением: %+v — «ноль расхождений» "+
			"тогда означало бы «сравнения не было»", got)
	}
}

// Выключенное сравнение — дешёвый no-op, а не паника и не ложные счётчики.
func TestCompare_DisabledIsANoOp(t *testing.T) {
	c := New(nil, quiet())
	c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "get", nil)(true, true)
	if got := settled(c).Counters(); got != (Snapshot{}) {
		t.Fatalf("выключенное сравнение что-то посчитало: %+v — «ноль расхождений» тогда "+
			"означало бы «сравнение не работает»", got)
	}
	// И на nil-приёмнике: сборка без сравнителя ведёт себя как прежняя.
	var nilComparator *Comparator
	nilComparator.Ask(context.Background(), "s", "t", "i", "v", nil)(true, true)
}

// ─────────────────────────────────────────────────────────────────────────────
// ЗНАМЕНАТЕЛЬ И ДОЛЯ
//
// «Сравнений тысяча» не отвечает на вопрос «какая это доля». Проба утверждает
// именно долю: решение, о котором форму E спросить не удалось, обязано попасть в
// знаменатель — иначе доля считается от подмножества, где сравнение и так
// удавалось, и растёт от каждого нового пропуска.

func TestCounters_ShareIsCountedFromEveryDecisionNotOnlyTheSucceededOnes(t *testing.T) {
	c := New(&stubAsker{allow: true}, quiet())
	// Два решения сравнены.
	c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "v_get", nil)(true, true)
	c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-2", "v_get", nil)(true, true)
	// Два — нет: у одного объект не разобран, у другого движок вердикта не дал.
	c.Unaskable("объект не разобран", "", "v_get")
	c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-3", "v_get", nil)(false, false)

	got := settled(c).Counters()
	if got.Decisions != 4 {
		t.Fatalf("решений посчитано %d, ожидалось 4 (%+v) — решение без вопроса, не попавшее "+
			"в знаменатель, делает долю лучше, ничего не улучшив", got.Decisions, got)
	}
	// «Спросить нельзя» и «не успели» — РАЗНЫЕ клетки, а не одна.
	//
	// Прежде обе лежали в «не выполнилось», и проба утверждала «невыполненных 2».
	// Утверждение было верным и слишком грубым: условие переключения типа
	// названо долей «спросить нельзя» ПО ЭТОМУ ТИПУ, а доля, размазанная по общей
	// корзине, не считается ни для одного. Сумма двух клеток осталась прежней —
	// изменилась только различимость, и это то, ради чего клетку и расщепили.
	if got.Compared != 2 || got.Unfinished != 1 || got.Unaskable != 1 {
		t.Fatalf("счётчики = %+v, ожидалось сравнений 2, невыполненных 1, «спросить нельзя» 1", got)
	}
	if got.Unfinished+got.Unaskable+got.Compared != got.Decisions {
		t.Fatalf("исходы не покрывают знаменатель: %+v", got)
	}
	if share := got.ComparedShare(); share != 0.5 {
		t.Fatalf("доля сравнённых = %v, ожидалось 0.5 (%+v)", share, got)
	}
}

func TestCounters_ShareOfNothingIsZeroNotAPanic(t *testing.T) {
	if share := (Snapshot{}).ComparedShare(); share != 0 {
		t.Fatalf("доля на нуле решений = %v", share)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ПЕРЕЧИСЛИТЕЛЬНЫЕ ВОПРОСЫ

// Согласие множеств не зависит от порядка обхода: у двух форм он свой.
func TestAskObjects_SameSetInAnotherOrderIsAgreement(t *testing.T) {
	c := New(&stubAsker{set: []string{"b", "a"}, complete: true}, quiet())
	c.AskObjects(context.Background(), "user:usr-1", "vpc_network", []string{"viewer"})(
		[]string{"a", "b"}, true, true)

	if got := settled(c).Counters(); got.Compared != 1 || got.Diverged != 0 {
		t.Fatalf("счётчики = %+v — разный порядок обхода объявлен расхождением", got)
	}
}

// ИНЪЕКЦИЯ: множества разные — расхождение обязано быть посчитано.
func TestAskObjects_InjectedDivergenceIsCounted(t *testing.T) {
	c := New(&stubAsker{set: []string{"a"}, complete: true}, quiet())
	c.AskObjects(context.Background(), "user:usr-1", "vpc_network", []string{"viewer"})(
		[]string{"a", "b"}, true, true)

	if got := settled(c).Counters(); got.Diverged != 1 || got.Compared != 1 {
		t.Fatalf("подложное расхождение множеств не посчитано: %+v", got)
	}
}

// Неполный ответ — «не выполнилось», а не согласие: сверялись бы два разных
// подмножества.
func TestAskSubjects_IncompleteAnswerIsNotAgreement(t *testing.T) {
	c := New(&stubAsker{set: []string{"user:a"}, complete: false}, quiet())
	c.AskSubjects(context.Background(), "vpc_network", "net-1", "v_get")(
		[]string{"user:a"}, true, true)

	got := settled(c).Counters()
	if got.Unfinished != 1 || got.Compared != 0 {
		t.Fatalf("неполный ответ засчитан сравнением: %+v — согласие двух усечённых "+
			"ответов не является согласием", got)
	}
	if got.Decisions != 1 {
		t.Fatalf("решение не попало в знаменатель: %+v", got)
	}
}

// Разворот отношений сверяется ОДНОСТОРОННЕ: движок называет выданный набор,
// форма E — и его, и тех, кто внутри. «У формы E названо больше» — форма ответа,
// а не расхождение.
func TestAskSources_WiderFormAnswerIsNotADivergence(t *testing.T) {
	c := New(&stubAsker{set: []string{"group:g", "user:a", "user:b"}}, quiet())
	c.AskSources(context.Background(), "vpc_network", "net-1", "v_get")(
		[]string{"group:g"}, true, true)

	if got := settled(c).Counters(); got.Compared != 1 || got.Diverged != 0 {
		t.Fatalf("счётчики = %+v — членство группы объявлено расхождением", got)
	}
}

// ИНЪЕКЦИЯ обратной стороны: движок назвал основание, которого форма E не знает.
// Это и есть расхождение — и односторонность его НЕ прячет.
func TestAskSources_GroundKnownOnlyToTheEngineIsADivergence(t *testing.T) {
	c := New(&stubAsker{set: []string{"user:a"}}, quiet())
	c.AskSources(context.Background(), "vpc_network", "net-1", "v_get")(
		[]string{"user:a", "user:z"}, true, true)

	if got := settled(c).Counters(); got.Diverged != 1 {
		t.Fatalf("основание, известное только движку, не объявлено расхождением: %+v — "+
			"односторонняя сверка обязана оставаться способной покраснеть", got)
	}
}

// ВЫВОД несёт долю, а не только число расхождений — и несёт её КАЖДАЯ запись.
//
// Счётчик в памяти, который никто не печатает, отвечает на «сколько разошлось» и
// молчит про «от скольких» — а именно это и делает «расхождений нет» неотличимым
// от «сравнений не было». Проверяется ПОСТРОЧНО: «доля нашлась где-то в выводе»
// зеленело бы и тогда, когда её несёт соседняя запись, а разбираемая — нет.
func TestEveryOutputRecordCarriesTheComparedShare(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	c := New(&stubAsker{allow: false}, logger)

	// Одно сравнение расходится, одно решение вообще не задано форме E.
	c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "v_get", nil)(true, true)
	// Ждём ЗДЕСЬ, а не только перед чтением: сравнение сводится рядом с запросом,
	// и числа в записи — снимок на момент ЕЁ написания. Без ожидания вторая
	// запись честно назвала бы долю, которой на тот миг ещё не было, и проба
	// мерила бы порядок планировщика, а не то, несёт ли запись долю вообще.
	c.Wait()
	c.Unaskable("объект не разобран", "", "v_get")

	c.Wait()
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("записей в выводе %d, ожидалось 2:\n%s", len(lines), buf.String())
	}
	for _, line := range lines {
		for _, field := range []string{"decisions=", "compared=", "compared_share="} {
			if !strings.Contains(line, field) {
				t.Fatalf("в записи нет %q — запись отвечает «сколько разошлось» и молчит "+
					"про «от скольких»:\n%s", field, line)
			}
		}
	}
	// И доля названа ЧИСЛОМ, а не подразумевается: половина решений сравнена.
	if !strings.Contains(lines[1], "compared_share=0.5") {
		t.Fatalf("доля сравнённых не названа значением 0.5:\n%s", lines[1])
	}
}

// countingAsker — форма E, которая ВЕДЁТ наблюдение за меточной ветвью.
//
// Отдельный дублёр рядом с `stubAsker`, а не поле в нём: наблюдение —
// необязательное расширение порта, и форма без него обязана оставаться законным
// входом. Один дублёр на оба случая скрыл бы именно это различие.
type countingAsker struct {
	stubAsker
	mirror, iamDirect, earlyStops int64
}

func (c *countingAsker) LabelArmGrounds() (int64, int64, int64) {
	return c.mirror, c.iamDirect, c.earlyStops
}

// TestCoverageCarriesLabelArmGroundsPerAxis — числа меточной ветви едут В КАЖДОЙ
// записи теневого пути, по осям раздельно.
//
// Проверяется ЗАПИСЬ, а не только доступность метода: счётчик, который никто не
// печатает, наблюдаемым не является — «расхождений нет» и «ветвь ни разу не
// спросили» остались бы неразличимы ровно так же, как до фикса.
func TestCoverageCarriesLabelArmGroundsPerAxis(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	form := &countingAsker{mirror: 3, iamDirect: 5}
	form.allow = false
	c := New(form, logger)

	// Расхождение — чтобы запись состоялась: у согласия своей строки нет.
	c.Ask(context.Background(), "user:usr-1", "iam_group", "grp-1", "v_get", nil)(true, true)

	c.Wait()
	out := buf.String()
	if !strings.Contains(out, "label_grounds_mirror=3") {
		t.Errorf("запись не назвала оснований меточной ветви на оси зеркала: %s", out)
	}
	if !strings.Contains(out, "label_grounds_iam_direct=5") {
		t.Errorf("запись не назвала оснований меточной ветви на оси собственных таблиц: %s", out)
	}
}

// TestCoverageWithoutObserverStaysUsable — ЗАКОННЫЙ БЛИЗНЕЦ: форма, наблюдения
// не ведущая, остаётся пригодной, и запись просто не несёт этих чисел.
//
// Без него расширение порта читалось бы как обязательное, и следующая форма
// понадобилась бы с заглушкой — то есть с числами, которых никто не мерил.
func TestCoverageWithoutObserverStaysUsable(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	c := New(&stubAsker{allow: false}, logger)

	c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "v_get", nil)(true, true)

	c.Wait()
	out := buf.String()
	if !strings.Contains(out, "РАСХОЖДЕНИЕ") {
		t.Fatalf("расхождение не записано вовсе: %s", out)
	}
	if strings.Contains(out, "label_grounds_") {
		t.Errorf("форма без наблюдения выдала числа, которых не вела: %s", out)
	}
}
