// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package shadowverdict

// switch_test.go — ПЕРЕКЛЮЧЁННОЕ НАПРАВЛЕНИЕ: решает форма, движок спрашивается
// рядом.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ — И ЧЕГО НАМЕРЕННО НЕ УТВЕРЖДАЕТСЯ
//
// Утверждается ИСХОД у вызывающего: чей ответ он получил. «Функция формы была
// вызвана» исходом не является — вызвать можно и выбросив ответ, и именно так
// выглядит молчаливый возврат к движку, который здесь запрещён.
//
// Не утверждается маршрутизация дверей решения (она в `authzcascade` и в
// `service`) — здесь предмет один: сам сравнитель.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/verdictsource"
)

// engineStub — движок, спрошенный РЯДОМ. Считает вызовы, чтобы «спрошен» было
// отличимо от «не спрошен», и отвечает заданным.
type engineStub struct {
	allowed  bool
	answered bool
	calls    int
}

func (e *engineStub) ask(context.Context) (bool, bool) {
	e.calls++
	return e.allowed, e.answered
}

func switched(form Asker, types ...string) *Comparator {
	return New(form, quiet()).WithSwitchboard(verdictsource.New(types...))
}

// Рубильник виден сравнителю: он отвечает на вопрос «кто решает», и отвечает
// одним предикатом — тем же, что читают страж старта и самоотчёт.
func TestComparatorReportsWhoDecides(t *testing.T) {
	c := switched(&stubAsker{}, "vpc_network")

	if !c.Decides("vpc_network") {
		t.Fatal("названный тип обязан решаться формой")
	}
	if c.Decides("vpc_subnet") {
		t.Fatal("не названный тип обязан остаться за движком")
	}
}

// ГЛАВНОЕ УТВЕРЖДЕНИЕ: вызывающий получает ответ ФОРМЫ, а не движка — и это
// проверяется на входе, где ответы ПРОТИВОПОЛОЖНЫ. Совпадающие ответы сделали
// бы утверждение тождественно истинным.
func TestSwitchedTypeReturnsTheFormsVerdictNotTheEngines(t *testing.T) {
	form := &stubAsker{allow: true}
	engine := &engineStub{allowed: false, answered: true}
	c := switched(form, "vpc_network")

	allowed, err := c.Verdict(context.Background(),
		"user:u1", "vpc_network", "n1", "v_get", nil, engine.ask)

	if err != nil {
		t.Fatalf("форма ответила — ошибки быть не должно: %v", err)
	}
	if !allowed {
		t.Fatal("вернулся ответ ДВИЖКА: источник вердикта не переключён")
	}

	settled(c)
	if engine.calls != 1 {
		t.Fatalf("движок обязан быть спрошен РЯДОМ ровно один раз, спрошен %d", engine.calls)
	}
}

// Зеркальная половина: форма отказывает — вызывающий получает отказ, даже когда
// движок разрешает. Без неё проба выше зеленела бы на «всегда разрешать».
func TestSwitchedTypeReturnsTheFormsDenialWhenEngineAllows(t *testing.T) {
	form := &stubAsker{allow: false}
	engine := &engineStub{allowed: true, answered: true}
	c := switched(form, "vpc_network")

	allowed, err := c.Verdict(context.Background(),
		"user:u1", "vpc_network", "n1", "v_get", nil, engine.ask)

	if err != nil || allowed {
		t.Fatalf("вернулся ответ движка: allowed=%v err=%v", allowed, err)
	}
}

// ОТКАЗ ФОРМЫ — ЭТО ОТКАЗ, А НЕ «СПРОСИ ДВИЖОК».
//
// Запасной путь на движок в момент переключения превращает измеренную
// независимость в фикцию: под нагрузкой он даёт ровно ту зависимость, ради
// снятия которой всё делается. Поэтому ошибка формы уезжает вызывающему
// ОТДЕЛЬНЫМ исходом — ни отказом в доступе, ни ответом движка.
func TestFormFailureIsAnOutageNotADenialAndNotTheEnginesAnswer(t *testing.T) {
	boom := errors.New("форма не ответила")
	form := &stubAsker{err: boom}
	engine := &engineStub{allowed: true, answered: true}
	c := switched(form, "vpc_network")

	allowed, err := c.Verdict(context.Background(),
		"user:u1", "vpc_network", "n1", "v_get", nil, engine.ask)

	if err == nil {
		t.Fatal("отказ формы обязан доехать до вызывающего ошибкой, а не превратиться в вердикт")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("причина отказа обязана сохраниться: %v", err)
	}
	if allowed {
		t.Fatal("ответ движка подставлен вместо неответившей формы — молчаливый возврат к движку")
	}
}

// Недоступность движка на ответ вызывающему не влияет НИКАК: тень не решает.
func TestEngineUnavailableDoesNotChangeTheAnswer(t *testing.T) {
	form := &stubAsker{allow: true}
	engine := &engineStub{answered: false}
	c := switched(form, "vpc_network")

	allowed, err := c.Verdict(context.Background(),
		"user:u1", "vpc_network", "n1", "v_get", nil, engine.ask)
	if err != nil || !allowed {
		t.Fatalf("тень повлияла на ответ: allowed=%v err=%v", allowed, err)
	}

	s := settled(c).Counters()
	if s.Compared != 0 {
		t.Fatalf("сравнивать не с чем — сравнений быть не должно, их %d", s.Compared)
	}
	if s.Unfinished != 1 {
		t.Fatalf("исход обязан лечь в «не выполнилось», их %d", s.Unfinished)
	}
}

// НАПРАВЛЕНИЕ РАСХОЖДЕНИЯ считается раздельно, и направления не равны.
//
// «Форма шире» — расширение доступа: уже случившееся событие безопасности.
// «Форма уже» — отказ в обслуживании. Один счётчик на оба сделал бы их
// неотличимыми ровно там, где различие и решает, откатывать ли тип.
func TestDivergenceIsCountedByDirection(t *testing.T) {
	t.Run("форма шире", func(t *testing.T) {
		c := switched(&stubAsker{allow: true}, "vpc_network")
		engine := &engineStub{allowed: false, answered: true}

		_, _ = c.Verdict(context.Background(), "user:u1", "vpc_network", "n1", "v_get", nil, engine.ask)

		s := settled(c).Counters()
		if s.DivergedFormWider != 1 || s.DivergedFormNarrower != 0 {
			t.Fatalf("направление названо неверно: шире=%d уже=%d", s.DivergedFormWider, s.DivergedFormNarrower)
		}
		if s.Diverged != 1 {
			t.Fatalf("направления обязаны оставаться подмножеством расхождений, их %d", s.Diverged)
		}
	})

	t.Run("форма уже", func(t *testing.T) {
		c := switched(&stubAsker{allow: false}, "vpc_network")
		engine := &engineStub{allowed: true, answered: true}

		_, _ = c.Verdict(context.Background(), "user:u1", "vpc_network", "n1", "v_get", nil, engine.ask)

		s := settled(c).Counters()
		if s.DivergedFormNarrower != 1 || s.DivergedFormWider != 0 {
			t.Fatalf("направление названо неверно: шире=%d уже=%d", s.DivergedFormWider, s.DivergedFormNarrower)
		}
	})

	t.Run("согласие направления не даёт", func(t *testing.T) {
		c := switched(&stubAsker{allow: true}, "vpc_network")
		engine := &engineStub{allowed: true, answered: true}

		_, _ = c.Verdict(context.Background(), "user:u1", "vpc_network", "n1", "v_get", nil, engine.ask)

		s := settled(c).Counters()
		if s.Diverged != 0 || s.DivergedFormWider != 0 || s.DivergedFormNarrower != 0 {
			t.Fatalf("согласие посчитано расхождением: %+v", s)
		}
		if s.Compared != 1 {
			t.Fatalf("сравнение состоялось, а не посчитано: %d", s.Compared)
		}
	})
}

// Направление считается и НА НЕПЕРЕКЛЮЧЁННОМ пути: оно свойство ПАРЫ ответов, а
// не того, кто спрошен первым. Иначе полярность пришлось бы «переворачивать»
// второй реализацией, и две меры одного предмета разошлись бы молча.
func TestDirectionIsCountedOnTheEngineDecidedPathToo(t *testing.T) {
	c := New(&stubAsker{allow: true}, quiet())

	settle := c.Ask(context.Background(), "user:u1", "vpc_network", "n1", "v_get", nil)
	settle(false, true) // движок отказал, форма разрешает ⇒ форма шире

	s := settled(c).Counters()
	if s.DivergedFormWider != 1 {
		t.Fatalf("направление на движковом пути не посчитано: %+v", s)
	}
}

// ИСТОЧНИК ВЕРДИКТА виден числом, и знаменатель сходится: каждое решение имеет
// ровно один источник. Без этого «переключено» и «объявлено переключённым»
// неразличимы — рубильник может стоять в позиции «форма», а решения продолжать
// идти движком.
func TestVerdictSourceIsCountedAndSumsToDecisions(t *testing.T) {
	c := switched(&stubAsker{allow: true}, "vpc_network")
	engine := &engineStub{allowed: true, answered: true}

	_, _ = c.Verdict(context.Background(), "user:u1", "vpc_network", "n1", "v_get", nil, engine.ask)
	c.Ask(context.Background(), "user:u1", "vpc_subnet", "s1", "v_get", nil)(true, true)
	c.Unaskable("объект вопроса не разобран", "", "v_get")

	s := settled(c).Counters()
	if s.VerdictsForm != 1 {
		t.Fatalf("вердиктов формы %d, ожидался 1", s.VerdictsForm)
	}
	if s.VerdictsEngine != 2 {
		t.Fatalf("вердиктов движка %d, ожидалось 2", s.VerdictsEngine)
	}
	if s.VerdictsForm+s.VerdictsEngine != s.Decisions {
		t.Fatalf("у решения обязан быть ровно один источник: %d+%d != %d",
			s.VerdictsForm, s.VerdictsEngine, s.Decisions)
	}
}

// Расхождение на ПЕРЕКЛЮЧЁННОМ типе в сторону расширения называется своим
// именем в журнале: это то, по чему оператор решает откатывать тип.
func TestWiderFormOnSwitchedTypeIsNamedAsAccessExpansion(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	c := New(&stubAsker{allow: true}, logger).WithSwitchboard(verdictsource.New("vpc_network"))
	engine := &engineStub{allowed: false, answered: true}

	_, _ = c.Verdict(context.Background(), "user:u1", "vpc_network", "n1", "v_get", nil, engine.ask)

	got := logOf(c, &buf)
	if !strings.Contains(got, "vpc_network") {
		t.Fatalf("запись не называет тип, который надо откатить: %s", got)
	}
	if !strings.Contains(got, "расширение доступа") {
		t.Fatalf("запись не называет направление как расширение доступа: %s", got)
	}
}

// Непровязанный рубильник не переключает ничего, и `Verdict` на нём — ошибка
// сборки, а не тихий «нет».
//
// Тихий отказ здесь был бы худшим из исходов: тип выглядел бы переключённым, а
// каждое решение по нему становилось бы отказом без единой записи.
func TestVerdictWithoutAFormIsAnErrorNotADenial(t *testing.T) {
	c := New(nil, quiet()).WithSwitchboard(verdictsource.New("vpc_network"))
	engine := &engineStub{allowed: true, answered: true}

	_, err := c.Verdict(context.Background(), "user:u1", "vpc_network", "n1", "v_get", nil, engine.ask)
	if err == nil {
		t.Fatal("вердикт без формы обязан быть ошибкой: тихий отказ неотличим от честного")
	}
	if c.Decides("vpc_network") {
		t.Fatal("без формы рубильник не вправе объявлять тип переключённым")
	}
}

// КЛЮЧ КЛАССА РАСХОЖДЕНИЯ — контракт с внешним прибором.
//
// Разбор сводки читает направление по суффиксу `движок=<bool>`. Ключ, у
// которого этот суффикс перестал быть последним, объявляет расхождение
// НЕРАЗОБРАННЫМ — то есть прибор печатает отказ там, где расхождения нет вовсе.
// Так уже случилось: второе написание направления в ключе дало четыре ложных
// «не разобрано» на прогоне с нулём расхождений.
//
// Проба закрепляет суффикс, а не весь ключ: остальное — свобода записи.
func TestDivergenceClassKeyEndsWithTheEngineAnswer(t *testing.T) {
	for _, tc := range []struct {
		name       string
		formAllows bool
		engine     bool
		wantSuffix string
	}{
		{"форма шире", true, false, "движок=false"},
		{"форма уже", false, true, "движок=true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))
			c := New(&stubAsker{allow: tc.formAllows}, logger).
				WithSwitchboard(verdictsource.New("vpc_network"))

			_, _ = c.Verdict(context.Background(), "user:u1", "vpc_network", "n1", "v_get", nil,
				func(context.Context) (bool, bool) { return tc.engine, true })

			got := logOf(c, &buf)
			// Ключ печатается в поле `class`; прибор читает его суффикс.
			//
			// Значение берётся из КАВЫЧЕК: ключ содержит пробелы, и обработчик
			// журнала его цитирует. Разбор по первому пробелу отрезал бы ключ на
			// первом же слове — и проба падала бы на исправном ключе, то есть
			// была бы отрицанием без положительного контроля к самой себе.
			m := regexp.MustCompile(`class="([^"]*)"`).FindStringSubmatch(got)
			if m == nil {
				t.Fatalf("запись не несёт ключа класса: %s", got)
			}
			key := m[1]
			if !strings.HasSuffix(key, tc.wantSuffix) {
				t.Fatalf("ключ %q обязан оканчиваться на %q — иначе разбор прибора объявит "+
					"расхождение неразобранным", key, tc.wantSuffix)
			}
		})
	}
}

// РАЗДЕЛИТЕЛЬ СВОДКИ не встречается ВНУТРИ ключа класса.
//
// Иначе поле `class_breakdown` неразбираемо by construction: прибор режет ключ
// на части и объявляет направление неразобранным — то есть печатает отказ там,
// где расхождения нет. Так и было с разделителем-пробелом: ключи содержат
// пробелы, и ошибка не проявлялась ровно до первой непустой сводки.
//
// Проба порождает классы ВСЕХ родов, которые сравнитель умеет заводить, и
// требует свойства от каждого — а не от одного выбранного.
func TestSummarySeparatorNeverOccursInsideAClassKey(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	c := New(&stubAsker{allow: true}, logger).WithSwitchboard(verdictsource.New("vpc_network"))

	// расхождение
	_, _ = c.Verdict(context.Background(), "user:u1", "vpc_network", "n1", "v_get", nil,
		func(context.Context) (bool, bool) { return false, true })
	// «не выполнилось» — движок вердикта не дал
	_, _ = c.Verdict(context.Background(), "user:u1", "vpc_network", "n2", "v_list", nil,
		func(context.Context) (bool, bool) { return false, false })
	// «спросить нельзя»
	c.Unaskable("объект вопроса не разобран", "", "v_get")
	settled(c)

	c.Summarise()
	got := buf.String()

	// Берётся ПОСЛЕДНЯЯ сводка: сравнитель печатает их по ходу, и первая знает
	// только о классах, случившихся до неё. Проба, читающая первую, утверждала
	// бы о неполном наборе и падала бы на предпосылке вместо предмета.
	all := regexp.MustCompile(`class_breakdown="([^"]*)"`).FindAllStringSubmatch(got, -1)
	if len(all) == 0 {
		t.Fatalf("сводка не несёт разбивки по классам: %s", got)
	}
	entries := strings.Split(all[len(all)-1][1], ClassBreakdownSeparator)
	if len(entries) < 3 {
		t.Fatalf("предпосылка пробы: классов породилось %d, ожидалось не меньше трёх (%q)",
			len(entries), all[len(all)-1][1])
	}
	for _, entry := range entries {
		key := entry
		if i := strings.LastIndex(entry, "×"); i > 0 {
			key = entry[:i]
		}
		if strings.Contains(key, strings.TrimSpace(ClassBreakdownSeparator)) {
			t.Fatalf("ключ класса %q содержит разделитель сводки — поле неразбираемо", key)
		}
	}
}
