// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package shadowverdict

// observability_test.go — вывод сравнения обязан РАЗЛИЧАТЬ, а не наполнять.
//
// # Два разных требования, и оба проверяются здесь
//
//  1. «Расхождений 0 из N сравнённых» отличимо от «сравнено 0». Пока наружу
//     выходили только записи о расхождениях, согласие форм и невыполненное
//     сравнение выглядели одинаково — тишиной, и «ноль» в журнале не утверждал
//     ничего.
//  2. Один дефект даёт одну запись, а не тысячу. За прогон таких записей было
//     3215; при таком объёме уровень ERROR перестаёт значить «требует действия
//     сейчас», и настоящая ошибка теряется by construction.
//
// # Почему это НЕ ослабление сравнения
//
// Ослаблением было бы перестать СЧИТАТЬ. Здесь счётчики и клетки метрики не
// меняются ни на единицу; повтор класса по-прежнему увеличивает `diverged`, и
// сводка называет его числом. Пропадает ровно дословный повтор уже названного —
// то, что нового действия не требует. Проба ниже утверждает обе половины: и что
// запись одна, и что счётчик вырос до трёх.

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func capturing() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

// НЕДОСТУПНОСТЬ ДВИЖКА НЕ МОЖЕТ БЫТЬ ЗАПИСАНА РАСХОЖДЕНИЕМ.
//
// Вопрос стоил отдельной пробы, потому что на него легко ответить рассуждением и
// ошибиться: полоса «модель прав не ответила» одно время отвечала вызывающему
// кодом отказа, и естественно спросить, не приехала ли часть расхождений оттуда —
// «недоступность, одетая в отказ».
//
// Ответ — не могла, и вот почему это свойство, а не совпадение: сведение исхода
// принимает ДВА значения, вердикт и признак «движок вообще ответил», и на
// неответе уходит в свою корзину ДО сравнения вердиктов. То, каким кодом
// недоступность видна вызывающему, на этот путь не влияет никак: сравнитель
// смотрит на признак, а не на код.
//
// Проба подаёт САМЫЙ неудобный вход: формы отвечают по-разному (форма E — «да»,
// вердикт движка — «нет»), и только признак говорит, что движок не отвечал.
func TestEngineThatDidNotAnswerIsNeverRecordedAsDivergence(t *testing.T) {
	logger, buf := capturing()
	c := New(&stubAsker{allow: true}, logger)

	c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "v_get", nil)(false, false)

	got := c.Counters()
	if got.Diverged != 0 {
		t.Errorf("неответ движка засчитан расхождением: %+v — тогда перебой в модели прав "+
			"неотличим от настоящего расхождения форм", got)
	}
	if got.Unfinished != 1 || got.Compared != 0 {
		t.Errorf("счётчики = %+v, ожидалось невыполненных 1 и сравнений 0", got)
	}
	if strings.Contains(buf.String(), "РАСХОЖДЕНИЕ формы E") {
		t.Errorf("запись о расхождении на неответе движка: %s", buf.String())
	}

	// Положительный контроль: тот же вход, но движок ОТВЕТИЛ — расхождение
	// записывается. Без него проба зеленела бы на сравнителе, который не пишет
	// расхождений вовсе.
	c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "v_get", nil)(false, true)
	if c.Counters().Diverged != 1 {
		t.Errorf("ответивший движок не дал расхождения: %+v", c.Counters())
	}
}

// Одно расхождение — одна запись; повтор того же класса считается и не печатается.
func TestDivergence_NamedOncePerClassCountedEveryTime(t *testing.T) {
	logger, buf := capturing()
	c := New(&stubAsker{allow: false}, logger)

	for i := 0; i < 3; i++ {
		c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "v_get", nil)(true, true)
	}

	if got := c.Counters().Diverged; got != 3 {
		t.Fatalf("расхождений сосчитано %d, ожидалось 3 — дедупликация записи не вправе "+
			"уменьшать счётчик", got)
	}
	if n := strings.Count(buf.String(), "РАСХОЖДЕНИЕ формы E"); n != 1 {
		t.Errorf("записей о расхождении %d, ожидалась 1 на класс: три тысячи одинаковых "+
			"строк делают уровень ERROR бесполезным", n)
	}
	// Координаты первого случая обязаны остаться: без них разбирать нечего.
	if !strings.Contains(buf.String(), "vpc_network") || !strings.Contains(buf.String(), "v_get") {
		t.Errorf("запись не назвала вопрос: %s", buf.String())
	}
}

// ЗАКОННЫЙ БЛИЗНЕЦ: ДРУГОЙ класс печатается своей записью.
//
// Без него проба выше зеленела бы на сравнении, которое печатает первую запись и
// замолкает навсегда, — то есть на потере находок.
func TestDivergence_AnotherClassGetsItsOwnRecord(t *testing.T) {
	logger, buf := capturing()
	c := New(&stubAsker{allow: false}, logger)

	c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "v_get", nil)(true, true)
	c.Ask(context.Background(), "user:usr-1", "vpc_subnet", "sub-1", "v_delete", nil)(true, true)

	if n := strings.Count(buf.String(), "РАСХОЖДЕНИЕ формы E"); n != 2 {
		t.Errorf("записей %d, ожидалось 2 — разные вопросы суть разные классы", n)
	}
}

// Идентификатор объекта класса НЕ образует: иначе перечень «уже названного» рос
// бы вместе с трафиком и дедупликация не давала бы ничего.
func TestDivergence_ObjectIdDoesNotSplitTheClass(t *testing.T) {
	logger, buf := capturing()
	c := New(&stubAsker{allow: false}, logger)

	for _, id := range []string{"net-1", "net-2", "net-3"} {
		c.Ask(context.Background(), "user:usr-1", "vpc_network", id, "v_get", nil)(true, true)
	}
	if n := strings.Count(buf.String(), "РАСХОЖДЕНИЕ формы E"); n != 1 {
		t.Errorf("записей %d, ожидалась 1: класс — вопрос, а не ресурс", n)
	}
}

// Сводка печатается ДАЖЕ при полном согласии: «расхождений 0 из N» — единственное,
// что в журнале отличает согласие форм от невыполненного сравнения.
func TestSummary_PrintedEvenWhenNothingDiverges(t *testing.T) {
	logger, buf := capturing()
	c := New(&stubAsker{allow: true}, logger)

	c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "v_get", nil)(true, true)

	out := buf.String()
	if !strings.Contains(out, "shadow verdict: сводка") {
		t.Fatalf("сводки нет: %s", out)
	}
	for _, field := range []string{"decisions=1", "compared=1", "diverged=0", "classes=0"} {
		if !strings.Contains(out, field) {
			t.Errorf("в сводке нет %q: %s", field, out)
		}
	}
}

// Сводка не чаще периода — иначе она сама станет тем шумом, от которого спасает.
func TestSummary_RateLimitedByItsOwnPeriod(t *testing.T) {
	logger, buf := capturing()
	now := time.Unix(0, 0)
	c := New(&stubAsker{allow: true}, logger).
		WithClock(func() time.Time { return now }).
		WithSummaryEvery(time.Minute)

	for i := 0; i < 5; i++ {
		c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "v_get", nil)(true, true)
	}
	if n := strings.Count(buf.String(), "shadow verdict: сводка"); n != 1 {
		t.Fatalf("сводок %d, ожидалась 1 в пределах периода", n)
	}

	// Положительный контроль: за периодом сводка выходит снова. Без него проба
	// зеленела бы на сравнении, печатающем сводку ровно один раз за жизнь
	// процесса, — а тогда числа прогона остались бы на его первой секунде.
	now = now.Add(2 * time.Minute)
	c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "v_get", nil)(true, true)
	if n := strings.Count(buf.String(), "shadow verdict: сводка"); n != 2 {
		t.Errorf("сводок %d, ожидалось 2 после истечения периода", n)
	}
}

// Сводка называет классы и их числа: перечень «сколько чего» — то, ради чего
// повтор и не печатается.
func TestSummary_NamesEachClassWithItsCount(t *testing.T) {
	logger, buf := capturing()
	c := New(&stubAsker{allow: false}, logger).WithSummaryEvery(time.Nanosecond)

	for i := 0; i < 4; i++ {
		c.Ask(context.Background(), "user:usr-1", "vpc_network", "net-1", "v_get", nil)(true, true)
	}
	c.Summarise()

	out := buf.String()
	if !strings.Contains(out, "diverged=4") {
		t.Errorf("сводка не назвала число расхождений: %s", out)
	}
	if !strings.Contains(out, "classes=1") {
		t.Errorf("сводка не назвала число классов: %s", out)
	}
	if !strings.Contains(out, "×4") {
		t.Errorf("сводка не назвала, сколько раз встретился класс: %s", out)
	}
}
