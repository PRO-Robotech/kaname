// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package accesssnapshot

// accesssnapshot_test.go — инструмент доказывает СВОЮ способность упасть.
//
// Снимок доступа существует ради утверждения «права переносятся, не
// расширяясь». Инструмент, который этого не различает, хуже отсутствующего: он
// отчитается зелёным о переносе, которого не было.
//
// Здесь проверяется ровно это, и обе ловушки названы приёмкой:
//
//   - равенство обязано падать в ОБЕ стороны. Проба, проверяющая только «всё
//     прежнее доступно», зеленеет на РАСШИРЕНИИ — то есть ровно на том, что
//     формулировка запрещает. Второе направление важнее первого: потеря шумит
//     (человек жалуется), приобретение молчит;
//   - пустое множество равно пустому. Несобравшийся снимок сравнивается с таким
//     же пустым и объявляет перенос доказанным.

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// stubChecker отвечает разрешением на объекты из allow и считает вопросы.
//
// Счётчик под мьютексом не для красоты: инструмент спрашивает партию
// ПАРАЛЛЕЛЬНО — это его заявленное свойство, — а настоящая дверь решения
// (`authzcascade.Client` поверх реляционной формы) безопасна для конкурентного
// вызова. Дублёр, который таковым не является, расходится с настоящим ровно в
// том, ради чего его подставляют, и роняет пробу гонкой в самом инструменте
// измерения.
type stubChecker struct {
	mu    sync.Mutex
	allow map[string]bool
	err   error
	asked int
}

func (c *stubChecker) Check(_ context.Context, _, _, object string) (bool, error) {
	if c.err != nil {
		return false, c.err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.asked++
	return c.allow[object], nil
}

func (c *stubChecker) askedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.asked
}

// pagesOf отдаёт идентификаторы страницами, как курсор своей БД.
func pagesOf(ids ...string) PageFunc {
	return func(_ context.Context, after string, limit int) ([]string, error) {
		start := 0
		if after != "" {
			for i, id := range ids {
				if id == after {
					start = i + 1
					break
				}
			}
		}
		if start >= len(ids) {
			return nil, nil
		}
		end := min(start+limit, len(ids))
		return ids[start:end], nil
	}
}

func snap(t *testing.T, allow map[string]bool, ids ...string) Snapshot {
	t.Helper()
	s, err := Take(context.Background(), &stubChecker{allow: allow},
		pagesOf(ids...), "user:u", "v_get", "project")
	require.NoError(t, err)
	return s
}

func TestCompare_FailsOnLoss(t *testing.T) {
	before := snap(t, map[string]bool{"project:p1": true, "project:p2": true}, "p1", "p2", "p3")
	after := snap(t, map[string]bool{"project:p1": true}, "p1", "p2", "p3")

	d, err := Compare(before, after)
	require.NoError(t, err)
	require.False(t, d.Empty(), "потеря доступа обязана быть замечена")
	require.Equal(t, []string{"p2"}, d.Lost)
	require.Empty(t, d.Gained)
}

// Направление, ради которого всё и написано: РАСШИРЕНИЕ.
//
// Односторонняя проба («всё прежнее доступно») здесь зелена — прежнее-то
// доступно. Именно поэтому её недостаточно.
func TestCompare_FailsOnGain(t *testing.T) {
	before := snap(t, map[string]bool{"project:p1": true}, "p1", "p2", "p3")
	after := snap(t, map[string]bool{"project:p1": true, "project:p3": true}, "p1", "p2", "p3")

	d, err := Compare(before, after)
	require.NoError(t, err)
	require.False(t, d.Empty(),
		"приобретение доступа обязано быть замечено: «не расширяясь» — половина утверждения, "+
			"и молчаливая половина")
	require.Equal(t, []string{"p3"}, d.Gained)
	require.Empty(t, d.Lost,
		"и при этом ничего не потеряно — односторонняя проба была бы здесь зелёной")
}

// Положительный контроль к обеим сторонам: совпадение действительно совпадает.
// Без него «падает на потере» и «падает на приобретении» были бы верны и у
// компаратора, который падает всегда.
func TestCompare_SilentOnEqualSets(t *testing.T) {
	allow := map[string]bool{"project:p1": true, "project:p3": true}
	before := snap(t, allow, "p1", "p2", "p3")
	after := snap(t, allow, "p1", "p2", "p3")

	d, err := Compare(before, after)
	require.NoError(t, err)
	require.True(t, d.Empty(), "равные множества обязаны сойтись: %+v", d)
}

// Вторая ловушка: пустое равно пустому.
func TestCompare_RefusesToCompareUnassembledSnapshots(t *testing.T) {
	empty := snap(t, map[string]bool{}) // страниц нет — осмотрено ноль
	require.Zero(t, empty.Examined, "ПРЕДПОСЫЛКА: снимок не собрался")

	nonEmpty := snap(t, map[string]bool{"project:p1": true}, "p1")

	for _, tc := range []struct {
		name          string
		before, after Snapshot
	}{
		{"не собрался «до»", empty, nonEmpty},
		{"не собрался «после»", nonEmpty, empty},
		{"не собрались оба", empty, empty},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compare(tc.before, tc.after)
			require.Error(t, err,
				"сравнение несобравшегося снимка обязано ОТКАЗЫВАТЬ, а не совпадать: "+
					"пустое совпадёт с любым пустым и объявит перенос доказанным")
			require.Contains(t, err.Error(), "осмотрено объектов",
				"отказ обязан называть, ЧЕГО не хватило — иначе его прочтут как поломку инструмента")
		})
	}
}

// Пустой доступ при НЕПУСТОМ осмотре — законное состояние, а не отказ.
// Человек без прав существует; отвергнув этот случай, инструмент требовал бы
// дефекта для своей работы.
func TestCompare_AllowsEmptyAccessWhenObjectsWereExamined(t *testing.T) {
	before := snap(t, map[string]bool{}, "p1", "p2")
	after := snap(t, map[string]bool{}, "p1", "p2")
	require.Positive(t, before.Examined)

	d, err := Compare(before, after)
	require.NoError(t, err, "ноль доступа — законное состояние, если объекты осмотрены")
	require.True(t, d.Empty())
}

// «Спросить не удалось» — НЕ «доступа нет».
//
// Вернуть здесь частичный снимок значило бы объявить потерю прав там, где её
// никто не наблюдал: у следующего сравнения все недоспрошенные объекты попали
// бы в Lost. Ответ решающей стороны различает эти миры сам (форма возвращает
// ОШИБКУ, а не отказ, когда ответа получить не удалось), и инструмент обязан
// это различие сохранить, а не схлопнуть в пустое множество.
func TestTake_UnansweredQuestionIsNotAbsenceOfAccess(t *testing.T) {
	_, err := Take(context.Background(),
		&stubChecker{err: errors.New("relation store unavailable")},
		pagesOf("p1", "p2"), "user:u", "v_get", "project")
	require.Error(t, err,
		"невозможность спросить обязана доезжать до вызывающего, а не превращаться "+
			"в пустой снимок")
}

// Обход идёт СТРАНИЦАМИ и спрашивает КАЖДЫЙ объект.
//
// Утверждение про потолок партии: объектов больше, чем BatchSize, — и все
// осмотрены, то есть курсор довёл до конца, а не остановился на первой странице.
func TestTake_WalksEveryObjectAcrossPages(t *testing.T) {
	ids := make([]string, 0, BatchSize+7)
	allow := map[string]bool{}
	for i := range BatchSize + 7 {
		id := "p" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		ids = append(ids, id)
		if i%2 == 0 {
			allow["project:"+id] = true
		}
	}
	ch := &stubChecker{allow: allow}
	s, err := Take(context.Background(), ch, pagesOf(ids...), "user:u", "v_get", "project")
	require.NoError(t, err)

	require.Equal(t, len(ids), s.Examined,
		"осмотрены обязаны быть ВСЕ объекты: остановка на первой странице дала бы усечённое "+
			"множество — ровно то, из-за чего «перечисли всё доступное» не годится (см. шапку пакета)")
	require.Equal(t, len(ids), ch.askedCount())
	require.Len(t, s.Allowed, (len(ids)+1)/2)
}
