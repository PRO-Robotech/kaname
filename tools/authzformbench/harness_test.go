// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzformbench

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMain terminates the shared stack after the package's tests.
func TestMain(m *testing.M) {
	code := m.Run()
	CloseSharedStack()
	os.Exit(code)
}

// bootForTest brings up the stack and returns it with the canonical DSL.
//
// A stack that will not start FAILS; it never skips. Inverting that would report
// "the comparison did not run" as green — the exact third outcome this package
// exists to keep visible.
func bootForTest(ctx context.Context, t *testing.T) (*Stack, string) {
	t.Helper()
	stack, err := SharedStack(ctx)
	require.NoError(t, err, "authzformbench: the measurement stack did not come up")
	path, canon, err := ResolveCanonicalModel()
	require.NoError(t, err)
	require.NotEmpty(t, canon)
	_ = path
	return stack, string(canon)
}

// ── предпосылка: прибор обязан быть показан РАЗЛИЧАЮЩИМ свой вход ─────────────
//
// Здесь стояли две пробы, и обе сняты вместе с движком отношений, а не «за
// ненадобностью»:
//
//   - различение по ВХОДУ снималось на форме A, чья цена ЕСТЬ N·M·S: удвоение N
//     обязано было удвоить и объём, и число круговых обращений. У формы E цена
//     выдачи ПОСТОЯННА по N — это её объявленная арифметика, а не сбой, — поэтому
//     то же утверждение на ней провалило бы законное поведение. Свойство не
//     потеряно: его несёт `TestHarnessSeesTheInputOfFormE` ниже, где растущей
//     величиной объявлена структурная часть, и оно перенесено туда вместе с
//     проверкой живости канала длительностей;
//   - различение между ФОРМАМИ (две формы на одних данных не должны дать один
//     объём) предмета лишилось буквально: форма осталась одна. Утверждать
//     «прибор не путает A с BCD» больше не о чем.

// TestHarnessSeesTheInputOfFormE — вторая предпосылка на шестой форме: прибор
// обязан быть показан различающим ЕЁ вход, а не только вход формы A.
//
// Точное удвоение здесь не требуется и требоваться не может: оно — арифметика
// формы A (её цена ЕСТЬ N·M·S), и три формы из пяти уже сегодня его не дают.
// Требование «вырасти вдвое», перенесённое на форму E, либо провалило бы её за
// законное поведение, либо вынудило бы написать её пооператорно — то есть
// исказить измеряемое ради утверждения о нём.
//
// Поэтому проверяется ПАРА, объявленная до прогона: (а) арифметика формы E
// называет величину, обязанную вырасти с N, — это структурная часть (строка
// зеркала на объект); (б) измерение показывает рост именно там и именно такой,
// какой арифметика предсказала. И отдельно — что величина выдачи ПОСТОЯННА, как
// её арифметика и объявляет: постоянство здесь результат, а не отказ прибора.
func TestHarnessSeesTheInputOfFormE(t *testing.T) {
	if testing.Short() {
		t.Skip("real-OpenFGA proof; -short")
	}
	ctx := t.Context()
	stack, _ := bootForTest(ctx, t)

	cfg := DefaultConfig()
	cfg.Forms = []Form{FormE}
	cfg.WriteRepeats = 2
	cfg.RelabelK = 5
	r := NewRunner(stack, cfg)

	small := NewScenario(20, 10, 5, "editor", DefaultVerbs())
	large := NewScenario(40, 10, 5, "editor", DefaultVerbs())

	cs := cellsByOp(r.RunWrites(ctx, FormE, small))
	cl := cellsByOp(r.RunWrites(ctx, FormE, large))
	require.Equalf(t, Measured, cs[OpVolume].Outcome, "объём при N=20: %s", cs[OpVolume].Reason)
	require.Equalf(t, Measured, cl[OpVolume].Outcome, "объём при N=40: %s", cl[OpVolume].Reason)

	// (а)+(б) величина, объявленная растущей, выросла — и ровно до предсказанного.
	require.Equal(t, int64(ExpectedStructuralRows(FormE, small)), cs[OpVolume].StructuralRows,
		"структурная часть формы E при N=20 разошлась с её объявленной арифметикой")
	require.Equal(t, int64(ExpectedStructuralRows(FormE, large)), cl[OpVolume].StructuralRows)
	require.Greater(t, cl[OpVolume].StructuralRows, cs[OpVolume].StructuralRows,
		"ни одна величина формы E не ответила на удвоение входа — предпосылка «прибор различает» "+
			"для шестой формы осталась бы недоказанной, и это находка постановки, а не результат")

	// Величина ВЫДАЧИ постоянна — и это её объявленная арифметика, а не сбой.
	require.Equal(t, int64(ExpectedGrantTuples(FormE, small)), cs[OpVolume].GrantTotal)
	require.Equal(t, cs[OpVolume].GrantTotal, cl[OpVolume].GrantTotal,
		"цена выдачи формы E изменилась с N, хотя её арифметика объявляет постоянство (S+2) — "+
			"расходятся измерение и арифметика, и публиковать нельзя ни то, ни другое")

	// Колонка стейтментов у формы E измерена, а не подставлена нулём, и сверена
	// со СВОЕЙ объявленной до прогона арифметикой — по каждой операции.
	//
	// Это не педантизм, а дыра, найденная инъекцией в эту самую пробу: форма E,
	// которая вдобавок к выдаче переразмечает весь набор, проходит ВСЕ утверждения
	// об объёме (правка метки строк не добавляет) и падает только здесь. Пока
	// величина сверялась только с «больше нуля», удвоение работы было невидимо.
	require.Empty(t, cs[OpGrant].StmtNote, "производитель StmtSQL формы E не прошёл контроль")
	for _, op := range []Op{OpGrant, OpRevoke, OpRelabel1, OpRelabelK, OpInlineGrant, OpInlineRevoke} {
		want := ExpectedStatements(FormE, op)
		require.Equalf(t, want, cs[op].StmtSQL,
			"%s при N=20: измерено %d стейтментов против объявленных %d — расходятся измерение "+
				"и арифметика, и публиковать нельзя ни то, ни другое", op, cs[op].StmtSQL, want)
		require.Equalf(t, want, cl[op].StmtSQL,
			"%s при N=40 стоила %d стейтментов против %d при N=20 — величина, объявленная "+
				"постоянной по N, с N изменилась", op, cl[op].StmtSQL, cs[op].StmtSQL)
	}
	// (в) канал длительностей ЖИВ и снят с ЭТОЙ операции. Предикат назван и живёт
	// рядом со своей инъекцией (`durationchannel_test.go`): три свойства — счётное
	// число повторов, пошедшие часы, порядок процентов между собой. Загрузка
	// машины не двигает ни одно.
	//
	// Блок перенесён сюда со снятой пробы формы A — вместе с её уроком (#713).
	// Прежде рядом стояло «вдвое большая работа обязана быть медленнее»; мысль
	// верна, способ проверки — нет: он сравнивал два ЗАМЕРА, то есть спрашивал про
	// свойство машины, а отвечал как про свойство дерева.
	//
	// ЧЕТВЁРТОГО СВОЙСТВА — «разброс непустой» (max > min) — здесь больше НЕТ, и
	// это не ослабление, а перенос вопроса туда, где на него есть ответ (#1516).
	// Оно роняло исправный стенд: два подлинных замера в ~2.7 мс совпадали после
	// усечения прибора до целых микросекунд, и вердикт становился функцией
	// разрешения часов. Хуже того, оно было неисполнимо по существу — подлинный
	// замер быстрой операции и подставленная константа ПО ЗНАЧЕНИЯМ неразличимы.
	// Своё «прибор не отдаёт константу» теперь доказывает
	// `TestTimerAnswersTheWorkItWasGiven`: там разница входов не выпрашивается у
	// машины, а создаётся ожиданием, и допуск назван числом.
	//
	// ГРАНИЦА НАЗВАНА ЧЕСТНО. Пара «повторов столько, сколько заказано» + «прибор
	// не константа» не покрывает одного остатка: цикл, который позвал прибор
	// дважды, а в выборку положил один и тот же замер. По значениям он неотличим
	// от быстрой машины (в том и суть), а отличить его по построению значило бы
	// протащить через выборки опознавательный номер снятия — то есть переписать
	// сам прибор ради утверждения о нём.
	for _, c := range []struct {
		name string
		cell Cell
	}{{"N=20", cs[OpGrant]}, {"N=40", cl[OpGrant]}} {
		require.NoErrorf(t, cellDurationChannelIsLive(c.cell, cfg.WriteRepeats),
			"%s: канал длительностей", c.name)
	}

	// (г) направление длительности — НАБЛЮДЕНИЕ, а не вердикт. Печатается, чтобы
	// его можно было прочесть в логе рядом со счётными величинами, и никогда не
	// роняет прогон: величина, которую двигают соседи по машине, не может быть
	// условием посадки (#713).
	t.Logf("наблюдение, не вердикт: grant p50 N=20 %.1fмс (min %.1f, max %.1f) против "+
		"N=40 %.1fмс (min %.1f, max %.1f); счётные стейтменты %d → %d, структурных строк %d → %d",
		cs[OpGrant].P50, cs[OpGrant].Min, cs[OpGrant].Max,
		cl[OpGrant].P50, cl[OpGrant].Min, cl[OpGrant].Max,
		cs[OpGrant].StmtSQL, cl[OpGrant].StmtSQL,
		cs[OpVolume].StructuralRows, cl[OpVolume].StructuralRows)
}

func cellsByOp(cs []Cell) map[Op]Cell {
	m := map[Op]Cell{}
	for _, c := range cs {
		m[c.Op] = c
	}
	return m
}
