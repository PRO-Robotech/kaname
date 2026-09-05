// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ledger_author_test.go — АВТОР снятия доезжает от применения до писателя
// ведомостей (#2005).
//
// # Что здесь утверждается и чего здесь НЕТ
//
// Здесь — только ШОВ: что применение зовёт оба оператора ведомости С АКТОРОМ,
// которого само же разрешило, а не с пустой строкой и не с константой писателя.
// Что колонка этот актор действительно принимает и что две записи от разных
// субъектов различаются, утверждает проба над живой базой
// (`ledgers_name_the_author_integration_test.go`); порознь ни одна из двух не
// достаточна.
//
// # Почему шов нужен отдельным утверждением
//
// «Актор разрешён» и «актор доехал до писателя» — разные факты. Между ними лежит
// пять шагов применения, и потеряться актор может молча: писатель принял бы
// пустую строку, колонка приняла бы её тоже (унаследованные строки автора не
// несут by construction), и ведомость отвечала бы «автор не записан» на каждое
// новое снятие. Со стороны это неотличимо от строки, переселённой до заведения
// колонки.
package modulecatalog_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
)

// TestApplyPassesTheResolvedActorToBothLedgers — несущее утверждение шва.
func TestApplyPassesTheResolvedActorToBothLedgers(t *testing.T) {
	w := &pruningWriter{live: liveTwo(),
		pruned: modulecatalog.Pruned{Rows: 1, Dropped: 0, Elements: 1}}
	applier := modulecatalog.NewApplier(&pruningTx{w: w})

	rep, err := applier.Apply(context.Background(), fixtureManifest("vpc", "network"))
	require.NoError(t, err)
	require.Positivef(t, rep.RetiredResources,
		"вход не произведён: снятия нет (%s) — значит ни один оператор ведомости не звался, "+
			"и утверждение об авторе беспредметно", rep)

	// Полоса СТАРТА несёт названный процессный актор. Именно его писатель и обязан
	// получить: подставленного `system` на этой полосе не бывает.
	require.Equalf(t, modulecatalog.BootActorID, w.appliedBy,
		"вырезание позвано с автором %q вместо %q: актор разрешён применением, но до "+
			"писателя не доехал", w.appliedBy, modulecatalog.BootActorID)
	require.NotEmpty(t, w.appliedBy,
		"автор пуст: писатель записал бы строку, неотличимую от переселённой ДО "+
			"заведения колонки — то есть ведомость отвечала бы «автор не записан» на "+
			"каждое новое снятие")

	// Переселение — второй оператор той же ведомости-пары, и молчание о нём
	// зеленело бы при авторе, доехавшем только до одного из двух.
	require.Equalf(t, modulecatalog.BootActorID, w.resettleAuthor,
		"переселение позвано с автором %q вместо %q", w.resettleAuthor, modulecatalog.BootActorID)

	t.Logf("осмотрено: снято ресурсов %d; автор у переселения %q, у вырезания %q",
		rep.RetiredResources, w.resettleAuthor, w.appliedBy)
}

// TestNothingRetiredMeansNoLedgerCall — положительный контроль.
//
// Без него утверждение выше зеленело бы у применения, зовущего ведомости ВСЕГДА:
// «автор доехал» не отличалось бы от «оператор зовётся на каждом применении, в
// том числе ничего не снявшем». Снятия нет — значит ведомость не трогают, и
// автору неоткуда взяться.
func TestNothingRetiredMeansNoLedgerCall(t *testing.T) {
	w := &pruningWriter{live: liveTwo()}
	applier := modulecatalog.NewApplier(&pruningTx{w: w})

	// Манифест объявляет ОБА живых ресурса: снимать нечего.
	rep, err := applier.Apply(context.Background(), fixtureManifest("vpc", "network", "gone"))
	require.NoError(t, err)
	require.Zerof(t, rep.RetiredResources, "предпосылка контроля: снятия быть не должно (%s)", rep)

	require.Empty(t, w.prunedFor,
		"вырезание позвано на применении, ничего не снявшем: ведомость наполняется "+
			"СНЯТИЕМ, а не фактом применения")
	require.Empty(t, w.appliedBy,
		"автор проставлен там, где ведомость не трогали — значит он следует применению, "+
			"а не снятию")
}
