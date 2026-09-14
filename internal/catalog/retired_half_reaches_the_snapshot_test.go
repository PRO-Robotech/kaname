// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_half_reaches_the_snapshot_test.go — снятая половина доезжает до факта
// ОБОИМИ путями: стартом и обновлением (kacho#1814, приёмка
// `docs/engineering/acceptance/retired-resource-names-its-successor.md`,
// `IAM-SUC-09` и `IAM-SUC-11`, слой кода).
//
// # Точек чтения снимка ДВЕ, и вторая — СТАРТ
//
// Путь обновления (`Refresh`) виден сразу и правится первым; путь СТАРТА
// (`NewSnapshot`) читает НОЛЬ операторов — строки приходят параметром от стража
// паритета. Пока параметром ехала одна живая половина, свежезапущенный процесс
// отвечал арендатору пустым перечнем снятого до первого обновления: целое окно
// он говорил «платформа ничего не снимала» на вопрос, ради которого к нему и
// пришли.
//
// Проба, утверждающая только обновление, эту половину предмета не видит вовсе:
// она зелена на снимке, который на старте берёт живую половину и доливает
// снятую через период.
//
// # Почему счётчик обращений, а не прочтение кода
//
// «Обе половины одним чтением» проверяется ЧИСЛОМ обращений к источнику:
// реализация, спросившая источник дважды, собрала бы факт из двух моментов, и
// арендатор увидел бы ресурс в обоих перечнях сразу либо ни в одном. Прочтение
// кода этого не утверждает.
package catalog_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
)

// halvesWithRetired — обе половины непусты.
//
// Живая берётся из литерала посева: она положительный контроль, без которого
// «снятое доехало» выполнялось бы и на снимке, взявшем всё подряд. Снятых строк
// две, и вторая преемника НЕ несёт — иначе «преемник пуст» было бы непредставимо.
func halvesWithRetired() catalog.Halves {
	return catalog.Halves{
		Live: seed.LiteralRows(),
		Retired: catalog.Rows{
			Resources: []catalog.ResourceRow{
				{Module: "compute", Resource: "disk", ObjectType: "compute_disk",
					SupersededBy: "storage.volumes"},
				{Module: "compute", Resource: "snapshot", ObjectType: "compute_snapshot"},
			},
		},
	}
}

// assertRetiredReached — снятая половина факта непуста И несёт преемника.
func assertRetiredReached(t *testing.T, f *catalog.Facts, path string) {
	t.Helper()
	got := f.RetiredResources()
	if len(got) != 2 {
		t.Fatalf("%s: снятых записей в факте %d, подано 2 — преемник существует данными "+
			"и до арендатора не доезжает", path, len(got))
	}
	// Порядок — по точечному имени: подано в обратном.
	if got[0].Resource != "disk" || got[1].Resource != "snapshot" {
		t.Errorf("%s: порядок перечня снятого не детерминирован: %+v", path, got)
	}
	if got[0].SupersededBy != "storage.volumes" {
		t.Errorf("%s: преемник compute.disk %q, подано storage.volumes", path, got[0].SupersededBy)
	}
	if got[1].SupersededBy != "" {
		t.Errorf("%s: у снятого без преемника поле преемника %q — факт обещает шаг, "+
			"которого строка не называла", path, got[1].SupersededBy)
	}
	// Положительный контроль: живая половина того же факта тоже непуста. Без
	// него «снятое доехало» было бы выполнимо снимком, потерявшим живое.
	if len(f.Resources()) == 0 {
		t.Errorf("%s: живая половина факта ПУСТА — снимок собран не из обеих половин", path)
	}
}

// TestIAMSUC11_StartPathCarriesTheRetiredHalf — `IAM-SUC-11`, слой кода.
//
// Процесс, чья петля обновления ещё ни разу не сработала, преемника уже
// называет: половины приходят параметром конструктора, а не читаются им.
func TestIAMSUC11_StartPathCarriesTheRetiredHalf(t *testing.T) {
	src := &stubSource{}
	snap, err := catalog.NewSnapshot(halvesWithRetired(), src, slog.New(&logSink{}), nil)
	if err != nil {
		t.Fatalf("снимок на старте: %v", err)
	}
	// Источник на старте НЕ спрашивается: строки уже прочитал страж паритета, и
	// второе чтение об одном предмете дало бы два места, расходящихся молча.
	if n := src.callCount(); n != 0 {
		t.Errorf("на старте у источника спросили каталог %d раз(а) — снимок завёл СВОЁ "+
			"чтение, и равенство операторов пути старта перестало держаться", n)
	}
	assertRetiredReached(t, snap.Facts(), "путь СТАРТА")
}

// TestIAMSUC09_RefreshCarriesBothHalvesInOneRead — `IAM-SUC-09`, слой кода.
//
// Обновление берёт обе половины ОДНИМ обращением к источнику. Число обращений
// утверждается наравне с содержимым: «одно обращение» на снимке, не взявшем
// снятую половину, истинно и бессмысленно.
func TestIAMSUC09_RefreshCarriesBothHalvesInOneRead(t *testing.T) {
	// Снимок на старте — БЕЗ снятой половины, чтобы её появление после
	// обновления было наблюдаемо, а не досталось от старта.
	src := &stubSource{}
	snap, err := catalog.NewSnapshot(catalog.Halves{Live: seed.LiteralRows()}, src,
		slog.New(&logSink{}), nil)
	if err != nil {
		t.Fatalf("снимок на старте: %v", err)
	}
	if n := len(snap.Facts().RetiredResources()); n != 0 {
		t.Fatalf("снятых записей на старте %d, подано 0 — контроль не выполнен, "+
			"и появление их после обновления доказывало бы не обновление", n)
	}

	src.setHalves(halvesWithRetired(), nil)
	if rerr := snap.Refresh(context.Background()); rerr != nil {
		t.Fatalf("обновление: %v", rerr)
	}
	if n := src.callCount(); n != 1 {
		t.Errorf("за одно обновление источник спрошен %d раз(а) — половины собраны из "+
			"РАЗНЫХ моментов, и ресурс оказался бы в обоих перечнях сразу либо ни в одном", n)
	}
	assertRetiredReached(t, snap.Facts(), "путь ОБНОВЛЕНИЯ")
}

// TestRetiredHalfMayBeEmptyAndThatMeansNothingIsRetired — пустая снятая
// половина ЗАКОННА и означает «снятого нет».
//
// Без этого утверждения реализация вправе была бы отвергать факт без снятой
// половины — то есть требовать от платформы, чтобы она что-нибудь сняла.
func TestRetiredHalfMayBeEmptyAndThatMeansNothingIsRetired(t *testing.T) {
	f, err := catalog.NewFacts(catalog.Halves{Live: seed.LiteralRows()})
	if err != nil {
		t.Fatalf("факт без снятой половины отвергнут: %v — платформа обязана была бы "+
			"что-нибудь снять, чтобы каталог собрался", err)
	}
	if n := len(f.RetiredResources()); n != 0 {
		t.Errorf("снятых записей %d при пустой снятой половине", n)
	}
	// Положительный контроль: живая половина собралась. Иначе «снятых ноль»
	// выполнялось бы на факте, не собравшемся вовсе.
	if len(f.Resources()) == 0 {
		t.Fatalf("живая половина пуста — утверждение выше вакуумно")
	}
}
