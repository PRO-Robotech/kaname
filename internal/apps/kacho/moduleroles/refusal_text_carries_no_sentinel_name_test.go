// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// refusal_text_carries_no_sentinel_name_test.go — текст отказа, который читает
// ВЫЗЫВАЮЩИЙ, не несёт служебного имени признака (задача #1889).
//
// ПОЧЕМУ ЗДЕСЬ, А НЕ ТОЛЬКО В `internal/errors`. Юнит на `StripSentinel` зовёт
// функцию без вызывающего и без тракта: он закрепляет ОТВЕТ функции, а не то,
// что доезжает до клиента. Наблюдалось же обратное — имя признака приезжало
// сквозь исполнителя транзакций, потому что применитель ставит свой контекст
// ВПЕРЁД и префикс перестаёт совпадать. Проба идёт тем же путём, каким шёл
// наблюдавшийся отказ: применитель → исполнитель → `shared.MapRepoErr`.
//
// ТРИ ПОЛОЖИТЕЛЬНЫХ КОНТРОЛЯ СТОЯТ РЯДОМ С ОТРИЦАНИЕМ, и они несущие.
// Утверждение «в тексте нет слов признака» выполняется тривиально на пустом
// тексте, на подменённом коде и на отказе, потерявшем предмет, — то есть на
// трёх разных поломках сразу. Поэтому рядом требуется: класс отказа тот же ·
// предмет назван дословно · контекст вызывающего сохранён.
package moduleroles_test

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/moduleroles"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

func TestWriterRefusalTextCarriesNoSentinelName(t *testing.T) {
	store := &refusingStore{
		fakeStore: newStore(),
		onRefs: iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"resources: %s is not a live platform resource", "probeWithdrawn"),
	}
	_, err := applierUnderTest(t, store).Apply(context.Background(),
		clusterManifest("vpc", "vpc.network.admin",
			[]manifest.Rule{{Module: "vpc", Resources: []string{"network"}, Classes: []string{"get"}}}),
		moduleroles.BootActorID)
	if err == nil {
		t.Fatalf("писатель отказал — применение обязано отказать тоже")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("отказ не несёт статуса: %v", err)
	}
	msg := st.Message()

	// ОТРИЦАНИЕ: имени признака в тексте нет. Проверяются оба текста — статуса
	// и цепочки: клиент за проводом читает первый, вызывающий в процессе —
	// второй, и разойтись им нельзя.
	for _, name := range []string{
		iamerr.ErrFailedPrecondition.Error(),
		iamerr.ErrInvalidArg.Error(),
		iamerr.ErrNotFound.Error(),
	} {
		if strings.Contains(msg, name+": ") {
			t.Errorf("текст статуса несёт служебное имя признака %q: %q", name, msg)
		}
		if strings.Contains(err.Error(), name+": ") {
			t.Errorf("текст цепочки несёт служебное имя признака %q: %v", name, err)
		}
	}

	// КОНТРОЛЬ 1: класс отказа тот же. Без него отрицание выполнялось бы на
	// отказе, схлопнутом в опаковый INTERNAL.
	if got := st.Code(); got != codes.FailedPrecondition {
		t.Errorf("класс отказа изменился: %v, хотел %v", got, codes.FailedPrecondition)
	}
	// КОНТРОЛЬ 2: предмет назван дословно — текст базы есть часть контракта.
	if !strings.Contains(msg, "resources: probeWithdrawn is not a live platform resource") {
		t.Errorf("отказ потерял предмет: %q", msg)
	}
	// КОНТРОЛЬ 3: контекст вызывающего сохранён — снимается ИМЯ ПРИЗНАКА, а не
	// всё, что стоит перед предметом.
	if !strings.Contains(msg, "moduleroles: writing the declared role failed: vpc.network.admin") {
		t.Errorf("отказ потерял контекст вызывающего: %q", msg)
	}
	// КОНТРОЛЬ 4: полоса по-прежнему различима машинно (#1880 не сломан).
	if got := moduleroles.RefusalLane(err); got != moduleroles.LaneWriteFailed {
		t.Errorf("полоса писателя перестала доезжать: %q, хотел %q", got, moduleroles.LaneWriteFailed)
	}

	t.Logf("перепись: осмотрено текстов 2 (статус · цепочка), имён признака сверено 3, контролей 4")
}
