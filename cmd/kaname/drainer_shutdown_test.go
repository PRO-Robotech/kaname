// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// drainer_shutdown_test.go — НАБЛЮДАЕМОЕ свойство задачи #2465: задача дренажа
// возвращает управление, когда отменён контекст гашения процесса.
//
// # Почему это проба ПОВЕДЕНИЯ, а не формы кода
//
// «В корне нет `context.Background()`» — свойство ДЕРЕВА, и его держит гейт
// рядом (`root_shutdown_context_test.go`). Здесь утверждается другое и более
// сильное: собранная задача действительно ВОЗВРАЩАЕТСЯ по отмене. Задача,
// принявшая контекст параметром и не отдавшая его вглубь, гейт проходит, а
// процесс держит ровно так же.
//
// # Почему проба не требует базы
//
// Пул `pgxpool` соединяется ЛЕНИВО, поэтому дренаж поднимается на адресе, где
// никто не слушает: подписка и клейм отказывают немедленно, а дренаж по
// контракту переживает недоступность базы — он для того и написан. Предмет
// пробы от базы не зависит: спрашивается «возвращается ли по отмене», а не
// «доставляет ли строки».
//
// # Отрицание стоит в паре с ПОЛОЖИТЕЛЬНЫМ контролем
//
// Сперва утверждается, что при ЖИВОМ контексте задача НЕ возвращается: без
// этого «вернулась после отмены» зеленело бы и на задаче, которая возвращается
// сразу и всегда, то есть на мёртвом дренаже.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// deadPool — пул к адресу, на котором никто не слушает. `pgxpool.New` не
// соединяется при построении, поэтому проба остаётся быстрой и не требует базы.
func deadPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(),
		"postgres://kaname:kaname@127.0.0.1:1/kaname?sslmode=disable")
	if err != nil {
		t.Fatalf("построить пул к недоступному адресу: %v", err)
	}
	// Закрытие — С ПРЕДЕЛОМ: голое `t.Cleanup(pool.Close)` ждёт соединение,
	// которое упавшая проба может не вернуть никогда, и уносит с собой вердикт
	// всего пакета. Канон дерева один на всех, и его держит гейт.
	pgtest.ClosePoolAtEnd(t, pool)
	return pool
}

// aliveGrace — сколько задаче даётся на то, чтобы НЕ вернуться при живом
// контексте. Величина мала намеренно: положительный контроль обязан быть
// дешёвым, а долгоживущая петля не возвращается ни за какой срок.
const aliveGrace = 300 * time.Millisecond

// shutdownGrace — предел ожидания возврата ПОСЛЕ отмены. Заведомо больше
// наблюдаемого возврата (миллисекунды) и заведомо меньше окна мягкого гашения
// пода, ради которого свойство и требуется.
const shutdownGrace = 30 * time.Second

// assertTaskStopsOnCancel — задача НЕ возвращается при живом контексте и
// возвращается после отмены.
func assertTaskStopsOnCancel(t *testing.T, name string, task func(context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- task(ctx) }()

	select {
	case err := <-done:
		t.Fatalf("%s: задача вернулась ДО отмены (%v) — положительный контроль не пройден: "+
			"утверждение «вернулась после отмены» на такой задаче зеленело бы всегда, "+
			"включая мёртвый дренаж", name, err)
	case <-time.After(aliveGrace):
	}

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("%s: задача вернулась с ошибкой %v — гашение обязано быть чистым", name, err)
		}
	case <-time.After(shutdownGrace):
		t.Fatalf("%s: задача НЕ вернулась за %s после отмены контекста гашения. "+
			"`runServe` оканчивается на `group.Wait()`, а группа ждёт ВСЕ задачи — "+
			"значит процесс не выйдет по сигналу вовсе, и его снимет среда по истечении "+
			"окна: посреди исходящего разговора, оставив строки очереди заклеймёнными "+
			"и не применёнными (kacho#2465)", name, shutdownGrace)
	}
}

// TestIAM2465_DrainerTasksReturnWhenTheShutdownContextIsCancelled — обе полосы
// дренажа корня обязаны нести свойство, которое несут остальные его задачи.
func TestIAM2465_DrainerTasksReturnWhenTheShutdownContextIsCancelled(t *testing.T) {
	pool := deadPool(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := metrics.NewRegistry()

	t.Run("письма приглашения", func(t *testing.T) {
		task, err := buildInviteMailDrainer(pool, config.Config{}, reg.InviteMailRecorder(), logger)
		if err != nil {
			t.Fatalf("сборка дренажа писем: %v", err)
		}
		assertTaskStopsOnCancel(t, "дренаж писем приглашения", task)
	})

	t.Run("компенсации провайдера", func(t *testing.T) {
		task, err := buildProviderCompensationDrainer(pool, config.Config{}, reg.CompensationRecorder(), logger)
		if err != nil {
			t.Fatalf("сборка дренажа компенсаций: %v", err)
		}
		assertTaskStopsOnCancel(t, "дренаж компенсаций провайдера", task)
	})
}
