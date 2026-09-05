// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzformbench

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Пин образа. Переопределяется окружением, чтобы прогон можно было повторить на
// той версии, которую несёт стенд; УМОЛЧАНИЕ — то, что дерево тянет и так, а
// отчёт печатает использованное.
//
// Здесь стояли ещё два пина — образ движка отношений и образ его командной
// строки. Оба сняты вместе с движком (S6). Вместе с ними ушёл и разнобой, который
// прежняя редакция этого файла честно называла: дерево пинило движок в двух
// местах разными версиями, и прибор не разрешал спор, а измерял потолок пакетной
// проверки на живом сервере. Спора больше нет — предмета не осталось.
const (
	defaultPostgres = "postgres:16-alpine"

	pgUser = "bench"
	pgPass = "bench"
	pgDB   = "bench"
)

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// Stack — Postgres, на котором прибор меряет форму E, и ничего кроме.
//
// Один стек на процесс: изоляцию между кейсами даёт СХЕМА внутри этой базы, и
// платить контейнером за кейс значило бы платить за изоляцию, которая уже есть,
// больше, чем стоит измеряемое. Это же свойство держит санкцию гейта
// `TestNoPackageStartsAContainerPerTest`, и доказано оно исходом —
// `isolation_test.go`, а не объявлением здесь.
//
// Прежде стек нёс ЧЕТЫРЕ предмета: сеть, Postgres движка отношений, сам движок и
// отдельный Postgres формы E. Первые три сняты вместе с движком; четвёртый остался
// и стал единственным. Отдельным он заводился затем, чтобы буферы, занятые
// кортежами движка, не наказывали чтение формы E за чужие данные, — довод пережил
// свой предмет, но не свою посадку: база по-прежнему своя, и числа остаются
// сопоставимыми с уже опубликованными отчётами.
type Stack struct {
	// DSN — строка подключения к этой базе. Хранилища формы E берут в ней по схеме.
	DSN string
	// Postgres — образ, который РЕАЛЬНО поднялся, а не тот, что задумывался.
	Postgres string

	terminate func()
}

var (
	stackOnce sync.Once
	stackVal  *Stack
	stackErr  error
)

// SharedStack поднимает стек при первом обращении и отдаёт его каждому следующему.
//
// Неудача подъёма возвращается КАЖДОМУ вызывающему, а не только тому, кто
// проиграл гонку за `Once`: иначе остальные пошли бы работать по пустому адресу и
// отчитались бы о форме как о «медленной» там, где не было поднято ничего.
func SharedStack(ctx context.Context) (*Stack, error) {
	stackOnce.Do(func() { stackVal, stackErr = bootStack(ctx) })
	return stackVal, stackErr
}

// CloseSharedStack гасит контейнер. Безопасна, когда ничего не поднималось.
func CloseSharedStack() {
	if stackVal != nil && stackVal.terminate != nil {
		stackVal.terminate()
		stackVal.terminate = nil
	}
}

func bootStack(ctx context.Context) (*Stack, error) {
	pgImage := envOr("AUTHZFORMBENCH_PG_IMAGE", defaultPostgres)

	req := testcontainers.ContainerRequest{
		Image:        pgImage,
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     pgUser,
			"POSTGRES_PASSWORD": pgPass,
			"POSTGRES_DB":       pgDB,
		},
		WaitingFor: wait.ForListeningPort("5432/tcp").
			WithStartupTimeout(90 * time.Second),
	}
	c, err := testcontainers.GenericContainer(ctx,
		testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		return nil, fmt.Errorf("поднять postgres: %w", err)
	}
	stop := func() { _ = c.Terminate(context.Background()) }

	host, err := c.Host(ctx)
	if err != nil {
		stop()
		return nil, fmt.Errorf("postgres, хост: %w", err)
	}
	port, err := c.MappedPort(ctx, "5432")
	if err != nil {
		stop()
		return nil, fmt.Errorf("postgres, порт: %w", err)
	}
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		pgUser, pgPass, host, port.Port(), pgDB)

	// Готовность спрашивается ДО возврата стека: контейнер, чей порт уже слушает,
	// ещё не обязан отвечать на запрос, и первая же операция замера отнеслась бы
	// к базе, которая поднималась, а не к форме.
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		stop()
		return nil, fmt.Errorf("открыть подключение: %w", err)
	}
	err = waitDB(ctx, db)
	_ = db.Close()
	if err != nil {
		stop()
		return nil, err
	}

	return &Stack{DSN: dsn, Postgres: pgImage, terminate: stop}, nil
}

func waitDB(ctx context.Context, db *sql.DB) error {
	deadline := time.Now().Add(60 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		last = db.PingContext(c)
		cancel()
		if last == nil {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("база так и не ответила: %w", last)
}
