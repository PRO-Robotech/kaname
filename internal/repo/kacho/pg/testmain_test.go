// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/pgtest"

	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// TestMain owns the one Postgres this package runs against, and enforces that the
// integration proofs cannot silently vanish from CI.
//
// # Why one container rather than one per test
//
// setupTestDB used to start a fresh container AND replay every migration on each
// call, and it is called hundreds of times here. That is what made this the most
// expensive package in the tree; the cost was the harness, not the tests.
//
// The container starts once, the migrations run once into a template database, and
// each caller gets its own database cloned from that template. Postgres builds a
// clone by copying the template's files, so it is cheap while remaining a genuinely
// separate database: the isolation the CAS / UNIQUE / EXCLUDE / SKIP LOCKED proofs
// depend on is unchanged, and concurrent goroutines inside one test still contend
// on the same real rows. See internal/pgtest for the argument in full.
//
// This package used to carry its own hand-written copy of that machinery, which
// left it with TWO mechanisms: the shared container for setupTestDB, and four
// helpers that each still booted a container of their own (startPostgresUpTo,
// setupKac127TestDB, setupRedactorPG, and iampgtest.NewTestPostgres). They now all take
// their database from internal/pgtest, so there is one mechanism here.
//
// # The enforcement half (unchanged in intent)
//
// Every integration test here individually skips under `-short` — the sole
// silent-skip vector, since none of them gate on a separate Docker probe. A full
// CI run invoked with `-short` would therefore drop every race proof that
// data-integrity.md requires while still reporting green (a skipped test is
// neither red nor green). When KACHO_IAM_REQUIRE_INTEGRATION is set (the CI
// integration lane), `-short` is refused hard, before anything else runs.
//
// Under `-short` no container starts at all: pgtest starts one on first use, and
// every test that would ask for one skips first.
func TestMain(m *testing.M) {
	flag.Parse()
	if os.Getenv("KACHO_IAM_REQUIRE_INTEGRATION") != "" && testing.Short() {
		fmt.Fprintln(os.Stderr,
			"KACHO_IAM_REQUIRE_INTEGRATION set but -short given: refusing to skip integration/concurrency/DB-trigger proofs")
		os.Exit(1)
	}

	// МОДЕЛЬ ПРОЦЕССА — до первого теста, то есть до первого её читателя.
	//
	// Окно у установки ровно одно и то же, что на старте службы: установка после
	// первого чтения запрещена (`authzmodel.ErrModelAlreadyRead`), а читают модель
	// пути вердикта. Другого места, где это окно ещё открыто, в прогоне пакета нет.
	//
	// Отказ ФАТАЛЕН и приходит ЗДЕСЬ, а не отказом вердикта: несозданное условие,
	// доехавшее до пробы, читалось бы как «красное» — и чинить пошли бы
	// `relverdict`, который ни при чём. Довод целиком —
	// harness_composed_model_test.go.
	//
	// Перепись печатается ВСЕГДА, независимо от исхода: без неё «добавлено 0»
	// неотличимо от «прочитано 0».
	rep, admission, mErr := installHarnessComposedModel()
	fmt.Fprintf(os.Stderr, "модель процесса прогона: композиция [%s]; допуск [%s]\n",
		rep.Census(), admission.Census())
	if mErr != nil {
		fmt.Fprintf(os.Stderr, "модель процесса не собрана: %v\n", mErr)
		os.Exit(1)
	}

	os.Exit(pgtest.Run(m, pgtest.Config{
		// Приведение схемы — ОДИН раз на пакет, у выдающего базу.
		// Прежде его приписывал каждый вызывающий своей копией; забывший
		// получал `relation … does not exist` — отказ, читающийся как дефект
		// продукта. Довод целиком — `internal/pgtest` §searchpath.
		SearchPath: "kacho_iam,public",
		Name:       "iam",
		Migrate:    pgtest.Goose(migrations.FS),
	}))
}
