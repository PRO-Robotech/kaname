// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap_token

import (
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/PRO-Robotech/corelib/pgtest"
)

// setupTestDB hands the calling test its OWN database — all goose migrations
// already applied (including 0058, which seeds the bootstrap SA + grant) — and
// returns a dsn with search_path=kaname.
//
// It used to start a fresh container and replay the whole chain on every call.
// The database now comes from the one container this test binary owns (wired in
// testmain_pgtest_test.go), cloned from a template migrated once — see
// pkg/pgtest for why a clone is the same isolation a separate container
// gave. The 0058 seed is part of the template, so it is present in every clone.
//
// # Почему здесь стоит пропуск под кратким режимом
//
// Пропуска тут не было, и это делало пакет ЕДИНСТВЕННЫМ во всём дереве, кто
// поднимает Postgres под `-short`. Перепись поведением (маркер в
// pkg/pgtest.newDatabase, прогон 43 пакетов-владельцев контейнера,
// `-short -p 1`): три теста этого пакета доходят до старта контейнера, у
// остальных 42 пакетов — ноль.
//
// Следствие было двойным. `make test-unit` (`go test ./... -race -short`) идёт с
// умолчанием `-p` = число ядер, то есть 12 пакетов разом, и его собственное
// обоснование гласит, что `-short` отсекает пакеты с testcontainers, — для этого
// пакета неверно. При этом отбор интеграционной джобы идёт по пути
// (`/internal/(repo|clients)` внутри services/), и сюда не достаёт. Значит
// контейнерные пробы исполняла ТОЛЬКО быстрая волна — в той самой раскладке,
// которую корневой Makefile описывает как негодную для контейнерных пакетов
// («под -p 12 контейнерные пакеты голодают друг у друга»). И второе, независимое
// от нагрузки: `pkg/pgtest` по построению ОТКАЗЫВАЕТ, а не пропускает, когда
// демона Docker нет, — поэтому быстрая волна, задуманная как обходящаяся без
// Docker, без него не проходила.
//
// Пропуск здесь НЕ снимает пробы с прогона: их гоняет контейнерное задание
// конвейера (`.github/scripts/run-integration.sh`, вердикт по числам). Отбор
// этого задания ВЫВОДИТСЯ признаком «сборка проб импортирует pgtest либо
// testcontainers», поэтому пакет попадает в него by construction — вписывать его
// в перечень не нужно и негде.
//
// Здесь стояли цель `make test-pg-outside-selection` и гейт
// `internal/repohygiene/shortgatedselection_test.go`. Ни цели, ни гейта в этом
// дереве нет: оба остались в монорепо, а координаты пережили вынос службы
// (kaname#19). Пока отбор был выписан образцом пути, этот пакет не исполнялся
// НИ В ОДНОМ задании — и текст отсылал за прогоном к тому, чего нет.
func setupTestDB(t testing.TB) string {
	t.Helper()
	if testing.Short() {
		t.Skip("нужен Postgres в контейнере: пропуск под -short, прогон — контейнерное задание конвейера (.github/scripts/run-integration.sh)")
	}
	return pgtest.NewDB(t)
}
