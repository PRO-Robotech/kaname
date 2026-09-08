// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Снимок схемы — ЭТАЛОН для сведения миграций.
//
// Слепок берётся ЗАПРОСОМ к каталогу, а не дампом: дамп зависит от порядка
// вывода и версии инструмента, структура — нет. Сравнивать надо РЕЗУЛЬТАТ
// применения, а не текст, которым его записали.
//
// # Это ИНСТРУМЕНТ, а не проба, и место ему выбрано ТРЕМЯ гейтами
//
// Он ничего не утверждает о дереве: каждая его ветка либо пишет файл, либо
// падает от поломки самого инструмента. Живёт он тем же укладом, что соседние
// приборы (`../relverdict`, `../scalegrid`), — запросом по переменной
// окружения, и без запроса выходит пропуском ПЕРВЫМ же оператором.
//
// Каталог выбран не по вкусу. Файл связан с трёх сторон, и законный вход у него
// ровно один — этот:
//
//  1. `internal/migrations` (где он лежал) назван в PG_OUTSIDE_SELECTION_PKGS
//     корневого Makefile, а там действует «ПРОПУСК = ОТКАЗ»: цель считает
//     строки `--- SKIP` и краснеет на любой. Пропуск по незапрошенному снимку
//     неотличим там от пакета, не исполнившегося вовсе, — ради этой
//     неразличимости цель и заведена. Инструмент ронял её КАЖДЫМ прогоном.
//
//  2. Признак сборки (`integration_snapshot`, он здесь был) вернуть нельзя:
//     пакеты под признаком не читает ни обычная сборка, ни короткий прогон, и
//     `internal/repohygiene/buildtagrunreach_test.go` требует, чтобы у такого
//     пакета был прогон, передающий признак. Такого прогона нет.
//
//  3. Пакет обязан попадать ХОТЬ В КАКОЙ-НИБУДЬ прогон — этого требует гейт
//     `shortgatedselection_test.go`. Он и назвал исходы: войти в отбор
//     интеграционной джобы; либо получить свой шаг конвейера; либо быть
//     записанным долгом с именем в ведомости.
//
// Отбор интеграционной джобы — `/internal/(repo|clients|reconciler|
// subscriptionjournal)` внутри services/ — этот путь достаёт, а пропуски он
// терпит (`deploy/scripts/classify-integration-outcome.sh` их не считает).
// Поэтому инструмент исполняется, ничего не роняя, и долгом не числится:
// ведомость прощений тут была бы послаблением без предмета.
package schemasnapshot_test

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

func itoa(i int) string { return strconv.Itoa(i) }

func TestSchemaSnapshot(t *testing.T) {
	out := os.Getenv("KACHO_SCHEMA_SNAPSHOT_OUT")
	if out == "" {
		t.Skip("KACHO_SCHEMA_SNAPSHOT_OUT не задан — снимок не запрошен")
	}
	dsn := pgtest.NewEmptyDB(t)
	if err := pgtest.Goose(migrations.FS)(context.Background(), dsn); err != nil {
		t.Fatalf("проиграть цепочку миграций: %v", err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("соединение: %v", err)
	}
	defer func() { _ = db.Close() }()

	// СНЯТИЕ ЛЕГАСИ выполняет СЕРВЕР, а не правка текста.
	//
	// Свод — преемник цепочки, а не её копия: то, что он снимает, обязано уйти
	// вместе со ВСЕМИ зависимыми объектами — ключами, индексами, ограничениями,
	// внешними ссылками. Перечислить их руками значит завести перечень, который
	// разойдётся с деревом молча; `DROP TABLE … CASCADE` знает их точно.
	//
	// Снятие идёт ДО слепка намеренно: тогда слепок есть «эталон минус
	// названные снятия», и равенство свода ему проверяется тем же побайтовым
	// сравнением, что и равенство без снятий. Разность двух слепков —
	// эталонного и этого — и есть поимённый перечень снятого.
	if retire := os.Getenv("KACHO_SCHEMA_RETIRE"); retire != "" {
		for _, name := range strings.Split(retire, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if _, derr := db.Exec(`DROP TABLE kaname.` + name + ` CASCADE`); derr != nil {
				t.Fatalf("снять %s: %v", name, derr)
			}
			t.Logf("снято: kaname.%s", name)
		}
	}

	var lines []string
	add := func(q string) {
		rows, err := db.Query(q)
		if err != nil {
			t.Fatalf("запрос слепка: %v", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatalf("чтение слепка: %v", err)
			}
			lines = append(lines, s)
		}
	}
	// колонки с типами и умолчаниями
	add(`SELECT 'COL '||table_name||'.'||column_name||' '||data_type||' null='||is_nullable||
	       ' def='||coalesce(column_default,'-')
	     FROM information_schema.columns WHERE table_schema='kaname'`)
	// ограничения с их выражениями
	add(`SELECT 'CON '||rel.relname||' '||con.conname||' '||pg_get_constraintdef(con.oid)
	     FROM pg_constraint con JOIN pg_class rel ON rel.oid=con.conrelid
	     JOIN pg_namespace n ON n.oid=rel.relnamespace WHERE n.nspname='kaname'`)
	// индексы
	add(`SELECT 'IDX '||indexname||' '||indexdef FROM pg_indexes WHERE schemaname='kaname'`)
	// триггеры
	add(`SELECT 'TRG '||c.relname||' '||t.tgname||' '||pg_get_triggerdef(t.oid)
	     FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
	     JOIN pg_namespace n ON n.oid=c.relnamespace
	     WHERE n.nspname='kaname' AND NOT t.tgisinternal`)
	// функции
	add(`SELECT 'FUN '||p.proname||' '||md5(pg_get_functiondef(p.oid))
	     FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='kaname'`)

	// Дамп снимается ТЕМ ЖЕ соединением, что и слепок: он даст SQL, которым
	// сведённая миграция и воспроизведёт схему. Слепок остаётся ПРЕДИКАТОМ
	// равенства, дамп — исходником; путать их нельзя.
	if dumpTo := os.Getenv("KACHO_SCHEMA_DUMP_OUT"); dumpTo != "" {
		cmd := exec.Command("pg_dump", "--schema-only", "--no-owner", "--no-privileges",
			"--schema=kaname", dsn)
		out, derr := cmd.Output()
		if derr != nil {
			t.Fatalf("снять дамп: %v", derr)
		}
		if werr := os.WriteFile(dumpTo, out, 0o644); werr != nil {
			t.Fatalf("запись дампа: %v", werr)
		}
		t.Logf("дамп схемы: байт %d → %s", len(out), dumpTo)
	}

	// ПОЛНЫЙ дамп — исходник сведённой миграции, и берётся он ОДНИМ вызовом, а
	// не склейкой схемы с данными. Порядок здесь несущий: pg_dump кладёт данные
	// МЕЖДУ созданием таблиц и созданием ограничений, индексов и триггеров.
	// Склеив два дампа руками, получаешь триггеры до вставок — и они дописывают
	// производные строки поверх тех, что дамп уже несёт. Расхождение переписи
	// приходит не оттуда, где его ищут.
	if fullTo := os.Getenv("KACHO_SCHEMA_FULL_OUT"); fullTo != "" {
		cmd := exec.Command("pg_dump", "--no-owner", "--no-privileges",
			"--column-inserts", "--schema=kaname", dsn)
		out, derr := cmd.Output()
		if derr != nil {
			t.Fatalf("снять полный дамп: %v", derr)
		}
		if werr := os.WriteFile(fullTo, out, 0o644); werr != nil {
			t.Fatalf("запись полного дампа: %v", werr)
		}
		t.Logf("полный дамп: байт %d → %s", len(out), fullTo)
	}

	// Дамп ДАННЫХ: перепись говорит СКОЛЬКО строк, но не ЧТО в них. Различить
	// справочник продукта («обязана ли строка существовать у арендатора») от
	// данных стенда по одному счётчику нельзя — нужно увидеть сами строки.
	if dataTo := os.Getenv("KACHO_SCHEMA_DATA_OUT"); dataTo != "" {
		cmd := exec.Command("pg_dump", "--data-only", "--no-owner", "--no-privileges",
			"--column-inserts", "--schema=kaname", dsn)
		out, derr := cmd.Output()
		if derr != nil {
			t.Fatalf("снять дамп данных: %v", derr)
		}
		if werr := os.WriteFile(dataTo, out, 0o644); werr != nil {
			t.Fatalf("запись дампа данных: %v", werr)
		}
		t.Logf("дамп данных: байт %d → %s", len(out), dataTo)
	}

	// Перепись СТРОК: дамп структуры их не несёт, а 47 миграций сеют. Различить
	// справочник продукта и данные стенда можно только увидев, что осталось.
	if rowsTo := os.Getenv("KACHO_SCHEMA_ROWS_OUT"); rowsTo != "" {
		var rl []string
		rs, rerr := db.Query(`SELECT table_name FROM information_schema.tables
		    WHERE table_schema='kaname' AND table_type='BASE TABLE' ORDER BY table_name`)
		if rerr != nil {
			t.Fatalf("перечень таблиц: %v", rerr)
		}
		var names []string
		for rs.Next() {
			var n string
			if err := rs.Scan(&n); err != nil {
				t.Fatalf("имя таблицы: %v", err)
			}
			names = append(names, n)
		}
		_ = rs.Close()
		for _, n := range names {
			var c int
			if err := db.QueryRow(`SELECT count(*) FROM kaname.` + n).Scan(&c); err != nil {
				t.Fatalf("счёт строк %s: %v", n, err)
			}
			if c > 0 {
				rl = append(rl, n+" "+itoa(c))
			}
		}
		if werr := os.WriteFile(rowsTo, []byte(strings.Join(rl, "\n")+"\n"), 0o644); werr != nil {
			t.Fatalf("запись переписи строк: %v", werr)
		}
		t.Logf("таблиц с данными: %d из %d", len(rl), len(names))
	}

	sort.Strings(lines)
	if err := os.WriteFile(out, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("запись слепка: %v", err)
	}
	t.Logf("слепок схемы: строк %d → %s", len(lines), out)
}
