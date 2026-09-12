// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// outcome_class_test.go — накатчик САМ называет класс своего отказа, и называет
// его КОДОМ ВЫХОДА, а не прозой.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ КОД, А НЕ ТЕКСТ
//
// Читатель исхода наката — не человек, а шаг конвейера: он обязан отличить
// «условие не создано» (базы нет, вердикта о дереве НЕТ НИ ОДНОГО) от «находка о
// дереве» (накат отвергнут по существу). До этой правки читатель узнавал класс
// ПОИСКОМ СЛОВ в выводе накатчика, и слова эти приезжали из ЭХА ВВОДА: отказ
// «адрес базы не называет хоста» вкладывает в сообщение обеззараженную строку
// подключения, а обеззараживание сохраняет запрос — значит `sslmode` в тексте
// стоит всегда, потому что посадка стенда экспортирует `sslmode=require` всегда.
//
// Предикат, ищущий в выводе то, что сам же в него и послал, НЕОПРОВЕРЖИМ — то
// есть не замер. Сторона ошибки тут худшая из двух: дефект, о котором накатчик
// прямо говорит «ожидание не сойдётся НИКОГДА», подавался как факт расписания.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СЛОВАРЬ ОДИН, А НЕ ДВА
//
// Класс «база недостижима» УЖЕ объявлен в дереве — им накатчик решает, имеет ли
// смысл ждать: `dbready.IsNotReady`. Тот же предикат отвечает и на вопрос шага
// конвейера, поэтому классификация зовёт ЕГО, а не свою редакцию: вторая
// редакция одного предмета разошлась бы с первой молча и разошлась бы там, где
// расхождение не видно — обе стороны отвечают «годно» на годном входе.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕМ ЭТИ ПРОБЫ ОТЛИЧАЮТСЯ ОТ ПРЕЖНИХ
//
// Ошибки здесь НЕ СОЧИНЕНЫ строкой: каждую производит настоящий путь продукта —
// сборка наката (`buildRunner`) либо барьер готовности базы (`dbready.Wait`),
// которому подставлен отказ пинга. Сочинённая строка доказывала бы совпадение
// предиката с собственной формулировкой, а не классификацию продуктового отказа.
//
// Инъекция двусторонняя: у каждого класса есть законный близнец, отличающийся
// ОДНИМ фактом, и ни одна проба не зеленеет на классификаторе-постоянной —
// перепись ниже отказывает, если в наборе представлен не оба класса.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/PRO-Robotech/corelib/dbready"
)

// pingerRefusingEveryTime — подставной пинг базы: отвечает одной и той же
// ошибкой на каждый вызов. Нужен затем, чтобы барьер готовности произвёл СВОЮ
// ошибку (с бюджетом ожидания внутри) без живой базы: настоящий Postgres здесь
// не поднимается — ни в этом дереве проб, ни на машине без контейнерного движка.
type pingerRefusingEveryTime struct{ err error }

func (p pingerRefusingEveryTime) PingContext(context.Context) error { return p.err }

// waitBudgetForProbes — ощутимо меньший бюджет, чем боевые две минуты: предмет
// пробы — класс ошибки, а не длительность ожидания.
var waitBudgetForProbes = dbready.Options{
	InitialInterval: time.Millisecond,
	MaxInterval:     time.Millisecond,
	MaxElapsed:      5 * time.Millisecond,
}

// failureFromReadinessBarrier — ошибка, произведённая БАРЬЕРОМ ГОТОВНОСТИ на
// заданном отказе пинга, обёрнутая так же, как её обёртывает открытие базы:
// через `%w`. Оборачивание здесь не украшение, а предмет — оно доказывает, что
// класс не теряется на глубине, а в поставке глубина ровно такая (открытие базы
// оборачивает барьер, барьер оборачивает последнюю причину).
func failureFromReadinessBarrier(t *testing.T, pingErr error) error {
	t.Helper()
	err := dbready.Wait(context.Background(), pingerRefusingEveryTime{err: pingErr}, waitBudgetForProbes)
	if err == nil {
		t.Fatalf("барьер готовности вернул nil на отказе пинга %v — производитель ошибки сломан, "+
			"и пробы ниже мерили бы не то, что называют", pingErr)
	}
	return fmt.Errorf("open db (driver=pgx): %w", err)
}

// failureFromRunnerBuild — НАСТОЯЩИЙ отказ сборки наката на заданном адресе базы.
// Соединение не открывается: адрес без хоста отвергается до всякого ожидания.
func failureFromRunnerBuild(t *testing.T, dsn string) error {
	t.Helper()
	_, err := buildRunner(&rootOptions{dialect: defaultDialect, dsn: dsn}, fstest.MapFS{})
	if err == nil {
		t.Fatalf("сборка наката приняла адрес %q — производитель ошибки сломан", dsn)
	}
	return err
}

// TestExitCodeForNamesTheClassOfTheFailureAndNotTheEchoOfTheInput — несущая проба.
//
// Каждый вход назван ДВУМЯ величинами: класс, который обязан быть назван, и
// подстрока ЭХА ВВОДА, которую прежний читатель ловил в выводе. Там, где эхо
// присутствует, а предмет отказа к соединению не относится, классификация обязана
// назвать НАХОДКУ — иначе неверная посадка не краснеет ни разу.
func TestExitCodeForNamesTheClassOfTheFailureAndNotTheEchoOfTheInput(t *testing.T) {
	type outcomeCase struct {
		name string
		// err — ошибка настоящего пути продукта, а не сочинённая строка.
		err error
		// want — код выхода, которым накатчик обязан назвать класс.
		want int
		// echoOfInput — подстрока, которую прежний образец ловил в ЭХЕ ВВОДА.
		// Непустая означает: эхо тут ЕСТЬ, и вердикт обязан его игнорировать.
		echoOfInput string
	}

	cases := []outcomeCase{
		{
			// КЛАСС ЗАДАЧИ: эхо ввода совпадает, предмет отказа — посадка.
			name:        "неверная посадка: адрес без хоста, а в эхе ввода стоит sslmode",
			err:         failureFromRunnerBuild(t, "postgres://kaname:s3cr3t@:5432/kaname?sslmode=require"),
			want:        exitFinding,
			echoOfInput: "sslmode",
		},
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ: тот же предмет, эха нет. Исход обязан совпасть —
			// иначе класс отказа оказался бы функцией ввода, а не причины.
			name: "неверная посадка: тот же адрес без хоста, но и без sslmode",
			err:  failureFromRunnerBuild(t, "postgres://kaname:s3cr3t@:5432/kaname"),
			want: exitFinding,
		},
		{
			// База НЕДОСТИЖИМА: транспорт. Единственный класс, который ждать
			// осмысленно, — и единственный, дающий «условие не создано».
			name: "база недостижима: соединение не установилось за бюджет ожидания",
			err: failureFromReadinessBarrier(t, &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: errors.New("connect: connection refused"),
			}),
			want: exitUnmet,
		},
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ ПРЕДЫДУЩЕГО: тот же барьер, тот же путь, один
			// изменённый факт — сервер ОТВЕТИЛ и назвал негодный пароль. Ждать
			// тут нечего, это дефект настройки, и в эхе стоит слово `password`.
			name: "сервер ответил: пароль негоден — ждать нечего",
			err: failureFromReadinessBarrier(t, &pgconn.PgError{
				Code:    "28P01",
				Message: "password authentication failed for user \"kaname\"",
			}),
			want:        exitFinding,
			echoOfInput: "password",
		},
		{
			// Отказ, к базе не относящийся вовсе: назван неподдерживаемый диалект.
			name: "назван неподдерживаемый диалект — до базы дело не доходит",
			err: func() error {
				_, err := buildRunner(&rootOptions{dialect: "sqlite", dsn: "postgres://kaname@pg:5432/kaname"}, fstest.MapFS{})
				if err == nil {
					t.Fatal("сборка наката приняла неподдерживаемый диалект — производитель ошибки сломан")
				}
				return err
			}(),
			want: exitFinding,
		},
	}

	seen := map[int]int{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.echoOfInput != "" && !strings.Contains(c.err.Error(), c.echoOfInput) {
				t.Fatalf("эха ввода %q в сообщении нет — проба утверждала бы не тот класс, "+
					"который называет: %q", c.echoOfInput, c.err.Error())
			}
			if got := exitCodeFor(c.err); got != c.want {
				t.Fatalf("exitCodeFor() = %d, want %d; сообщение: %q", got, c.want, c.err.Error())
			}
		})
		seen[c.want]++
	}

	// ПЕРЕПИСЬ И ОТКАЗ НА ПУСТОМ ОБХОДЕ. Набор, потерявший один из двух классов,
	// зеленел бы на классификаторе-постоянной — то есть ровно на том дефекте,
	// который эти пробы заведены ловить.
	t.Logf("рассмотрено входов классификатора: %d (находок %d, несозданных условий %d)",
		len(cases), seen[exitFinding], seen[exitUnmet])
	if len(cases) == 0 {
		t.Fatal("ни одного входа не рассмотрено — доказательства нет, и это не зелёное")
	}
	if seen[exitFinding] == 0 || seen[exitUnmet] == 0 {
		t.Fatalf("набор не представляет оба класса (находок %d, несозданных условий %d) — "+
			"классификатор-постоянная прошёл бы такой набор", seen[exitFinding], seen[exitUnmet])
	}
}

// TestExitCodeForSuccessIsZero — положительный контроль: успех не классифицируется.
func TestExitCodeForSuccessIsZero(t *testing.T) {
	if got := exitCodeFor(nil); got != 0 {
		t.Fatalf("exitCodeFor(nil) = %d, want 0", got)
	}
}

// TestExitCodesOfTheTwoClassesDiffer — контроль ПОДСТАНОВКОЙ.
//
// Отношение «называет класс» выполнимо тождественно: приравняв константы, можно
// пройти каждую пробу выше, ничего не различая. Поэтому различие констант
// утверждается отдельно, и ни одна из них не равна нулю: нулём накатчик
// отвечает об УСПЕХЕ, и класс отказа, совпавший с ним, объявил бы накат
// выполненным.
func TestExitCodesOfTheTwoClassesDiffer(t *testing.T) {
	if exitFinding == exitUnmet {
		t.Fatalf("коды классов совпали (%d): различение объявлено и неисполнимо", exitFinding)
	}
	if exitFinding == 0 || exitUnmet == 0 {
		t.Fatalf("код отказа совпал с кодом успеха (находка %d, условие %d)", exitFinding, exitUnmet)
	}
}
