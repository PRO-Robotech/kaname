// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// failure_reset_sole_writer_test.go — ГЕЙТ КЛАССА: всякая полоса, ЗАВЕРШАЮЩАЯ
// ВХОД, решает судьбу счёта по адресу одним местом (приёмка Ф12 Р7 редакция 11,
// сценарий Ф12-46; Ф3 Р10 редакция 11; задача PRO-Robotech/kaname#287).
//
// # Популяция ВЫВОДИТСЯ, а не выписывается
//
// Полосой, завершающей вход, считается та, что ПИШЕТ уровень сессии: выдаёт
// сессию либо предъявляет внутрь живой. Перечень таких полос выводится обходом
// дерева, а не памятью автора, и каждая обязана решить счёт — через дом либо
// записью ведомости.
//
// Граница названа прямо: гейт, судящий только ПОРТ обнуления, не видит полосу,
// которая счёт не решает ВОВСЕ, — она порт не зовёт. Поэтому переписей две:
// «полос, пишущих уровень, N» и «из них зовут дом M · в ведомости K».
//
// # Ведомость ключуется файлом И ЧИСЛОМ
//
// Запись прощает названное число прямых обращений, а не файл целиком: второй
// прямой вызов в том же файле — находка. Самоистечение работает в обе стороны —
// и на нуле, и на расхождении числа.
//
// # Премисы названы отдельно
//
// Ноль прочитанных файлов · отсутствие объявления порта · отсутствие реализации
// · дом, переставший звать порт · пустая популяция — каждое роняет прогон своей
// ошибкой, а не объявляется «находок ноль».
//
// Способность упасть и смолчать доказана инъекцией —
// failure_reset_sole_writer_injection_test.go: она подаёт СИНТЕТИЧЕСКИЙ корпус
// в тот же вердикт, что судит дерево.
package check_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// failureResetLedger — полосы, завершающие вход, которые счёт решают НЕ через
// дом. Ключ — путь от корня модуля; `Resets` — сколько прямых обращений к порту
// в файле законно; `Subject` — почему; `Refs` — предмет трекера (обязателен у
// записи, прощающей прямое обращение); `Removal` — предикат снятия командой.
//
// Перечень закрыт и самоистекает: на нуле, на расхождении числа и на полосе,
// перешедшей на дом.
var failureResetLedger = map[string]check.FailureResetLedgerEntry{
	// Две одобренные приёмки говорят о восстановлении РАЗНОЕ, и разрешает
	// расхождение приёмка, а не реализация; предмет — PRO-Robotech/kaname#305:
	//
	//	`recovery-of-access.md` Р5 (ред. 3) перечисляет «сброс счёта по адресу»
	//	   шагом одной транзакции завершения, без условия об уровне;
	//	`login-lane-…md` Р10 (ред. 11) — дом счёта — говорит, что обнуляет его
	//	   вход, завершённый до уровня ВСЕХ заведённых факторов, а код
	//	   восстановления даёт «1» и ко «2» не прибавляет (`internal/assurance`).
	//
	// Снятие — по внешнему факту: предмет закрыт. Полоса, перешедшая на дом,
	// роняет запись сама: прямых обращений у неё не остаётся, и запись
	// истекает правилом «полоса решает счёт через дом».
	"internal/apps/kaname/api/humansession/recovery_complete.go": {
		Resets: 1,
		Subject: "восстановление доступа: `recovery-of-access.md` Р5 и `login-lane-…md` Р10 ред. 11 расходятся " +
			"об уровне восстановившего",
		Refs: "PRO-Robotech/kaname#305",
		Removal: "`gh issue view 305 -R PRO-Robotech/kaname --json state -q .state` печатает CLOSED; " +
			"полоса на доме — `git grep -c ResetFailures -- internal/apps/kaname/api/humansession/recovery_complete.go` " +
			"пуст (код выхода 1), и гейт на этом краснеет сам",
	},
	// Регистрация выдаёт сессию и счёта не трогает ВООБЩЕ — ни через дом, ни
	// напрямую. Это законно и безопасно: у только что заведённого адреса счёта
	// нет, а «не обнулять» — безопасная сторона; послаблением обнуления запись
	// не является, поэтому предмета трекера не несёт. Стоит здесь потому, что
	// полоса ПИШЕТ уровень сессии и обязана быть видимой: без неё гейт по порту
	// не заметил бы её никогда.
	"internal/apps/kaname/api/registration/register.go": {
		Resets:  0,
		Subject: "регистрация: сессия выдаётся впервые заведённому адресу, счёта по нему нет",
		Removal: "полоса начала решать счёт — `git grep -nE 'resetFailuresOnCompletedLogin|ResetFailures' -- " +
			"internal/apps/kaname/api/registration/register.go` непуст; гейт краснеет на этом сам",
	},
}

func TestFailureResetGoesThroughTheCompletedLoginGuard(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	tree, err := treecorpus.NewTree(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева: %v", err)
	}
	corpus, err := check.CorpusFrom(tree, check.ProductionGoFile)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}

	findings, census, err := check.JudgeFailureReset(corpus, check.FailureResetHomeRel, failureResetLedger)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}

	switch {
	case census.Declarations == 0:
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: объявления порта %s в прод-коде нет — стеречь нечего "+
			"(прочитано файлов %d)", check.FailureResetPort, census.Files)
	case census.Implementations == 0:
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: реализации порта %s в прод-коде нет — порт мёртв "+
			"(прочитано файлов %d)", check.FailureResetPort, census.Files)
	case census.HomeCalls == 0:
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: дом %s не зовёт порт %s — либо дома нет, либо он перестал "+
			"обнулять счёт; тогда молчание гейта сказано ни о чём", check.FailureResetHomeRel, check.FailureResetPort)
	case census.LevelWritingFiles == 0:
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: полос, пишущих уровень сессии, прочитано 0 — популяция пуста, "+
			"судить некого (прочитано файлов %d)", census.Files)
	}

	t.Logf("перепись: файлов прод-кода прочитано %d, называющих порт %d; вызовов порта %d, значений-методов %d, "+
		"объявлений %d, реализаций %d, обращений в доме %d",
		census.Files, census.FilesNamingPort, census.Calls, census.MethodValues,
		census.Declarations, census.Implementations, census.HomeCalls)
	t.Logf("перепись популяции: полос, ПИШУЩИХ уровень сессии, %d (записей уровня %d) — зовут дом %d · "+
		"в ведомости %d (записей ведомости %d)",
		census.LevelWritingFiles, census.LevelWritingCalls, census.ThroughHome, census.InLedger, len(failureResetLedger))

	if len(findings) != 0 {
		t.Fatalf("полоса, завершающая вход, решает счёт по адресу мимо единственного писателя — %d находок:\n  %s\n\n"+
			"Счёт обнуляет вход, завершённый до уровня всех заведённых способов входа (Ф12 Р7 ред. 11, "+
			"Ф3 Р10 ред. 11). Условие решает %s; полоса зовёт его, а не порт напрямую.",
			len(findings), strings.Join(findings, "\n  "), check.FailureResetHomeRel)
	}
}

// TestFailureResetPremise_RowsLeaveOnlyThroughThePortAndTheSweep — ПОСЫЛКА
// гейта выше, судимая по дереву: текст оператора, называющий таблицу счёта и
// несущий изменяющее слово, законен только удалением по ключу в реализации
// порта `ResetFailures` и по возрасту в уборщике `SweepAgedFailures`; текст с
// таблицей, который разбор не классифицирует, — находка. Гейт выше судит ИМЯ
// порта, и его молчание значит «счёт не обнуляется мимо дома» ровно до тех
// пор, пока эта посылка верна; без пробы она была бы утверждением, а не
// фактом. Граница посылки названа в шапке `failure_reset_sole_writer.go`.
func TestFailureResetPremise_RowsLeaveOnlyThroughThePortAndTheSweep(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	tree, err := treecorpus.NewTree(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева: %v", err)
	}
	corpus, err := check.CorpusFrom(tree, check.ProductionGoFile)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}

	findings, census, err := check.JudgeFailureRowRemovals(corpus)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	switch {
	case census.ByKeyInPort == 0:
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: реализация %s не удаляет строк %s по ключу — распознаватель слеп "+
			"либо таблица переименована; молчание о прочих удалениях сказано ни о чём (прочитано файлов %d, строковых значений %d)",
			check.FailureResetPort, check.FailureRowsTable, census.Files, census.StringValues)
	case census.ByAgeInSweep == 0:
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: уборщик %s не удаляет строк %s по возрасту — распознаватель слеп "+
			"либо уборщик переименован (прочитано файлов %d, строковых значений %d)",
			check.FailureRowsSweep, check.FailureRowsTable, census.Files, census.StringValues)
	}
	t.Logf("перепись посылки: файлов прод-кода прочитано %d, строковых значений %d, из них называют %s %d; "+
		"с изменяющим словом %d — по ключу в реализации порта %d · по возрасту в уборщике %d",
		census.Files, census.StringValues, check.FailureRowsTable, census.NamingTable, census.Removals,
		census.ByKeyInPort, census.ByAgeInSweep)

	if len(findings) != 0 {
		t.Fatalf("строки счёта снимаются мимо реализации порта и уборщика — %d находок:\n  %s\n\n"+
			"Гейт единственного писателя судит имя порта %s; такое снятие он не увидит, и его молчание "+
			"перестаёт значить «счёт не обнуляется мимо дома».",
			len(findings), strings.Join(findings, "\n  "), check.FailureResetPort)
	}
}
