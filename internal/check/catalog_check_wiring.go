// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_check_wiring.go — сверка каталога прав с копией края обязана быть
// ЗВАНОЙ конвейером, а не просто существующей целью Makefile.
//
// # ПРЕДМЕТ У ГЕЙТА ФОРМА-ПРОВЕРКА, А НЕ ФОРМА-СИНХРОНИЗАЦИЯ (kaname#15)
//
// Портированная редакция требовала вызова `sync-permission-catalog` — и была
// НЕИСПОЛНИМА by construction: эта цель ПИШЕТ файл. Задание, правящее дерево,
// вердикта о дереве не даёт: «копии совпали» после собственного `cp` истинно
// всегда, а рабочая копия ранера уезжает от коммита. Поэтому решение записано в
// самом рецепте, а гейт судит его: конвейер зовёт `check-permission-catalog`
// (ничего не пишет, годна обеим посадкам) и НЕ зовёт пишущую форму, которая
// объявлена ручной операцией выпуска.
//
// Отсюда и переименование пробы: портированное имя было
// `TestCatalogSyncTargetIsCalledByThePipeline`, и после смены предмета оно
// утверждало бы неверное — цель синхронизации конвейером не звана НАМЕРЕННО.
//
// Вторая половина того же решения — ОТКУДА БЕРЁТСЯ КОПИЯ КРАЯ. Замер, которого у
// портированной редакции не было: копия края приезжает в самостоятельный клон
// МОДУЛЕМ-ПИНОМ платформы (`go.mod`), поэтому сверка исполнима и здесь, а не
// только в полном чекауте монорепо. Предикат и его граница — в рецепте, у самой
// цели.
//
// Порт с монорепо (`internal/repohygiene/catalogcheckwiring_test.go`, снят
// вынесением службы — `kacho#2597` с заявлением «предмет уехал вместе со
// службой»). Заявление НЕВЕРНО для kaname: своя половина цепочки уехала СЮДА
// — цель `sync-permission-catalog` объявлена в корневом Makefile службы
// (`GATEWAY_CATALOG`/`IAM_CATALOG_EMBED`), и её собственный комментарий
// говорит: «Копия каталога у iam ОБЯЗАНА побайтово совпадать с копией шлюза».
// Предмет, которым монорепошный гейт стерёг
// ПРОВЯЗКУ, здесь тот же самый, только половина цепочки живёт по обе стороны
// границы репозитория.
//
// Здесь СУЖЕННАЯ форма монорепошного гейта: он спрашивал достижимость через
// ОБЩИЙ анализатор рецептов Makefile (`gatetargetwiring.go`, там же судят
// гейты `services/*`), которого в этом репозитории нет и заводить его ради
// двух целей с нулём зависимых — избыточно (ни у `check-permission-catalog`, ни
// у `sync-permission-catalog` сегодня НЕТ ни одной цели-потребителя внутри
// Makefile: обе стоят сами по себе, реаситься до них нечему). Поэтому
// проверяется прямая достижимость: зовёт ли ХОТЬ ОДИН шаг конвейера имя цели
// напрямую (`make check-permission-catalog` либо `make -C … <цель>`).
// Появится цель-потребитель — предикат обязан расшириться до реситься-графа,
// как в монорепо; это отдельное изменение, а не молчаливое сужение.
//
// # Чем этот гейт НЕ является
//
// Он не сверяет копии побайтово — это отдельный предмет, и живёт он внутри
// рецепта `check-permission-catalog`. Предмет ЭТОГО гейта — ПРОВЯЗКА:
// существует ли у сверки вызывающий среди того, что исполняется САМО, и не
// зовёт ли конвейер пишущую форму вместо неё.
package check

import (
	"regexp"
	"strings"
)

// CatalogSyncTarget — имя цели Makefile, ПЕРЕПИСЫВАЮЩЕЙ каталог прав из копии
// края. Ручная операция выпуска: конвейер её звать не вправе.
const CatalogSyncTarget = "sync-permission-catalog"

// CatalogCheckTarget — имя цели Makefile, СВЕРЯЮЩЕЙ копии и ничего не пишущей.
// Ровно её обязан звать конвейер.
const CatalogCheckTarget = "check-permission-catalog"

// makefileTargetDeclRe — объявление цели `<имя>:` в начале строки (не внутри
// рецепта — там строка начинается с табуляции).
var makefileTargetDeclRe = regexp.MustCompile(`(?m)^([A-Za-z0-9_.-]+)\s*:`)

// MakefileDeclaresTarget — объявлена ли цель в тексте Makefile.
func MakefileDeclaresTarget(makefile, target string) bool {
	for _, m := range makefileTargetDeclRe.FindAllStringSubmatch(makefile, -1) {
		if m[1] == target {
			return true
		}
	}
	return false
}

// CallsMakeTarget — исполняемое тело шага (`run:` без строк оболочечных
// комментариев) зовёт названную цель формой `make <цель>` либо
// `make -C <каталог> <цель>` (в этом репозитории цель лежит в корневом
// Makefile, поэтому `-C` без аргумента либо `-C .` — тоже законная форма).
func CallsMakeTarget(body, target string) bool {
	for _, ln := range strings.Split(body, "\n") {
		t := strings.TrimSpace(ln)
		if !strings.HasPrefix(t, "make") {
			// Строка внутри тела `run:`, не начинающаяся с `make`, всё же может
			// звать его после `&&`/`;` — берём КАЖДОЕ слово-токен построчно,
			// разбирая по этим разделителям.
			for _, seg := range splitShellSegments(t) {
				if callsMakeTargetSegment(seg, target) {
					return true
				}
			}
			continue
		}
		if callsMakeTargetSegment(t, target) {
			return true
		}
	}
	return false
}

func splitShellSegments(line string) []string {
	line = strings.ReplaceAll(line, "&&", "\n")
	line = strings.ReplaceAll(line, ";", "\n")
	line = strings.ReplaceAll(line, "|", "\n")
	return strings.Split(line, "\n")
}

func callsMakeTargetSegment(seg, target string) bool {
	seg = strings.TrimSpace(seg)
	fields := strings.Fields(seg)
	if len(fields) == 0 || fields[0] != "make" {
		return false
	}
	for i := 1; i < len(fields); i++ {
		f := fields[i]
		if f == "-C" {
			i++ // пропускаем аргумент каталога
			continue
		}
		if strings.HasPrefix(f, "-") {
			continue
		}
		if f == target {
			return true
		}
	}
	return false
}
