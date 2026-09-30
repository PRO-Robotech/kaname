// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// laneposture.go — половина ПОЛНОТЫ ПРОВЯЗКИ у полосности посадки личности
// (задача #1125, подфаза Ф4д эпика #896).
//
// Требования полосы делятся на две половины, и они не взаимозаменяемы:
//
//   - ПОСАДОЧНАЯ читает значения настройки и живёт в config.Validate();
//   - ПОЛНОТА ПРОВЯЗКИ читает СОБРАННЫЕ ОБЪЕКТЫ. Настройка их не видит и
//     выразить их отсутствие не может, поэтому эта половина живёт здесь.
//
// Отказ здесь — ОТДЕЛЬНЫЙ текст, и он не заменяется посадочной проверкой:
// проба, доказавшая одну точку, о второй не утверждает ничего.
//
// ВЕЛИЧИНА ПОДАЁТСЯ ПАРАМЕТРОМ. Требование «посадка умеет предъявить каждый
// уровень доверия, которого требует каталог прав» берёт число ИЗ КАТАЛОГА.
// Каталог читается здесь и подаётся в стража значением — ровно так, как его
// подаёт композиционный корень края. Читай его страж сам из встроенного файла,
// сценарий «подмена каталога на набор без поднятых полов» стал бы описываемым,
// но не вызываемым.

import (
	"context"
	"log/slog"

	"github.com/PRO-Robotech/corelib/acrlevel"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// observeLaneWiring снимает факты о ПРОВЯЗКЕ, которых настройка не видит.
//
// Каждое поле обязано отражать собранную проводку, а не намерение профиля:
// иначе страж отчитывался бы о намерении вместо исхода — тот самый класс, ради
// которого заведён самоотчёт о посадке.
//
// signIn — способы входа человека, чьи проверяющие собраны ЭТИМ корнем
// (wiredSignInMethods). Подаются параметром по той же причине, что и каталог:
// перечень предъявимых уровней ВЫВОДИТСЯ из них правилом (приёмка Ф11, Р9), и
// сценарий «провязан только пароль» обязан быть вызываемым, а не описываемым.
func observeLaneWiring(ctx context.Context, signer *tokensigner.Signer,
	signIn []assurance.Method, lane *loginLane, logger *slog.Logger,
) config.LaneWiring {
	human := laneWiringOf(lane)
	return config.LaneWiring{
		OwnMintSignerWired: signer != nil,

		// СВОИ способы входа человека и СВОЯ сессия — НАБЛЮДЕНИЕ за полосой
		// входа паролем (Ф3, kacho#1269; хранилище способов входа — Ф2,
		// kacho#1268). Оба поля читают провязку полосы (`buildLoginLane`):
		// хранилище сессии и хранилище способов входа собраны — `true`; полосы
		// нет — `false`. Литерала здесь нет ни в одну сторону: полоса, которую
		// корень не собрал, доложена несобранной, и страж сборки откажет.
		HumanCredentialsWired: human.HumanCredentialsWired,
		HumanSessionsWired:    human.HumanSessionsWired,

		// ДОРОГИ К ВНЕШНЕМУ ПОСТАВЩИКУ здесь больше нет — ни в наблюдении, ни в
		// самоотчёте: корень её не строит ни на каком старте, и клиента, которым
		// её строили, в дереве нет (kaname#363). Докладывать о ней нечего.

		// Уровни, которые полоса своего входа умеет предъявить ЧЕЛОВЕКУ, — ВЫВЕДЕНЫ
		// ПРАВИЛОМ из провязанных способов, взятых в лучшем исходе их флагов
		// (приёмка Ф11, Р9). Здесь стоял литерал «ни одного»; литерал не мог
		// покраснеть ни при какой провязке — наблюдатель отчитывался о
		// намерении вместо исхода. Пока корень не провязал ни одного способа,
		// перечень пуст — и это наблюдение того же рода, что два поля выше.
		PresentableACRs: assurance.PresentableLevels(signIn).Strings(),

		CatalogFloors: readCatalogFloors(ctx, logger),
	}
}

// readCatalogFloors — сколько записей каталога прав требуют каждого уровня
// доверия.
//
// Readable отделяет «каталог не прочитан» от «каталог не требует ничего»:
// нечитанный и пустой дают ОДНО И ТО ЖЕ число записей, и различает их только
// это поле. Уровни, которых платформа не знает, сюда попадают как есть — решает
// ли это требование, судит единственная функция ранжирования, и судит она в
// страже, а не здесь.
func readCatalogFloors(ctx context.Context, logger *slog.Logger) config.CatalogFloors {
	reg, err := seed.LoadPermissionRegistry(ctx, logger)
	if err != nil || reg == nil {
		return config.CatalogFloors{Readable: false}
	}
	byLevel := map[string]int{}
	for _, e := range reg.All() {
		if e.RequiredACRMin == "" {
			continue
		}
		byLevel[e.RequiredACRMin]++
	}
	return config.CatalogFloors{Readable: true, ByLevel: byLevel}
}

// laneWiringCensus — что процесс увидел о полосе, одной строкой для оператора.
//
// Печатается ВСЕГДА, включая успешный старт: «ноль недостижимых записей»
// обязано быть отличимо от «каталог не читали». Строка не заменяет самоотчёта о
// посадке — она объясняет, из чего он получился.
func laneWiringCensus(w config.LaneWiring) []any {
	demanded := 0
	for level, n := range w.CatalogFloors.ByLevel {
		if acrlevel.Rank(level) > 0 {
			demanded += n
		}
	}
	return []any{
		"catalog_readable", w.CatalogFloors.Readable,
		"catalog_entries_demanding_a_raised_floor", demanded,
		"lane_presentable_acrs", len(w.PresentableACRs),
		"own_mint_signer_wired", w.OwnMintSignerWired,
		"human_credentials_wired", w.HumanCredentialsWired,
		"human_sessions_wired", w.HumanSessionsWired,
	}
}
