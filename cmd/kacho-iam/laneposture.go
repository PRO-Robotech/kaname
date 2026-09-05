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

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/tokensigner"
	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

// observeLaneWiring снимает факты о ПРОВЯЗКЕ, которых настройка не видит.
//
// Каждое поле обязано отражать собранную проводку, а не намерение профиля:
// иначе страж отчитывался бы о намерении вместо исхода — тот самый класс, ради
// которого заведён самоотчёт о посадке.
func observeLaneWiring(ctx context.Context, signer *tokensigner.Signer, logger *slog.Logger) config.LaneWiring {
	return config.LaneWiring{
		OwnMintSignerWired: signer != nil,

		// СВОИХ способов входа человека и СВОЕЙ сессии в этом дереве ещё нет:
		// проверку пароля, второй фактор и сессию браузера сегодня исполняет
		// внешний поставщик, в своей базе. Значения здесь — НАБЛЮДЕНИЕ, а не
		// заглушка: полоса `own` действительно не может впустить человека, и
		// стенд, объявивший её, обязан об этом узнать при старте, а не после
		// того, как первый человек не смог войти.
		//
		// ПРЕДИКАТ СМЕНЫ: как только в композиционном корне появятся хранилище
		// способов входа и хранилище сессии человека, эти поля читают их
		// провязку (`store != nil`) — и обе строки таблицы требований начинают
		// проходить. Строки таблицы при этом не меняются: их предмет — провязка,
		// а не то, чем она сегодня оказалась.
		HumanCredentialsWired: false,
		HumanSessionsWired:    false,

		// Уровни, которые полоса `own` умеет предъявить ЧЕЛОВЕКУ. Пока своих
		// способов входа нет — ни одного; «ни одного» отличимо от «не
		// заполнено» тем, что перечень пуст осознанно (см. выше).
		PresentableACRs: nil,

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
		if grpcsrv.ACRRank(level) > 0 {
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
