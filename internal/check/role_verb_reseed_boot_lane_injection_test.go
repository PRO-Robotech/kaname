// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_verb_reseed_boot_lane_injection_test.go — инъекция гейта IAM-RV-1-07
// (загрузочная половина) — В ОБЕ СТОРОНЫ.
//
// Порт с монорепо: доказательство инъекцией семейства
// `roleverbreseedbootlane` (координата монорепо не пишется целиком —
// путь доказательства читался бы как обещание в ЭТОМ дереве),
// снят вынесением службы — `kacho#2597`). Дословно: все шесть прогонов.
// Изменилось только: пакет (`repohygiene` → `check_test`).
//
// Признак воспроизводится над СИНТЕТИЧЕСКИМ композиционным корнем: правкой
// настоящего дерева инъекция не ставится — она рвала бы чужие прогоны в общей
// рабочей копии.
package check_test

import "testing"

func bootSrc(body string) string {
	return "package main\n\nfunc run() {\n\ttasks = append(tasks, func() error {\n" + body + "\n\t\treturn nil\n\t})\n}\n"
}

// TestIAMRV107_InjectionRedWhenTheReseedHasNoOwnCall — сегодняшнее состояние
// дерева, воспроизведённое синтетикой (проекция глаголов зовётся внутри
// собственного `if`, значит вызов ЕСТЬ — здесь проверяется противоположный
// случай, когда его нет вовсе).
func TestIAMRV107_InjectionRedWhenTheReseedHasNoOwnCall(t *testing.T) {
	t.Parallel()
	src := bootSrc(`		if oerr := seed.BackfillOwnerBindings(ctx, pool); oerr != nil {
			logger.Warn("p8 backfill: owner-binding data-backfill failed", slog.Any("err", oerr))
		}
		seed.LogSystemGrantCensus(ctx, pool, logger)`)
	rep, err := inspectBootRoleVerbReseed("zz_boot.go", src)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if rep.SeedCalls == 0 {
		t.Fatal("признак не видит вызовов пакета досева вовсе — перепись мертва, и «ноль " +
			"вызовов досева проекции» неотличимо от «файл не разобран»")
	}
	if len(rep.ReseedCalls) != 0 {
		t.Fatalf("признак нашёл досев проекции там, где его нет: %v — гейт не способен "+
			"покраснеть на сегодняшнем дереве", rep.ReseedCalls)
	}
}

// TestIAMRV107_InjectionRedOnASwallowedFailure — полоса есть, но отказ
// печатается `Warn` → находка, называющая уровень.
func TestIAMRV107_InjectionRedOnASwallowedFailure(t *testing.T) {
	t.Parallel()
	src := bootSrc(`		if rerr := seed.ReseedSystemRoleVerbs(ctx, kanameRepo, logger); rerr != nil {
			logger.Warn("пересчёт проекции ролей не удался", slog.Any("err", rerr))
		}`)
	rep, err := inspectBootRoleVerbReseed("zz_boot.go", src)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if len(rep.ReseedCalls) != 1 {
		t.Fatalf("признак не опознал вызов досева проекции: %v", rep.ReseedCalls)
	}
	swallowed := false
	for _, lvl := range rep.Levels {
		if swallowingLevels[lvl] {
			swallowed = true
		}
	}
	if !swallowed {
		t.Fatalf("признак МОЛЧИТ на проглоченном отказе (уровни %v) — ось «заменить Error "+
			"на Warn» осталась бы без держателя", rep.Levels)
	}
}

// TestIAMRV107_InjectionSilentOnTheLawfulForm — ЗАКОННЫЙ БЛИЗНЕЦ: собственная
// полоса, уровень `Error`. Гейт обязан молчать.
func TestIAMRV107_InjectionSilentOnTheLawfulForm(t *testing.T) {
	t.Parallel()
	src := bootSrc(`		if rerr := seed.ReseedSystemRoleVerbs(ctx, kanameRepo, logger); rerr != nil {
			logger.Error("пересчёт проекции ролей не удался", slog.Any("err", rerr))
		}`)
	rep, err := inspectBootRoleVerbReseed("zz_boot.go", src)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if len(rep.ReseedCalls) != 1 {
		t.Fatalf("признак не опознал законный вызов: %v", rep.ReseedCalls)
	}
	for _, lvl := range rep.Levels {
		if swallowingLevels[lvl] {
			t.Fatalf("гейт краснеет на ЗАКОННОЙ форме (уровень %s) — первый же ложный срабат "+
				"его отключит", lvl)
		}
	}
	if len(rep.Silent) != 0 {
		t.Fatalf("гейт считает немой ветку, которая печатает `Error`: %v", rep.Silent)
	}
}

// TestIAMRV107_InjectionSilentOnTheTwoStatementForm — ЗАКОННЫЙ БЛИЗНЕЦ второго
// рода: присваивание и отдельный `if`.
func TestIAMRV107_InjectionSilentOnTheTwoStatementForm(t *testing.T) {
	t.Parallel()
	src := bootSrc(`		census, rerr := seed.ReseedSystemRoleVerbs(ctx, kanameRepo)
		if rerr != nil {
			logger.Error("пересчёт проекции ролей не удался",
				slog.Any("err", rerr), slog.Int("examined", census.Examined))
		}`)
	rep, err := inspectBootRoleVerbReseed("zz_boot.go", src)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if len(rep.ReseedCalls) != 1 {
		t.Fatalf("признак не опознал двухстрочную форму: %v — она законна и обычна в этом корне",
			rep.ReseedCalls)
	}
	if len(rep.Levels) == 0 || len(rep.Silent) != 0 {
		t.Fatalf("признак считает двухстрочную форму немой (уровни %v, немых %v)",
			rep.Levels, rep.Silent)
	}
}

// TestIAMRV107_InjectionSilentOnANeighbouringLane — ЗАКОННЫЙ БЛИЗНЕЦ третьего
// рода: СОСЕДНЯЯ полоса старта, законно сообщающая свой отказ `Warn`.
func TestIAMRV107_InjectionSilentOnANeighbouringLane(t *testing.T) {
	t.Parallel()
	src := bootSrc(`		if oerr := seed.BackfillOwnerBindings(ctx, pool); oerr != nil {
			logger.Warn("p8 backfill: owner-binding data-backfill failed", slog.Any("err", oerr))
		}
		if rerr := seed.ReseedSystemRoleVerbs(ctx, kanameRepo, logger); rerr != nil {
			logger.Error("пересчёт проекции ролей не удался", slog.Any("err", rerr))
		}`)
	rep, err := inspectBootRoleVerbReseed("zz_boot.go", src)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	for _, lvl := range rep.Levels {
		if swallowingLevels[lvl] {
			t.Fatalf("гейт приписал досеву проекции `%s` СОСЕДНЕЙ полосы — он ловит форму, "+
				"а не предмет", lvl)
		}
	}
}

// TestIAMRV107_InjectionRedOnASilentFailureBranch — ветка отказа пуста.
func TestIAMRV107_InjectionRedOnASilentFailureBranch(t *testing.T) {
	t.Parallel()
	src := bootSrc(`		if rerr := seed.ReseedSystemRoleVerbs(ctx, kanameRepo, logger); rerr != nil {
			_ = rerr
		}`)
	rep, err := inspectBootRoleVerbReseed("zz_boot.go", src)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if len(rep.Silent) != 1 {
		t.Fatalf("признак не считает немой пустую ветку отказа: немых %v, уровней %v",
			rep.Silent, rep.Levels)
	}
}
