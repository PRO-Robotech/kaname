// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// module_catalog_verb_wiring_injection_test.go — доказательство, что гейт
// провязки ВТОРОГО вызывающего (`module_catalog_verb_wiring_test.go`) СПОСОБЕН
// упасть и СПОСОБЕН смолчать (задача #1034, О10).
//
// # Инъекция роняет ТОЛЬКО проверяемое
//
// Каждый случай отличается от своего законного близнеца РОВНО одним: снята
// передача · подменён пакет-получатель · выпотрошен потребитель · подменён тип
// поля, на котором зовётся применение. Ни один случай не заводит «ещё один
// элемент» — предмет гейта не перечень, а поток одного значения к тому, кто его
// применяет.
//
// # Обе половины проверяются ПОРОЗНЬ
//
// Половина A (корень передал) и половина B (потребитель применяет) обязаны
// краснеть каждая своим входом: гейт, у которого работает одна, зелен на
// дефекте другой и об этом молчит.

import (
	"strings"
	"testing"
)

// ── Половина A: корень строит глагольный применитель и передаёт потребителю ──

// verbApplierHandedToTheConsumer — ЖИВАЯ раскладка.
const verbApplierHandedToTheConsumer = `package main

import (
	moduleapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/module"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
)

func buildServices() *services {
	moduleApplier := modulecatalog.NewVerbApplier(writeRepo)
	return &services{moduleHandler: moduleapp.NewHandler(
		moduleapp.NewPlanUseCase(delivery, rows, nil),
		moduleapp.NewApplyUseCase(delivery, moduleApplier, opsRepo, logger),
		moduleapp.NewGetUseCase(rows),
		moduleapp.NewListUseCase(rows),
	)}
}
`

// verbApplierBuiltNeverHandedOff — ДЕФЕКТ: применитель есть, потребителю не
// передан. Служба смонтирована, применять ей нечем.
const verbApplierBuiltNeverHandedOff = `package main

import (
	moduleapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/module"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
)

func buildServices() *services {
	moduleApplier := modulecatalog.NewVerbApplier(writeRepo)
	logger.Info("применитель собран", slog.Any("applier", moduleApplier))
	return &services{moduleHandler: moduleapp.NewHandler(nil, nil, nil, nil)}
}
`

// verbApplierHandedToAnotherPackage — ДЕФЕКТ ТОНЬШЕ: применитель передан, но
// ЧУЖОМУ пакету. Гейт, довольствующийся «кому-то передан», молчал бы здесь.
const verbApplierHandedToAnotherPackage = `package main

import (
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
	otherapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/cluster"
)

func buildServices() *services {
	moduleApplier := modulecatalog.NewVerbApplier(writeRepo)
	return &services{clusterHandler: otherapp.NewHandler(moduleApplier)}
}
`

// verbApplierUnderAnAlias — тот же дефект под ПСЕВДОНИМОМ обоих импортов: гейт,
// знающий одно написание, молчал бы на форме столь же законной.
const verbApplierUnderAnAlias = `package main

import (
	ma "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/module"
	mc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
)

func buildServices() *services {
	moduleApplier := mc.NewVerbApplier(writeRepo)
	_ = ma.NewHandler(nil, nil, nil, nil)
	logger.Info("собран", slog.Any("applier", moduleApplier))
	return nil
}
`

// verbApplierUnderAnAliasHandedOff — тот же псевдоним, но ЗАКОННАЯ раскладка:
// без этого близнеца находка выше зеленела бы на реализации, краснеющей на
// всяком псевдониме.
const verbApplierUnderAnAliasHandedOff = `package main

import (
	ma "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/module"
	mc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
)

func buildServices() *services {
	moduleApplier := mc.NewVerbApplier(writeRepo)
	return &services{moduleHandler: ma.NewApplyUseCase(delivery, moduleApplier, opsRepo, logger)}
}
`

// verbApplierDiscarded — не связан вовсе: предмета нет, находки быть не должно.
const verbApplierDiscarded = `package main

import "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"

func probe() { _ = modulecatalog.NewVerbApplier(writeRepo) }
`

func TestIAM1034_VerbInjectionRedsTheUnhandedApplierAndKeepsQuietOnTheHandedOne(t *testing.T) {
	cases := []struct {
		name  string
		files []wiringFile
		finds bool
	}{
		{
			name:  "передан потребителю — молчание (живая раскладка)",
			files: []wiringFile{{"cmd/kacho-iam/wiring.go", verbApplierHandedToTheConsumer}},
		},
		{
			name:  "построен и НЕ передан — находка",
			files: []wiringFile{{"cmd/kacho-iam/wiring.go", verbApplierBuiltNeverHandedOff}},
			finds: true,
		},
		{
			name:  "передан ЧУЖОМУ пакету — находка",
			files: []wiringFile{{"cmd/kacho-iam/wiring.go", verbApplierHandedToAnotherPackage}},
			finds: true,
		},
		{
			name:  "под псевдонимом и НЕ передан — находка",
			files: []wiringFile{{"cmd/kacho-iam/wiring.go", verbApplierUnderAnAlias}},
			finds: true,
		},
		{
			name:  "под псевдонимом и передан — молчание",
			files: []wiringFile{{"cmd/kacho-iam/wiring.go", verbApplierUnderAnAliasHandedOff}},
		},
		{
			name:  "отброшен связыванием — молчание",
			files: []wiringFile{{"cmd/kacho-iam/probe.go", verbApplierDiscarded}},
		},
		{
			name:  "проба, строящая применитель, предметом не является — молчание",
			files: []wiringFile{{"cmd/kacho-iam/wiring_test.go", verbApplierBuiltNeverHandedOff}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, paths := writeSyntheticRoot(t, tc.files)
			built, handed, files, parsedN, handedN, err := verbApplierWiring(root, paths)
			if err != nil {
				t.Fatalf("%v", err)
			}
			t.Logf("файлов %d · разобрано %d · построено %d · передач %d",
				files, parsedN, len(built), handedN)

			var unhanded []applierBinding
			for _, b := range built {
				if !handed[b.Name] {
					unhanded = append(unhanded, b)
				}
			}
			switch {
			case tc.finds && len(unhanded) == 0:
				t.Fatalf("гейт СМОЛЧАЛ на внесённом дефекте — он не способен упасть "+
					"(построено %d, передач %d)", len(built), handedN)
			case !tc.finds && len(unhanded) > 0:
				t.Fatalf("гейт покраснел на ЗАКОННОЙ раскладке: %s:%d `%s` — ложная "+
					"находка отключает гейт первой",
					unhanded[0].File, unhanded[0].Line, unhanded[0].Name)
			}
			if !tc.finds {
				return
			}
			u := unhanded[0]
			if u.Name != "moduleApplier" || u.Line == 0 ||
				!strings.HasSuffix(u.File, "wiring.go") {
				t.Fatalf("находка не назвала ни переменную, ни координату: %+v", u)
			}
		})
	}
}

// ── Половина B: потребитель ПРИМЕНЯЕТ на значении порта ─────────────────────

// consumerAppliesOnThePort — ЖИВАЯ раскладка: применение зовётся на поле,
// объявленном портом применителя.
const consumerAppliesOnThePort = `package module

type ApplyUseCase struct {
	applier CatalogApplier
}

func (uc *ApplyUseCase) Execute(ctx context.Context) error {
	_, err := uc.applier.Apply(ctx, req)
	return err
}
`

// consumerHoldsThePortAndNeverApplies — ПОСРЕДНИК-ПУСТЫШКА: порт объявлен,
// применения нет. Гейт, довольствующийся передачей, молчал бы здесь — то есть
// на глаголе, который по-прежнему не позван.
const consumerHoldsThePortAndNeverApplies = `package module

type ApplyUseCase struct {
	applier CatalogApplier
}

func (uc *ApplyUseCase) Execute(ctx context.Context) error {
	logger.Info("применитель на месте", slog.Any("applier", uc.applier))
	return nil
}
`

// consumerAppliesOnAnotherType — применение зовётся на поле ЧУЖОГО типа. Гейт,
// судящий по имени метода, счёл бы потребителя применяющим.
const consumerAppliesOnAnotherType = `package module

type ApplyUseCase struct {
	applier CatalogApplier
	patcher LabelPatcher
}

func (uc *ApplyUseCase) Execute(ctx context.Context) error {
	_, err := uc.patcher.Apply(ctx, req)
	return err
}
`

// consumerAppliesOnAPortParameter — законная вторая форма: порт приезжает
// ПАРАМЕТРОМ, а не полем.
const consumerAppliesOnAPortParameter = `package module

func applyOnce(ctx context.Context, applier CatalogApplier) error {
	_, err := applier.Apply(ctx, req)
	return err
}
`

func TestIAM1034_VerbInjectionRedsTheHollowConsumerAndKeepsQuietOnTheApplyingOne(t *testing.T) {
	cases := []struct {
		name    string
		files   []wiringFile
		applies bool
	}{
		{
			name:    "применение на поле порта — молчание (живая раскладка)",
			files:   []wiringFile{{"api/module/apply.go", consumerAppliesOnThePort}},
			applies: true,
		},
		{
			name:    "применение на параметре порта — молчание",
			files:   []wiringFile{{"api/module/apply.go", consumerAppliesOnAPortParameter}},
			applies: true,
		},
		{
			name:  "порт есть, применения нет — находка",
			files: []wiringFile{{"api/module/apply.go", consumerHoldsThePortAndNeverApplies}},
		},
		{
			name:  "применение на ЧУЖОМ типе — находка",
			files: []wiringFile{{"api/module/apply.go", consumerAppliesOnAnotherType}},
		},
		{
			name:    "проба потребителя предметом не является — находка",
			files:   []wiringFile{{"api/module/apply_test.go", consumerAppliesOnThePort}},
			applies: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, paths := writeSyntheticRoot(t, tc.files)
			portNames, applyCalls, parsedN, err := consumerApplies(paths)
			if err != nil {
				t.Fatalf("%v", err)
			}
			t.Logf("разобрано %d · имён порта %d · вызовов применения %d",
				parsedN, len(portNames), applyCalls)
			switch {
			case tc.applies && applyCalls == 0:
				t.Fatalf("гейт не увидел применения на ЗАКОННОЙ раскладке — "+
					"ложная находка отключает его первой (имён порта %d)", len(portNames))
			case !tc.applies && applyCalls > 0:
				t.Fatalf("гейт счёл применяющим потребителя, который не применяет: "+
					"вызовов %d — половина B вакуумна", applyCalls)
			}
		})
	}
}

// TestIAM1034_VerbInjectionProvesTheEmptyWalkIsRefused — премиса обеих половин:
// обход, не прочитавший ничего, обязан быть отказом, а не молчаливым успехом.
// Живой гейт превращает нулевые величины переписи в отказ; здесь доказано, что
// на пустом составе они действительно нулевые.
func TestIAM1034_VerbInjectionProvesTheEmptyWalkIsRefused(t *testing.T) {
	root := t.TempDir()
	built, handed, files, parsedN, handedN, err := verbApplierWiring(root, nil)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if files != 0 || parsedN != 0 || len(built) != 0 || len(handed) != 0 || handedN != 0 {
		t.Fatalf("пустой состав дал непустую перепись: файлов %d, разобрано %d, "+
			"построено %d, передач %d", files, parsedN, len(built), handedN)
	}
	portNames, applyCalls, consumerParsed, err := consumerApplies(nil)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if consumerParsed != 0 || len(portNames) != 0 || applyCalls != 0 {
		t.Fatalf("пустой состав потребителя дал непустую перепись: разобрано %d, "+
			"имён порта %d, применений %d", consumerParsed, len(portNames), applyCalls)
	}
}
