// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// module_catalog_apply_wiring_injection_test.go — доказательство, что гейт
// провязки применителя (`module_catalog_apply_wiring_test.go`) СПОСОБЕН упасть и
// СПОСОБЕН смолчать (задача #1034).
//
// Пара «красное до · зелёное после» снята и на ЖИВОМ дереве: до провязки часть A
// напечатала «применителей построено 0», часть B — «применение \"\"»; после
// провязки обе молчат. Здесь то же свойство закреплено воспроизводимо, на
// синтетике: доказательство, требующее вынуть провязку из рабочей копии, в
// конвейере не исполняется никогда.
//
// # Инъекция роняет ТОЛЬКО проверяемое
//
// Каждый случай отличается от своего законного близнеца РОВНО одним: снят вызов,
// переставлен вызов, выпотрошен посредник, подменён тип параметра. Инъекция вида
// «завести ещё один элемент» здесь невозможна by construction — предмет гейта не
// перечень, а поток одного значения.

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// ── Часть A: связывание → вызов ─────────────────────────────────────────────

const applierBuiltAndCalledDirectly = `package main

import "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"

func serve() error {
	catalogApplier := modulecatalog.NewApplier(writeRepo)
	if _, err := catalogApplier.ApplyAll(ctx, manifests); err != nil {
		return err
	}
	return nil
}
`

// applierHandedToAnApplyingHelper — ЖИВАЯ раскладка: корень строит применитель и
// передаёт его провязке, которая зовёт применение на своём параметре.
const applierHandedToAnApplyingHelper = `package main

import "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"

func applyDeliveredManifests(ctx context.Context, applier *modulecatalog.Applier) error {
	_, err := applier.ApplyAll(ctx, manifests)
	return err
}

func serve() error {
	catalogApplier := modulecatalog.NewApplier(writeRepo)
	return applyDeliveredManifests(ctx, catalogApplier)
}
`

// applierBuiltNeverCalled — ДЕФЕКТ, который наблюдался вживую: применитель есть,
// зовущего нет.
const applierBuiltNeverCalled = `package main

import "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"

func serve() error {
	catalogApplier := modulecatalog.NewApplier(writeRepo)
	use(catalogApplier)
	return nil
}
`

// applierAliasedNeverCalled — тот же дефект под ПСЕВДОНИМОМ импорта. Гейт,
// знающий одно написание, молчал бы на форме столь же законной.
const applierAliasedNeverCalled = `package main

import mc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"

func serve() error {
	catalogApplier := mc.NewApplier(writeRepo)
	use(catalogApplier)
	return nil
}
`

// applierHandedToAHollowHelper — ПОСРЕДНИК-ПУСТЫШКА: берёт применитель нужного
// типа и не применяет. Гейт, довольствующийся «применитель кому-то передан»,
// молчал бы здесь — то есть на глаголе, который по-прежнему не позван.
const applierHandedToAHollowHelper = `package main

import "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"

func logTheApplier(ctx context.Context, applier *modulecatalog.Applier) error {
	logger.Info("применитель собран", slog.Any("applier", applier))
	return nil
}

func serve() error {
	catalogApplier := modulecatalog.NewApplier(writeRepo)
	return logTheApplier(ctx, catalogApplier)
}
`

// applierHandedToAHelperOfAnotherType — посредник зовёт `ApplyAll` на параметре
// ЧУЖОГО типа. Гейт, судящий по имени метода, счёл бы его применяющим и смолчал
// бы на непозванном применителе.
const applierHandedToAHelperOfAnotherType = `package main

import "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"

func applyLabels(ctx context.Context, patcher *labels.Patcher) error {
	_, err := patcher.ApplyAll(ctx, nil)
	return err
}

func serve() error {
	catalogApplier := modulecatalog.NewApplier(writeRepo)
	return applyLabels(ctx, catalogApplier)
}
`

// applierDiscarded — применитель не связан вовсе. Предмета нет, находки быть не
// должно: иначе гейт краснел бы на пробе, которая его строит и выбрасывает.
const applierDiscarded = `package main

import "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"

func probe() { _ = modulecatalog.NewApplier(writeRepo) }
`

// applierCalledElsewhere — построен в одном файле, позван в другом: законная
// раскладка одного пакета, и гейт обязан на ней молчать.
const applierCalledElsewhere = `package main

func startCatalogApply() error {
	_, err := catalogApplier.ApplyAll(ctx, manifests)
	return err
}
`

func TestIAM1034_InjectionRedsTheUncalledApplierAndKeepsQuietOnTheCalledOne(t *testing.T) {
	cases := []struct {
		name  string
		files []wiringFile
		finds bool
	}{
		{
			name:  "построен и позван напрямую — молчание",
			files: []wiringFile{{"cmd/kacho-iam/serve.go", applierBuiltAndCalledDirectly}},
		},
		{
			name:  "передан применяющей провязке — молчание (живая раскладка)",
			files: []wiringFile{{"cmd/kacho-iam/serve.go", applierHandedToAnApplyingHelper}},
		},
		{
			name:  "построен и НЕ позван — находка",
			files: []wiringFile{{"cmd/kacho-iam/serve.go", applierBuiltNeverCalled}},
			finds: true,
		},
		{
			name:  "под псевдонимом и НЕ позван — находка",
			files: []wiringFile{{"cmd/kacho-iam/serve.go", applierAliasedNeverCalled}},
			finds: true,
		},
		{
			name:  "передан посреднику-ПУСТЫШКЕ — находка",
			files: []wiringFile{{"cmd/kacho-iam/serve.go", applierHandedToAHollowHelper}},
			finds: true,
		},
		{
			name:  "посредник применяет ЧУЖОЙ тип — находка",
			files: []wiringFile{{"cmd/kacho-iam/serve.go", applierHandedToAHelperOfAnotherType}},
			finds: true,
		},
		{
			name:  "применитель отброшен связыванием — молчание",
			files: []wiringFile{{"cmd/kacho-iam/probe.go", applierDiscarded}},
		},
		{
			name: "построен в одном файле, позван в другом — молчание",
			files: []wiringFile{
				{"cmd/kacho-iam/serve.go", applierBuiltNeverCalled},
				{"cmd/kacho-iam/apply.go", applierCalledElsewhere},
			},
		},
		{
			name:  "проба, строящая применитель, предметом не является — молчание",
			files: []wiringFile{{"cmd/kacho-iam/serve_test.go", applierBuiltNeverCalled}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, paths := writeSyntheticRoot(t, tc.files)
			built, used, census, err := applierWiring(root, paths)
			if err != nil {
				t.Fatalf("%v", err)
			}
			t.Logf("%s", census.Summary())

			var uncalled []applierBinding
			for _, b := range built {
				if !used[b.Name] {
					uncalled = append(uncalled, b)
				}
			}
			switch {
			case tc.finds && len(uncalled) == 0:
				t.Fatalf("гейт СМОЛЧАЛ на внесённом дефекте — он не способен упасть "+
					"(построено %d, функций-применителей %d)", census.Built, census.ApplyFns)
			case !tc.finds && len(uncalled) > 0:
				t.Fatalf("гейт покраснел на ЗАКОННОЙ раскладке: %s:%d `%s` — "+
					"ложная находка отключает гейт первой",
					uncalled[0].File, uncalled[0].Line, uncalled[0].Name)
			}
			if !tc.finds {
				return
			}
			// Находка обязана НАЗВАТЬ переменную и координату: покрасневший молча
			// гейт посылает читателя искать не там.
			u := uncalled[0]
			if u.Name != "catalogApplier" || u.Line == 0 || !strings.HasSuffix(u.File, "serve.go") {
				t.Fatalf("находка не назвала ни переменную, ни координату: %+v", u)
			}
		})
	}
}

// TestIAM1034_InjectionProvesTheEmptyWalkIsRefused — премиса части A: обход, не
// прочитавший ничего, обязан быть отказом, а не молчаливым успехом. Живой гейт
// превращает обе нулевые величины переписи в отказ; здесь доказано, что на
// пустом составе они действительно нулевые.
func TestIAM1034_InjectionProvesTheEmptyWalkIsRefused(t *testing.T) {
	root := t.TempDir()
	built, used, census, err := applierWiring(root, nil)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(built) != 0 || len(used) != 0 {
		t.Fatalf("на пустом составе найдено построенных %d, использованных %d — ядро выдумывает",
			len(built), len(used))
	}
	if census.Parsed != 0 || census.Built != 0 {
		t.Fatalf("перепись пустого состава непуста: %s", census.Summary())
	}
	t.Logf("пустой состав: %s — живой гейт на такой переписи ОТКАЗЫВАЕТ", census.Summary())
}

// ── Часть B: порядок на пути старта ─────────────────────────────────────────

const bootOrderCorrect = `package main

func serve() error {
	deliveredManifests, mErr := loadDeliveredManifests(logger, cfg.Manifests)
	if mErr != nil {
		return mErr
	}
	if aErr := applyDeliveredManifests(ctx, logger, catalogApplier, deliveredManifests); aErr != nil {
		return aErr
	}
	catalogCensus, catErr := seed.AssertCatalogParity(ctx, catalogRepo, seed.ImageAnchor())
	return catErr
}
`

const bootOrderApplyMissing = `package main

func serve() error {
	deliveredManifests, mErr := loadDeliveredManifests(logger, cfg.Manifests)
	if mErr != nil {
		return mErr
	}
	use(deliveredManifests)
	catalogCensus, catErr := seed.AssertCatalogParity(ctx, catalogRepo, seed.ImageAnchor())
	return catErr
}
`

const bootOrderApplyAfterParity = `package main

func serve() error {
	deliveredManifests, mErr := loadDeliveredManifests(logger, cfg.Manifests)
	if mErr != nil {
		return mErr
	}
	catalogCensus, catErr := seed.AssertCatalogParity(ctx, catalogRepo, seed.ImageAnchor())
	if catErr != nil {
		return catErr
	}
	return applyDeliveredManifests(ctx, logger, catalogApplier, deliveredManifests)
}
`

const bootOrderApplyBeforeDelivery = `package main

func serve() error {
	if aErr := applyDeliveredManifests(ctx, logger, catalogApplier, nil); aErr != nil {
		return aErr
	}
	deliveredManifests, mErr := loadDeliveredManifests(logger, cfg.Manifests)
	if mErr != nil {
		return mErr
	}
	use(deliveredManifests)
	return seed.AssertCatalogParity(ctx, catalogRepo, seed.ImageAnchor())
}
`

// bootOrderOnlyInComments — все три имени названы ПРОЗОЙ и ни одно не позвано.
// Проверка по подстроке краснела бы на собственном объяснении и зеленела бы на
// файле, где нет ни одного вызова; узел вызова этого не путает.
const bootOrderOnlyInComments = `package main

// serve — путь старта.
//
// Порядок: loadDeliveredManifests, затем applyDeliveredManifests, затем
// seed.AssertCatalogParity. Здесь ничего из этого не зовётся.
func serve() error { return nil }
`

func TestIAM1034_InjectionRedsTheBootOrderAndKeepsQuietOnTheCorrectOne(t *testing.T) {
	cases := []struct {
		name          string
		src           string
		wantDelivery  bool
		wantApply     bool
		wantParity    bool
		wantApplyLate bool // применение стоит ПОСЛЕ стража
		wantApplyEarl bool // применение стоит ПЕРЕД доставкой
	}{
		{
			name: "верный порядок — молчание", src: bootOrderCorrect,
			wantDelivery: true, wantApply: true, wantParity: true,
		},
		{
			name: "применения нет вовсе — находка", src: bootOrderApplyMissing,
			wantDelivery: true, wantParity: true,
		},
		{
			name: "применение ПОСЛЕ стража — находка", src: bootOrderApplyAfterParity,
			wantDelivery: true, wantApply: true, wantParity: true, wantApplyLate: true,
		},
		{
			name: "применение ПЕРЕД доставкой — находка", src: bootOrderApplyBeforeDelivery,
			wantDelivery: true, wantApply: true, wantParity: true, wantApplyEarl: true,
		},
		{
			name: "все три названы только прозой — предпосылки нет", src: bootOrderOnlyInComments,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "serve.go", tc.src, parser.ParseComments)
			if err != nil {
				t.Fatalf("синтетика не разобрана: %v", err)
			}
			a := bootOrderAnchors(fset, file)
			t.Logf("осмотрено вызовов %d · доставка %q · применение %q · страж %q",
				a.CallsSeen, a.DeliveryAt, a.ApplyAt, a.ParityAt)

			if got := a.Delivery.IsValid(); got != tc.wantDelivery {
				t.Fatalf("доставка: найдена=%t, ожидалось %t", got, tc.wantDelivery)
			}
			if got := a.Apply.IsValid(); got != tc.wantApply {
				t.Fatalf("применение: найдено=%t, ожидалось %t — гейт %s", got, tc.wantApply,
					map[bool]string{true: "выдумывает вызов", false: "не видит вызова"}[got])
			}
			if got := a.Parity.IsValid(); got != tc.wantParity {
				t.Fatalf("страж: найден=%t, ожидалось %t", got, tc.wantParity)
			}
			if !tc.wantApply {
				return
			}
			if got := a.Apply > a.Parity; got != tc.wantApplyLate {
				t.Fatalf("«применение после стража»: %t, ожидалось %t — порядок не судится",
					got, tc.wantApplyLate)
			}
			if got := a.Apply < a.Delivery; got != tc.wantApplyEarl {
				t.Fatalf("«применение перед доставкой»: %t, ожидалось %t — порядок не судится",
					got, tc.wantApplyEarl)
			}
		})
	}
}
