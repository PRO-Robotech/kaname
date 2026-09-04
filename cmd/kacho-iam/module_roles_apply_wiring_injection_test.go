// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

// module_roles_apply_wiring_injection_test.go — доказательство, что гейт провязки
// применителя РОЛЕЙ (`module_roles_apply_wiring_test.go`) СПОСОБЕН упасть и
// СПОСОБЕН смолчать (задача #2010).
//
// Пара «красное до · зелёное после» снята и на ЖИВОМ дереве: до провязки часть A
// напечатала «применителей ролей построено 0», часть B — «роли \"\"»; после
// провязки обе молчат, а перепись выросла с 34 прод-файлов до 35. Здесь то же
// свойство закреплено воспроизводимо, на синтетике: доказательство, требующее
// вынуть провязку из рабочей копии, в конвейере не исполняется никогда.
//
// # Инъекция роняет ТОЛЬКО проверяемое
//
// Каждый случай отличается от своего законного близнеца РОВНО одним: снят вызов,
// переставлен вызов, выпотрошен посредник, подменён тип параметра. Сборку ни один
// не трогает — синтетика разбирается, а не собирается, — поэтому красное не может
// прийти от соседа.

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// ── Часть A: связывание → вызов ─────────────────────────────────────────────

const rolesApplierBuiltAndCalledDirectly = `package main

import "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/moduleroles"

func serve() error {
	rolesApplier := moduleroles.NewApplier(txRunner, rights)
	if _, err := rolesApplier.Apply(ctx, m, moduleroles.BootActorID); err != nil {
		return err
	}
	return nil
}
`

// rolesApplierHandedToAnApplyingHelper — ЖИВАЯ раскладка: корень строит
// применитель и передаёт его провязке, которая зовёт применение на своём
// параметре.
const rolesApplierHandedToAnApplyingHelper = `package main

import "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/moduleroles"

func applyDeliveredModuleRoles(ctx context.Context, applier *moduleroles.Applier) error {
	for _, m := range manifests {
		if _, err := applier.Apply(ctx, m, moduleroles.BootActorID); err != nil {
			return err
		}
	}
	return nil
}

func serve() error {
	rolesApplier := moduleroles.NewApplier(txRunner, rights)
	return applyDeliveredModuleRoles(ctx, rolesApplier)
}
`

// rolesApplierBuiltNeverCalled — ДЕФЕКТ, который наблюдался вживую: применитель
// есть, зовущего нет.
const rolesApplierBuiltNeverCalled = `package main

import "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/moduleroles"

func serve() error {
	rolesApplier := moduleroles.NewApplier(txRunner, rights)
	use(rolesApplier)
	return nil
}
`

// rolesApplierAliasedNeverCalled — тот же дефект под ПСЕВДОНИМОМ импорта. Гейт,
// знающий одно написание, молчал бы на форме столь же законной.
const rolesApplierAliasedNeverCalled = `package main

import mr "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/moduleroles"

func serve() error {
	rolesApplier := mr.NewApplier(txRunner, rights)
	use(rolesApplier)
	return nil
}
`

// rolesApplierHandedToAHollowHelper — ПОСРЕДНИК-ПУСТЫШКА: берёт применитель
// нужного типа и не применяет. Гейт, довольствующийся «применитель кому-то
// передан», молчал бы здесь — то есть на глаголе, который по-прежнему не позван.
const rolesApplierHandedToAHollowHelper = `package main

import "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/moduleroles"

func logTheRolesApplier(ctx context.Context, applier *moduleroles.Applier) error {
	logger.Info("применитель ролей собран", slog.Any("applier", applier))
	return nil
}

func serve() error {
	rolesApplier := moduleroles.NewApplier(txRunner, rights)
	return logTheRolesApplier(ctx, rolesApplier)
}
`

// rolesApplierHandedToAHelperOfAnotherType — посредник зовёт `Apply` на параметре
// ЧУЖОГО типа. Гейт, судящий по имени метода, счёл бы его применяющим и смолчал
// бы на непозванном применителе. Форма не выдумана: корень СТРОИТ второй
// применитель того же имени метода — каталожный, — и перепутать их легко.
const rolesApplierHandedToAHelperOfAnotherType = `package main

import "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/moduleroles"

func applyCatalog(ctx context.Context, applier *modulecatalog.Applier) error {
	_, err := applier.Apply(ctx, req, moduleroles.BootActorID)
	return err
}

func serve() error {
	rolesApplier := moduleroles.NewApplier(txRunner, rights)
	return applyCatalog(ctx, rolesApplier)
}
`

// rolesApplierDiscarded — применитель не связан вовсе. Предмета нет, находки быть
// не должно: иначе гейт краснел бы на пробе, которая его строит и выбрасывает.
const rolesApplierDiscarded = `package main

import "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/moduleroles"

func probe() { _ = moduleroles.NewApplier(txRunner, rights) }
`

// rolesApplierCalledElsewhere — построен в одном файле, позван в другом:
// законная раскладка одного пакета, и гейт обязан на ней молчать.
const rolesApplierCalledElsewhere = `package main

func startRolesApply() error {
	_, err := rolesApplier.Apply(ctx, m, moduleroles.BootActorID)
	return err
}
`

func TestIAM2010_InjectionRedsTheUncalledRolesApplierAndKeepsQuietOnTheCalledOne(t *testing.T) {
	cases := []struct {
		name  string
		files []wiringFile
		finds bool
	}{
		{
			name:  "построен и позван напрямую — молчание",
			files: []wiringFile{{"cmd/kacho-iam/serve.go", rolesApplierBuiltAndCalledDirectly}},
		},
		{
			name:  "передан применяющей провязке — молчание (живая раскладка)",
			files: []wiringFile{{"cmd/kacho-iam/serve.go", rolesApplierHandedToAnApplyingHelper}},
		},
		{
			name:  "построен и НЕ позван — находка",
			files: []wiringFile{{"cmd/kacho-iam/serve.go", rolesApplierBuiltNeverCalled}},
			finds: true,
		},
		{
			name:  "под псевдонимом и НЕ позван — находка",
			files: []wiringFile{{"cmd/kacho-iam/serve.go", rolesApplierAliasedNeverCalled}},
			finds: true,
		},
		{
			name:  "передан посреднику-ПУСТЫШКЕ — находка",
			files: []wiringFile{{"cmd/kacho-iam/serve.go", rolesApplierHandedToAHollowHelper}},
			finds: true,
		},
		{
			name:  "посредник применяет ЧУЖОЙ тип (каталожный) — находка",
			files: []wiringFile{{"cmd/kacho-iam/serve.go", rolesApplierHandedToAHelperOfAnotherType}},
			finds: true,
		},
		{
			name:  "применитель отброшен связыванием — молчание",
			files: []wiringFile{{"cmd/kacho-iam/probe.go", rolesApplierDiscarded}},
		},
		{
			name: "построен в одном файле, позван в другом — молчание",
			files: []wiringFile{
				{"cmd/kacho-iam/serve.go", rolesApplierBuiltNeverCalled},
				{"cmd/kacho-iam/roles.go", rolesApplierCalledElsewhere},
			},
		},
		{
			name:  "проба, строящая применитель, предметом не является — молчание",
			files: []wiringFile{{"cmd/kacho-iam/serve_test.go", rolesApplierBuiltNeverCalled}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, paths := writeSyntheticRoot(t, tc.files)
			built, used, census, err := rolesApplierWiring(root, paths)
			if err != nil {
				t.Fatalf("%v", err)
			}
			t.Logf("%s", census.Summary())

			var uncalled []rolesApplierBinding
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
			if u.Name != "rolesApplier" || u.Line == 0 || !strings.HasSuffix(u.File, "serve.go") {
				t.Fatalf("находка не назвала ни переменную, ни координату: %+v", u)
			}
		})
	}
}

// TestIAM2010_InjectionProvesTheEmptyWalkIsRefused — премиса части A: обход, не
// прочитавший ничего, обязан быть отказом, а не молчаливым успехом. Живой гейт
// превращает обе нулевые величины переписи в отказ; здесь доказано, что на
// пустом составе они действительно нулевые.
func TestIAM2010_InjectionProvesTheEmptyWalkIsRefused(t *testing.T) {
	root := t.TempDir()
	built, used, census, err := rolesApplierWiring(root, nil)
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

const rolesOrderCorrect = `package main

func serve() error {
	deliveredManifests, mErr := loadDeliveredManifests(logger, cfg.Manifests)
	if mErr != nil {
		return mErr
	}
	catalogCensus, catErr := seed.AssertCatalogParity(ctx, catalogRepo)
	if catErr != nil {
		return catErr
	}
	return applyDeliveredModuleRoles(ctx, logger, rolesApplier, deliveredManifests)
}
`

const rolesOrderApplyMissing = `package main

func serve() error {
	deliveredManifests, mErr := loadDeliveredManifests(logger, cfg.Manifests)
	if mErr != nil {
		return mErr
	}
	use(deliveredManifests)
	catalogCensus, catErr := seed.AssertCatalogParity(ctx, catalogRepo)
	return catErr
}
`

const rolesOrderApplyBeforeParity = `package main

func serve() error {
	deliveredManifests, mErr := loadDeliveredManifests(logger, cfg.Manifests)
	if mErr != nil {
		return mErr
	}
	if rErr := applyDeliveredModuleRoles(ctx, logger, rolesApplier, deliveredManifests); rErr != nil {
		return rErr
	}
	catalogCensus, catErr := seed.AssertCatalogParity(ctx, catalogRepo)
	return catErr
}
`

const rolesOrderApplyBeforeDelivery = `package main

func serve() error {
	if rErr := applyDeliveredModuleRoles(ctx, logger, rolesApplier, nil); rErr != nil {
		return rErr
	}
	deliveredManifests, mErr := loadDeliveredManifests(logger, cfg.Manifests)
	if mErr != nil {
		return mErr
	}
	use(deliveredManifests)
	return seed.AssertCatalogParity(ctx, catalogRepo)
}
`

// rolesOrderOnlyInComments — все три имени названы ПРОЗОЙ и ни одно не позвано.
// Проверка по подстроке краснела бы на собственном объяснении и зеленела бы на
// файле, где нет ни одного вызова; узел вызова этого не путает.
const rolesOrderOnlyInComments = `package main

// serve — путь старта.
//
// Порядок: loadDeliveredManifests, затем seed.AssertCatalogParity, затем
// applyDeliveredModuleRoles. Здесь ничего из этого не зовётся.
func serve() error { return nil }
`

func TestIAM2010_InjectionRedsTheRolesOrderAndKeepsQuietOnTheCorrectOne(t *testing.T) {
	cases := []struct {
		name          string
		src           string
		wantDelivery  bool
		wantParity    bool
		wantRoles     bool
		wantRolesEarl bool // роли стоят ПЕРЕД стражем каталога
		wantBeforeDlv bool // роли стоят ПЕРЕД доставкой
	}{
		{
			name: "верный порядок — молчание", src: rolesOrderCorrect,
			wantDelivery: true, wantParity: true, wantRoles: true,
		},
		{
			name: "применения ролей нет вовсе — находка", src: rolesOrderApplyMissing,
			wantDelivery: true, wantParity: true,
		},
		{
			name: "роли ПЕРЕД стражем каталога — находка", src: rolesOrderApplyBeforeParity,
			wantDelivery: true, wantParity: true, wantRoles: true, wantRolesEarl: true,
		},
		{
			name: "роли ПЕРЕД доставкой — находка", src: rolesOrderApplyBeforeDelivery,
			wantDelivery: true, wantParity: true, wantRoles: true,
			wantRolesEarl: true, wantBeforeDlv: true,
		},
		{
			name: "все три названы только прозой — предпосылки нет", src: rolesOrderOnlyInComments,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "serve.go", tc.src, parser.ParseComments)
			if err != nil {
				t.Fatalf("синтетика не разобрана: %v", err)
			}
			a := bootRolesOrderAnchors(fset, file)
			t.Logf("осмотрено вызовов %d · доставка %q · страж %q · роли %q",
				a.CallsSeen, a.DeliveryAt, a.ParityAt, a.RolesAt)

			if got := a.Delivery.IsValid(); got != tc.wantDelivery {
				t.Fatalf("доставка: найдена=%t, ожидалось %t", got, tc.wantDelivery)
			}
			if got := a.Parity.IsValid(); got != tc.wantParity {
				t.Fatalf("страж: найден=%t, ожидалось %t", got, tc.wantParity)
			}
			if got := a.Roles.IsValid(); got != tc.wantRoles {
				t.Fatalf("применение ролей: найдено=%t, ожидалось %t — гейт %s", got, tc.wantRoles,
					map[bool]string{true: "выдумывает вызов", false: "не видит вызова"}[got])
			}
			if !tc.wantRoles {
				return
			}
			if got := a.Roles < a.Parity; got != tc.wantRolesEarl {
				t.Fatalf("«роли перед стражем»: %t, ожидалось %t — порядок не судится",
					got, tc.wantRolesEarl)
			}
			if got := a.Roles < a.Delivery; got != tc.wantBeforeDlv {
				t.Fatalf("«роли перед доставкой»: %t, ожидалось %t — порядок не судится",
					got, tc.wantBeforeDlv)
			}
		})
	}
}
