// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acr_floor_module_apply_test.go — ступень подтверждения личности у
// `InternalModuleService/Apply` ДЕЙСТВУЕТ, а не объявлена (задача #1991, Д9
// приёмки `plan-confirms-what-apply-withdraws.md`).
//
// ПРЕДМЕТ. Контракт объявляет `required_acr_min = "2"`: применение манифеста
// ОТЗЫВАЕТ права арендатора, то есть меняет посадку безопасности. Но `ACRFloor`
// применяет ступень ТОЛЬКО к методам рукописного круга гейт-фронтируемых
// (`GatewayFrontedInternalRPCs`), а четырёх методов службы там не было — значит
// объявление было инертным.
//
// Инертность была РЕШЕНИЕМ с названным предикатом снятия: запись круга заодно
// объявляет, что звать метод вправе только край, а REST-маршрута у края не было,
// и запись завела бы поверхность, недостижимую ни для кого. Маршрут заведён,
// предикат сработал, круг пополнен — и это надо УТВЕРЖДАТЬ, иначе следующая
// правка круга вернёт инертность молча, а объявление контракта продолжит
// обещать ступень.
//
// КАТАЛОГ БЕРЁТСЯ НАСТОЯЩИЙ, А НЕ ПОДДЕЛЬНЫЙ. Соседние пробы этого файла-семейства
// строят `fakeACRCatalog` — им нужен управляемый вход. Здесь предмет ДРУГОЙ:
// утверждается, что ступень действует на ТОЙ величине, которую объявляет
// поставляемый каталог. Подделка ответила бы то, что в неё вписали, и проба
// зеленела бы при `required_acr_min`, снятом с контракта.
//
// ОБЕ СТОРОНЫ. Отрицание («acr=1 отвергается») зеленело бы на floor, отвергающем
// ВСЁ, поэтому положительный близнец («acr=2 проходит») утверждается тем же
// прогоном, а вместе с ними — членство в круге, без которого ступень не
// применяется вовсе.
package authzguard

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
)

const moduleApplyMethod = "/kacho.cloud.iam.v1.InternalModuleService/Apply"

func TestACRFloor_ModuleApply_StepUpIsLiveNotDeclared(t *testing.T) {
	reg, err := seed.LoadPermissionRegistry(context.Background(),
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		t.Fatalf("каталог прав не прочитан: %v", err)
	}

	// (1) Величину объявляет каталог, и она равна "2". Читается у поставляемого
	// каталога, а не у литерала рядом: литерал согласился бы с любой редакцией.
	const fqn = "kacho.cloud.iam.v1.InternalModuleService/Apply"
	if got := reg.RequiredACRMin(fqn); got != "2" {
		t.Fatalf("каталог объявляет ступень %q у %s, ожидалась \"2\" — предмет пробы исчез: "+
			"либо требование снято с контракта, либо запись каталога разошлась с ним", got, fqn)
	}

	// (2) Метод в круге гейт-фронтируемых. Без членства ступень НЕ применяется
	// вовсе — это и есть та инертность, ради снятия которой проба написана.
	inRoster := false
	for _, m := range GatewayFrontedInternalRPCs() {
		if m == moduleApplyMethod {
			inRoster = true
			break
		}
	}
	if !inRoster {
		t.Fatalf("%s нет в GatewayFrontedInternalRPCs(): ACRFloor применяет ступень ТОЛЬКО к "+
			"методам круга, поэтому объявленное контрактом требование инертно — заявлено и не "+
			"исполняется", moduleApplyMethod)
	}

	f := NewACRFloor(reg, GatewayFrontedInternalRPCs()).WithProductionMode(true)

	// (3) Отрицание: подтверждение ниже ступени отвергается.
	err = f.allow(gatewayACRCtx("1"), moduleApplyMethod)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("acr=1 при ступени 2 обязан быть PermissionDenied, получено %v", err)
	}
	if got := status.Convert(err).Message(); got != "permission denied" {
		t.Errorf("текст отказа обязан быть дословно 'permission denied', получено %q", got)
	}
	assertStepUpDetail(t, err, "2")

	// (4) Положительный близнец: без него отрицание зеленело бы на floor,
	// отвергающем всё.
	if err := f.allow(gatewayACRCtx("2"), moduleApplyMethod); err != nil {
		t.Errorf("acr=2 при ступени 2 обязан проходить, получено %v", err)
	}

	t.Logf("осмотрено: записей каталога %d · ступень у %s = %q · круг гейт-фронтируемых %d",
		len(reg.All()), fqn, reg.RequiredACRMin(fqn), len(GatewayFrontedInternalRPCs()))
}
