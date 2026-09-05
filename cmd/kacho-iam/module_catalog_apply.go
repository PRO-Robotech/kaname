// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// module_catalog_apply.go — доставленные манифесты ПРИМЕНЯЮТСЯ на старте
// (задача продукта #1034).
//
// # Зачем это здесь
//
// Применитель каталога был написан, покрыт пробами против живой Postgres — и не
// позван НИ РАЗУ: прод-файлов композиционного корня, знающих его, было НОЛЬ.
// Пока так, строки `kacho_iam.catalog_*` наполняет ПОСЕВ МИГРАЦИИ, то есть
// объявленное манифестом состояние доезжает до базы только пересборкой образа
// (`//go:embed *.sql`), а манифест остаётся объявлением без производителя.
//
// Глагол, написанный и не позванный, отличается от отсутствующего ровно одним:
// он покрыт пробами и потому выглядит работающим. Это класс мёртвого стража
// (`00-kacho-core` ban #16): отличать надо не «глагол есть» от «глагола нет», а
// «вызов меняет состояние платформы» от «не меняет».
//
// # Порядок: ПОСЛЕ доставки, ПЕРЕД стражем паритета
//
// Довод целиком —
// `services/iam/docs/engineering/architecture/module-catalog-applier-runs-at-boot.md`.
// Коротко: страж, стоящий ПОСЛЕ применителя, судит то, что применитель ТОЛЬКО ЧТО
// записал. Значит ConfigMap с манифестами — данные ОПЕРАТОРА, а не релиза — в
// одиночку не вправе расширить каталог за пределы того, что знает образ.
// Переставь их, и страж будет судить посев, а продукт применителя не проверит
// никто. Порядок держит гейт `module_catalog_apply_wiring_test.go`, а не эта
// строка.
//
// # Миграции идут РАНЬШЕ — by construction, а не по памяти
//
// Миграции исполняет отдельный бинарь в initContainer того же образа
// (`deploy/helm/umbrella/charts/kacho-iam/templates/deployment.yaml`,
// `initContainers.migrate`), и основной контейнер не стартует, пока тот не
// завершился успехом. Применителю поэтому нечего проверять: таблиц нет — он
// отказывает отказом сервера, называющим отсутствующее отношение, и это ровно то
// же «условие не создано», о котором сказал бы страж.
//
// # Отказ применения — ОТКАЗ ПУСКА
//
// Мягкий проход дал бы производителя, не произведшего ни разу и не сказавшего об
// этом (`security.md` §Hardening, п. 8): служба поднялась бы с каталогом, который
// объявленному состоянию не отвечает, и снаружи это выглядит как «прав не
// выдали» либо — что хуже — как «снятое право продолжает действовать». Отказ,
// который манифест объявил, но применитель не довёз, есть отзыв, не наступивший
// молча.
//
// Цена названа: временный отказ базы на старте роняет под, и он уходит в
// перезапуск. Она мала и ограничена — применение идемпотентно (доказано против
// живой базы), поэтому перезапуск есть повтор, а не углубление беды; а путь
// старта УЖЕ отказывает на сорванной доставке и на расхождении каталога, то есть
// третий отказ не заводит оператору новой таксономии, а расширяет её текстом,
// называющим модуль.

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

// applyDeliveredManifests приводит строки каталога к объявленному доставленными
// манифестами состоянию и печатает перепись — ВСЕГДА, независимо от исхода.
//
// Перепись обязательна: «применено шесть манифестов, изменений ноль» и
// «применено ноль манифестов» — разные утверждения о платформе, а молчание у них
// одно и то же.
func applyDeliveredManifests(
	ctx context.Context,
	logger *slog.Logger,
	applier *modulecatalog.Applier,
	manifests []*manifest.Manifest,
) error {
	if len(manifests) == 0 {
		// Законное состояние ровно одно: доставка посадкой не объявлена.
		// «Объявлена и сорвана» сюда не доходит — её отверг читатель доставки.
		// Молчать нельзя по той же причине, по какой не молчит читатель: снаружи
		// «применять нечего» неотличимо от «применили и ничего не изменилось».
		logger.Info("применение каталога модуля: доставленных манифестов нет, применять нечего")
		return nil
	}

	census, err := applier.ApplyAll(ctx, manifests)
	logger.Info("перепись применения каталога модуля",
		slog.Int("delivered", len(manifests)),
		slog.Int("applied", census.Applied),
		slog.Any("modules", census.Modules),
		slog.Int("changed_modules", census.ChangedModules),
		slog.Int("written_resources", census.WrittenResources),
		slog.Int("written_verbs", census.WrittenVerbs),
		slog.Int("retired_resources", census.RetiredResources),
		slog.Int("retired_verbs", census.RetiredVerbs),
		slog.Int("resettled_rule_refs", census.Resettled.RuleRefs),
		slog.Int("resettled_role_verbs", census.Resettled.RoleVerbs),
		slog.Int("pruned_selector_rows", census.PrunedSelectorRows),
		slog.Int("pruned_selector_rows_dropped", census.PrunedSelectorRowsDropped),
		slog.Int("pruned_selector_types", census.PrunedSelectorTypes),
		slog.Bool("changed", census.Changed()))
	if err != nil {
		return fmt.Errorf("каталог модуля: применение доставленных манифестов: %w", err)
	}
	return nil
}
