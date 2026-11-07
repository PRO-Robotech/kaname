// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// fgaproxy.go — страж авторизации прокси FGA.
//
// RegisterResource / UnregisterResource несут `permission = "<exempt>"` в
// каталоге proto (как все внутренние RPC IAM), поэтому минимальные полномочия НЕ
// выражаются плоской строкой права. Они обеспечиваются ЗДЕСЬ через ReBAC:
//
//  1. SAN клиентского сертификата mTLS (формат SPIRE
//     spiffe://<trust-domain>/ns/<ns>/sa/kacho-<svc>, извлечённый SEC-B через
//     grpcsrv.CertIdentityFromContext в домене, объявленном
//     установкой) распознаётся по перечню модулей установки
//     (moduleidentity.Roster, kaname#984 — лишь ОБЪЯВЛЕННАЯ пара пространства имён и учётки
//     является модулем) и отображается в детерминированный
//     идентификатор ServiceAccount (`'sva' || substr(md5('kacho-<svc>'),1,17)`).
//  2. Выполняется ReBAC Check `service_account:<sva>#fga_writer@account:<canonical-id>`
//     ALLOW → RPC продолжается; DENY → PermissionDenied. Право
//     выдаётся системной выдачей на кластере (kacho#914) — оно видно перечислением
//     выдач и закрывается отзывом.
//
// Безопасный отказ: непроверенный пир, неверный SAN / чужой домен доверия,
// неизвестная SA либо запрещённое отношение сводятся к PermissionDenied.
// Межсервисный путь (mTLS-SA) никогда не спрашивает `required_acr_min`: нижний предел ACR
// касается только пользовательского токена; страж решает лишь по
// отношению ReBAC.
package authzguard

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
)

const (
	// RelationWriteRelation — отношение, которое обязана держать служебная учётка
	// модуля, чтобы писать кортежи через iam. Экспортировано намеренно: пробы и
	// перепись обязаны спрашивать ТО ЖЕ имя, которое спрашивает гейт, — имя,
	// выписанное на стороне пробы, остаётся зелёным, когда гейт спрашивает другое.
	RelationWriteRelation = "fga_writer"
	// relationWriteObject — объект, на котором спрашивается право писать
	// кортежи. Это ПЛАТФОРМЕННЫЙ СИНГЛТОН кластера — тот же, на котором стоят
	// кластерные выдачи (`clusterRootObject`, system_viewer_floor.go).
	//
	// Прежде здесь стоял якорь вне иерархии `cluster → account → project`.
	// У такого якоря нет ни яруса, ни владельца: право не выражалось выдачей,
	// не было видно перечислением выдач и не отзывалось (kacho#914, решение 1 в
	// `docs/engineering/architecture/grant-surface-boundaries.md`).
	// Фактический доступ переезд не расширяет: модуль и прежде писал кортежи по
	// всему кластеру — честнее стало ОБЪЯВЛЕНИЕ этого права.
	relationWriteObject = clusterRootObject

	// svcNamePrefix — приставка учётки модуля (`kacho-<svc>`). Объявлена у
	// разбора личности (`moduleidentity.AccountPrefix`): выводом имени службы из
	// учётки и формулой идентификатора служебной учётки правит одна величина.
	svcNamePrefix = moduleidentity.AccountPrefix
	// saPrefix — приставка идентификатора служебной учётки.
	//
	// Объявлена именем, а не вписана в формулу литералом: круговая сверка с
	// посевом (module_identity_seed_test.go) читает её ОТСЮДА, и вписанный
	// литерал был бы вторым местом об одном предмете — с тем же исходом, ради
	// которого сверка и заведена.
	saPrefix = "sva"
)

// RelationWriteGate авторизует RegisterResource / UnregisterResource через ReBAC.
// Использует порт RelationChecker пакета (scope.go) — ту же поверхность FGA
// `Check(subject, relation, object)`, что и страж области; ей напрямую удовлетворяет
// clients.RelationStore (без дополнительного адаптера в корне композиции).
type RelationWriteGate struct {
	checker RelationChecker
	// modules — личности модулей установки (kaname#984). Нулевое значение не
	// признаёт никого.
	modules moduleidentity.Roster
}

// WithModuleRoster подставляет перечень личностей модулей установки: писать
// отношения вправе только объявленная пара, и домен записи — имя службы её
// учётки.
func (g *RelationWriteGate) WithModuleRoster(r moduleidentity.Roster) *RelationWriteGate {
	g.modules = r
	return g
}

// NewRelationWriteGate строит страж личности/аккаунта с безопасным отказом.
func NewRelationWriteGate(checker RelationChecker) *RelationWriteGate {
	return &RelationWriteGate{checker: checker}
}

// WithProductionMode сохраняет совместимость исходников с корнями композиции.
// Контроль личности/аккаунта регистрации строг в любом режиме.
func (g *RelationWriteGate) WithProductionMode(prod bool) *RelationWriteGate {
	_ = prod
	return g
}

// Authorize распознаёт проверенную личность модуля. Полномочия аккаунта проверяются
// отдельно, после допуска и вывода иерархии объекта службой kaname.
// У писателя регистрации нет обхода для незащищённого режима / разработки.
func (g *RelationWriteGate) Authorize(ctx context.Context) (string, error) {
	module, ok := g.modules.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	return module.Service, nil
}

// AuthorizeCatalogModule возвращает каталоговую личность из доверенного перечня.
// Принадлежность конкретного типа всё равно судится текущей строкой каталога
// в транзакции регистрации; имя из запроса не участвует в признании личности.
func (g *RelationWriteGate) AuthorizeCatalogModule(ctx context.Context) (string, error) {
	module, ok := g.modules.FromContext(ctx)
	if !ok || module.CatalogModule == "" {
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	return module.CatalogModule, nil
}

// AuthorizeAccount проверяет лишь названный аккаунт; выдачи кластера не имеют значения.
// Намеренно не кеширует успешные решения между доставками.
func (g *RelationWriteGate) AuthorizeAccount(ctx context.Context, accountID string) error {
	module, err := g.Authorize(ctx)
	if err != nil {
		return err
	}
	if accountID == "" || g.checker == nil {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	allowed, err := g.checker.Check(ctx, "service_account:"+ServiceAccountIDForService(module), RelationWriteRelation, "account:"+accountID)
	if err != nil {
		return AuthzBackendUnavailable()
	}
	if !allowed {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	return nil
}

// ServiceAccountIDForService выводит детерминированный идентификатор SA модуля из
// короткого имени службы (`'sva' || substr(md5('kacho-<svc>'),1,17)`). Единственный
// источник истины для стража и помощника начальной миграции.
//
// Формула ОДНА на дерево и живёт в `domain.DerivedIDSuffix`: своя копия здесь
// разошлась бы с постгресовой молча — полученный идентификатор остался бы
// синтаксически верным и перестал бы находить строку.
func ServiceAccountIDForService(svc string) string {
	return saPrefix + domain.DerivedIDSuffix(svcNamePrefix+svc)
}
