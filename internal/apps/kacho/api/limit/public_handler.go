// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package limit

import (
	"context"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
)

// PublicHandler — реализация `iamv1.LimitServiceServer`: та же административная
// поверхность пределов на ПУБЛИЧНОМ слушателе, под правом `system_admin` @
// `cluster` (ADM-1 S1, #878).
//
// # Почему поверхность вообще переезжает
//
// Величины назначает администратор облака, и назначает он их через край.
// Объявленные только внутренним сервисом, глаголы наружу не выходили, и страница
// пределов консоли получала **404** — отказ, неотличимый от «такого раздела нет
// вовсе». Сервис при этом был исправен: класс жил целиком на крае, и ни одна
// проба сервиса не видела его by construction.
//
// # Тонкий транспорт, и «тонкий» здесь проверяемо
//
// Ни одной строки собственной логики: composition root передаёт сюда указатель
// на УЖЕ СОБРАННЫЙ внутренний handler — не копию его зависимостей, а его
// самого, — поэтому «оба пути делают одно» держится построением, а не
// совпадением сборки. Заведи мы здесь свои вызовы use-case'ов, два пути
// разошлись бы на первой же правке одного из них, и разошлись бы молча.
//
// # Что переезд НЕ меняет
//
// Решение о доступе. Обе записи каталога требуют `system_admin` @ `cluster` при
// одном и том же подтверждении личности; согласие двух записей держит проба
// `TestLimits_AdminSurfaceIsReachableFromOutside` тем же предикатом, каким
// гейт общей пары стережёт пул адресов. Публикация адреса не расширяет круг —
// она делает отказ ЧЕСТНЫМ: 403 вместо 404, «нет права» вместо «нет продукта».
//
// # Чего здесь нет
//
// `Resolve` и `ListChangedSince` — сервисная поверхность под узким
// `quota_reader`, её зовут владельцы типов, а не человек. Они остаются
// внутренними: публиковать их значило бы расширить поверхность ради предмета,
// которого у арендатора нет.
type PublicHandler struct {
	iamv1.UnimplementedLimitServiceServer

	admin *Handler
}

// NewPublicHandler собирает публичный транспорт поверх уже собранного
// внутреннего handler'а.
func NewPublicHandler(admin *Handler) *PublicHandler {
	return &PublicHandler{admin: admin}
}

func (h *PublicHandler) Get(ctx context.Context, req *iamv1.GetLimitRequest) (*iamv1.Limit, error) {
	return h.admin.Get(ctx, req)
}

func (h *PublicHandler) List(ctx context.Context, req *iamv1.ListLimitsRequest) (*iamv1.ListLimitsResponse, error) {
	return h.admin.List(ctx, req)
}

func (h *PublicHandler) Create(ctx context.Context, req *iamv1.CreateLimitRequest) (*operationpb.Operation, error) {
	return h.admin.Create(ctx, req)
}

func (h *PublicHandler) Update(ctx context.Context, req *iamv1.UpdateLimitRequest) (*operationpb.Operation, error) {
	return h.admin.Update(ctx, req)
}

func (h *PublicHandler) Delete(ctx context.Context, req *iamv1.DeleteLimitRequest) (*operationpb.Operation, error) {
	return h.admin.Delete(ctx, req)
}
