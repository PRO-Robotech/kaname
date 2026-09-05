// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard_test

// own_door_liveness_test.go — проба живости платформы обязана проходить дверь.
//
// # Предмет
//
// Слушатель iam несёт БОЛЬШЕ, чем контракт iam: `pkg/grpcsrv.NewServer`
// регистрирует `grpc.health.v1.Health` каждому сервису платформы. Карта двери
// выводится из аннотаций ПАКЕТОВ КОНТРАКТА, поэтому службы grpc-go в ней не
// бывает by construction — и незамапленный метод дверь отвергает fail-closed.
//
// Для iam это не деталь: край объявляет `Health/Check` СВОЕЙ готовностью
// («критичные зависимости» в gateway/internal/health/health.go — iam единственный
// критичный), и отвергнутая проба означает 503 на `/readyz` НАВСЕГДА, а не
// «пока сосед не поднялся». Реплика края не становится Ready ни при каком
// состоянии продукта, выкатка не сходится по сроку, а причина видна только в
// журнале края.
//
// # Почему это не послабление, а сведение ДВУХ мест об одном предмете
//
// Решение об этом методе платформой уже принято и записано — единственная запись
// круга публичных на крае (`gateway/internal/middleware/authz_public_allowlist.go`):
// ответ КОНСТАНТЕН, одинаков для всякого вызывающего, не несёт ни арендатора, ни
// идентификаторов, а гейтить живость вопросом о правах значит превратить перебой
// модели в перезапуск всего кластера. Здесь та же запись доводится до
// СЛУЖЕБНОЙ стороны того же вызова: край объявляет метод публичным, а служба
// его отвергала — два места об одном предмете, из которых верно одно.
//
// # Круг узок и проверяется в обе стороны
//
// Освобождается РОВНО `Health/Check` — то, что край действительно зовёт. Всё
// прочее у той же службы (`Health/Watch`) и всякий незамапленный метод остаются
// за дверью: без этой половины проба зеленела бы на двери, пропускающей всё.

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// livenessProbeMethod — то, что зовёт край, опрашивая готовность бэкендов.
const livenessProbeMethod = "/grpc.health.v1.Health/Check"

// ПОЛОЖИТЕЛЬНЫЙ: проба живости доходит до обработчика, и модель о ней не
// спрашивается вовсе — иначе живость была бы связана с доступностью модели.
func TestOwnDoor_PlatformLivenessProbePassesTheDoor(t *testing.T) {
	store := &grantStore{allow: map[string]bool{}}
	door := doorUnder(t, store)

	var hit bool
	_, err := door(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: livenessProbeMethod}, reached(&hit))
	if err != nil {
		t.Fatalf("проба живости отвергнута дверью (%v): край считает iam критичной "+
			"зависимостью, поэтому его /readyz остался бы 503 навсегда", err)
	}
	if !hit {
		t.Fatal("проба живости не дошла до обработчика: дверь ответила за него")
	}
	if len(store.asked) != 0 {
		t.Fatalf("о живости спросили модель (%v): перебой модели стал бы "+
			"перезапуском каждой реплики края", store.asked)
	}
}

// ОТРИЦАНИЕ (законный близнец той же службы): освобождён РОВНО Check.
// Без этой половины «дверь пропускает живость» было бы неотличимо от двери,
// пропускающей всё, что названо не нашим контрактом.
func TestOwnDoor_TheRestOfTheLivenessServiceStaysBehindTheDoor(t *testing.T) {
	store := &grantStore{allow: map[string]bool{}}
	door := doorUnder(t, store)

	for _, method := range []string{
		"/grpc.health.v1.Health/Watch",
		"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
	} {
		var hit bool
		_, err := door(context.Background(), nil,
			&grpc.UnaryServerInfo{FullMethod: method}, reached(&hit))
		if hit {
			t.Fatalf("%s дошёл до обработчика: круг освобождённых шире принятого", method)
		}
		if got := status.Code(err); got != codes.PermissionDenied {
			t.Fatalf("%s: код %s, ждали PermissionDenied", method, got)
		}
	}
}
