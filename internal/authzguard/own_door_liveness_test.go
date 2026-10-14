// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard_test

// own_door_liveness_test.go — проба живости платформы обязана проходить дверь.
//
// # Предмет
//
// Слушатель iam несёт БОЛЬШЕ, чем контракт iam: `grpcsrv.NewServer` фундамента
// регистрирует `grpc.health.v1.Health` каждому сервису платформы. Карта двери
// выводится из аннотаций ПАКЕТОВ КОНТРАКТА, поэтому службы grpc-go в ней не
// бывает by construction, а незамапленный метод звено отвергает fail-closed.
// Публичность `Health/Check` объявляет сам фундамент рядом с регистрацией
// (`grpcsrv.PublicPlatformMethods`, corelib#90), и его звено доступа читает это
// объявление после карты; своей разметки у двери нет (kaname#609).
//
// Для iam это не деталь: край объявляет `Health/Check` СВОЕЙ готовностью
// («критичные зависимости» в gateway/internal/health/health.go — iam единственный
// критичный), и отвергнутая проба означает 503 на `/readyz` НАВСЕГДА, а не
// «пока сосед не поднялся». Реплика края не становится Ready ни при каком
// состоянии продукта, выкатка не сходится по сроку, а причина видна только в
// журнале края.
//
// # Почему это не послабление
//
// Решение об этом методе принято и записано: ответ КОНСТАНТЕН, одинаков для
// всякого вызывающего, не несёт ни арендатора, ни идентификаторов, а гейтить
// живость вопросом о правах значит превратить перебой модели в перезапуск всего
// кластера. Записано оно ОДИН раз — в фундаменте; проба ниже держит, что дверь
// службы его исполняет и не заводит второй копии.
//
// # Круг узок и проверяется в обе стороны
//
// Освобождается РОВНО `Health/Check` — то, что край действительно зовёт. Всё
// прочее у той же службы (`Health/Watch`) и всякий незамапленный метод остаются
// за дверью: без этой половины проба зеленела бы на двери, пропускающей всё.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/grpcsrv"
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

// ОДНО МЕСТО (kaname#609): публичность `Health/Check` объявляет фундамент рядом с
// регистрацией службы (`grpcsrv.PublicPlatformMethods`, corelib#90), и звено
// доступа фундамента её читает. Своя разметка того же метода в двери была бы
// вторым местом об одном предмете — и пережила бы снятие первого молча.
//
// Судится УЗЕЛ разбора, а не подстрока: полное имя метода строковым литералом в
// исполняемой части пакета двери. Комментарий, объясняющий, почему разметки
// здесь нет, находкой не является by construction. Объём осмотренного
// печатается, пустой обход — отказ.
func TestOwnDoor_LivenessPublicnessHasASingleHomeInTheFoundation(t *testing.T) {
	if !grpcsrv.IsPublicPlatformMethod(livenessProbeMethod) {
		t.Fatalf("фундамент не объявляет %s публичным: дверь, снявшая свою разметку, "+
			"отвергала бы пробу живости", livenessProbeMethod)
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	read, found := 0, []string{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("%s не разобрался: %v", name, err)
		}
		read++
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			if v, err := strconv.Unquote(lit.Value); err == nil && v == livenessProbeMethod {
				found = append(found, fset.Position(lit.Pos()).String())
			}
			return true
		})
	}
	t.Logf("осмотрено файлов пакета двери (без проб): %d · литералов %s: %d", read, livenessProbeMethod, len(found))
	if read == 0 {
		t.Fatal("проба НЕ ИСПОЛНЯЛАСЬ: ни одного файла пакета двери не прочитано")
	}
	if len(found) != 0 {
		t.Fatalf("дверь сама размечает %s (%v), хотя публичность объявляет фундамент "+
			"(grpcsrv.PublicPlatformMethods): два места об одном предмете", livenessProbeMethod, found)
	}
}
