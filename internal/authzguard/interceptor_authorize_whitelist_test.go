// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// interceptor_authorize_whitelist_test.go — обход анонимного стража для двух
// имён AuthorizeService, из которых ОДНО пережило свой предмет.
//
// ЖИВОЕ. `ListSubjects` — обратный вопрос («кто вправе <verb> этот объект?»),
// который потребители зовут service→service без PerRPCCredentials. Суффиксный
// разбор его не покрывает: `HasSuffix` по "List" совпадает только с именами,
// ровно на "List" и кончающимися, поэтому нужна явная запись по полному имени.
//
// ПЕРЕЖИВШЕЕ СВОЙ ПРЕДМЕТ. `ListObjects` в контракте БОЛЬШЕ НЕТ (снят вместе с
// внешним движком: перечисление у чужого хранилища имело жёсткий предел и не
// имело продолжения). Запись обхода в `whitelistFullMethod` при этом ОСТАЛАСЬ —
// то есть в наборе стоит послабление, которому больше нечего послаблять. Само по
// себе оно сегодня ничего не открывает: маршрута нет, вызов получает
// Unimplemented ещё до стража. Опасно другое — послабление, у которого нет
// предмета, НЕ ИСТЕКАЕТ САМО и достанется следующему RPC, который назовут тем же
// именем.
//
// Проба ниже удерживает эту запись НАМЕРЕННО, а не по недосмотру: снять её здесь
// значило бы оставить запись прод-набора без единого свидетеля. Снимать надо
// ПАРОЙ — запись в interceptor.go и утверждение здесь, одним изменением. Пока
// пара не снята, эта проба обязана оставаться зелёной и обязана покраснеть, если
// запись уберут в одиночку.
package authzguard

import (
	"log/slog"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Test_Authzguard_ListSubjects_AnonymousCaller_AllowedByWhitelist — живая
// половина. AuthorizeService.ListSubjects — обратный вопрос (для объекта → какие
// субъекты вправе его <verb>), который зовут тем же service→service путём без
// PerRPCCredentials.
func Test_Authzguard_ListSubjects_AnonymousCaller_AllowedByWhitelist(t *testing.T) {
	iceptor := AntiAnonymousUnary(slog.Default())
	fm := "/kacho.cloud.iam.v1.AuthorizeService/ListSubjects"
	_, err := iceptor(anonCtx(), nil,
		&grpc.UnaryServerInfo{FullMethod: fm}, fakeHandler)
	if err != nil {
		t.Fatalf("%s обязан быть в наборе обхода для анонимного вызывающего: его зовут service→service без PerRPCCredentials; got %v", fm, err)
	}
}

// Test_Authzguard_OtherMethod_AnonymousCaller_StillBlocked — парный
// положительный контроль: записи обхода НЕ ослабляют посадку default-deny для
// посторонних мутирующих RPC. Без него оба утверждения выше зеленели бы и на
// страже, который пропускает вообще всё. UserService.Create — канонический
// мутирующий RPC; анонимный вызывающий обязан получить PermissionDenied.
func Test_Authzguard_OtherMethod_AnonymousCaller_StillBlocked(t *testing.T) {
	iceptor := AntiAnonymousUnary(slog.Default())
	fm := "/kacho.cloud.iam.v1.UserService/Create"
	_, err := iceptor(anonCtx(), nil,
		&grpc.UnaryServerInfo{FullMethod: fm}, fakeHandler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("negative control: %s anonymous → expected PermissionDenied, got %v", fm, err)
	}
}
