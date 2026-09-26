// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// issuing_surface_test.go — объявление аутентификации внешней поверхности
// выдачи называет КАЖДЫЙ способ, которым на ней аутентифицируется запрос, и
// исключение без аутентификации — с причиной (задача PRO-Robotech/kaname#423,
// возврат ревью безопасности сборки 425).
//
// Церемония монтирует на эту поверхность эндпоинт авторизации (его запрос
// аутентифицирует сессия нашего входа) и метаданные обнаружения (публичное
// чтение без аутентификации). Объявление, которое о них молчит, — самоотчёт
// процесса и дескриптор посадки без пути без аутентификации, при том что путь
// смонтирован. Без церемонии их в объявлении нет: объявление говорит о том, что
// смонтировано.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/handler/ceremonyhttp"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

func TestIssuingSurfaceAuthNamesEveryMountedPresentation(t *testing.T) {
	mounted, ok := issuingSurfaceAuth(true).Get()
	if !ok {
		t.Fatalf("объявление аутентификации поверхности выдачи не несёт значения")
	}
	for _, want := range []string{
		ceremonyhttp.AuthorizePath, loginlanehttp.CookieSession, // путь авторизации и чем он аутентифицирован
		ceremonyhttp.DiscoveryPath, "без аутентификации", "RFC 8414", // исключение и его причина
	} {
		if !strings.Contains(string(mounted), want) {
			t.Errorf("объявление поверхности с церемонией не называет %q: %q", want, mounted)
		}
	}

	bare, ok := issuingSurfaceAuth(false).Get()
	if !ok {
		t.Fatalf("близнец: объявление без церемонии не несёт значения")
	}
	for _, absent := range []string{ceremonyhttp.AuthorizePath, ceremonyhttp.DiscoveryPath} {
		if strings.Contains(string(bare), absent) {
			t.Errorf("близнец: объявление поверхности без церемонии называет несмонтированный %q", absent)
		}
	}
	if !strings.Contains(string(bare), "docker-токена") {
		t.Errorf("близнец: объявление без церемонии потеряло способы машинных полос: %q", bare)
	}
}
