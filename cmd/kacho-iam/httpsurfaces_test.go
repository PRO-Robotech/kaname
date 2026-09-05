// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// httpsurfaces_test.go — четыре не-gRPC поверхности iam ОБСЛУЖИВАЮТСЯ и
// ОСВОБОЖДАЮТ порт, а их объявления судятся парой осей.
//
// Пробы заведены взамен той части трёх соседних текстовых гейтов, которая искала
// в исходнике имена снятых полей (`*HTTPServer.Serve`, `*HTTPServer.Shutdown`,
// обёртка слушателя транспортом). Поиск имени снятого поля — требование дефекта;
// здесь утверждается исход.

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/servicecontract"
	"github.com/PRO-Robotech/kacho/pkg/servicehost"
)

// freeSurfaceAddr занимает и тут же отпускает порт: «порт освобождён»
// доказывается повторной привязкой к ТОМУ ЖЕ адресу, поэтому он обязан быть
// фиксированным.
func freeSurfaceAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("занять порт под пробу: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// TestIAMSurfacesServeAndReleaseTheirPorts — поверхность, объявленная общей
// частью iam, поднимается и ПОСЛЕ отмены контекста отдаёт порт.
//
// Утверждается наблюдаемое. Проба вида «гашение было вызвано» осталась бы
// зелёной на слушателе, который порт всё ещё держит, — то есть ровно на том
// дефекте, ради которого профиль и написан.
func TestIAMSurfacesServeAndReleaseTheirPorts(t *testing.T) {
	addr := freeSurfaceAddr(t)
	d, err := iamHTTPSurface(servicecontract.Surface{
		Name:    "проба поверхности",
		Mode:    servicecontract.ModeProduction,
		Logger:  discardSurfaceLogger(),
		Addr:    addrAxis(addr, "адрес пробы задан, эта причина не используется"),
		Handler: http404Only(),
		Reach:   servicecontract.ReachClusterInternal,
		Auth: servicecontract.NotApplicable[servicecontract.SurfaceAuthMech](
			"проба: внутренний Service, на проводе ничего, кроме пустого ответа"),
	})
	if err != nil {
		t.Fatalf("законное объявление отвергнуто: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	wait, serr := servicehost.ServeSurface(ctx, d)
	if serr != nil {
		t.Fatalf("поверхность не поднялась: %v", serr)
	}
	done := make(chan error, 1)
	go func() { done <- wait() }()

	// Положительный контроль: пока контекст жив, порт ЗАНЯТ. Без него «порт
	// свободен» ниже было бы верно и для поверхности, которая не поднялась вовсе.
	if !portBusyWithin(t, addr) {
		t.Fatal("поверхность объявлена поднимаемой, а порт свободен — она не поднялась")
	}

	cancel()
	if serr := <-done; serr != nil {
		t.Fatalf("гашение вернуло ошибку: %v", serr)
	}
	l, berr := net.Listen("tcp", addr)
	if berr != nil {
		t.Fatalf("порт %s занят ПОСЛЕ возврата профиля — следующий старт процесса споткнулся бы "+
			"о собственный предыдущий: %v", addr, berr)
	}
	_ = l.Close()
}

// TestIAMExternalSurfaceWithoutAuthIsRefused — пара осей судит по существу.
//
// Поверхность выдачи docker-токена — единственная внешне досягаемая у iam, и
// снять на ней аутентификацию нельзя даже объявлением. Проба идёт через ТУ ЖЕ
// общую часть, что и корень: инъекция в копию помощника доказывала бы свойство
// копии.
func TestIAMExternalSurfaceWithoutAuthIsRefused(t *testing.T) {
	base := func() servicecontract.Surface {
		return servicecontract.Surface{
			Name:    "выдача docker-токена (проба)",
			Mode:    servicecontract.ModeProduction,
			Logger:  discardSurfaceLogger(),
			Addr:    servicecontract.Value("127.0.0.1:0"),
			Handler: http404Only(),
			Reach:   servicecontract.ReachExternal,
		}
	}

	unauth := base()
	unauth.Auth = servicecontract.NotApplicable[servicecontract.SurfaceAuthMech](
		"мы решили, что и так сойдёт")
	if _, err := iamHTTPSurface(unauth); err == nil {
		t.Fatal("внешне досягаемая поверхность со снятой аутентификацией принята — " +
			"пара осей не судит ничего")
	} else if !strings.Contains(err.Error(), "ИЗВНЕ") {
		t.Fatalf("отказ не называет предмета: %v", err)
	}

	// Законный близнец той же формы: та же внешняя досягаемость, но механизм
	// назван. Без него отрицание выше зеленело бы на объявлении, которое
	// отвергает вообще всё.
	twin := base()
	twin.Auth = servicecontract.Value[servicecontract.SurfaceAuthMech](
		"подпись ключом служебной учётки, проверяется обработчиком на каждом запросе")
	if _, err := iamHTTPSurface(twin); err != nil {
		t.Fatalf("внешняя поверхность с названной аутентификацией отвергнута: %v", err)
	}
}

// TestIAMSurfaceDisabledByDeclarationCarriesItsReason — выключение поверхности
// есть ОБЪЯВЛЕНИЕ, и цена выключения у каждой своя.
//
// Это и есть предмет `addrAxis`: причина требуется аргументом, а не берётся из
// общего шаблона. У скрейпа выключение стоит наблюдаемости, у зеркала ключей —
// закрытой верификации всей плоскости данных реестра, и общая формулировка
// сделала бы обе неразличимыми.
func TestIAMSurfaceDisabledByDeclarationCarriesItsReason(t *testing.T) {
	const because = "адрес зеркала ключей не задан: плоскости данных реестра неоткуда взять ключи"
	d, err := iamHTTPSurface(servicecontract.Surface{
		Name:   "зеркало ключей (проба)",
		Mode:   servicecontract.ModeProduction,
		Logger: discardSurfaceLogger(),
		Addr:   addrAxis("", because),
		Reach:  servicecontract.ReachClusterInternal,
		Auth: servicecontract.NotApplicable[servicecontract.SurfaceAuthMech](
			"проба: публичный материал проверки подписи"),
	})
	if err != nil {
		t.Fatalf("объявленное выключение отвергнуто: %v", err)
	}
	if d.Enabled() {
		t.Fatal("поверхность объявлена выключенной, а сообщает, что поднимается")
	}
	if d.DisabledBecause() != because {
		t.Fatalf("причина выключения не доехала до вызывающего: %q", d.DisabledBecause())
	}
	// Выключенная поверхность есть ИСХОД, а не пропуск: функция возвращается сразу.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wait, serr := servicehost.ServeSurface(ctx, d)
	if serr != nil {
		t.Fatalf("выключенная поверхность вернула ошибку: %v", serr)
	}
	if werr := wait(); werr != nil {
		t.Fatalf("ожидание выключенной поверхности вернуло ошибку: %v", werr)
	}
}

// http404Only — обработчик-пустышка: предмет проб выше — жизненный цикл
// слушателя, а не то, что он отдаёт.
func http404Only() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
}

func discardSurfaceLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// portBusyWithin ждёт, пока порт станет занят: привязка происходит в горутине,
// и мгновенная проверка была бы гонкой, а фиксированная пауза — флейкой на
// загруженной машине.
func portBusyWithin(t *testing.T, addr string) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return true
		}
		_ = l.Close()
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
