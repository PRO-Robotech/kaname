// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// mtls_internalrest_clientauth_test.go — ЧТО ПРОИСХОДИТ НА ПРОВОДЕ у внутреннего
// REST-фронта, когда клиент не предъявляет сертификата.
//
// # Почему проба поведенческая, а не декларативная
//
// Утверждение «режим объявлен взаимным» есть утверждение о ЗНАЧЕНИИ, и оно
// зеленело бы на посадке, где транспорт этого значения не исполняет. Предмет
// задачи — расхождение ПОКАЗАНИЯ с ПРОВОДОМ, поэтому провод спрашивается
// напрямую: поднимается настоящий слушатель под тем самым транспортом, который
// строит процесс, и в него идёт настоящий HTTP-клиент — с удостоверением и без.
//
// Транспорт берётся ТЕМ ЖЕ путём, каким его получает процесс: настройка
// читается из окружения (LoadMTLS) и превращается в транспорт своим методом.
// Собранный в пробе руками, он отвечал бы за пробу, а не за посадку.
//
// # Дельта между мирами — ОДИН факт
//
// Три прогона ниже отличаются друг от друга ровно одной величиной — режимом
// проверки клиента, — и ничем больше: те же файлы материала, тот же адрес, тот
// же обработчик, тот же клиент. Сравнивать поэтому есть что: различие исходов
// приписывается режиму, а не соседней перемене.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// internalRESTWire — поднятый внутренний REST-фронт: адрес слушателя и то, как
// он построен процессом.
type internalRESTWire struct {
	addr             string
	requiresCertSays bool
}

// raiseInternalRESTFront поднимает слушатель под транспортом внутреннего
// REST-фронта, объявленным режимом mode.
//
// Пустой mode означает «ручка не задана» — тот самый вход, который процесс
// читает своим разрешённым значением, и его исход обязан быть измерен наравне
// с явными.
func raiseInternalRESTFront(t *testing.T, mode, certFile, keyFile, caFile string) internalRESTWire {
	t.Helper()
	t.Setenv("KANAME_INTERNALREST_SERVER_MTLS_ENABLE", "true")
	t.Setenv("KANAME_INTERNALREST_SERVER_MTLS_CERTFILE", certFile)
	t.Setenv("KANAME_INTERNALREST_SERVER_MTLS_KEYFILE", keyFile)
	t.Setenv("KANAME_INTERNALREST_SERVER_MTLS_CLIENTCAFILES", caFile)
	t.Setenv("KANAME_INTERNALREST_SERVER_MTLS_CLIENTAUTHMODE", mode)

	m, err := config.LoadMTLS()
	require.NoError(t, err)
	tlsCfg, err := m.InternalRESTServerTLSConfig()
	require.NoError(t, err)
	require.NotNil(t, tlsCfg, "включённое ребро обязано дать транспорт")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln = tls.NewListener(ln, tlsCfg)
	t.Cleanup(func() { _ = ln.Close() })

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		ReadHeaderTimeout: time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	return internalRESTWire{addr: ln.Addr().String(), requiresCertSays: m.InternalRESTRequiresClientCert()}
}

// dialInternalRESTFront идёт на фронт настоящим HTTP-клиентом. withClientCert
// решает, предъявляет ли клиент удостоверение; всё остальное у обоих клиентов
// одинаково.
func dialInternalRESTFront(t *testing.T, w internalRESTWire, withClientCert bool,
	certFile, keyFile, caFile string) (int, error) {
	t.Helper()
	pool := x509.NewCertPool()
	caPEM, err := os.ReadFile(caFile)
	require.NoError(t, err)
	require.True(t, pool.AppendCertsFromPEM(caPEM))

	// Имя сервера ВЫВОДИТСЯ из выданного материала, а не выписывается: вторая
	// запись того же имени разошлась бы с первой молча — рукопожатие перестало
	// бы состояться, и проба назвала бы это отказом транспорта.
	clientTLS := &tls.Config{
		RootCAs:    pool,
		ServerName: serverNameFromCert(t, certFile),
		MinVersion: tls.VersionTLS12,
	}
	if withClientCert {
		leaf, lerr := tls.LoadX509KeyPair(certFile, keyFile)
		require.NoError(t, lerr)
		clientTLS.Certificates = []tls.Certificate{leaf}
	}
	cl := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: clientTLS},
	}
	resp, err := cl.Get("https://" + w.addr + "/")
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// serverNameFromCert — имя, на которое выписан серверный лист пробы.
func serverNameFromCert(t *testing.T, certFile string) string {
	t.Helper()
	pemBytes, err := os.ReadFile(certFile)
	require.NoError(t, err)
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block, "серверный лист пробы не разбирается")
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.NotEmpty(t, leaf.DNSNames,
		"у листа пробы нет имён: рукопожатие не состоялось бы по причине, к предмету не относящейся")
	return leaf.DNSNames[0]
}

// TestInternalRESTFront_ServerTLSOnly_AdmitsACallerWithNoCertificate — ПРЕДМЕТ,
// названный исходом на проводе: на одностороннем режиме вызывающий без
// удостоверения доходит до обработчика.
//
// Это отрицательная сторона пары, и она обязана быть здесь: без неё утверждение
// ниже («взаимный режим не пускает») зеленело бы на слушателе, не пускающем
// никого.
func TestInternalRESTFront_ServerTLSOnly_AdmitsACallerWithNoCertificate(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	w := raiseInternalRESTFront(t, "server-tls-only", certFile, keyFile, caFile)

	require.False(t, w.requiresCertSays,
		"на одностороннем режиме показание обязано отвечать «сертификата не требую»")

	code, err := dialInternalRESTFront(t, w, false, certFile, keyFile, caFile)
	require.NoError(t, err,
		"односторонний режим обязан пропускать вызывающего без удостоверения — "+
			"это и есть измеряемое положение дел, а не пожелание")
	require.Equal(t, http.StatusOK, code)
}

// TestInternalRESTFront_UnsetMode_AdmitsACallerWithNoCertificate — тот же исход
// при НЕЗАДАННОЙ ручке.
//
// Стоит отдельно, потому что это другой вход: профиль, о режиме умолчавший,
// получает не отказ, а односторонний транспорт, — и на посадке это неотличимо
// от объявленного решения.
func TestInternalRESTFront_UnsetMode_AdmitsACallerWithNoCertificate(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	w := raiseInternalRESTFront(t, "", certFile, keyFile, caFile)

	require.False(t, w.requiresCertSays,
		"незаданная ручка обязана отвечать «сертификата не требую»: умолчание транспорта односторонее")

	code, err := dialInternalRESTFront(t, w, false, certFile, keyFile, caFile)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)
}

// TestInternalRESTFront_Mutual_RefusesTheHandshakeWithoutACertificate —
// НЕСУЩЕЕ УТВЕРЖДЕНИЕ: на взаимном режиме тот же клиент до обработчика не
// доходит, и останавливает его РУКОПОЖАТИЕ, а не ответ.
func TestInternalRESTFront_Mutual_RefusesTheHandshakeWithoutACertificate(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	w := raiseInternalRESTFront(t, "mutual", certFile, keyFile, caFile)

	require.True(t, w.requiresCertSays,
		"на взаимном режиме показание обязано отвечать «сертификат требую»")

	code, err := dialInternalRESTFront(t, w, false, certFile, keyFile, caFile)
	require.Error(t, err,
		"взаимный режим обязан отвергнуть вызывающего без удостоверения на рукопожатии; "+
			"получен код %d", code)
	require.Zero(t, code, "ответа не бывает вовсе: соединение не состоялось")
}

// TestInternalRESTFront_Mutual_AdmitsACallerWithACertificate — ЗАКОННЫЙ БЛИЗНЕЦ
// несущего утверждения.
//
// Без него отказ выше был бы неотличим от сломанного слушателя: «не пускает
// никого» и «не пускает безымянного» дают один и тот же вывод у первой пробы.
func TestInternalRESTFront_Mutual_AdmitsACallerWithACertificate(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	w := raiseInternalRESTFront(t, "mutual", certFile, keyFile, caFile)

	code, err := dialInternalRESTFront(t, w, true, certFile, keyFile, caFile)
	require.NoError(t, err,
		"предъявивший удостоверение внутреннего центра обязан пройти: иначе взаимный "+
			"режим означал бы недостижимую поверхность, а не сужение")
	require.Equal(t, http.StatusOK, code)
}

// TestInternalRESTFront_OptionalMutual_StillAdmitsACallerWithNoCertificate —
// ГРАНИЦА решения, названная исходом, а не прозой.
//
// Запрашивающий режим выглядит сужением и им не является: соединение без
// удостоверения проходит. Сужает при нём обработчик, который проверенного пира
// требует сам, — а у этой поверхности его нет.
func TestInternalRESTFront_OptionalMutual_StillAdmitsACallerWithNoCertificate(t *testing.T) {
	certFile, keyFile, caFile := writeTestCert(t)
	w := raiseInternalRESTFront(t, "optional-mutual", certFile, keyFile, caFile)

	require.False(t, w.requiresCertSays,
		"запрашивающий режим сертификата НЕ требует — показание обязано говорить это, "+
			"а не считать запрос требованием")

	code, err := dialInternalRESTFront(t, w, false, certFile, keyFile, caFile)
	require.NoError(t, err, "запрашивающий режим пропускает вызывающего без удостоверения")
	require.Equal(t, http.StatusOK, code)
}
