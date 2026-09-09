// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// ownfronthop_injection_test.go — доказательство того, что обе половины
// происхождения имени фронта СПОСОБНЫ упасть, и падают на своём предмете (#2371).
//
// # Осей три, по числу мест, где величина может разойтись с проводом
//
//  1. ЧАРТ. Учётную запись переименовывают в файле значений — дословно того же
//     вида, что читает проба согласия. Сверка обязана покраснеть и назвать обе
//     строки. Законный близнец — тот же файл без правки: сверка молчит.
//  2. ОТБОР ИМЕНИ. Лист несёт имя чужого домена ПЕРВЫМ. Наивный отбор («взять
//     URIs[0]») вернул бы чужое; действующий обязан вернуть наше. Законный
//     близнец — лист с одним именем: оба отбора совпадают, поэтому проба на нём
//     ничего не доказала бы.
//  3. ПОРЯДОК ЦЕПОЧКИ. Файл несёт лист И удостоверяющий центр. Разбор обязан
//     взять ЛИСТ; взявший последний прочитал бы имя центра.
//
// # Инъекция роняет ТОЛЬКО проверяемое
//
// Каждый мир отличается от своего близнеца одним фактом: одно значение в
// значениях чарта либо один добавленный сертификат. Настоящий чарт дерева не
// правится вовсе — инъекция подаёт свой файл, — поэтому соседние проверки
// посадки не задеваются.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

// writeChartValues кладёт файл значений с объявленным листом и отдаёт путь.
func writeChartValues(t *testing.T, trust, ns, sa string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "kaname")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("каталог не создан: %v", err)
	}
	path := filepath.Join(dir, "values.yaml")
	body := "mtls:\n  spiffe:\n    trustDomain: " + trust +
		"\n    namespace: " + ns + "\n    saName: " + sa + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("файл значений не записан: %v", err)
	}
	return path
}

// TestOwnFrontHopInjection_ChartRenameIsCaught — переименование учётной записи в
// чарте ловится, и сверка называет ОБЕ строки.
func TestOwnFrontHopInjection_ChartRenameIsCaught(t *testing.T) {
	got := chartFrontLeafMismatch(t, writeChartValues(t, frontTrustDomain, frontNamespace, "kaname-renamed"))
	if got == "" {
		t.Fatal("переименование учётной записи в чарте прошло молча — проба политики осталась бы " +
			"зелёной, спрашивая про лист, которого установка не выдаёт")
	}
	for _, want := range []string{"kaname-renamed", "sa/kaname\""} {
		if !strings.Contains(got, want) {
			t.Errorf("расхождение не называет %q: %s", want, got)
		}
	}
	t.Logf("инъекция чарта поймана: %s", got)
}

// TestOwnFrontHopInjection_ChartTwinStaysSilent — законный близнец: файл с тем
// же листом, что выдаёт дерево, молчит.
//
// Без него красное выше приходило бы от чего угодно — например от сверки,
// краснеющей на любом файле.
func TestOwnFrontHopInjection_ChartTwinStaysSilent(t *testing.T) {
	if got := chartFrontLeafMismatch(t, writeChartValues(t, frontTrustDomain, frontNamespace, "kaname")); got != "" {
		t.Fatalf("законный лист объявлен расхождением: %s", got)
	}
}

// TestOwnFrontHopInjection_NaiveSelectionWouldTakeTheForeignName — наивный отбор
// «первое имя URI» вернул бы чужое, действующий возвращает наше.
//
// Обе величины утверждаются рядом: без первой проба не показала бы, что предмет
// у неё вообще есть, — на листе с одним именем оба отбора совпадают.
func TestOwnFrontHopInjection_NaiveSelectionWouldTakeTheForeignName(t *testing.T) {
	const foreign = "spiffe://evil.example/ns/" + frontNamespace + "/sa/kaname"
	const ours = frontHopSAN
	path := writeLeafWithURIs(t, foreign, ours)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("сертификат не читается: %v", err)
	}
	leaf, err := firstCertificate(raw)
	if err != nil {
		t.Fatalf("лист не разобран: %v", err)
	}
	if naive := leaf.URIs[0].String(); naive != foreign {
		t.Fatalf("инъекция беспредметна: первым именем стоит %q, а не чужое %q", naive, foreign)
	}
	got, err := ownFrontHopSAN(mtlsWithFrontLeaf(path), grpcsrv.NewTrustDomain(frontTrustDomain))
	if err != nil {
		t.Fatalf("имя не прочитано: %v", err)
	}
	if got == foreign {
		t.Fatal("отбор вернул имя чужого домена доверия — политика узнавала бы хопом чужой лист")
	}
	if got != ours {
		t.Fatalf("отбор вернул %q, ожидалось %q", got, ours)
	}
}

// TestOwnFrontHopInjection_ChainOrderTakesTheLeaf — из цепочки берётся ЛИСТ, а
// не удостоверяющий центр.
func TestOwnFrontHopInjection_ChainOrderTakesTheLeaf(t *testing.T) {
	const leafSAN = frontHopSAN
	const caSAN = "spiffe://" + frontTrustDomain + "/ns/" + frontNamespace + "/sa/" + frontNamespace + "-internal-ca"
	path := filepath.Join(t.TempDir(), "tls.crt")
	if err := os.WriteFile(path, append(certPEM(t, leafSAN), certPEM(t, caSAN)...), 0o600); err != nil {
		t.Fatalf("цепочка не записана: %v", err)
	}
	got, err := ownFrontHopSAN(mtlsWithFrontLeaf(path), grpcsrv.NewTrustDomain(frontTrustDomain))
	if err != nil {
		t.Fatalf("имя не прочитано: %v", err)
	}
	if got == caSAN {
		t.Fatal("из цепочки взято имя удостоверяющего центра вместо листа")
	}
	if got != leafSAN {
		t.Fatalf("из цепочки взято %q, ожидался лист %q", got, leafSAN)
	}
}

// certPEM — самоподписанный сертификат с одним именем URI, в кодировке PEM.
func certPEM(t *testing.T, uri string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ключ не сгенерирован: %v", err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("имя URI %q не разбирается: %v", uri, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "kaname"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("сертификат не выпущен: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
