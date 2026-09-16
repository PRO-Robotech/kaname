// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// ownfronthop_test.go — имя, под которым политика вызывающего узнаёт собственный
// REST-фронт, берётся у ПРОВОДА и совпадает с тем, что выдаёт чарт (#2371).
//
// # Что здесь утверждается, а что нет
//
// Утверждается ПРОИСХОЖДЕНИЕ величины: она читается из того сертификата, который
// фронт предъявляет, тем же отбором, которым имя извлекает слушатель. Что
// политика делает с этим именем — предмет проб `internal/authzguard`, и здесь
// это не пересказывается.

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

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// writeLeafWithURIs кладёт на диск лист с заданными именами URI и отдаёт путь.
//
// Настоящий сертификат, а не подделка строкой: предмет пробы — разбор ТОГО
// формата, который монтирует чарт, и подделка обошла бы ровно его.
func writeLeafWithURIs(t *testing.T, uris ...string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ключ не сгенерирован: %v", err)
	}
	var parsed []*url.URL
	for _, u := range uris {
		p, perr := url.Parse(u)
		if perr != nil {
			t.Fatalf("имя URI %q не разбирается: %v", u, perr)
		}
		parsed = append(parsed, p)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kaname-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         parsed,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("сертификат не выпущен: %v", err)
	}
	path := filepath.Join(t.TempDir(), "tls.crt")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("сертификат не записан: %v", err)
	}
	return path
}

func mtlsWithFrontLeaf(certFile string) config.MTLSConfig {
	var m config.MTLSConfig
	m.RESTUpstreamMTLS.Enable = true
	m.RESTUpstreamMTLS.CertFile = certFile
	return m
}

// TestOwnFrontHopSAN_ReadFromTheLeafTheFrontPresents — несущее: величина есть
// РОВНО то имя, которое слушатель увидит на проводе.
// Домен доверия и пространство имён установки, в которой снят замер, стоят
// ЕДИНОЖДЫ на пакет и собирают остальные величины фикстур.
//
// Не стиль: имя платформы на поверхности, которой продукт называет СЕБЯ, ведётся
// ведомостью остатка (internal/repohygiene), и она судит вхождения. Повторённый
// по фикстурам литерал растит остаток на ровном месте.
const (
	frontTrustDomain = "kacho.cloud"
	frontNamespace   = "kacho"
)

// frontHopSAN — имя клиентского листа фронта в этой установке.
const frontHopSAN = "spiffe://" + frontTrustDomain + "/ns/" + frontNamespace + "/sa/kaname"

func TestOwnFrontHopSAN_ReadFromTheLeafTheFrontPresents(t *testing.T) {
	const want = frontHopSAN
	path := writeLeafWithURIs(t, want)
	got, err := ownFrontHopSAN(mtlsWithFrontLeaf(path), grpcsrv.NewTrustDomain(frontTrustDomain))
	if err != nil {
		t.Fatalf("имя не прочитано: %v", err)
	}
	if got != want {
		t.Fatalf("имя листа фронта = %q, ожидалось %q", got, want)
	}
}

// TestOwnFrontHopSAN_UsesTheSameSelectionAsTheListener — при нескольких именах
// URI берётся ПЕРВОЕ В НАШЕМ ДОМЕНЕ, а не просто первое.
//
// Проба существует затем, что своя копия правила отбора разошлась бы со
// слушателем МОЛЧА: обе строки остались бы синтаксически годными, и хоп получал
// бы отказ на каждом запросе с виду по неизвестной причине.
func TestOwnFrontHopSAN_UsesTheSameSelectionAsTheListener(t *testing.T) {
	const ours = frontHopSAN
	path := writeLeafWithURIs(t, "spiffe://other.example/ns/"+frontNamespace+"/sa/kaname", ours)
	d := grpcsrv.NewTrustDomain(frontTrustDomain)
	got, err := ownFrontHopSAN(mtlsWithFrontLeaf(path), d)
	if err != nil {
		t.Fatalf("имя не прочитано: %v", err)
	}
	if got != ours {
		t.Fatalf("отбор дал %q, ожидалось %q — правило разошлось с тем, которым имя извлекает слушатель",
			got, ours)
	}
	// И то же самое, спрошенное У СЛУШАТЕЛЯ: сравниваются не строки из головы
	// автора, а два прочтения одного сертификата.
	raw, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatalf("сертификат не читается: %v", rerr)
	}
	leaf, lerr := firstCertificate(raw)
	if lerr != nil {
		t.Fatalf("лист не разобран: %v", lerr)
	}
	if listener := d.CertIdentity(leaf); listener != got {
		t.Fatalf("слушатель прочитал %q, корень — %q: два места об одном предмете разошлись",
			listener, got)
	}
}

// TestOwnFrontHopSAN_LeafOutsideOurTrustDomainYieldsNothing — лист чужого центра
// именем фронта не становится.
func TestOwnFrontHopSAN_LeafOutsideOurTrustDomainYieldsNothing(t *testing.T) {
	path := writeLeafWithURIs(t, "spiffe://evil.example/ns/"+frontNamespace+"/sa/kaname")
	got, err := ownFrontHopSAN(mtlsWithFrontLeaf(path), grpcsrv.NewTrustDomain(frontTrustDomain))
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if got != "" {
		t.Fatalf("имя из чужого домена доверия = %q, ожидалось пустое", got)
	}
}

// TestOwnFrontHopSAN_DisabledCredentialIsSilent — ребро открытым текстом:
// удостоверения нет, и это законная посадка, а не отказ.
func TestOwnFrontHopSAN_DisabledCredentialIsSilent(t *testing.T) {
	got, err := ownFrontHopSAN(config.MTLSConfig{}, grpcsrv.NewTrustDomain(frontTrustDomain))
	if err != nil {
		t.Fatalf("выключенное удостоверение дало отказ: %v", err)
	}
	if got != "" {
		t.Fatalf("имя при выключенном удостоверении = %q, ожидалось пустое", got)
	}
}

// TestOwnFrontHopSAN_DeclaredButUnreadableIsAnError — объявлено и не читается:
// расхождение профиля с деревом, и молчать о нём нельзя.
func TestOwnFrontHopSAN_DeclaredButUnreadableIsAnError(t *testing.T) {
	for _, tc := range []struct{ name, file string }{
		{"файл не назван", ""},
		{"файла нет", filepath.Join(t.TempDir(), "нет.crt")},
	} {
		if _, err := ownFrontHopSAN(mtlsWithFrontLeaf(tc.file), grpcsrv.NewTrustDomain(frontTrustDomain)); err == nil {
			t.Errorf("%s: отказа нет — профиль разошёлся с деревом молча", tc.name)
		}
	}
	bad := filepath.Join(t.TempDir(), "tls.crt")
	if err := os.WriteFile(bad, []byte("это не сертификат"), 0o600); err != nil {
		t.Fatalf("файл не записан: %v", err)
	}
	if _, err := ownFrontHopSAN(mtlsWithFrontLeaf(bad), grpcsrv.NewTrustDomain(frontTrustDomain)); err == nil {
		t.Error("неразбираемый файл принят молча")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// СТРАЖ ПОСАДКИ

// TestRequireOwnFrontHopIdentity_RefusesAnUnnamedFrontInProduction — поднятый в
// боевой посадке фронт без узнаваемого имени НЕ ПОДНИМАЕТСЯ.
//
// Без стража поломка вернулась бы ровно в прежнем виде: поверхность есть,
// маршруты есть, обслуженных вызовов ноль — и заметить это стендом нельзя, там
// политика вырождается целиком.
func TestRequireOwnFrontHopIdentity_RefusesAnUnnamedFrontInProduction(t *testing.T) {
	m := mtlsWithFrontLeaf("/etc/kaname/tls/client/tls.crt")
	d := grpcsrv.NewTrustDomain(frontTrustDomain)
	err := requireOwnFrontHopIdentity(true, "0.0.0.0:9099", "", m, d, "")
	if err == nil {
		t.Fatal("боевая посадка приняла поднятый фронт без имени — отказ на каждом запросе остался бы невидим")
	}
	// Отказ называет ОБЕ величины: где искали и в каком домене. Называющий одну
	// сообщает оператору, что не так, и не сообщает, где смотреть.
	for _, want := range []string{"/etc/kaname/tls/client/tls.crt", frontTrustDomain} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}
}

// TestRequireOwnFrontHopIdentity_LegitimateTwins — законные близнецы стража, по
// одному на каждую ось его условия.
//
// Без них страж мог бы отказывать всегда, и проба выше этого не показала бы.
func TestRequireOwnFrontHopIdentity_LegitimateTwins(t *testing.T) {
	m := mtlsWithFrontLeaf("/etc/kaname/tls/client/tls.crt")
	d := grpcsrv.NewTrustDomain(frontTrustDomain)
	const san = frontHopSAN
	for _, tc := range []struct {
		name     string
		prod     bool
		internal string
		public   string
		san      string
	}{
		{"не боевая посадка", false, "0.0.0.0:9099", "0.0.0.0:9098", ""},
		{"фронтов нет вовсе", true, "", "", ""},
		{"имя прочитано", true, "0.0.0.0:9099", "0.0.0.0:9098", san},
		{"только публичный фронт, имя прочитано", true, "", "0.0.0.0:9098", san},
	} {
		if err := requireOwnFrontHopIdentity(tc.prod, tc.internal, tc.public, m, d, tc.san); err != nil {
			t.Errorf("%s: неожиданный отказ %v", tc.name, err)
		}
	}
	// И обратная ось: публичный фронт без имени в боевой посадке тоже
	// отказывает — оба фронта идут к слушателям ОДНИМ удостоверением.
	if err := requireOwnFrontHopIdentity(true, "", "0.0.0.0:9098", m, d, ""); err == nil {
		t.Error("публичный фронт без имени принят: удостоверение у фронтов одно, и отказ у них общий")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// СОГЛАСИЕ С ЧАРТОМ — СНЯТО ВМЕСТЕ С ПРЕДМЕТОМ
//
// Здесь стояла сверка величины `frontHopSAN` с тем, что ФАКТИЧЕСКИ выдаёт чарт:
// она читала `charts/kaname/values.yaml` зонтичного чарта стенда ПЛАТФОРМЫ. В
// этот репозиторий он не входит, а собственный чарт службы (`deploy/`) ключей
// листа фронта не объявляет вовсе.
//
// После выноса службы сверка не исполнялась НИ РАЗУ: резолв координаты называл
// «условие не создано», и проба пропускала себя целиком. Держать её пропуском
// значило бы держать нить, которой нет, — и именно так «единственная нить между
// величиной пробы политики и чартом» полтора месяца выглядела натянутой, будучи
// оборванной.
//
// Предмет не исчез, он сменил дом: чарт, выдающий лист нашего фронта, живёт у
// платформы, и сверка принадлежит её дереву.
//
// Что осталось здесь и держится по-прежнему: ПРОИСХОЖДЕНИЕ величины (читается из
// листа, который предъявляет фронт, тем же отбором, что у слушателя) и страж
// боевой посадки, отказывающий поднятому фронту без имени.
