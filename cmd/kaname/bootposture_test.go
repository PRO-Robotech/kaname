// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/observability"
	"github.com/PRO-Robotech/kacho/pkg/servicecontract"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// captureBootPosture прогоняет posture через реальный JSON-логгер и возвращает
// разобранную строку: локаем НАБЛЮДАЕМЫЙ вывод (его парсит production-posture
// гейт), а не вызов.
func captureBootPosture(t *testing.T, p observability.BootPosture) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	observability.LogBootPosture(observability.NewSlogger(&buf), p)
	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("boot posture line is not one JSON object: %v (raw=%q)", err, buf.String())
	}
	return line
}

// acceptedPosture — дескриптор, ПРИНЯТЫЙ центральным конструктором.
//
// Проба строит самоотчёт из него, а не из настройки рядом, ровно по той причине,
// по какой это делает композиционный корень: самоотчёт обязан рапортовать
// посадку, которая прошла отказы старта, а не ту, которую профиль хотел.
func acceptedPosture(t *testing.T, cfg config.Config) servicecontract.Descriptor {
	t.Helper()
	desc, err := describePosture(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("посадка не принята центральным дескриптором: %v", err)
	}
	return desc
}

func requireBootPostureFields(t *testing.T, line map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		got, ok := line[k]
		if !ok {
			t.Fatalf("field %q missing: %v", k, line)
		}
		if got != v {
			t.Fatalf("field %q = %v (%T), want %v (%T)", k, got, got, v, v)
		}
	}
}

// TestBootPosture_Production — kaname самоотчитывается о принятой posture.
// Из множества листенеров iam (hooks/metrics/jwks-proxy) в контракт попадают
// РОВНО два gRPC-листенера — public :9090 и cluster-internal :9091.
func TestBootPosture_Production(t *testing.T) {
	var cfg config.Config
	cfg.AuthN.Mode = config.ModeProduction
	cfg.Repository.Postgres.URL = "postgres://u:p@pg-iam:5432/kaname"
	cfg.Repository.Postgres.SSLMode = "require"
	// Круг отправителей сужен: без него центральный дескриптор посадку НЕ
	// принимает (О1), и это его работа, а не помеха пробе.
	cfg.AuthN.TrustedForwarderSANs = []string{"spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"}
	// Домен доверия — величина установки: без неё дескриптор не принимается,
	// потому что процесс, не назвавший домена, своим не признаёт никого.
	cfg.AuthN.TrustDomainName = "kacho.cloud"
	var mtls config.MTLSConfig
	mtls.PublicServerMTLS.Enable = true
	mtls.InternalServerMTLS.Enable = true

	requireBootPostureFields(t, captureBootPosture(t, bootPosture(acceptedPosture(t, cfg), cfg, mtls, true, restFrontUp(), restFrontUp())), map[string]any{
		"msg":           observability.BootPostureMsg,
		"service":       "iam",
		"auth_mode":     "production",
		"db_sslmode":    "require",
		"public_mtls":   true,
		"internal_mtls": "true",
		"authz_check":   true,
		// Оси собственных REST-фронтов локаются на НАБЛЮДАЕМОЙ строке: её
		// разбирает гейт посадки, и пустое значение он судит отказом наравне с
		// отсутствием ключа.
		"own_rest_public_tls":   "true",
		"own_rest_internal_tls": "true",
	})
}

// TestBootPosture_SSLModeComesFromTheDSNThatReachesThePool — sslmode может жить
// прямо в raw-URL (composeDSN его НЕ перетирает).
func TestBootPosture_SSLModeComesFromTheDSNThatReachesThePool(t *testing.T) {
	var cfg config.Config
	cfg.AuthN.Mode = config.ModeProductionStrict
	cfg.Repository.Postgres.URL = "postgres://u:p@pg-iam:5432/kaname?sslmode=verify-ca"
	cfg.Repository.Postgres.SSLMode = ""
	cfg.AuthN.TrustedForwarderSANs = []string{"spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"}
	// Домен доверия — величина установки: без неё дескриптор не принимается,
	// потому что процесс, не назвавший домена, своим не признаёт никого.
	cfg.AuthN.TrustDomainName = "kacho.cloud"

	requireBootPostureFields(t, captureBootPosture(t, bootPosture(acceptedPosture(t, cfg), cfg, config.MTLSConfig{}, true, restFrontUp(), restFrontUp())), map[string]any{
		"auth_mode":  "production-strict",
		"db_sslmode": "verify-ca",
	})
}

// TestBootPosture_InsecureIsReportedHonestly — dev + plaintext-DB + листенеры без
// mTLS + не поднятый PDP-бэкенд (authz-Check) обязаны быть видны как есть.
func TestBootPosture_InsecureIsReportedHonestly(t *testing.T) {
	var cfg config.Config
	cfg.AuthN.Mode = config.ModeDev
	cfg.Repository.Postgres.URL = "postgres://u:p@pg-iam:5432/kaname"
	// Вне боевого режима несужённый круг законен, но ТОЛЬКО как явный опт-ин:
	// умолчанием его не получить (secure-by-default общей библиотеки).
	cfg.AuthN.TrustAnyForwarder = true
	// У ДОМЕНА опт-ина нет и быть не может, и это не пробел рядом с соседкой
	// выше: пустой круг ПОЗВОЛЯЕТ лишнее (доверять всякому предъявителю), а
	// необъявленный домен, наоборот, не признаёт никого. Опт-ин «поднимусь без
	// домена» означал бы согласие не работать, поэтому домен называется и здесь.
	cfg.AuthN.TrustDomainName = "kacho.cloud"

	requireBootPostureFields(t, captureBootPosture(t, bootPosture(acceptedPosture(t, cfg), cfg, config.MTLSConfig{}, false, ownRESTFront{}, ownRESTFront{})), map[string]any{
		"service":       "iam",
		"auth_mode":     "dev",
		"db_sslmode":    "disable",
		"public_mtls":   false,
		"internal_mtls": "false",
		"authz_check":   false,
		// Фронты профилем не объявлены — «поверхности нет», а не «открытый
		// текст»: путать эти два значило бы отчитываться о защите того, чего
		// не существует.
		"own_rest_public_tls":   "n/a",
		"own_rest_internal_tls": "n/a",
	})
}

// TestBootPosture_EmittedFromTheLiveBootPath — статический guard размещения:
// строка обязана эмититься ИЗ composition root'а реальным логгером, ПОСЛЕ
// listener-mTLS boot-guard'а и ДО подъёма листенеров.
//
// # СУДИТСЯ ПОРЯДОК ВЫЗОВОВ, А НЕ ПОЛОЖЕНИЕ ТЕКСТА В ФАЙЛЕ (задача #2514)
//
// Здесь сравнивались СМЕЩЕНИЯ ПОДСТРОК: страж находился по тексту своего
// отказа, и «после стража» означало «ниже по файлу». Предикат верен ровно пока
// условие живёт встроенной ветвью: вынесенное в именованного стража, оно
// уезжает в конец файла — вызов остаётся на прежнем месте потока, а текст
// отказа оказывается НИЖЕ строки посадки, и проба краснеет на изменении,
// которое порядка исполнения не трогало вовсе.
//
// Поэтому читается синтаксическое дерево: положение ВЫЗОВОВ внутри тела
// подъёма. Оно и есть предмет — «после» здесь про поток, а не про строки.
//
// Отсутствие любого из трёх вызовов — НАХОДКА, а не молчание: переименуют
// страж, и предикат по имени перестал бы находить предмет, оставаясь зелёным.
func TestBootPosture_EmittedFromTheLiveBootPath(t *testing.T) {
	src, err := os.ReadFile("serve.go")
	if err != nil {
		t.Fatalf("read composition root: %v", err)
	}
	if !strings.Contains(string(src), "bootPosture(posture, cfg, mtlsCfg,") {
		t.Fatal("posture line must be built from the accepted config + the per-listener mTLS config")
	}

	fset := token.NewFileSet()
	file, perr := parser.ParseFile(fset, "serve.go", src, 0)
	if perr != nil {
		t.Fatalf("composition root не разбирается: %v", perr)
	}

	// Искомые вызовы: страж транспорта gRPC-слушателей, эмиссия строки посадки
	// и построение слушателя. Каждый называется ОДИН раз.
	const (
		guardCall   = "requireGRPCListenerMTLS"
		postureCall = "LogBootPosture"
		serverCall  = "NewServer"
	)
	at := map[string]int{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "runServe" || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch f := call.Fun.(type) {
			case *ast.Ident:
				name = f.Name
			case *ast.SelectorExpr:
				name = f.Sel.Name
			}
			if name == "" {
				return true
			}
			if _, seen := at[name]; !seen {
				at[name] = fset.Position(call.Pos()).Offset
			}
			return true
		})
	}

	for _, want := range []string{guardCall, postureCall, serverCall} {
		if _, found := at[want]; !found {
			t.Fatalf("тело подъёма не зовёт %s — предикат размещения потерял предмет: "+
				"переименование сделало бы его зелёным, ничего не проверяя", want)
		}
	}
	if at[postureCall] < at[guardCall] {
		t.Fatal("posture line must be emitted AFTER the production listener-mTLS boot guard")
	}
	if at[postureCall] > at[serverCall] {
		t.Fatal("posture line must be emitted BEFORE the gRPC listeners are built")
	}
	t.Logf("осмотрено: порядок вызовов в теле подъёма — %s(%d) → %s(%d) → %s(%d)",
		guardCall, at[guardCall], postureCall, at[postureCall], serverCall, at[serverCall])
}
