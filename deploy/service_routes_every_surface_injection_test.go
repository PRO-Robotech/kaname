// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// service_routes_every_surface_injection_test.go — доказательство того, что гейт
// маршрутов СПОСОБЕН УПАСТЬ и падает ровно на своём предмете.
//
// # Почему инъекция чартом, а не подставным входом
//
// Предмет гейта — расхождение ОБЪЯВЛЕНИЙ чарта с тем, что поднимает процесс.
// Подставной вход доказывал бы о своей копии; здесь возвращается настоящий
// дефект — состояние чарта ДО починки — и гейт судит его тем же кодом, которым
// судит дерево.
//
// # Осей три, у каждой законный близнец
//
//  1. МАРШРУТ    порт снят у поднятой поверхности → красное с её именем;
//     поверхность не поднята этим входом → молчание (её нечем вести).
//  2. ПЕРИМЕТР   служебная дверь перенесена на публичный объект → красное,
//     называющее расширение периметра; она же на своём → молчание.
//  3. ПУСТОТА    рендер без объектов Service → отказ, а не «поверхностей 0».
//
// Третья ось обязательна: без неё «ноль находок» неотличимо от «ноль
// прочитанного».
package deploy_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// chartCopyWithService — копия чарта, у которой шаблон Service заменён данным.
func chartCopyWithService(t *testing.T, serviceTemplate string) string {
	t.Helper()
	dir := chartCopy(t)
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "templates", "service.yaml"), []byte(serviceTemplate), 0o600),
		"подмена шаблона Service")
	return dir
}

// chartCopy — копия чарта, которую инъекция вправе портить.
//
// Копия, а не правка дерева: гейт судит дерево, и правка на месте сделала бы
// вердикт свойством прогона, а не чарта, — плюс уронила бы соседние полосы,
// работающие в этой же копии.
func chartCopy(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	src, err := filepath.Abs(".")
	require.NoError(t, err)

	require.NoError(t, filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if d.Name() == "templates" || rel == "templates" {
				return os.MkdirAll(filepath.Join(dst, rel), 0o750)
			}
			if strings.Contains(rel, string(os.PathSeparator)) {
				return filepath.SkipDir
			}
			return filepath.SkipDir
		}
		if ext := filepath.Ext(rel); ext != ".yaml" && ext != ".tpl" {
			return nil
		}
		b, rerr := os.ReadFile(p) // #nosec G304 -- путь из дерева чарта
		if rerr != nil {
			return rerr
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
	}), "копия чарта")

	return dst
}

// patchInCopy заменяет подстроку в файле копии чарта, требуя, чтобы предмет
// замены там нашёлся: инъекция, ничего не изменившая, доказывает не способность
// гейта упасть, а собственную безвредность.
func patchInCopy(t *testing.T, dir, rel, old, new string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	b, err := os.ReadFile(path) // #nosec G304 -- путь из t.TempDir
	require.NoError(t, err, "чтение %s копии чарта", rel)
	require.Containsf(t, string(b), old,
		"инъекция не нашла, что портить, в %s: она бы прошла, ничего не изменив", rel)
	require.NoError(t, os.WriteFile(path, []byte(strings.Replace(string(b), old, new, 1)), 0o600),
		"запись %s копии чарта", rel)
}

// renderChartAt рендерит чарт по названному пути.
func renderChartAt(t *testing.T, dir string, valueFiles ...string) string {
	t.Helper()
	return renderChartAt2(t, dir, valueFiles)
}

// renderChartAt2 — тот же рендер с дополнительными `--set`.
func renderChartAt2(t *testing.T, dir string, valueFiles []string, sets ...string) string {
	t.Helper()
	out, err := renderChartAtAllowingFailure(t, dir, valueFiles, sets...)
	require.NoErrorf(t, err, "чарт копии не отрендерился — это «не выполнилось», а не вердикт\n%s", out)
	return out
}

// renderChartAtAllowingFailure отдаёт ОТКАЗ рендера вызывающему, а не роняет
// пробу: есть оси, на которых отказ установки и ЕСТЬ проверяемое свойство.
func renderChartAtAllowingFailure(t *testing.T, dir string, valueFiles []string, sets ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		if os.Getenv(renderGuardLaneEnv) != "" {
			t.Fatalf("helm не в PATH, а полоса рендера объявлена (%s задан): гейт обещал вердикт и дать его не может", renderGuardLaneEnv)
		}
		t.Skipf("helm не в PATH — вердикта НЕТ: третья категория, не зелёное и не красное (полоса %s)", renderGuardLaneEnv)
	}
	args := []string{"template", "kaname", dir, "--namespace", "kaname"}
	for _, f := range valueFiles {
		args = append(args, "-f", filepath.Join(dir, f))
	}
	for _, kv := range sets {
		args = append(args, "--set", kv)
	}
	out, err := exec.Command("helm", args...).CombinedOutput() // #nosec G204 -- фиксированный бинарь, путь из дерева/t.TempDir
	return string(out), err
}

// dropLineInCopy убирает из файла копии строку, начинающуюся с данной приставки.
func dropLineInCopy(t *testing.T, dir, rel, prefix string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	b, err := os.ReadFile(path) // #nosec G304 -- путь из t.TempDir
	require.NoError(t, err, "чтение %s копии чарта", rel)
	lines := strings.Split(string(b), "\n")
	kept := make([]string, 0, len(lines))
	dropped := 0
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), prefix) {
			dropped++
			continue
		}
		kept = append(kept, l)
	}
	require.NotZerof(t, dropped,
		"инъекция не нашла строки %q в %s: она бы прошла, ничего не изменив", prefix, rel)
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(kept, "\n")), 0o600), "запись %s", rel)
}

// serviceBeforeTheFix — шаблон Service, каким он был ДО починки: один объект,
// два порта из восьми поверхностей.
const serviceBeforeTheFix = `apiVersion: v1
kind: Service
metadata:
  name: {{ .Values.name }}
  namespace: {{ .Release.Namespace }}
spec:
  selector:
    app: {{ .Values.name }}
  ports:
    - name: grpc
      port: {{ .Values.ports.grpc }}
      targetPort: grpc
    - name: grpc-internal
      port: {{ .Values.ports.internalGrpc }}
      targetPort: grpc-internal
`

// serviceWithInternalOnPublic — служебная дверь перенесена на ПУБЛИЧНЫЙ объект.
// Порт есть у каждой поверхности; неверна ДОСЯГАЕМОСТЬ.
const serviceWithInternalOnPublic = `apiVersion: v1
kind: Service
metadata:
  name: {{ .Values.name }}
  namespace: {{ .Release.Namespace }}
spec:
  selector:
    app: {{ .Values.name }}
  ports:
    - name: grpc
      port: {{ .Values.ports.grpc }}
      targetPort: grpc
    - name: registry-token
      port: {{ include "kaname-svc.processDefaultPort" "registryToken" }}
      targetPort: registry-token
    - name: http-jwks
      port: {{ include "kaname-svc.processDefaultPort" "jwksProxy" }}
      targetPort: http-jwks
    {{- if .Values.apiServer.restEndpoint }}
    - name: http-rest
      port: {{ include "kaname-svc.surfacePort" .Values.apiServer.restEndpoint }}
      targetPort: http-rest
    {{- end }}
---
apiVersion: v1
kind: Service
metadata:
  name: {{ .Values.name }}-internal
  namespace: {{ .Release.Namespace }}
spec:
  selector:
    app: {{ .Values.name }}
  ports:
    - name: grpc-internal
      port: {{ .Values.ports.internalGrpc }}
      targetPort: grpc-internal
    - name: http-hooks
      port: {{ include "kaname-svc.processDefaultPort" "hooks" }}
      targetPort: http-hooks
    {{- if .Values.apiServer.internalRestEndpoint }}
    - name: http-rest-int
      port: {{ include "kaname-svc.surfacePort" .Values.apiServer.internalRestEndpoint }}
      targetPort: http-rest-int
    {{- end }}
`

// ── ось 1: маршрут ───────────────────────────────────────────────────────────

func TestSurfaceRouteCensusCanFail(t *testing.T) {
	roster := readSurfaceRoster(t)
	dir := chartCopyWithService(t, serviceBeforeTheFix)
	rendered := renderChartAt(t, dir, "values.yaml", "values.prod.yaml")

	raised, routed, findings := judgeSurfaceRoutes(t, roster, rendered)
	require.NotEmpty(t, findings,
		"гейт молчит на чарте, ведущем к двум поверхностям из восьми, — он не измеряет своего предмета")
	require.Equal(t, 8, raised, "этим входом поднимаются все восемь поверхностей")
	require.Equal(t, 2, routed, "до починки маршрут несли ровно две")

	joined := strings.Join(findings, "\n")
	for _, name := range []string{
		"выдача токенов", "зеркало публичных ключей", "вебхуки провайдера личности",
		"собственный публичный REST-фронт", "собственный внутренний REST-фронт",
	} {
		require.Containsf(t, joined, name, "находка обязана НАЗЫВАТЬ поверхность %q, а не только считать их", name)
	}
}

// ЗАКОННЫЙ БЛИЗНЕЦ: поверхность, которую этот вход НЕ ПОДНИМАЕТ, находкой не
// является — вести к ней нечем, и процесс говорит об этом сам.
func TestSurfaceRouteStaysSilentOnSurfacesThatAreNotRaised(t *testing.T) {
	roster := readSurfaceRoster(t)
	rendered := renderStandaloneChart(t, []string{"values.yaml", "values.dev.yaml"})

	raised, routed, findings := judgeSurfaceRoutes(t, roster, rendered)
	require.Empty(t, findings,
		"стендовый профиль не поднимает REST-фронтов, и молчание о них — верный вердикт, а не пропуск")
	require.Equal(t, 6, raised, "стендовый профиль поднимает шесть поверхностей")
	require.Equal(t, routed, raised, "и ведёт ко всем шести")
}

// ── ось 2: периметр ──────────────────────────────────────────────────────────

func TestSurfaceRouteCatchesAnInternalDoorOnThePublicObject(t *testing.T) {
	roster := readSurfaceRoster(t)
	dir := chartCopyWithService(t, serviceWithInternalOnPublic)
	rendered := renderChartAt(t, dir, "values.yaml", "values.prod.yaml")

	_, _, findings := judgeSurfaceRoutes(t, roster, rendered)
	require.NotEmpty(t, findings,
		"порт есть у каждой двери, и гейт, судящий только наличие порта, промолчал бы — "+
			"а служебная дверь стоит на объекте, тип которого оператор меняет, выводя наружу публичные")
	joined := strings.Join(findings, "\n")
	require.Contains(t, joined, "зеркало публичных ключей", "находка обязана назвать перенесённую поверхность")
	require.Contains(t, joined, "периметр", "находка обязана назвать, ЧЕМ это плохо, а не только что не сошлось")
	require.NotContains(t, joined, "вебхуки провайдера личности",
		"вебхуки остались на своём объекте — законный близнец обязан молчать")
}

// ── ось 3: пустота ───────────────────────────────────────────────────────────

func TestSurfaceRouteRefusesARenderWithoutRouteSources(t *testing.T) {
	dir := chartCopyWithService(t, "# ни одного объекта Service\n")
	rendered := renderChartAt(t, dir, "values.yaml", "values.prod.yaml")

	// Предпосылка читается ТЕМ ЖЕ кодом, которым её читает гейт.
	svcPorts, _ := renderedServicePorts(t, rendered)
	scrape := renderedScrapeDeclared(t, rendered)

	// Законный близнец: объявление сбора на месте, поэтому источник маршрутов
	// ЕСТЬ — предпосылка держится, и молчать она обязана.
	require.True(t, scrape.enabled, "объявление сбора этим входом рендерится")
	require.NoError(t, routeSourcesPresent(svcPorts, scrape),
		"объявление сбора — тоже источник маршрута; предпосылка обязана держаться на нём одном")

	// Инъекция: источников не осталось ни одного.
	err := routeSourcesPresent(map[string]map[string]bool{}, scrapeDecl{})
	require.Error(t, err,
		"рендер без портов Service и без объявления сбора обязан быть ОТКАЗОМ, "+
			"а не вердиктом «поверхностей 0, все покрыты»")
	require.Contains(t, err.Error(), "неотличимо",
		"отказ обязан называть, ЧЕМ пустой обход опасен, иначе его снимут как непонятный")
}
