// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// docs_listener_address_injection_test.go — доказательство того, что ось адреса
// СПОСОБНА упасть, и того, что она молчит на законном близнеце.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОДИН ФАКТ ПРОТИВ БЛИЗНЕЦА
//
// Годный корень собран один раз; каждая проба меняет в нём РОВНО ОДИН факт —
// строку документации либо одно выражение шаблона. Инъекция вида «дописать ещё
// один объект Service» здесь не годится: новый объект менял бы и перепись, и
// принадлежность портов разом, и красное приходило бы от соседа.
// Контроль («всё верно — находок ноль») стоит первым.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОБЕ СТОРОНЫ ПОДМЕНЫ
//
// Ось стережёт не «внутренний порт на публичном имени», а ПОДМЕНУ ОБЪЕКТА, и
// проверяется это в обе стороны: внутренний порт на публичном имени и публичный
// порт на внутреннем. Односторонняя проба зеленела бы на дереве, где перепутали
// вторую половину.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦА ОСИ ТОЖЕ ДОКАЗЫВАЕТСЯ
//
// Порт, не выставленный ни одним объектом (`kaname:5432` — база вне чарта), и
// порт, чьё выражение разбору не поддаётся, находками НЕ являются. Обе границы
// объявлены в шапке гейта, и обе подаются входом: объявление без пробы
// неотличимо от слепоты.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// addressGoodValues — профиль: имя службы и два порта.
const addressGoodValues = `name: kaname
ports:
  grpc: 9090
  internalGrpc: 9091
`

// addressGoodTemplate — два объекта Service, порты разведены по досягаемости.
const addressGoodTemplate = `apiVersion: v1
kind: Service
metadata:
  name: {{ .Values.name }}
spec:
  ports:
    - name: grpc
      port: {{ .Values.ports.grpc }}
---
apiVersion: v1
kind: Service
metadata:
  name: {{ .Values.name }}-internal
spec:
  ports:
    - name: grpc-internal
      port: {{ .Values.ports.internalGrpc }}
`

// addressGoodDocs — руководство, называющее оба адреса верно.
const addressGoodDocs = "# Разбор\n\n" +
	"```bash\ngrpcurl kaname:9090 kaname.cloud.iam.v1.UserService/Get\n" +
	"grpcurl kaname-internal:9091 kaname.cloud.iam.v1.InternalClusterService/ListAdmins\n```\n"

// syntheticAddressRoot — корень: профиль, шаблон объектов и документация.
// Всякая проба ниже строит СВОЙ и меняет ровно один факт.
func syntheticAddressRoot(t *testing.T, values, template, docs string) string {
	t.Helper()

	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "deploy", "templates"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(root, chartValuesFile), []byte(values), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, chartServiceTemplate), []byte(template), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(root, docsDir), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(root, docsDir, "runbook.md"), []byte(docs), 0o600))
	return root
}

// requireAddressFinding — находка с названной подстрокой есть, и перепись непуста.
func requireAddressFinding(t *testing.T, root, want string) {
	t.Helper()
	census, findings, err := scanDocsListenerAddresses(root)
	require.NoError(t, err)
	require.NotZero(t, census.addressesOwned, "инъекция беспредметна: адресов на объявленный объект не распознано")

	var rendered []string
	for _, f := range findings {
		rendered = append(rendered, f.file+":"+itoa(f.line)+" "+f.host+":"+itoa(f.port)+" -> "+f.owner)
	}
	joined := strings.Join(rendered, "\n")
	require.Containsf(t, joined, want,
		"ось НЕ упала на внесённом дефекте — она вакуумна.\nнаходки:\n%s", joined)
}

// itoa — местное преобразование, чтобы проба не тянула форматирование ради числа.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// TestDocsListenerAddressInjection_ControlIsSilent — КОНТРОЛЬ: оба адреса верны,
// находок ноль. Без него всякое красное ниже могло бы приходить от соседа.
func TestDocsListenerAddressInjection_ControlIsSilent(t *testing.T) {
	t.Parallel()
	root := syntheticAddressRoot(t, addressGoodValues, addressGoodTemplate, addressGoodDocs)

	census, findings, err := scanDocsListenerAddresses(root)
	require.NoError(t, err)
	require.Equal(t, 2, census.servicesParsed, "разобраны оба объекта Service")
	require.Equal(t, 2, census.portsResolved, "резолвятся оба порта")
	require.Equal(t, 2, census.addressesOwned, "оба адреса распознаны как адреса объявленных объектов")
	require.Empty(t, findings, "на верном входе находок быть не должно")
}

// TestDocsListenerAddressInjection_InternalPortOnPublicName — ДЕФЕКТ, ради
// которого ось заведена: внутренний порт назван на публичном имени.
func TestDocsListenerAddressInjection_InternalPortOnPublicName(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(addressGoodDocs, "kaname-internal:9091", "kaname:9091", 1)
	require.NotEqual(t, addressGoodDocs, broken, "инъекция не внесена: вход не изменился")

	root := syntheticAddressRoot(t, addressGoodValues, addressGoodTemplate, broken)
	requireAddressFinding(t, root, "runbook.md:5 kaname:9091 -> kaname-internal")
}

// TestDocsListenerAddressInjection_PublicPortOnInternalName — ЗЕРКАЛО того же
// дефекта. Односторонняя ось зеленела бы на перепутанной второй половине.
func TestDocsListenerAddressInjection_PublicPortOnInternalName(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(addressGoodDocs, "kaname:9090", "kaname-internal:9090", 1)
	require.NotEqual(t, addressGoodDocs, broken, "инъекция не внесена: вход не изменился")

	root := syntheticAddressRoot(t, addressGoodValues, addressGoodTemplate, broken)
	requireAddressFinding(t, root, "runbook.md:4 kaname-internal:9090 -> kaname")
}

// TestDocsListenerAddressInjection_PortNoObjectExposesIsNotAFinding — ГРАНИЦА:
// порт, которого нет ни у одного объекта, находкой не объявляется. Он бывает
// адресом чужой службы или локальной переадресации, и различить это нечем.
func TestDocsListenerAddressInjection_PortNoObjectExposesIsNotAFinding(t *testing.T) {
	t.Parallel()
	docs := addressGoodDocs + "\n```bash\npsql -h kaname:5432\n```\n"

	root := syntheticAddressRoot(t, addressGoodValues, addressGoodTemplate, docs)
	census, findings, err := scanDocsListenerAddresses(root)
	require.NoError(t, err)
	require.Equal(t, 3, census.addressesOwned, "адрес распознан как адрес объявленного объекта")
	require.Empty(t, findings, "порт вне чарта предметом оси не является")
}

// TestDocsListenerAddressInjection_UnresolvedPortIsCountedNotInvented — ГРАНИЦА:
// неразобранное выражение порта учитывается ОТДЕЛЬНОЙ величиной переписи и не
// превращается в находку. Иначе «порт не выставлен» стало бы неотличимо от
// «порт не прочитан», и ось выдумывала бы подмену на каждом `include`.
func TestDocsListenerAddressInjection_UnresolvedPortIsCountedNotInvented(t *testing.T) {
	t.Parallel()
	template := strings.Replace(addressGoodTemplate,
		"port: {{ .Values.ports.internalGrpc }}",
		`port: {{ include "kaname-svc.processDefaultPort" "hooks" }}`, 1)
	require.NotEqual(t, addressGoodTemplate, template, "инъекция не внесена: вход не изменился")

	root := syntheticAddressRoot(t, addressGoodValues, template, addressGoodDocs)
	census, findings, err := scanDocsListenerAddresses(root)
	require.NoError(t, err)
	require.Equal(t, 1, census.portsResolved, "резолвится один порт из двух")
	require.Equal(t, 1, census.portsUnresolved, "неразобранное выражение сосчитано отдельно")
	require.Empty(t, findings, "неразобранный порт находкой не является")
}

// TestDocsListenerAddressInjection_EmptyDocsTreeIsVoidNotGreen — ПУСТОЙ ОБХОД:
// документации нет, адресов не распознано ни одного. Главный тест на такой
// переписи падает своим стражем — «ноль находок» отличимо от «ноль прочитанного».
func TestDocsListenerAddressInjection_EmptyDocsTreeIsVoidNotGreen(t *testing.T) {
	t.Parallel()
	root := syntheticAddressRoot(t, addressGoodValues, addressGoodTemplate, "")

	census, findings, err := scanDocsListenerAddresses(root)
	require.NoError(t, err)
	require.Empty(t, findings)
	require.Zero(t, census.addressesOwned,
		"на пустой документации адресов быть не может — на этой переписи главный тест обязан падать стражем")
}
