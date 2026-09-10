// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_anchor_is_its_own_coordinate_injection_test.go — доказательство того,
// что соседний гейт СПОСОБЕН упасть и падает на своём предмете.
//
// Инъекция зовёт ТО ЖЕ ТЕЛО (`judgeProviderAnchorCoordinates`) и ТЕ ЖЕ
// распознаватели (`clientCircles`, `declaredAnchor`, `splitAnchorList`), что
// исполняются на дереве. Второго тела здесь нет намеренно: разойдясь, они
// разошлись бы молча, и доказательство относилось бы к другому коду.
//
// ПОДМЕНЯЕТСЯ ОДИН ФАКТ на случай, и у каждого отрицания рядом стоит законный
// близнец: без него «краснеет всегда» неотличимо от работы.
package deploy_test

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// anchorStack разбирает синтетический стек. Форма — та же, что у профиля чарта:
// служба стоит в КОРНЕ документа, поэтому приставки нет.
func anchorStack(t *testing.T, body string) map[string]any {
	t.Helper()
	var tree map[string]any
	if err := yaml.Unmarshal([]byte(body), &tree); err != nil {
		t.Fatalf("синтетика не разбирается: %v", err)
	}
	return tree
}

// separateCoordinates — КОНТРОЛЬ: якорь поставщика назван своей координатой,
// круги слушателей — своей. Именно это и объявляет боевой профиль чарта.
const separateCoordinates = `
authMode: production-strict
env:
  KANAME_PUBLIC_SERVER_MTLS_CLIENTCAFILES: /etc/kaname/tls/server/ca.crt
  KANAME_INTERNAL_SERVER_MTLS_CLIENTCAFILES: /etc/kaname/tls/server/ca.crt
  KANAME_HYDRA_ADMIN_CA_FILE: /etc/kaname/tls/provider/ca.crt
  KANAME_HYDRA_JWKS_CA_FILE: /etc/kaname/tls/provider/ca.crt
  KANAME_HYDRA_TOKEN_CA_FILE: /etc/kaname/tls/provider/ca.crt
`

func TestProviderAnchorInjection_SeparateCoordinatesAreSilent(t *testing.T) {
	findings, circles, anchors := judgeProviderAnchorCoordinates(
		"synthetic", anchorStack(t, separateCoordinates), nil)
	if len(findings) != 0 {
		t.Fatalf("гейт покраснел на разведённых координатах: %v", findings)
	}
	// Предпосылка КОНТРОЛЯ: он читал предмет, а не молчал на пустоте. Без этой
	// половины зелёное контроля означало бы «распознаватель ослеп».
	if circles == 0 || anchors == 0 {
		t.Fatalf("контроль прочитал ноль: кругов %d, якорей %d — его молчание ничего не значит", circles, anchors)
	}
}

func TestProviderAnchorInjection_SharedCoordinateIsAFinding(t *testing.T) {
	// ИНЪЕКЦИЯ, ОДИН ФАКТ против контроля: якорь поставщика переведён на
	// координату круга клиентских листов. Это и есть состояние до фикса #2487.
	injected := strings.Replace(separateCoordinates,
		"KANAME_HYDRA_ADMIN_CA_FILE: /etc/kaname/tls/provider/ca.crt",
		"KANAME_HYDRA_ADMIN_CA_FILE: /etc/kaname/tls/server/ca.crt", 1)
	findings, _, _ := judgeProviderAnchorCoordinates("synthetic", anchorStack(t, injected), nil)
	if len(findings) != 1 {
		t.Fatalf("склейка координат не найдена (находок %d): %v", len(findings), findings)
	}
	// Находка обязана НАЗЫВАТЬ координату и слушателей: находка, называющая
	// симптом, посылает читателя искать не там.
	if !strings.Contains(findings[0], "/etc/kaname/tls/server/ca.crt") ||
		!strings.Contains(findings[0], "PUBLIC_SERVER") ||
		!strings.Contains(findings[0], "admin API") {
		t.Fatalf("находка не называет ни координаты, ни слушателей, ни хопа: %s", findings[0])
	}
}

// TestProviderAnchorInjection_CirclesMaySharedAmongThemselves — ЗАКОННЫЙ
// БЛИЗНЕЦ: круги слушателей делят координату между собой, и это НЕ находка.
//
// Без этой пробы гейт ловил бы форму («две ручки называют один путь»), а не
// существо, и первый же верный профиль его бы отключил: у установки один
// внутренний центр, и все её слушатели опираются на один якорь по решению
// оператора.
func TestProviderAnchorInjection_CirclesMayShareAmongThemselves(t *testing.T) {
	shared := `
authMode: production-strict
env:
  KANAME_PUBLIC_SERVER_MTLS_CLIENTCAFILES: /etc/kaname/tls/server/ca.crt
  KANAME_INTERNAL_SERVER_MTLS_CLIENTCAFILES: /etc/kaname/tls/server/ca.crt
  KANAME_REST_SERVER_MTLS_CLIENTCAFILES: /etc/kaname/tls/server/ca.crt
  KANAME_HYDRA_ADMIN_CA_FILE: /etc/kaname/tls/provider/ca.crt
`
	findings, circles, _ := judgeProviderAnchorCoordinates("synthetic", anchorStack(t, shared), nil)
	if len(findings) != 0 {
		t.Fatalf("общий якорь слушателей между собой сосчитан находкой: %v", findings)
	}
	if circles != 3 {
		t.Fatalf("кругов прочитано %d, а объявлено 3 — распознаватель не видит части предмета", circles)
	}
}

// TestProviderAnchorInjection_ClashHiddenInAListIsFound — склейка, спрятанная
// в ПЕРЕЧНЕ из двух путей.
//
// Обе стороны принимают перечень через запятую, поэтому сравнение обязано быть
// поэлементным: гейт, сверяющий значения целиком, промолчал бы здесь — и
// промолчал бы ровно на той форме, которой склейку внесут незамеченной.
func TestProviderAnchorInjection_ClashHiddenInAListIsFound(t *testing.T) {
	inList := `
authMode: production-strict
env:
  KANAME_PUBLIC_SERVER_MTLS_CLIENTCAFILES: /etc/kaname/tls/server/ca.crt
  KANAME_HYDRA_ADMIN_CA_FILE: /etc/kaname/tls/provider/ca.crt,/etc/kaname/tls/server/ca.crt
`
	findings, _, _ := judgeProviderAnchorCoordinates("synthetic", anchorStack(t, inList), nil)
	if len(findings) != 1 {
		t.Fatalf("склейка внутри перечня не найдена (находок %d): %v", len(findings), findings)
	}
}

// TestProviderAnchorInjection_EmptyStackReadsNothing — предпосылка обхода:
// на стеке без карты `env` гейт читает НОЛЬ кругов, и вызывающий обязан на этом
// упасть, а не отчитаться чистым.
func TestProviderAnchorInjection_EmptyStackReadsNothing(t *testing.T) {
	findings, circles, anchors := judgeProviderAnchorCoordinates(
		"synthetic", anchorStack(t, "authMode: production-strict\n"), nil)
	if len(findings) != 0 || circles != 0 || anchors != 0 {
		t.Fatalf("пустой стек дал находки/кругов/якорей: %v / %d / %d", findings, circles, anchors)
	}
}
