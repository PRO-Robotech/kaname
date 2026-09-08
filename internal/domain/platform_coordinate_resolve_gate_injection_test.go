// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_coordinate_resolve_gate_injection_test.go — гейт СПОСОБЕН упасть и
// СПОСОБЕН смолчать.
//
// Инъекция идёт по СИНТЕТИЧЕСКИМ исходникам, а не по настоящему дереву: вернуть
// дефект в дерево значило бы править файл, чей вердикт этим же прогоном и
// читается. У каждого случая-находки есть ЗАКОННЫЙ БЛИЗНЕЦ, отличающийся ровно
// одним фактом, — иначе неизвестно, от чего пришло красное.
package domain_test

import (
	"strings"
	"testing"
)

// resolveFixture — минимальный исходник Go: гейт разбирает синтаксическое
// дерево, поэтому фикстура обязана быть разбираемой, а не похожей на код.
func resolveFixture(body string) string {
	return "package p\n\nimport (\n\t\"path/filepath\"\n\t\"os\"\n)\n\n" +
		"var _ = os.ReadFile\nvar _ = filepath.Join\n\n" + body
}

func TestPlatformCoordinateResolveGate_CanFailAndStaysSilent(t *testing.T) {
	cases := []struct {
		name         string
		body         string
		wantFinding  string
		wantCoords   int
		wantResolves int
		wantAscents  int
		why          string
	}{
		{
			name: "форма дефекта #2160: координата плюс свой подъём, детектора нет",
			body: `
func root() string {
	dir, _ := os.Getwd()
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "proto/kaname/cloud/iam/v1/role.proto")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	return ""
}`,
			wantFinding:  "предпосылку назначает не детектор посадки",
			wantCoords:   1,
			wantResolves: 0,
			wantAscents:  1,
			why:          "ровно то, чем три пробы задачи читали контракт до правки",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: та же координата через детектор посадки",
			body: `
func root(t *testingT) string {
	return platformtree.RequirePath(t, "proto/kaname/cloud/iam/v1/role.proto")
}

type testingT struct{}`,
			wantCoords:   1,
			wantResolves: 1,
			wantAscents:  0,
			why:          "один факт против предыдущего случая — кто назначает предпосылку",
		},
		{
			name: "координата через детектор, а подъём РЯДОМ остался",
			body: `
func root(t *testingT) string {
	base := platformtree.RequirePath(t, "proto/kaname/cloud/iam/v1/role.proto")
	dir := base
	for i := 0; i < 3; i++ {
		dir = filepath.Dir(dir)
	}
	return dir
}

type testingT struct{}`,
			wantFinding:  "исход назначает НАЛИЧИЕ ФАЙЛА",
			wantCoords:   1,
			wantResolves: 1,
			wantAscents:  1,
			why:          "один факт против близнеца выше — добавлен подъём; резолв не искупает его",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: подъём БЕЗ координаты от корня платформы",
			body: `
func moduleRoot() string {
	dir, _ := os.Getwd()
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	return ""
}`,
			wantCoords:  0,
			wantAscents: 1,
			why:         "подъём сам по себе законен: о посадке он ничего не утверждает",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: filepath.Dir ВНЕ цикла рядом с координатой",
			body: `
func dirOf(t *testingT) string {
	return filepath.Dir(platformtree.RequirePath(t, "proto/kaname/cloud/iam/v1/role.proto"))
}

type testingT struct{}`,
			wantCoords:   1,
			wantResolves: 1,
			wantAscents:  0,
			why:          "одиночное взятие каталога подъёмом не является — иначе гейт краснел бы на верном коде",
		},
		{
			name: "вторая законная форма координаты: filepath.Join по сегментам",
			body: `
var rel = filepath.Join("proto", "kaname", "cloud", "iam", "v1", "role.proto")`,
			wantFinding:  "резолвов через platformtree 0",
			wantCoords:   1,
			wantResolves: 0,
			wantAscents:  0,
			why:          "именно этой формой координата была записана до правки — не знай гейт её, дефект остался бы невидим",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: filepath.Join по сегменту, который координатой не является",
			body: `
var rel = filepath.Join("docs", "content", "api", "role.mdx")`,
			wantCoords: 0,
			why:        "один факт против предыдущего — первый сегмент не из корня платформы",
		},
		{
			name: "гейт читает ИСПОЛНЯЕМУЮ часть: координата в комментарии не координата",
			body: `
// Здесь названа координата "proto/kaname/cloud/iam/v1/role.proto" — но она
// стоит в объяснении, а не в коде.
func nothing() {}`,
			wantCoords: 0,
			why:        "проверка по подстроке краснела бы на собственном объяснении гейта",
		},
		{
			name:       "голое имя каталога координатой не является",
			body:       "\nvar seg = \"deploy\"\n",
			wantCoords: 0,
			why:        "без разделителя это слово, а не путь от корня платформы",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings, census, err := auditPlatformCoordinateResolve(
				map[string]string{"fixture.go": resolveFixture(c.body)})
			if err != nil {
				t.Fatalf("разбор не отработал: %v", err)
			}
			t.Logf("перепись: %s", census)

			if census.Coords != c.wantCoords {
				t.Errorf("координат распознано %d, хотел %d (%s)", census.Coords, c.wantCoords, c.why)
			}
			if census.Resolves != c.wantResolves {
				t.Errorf("резолвов распознано %d, хотел %d", census.Resolves, c.wantResolves)
			}
			if census.Ascents != c.wantAscents {
				t.Errorf("подъёмов распознано %d, хотел %d", census.Ascents, c.wantAscents)
			}

			joined := strings.Join(findings, "\n")
			if c.wantFinding == "" {
				if len(findings) != 0 {
					t.Errorf("гейт краснеет на законном исходнике (%s):\n%s", c.why, joined)
				}
				return
			}
			if !strings.Contains(joined, c.wantFinding) {
				t.Errorf("находка не названа (%s).\nхотел подстроку: %q\nполучил:\n%s",
					c.why, c.wantFinding, joined)
			}
		})
	}

	t.Logf("перепись инъекции: случаев %d", len(cases))
}

// TestPlatformCoordinateResolveGate_UnparsableSourceIsNotAVerdict — неразбираемый
// исходник даёт ОТКАЗ РАЗБОРА, а не «находок ноль».
//
// Без этого случая гейт, споткнувшийся о разбор, печатал бы зелёное — то есть
// «ноль прочитанного» под видом согласия.
func TestPlatformCoordinateResolveGate_UnparsableSourceIsNotAVerdict(t *testing.T) {
	_, _, err := auditPlatformCoordinateResolve(
		map[string]string{"broken.go": "package p\n\nfunc ( {"})
	if err == nil {
		t.Fatal("неразбираемый исходник принят за прочитанный — вердикт был бы беспредметным")
	}
	t.Logf("отказ разбора, как и должно: %v", err)
}

// TestPlatformCoordinateResolveGate_EmptyWalkIsCountedAsZero — пустой вход даёт
// нулевую перепись, и именно она отличает «ноль находок» от «ноль прочитанного».
func TestPlatformCoordinateResolveGate_EmptyWalkIsCountedAsZero(t *testing.T) {
	findings, census, err := auditPlatformCoordinateResolve(map[string]string{})
	if err != nil {
		t.Fatalf("разбор не отработал: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("находки на пустом входе: %v", findings)
	}
	if census.Files != 0 {
		t.Fatalf("файлов прочитано %d на пустом входе — перепись лжёт", census.Files)
	}
	t.Logf("перепись: %s — премиса `Files == 0` в пробе дерева роняет прогон", census)
}
