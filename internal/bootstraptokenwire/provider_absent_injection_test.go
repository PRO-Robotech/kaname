// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_absent_injection_test.go — доказательство, что разбор дороги к
// поставщику СПОСОБЕН упасть и способен смолчать.
//
// Вход СИНТЕТИЧЕСКИЙ, и это не удобство. Доказательство, опирающееся на живой
// файл дерева, истекает вместе с ним: соседние подфазы переводят на свою
// чеканку остальные контуры, и «законный близнец», выбранный из них, исчезнет —
// унеся с собой свидетельство, что гейт не срабатывает вхолостую.
package bootstraptokenwire

import (
	"os"
	"path/filepath"
	"testing"
)

// writeSyntheticPkg кладёт в свежий каталог один файл Go с заданными импортами.
func writeSyntheticPkg(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "synthetic.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("синтетический источник не записан: %v", err)
	}
	return dir
}

// TestProviderRoadDetector_FindsTheRoad — дефект, возвращённый синтетикой,
// НАХОДИТСЯ и НАЗЫВАЕТСЯ координатой.
func TestProviderRoadDetector_FindsTheRoad(t *testing.T) {
	dir := writeSyntheticPkg(t, `package synthetic

import (
	"context"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
)

func provision(ctx context.Context, a *clients.HydraAdminClient) {}
`)
	found, read := providerImportsIn(t, dir)
	if read != 1 {
		t.Fatalf("прочитано файлов %d, ожидался 1 — инъекция не дошла до разбора", read)
	}
	if len(found) != 1 {
		t.Fatalf("дорога к поставщику не найдена: находок %d — гейт не способен упасть", len(found))
	}
}

// TestProviderRoadDetector_SilentOnALegitimateTwin — та же форма без дороги к
// поставщику молчит. Без этой половины гейт ловил бы форму, а не существо, и
// первый же ложный срабат его отключил бы.
func TestProviderRoadDetector_SilentOnALegitimateTwin(t *testing.T) {
	dir := writeSyntheticPkg(t, `package synthetic

import (
	"context"

	"github.com/PRO-Robotech/kacho-iam/internal/tokensigner"
)

func mint(ctx context.Context, s *tokensigner.Signer) {}
`)
	found, read := providerImportsIn(t, dir)
	if read != 1 {
		t.Fatalf("прочитано файлов %d, ожидался 1", read)
	}
	if len(found) != 0 {
		t.Fatalf("законный близнец объявлен находкой: %v", found)
	}
}

// TestProviderRoadDetector_IgnoresTestTrees — подставной клиент в пробе процессом
// не является. Без этой границы перевод контура нельзя было бы доказать: пробы
// прежней полосы остаются в дереве до тех пор, пока их предмет не снят.
func TestProviderRoadDetector_IgnoresTestTrees(t *testing.T) {
	dir := t.TempDir()
	body := `package synthetic

import "github.com/PRO-Robotech/kacho-iam/internal/clients"

var _ = clients.JWK{}
`
	if err := os.WriteFile(filepath.Join(dir, "synthetic_test.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("синтетический источник не записан: %v", err)
	}
	found, read := providerImportsIn(t, dir)
	if read != 0 || len(found) != 0 {
		t.Fatalf("тестовый файл попал в разбор: прочитано %d, находок %d", read, len(found))
	}
}
