// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelcompose_test

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	"github.com/PRO-Robotech/kaname/internal/modelrender"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// Здесь читаются реальные фикстуры доставки, а ожидаемый блок берётся из
// вшитого канона. Рендер не порождает себе ожидаемые байты. Проза notes.text
// участвует в побайтовом контракте, даже если каждая её строка начинается с #.
func editorialRegistryFixture(t *testing.T, path string) *manifest.Manifest {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("не прочитана закреплённая фикстура registry")
	}
	// Прежней фикстуре добавляем writes; собственный стенд уже объявляет оба блока.
	switch bytes.Count(raw, []byte("\n    writes:\n")) {
	case 0:
		raw, err = publicreadfixture.WithWrites(raw)
		if err != nil {
			t.Fatal("не подготовлена обычная доставка с записью owner")
		}
	case 2:
		// Читаем исходные байты без повторного добавления ключей YAML.
	default:
		t.Fatal("фикстура содержит неожиданный набор объявлений writes")
	}
	m, err := manifest.Load(raw)
	if err != nil {
		t.Fatal("обычный загрузчик отверг фикстуру registry")
	}
	if m.Module != "registry" || len(m.Resources) != 2 ||
		m.Resources[0].ObjectType != "registry_registry" || m.Resources[1].ObjectType != "registry_repository" {
		t.Fatal("фикстура не содержит ровно два исходных ресурса registry")
	}
	return m
}

func editorialRegistryAccept(t *testing.T, m *manifest.Manifest) {
	t.Helper()
	for _, r := range m.Resources {
		got, err := modelrender.RenderForCanon(r)
		if err != nil || !bytes.Equal(got, sc70CanonBlock(t, r.ObjectType)) {
			t.Fatal("рендер реальной фикстуры не равен каноническому блоку побайтово")
		}
	}
	got, rep, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	if err != nil || got != authzmodel.DSL || rep.ManifestsSeen != 1 || rep.ResourcesSeen != 2 ||
		!reflect.DeepEqual(rep.Reaffirmed, []string{"registry_registry", "registry_repository"}) ||
		len(rep.Composed) != 0 || len(rep.PriorEdition) != 0 {
		t.Fatal("обычная композиция не подтвердила оба блока без изменения канона")
	}
}

func TestEditorialRegistryContract_CanonCopies(t *testing.T) {
	for _, path := range []string{"../authzmodel/fga_model.fga", "../../proto/kaname/cloud/iam/v1/fga_model.fga"} {
		raw, err := os.ReadFile(path)
		if err != nil || string(raw) != authzmodel.DSL {
			t.Fatal("копия канона на диске не равна вшитому канону целиком")
		}
	}
}

func TestEditorialRegistryContract_DelegationFixture(t *testing.T) {
	editorialRegistryAccept(t, editorialRegistryFixture(t, "../manifest/testdata/registry.delegation-fixture.yaml"))
}

func TestEditorialRegistryContract_OwnStandFixture(t *testing.T) {
	editorialRegistryAccept(t, editorialRegistryFixture(t, "../../tests/authz-fixtures/registry-own-stand-fixture.yaml"))
}

func TestEditorialRegistryContract_LegacyEdition(t *testing.T) {
	// Существующий контроль сначала сверяет сырой рендер с историческими SHA.
	// Новый канон не должен переопределять закрепление прежней редакции.
	ms := sc70ControlPrior(t)
	for _, m := range ms {
		for _, r := range m.Resources {
			b, err := modelrender.RenderForCanon(r)
			if err != nil || !modelrender.IsPriorEdition(r.ObjectType, b) {
				t.Fatal("точный перевод прозы потерял закреплённую прежнюю редакцию")
			}
		}
	}
	got, rep, err := modelcompose.Compose(authzmodel.DSL, ms)
	if err != nil || got != authzmodel.DSL || rep.ResourcesSeen != 2 ||
		!reflect.DeepEqual(rep.PriorEdition, []string{"registry_registry", "registry_repository"}) ||
		len(rep.Reaffirmed) != 0 || len(rep.Composed) != 0 {
		t.Fatal("прежняя редакция не принята с неизменным действующим каноном")
	}
}

func editorialRegistryRejectNote(t *testing.T, path string) {
	t.Helper()
	m := editorialRegistryFixture(t, path)
	editorialRegistryAccept(t, m)
	for i := range m.Resources {
		if len(m.Resources[i].Notes) == 0 || m.Resources[i].Notes[0].Text == "" {
			t.Fatal("предпосылка контроля: у ресурса нет контрактного примечания")
		}
		before := m.Resources[i].Notes[0].Text
		m.Resources[i].Notes[0].Text = before + "# Неизвестная строка контрактной прозы.\n"
		got, _, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
		if err == nil || got != "" || !strings.Contains(err.Error(), "расходятся побайтово") {
			t.Fatal("неизвестная проза не отвергнута точным побайтовым судьёй")
		}
		m.Resources[i].Notes[0].Text = before
		editorialRegistryAccept(t, m)
	}
}

func TestEditorialRegistryContract_UnknownDelegationNote(t *testing.T) {
	editorialRegistryRejectNote(t, "../manifest/testdata/registry.delegation-fixture.yaml")
}

func TestEditorialRegistryContract_UnknownOwnStandNote(t *testing.T) {
	editorialRegistryRejectNote(t, "../../tests/authz-fixtures/registry-own-stand-fixture.yaml")
}

func editorialRegistryRejectAuthority(t *testing.T, path string) {
	t.Helper()
	m := editorialRegistryFixture(t, path)
	editorialRegistryAccept(t, m)
	for i := range m.Resources {
		owner := -1
		for j, r := range m.Resources[i].Relations {
			if r.Name == "owner" {
				if owner != -1 {
					t.Fatal("предпосылка контроля: повторное отношение owner")
				}
				owner = j
			}
		}
		if owner == -1 || m.Resources[i].Relations[owner].Definition != "[user, service_account]" {
			t.Fatal("предпосылка контроля: исходное отношение owner изменилось")
		}
		before := m.Resources[i].Relations[owner].Definition
		m.Resources[i].Relations[owner].Definition = "[user]"
		got, _, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
		if err == nil || got != "" || !strings.Contains(err.Error(), "расходятся побайтово") {
			t.Fatal("изменение права owner принято либо отказало до побайтового судьи")
		}
		m.Resources[i].Relations[owner].Definition = before
		editorialRegistryAccept(t, m)
	}
}

func TestEditorialRegistryContract_ChangedDelegationAuthority(t *testing.T) {
	editorialRegistryRejectAuthority(t, "../manifest/testdata/registry.delegation-fixture.yaml")
}

func TestEditorialRegistryContract_ChangedOwnStandAuthority(t *testing.T) {
	editorialRegistryRejectAuthority(t, "../../tests/authz-fixtures/registry-own-stand-fixture.yaml")
}
