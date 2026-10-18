// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// role_description_ceiling_test.go — загрузчик судит ВЕРХНИЙ предел назначения
// роли тем же судьёй и в тех же единицах (знаки), что применитель ролей
// (kaname#867).
//
// Применитель на старте отвергает назначение длиннее предела доменного типа, а
// загрузчик такой манифест принимал: доставка грузилась и не применялась, и
// отказ приходил на старте службы, а не автору манифеста с путём поля.

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

func TestRoleDescriptionCeilingIsJudgedByTheLoaderInCharacters(t *testing.T) {
	base := "apiVersion: iam/v1\nmodule: iam\nroles:\n" +
		"  - id: iam.role.edit\n    description: %s\n" +
		"    tier: {tierType: iam.cluster, tierId: cluster_root}\n" +
		"    rules:\n      - {module: iam, resources: [role], classes: [get, list, update]}\n"
	load := func(desc string) error {
		_, err := manifest.Load([]byte(strings.Replace(base, "%s", `"`+desc+`"`, 1)))
		return err
	}

	// Близнецы: граница и кириллица ниже границы. Кириллическое назначение в
	// 200 знаков — 400 байт: судья в байтах отверг бы его, в знаках — нет.
	for _, ok := range []string{
		strings.Repeat("a", domain.DescriptionMax),
		strings.Repeat("ж", domain.DescriptionMax),
		strings.Repeat("ж", 200),
	} {
		if err := load(ok); err != nil {
			t.Errorf("назначение %d знаков (%d байт) отвергнуто: %v",
				utf8.RuneCountInString(ok), len(ok), err)
		}
	}

	// Отрицательные: на знак выше предела в обеих единицах.
	for _, long := range []string{
		strings.Repeat("a", domain.DescriptionMax+1),
		strings.Repeat("ж", domain.DescriptionMax+1),
	} {
		err := load(long)
		if err == nil {
			t.Fatalf("назначение %d знаков принято загрузчиком, хотя применитель его отвергнет",
				utf8.RuneCountInString(long))
		}
		if !errors.Is(err, manifest.ErrRoleDescriptionTooLong) {
			t.Errorf("отказ не отнесён к своей причине: %v", err)
		}
		if !strings.Contains(err.Error(), "roles[0].description") {
			t.Errorf("отказ не называет путь поля: %v", err)
		}
		// Судья — доменный тип, и его суждение совпадает с суждением загрузчика.
		if domain.Description(long).Validate() == nil {
			t.Errorf("предпосылка: доменный тип принял %d знаков", utf8.RuneCountInString(long))
		}
	}
}
