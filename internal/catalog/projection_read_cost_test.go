// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog_test

// projection_read_cost_test.go — ЦЕНА ЧТЕНИЯ после перевода переходника имени
// типа на живые строки (kacho#1816).
//
// # Почему замер именно здесь, а не прибором применения
//
// Прибор `catalog_apply_cost_integration_test.go` меряет ПРИМЕНЕНИЕ манифеста;
// эта правка его не трогает. Тронут путь ЧТЕНИЯ — раскрытие проекции, лежащее на
// пути КАЖДОГО создания и правки роли, — и цена там дороже, чем на применении.
//
// # Что сравнивается
//
// Ровно ОДНА подменённая операция: переходник «точечное имя → имя типа модели».
// Было — поиск в словаре, порождённом сборкой (`authzmap.FGAObjectType`); стало —
// поиск в словаре снимка (`Facts.FGAObjectType`). Всё остальное в раскрытии не
// менялось, поэтому сравнение двух переходников на ОДНОМ входе и есть цена
// правки, а не её оценка.
//
// Сверх того замеряется сборка снимка: новый словарь строится один раз на
// снимок, и эта величина — плата за период обновления, а не за запрос.

import (
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// benchDotted — точечные имена ВСЕХ посеянных ресурсов: переходник спрашивают по
// каждому, а не по одному удачному. Выводятся из перечня посева, а не выписаны.
func benchDotted() []string {
	rows := seed.LiteralRows()
	out := make([]string, 0, len(rows.Resources))
	for _, r := range rows.Resources {
		out = append(out, r.Module+"."+r.Resource)
	}
	return out
}

// BenchmarkTranslatorFromRows — переходник ПОСЛЕ правки (словарь снимка).
func BenchmarkTranslatorFromRows(b *testing.B) {
	f, err := catalog.NewFacts(seed.LiteralRows())
	if err != nil {
		b.Fatalf("снимок: %v", err)
	}
	keys := benchDotted()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, k := range keys {
			if _, ok := f.FGAObjectType(k); !ok {
				b.Fatalf("переходник не знает %q — замер беспредметен", k)
			}
		}
	}
}

// BenchmarkTranslatorFromBuildTable — переходник ДО правки (словарь сборки).
// Оставлен ЗАКОННЫМ БЛИЗНЕЦОМ замера: без него число выше не с чем сравнить, и
// «цена не выросла» было бы утверждением без предиката.
func BenchmarkTranslatorFromBuildTable(b *testing.B) {
	keys := benchDotted()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, k := range keys {
			if _, ok := authzmap.FGAObjectType(k); !ok {
				b.Fatalf("переходник не знает %q — замер беспредметен", k)
			}
		}
	}
}

// BenchmarkRoleVerbsFromSelectors — раскрытие целиком, на подстановке `*` по
// всем посеянным типам: это то, что исполняется на создании и правке роли.
func BenchmarkRoleVerbsFromSelectors(b *testing.B) {
	f, err := catalog.NewFacts(seed.LiteralRows())
	if err != nil {
		b.Fatalf("снимок: %v", err)
	}
	sel := []domain.RuleSelector{{ObjectTypes: benchDotted(), Verbs: []string{"*"}}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(f.RoleVerbsFromSelectors(sel)) == 0 {
			b.Fatal("пар ноль — замер беспредметен")
		}
	}
}

// BenchmarkNewFacts — сборка снимка. Новый словарь строится ЗДЕСЬ, один раз на
// снимок: эта величина платится раз в период обновления, а не запросом.
func BenchmarkNewFacts(b *testing.B) {
	rows := seed.LiteralRows()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := catalog.NewFacts(rows); err != nil {
			b.Fatalf("снимок: %v", err)
		}
	}
}
