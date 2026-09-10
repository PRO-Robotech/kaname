// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// module_seed_delivery_test.go — ДОСТАВКА манифестов модулей для проб, чей
// предмет — платформенное состояние базы (задача продукта #2452).
//
// # Зачем помощник появился
//
// Служебные учётки модулей платформы, их членства и выдачи заводила ПРИМЕНЁННАЯ
// МИГРАЦИЯ службы доступа, и пробы ниже спрашивали их у базы, поднятой одной лишь
// цепочкой миграций. Это перестало быть верным: миграция применяется ВЕЗДЕ,
// включая установку, где платформы нет вовсе, и заводила там пять личностей
// чужого продукта. Строки сняты
// (`20260909202745_module_identities_leave_the_baseline.sql`), а заводит их
// теперь применитель посева из ДОСТАВЛЕННЫХ манифестов.
//
// # Что помощник НЕ делает, и это несущее различие
//
// Он не подставляет пробам ожидаемые строки. Он воспроизводит ту же доставку и
// зовёт ТОТ ЖЕ применитель, что и композиционный корень, — то есть создаёт
// УСЛОВИЕ, в котором предмет проб существует. Второй, «тестовый», посев рядом с
// продуктовым разошёлся бы с ним молча, и пробы удостоверяли бы собственную
// фикстуру вместо продукта.
//
// # Посадка решает, есть ли у проб предмет вообще
//
// В самостоятельном клоне службы манифестов соседей нет BY CONSTRUCTION — они
// доезжают доставкой в рантайме, а не деревом сборки. Значит там личностей
// модулей платформы не существует, и это ВЕРНО, а не сломано. Такой прогон
// объявляется третьей категорией — «условие не создано», — а не зелёным и не
// красным: молчаливый зелёный здесь означал бы, что проба о платформе прошла на
// дереве без платформы.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/modulemanifests"
)

// applyPlatformModuleSeed приводит базу к состоянию, объявленному манифестами
// модулей дерева, и печатает перепись — ВСЕГДА, независимо от исхода.
//
// Перепись несущая: проба, прошедшая после применителя, который не записал НИ
// ОДНОЙ строки, утверждала бы о состоянии, которого никто не создавал.
func applyPlatformModuleSeed(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	wd, err := os.Getwd()
	require.NoError(t, err, "рабочий каталог не установлен: посадку назвать нечем")
	set, err := modulemanifests.Available(wd)
	require.NoError(t, err, "перечень манифестов не снят — условие НЕ СОЗДАНО, и вердикт пробы "+
		"был бы сказан ни о чём")

	if set.Posture != modulemanifests.PlatformTree {
		t.Skipf("условие не создано: %s. Личностей модулей платформы в этой посадке не "+
			"существует by construction — их манифесты доезжают ДОСТАВКОЙ, а не деревом "+
			"сборки, — поэтому у пробы нет предмета, а не отрицательный исход", set.Census())
	}

	manifests := make([]*manifest.Manifest, 0, len(set.Files))
	for _, file := range set.Files {
		// #nosec G304 -- путь получен обходом дерева ЭТОГО прогона, снаружи не приходит
		src, rerr := os.ReadFile(filepath.Join(set.Root, filepath.FromSlash(file)))
		require.NoErrorf(t, rerr, "манифест %s не прочитан", file)
		m, lerr := manifest.Load(src)
		require.NoErrorf(t, lerr, "манифест %s не разобран", file)
		manifests = append(manifests, m)
	}

	applier := moduleseed.NewApplier(kanamepg.NewModuleSeedWriteRepo(pool))
	census, err := applier.ApplyAll(ctx, manifests)
	t.Logf("доставка модулей платформы: %s; %s", set.Census(), census)
	require.NoError(t, err, "применитель посева отказал — предмет пробы не создан")

	declared, _ := census.Totals()
	require.NotZerof(t, declared,
		"доставленные манифесты не объявили НИ ОДНОЙ строки посева (манифестов %d): проба о "+
			"личностях модулей прошла бы на дереве, где их некому завести",
		census.Manifests)
}
