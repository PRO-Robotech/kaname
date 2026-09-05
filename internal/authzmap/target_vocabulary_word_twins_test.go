// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap

// target_vocabulary_word_twins_test.go — пообъектная цель не принимается по
// написанию, отличающемуся СЛОВОМ, а не регистром.
//
// # Чей это предмет и почему гейт живёт здесь
//
// Утверждение — о `domain.ValidTargetType`, а производитель входа — о ПОРОЖДЁННОЙ
// таблице `objectTypes` (словарь каталога → словарь модели, выводится из
// манифестов модулей). Разные пакеты, и Go разрешает их встретиться только тут:
// `authzmap` импортирует `domain`, обратное — цикл. Гейт ставится к
// ПРОИЗВОДИТЕЛЮ, а не к потребителю.
//
// # Что этот гейт ловит сверх соседнего
//
// В `domain` уже стоит гейт, выводящий близнецов ПЕРЕПИСЫВАНИЕМ РЕГИСТРА живой
// ленты (`vpc.routeTable` → `vpc.route_table`). До написаний, отличающихся
// СЛОВОМ, он не достаёт by construction:
//
//	лента (каталог)          модель            близнец слова
//	loadbalancer.listeners   nlb_listener      nlb.listener
//	registry.registries      registry_registry registry.registry
//	storage.images           storage_image     storage.image
//
// Модуль назван другим словом (`loadbalancer` против `nlb`), а ресурс — другим
// числом. Такое написание выглядит законным, принимается, хранится и
// материализуется — и не совпадает НИ С ОДНИМ объектом: `Contains` сверяет
// точечную строку цели с точечной строкой ленты дословно.
//
// # Откуда брался вход РАНЬШЕ
//
// Из `domain.validResourceTypes` — рукописной карты, которая была вторым,
// разошедшимся объявлением вокабуляра ЯКОРЯ. Карта снята вместе со своим
// предметом (#1092), и гейт, ходивший в неё, падал бы не находкой, а
// невозможностью отработать (#1944). Производитель заменён на живой: порождённую
// таблицу, которая перечисляет ровно те типы, что объявлены манифестами.

// # ПРЕДПОСЫЛКА ГЕЙТА, названная им самим
//
// Гейт — регрессионный замок против ВЫВОДА написания, а не против промаха
// таблицы. Пока `ValidTargetType` есть прямой поиск в той же карте, из ключей
// которой берётся лента, он упасть НЕ МОЖЕТ by construction: близнец в ленте
// отсутствует, значит предикат на нём ложен всегда. Это сказано вслух, чтобы
// зелёное не читалось шире сделанного.
//
// Предмет появляется в тот день, когда предикат снова начнёт ВЫВОДИТЬ имя из
// имени, — а он это уже делал (разбор у `ValidTargetType`). Доказано инъекцией:
// возврат вывода по словарю модели даёт находку с именами
// `nlb.listener registry.registry storage.image`, и соседний гейт близнецов по
// РЕГИСТРУ (domain) не ловит из них НИ ОДНОГО — ради этой разницы гейт и заведён.

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

func TestTargetTypeRegistryRefusesModelSpellingsOfLiveTypes(t *testing.T) {
	require.NotEmpty(t, objectTypes, "objectTypes пуста — обход беспредметен")

	feed := domain.AllMaterializableTypes()
	require.NotEmpty(t, feed, "AllMaterializableTypes() пуста — гейт не утверждал бы ничего")
	live := make(map[string]bool, len(feed))
	for _, dotted := range feed {
		live[dotted] = true
	}

	// Близнец: имя МОДЕЛИ, прочитанное как точечное (первое подчёркивание —
	// разделитель модуля). Ярусные предки (`account`, `project`) подчёркивания не
	// несут и близнеца не дают вовсе.
	var twins, accepted []string
	for _, model := range objectTypes {
		i := strings.IndexByte(model, '_')
		if i <= 0 || i == len(model)-1 {
			continue
		}
		twin := model[:i] + "." + model[i+1:]
		if live[twin] {
			continue // это и есть живое написание — им владеет положительная половина
		}
		twins = append(twins, twin)
		if domain.ValidTargetType(twin) {
			accepted = append(accepted, twin)
		}
	}
	sort.Strings(twins)
	sort.Strings(accepted)

	require.NotEmptyf(t, twins,
		"из %d записей таблицы не выведено ни одного близнеца, отличного от живого написания — "+
			"вокабуляр стал односложным, и у гейта не осталось предмета", len(objectTypes))
	t.Logf("перепись: записей таблицы %d, типов ленты %d, выведено близнецов %d, принято %d",
		len(objectTypes), len(feed), len(twins), len(accepted))

	require.Emptyf(t, accepted,
		"%d написаний модели приняты как пообъектная цель, хотя лента отдаёт другое написание; "+
			"такая привязка создаётся, хранится, материализуется и не совпадает ни с одним объектом: %v",
		len(accepted), accepted)

	// Контроль, что предикат не «ложь на всё»: живое написание обязано приниматься.
	require.Truef(t, domain.ValidTargetType(feed[0]),
		"ValidTargetType(%q) ложно — отрицание выше ничего не доказывает", feed[0])
}
