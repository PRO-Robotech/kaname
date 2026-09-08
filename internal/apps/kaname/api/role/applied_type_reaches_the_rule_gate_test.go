// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

// applied_type_reaches_the_rule_gate_test.go — ПЕРВОЕ звено цепи «клиент завёл
// тип манифестом → получил права» (kacho#1993, эпик #1027 DoD п. 1).
//
// # Что утверждается и почему именно ЗДЕСЬ
//
// Гейт грантуемого токена (`validateRuleCatalog`) закрывает сегмент РЕСУРСА
// авторского правила и стоит СИНХРОННО, до Operation. Его источником был
// словарь, ПОРОЖДЁННЫЙ СБОРКОЙ (`authzmap.ObjectType`, `tables_gen.go`), — тот
// же класс, что уже снят у проекции (#1816), у зеркала (#1982) и у регистрации
// (#1990). Тип, заведённый применением манифеста в РАБОТАЮЩЕМ процессе, этому
// словарю неизвестен, поэтому `Role.Create` и `Role.Update` отвергали правило
// над ним `INVALID_ARGUMENT`.
//
// Для арендатора это ПЕРВЫЙ шаг после применения манифеста: ниже по цепи чинить
// нечего — роли нет.
//
// # Почему проба идёт ЧЕРЕЗ USE-CASE, а не через писателей репозитория
//
// Сквозная проба пункта 1 DoD заводит роль ТРЕМЯ ПИСАТЕЛЯМИ репозитория, минуя
// use-case создания, — и говорит об этом в своей шапке прямо. Гейта на её пути
// нет by construction, поэтому звено оставалось неизмеренным: проверка была
// верной и МИМО. Утверждать здесь надо ИСХОД СОЗДАНИЯ РОЛИ, а не факт перевода
// имени: перевод можно починить, оставив отказ на месте.
//
// # НАПРАВЛЕНИЙ ДВА, и оба обязаны быть верны по живым строкам
//
//   - ЗАВЕДЕНИЕ: тип, заведённый в работающем процессе, ПРИНИМАЕТСЯ;
//   - СНЯТИЕ: тип, чья строка снята, ОТВЕРГАЕТСЯ. Порождённая сборкой таблица
//     этого направления не закрывала вовсе — она продолжала отвечать «грантуем»
//     про ресурс, которого у платформы больше нет.
//
// Порознь каждое направление выполнимо гейтом, который не отвергает НИКОГДА
// (заведение зеленело бы на нём целиком) либо отвергает ВСЁ (снятие зеленело бы),
// поэтому оба утверждаются вместе с отрицательным контролем ниже.

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// appliedModule / appliedResource — модуль и ресурс, заведённые ПОСЛЕ сборки:
// ни имени модуля, ни имени типа в порождённой таблице нет. Что таблица их
// действительно не знает — утверждается пробой (положительный контроль
// предпосылки), а не объявляется этим комментарием.
const (
	appliedModule     = "probemod"
	appliedResource   = "alpha"
	appliedDotted     = appliedModule + "." + appliedResource
	appliedObjectType = "probemod_alpha"

	// seededNeighbour — ЖИВОЙ сосед из посева. Положительный контроль: без него
	// «отвергнуто» неотличимо от «путь не работает вовсе», а «принято» — от
	// гейта, который принимает всё.
	seededModule   = "compute"
	seededResource = "instance"

	// withdrawnResource — ресурс, чью строку каталога сняли в работающем
	// процессе. Порождённая сборкой таблица о снятии не знает НИКОГДА.
	withdrawnModule   = "compute"
	withdrawnResource = "placementGroup"
	withdrawnDotted   = withdrawnModule + "." + withdrawnResource
)

// factsWithAppliedType — живые строки посева ПЛЮС ресурс, заведённый
// применением манифеста в работающем процессе.
//
// Строки посева берутся у `seed.LiteralRows()` — того же перечня, которым
// каталог посеян и с которым его сверяет страж старта. Второй производитель
// того же перечня разошёлся бы с первым молча.
func factsWithAppliedType(t *testing.T) *catalog.Facts {
	t.Helper()
	rows := seed.LiteralRows()
	rows.Modules = append(rows.Modules, appliedModule)
	rows.Resources = append(rows.Resources, catalog.ResourceRow{
		Module: appliedModule, Resource: appliedResource, ObjectType: appliedObjectType,
	})
	for _, verb := range []string{"get", "list", "update", "delete"} {
		rows.Verbs = append(rows.Verbs, catalog.VerbRow{
			Module: appliedModule, Resource: appliedResource, Verb: verb, PerObject: true,
		})
	}
	f, err := catalog.NewFacts(rows)
	if err != nil {
		t.Fatalf("снимок со строкой заведённого ресурса: %v", err)
	}
	return f
}

// factsWithoutWithdrawnType — живые строки посева МИНУС строка снятого ресурса
// (и её глаголы). Модуль при этом остаётся живым: снят ресурс, а не модуль, —
// иначе отказ пришёл бы чужой полосой (`unknown module`), и вердикт был бы о
// другом предмете.
func factsWithoutWithdrawnType(t *testing.T) *catalog.Facts {
	t.Helper()
	src := seed.LiteralRows()
	rows := catalog.Rows{Modules: src.Modules}
	for _, r := range src.Resources {
		if r.Module == withdrawnModule && r.Resource == withdrawnResource {
			continue
		}
		rows.Resources = append(rows.Resources, r)
	}
	for _, v := range src.Verbs {
		if v.Module == withdrawnModule && v.Resource == withdrawnResource {
			continue
		}
		rows.Verbs = append(rows.Verbs, v)
	}
	if len(rows.Resources) != len(src.Resources)-1 {
		t.Fatalf("строка снятого ресурса %s в посеве не найдена: ресурсов %d, осталось %d — "+
			"вердикт о снятии был бы беспредметен",
			withdrawnDotted, len(src.Resources), len(rows.Resources))
	}
	f, err := catalog.NewFacts(rows)
	if err != nil {
		t.Fatalf("снимок без строки снятого ресурса: %v", err)
	}
	return f
}

// TestIAM1993_PremiseTheBuildTableDoesNotKnowTheAppliedType — ПРЕДПОСЫЛКА,
// проверенная, а не объявленная.
//
// Если бы порождённая сборкой таблица знала `probemod.alpha`, всё, что ниже,
// зеленело бы и на неисправленном коде: проба утверждала бы о типе, который
// сборке известен, то есть ни о чём.
func TestIAM1993_PremiseTheBuildTableDoesNotKnowTheAppliedType(t *testing.T) {
	if _, ok := authzmap.ObjectType(appliedModule, appliedResource); ok {
		t.Fatalf("порождённая сборкой таблица знает %s — предмет пробы исчез, "+
			"выберите имя, которого в дереве нет ни одним литералом", appliedDotted)
	}
	if _, ok := authzmap.ObjectType(seededModule, seededResource); !ok {
		t.Fatalf("порождённая сборкой таблица НЕ знает %s.%s — положительный контроль "+
			"беспредметен", seededModule, seededResource)
	}
	// СНЯТИЕ: таблица сборки продолжает отвечать «грантуем» про ресурс, чья
	// живая строка снята. Это и есть второе направление, которое она не
	// закрывает вовсе.
	if _, ok := authzmap.ObjectType(withdrawnModule, withdrawnResource); !ok {
		t.Fatalf("порождённая сборкой таблица НЕ знает %s — вердикт о снятии был бы "+
			"неотличим от вердикта о незнакомом типе", withdrawnDotted)
	}
}

// TestIAM1993_CreateRole_OverAppliedType_Accepted — НЕСУЩЕЕ утверждение:
// роль над типом, заведённым применением манифеста в работающем процессе,
// создаётся БЕЗ ОТКАЗА.
//
// Утверждается ИСХОД СОЗДАНИЯ (Execute вернул Operation и не вернул ошибки), а
// не факт перевода имени.
func TestIAM1993_CreateRole_OverAppliedType_Accepted(t *testing.T) {
	facts := factsWithAppliedType(t)
	// Положительный контроль ПРЕДПОСЫЛКИ: членство модуля живо. Без него отказ
	// пришёл бы от `validateModule` («unknown module»), и вердикт был бы о
	// другом сегменте правила.
	if !facts.IsKnownModule(appliedModule) {
		t.Fatalf("модуль %q не признан живым — строки не доехали, вердикт беспредметен", appliedModule)
	}

	uc := NewCreateRoleUseCase(newRlUpdRepo(domain.Labels{}), newRlFakeOps(), catalog.Fixed{F: facts})
	op, err := uc.Execute(authnCtx(), domain.Role{
		AccountID: "acc0000000000000abcd",
		Name:      "applied_type_role",
		Rules: domain.Rules{
			{Module: appliedModule, Resources: []string{appliedResource}, Verbs: []string{"get", "list"}},
		},
	})
	if err != nil {
		st, _ := status.FromError(err)
		t.Fatalf("роль над ЗАВЕДЁННЫМ типом %s отвергнута синхронно (%v): %s — "+
			"арендатор применил манифест своего модуля и роль над своим типом создать не может",
			appliedDotted, st.Code(), st.Message())
	}
	if op == nil {
		t.Fatalf("Execute вернул nil Operation без ошибки — исход создания не определён")
	}
	waitOps(t)
}

// TestIAM1993_CreateRole_OverSeededNeighbour_Accepted — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ
// на посеянном соседе, тем же путём и тем же снимком.
//
// Без него «принято» у заведённого типа было бы неотличимо от гейта, который
// перестал отвергать вообще.
func TestIAM1993_CreateRole_OverSeededNeighbour_Accepted(t *testing.T) {
	uc := NewCreateRoleUseCase(newRlUpdRepo(domain.Labels{}), newRlFakeOps(),
		catalog.Fixed{F: factsWithAppliedType(t)})
	op, err := uc.Execute(authnCtx(), domain.Role{
		AccountID: "acc0000000000000abcd",
		Name:      "seeded_neighbour_role",
		Rules: domain.Rules{
			{Module: seededModule, Resources: []string{seededResource}, Verbs: []string{"get", "list"}},
		},
	})
	if err != nil {
		st, _ := status.FromError(err)
		t.Fatalf("посеянный сосед %s.%s отвергнут (%v): %s — путь не работает вовсе",
			seededModule, seededResource, st.Code(), st.Message())
	}
	if op == nil {
		t.Fatalf("Execute вернул nil Operation без ошибки")
	}
	waitOps(t)
}

// TestIAM1993_CreateRole_OverUnknownType_StillRejected — ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ:
// тип, которого у платформы нет НИ В ОДНОМ словаре, по-прежнему отвергается ТЕМ
// ЖЕ кодом и ТЕМ ЖЕ текстом. Смена источника не есть снятие гейта.
func TestIAM1993_CreateRole_OverUnknownType_StillRejected(t *testing.T) {
	uc := NewCreateRoleUseCase(newRlUpdRepo(domain.Labels{}), newRlFakeOps(),
		catalog.Fixed{F: factsWithAppliedType(t)})
	_, err := uc.Execute(authnCtx(), domain.Role{
		AccountID: "acc0000000000000abcd",
		Name:      "typo_role",
		// Множественное число сингулярного токена каталога — тот самый тихий
		// отказ, ради которого гейт заведён.
		Rules: domain.Rules{
			{Module: seededModule, Resources: []string{"instances"}, Verbs: []string{"get"}},
		},
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("незнакомый тип принят (%v) — гейт перестал отвергать; err=%v", st.Code(), err)
	}
	if want := "compute.instances"; !strings.Contains(st.Message(), want) {
		t.Fatalf("текст отказа не называет токен %q: %s", want, st.Message())
	}
	if want := "/iam/v1/permissionCatalog"; !strings.Contains(st.Message(), want) {
		t.Fatalf("текст отказа не называет публичный каталог %q: %s", want, st.Message())
	}
}

// TestIAM1993_CreateRole_OverWithdrawnType_Rejected — ПАРНАЯ СТОРОНА того же
// источника: тип, чья строка каталога СНЯТА в работающем процессе, отвергается.
//
// Порождённая сборкой таблица этого не давала: она продолжала отвечать
// «грантуем» про ресурс, которого у платформы больше нет, — то есть роль над
// снятым типом принималась и материализовалась в ничто.
func TestIAM1993_CreateRole_OverWithdrawnType_Rejected(t *testing.T) {
	facts := factsWithoutWithdrawnType(t)
	// Предпосылка: модуль остался живым — значит отказ придёт от гейта каталога,
	// а не от проверки модуля.
	if !facts.IsKnownModule(withdrawnModule) {
		t.Fatalf("модуль %q снят вместе с ресурсом — вердикт был бы о другом сегменте", withdrawnModule)
	}

	uc := NewCreateRoleUseCase(newRlUpdRepo(domain.Labels{}), newRlFakeOps(), catalog.Fixed{F: facts})
	_, err := uc.Execute(authnCtx(), domain.Role{
		AccountID: "acc0000000000000abcd",
		Name:      "withdrawn_type_role",
		Rules: domain.Rules{
			{Module: withdrawnModule, Resources: []string{withdrawnResource}, Verbs: []string{"get"}},
		},
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("роль над СНЯТЫМ типом %s принята (%v) — гейт судит по словарю сборки, "+
			"который о снятии не знает; err=%v", withdrawnDotted, st.Code(), err)
	}
	if !strings.Contains(st.Message(), withdrawnDotted) {
		t.Fatalf("текст отказа не называет снятый токен %q: %s", withdrawnDotted, st.Message())
	}
}

// TestIAM1993_UpdateRole_OverAppliedType_Accepted — ПАРИТЕТ ПРАВКИ: тот же гейт
// стоит на изменяемых rules[], и правка роли на заведённый тип обязана
// приниматься так же, как создание. Иначе арендатор создаёт роль и не может её
// исправить.
func TestIAM1993_UpdateRole_OverAppliedType_Accepted(t *testing.T) {
	repo := newRlUpdRepo(domain.Labels{})
	uc := NewUpdateRoleUseCase(repo, newRlFakeOps(), catalog.Fixed{F: factsWithAppliedType(t)})

	_, err := uc.Execute(ownerCtx(), UpdateRoleInput{
		ID: rlUpdRoleID,
		Rules: domain.Rules{
			{Module: appliedModule, Resources: []string{appliedResource}, Verbs: []string{"get"}},
		},
		UpdateMask: []string{"rules"},
	})
	if err != nil {
		st, _ := status.FromError(err)
		t.Fatalf("правка роли на ЗАВЕДЁННЫЙ тип %s отвергнута (%v): %s",
			appliedDotted, st.Code(), st.Message())
	}
	waitOps(t)
}
