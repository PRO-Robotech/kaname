// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// service_account_creator_sac42_test.go — SAC-42 приёмки
// docs/engineering/acceptance/service-account-creation-is-its-own-right.md
// (редакция 3, отпечаток cd31c47cb19dea4163a70a4e181545c2462e0ef0a62d5f330a23f66fe14bc08f;
// задача PRO-Robotech/kaname#1003): форма манифеста — контейнерное действие
// `containerVerbs` и селектор создателя `createdBySubject` — в загрузчике,
// roleexport, генераторе модели и раскрытии подстановки (Р2а).
//
// # Вход — встроенный манифест iam, варианты — РОВНО ОДНА правка текста
//
// Вариант a — манифест как есть. Варианты b…g отличаются от него одной текстовой
// правкой по якорю; якоря нет — правка не применена, и проба говорит это словами
// «ПРЕДМЕТА НЕТ», а не судит вход, который продукт не производит. Близнец каждой
// строки b…g — строка a.

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/manifest/roleexport"
	"github.com/PRO-Robotech/kaname/internal/modelrender"
	"github.com/PRO-Robotech/kaname/internal/servicemanifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// Якоря правок — фрагменты манифеста iam ПОСЛЕ изменения (Р2а приёмки).
const (
	sac42ContainerVerbs = "    containerVerbs:\n" +
		"      - {name: create, parent: account, relation: service_account_creator}\n"
	sac42CreatorRelation = "      - name: service_account_creator\n" +
		"        definition: '[service_account] or editor'\n" +
		"        position: afterVerbs\n"
	sac42Rule1     = "        resources: [serviceAccount]\n        verbs: [create]\n"
	sac42Rule2     = "        resources: [serviceAccount]\n        verbs: [get, list, update, delete]\n        createdBySubject: true\n"
	sac42GroupView = "        resources: [group]\n        classes: [list, get]\n"
	sac42RoleC     = "iam.service_account.creator"
)

// sac42Variant — вариант манифеста: одна правка текста (old → new) против a.
type sac42Variant struct {
	name     string
	old, new string
	// want — фрагменты, которые обязан назвать отказ загрузчика.
	want []string
	// kind — вид отказа, если он объявлен сентинелом; nil — судится по тексту.
	kind error
}

func sac42Variants() []sac42Variant {
	return []sac42Variant{
		{name: "b — снята запись containerVerbs",
			old: sac42ContainerVerbs, new: "",
			want: []string{sac42RoleC, "create", "verbs", "line "},
			kind: manifest.ErrRoleRuleVerbUnknownToContract},
		{name: "c — правило 1 classes: [create]",
			old: sac42Rule1, new: "        resources: [serviceAccount]\n        classes: [create]\n",
			want: []string{sac42RoleC, "rules[0]", "create", "line "}},
		{name: "d — отношение с приставкой v_",
			old: sac42CreatorRelation + "@" + "relation: service_account_creator}",
			new: "      - name: v_service_account_creator\n" +
				"        definition: '[service_account] or editor'\n" +
				"        position: afterVerbs\n" + "@" + "relation: v_service_account_creator}",
			want: []string{"v_service_account_creator", "v_", "line "}},
		{name: "e — parent: project",
			old:  "{name: create, parent: account, relation: service_account_creator}",
			new:  "{name: create, parent: project, relation: service_account_creator}",
			want: []string{"project", "serviceAccount", "line "}},
		{name: "f — createdBySubject над group",
			old: sac42GroupView, new: sac42GroupView + "        createdBySubject: true\n",
			want: []string{"createdBySubject", "group", "create", "line "}},
		{name: "g — createdBySubject с resourceNames",
			old: sac42Rule2, new: sac42Rule2 + "        resourceNames: [x]\n",
			want: []string{"createdBySubject", "resourceNames", "line "}},
	}
}

// applyEdit — правка варианта; старых фрагментов бывает два (через «@»), каждый
// обязан встретиться ровно один раз.
func applyEdit(t *testing.T, doc string, v sac42Variant) string {
	t.Helper()
	olds, news := strings.Split(v.old, "@"), strings.Split(v.new, "@")
	if v.old == "" || len(olds) != len(news) {
		t.Fatalf("вариант %s: правка задана неверно", v.name)
	}
	for i, o := range olds {
		if n := strings.Count(doc, o); n != 1 {
			t.Fatalf("SAC-42 %s: ПРЕДМЕТА НЕТ — якорь правки встречается в манифесте iam %d раз, ждали ровно один:\n%s",
				v.name, n, o)
		}
		doc = strings.Replace(doc, o, news[i], 1)
	}
	return doc
}

// sac42Actions — действия модулей из каталога прав (тот же, что судит дверь).
func sac42Actions(t *testing.T) []roleexport.Action {
	t.Helper()
	reg, err := seed.LoadPermissionRegistry(context.Background(),
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		t.Fatalf("каталог прав не прочитан: %v", err)
	}
	var entries []roleexport.CatalogEntry
	for _, r := range reg.All() {
		entries = append(entries, roleexport.CatalogEntry{
			FQN: r.FQN, RequiredRelation: r.RequiredRelation, ScopeObjectType: r.ScopeExtractor.ObjectType,
		})
	}
	actions, _ := roleexport.Attribute(entries)
	if len(actions) == 0 {
		t.Fatal("действий ноль: судить нечем")
	}
	return actions
}

// sac42Facts — каталожный факт, выведенный из ЭТОГО манифеста тем же
// производителем строк, что применитель каталога (`modulecatalog.RowsOf`).
func sac42Facts(t *testing.T, m *manifest.Manifest) *catalog.Facts {
	t.Helper()
	d, err := modulecatalog.RowsOf(m)
	if err != nil {
		t.Fatalf("строки каталога манифеста iam: %v", err)
	}
	f, err := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{
		Modules: []string{m.Module}, Resources: d.Resources, Verbs: d.Verbs,
	}})
	if err != nil {
		t.Fatalf("каталожный факт манифеста iam: %v", err)
	}
	return f
}

func resourceNamed(t *testing.T, m *manifest.Manifest, name string) manifest.Resource {
	t.Helper()
	for _, r := range m.Resources {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("ресурса %s в манифесте нет", name)
	return manifest.Resource{}
}

func TestServiceAccountCreator_SAC42_ManifestFormLoaderRoleexportGeneratorWildcard(t *testing.T) {
	raw := string(servicemanifest.Raw())
	for _, anchor := range []string{sac42ContainerVerbs, sac42CreatorRelation, sac42Rule1, sac42Rule2} {
		if !strings.Contains(raw, anchor) {
			t.Fatalf("SAC-42 a: ПРЕДМЕТА НЕТ — во встроенном манифесте iam нет фрагмента Р2а:\n%s", anchor)
		}
	}
	read, refused := 0, map[string]int{}

	// ── a — как есть ─────────────────────────────────────────────────────────
	read++
	m, err := manifest.Load([]byte(raw))
	if err != nil {
		t.Fatalf("SAC-42 a: загрузчик отверг манифест iam: %v", err)
	}
	refused["a"] = 0
	actions := sac42Actions(t)
	faults, census := roleexport.CheckNamedVerbs(catalogfixture.Facts(), m, actions)
	t.Logf("SAC-42 a: %s", census.Summary())
	if len(faults) != 0 {
		t.Errorf("SAC-42 a: roleexport MOD-RL-19 — находок %d, ждали 0: %v", len(faults), faults)
	}
	exported, xfaults, xcensus := roleexport.ExportRoleRules(catalogfixture.Facts(), m, actions)
	t.Logf("SAC-42 a: %s", xcensus.Summary())
	if len(xfaults) != 0 {
		t.Errorf("SAC-42 a: roleexport MOD-RL-18 — находок %d, ждали 0: %v", len(xfaults), xfaults)
	}
	rules, ok := exported[sac42RoleC]
	if !ok || len(rules) != 2 {
		t.Fatalf("SAC-42 a: роль C экспортирована правилами %#v, ждали два", rules)
	}
	if got := rules[0]; ruleCreatedBySubject(t, got) || strings.Join(got.Verbs, ",") != "create" {
		t.Errorf("SAC-42 a: правило 1 роли C экспортировано как %#v, ждали verbs [create] без селектора", got)
	}
	if got := rules[1]; !ruleCreatedBySubject(t, got) {
		t.Errorf("SAC-42 a: правило 2 роли C экспортировано без селектора создателя: %#v", got)
	}
	// Правило 2 уезжает ровно объявленным набором глаголов (SAC-41: get, list,
	// update, delete как множество). Сведение к наименьшему набору классов по
	// покрытию действий здесь неприменимо: селектор создателя пишет на объекте
	// только кортежи глаголов (Р2 п.3), и «list», покрытый другим классом через
	// ярус, создатель терял бы — его список своих учёток пустел бы (SAC-15).
	if got := append([]string(nil), rules[1].Verbs...); len(got) > 0 {
		sort.Strings(got)
		if strings.Join(got, ",") != "delete,get,list,update" {
			t.Errorf("SAC-42 a: правило 2 роли C экспортировано глаголами %v, ждали множество [get list update delete]", rules[1].Verbs)
		}
	} else {
		t.Errorf("SAC-42 a: правило 2 роли C экспортировано без глаголов: %#v", rules[1])
	}
	acc, err := modelrender.Render(resourceNamed(t, m, "account"))
	if err != nil {
		t.Fatalf("SAC-42 a: рендер account: %v", err)
	}
	if !strings.Contains(string(acc), "define service_account_creator: [service_account] or editor") {
		t.Errorf("SAC-42 a: в блоке account нет отношения Р1:\n%s", acc)
	}
	sa, err := modelrender.Render(resourceNamed(t, m, "serviceAccount"))
	if err != nil {
		t.Fatalf("SAC-42 a: рендер serviceAccount: %v", err)
	}
	if strings.Contains(string(sa), "define v_create") {
		t.Errorf("SAC-42 a: у iam_service_account выведен v_create:\n%s", sa)
	}
	if n := strings.Count(authzmodel.DSL, "define v_create"); n != 1 {
		t.Errorf("SAC-42 a: define v_create в модели %d, ждали 1", n)
	}
	if !strings.Contains(authzmodel.DSL, "define service_account_creator: [service_account] or editor") {
		t.Errorf("SAC-42 a: в канонической модели нет отношения Р1")
	}

	// ── b…g — одна правка ───────────────────────────────────────────────────
	for _, v := range sac42Variants() {
		t.Run(v.name, func(t *testing.T) {
			read++
			doc := applyEdit(t, raw, v)
			_, lerr := manifest.Load([]byte(doc))
			if lerr == nil {
				refused[v.name] = 0
				t.Fatalf("SAC-42 %s: манифест принят — ждали отказ загрузчика", v.name)
			}
			refused[v.name] = strings.Count(lerr.Error(), "\n") + 1
			if v.kind != nil && !errors.Is(lerr, v.kind) {
				t.Errorf("SAC-42 %s: отказ не отнесён к %v: %v", v.name, v.kind, lerr)
			}
			for _, w := range v.want {
				if !strings.Contains(lerr.Error(), w) {
					t.Errorf("SAC-42 %s: отказ не называет %q: %v", v.name, w, lerr)
				}
			}
		})
	}

	// ── h — подстановка `*` правила SAA ─────────────────────────────────────
	read++
	facts := sac42Facts(t, m)
	verbs := facts.GrantedVerbs("iam_service_account", []string{"*"}, facts.VerbsOfType("iam_service_account"),
		domain.PolicyOfRole(true, "iam"))
	sort.Strings(verbs)
	if strings.Join(verbs, ",") != "delete,get,list,update" {
		t.Errorf("SAC-42 h: `*` на iam_service_account развернулся в %v, ждали get, list, update, delete", verbs)
	}
	if got := containerGrants(t, facts, "iam", "serviceAccount", "*"); len(got) != 0 {
		t.Errorf("SAC-42 h: правило с `*` даёт отношения на родителе: %v", got)
	}
	// Близнец h — то же правило с поимённым `create`: отношение на account есть.
	got := containerGrants(t, facts, "iam", "serviceAccount", "create")
	if len(got) != 1 || got[0] != "account#service_account_creator" {
		t.Errorf("SAC-42 h (близнец): поимённый create даёт %v, ждали account#service_account_creator", got)
	}
	refused["h"] = 0

	t.Logf("SAC-42: вариантов прочитано %d, отказы по вариантам: %v", read, refused)
	if read == 0 {
		t.Fatal("SAC-42: НЕ ВЫПОЛНИЛОСЬ — прочитано 0 вариантов")
	}
}

// ruleCreatedBySubject — признак селектора создателя у правила домена (Р2а).
//
// Читается ОТРАЖЕНИЕМ поля по имени, а не обращением к полю: на стволе до
// изменения поля нет, и проба обязана собираться и исполняться, называя
// отсутствие предмета, а не падать сборкой («не выполнилось» ≠ «красное»).
func ruleCreatedBySubject(t *testing.T, r domain.Rule) bool {
	t.Helper()
	f := reflect.ValueOf(r).FieldByName("CreatedBySubject")
	if !f.IsValid() {
		t.Fatalf("SAC-42: ПРЕДМЕТА НЕТ — у правила домена нет поля CreatedBySubject (Р2а)")
	}
	return f.Bool()
}

// containerGrants — отношения на родителе, которые правило {module, [resource],
// [verb]} даёт контейнерным действием, по каталожному факту, формой
// «родитель#отношение». Метод факта спрашивается ОТРАЖЕНИЕМ по той же причине,
// что поле выше.
func containerGrants(t *testing.T, f *catalog.Facts, module, resource, verb string) []string {
	t.Helper()
	m := reflect.ValueOf(f).MethodByName("ContainerGrants")
	if !m.IsValid() {
		t.Fatalf("SAC-42: ПРЕДМЕТА НЕТ — у каталожного факта нет метода ContainerGrants (Р2а)")
	}
	out := m.Call([]reflect.Value{reflect.ValueOf(module), reflect.ValueOf([]string{resource}),
		reflect.ValueOf([]string{verb})})[0]
	var res []string
	for i := 0; i < out.Len(); i++ {
		g := out.Index(i)
		res = append(res, g.FieldByName("ParentType").String()+"#"+g.FieldByName("Relation").String())
	}
	return res
}
