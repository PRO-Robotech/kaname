// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// relationgrant_test.go — выдача ОТНОШЕНИЕМ объявляется манифестом модуля
// (задача продукта #1936, приёмка
// services/iam/docs/engineering/acceptance/module-manifest-relation-grant.md,
// APPROVED круг 1; сценарии MOD-RG-01…13 и 23).
//
// # Что здесь проверяется и почему именно вызовом
//
// Форма выдачи несла один ключ — `roleId`, — и валидатор связности требовал
// его непустым. Живые же выдачи посева двух модулей наделяют служебную запись
// ОТНОШЕНИЕМ, ключа для которого у формы не было ни одного. Возможность была
// объявлена и неисполнима: пересечение двух правил об одном поле пусто.
//
// Проверять форму запроса недостаточно — этот класс ловится только ВЫЗОВОМ с
// минимально-законным входом: обе проверки по отдельности защитимы, неисполним
// их стык. Поэтому каждая проба ниже зовёт [manifest.Load], а не осматривает
// теги структуры.
//
// # Отрицания стоят В ПАРЕ с положительным
//
// Отказ, у которого нет законного близнеца, зеленеет на реализации,
// отвергающей всё. Пары названы у каждой пробы поимённо; самая важная —
// MOD-RG-08 к MOD-RG-09: без неё правило о получателе-группе зеленело бы на
// реализации, отвергающей группу ВСЕГДА, и §3.5 приёмки-основания оказалась бы
// перевёрнута вместо того, чтобы получить названное исключение.
package manifest_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
	"github.com/PRO-Robotech/kacho-iam/internal/manifestoracle"
)

// canonOracle — модель, ВНЕСЁННАЯ в загрузчик пробой.
//
// С #2002 связность выдачи отношением судится не тем, что загрузчик добыл сам, а
// тем, что внёс вызывающий. Пробы этого файла — про СВЯЗНОСТЬ, поэтому вносят
// канон образа: он и был судьёй, которого загрузчик прежде добывал.
//
// Что при этом стало другим и почему это не ослабление: путь СТАРТА службы
// оракула не вносит вовсе — там модель ещё собирается из доставленных
// манифестов, и суждение каноном отвергло бы выдачу на типе нового модуля by
// construction. Обе полосы держит пара проб в relationoraclereferent_test.go.
func canonOracle(t *testing.T) manifest.LoadOption {
	t.Helper()
	o, err := manifestoracle.Canon()
	if err != nil {
		t.Fatalf("канон образа не разобран — судить об отношении нечем: %v", err)
	}
	return manifest.WithRelationOracle(o)
}

// seedWithBinding — оболочка манифеста с одной служебной записью, одной
// группой и ОДНОЙ выдачей, тело которой подставляет проба.
//
// Постоянная часть намеренно минимальна и законна: всё, что проба портит, она
// портит РОВНО ОДНИМ отличием от этого текста. Инъекция, роняющая заодно
// соседнее свойство, доказательством не является — красное пришло бы от соседа.
func seedWithBinding(binding string) []byte {
	return []byte(`apiVersion: iam/v1
module: vpc
seed:
  serviceAccounts:
    - name: kacho-vpc
      account: system
      description: >
        Личность модуля на пути запроса: под ней vpc ходит к соседям.
  accessBindings:
` + binding)
}

// seedWithGroupAndBinding — та же оболочка плюс ГРУППА.
//
// Отдельная от [seedWithBinding] намеренно: заведённая группа обязана быть
// названа хотя бы одной выдачей, поэтому в пробах, чья выдача группу не
// называет, её объявление уронило бы СОСЕДНЮЮ проверку — и красное пришло бы не
// от проверяемого свойства.
func seedWithGroupAndBinding(binding string) []byte {
	return []byte(`apiVersion: iam/v1
module: vpc
seed:
  serviceAccounts:
    - name: kacho-vpc
      account: system
      description: >
        Личность модуля на пути запроса: под ней vpc ходит к соседям.
  groups:
    - name: vpc-quota-readers
      account: system
      description: Потребители модуля, читающие действующие пределы.
  accessBindings:
` + binding)
}

// bindingRelationToServiceAccount — выдача ОТНОШЕНИЕМ служебной записи своего
// модуля. Это ровно форма двух живых строк посева (`kacho-vpc` и
// `kacho-compute` → `system_viewer` на кластерном якоре).
const bindingRelationToServiceAccount = `    - subjects:
        - {type: serviceAccount, name: kacho-vpc}
      grantedRelation: system_viewer
      scopeType: iam.cluster
      scopeId: cluster_kacho_root
      target: allInScope
`

// bindingRelationToGroup — выдача ОТНОШЕНИЕМ группе. Отношение выбрано такое,
// которое канон объявляет принимающим членство группы: иначе проба измеряла бы
// не тот отказ.
const bindingRelationToGroup = `    - subjects:
        - {type: group, name: vpc-quota-readers}
      grantedRelation: quota_reader
      scopeType: iam.cluster
      scopeId: cluster_kacho_root
      target: allInScope
`

// mustLoadOK — законный вход обязан проходить. Отдельный помощник, потому что
// положительный контроль зовётся из КАЖДОГО отрицания, и его молчание есть
// половина доказательства.
func mustLoadGrantOK(t *testing.T, doc []byte, why string) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load(doc, canonOracle(t))
	if err != nil {
		t.Fatalf("законный вход отвергнут (%s): %v", why, err)
	}
	return m
}

// mustRefuse — отказ обязан быть НАЗВАННОГО вида и называть предмет спора.
// Проверяется и вид, и текст: код без текста не отличает «валидация» от
// «состояние», а текст без вида ломается молча при смене вида.
func mustRefuseGrant(t *testing.T, doc []byte, kind error, mentions ...string) string {
	t.Helper()
	_, err := manifest.Load(doc, canonOracle(t))
	if err == nil {
		t.Fatalf("ожидался отказ; получен nil")
	}
	if kind != nil && !errors.Is(err, kind) {
		t.Errorf("отказ не относится к виду %v: %v", kind, err)
	}
	msg := err.Error()
	for _, m := range mentions {
		if !strings.Contains(msg, m) {
			t.Errorf("отказ не называет %q: %s", m, msg)
		}
	}
	return msg
}

// ── MOD-RG-01 · ключ существует и законная выдача отношением проходит ────────

// TestMODRG01RelationGrantToOwnServiceAccountIsAccepted — НЕСУЩАЯ проба задачи.
//
// До этой работы вход отвергался дважды и по разным причинам: ключа
// `grantedRelation` у формы не было вовсе (`KnownFields(true)`), а валидатор
// связности требовал `roleId`. Обе стороны по отдельности защитимы; неисполним
// их стык — ровно тот класс, ради которого задача заведена.
func TestMODRG01RelationGrantToOwnServiceAccountIsAccepted(t *testing.T) {
	m := mustLoadGrantOK(t, seedWithBinding(bindingRelationToServiceAccount),
		"выдача отношением служебной записи своего модуля")

	if got := len(m.Seed.AccessBindings); got != 1 {
		t.Fatalf("выдач прочитано %d, ожидалась 1", got)
	}
	b := m.Seed.AccessBindings[0]
	if b.GrantedRelation != "system_viewer" {
		t.Errorf("grantedRelation прочитан как %q, ожидался system_viewer", b.GrantedRelation)
	}
	if b.RoleID != "" {
		t.Errorf("roleId непуст (%q) у выдачи отношением", b.RoleID)
	}
	t.Logf("перепись связности: %s", m.Linkage())
}

// ── MOD-RG-08 · вторая ветвь получателя, положительный контроль к 09 ────────

// TestMODRG08RelationGrantToGroupIsAcceptedWhenTheCanonAdmitsGroup — обе ветви
// правила о получателе имеют ЖИВОЙ вход: на кластерном якоре отношений,
// принимающих членство группы, два (`quota_reader`, `fga_writer`), и это не
// синтетика.
//
// Без этой пробы отказ MOD-RG-09 зеленел бы на реализации, отвергающей
// получателя-группу ВСЕГДА.
func TestMODRG08RelationGrantToGroupIsAcceptedWhenTheCanonAdmitsGroup(t *testing.T) {
	mustLoadGrantOK(t, seedWithGroupAndBinding(bindingRelationToGroup),
		"выдача отношением группе, чьё членство канон принимает")
}

// ── MOD-RG-02 · выдача РОЛЬЮ не тронута ─────────────────────────────────────

// TestMODRG02RoleGrantStillPassesUnchanged — контроль в обратную сторону:
// прежняя форма выдачи не сузилась. Отрицания ниже без него зеленели бы на
// реализации, отвергающей выдачу вообще.
func TestMODRG02RoleGrantStillPassesUnchanged(t *testing.T) {
	doc := []byte(`apiVersion: iam/v1
module: vpc
seed:
  groups:
    - name: vpc-quota-readers
      account: system
      description: Потребители модуля, читающие действующие пределы.
  accessBindings:
    - subjects:
        - {type: group, name: vpc-quota-readers}
      roleId: vpc.internal_consumer
      scopeType: iam.cluster
      scopeId: cluster_kacho_root
      target: allInScope
`)
	m := mustLoadGrantOK(t, doc, "выдача ролью, форма которой не менялась")
	if m.Seed.AccessBindings[0].GrantedRelation != "" {
		t.Errorf("у выдачи ролью grantedRelation непуст: %q",
			m.Seed.AccessBindings[0].GrantedRelation)
	}
}

// ── MOD-RG-03 · названы ОБЕ формы → отказ ───────────────────────────────────

// TestMODRG03BothGrantFormsNamedIsRefused — зеркало живого ключа хранилища
// `(role_id IS NOT NULL AND granted_relation = ”) OR (role_id IS NULL AND
// granted_relation <> ”)`. Выдача выдаёт ровно одно.
//
// Положительный контроль — MOD-RG-01 и MOD-RG-02: каждая форма ПО ОТДЕЛЬНОСТИ
// проходит, значит отказ ловит их сочетание, а не саму форму.
func TestMODRG03BothGrantFormsNamedIsRefused(t *testing.T) {
	doc := seedWithBinding(`    - subjects:
        - {type: serviceAccount, name: kacho-vpc}
      roleId: vpc.viewer
      grantedRelation: system_viewer
      scopeType: iam.cluster
      scopeId: cluster_kacho_root
      target: allInScope
`)
	mustRefuseGrant(t, doc, manifest.ErrBindingIncomplete,
		"названы ОБЕ формы выдачи", `roleId "vpc.viewer"`,
		`grantedRelation "system_viewer"`, "оставьте один ключ")
}

// ── MOD-RG-04 · не названа НИ ОДНА форма → отказ, верный для обоих ключей ────

// TestMODRG04NeitherGrantFormNamedIsRefused — прежний отказ был однобоким: он
// требовал именно `roleId`, тогда как после этой работы выдача вправе сказать
// то же вторым ключом. Довод «выдача не сказала, ЧТО она выдаёт» остаётся
// верным; неверным стало требование.
func TestMODRG04NeitherGrantFormNamedIsRefused(t *testing.T) {
	doc := seedWithBinding(`    - subjects:
        - {type: serviceAccount, name: kacho-vpc}
      scopeType: iam.cluster
      scopeId: cluster_kacho_root
      target: allInScope
`)
	msg := mustRefuseGrant(t, doc, manifest.ErrBindingIncomplete,
		"не названа ни одна форма выдачи", "roleId", "grantedRelation",
		"выдача не сказала, ЧТО она выдаёт")

	// Прежний однобокий текст снят вместе со своим требованием: он отправлял
	// автора заполнять ровно один из двух законных ключей.
	if strings.Contains(msg, "seed.accessBindings[0].roleId: ключ не назван") {
		t.Errorf("прежний однобокий отказ пережил своё требование: %s", msg)
	}
}

// ── MOD-RG-09 · получатель-группа у отношения, группу НЕ принимающего ───────

// TestMODRG09GroupRecipientRefusedWhenTheCanonDoesNotAdmitGroup — правило о
// получателе судится КАНОНОМ, а не вторым перечнем.
//
// Положительный контроль — MOD-RG-08: ТА ЖЕ группа того же посева с отношением
// `quota_reader` проходит.
func TestMODRG09GroupRecipientRefusedWhenTheCanonDoesNotAdmitGroup(t *testing.T) {
	doc := seedWithGroupAndBinding(`    - subjects:
        - {type: group, name: vpc-quota-readers}
      grantedRelation: system_viewer
      scopeType: iam.cluster
      scopeId: cluster_kacho_root
      target: allInScope
`)
	msg := mustRefuseGrant(t, doc, manifest.ErrRelationRecipientKind,
		`отношение "system_viewer"`, `типа "cluster"`,
		`получателя вида "group" не принимает`, "объявление принимает",
		"user", "service_account")

	// Отказ не вправе предлагать путь, который для ЭТОГО отношения неисполним:
	// «заведи группу и вступи в неё» отправило бы автора чинить то, что не
	// чинится — членства группы это отношение не принимает вовсе.
	for _, forbidden := range []string{"вступ", "joins"} {
		if strings.Contains(msg, forbidden) {
			t.Errorf("отказ предлагает неисполнимый путь (%q): %s", forbidden, msg)
		}
	}
}

// ── MOD-RG-10 · отношение каноном у типа якоря не объявлено ─────────────────

// TestMODRG10UndeclaredRelationIsRefusedWithTheCanonList — перечень объявленных
// берётся У КАНОНА, а не выписывается: выписанный разошёлся бы с ним молча.
//
// Положительный контроль — MOD-RG-01 и MOD-RG-08: два РАЗНЫХ объявленных
// отношения проходят.
func TestMODRG10UndeclaredRelationIsRefusedWithTheCanonList(t *testing.T) {
	doc := seedWithBinding(`    - subjects:
        - {type: serviceAccount, name: kacho-vpc}
      grantedRelation: system_vewer
      scopeType: iam.cluster
      scopeId: cluster_kacho_root
      target: allInScope
`)
	msg := mustRefuseGrant(t, doc, manifest.ErrRelationNotDeclared,
		`отношения "system_vewer"`, `типа "cluster"`, "не объявляет", "объявлены:")

	// Перечень обязан быть НАСТОЯЩИМ перечнем канона, а не парой имён: проба
	// называет три далеко отстоящих друг от друга, чтобы обход по одному терму
	// не прошёл за обход по всем.
	for _, rel := range []string{"any_admin", "quota_reader", "system_viewer"} {
		if !strings.Contains(msg, rel) {
			t.Errorf("перечень объявленных не называет %q: %s", rel, msg)
		}
	}
}

// ── MOD-RG-11 · отношение вычисляемое → СВОЙ отказ ─────────────────────────

// TestMODRG11ComputedRelationGetsItsOwnRefusal — ответов канона ТРИ, и
// схлопывание любых двух дало бы судью, чей отказ называет неверный предмет:
// автор чинил бы вид получателя там, где чинить надо выбор отношения.
//
// Положительный контроль — MOD-RG-01 и MOD-RG-08: два ПРЯМЫХ отношения того же
// типа проходят, значит отказ ловит вычисляемость, а не всякое отношение.
func TestMODRG11ComputedRelationGetsItsOwnRefusal(t *testing.T) {
	doc := seedWithBinding(`    - subjects:
        - {type: serviceAccount, name: kacho-vpc}
      grantedRelation: any_admin
      scopeType: iam.cluster
      scopeId: cluster_kacho_root
      target: allInScope
`)
	msg := mustRefuseGrant(t, doc, manifest.ErrRelationComputed,
		`отношение "any_admin"`, "ВЫЧИСЛЯЕМЫМ", "прямых субъектов у него нет")

	// Отказ обязан быть ОТЛИЧИМ от двух соседних: иначе три ответа канона
	// схлопнуты, и различие, ради которого они разведены, потеряно.
	if strings.Contains(msg, "не объявляет") || strings.Contains(msg, "не принимает") {
		t.Errorf("отказ о вычисляемом отношении неотличим от соседних: %s", msg)
	}
}

// ── MOD-RG-12 · одноимённое отношение соседнего типа не подменяет ──────────

// TestMODRG12SameNameOnAnotherTypeDoesNotSubstitute — ответ даётся по
// объявлению СВОЕГО типа: `member` объявлен у типа `group` и не объявлен у
// `cluster`.
//
// Положительный контроль — MOD-RG-01: отношение, объявленное У ТИПА ЯКОРЯ,
// проходит. Без него проба зеленела бы на судье, не находящем ничего.
func TestMODRG12SameNameOnAnotherTypeDoesNotSubstitute(t *testing.T) {
	doc := seedWithBinding(`    - subjects:
        - {type: serviceAccount, name: kacho-vpc}
      grantedRelation: member
      scopeType: iam.cluster
      scopeId: cluster_kacho_root
      target: allInScope
`)
	mustRefuseGrant(t, doc, manifest.ErrRelationNotDeclared,
		`отношения "member"`, `типа "cluster"`, "не объявляет")
}

// ── MOD-RG-13 · порядок двух проверок получателя ───────────────────────────

// TestMODRG13SeedableCheckPrecedesTheCanonCheck — порядок ОБЪЯВЛЕН, а не выведен
// из порядка чтения полей.
//
// Человека посев модуля не заводит ни при каком входе, поэтому отказ обязан
// остаться прежним. Канон при этом `user` ПРИНИМАЕТ — назвать его виновником
// значило бы отправить автора чинить не то.
//
// Положительный контроль — MOD-RG-01: `serviceAccount` своего посева с тем же
// отношением проходит ОБЕ проверки.
func TestMODRG13SeedableCheckPrecedesTheCanonCheck(t *testing.T) {
	doc := seedWithBinding(`    - subjects:
        - {type: user, name: someone}
      grantedRelation: system_viewer
      scopeType: iam.cluster
      scopeId: cluster_kacho_root
      target: allInScope
`)
	msg := mustRefuseGrant(t, doc, manifest.ErrSubjectNotSeeded,
		"посев модуля не заводит")

	// Отказа про канон быть не должно: канон этот вид принимает.
	if strings.Contains(msg, "не принимает") || strings.Contains(msg, "объявление принимает") {
		t.Errorf("выдан отказ про канон там, где канон вид принимает: %s", msg)
	}
}

// ── MOD-RG-23 · якорь формы отношения ──────────────────────────────────────

// TestMODRG23RelationGrantOnANonClusterAnchorIsRefused — выдача отношением
// объявляется ТОЛЬКО на кластерном якоре, и это судится by construction: без
// резолва типа якоря канон спрашивать не о чем.
//
// Выдача РОЛЬЮ этой проверкой не затронута — её якорь остаётся предметом
// задачи продукта #1953, и MOD-RG-02 это утверждает молчанием.
func TestMODRG23RelationGrantOnANonClusterAnchorIsRefused(t *testing.T) {
	doc := seedWithBinding(`    - subjects:
        - {type: serviceAccount, name: kacho-vpc}
      grantedRelation: system_viewer
      scopeType: iam.project
      scopeId: prj-something
      target: allInScope
`)
	mustRefuseGrant(t, doc, manifest.ErrBindingAnchor,
		`якоре "iam.cluster"`, `получено "iam.project"`)
}
