// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// audience_fence_integration_test.go — полоса K3 приёмки NTF-3 (kacho#2918,
// редакция 42, отпечаток 1d7d2ad0a39805c3345efb48aee562d76a812e6a19087be427982f7d0d8373ba;
// Р7, Р30; Д133, Д134): справочник адресов отвечает на вопрос об аудитории
// версии события — перечнем `ListEventAudience` и членством
// `Resolve{audience = event}` — с оградой токена версии прав `R_E`.
//
// Сценарии — половина службы доступа: NTF3-165, 166, 167, 168 (г), 171, 173,
// 176, 177, 178, 181, 183; буквы вопроса об аудитории NTF3-170 (а) и
// NTF3-174 (а), (б), (в), (е), (з), (и), (л), (м). Плюс гонка ограды:
// изменение права, закоммиченное конкурирующей транзакцией до и во время
// снятия токена. Буквы NTF3-174 (г), (д), (к), (н) — приём поколения (полоса
// K2, `internal_iam`); (ж) — горизонт — здесь не построена: средства «часы
// службы доступа» в §8 приёмки нет (вопрос к приёмке, см. отчёт полосы).
//
// Порядок в каждой пробе несущий (скил `change-graph` §2): мир и миры
// близнецов строятся и судятся СВОИМИ средствами раньше первого вопроса о
// предмете; отсутствие метода либо формы — последний шаг.
//
// ─────────────────────────────────────────────────────────────────────────────
// КОНТРАКТ, КОТОРЫЙ ЗАДАЁТ ЭТА ПРОБА (полоса RED, до реализации)
//
//	service InternalNotificationRecipientService {      // только внутренний слушатель
//	  rpc Resolve (ResolveRecipientRequest) returns (ResolveRecipientResponse);
//	  rpc ListEventAudience (<запрос>) returns (<ответ>);
//	}
//	<запрос ListEventAudience> {
//	  string object;            // "<тип модели>:<id>"
//	  int64  source_version;    // поколение g_E
//	  string authz_rev;         // R_E — текстовая форма полного снимка (pg_snapshot)
//	  <факты> facts;            // project_id, account_id, labels (map), parent_chain
//	                            // (repeated string "<тип>:<id>"), previous_labels,
//	                            // previous_parent_chain (у UPDATED)
//	  string page_token; int32 page_size;
//	}
//	<ответ>: ровно один перечень строк субъектов "user:<id>" + next_page_token;
//	ResolveRecipientRequest.audience += event{object, source_version, authz_rev,
//	  facts, via_subscription}, account_reader{account_id};
//	закрытый перечень звена корня (`serviceIdentityMethods`) знает
//	`InternalNotificationRecipientService/ListEventAudience`;
//	отказы — `UNAVAILABLE` ErrorInfo{reason: OBJECT_GENERATION_NOT_APPLIED},
//	`INVALID_ARGUMENT` `<field>: required` либо нарушение поля, вызывающий вне
//	круга `notify` — `PERMISSION_DENIED` `permission denied` AUTHZ_DENIED.
//
// Имя перечня субъектов в ответе Р7 не закрепляет — проба берёт единственное
// повторяемое строковое поле ответа.
package main

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kaname/pkg/ownerregister"
)

func afSkipShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
}

var (
	afProd = map[string]string{"env": "prod"}
	afDev  = map[string]string{"env": "dev"}
	afNone = map[string]string{}
)

func afCreated(labels map[string]string) afFacts {
	return afFacts{project: "prj-1", account: "acc-1", labels: labels}
}

func afUpdated(prev, now map[string]string) afFacts {
	return afFacts{project: "prj-1", account: "acc-1", labels: now, prevLabels: prev}
}

// af165 — «Дано» и «Когда» NTF3-165 до вопросов: vol-31 создан (V31), затем
// правило usr-R на закреплённый id vol-31, затем правка описания (V31u);
// vol-32 с метками {env: dev} после выдачи правила.
func af165(t *testing.T, opts ...afWorldOption) (w *afWorld, v31, v31u, v32 afEvent) {
	t.Helper()
	w = newAFWorld(t, opts...)
	r31 := w.afToken(t)
	w.afApply(t, afVolume, "vol-31", 1, afCreated(afProd))
	afRequireDoor(t, w.door, "user:usr-own", "v_get", afVolume+":vol-31", true)
	afRequireDoor(t, w.door, "user:usr-X", "v_get", afVolume+":vol-31", false)
	w.afNamesRole(t, "rol-k3-names-31", "vol-31")
	w.afBind(t, afBinding{"acb-k3-r", "user", "usr-R", "rol-k3-names-31", "project", "prj-1"})
	afRequireDoor(t, w.door, "user:usr-R", "v_get", afVolume+":vol-31", true)
	r31u := w.afToken(t)
	w.afApply(t, afVolume, "vol-31", 2, afUpdated(afProd, afProd))
	r32 := w.afToken(t)
	w.afApply(t, afVolume, "vol-32", 1, afCreated(afDev))
	afRequireDoor(t, w.door, "user:usr-R", "v_get", afVolume+":vol-32", false)
	return w, afVol("vol-31", 1, r31, afCreated(afProd)), afVol("vol-31", 2, r31u, afUpdated(afProd, afProd)),
		afVol("vol-32", 1, r32, afCreated(afDev))
}

// ── NTF3-165 ────────────────────────────────────────────────────────────────

func TestNTF3165_EveryBindingScopeMakesTheUserAnAddressee(t *testing.T) {
	afSkipShort(t)
	w, v31, v31u, v32 := af165(t)

	// Миры близнецов букв — до вопроса о предмете: та же единственная привязка
	// пользователя снята до «Когда».
	type twin struct {
		name, user string
		w          *afWorld
		t31, t31u  afEvent
	}
	var twins []twin
	for _, letter := range []struct{ name, binding, user string }{
		{"(а) аккаунт", "acb-k3-c", "usr-C"},
		{"(б) проект", "acb-k3-b", "usr-B"},
		{"(в) модуль", "acb-k3-m", "usr-M"},
		{"(г) тип ресурса", "acb-k3-t", "usr-T"},
		{"(е) метки", "acb-k3-l", "usr-L"},
		{"(ж) группа", "acb-k3-grp", "usr-D"},
	} {
		tw, t31, t31u, _ := af165(t, afWithout(letter.binding))
		twins = append(twins, twin{name: letter.name, user: letter.user, w: tw, t31: t31, t31u: t31u})
	}

	md := afRequireListMethod(t)
	w.afServe(t)
	require.Equal(t, afSorted(afGW9...), w.afMustAudience(t, md, v31),
		"снимок версии CREATED V31 — ровно 9 субъектов (usr-R правило получил после события)")
	require.Equal(t, afPlus(afGW9, "usr-R"), w.afMustAudience(t, md, v31u),
		"снимок версии UPDATED V31u — 10 субъектов: правило usr-R выдано до правки")
	require.Equal(t, afMinus(afGW9, "usr-L"), w.afMustAudience(t, md, v32),
		"vol-32 {env: dev}: usr-M, usr-T есть; usr-R (закреплён id vol-31) и usr-L (метки) — нет")
	for _, e := range []afEvent{v31, v31u, v32} {
		require.NotContains(t, w.afMustAudience(t, md, e), "usr-E",
			"usr-E (право на project:prj-1, правила на тома нет) — не адресат %s@%d", e.object, e.gen)
	}
	for _, tw := range twins {
		t.Run("близнец "+tw.name, func(t *testing.T) {
			tw.w.afServe(t)
			require.Equal(t, afMinus(afGW9, tw.user), tw.w.afMustAudience(t, md, tw.t31))
			require.Equal(t, afMinus(afPlus(afGW9, "usr-R"), tw.user), tw.w.afMustAudience(t, md, tw.t31u))
		})
	}
}

// ── NTF3-166 ────────────────────────────────────────────────────────────────

func af166(t *testing.T, opts ...afWorldOption) (*afWorld, afEvent) {
	t.Helper()
	opts = append(opts,
		afWith(afBinding{"acb-k3-reg-a", "user", "usr-A", afRoleRegistry, "project", "prj-1"}),
		afWith(afBinding{"acb-k3-reg-sva", "service_account", "sva-1", afRoleRegistry, "project", "prj-1"}))
	w := newAFWorld(t, opts...)
	// Реестр reg-1 в prj-1 и репозиторий pub в нём — наборами событий их
	// модуля: структурный кортеж реестра; у репозитория — родитель-реестр и
	// владение создателя (usr-own), цепь [реестр, проект, аккаунт] (С24).
	w.afApplySet(t, "registry_registry:reg-1", 1,
		[]*iamv1.RegisteredTuple{{SubjectId: "project:prj-1", Relation: "project"}},
		ownerregister.ParentChain(nil, "prj-1", "acc-1"))
	r := w.afToken(t)
	w.afApplySet(t, "registry_repository:reg-1/pub", 1,
		[]*iamv1.RegisteredTuple{{SubjectId: "registry_registry:reg-1", Relation: "parent"}, {SubjectId: "user:usr-own", Relation: "owner"}},
		[]string{"registry_registry:reg-1", "project:prj-1", "account:acc-1"})
	// Видимость PUBLIC — публикацией своим методом с поколением CREATED.
	w.afPublish(t, "registry_repository:reg-1/pub", 1)
	afRequireDoor(t, w.door, "user:usr-X", "v_get", "registry_repository:reg-1/pub", true)
	afRequireDoor(t, w.door, "user:usr-A", "v_get", "registry_repository:reg-1/pub", true)
	return w, afEvent{object: "registry_repository:reg-1/pub", gen: 1, rev: r, facts: &afFacts{
		project: "prj-1", account: "acc-1", labels: afNone,
		chain: []string{"registry_registry:reg-1", "project:prj-1", "account:acc-1"}}}
}

func TestNTF3166_WildcardServiceAccountAndSystemFormNoAudience(t *testing.T) {
	afSkipShort(t)
	w, e := af166(t)
	// Близнец — до вопроса: usr-X получил привязку роли с v_get на репозитории до события.
	tw, te := af166(t, afWith(afBinding{"acb-k3-reg-x", "user", "usr-X", afRoleRegistry, "project", "prj-1"}))

	md := afRequireListMethod(t)
	w.afServe(t)
	got := w.afMustAudience(t, md, e) // каждый субъект — формы user:<id> (afUsers)
	require.Contains(t, got, "usr-A")
	require.NotContains(t, got, "usr-X", "usr-X видит репозиторий только подстановочным правом user:*")
	require.Equal(t, afSorted("usr-A", "usr-own"), got,
		"sva-1 (сервисный аккаунт) и user:* — не адресаты; владение usr-own кортежем набора CREATED записано после R")

	t.Run("близнец: usr-X получил привязку роли с v_get на репозитории до события", func(t *testing.T) {
		tw.afServe(t)
		require.Equal(t, afSorted("usr-A", "usr-X", "usr-own"), tw.afMustAudience(t, md, te))
	})
}

// ── NTF3-167 ────────────────────────────────────────────────────────────────

func TestNTF3167_LabelRemovalKeepsTheRemovingVersionAndDropsTheNext(t *testing.T) {
	afSkipShort(t)
	w := newAFWorld(t)
	r1 := w.afToken(t)
	w.afApply(t, afVolume, "vol-33", 1, afCreated(afProd))
	r2 := w.afToken(t)
	w.afApply(t, afVolume, "vol-33", 2, afUpdated(afProd, afNone))
	r3 := w.afToken(t)
	w.afApply(t, afVolume, "vol-33", 3, afUpdated(afNone, afNone))
	r4 := w.afToken(t)
	w.afApply(t, afVolume, "vol-34", 1, afCreated(afNone))
	r5 := w.afToken(t)
	w.afApply(t, afVolume, "vol-34", 2, afUpdated(afNone, afProd))

	// Близнец — до вопроса: первым Update меняется описание, метка остаётся.
	tw := newAFWorld(t)
	tw.afApply(t, afVolume, "vol-33", 1, afCreated(afProd))
	q2 := tw.afToken(t)
	tw.afApply(t, afVolume, "vol-33", 2, afUpdated(afProd, afProd))
	q3 := tw.afToken(t)
	tw.afApply(t, afVolume, "vol-33", 3, afUpdated(afProd, afProd))

	md := afRequireListMethod(t)
	w.afServe(t)
	require.Contains(t, w.afMustAudience(t, md, afVol("vol-33", 1, r1, afCreated(afProd))), "usr-L")
	require.Contains(t, w.afMustAudience(t, md, afVol("vol-33", 2, r2, afUpdated(afProd, afNone))), "usr-L",
		"V2 — объединение до и после: до снятия метки usr-L том видел")
	require.NotContains(t, w.afMustAudience(t, md, afVol("vol-33", 3, r3, afUpdated(afNone, afNone))), "usr-L")
	require.NotContains(t, w.afMustAudience(t, md, afVol("vol-34", 1, r4, afCreated(afNone))), "usr-L",
		"обратное направление: CREATED без меток")
	require.Contains(t, w.afMustAudience(t, md, afVol("vol-34", 2, r5, afUpdated(afNone, afProd))), "usr-L",
		"обратное направление: метка добавлена — аудитория после")

	t.Run("близнец: первым Update меняется описание, метка остаётся", func(t *testing.T) {
		tw.afServe(t)
		require.Contains(t, tw.afMustAudience(t, md, afVol("vol-33", 2, q2, afUpdated(afProd, afProd))), "usr-L")
		require.Contains(t, tw.afMustAudience(t, md, afVol("vol-33", 3, q3, afUpdated(afProd, afProd))), "usr-L")
	})
}

// ── NTF3-171 ────────────────────────────────────────────────────────────────

func TestNTF3171_ListEventAudiencePagesAndRefusesInput(t *testing.T) {
	afSkipShort(t)
	w, _, v31u, _ := af165(t)
	md := afRequireListMethod(t)
	w.afServe(t)
	want := afPlus(afGW9, "usr-R")

	t.Run("обход page_size=4: страниц 3 (4+4+2), id по возрастанию, повторов нет", func(t *testing.T) {
		var all []string
		var sizes []int
		token := ""
		for i := 0; i < 10; i++ {
			page, err := w.afList(t, ntfNotifySAN, md, afListReq(t, md, v31u, token, 4))
			require.NoError(t, err, "страница %d", i+1)
			all = append(all, page.subjects...)
			sizes = append(sizes, len(page.subjects))
			if page.next == "" {
				break
			}
			token = page.next
		}
		require.Equal(t, []int{4, 4, 2}, sizes)
		require.Equal(t, want, afUsers(t, all), "объединение — ровно 10 субъектов V31u, по возрастанию")
	})
	t.Run("близнец обхода page_size=0 (умолчание 50): одна страница", func(t *testing.T) {
		page, err := w.afList(t, ntfNotifySAN, md, afListReq(t, md, v31u, "", 0))
		require.NoError(t, err)
		require.Equal(t, want, afUsers(t, page.subjects))
		require.Empty(t, page.next)
	})

	// База каждой буквы — вызов без курсора и без page_size; в букве меняется
	// одно поле. Вопросов об аудитории у отказа 0 (положительный контроль —
	// база).
	base := func() afEvent { return v31u }
	w.db.wire.reset()
	_, err := w.afList(t, ntfNotifySAN, md, afListReq(t, md, base(), "", 0))
	require.NoError(t, err)
	require.Positive(t, afAudienceStatements(w.db.wire), "положительный контроль: база задаёт вопрос об аудитории")

	refused := func(t *testing.T, e afEvent, token string, size int64, message, field, reason string) {
		t.Helper()
		w.db.wire.reset()
		_, err := w.afList(t, ntfNotifySAN, md, afListReq(t, md, e, token, size))
		afRequireRefusal(t, err, "InvalidArgument", message, field, reason)
		require.Zero(t, afAudienceStatements(w.db.wire), "вопросов об аудитории у отказа входа 0")
	}
	t.Run("(а) page_size=1001; близнец 1000", func(t *testing.T) {
		refused(t, base(), "", 1001, "", "page_size", "")
		page, err := w.afList(t, ntfNotifySAN, md, afListReq(t, md, base(), "", 1000))
		require.NoError(t, err)
		require.Equal(t, want, afUsers(t, page.subjects))
	})
	t.Run("(б) page_size=-1; близнец 0", func(t *testing.T) {
		refused(t, base(), "", -1, "", "page_size", "")
	})
	t.Run("(в) непримененное поколение и мусорный курсор — отказ курсора, а не барьер", func(t *testing.T) {
		e := base()
		e.gen = 3
		refused(t, e, "!!not-a-cursor!!", 0, "", "page_token", "")
		_, err := w.afList(t, ntfNotifySAN, md, afListReq(t, md, e, "", 0))
		afRequireRefusal(t, err, "Unavailable", "", "", "OBJECT_GENERATION_NOT_APPLIED")
	})
	t.Run("(г) мусорный page_token", func(t *testing.T) {
		refused(t, base(), "!!not-a-cursor!!", 0, "", "page_token", "")
	})
	t.Run("(д) object пуст", func(t *testing.T) {
		e := base()
		e.object = ""
		refused(t, e, "", 0, "object: required", "", "")
	})
	t.Run("(е) source_version не задана", func(t *testing.T) {
		e := base()
		e.gen = 0
		refused(t, e, "", 0, "source_version: required", "", "")
	})
	t.Run("(ж) object без типа и тип вне опубликованных видов", func(t *testing.T) {
		e := base()
		e.object = "vol-31"
		refused(t, e, "", 0, "", "object", "")
		e.object = "geo_zone:zn-1"
		refused(t, e, "", 0, "", "object", "")
	})
	t.Run("(з) authz_rev не задан", func(t *testing.T) {
		e := base()
		e.rev = ""
		refused(t, e, "", 0, "authz_rev: required", "", "")
	})
	t.Run("(и) вызывающий вне круга notify; близнец — service:notify", func(t *testing.T) {
		_, err := w.afList(t, rdStorageSAN, md, afListReq(t, md, base(), "", 0))
		afRequireRefusal(t, err, "PermissionDenied", "permission denied", "", "AUTHZ_DENIED")
		require.Equal(t, want, w.afMustAudience(t, md, base()))
	})
}

// ── NTF3-173 ────────────────────────────────────────────────────────────────

func TestNTF3173_ResolveEventAndAccountReaderOutcomesAndRefusals(t *testing.T) {
	afSkipShort(t)
	w := newAFWorld(t)
	r1 := w.afToken(t)
	w.afApply(t, afVolume, "vol-1", 1, afCreated(afProd))
	afRequireDoor(t, w.door, "user:usr-A", "v_get", afVolume+":vol-1", true)
	afRequireResolveForm(t, "event")
	afRequireResolveForm(t, "account_reader")
	afRequireListMethod(t)
	w.afServe(t)

	base := afVol("vol-1", 1, r1, afCreated(afProd))
	w.db.wire.reset()
	resp, err := w.afResolve(t, ntfNotifySAN, afResolveEvent(t, afNamespace, "user:usr-A", base, false))
	require.NoError(t, err, "база NTF3-23")
	rdRequireAddress(t, resp, "a@example.test")
	require.Positive(t, afAudienceStatements(w.db.wire), "положительный контроль: база задаёт вопрос об аудитории")

	refused := func(t *testing.T, req *iamv1.ResolveRecipientRequest, message string) {
		t.Helper()
		w.db.wire.reset()
		_, err := w.afResolve(t, ntfNotifySAN, req)
		afRequireRefusal(t, err, "InvalidArgument", message, "", "")
		require.Zero(t, afAudienceStatements(w.db.wire), "вопросов у отказа входа 0")
	}
	t.Run("(а) audience.event.object пуст", func(t *testing.T) {
		e := base
		e.object = ""
		refused(t, afResolveEvent(t, afNamespace, "user:usr-A", e, false), "audience.event.object: required")
	})
	t.Run("(б) audience.event.source_version не задана", func(t *testing.T) {
		e := base
		e.gen = 0
		refused(t, afResolveEvent(t, afNamespace, "user:usr-A", e, false), "audience.event.source_version: required")
	})
	t.Run("(в) subject пуст", func(t *testing.T) {
		refused(t, afResolveEvent(t, afNamespace, "", base, false), "subject: required")
	})
	t.Run("(г) subject без id", func(t *testing.T) {
		refused(t, afResolveEvent(t, afNamespace, "user:", base, false), "subject: required")
	})
	t.Run("(д) namespace пуст", func(t *testing.T) {
		refused(t, afResolveEvent(t, "", "user:usr-A", base, false), "namespace: required")
	})
	t.Run("(н) audience.event.authz_rev не задан", func(t *testing.T) {
		e := base
		e.rev = ""
		refused(t, afResolveEvent(t, afNamespace, "user:usr-A", e, false), "audience.event.authz_rev: required")
	})
	t.Run("account_reader: база и (е), (ж)", func(t *testing.T) {
		resp, err := w.afResolve(t, ntfNotifySAN, afResolveAccountReader(t, "notify", "user:usr-own", "acc-1"))
		require.NoError(t, err)
		rdRequireAddress(t, resp, "own@example.test")
		refused(t, afResolveAccountReader(t, "notify", "user:usr-own", ""), "audience.account_reader.account_id: required")
		refused(t, afResolveAccountReader(t, "notify", "", "acc-1"), "subject: required")
	})
	t.Run("исходы по субъекту (з)–(л)", func(t *testing.T) {
		resp, err := w.afResolve(t, ntfNotifySAN, afResolveEvent(t, afNamespace, "user:usr-X", base, false))
		require.NoError(t, err)
		rdRequireOutcome(t, resp, iamv1.RecipientOutcome_RECIPIENT_OUTCOME_AUDIENCE_DENIED)
		resp, err = w.afResolve(t, ntfNotifySAN, afResolveAccountReader(t, "notify", "user:usr-X", "acc-1"))
		require.NoError(t, err)
		rdRequireOutcome(t, resp, iamv1.RecipientOutcome_RECIPIENT_OUTCOME_AUDIENCE_DENIED)
		resp, err = w.afResolve(t, ntfNotifySAN, afResolveAccountReader(t, "notify", "user:usr-blk", "acc-1"))
		require.NoError(t, err)
		rdRequireOutcome(t, resp, iamv1.RecipientOutcome_RECIPIENT_OUTCOME_SUBJECT_INACTIVE)
	})
	t.Run("(м) непримененное поколение — отказ UNAVAILABLE, а не исход", func(t *testing.T) {
		e := base
		e.gen = 2
		_, err := w.afResolve(t, ntfNotifySAN, afResolveEvent(t, afNamespace, "user:usr-A", e, false))
		afRequireRefusal(t, err, "Unavailable", "", "", "OBJECT_GENERATION_NOT_APPLIED")
	})
}

// ── NTF3-170 (а) · NTF3-174 (л): барьер поколения ──────────────────────────

func TestNTF3K3_UnappliedGenerationIsUnavailableNotGuessed(t *testing.T) {
	afSkipShort(t)
	w := newAFWorld(t)
	w.afApply(t, afVolume, "vol-37", 1, afCreated(afNone))
	r2 := w.afToken(t)
	md := afRequireListMethod(t)
	w.afServe(t)

	e2 := afVol("vol-37", 2, r2, afUpdated(afNone, afNone))
	_, err := w.afAudience(t, md, e2)
	afRequireRefusal(t, err, "Unavailable", "", "", "OBJECT_GENERATION_NOT_APPLIED")

	// Близнец по одному факту — поколение 2 применено: ответ без отказа,
	// аудитория тома без меток — 8 субъектов (usr-L не входит).
	w.afApply(t, afVolume, "vol-37", 2, afUpdated(afNone, afNone))
	require.Equal(t, afMinus(afGW9, "usr-L"), w.afMustAudience(t, md, e2))
}

// ── NTF3-174 (е), (з): право, изменённое после токена, адресата не даёт ────

func TestNTF3K3_RightChangedAfterTheTokenClosesTheQuestion(t *testing.T) {
	afSkipShort(t)
	w := newAFWorld(t)
	r1 := w.afToken(t)
	w.afApply(t, afVolume, "vol-41", 1, afCreated(afProd))
	md := afRequireListMethod(t)
	w.afServe(t)
	e1 := afVol("vol-41", 1, r1, afCreated(afProd))

	// Близнец — вопрос до изменения прав.
	require.Equal(t, afSorted(afGW9...), w.afMustAudience(t, md, e1))

	// (е) привязка usr-B снята после R1.
	w.afRevoke(t, "acb-k3-b")
	afRequireDoor(t, w.door, "user:usr-B", "v_get", afVolume+":vol-41", false)
	require.Equal(t, afMinus(afGW9, "usr-B"), w.afMustAudience(t, md, e1), "(е) право usr-B изменилось после R1")

	// (з) usr-D исключён из grp-1 после R1.
	afExec(t, w.db, "исключение usr-D из grp-1", `DELETE FROM kaname.group_members WHERE group_id = 'grp-1' AND member_id = 'usr-D'`)
	afRequireDoor(t, w.door, "user:usr-D", "v_get", afVolume+":vol-41", false)
	require.Equal(t, afMinus(afGW9, "usr-B", "usr-D"), w.afMustAudience(t, md, e1), "(з) выход из группы после R1")
}

// ── NTF3-174 (м): выдача после токена не открывает событие ─────────────────

func TestNTF3K3_GrantAfterTheTokenDoesNotOpenTheEvent(t *testing.T) {
	afSkipShort(t)
	build := func(t *testing.T, grantBeforeToken bool) (*afWorld, afEvent) {
		t.Helper()
		w := newAFWorld(t)
		x := afBinding{"acb-k3-x", "user", "usr-X", afRoleModule, "project", "prj-1"}
		if grantBeforeToken {
			w.afBind(t, x)
		}
		r1 := w.afToken(t)
		if !grantBeforeToken {
			w.afBind(t, x)
		}
		afRequireDoor(t, w.door, "user:usr-X", "v_get", "project:prj-1", false)
		w.afApply(t, afVolume, "vol-41", 1, afCreated(afProd))
		// Применение v1 пишет материализованные кортежи по всем привязкам
		// области, в том числе usr-X: дверь его видит.
		afRequireDoor(t, w.door, "user:usr-X", "v_get", afVolume+":vol-41", true)
		return w, afVol("vol-41", 1, r1, afCreated(afProd))
	}
	w, e := build(t, false)
	tw, te := build(t, true)

	md := afRequireListMethod(t)
	w.afServe(t)
	require.Equal(t, afSorted(afGW9...), w.afMustAudience(t, md, e),
		"привязка usr-X записана после R1 — за оградой, хотя применение v1 видит её")
	tw.afServe(t)
	require.Equal(t, afPlus(afGW9, "usr-X"), tw.afMustAudience(t, md, te), "близнец: привязка до R1 — 10 субъектов")
}

// ── гонка ограды: токен — ПОЛНЫЙ снимок, а не его нижняя граница ────────────

// TestNTF3K3_ConcurrentGrantsAreJudgedByTheFullSnapshot — восемь конкурирующих
// транзакций выдают права пользователям usr-P0…P7; чётные коммитятся до снятия
// токена, нечётные — после, будучи открытыми в момент снятия. Нижний предел
// снимка удерживает долгая транзакция, начатая раньше всех.
//
// Ограда «authz_rev < xmin(R)» отбросила бы чётных (их xid не ниже xmin, а в
// снимке они видны); ограда «authz_rev < xmax(R)» пропустила бы нечётных (их xid
// ниже xmax, а в снимке они не видны). Верен только ответ по видимости в
// снимке — и оракул пробы считает ожидаемое тем же выражением базы.
func TestNTF3K3_ConcurrentGrantsAreJudgedByTheFullSnapshot(t *testing.T) {
	afSkipShort(t)
	w := newAFWorld(t)
	w.afApply(t, afVolume, "vol-50", 1, afCreated(afProd))
	long := w.afBegin(t)

	const n = 8
	holds := make([]*afHold, n)
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		holds[i] = w.afBegin(t)
	}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx := context.Background()
			id, user := fmt.Sprintf("acb-k3-p%d", i), fmt.Sprintf("usr-P%d", i)
			if _, err := holds[i].tx.Exec(ctx, `
				INSERT INTO kaname.access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
				VALUES ($1, 'user', $2, $3, 'project', 'prj-1', 'ACTIVE')`, id, user, afRoleModule); err != nil {
				errs <- err
				return
			}
			if _, err := holds[i].tx.Exec(ctx, `
				INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id) VALUES ($1, 'user', $2)`,
				id, user); err != nil {
				errs <- err
				return
			}
			if i%2 == 0 {
				if err := holds[i].tx.Commit(ctx); err != nil {
					errs <- err
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		afBroken(t, "конкурирующая выдача: %v", err)
	}
	r := w.afToken(t)
	for i := 1; i < n; i += 2 {
		holds[i].afCommit(t)
	}
	long.afCommit(t)

	// Оракул и построение близнецов — до вопроса.
	want := append([]string(nil), afGW9...)
	for i := 0; i < n; i++ {
		visible := w.afVisible(t, holds[i].xid, r)
		if visible != (i%2 == 0) {
			afBroken(t, "оракул: транзакция usr-P%d (%s) видна в %s = %v, построение ждало %v", i, holds[i].xid, r, visible, i%2 == 0)
		}
		var belowXmin bool
		if err := w.db.fixture.QueryRow(context.Background(),
			`SELECT $1::xid8 < pg_snapshot_xmin($2::pg_snapshot)`, holds[i].xid, r).Scan(&belowXmin); err != nil {
			afBroken(t, "сравнение с xmin: %v", err)
		}
		if belowXmin {
			afBroken(t, "транзакция usr-P%d ниже xmin снимка — близнец «видна, хотя не ниже xmin» не построен", i)
		}
		if visible {
			want = append(want, fmt.Sprintf("usr-P%d", i))
		}
		afRequireDoor(t, w.door, fmt.Sprintf("user:usr-P%d", i), "v_get", afVolume+":vol-50", true)
	}

	md := afRequireListMethod(t)
	w.afServe(t)
	require.Equal(t, afSorted(want...), w.afMustAudience(t, md, afVol("vol-50", 1, r, afCreated(afProd))),
		"адресат — ровно тот, чья выдача видна в снимке R: закоммиченные до снятия есть, шедшие в момент снятия — нет")
}

// ── NTF3-176 ────────────────────────────────────────────────────────────────

func af176(t *testing.T, opts ...afWorldOption) (*afWorld, afEvent) {
	t.Helper()
	w := newAFWorld(t, opts...)
	w.afApply(t, afVolume, "vol-42", 1, afCreated(afProd))
	r2 := w.afToken(t)
	w.afApply(t, afVolume, "vol-42", 2, afUpdated(afProd, afProd))
	return w, afVol("vol-42", 2, r2, afUpdated(afProd, afProd))
}

func TestNTF3176_ClusterLevelRightOnlyViaSubscription(t *testing.T) {
	afSkipShort(t)
	w, e := af176(t)
	afRequireDoor(t, w.door, "user:usr-ca", "v_get", afVolume+":vol-42", true)
	// Близнец — до вопроса: usr-ca — администратор на acc-1, а не на кластере.
	tw, te := af176(t, afNoClusterAdmin(), afAdminOnAccount("acb-k3-ca", "usr-ca"))
	afRequireDoor(t, tw.door, "user:usr-ca", "v_get", afVolume+":vol-42", true)

	md := afRequireListMethod(t)
	afRequireResolveForm(t, "event")
	w.afServe(t)
	require.NotContains(t, w.afMustAudience(t, md, e), "usr-ca", "право только уровня кластера аудитории не образует")
	resp, err := w.afResolve(t, ntfNotifySAN, afResolveEvent(t, afNamespace, "user:usr-ca", e, true))
	require.NoError(t, err)
	rdRequireAddress(t, resp, "ca@example.test")
	resp, err = w.afResolve(t, ntfNotifySAN, afResolveEvent(t, afNamespace, "user:usr-ca", e, false))
	require.NoError(t, err)
	rdRequireOutcome(t, resp, iamv1.RecipientOutcome_RECIPIENT_OUTCOME_AUDIENCE_DENIED)

	t.Run("близнец: usr-ca — администратор на acc-1, а не на кластере", func(t *testing.T) {
		tw.afServe(t)
		require.Contains(t, tw.afMustAudience(t, md, te), "usr-ca")
		resp, err := tw.afResolve(t, ntfNotifySAN, afResolveEvent(t, afNamespace, "user:usr-ca", te, false))
		require.NoError(t, err)
		rdRequireAddress(t, resp, "ca@example.test")
	})
}

// ── NTF3-177 ────────────────────────────────────────────────────────────────

// af177 — vol-41 применён; кортеж `user:usr-K v_get storage_volume:vol-41`
// с условием condition либо без него (""). С25 строится условием модели
// продукта `mfa_fresh` — единственным, которое вычисляет дверь службы
// доступа на этом дереве (§8 приёмки называет `non_expired` — его в модели
// нет; правило Д133 (4) от имени условия не зависит).
func af177(t *testing.T, condition string) (*afWorld, afEvent) {
	t.Helper()
	w := newAFWorld(t)
	w.afApply(t, afVolume, "vol-41", 1, afCreated(afProd))
	if condition == "" {
		afExec(t, w.db, "безусловный кортеж usr-K", `
			INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
			VALUES ('storage_volume', 'vol-41', 'v_get', 'user:usr-K')`)
		afRequireDoor(t, w.door, "user:usr-K", "v_get", afVolume+":vol-41", true)
	} else {
		afExec(t, w.db, "условный кортеж usr-K", `
			INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject, condition_name, condition_params)
			VALUES ('storage_volume', 'vol-41', 'v_get', 'user:usr-K', $1, '{}'::jsonb)`, condition)
		// С25: Check с контекстом, где условие истинно, — true; без довода — нет.
		verdict, err := afAskWithContext(t, w, "user:usr-K", "vol-41", true)
		if err != nil || !verdict {
			afNotRun(t, "С25 (условное отношение в модели обвязки): Check(user:usr-K, v_get, storage_volume:vol-41) "+
				"с истинным условием %s — %v, %v", condition, verdict, err)
		}
		verdict, err = afAskWithContext(t, w, "user:usr-K", "vol-41", false)
		if err != nil || verdict {
			afBroken(t, "С25: условие %s без довода дало %v, %v — кортеж не условный", condition, verdict, err)
		}
	}
	return w, afVol("vol-41", 1, w.afToken(t), afCreated(afProd))
}

func TestNTF3177_ConditionalRightFormsNoAudience(t *testing.T) {
	afSkipShort(t)
	w, e := af177(t, "mfa_fresh")
	tw, te := af177(t, "") // близнец — до вопроса: тот же кортеж без условия

	md := afRequireListMethod(t)
	afRequireResolveForm(t, "event")
	w.afServe(t)
	require.NotContains(t, w.afMustAudience(t, md, e), "usr-K", "условное право аудитории не образует")
	for _, via := range []bool{false, true} {
		resp, err := w.afResolve(t, ntfNotifySAN, afResolveEvent(t, afNamespace, "user:usr-K", e, via))
		require.NoError(t, err)
		rdRequireOutcome(t, resp, iamv1.RecipientOutcome_RECIPIENT_OUTCOME_AUDIENCE_DENIED)
	}
	t.Run("близнец: тот же кортеж без условия", func(t *testing.T) {
		tw.afServe(t)
		require.Contains(t, tw.afMustAudience(t, md, te), "usr-K")
		for _, via := range []bool{false, true} {
			resp, err := tw.afResolve(t, ntfNotifySAN, afResolveEvent(t, afNamespace, "user:usr-K", te, via))
			require.NoError(t, err)
			rdRequireAddress(t, resp, "k@example.test")
		}
	})
}

// ── NTF3-178 ────────────────────────────────────────────────────────────────

// af178 — vol-43 создан; затем usr-O получает выдачу с закрытым набором
// объектов [vol-43]; затем (revokeFirst — отдельным снятием выдачи) том снят.
func af178(t *testing.T, revokeFirst bool) (w *afWorld, created, deleted afEvent) {
	t.Helper()
	w = newAFWorld(t)
	r1 := w.afToken(t)
	w.afApply(t, afVolume, "vol-43", 1, afCreated(afProd))
	w.afClosedSet(t, "acb-k3-o", "usr-O", afRoleType, "vol-43")
	afRequireDoor(t, w.door, "user:usr-O", "v_get", afVolume+":vol-43", true)
	if revokeFirst {
		w.afRevoke(t, "acb-k3-o")
		afRequireDoor(t, w.door, "user:usr-O", "v_get", afVolume+":vol-43", false)
	}
	r2 := w.afToken(t)
	w.afUnapply(t, afVolume, "vol-43", 2)
	afRequireDoor(t, w.door, "user:usr-O", "v_get", afVolume+":vol-43", false)
	return w, afVol("vol-43", 1, r1, afCreated(afProd)), afVol("vol-43", 2, r2, afCreated(afProd))
}

func TestNTF3178_DeletedReachesHoldersOfCascadeRemovedGrants(t *testing.T) {
	afSkipShort(t)
	w, created, deleted := af178(t, false)
	tw, _, td := af178(t, true) // близнец — до вопроса

	md := afRequireListMethod(t)
	w.afServe(t)
	require.Equal(t, afPlus(afGW9, "usr-O"), w.afMustAudience(t, md, deleted),
		"DELETED — аудитория до снятия по фактам g_E−1 и держатель выдачи на сам объект, снятой каскадом")
	require.NotContains(t, w.afMustAudience(t, md, created), "usr-O", "выдача после события CREATED его не открывает")

	t.Run("близнец: выдача usr-O снята отдельным действием до снятия тома", func(t *testing.T) {
		tw.afServe(t)
		require.Equal(t, afSorted(afGW9...), tw.afMustAudience(t, md, td))
	})
}

// ── NTF3-181 ────────────────────────────────────────────────────────────────

func TestNTF3181_FenceAtInfinityEqualsLiveSubjects(t *testing.T) {
	afSkipShort(t)
	w := newAFWorld(t)
	objects := []struct {
		id    string
		facts afFacts
	}{
		{"vol-p", afCreated(afProd)}, {"vol-d", afCreated(afDev)}, {"vol-n", afCreated(afNone)},
	}
	for _, o := range objects {
		w.afApply(t, afVolume, o.id, 1, o.facts)
	}
	w.afNamesRole(t, "rol-k3-names-n", "vol-n")
	w.afBind(t, afBinding{"acb-k3-r", "user", "usr-R", "rol-k3-names-n", "project", "prj-1"})
	afRequireDoor(t, w.door, "user:usr-R", "v_get", afVolume+":vol-n", true)
	afRequireDoor(t, w.door, "user:usr-ca", "v_get", afVolume+":vol-p", true)
	rInf := w.afToken(t)
	live := map[string][]string{}
	for _, o := range objects {
		live[o.id] = afLiveSubjects(t, w.db, afVolume, o.id)
		if len(live[o.id]) == 0 {
			afBroken(t, "relverdict.Subjects(%s) пуст — паритет судил бы пустое", o.id)
		}
	}
	md := afRequireListMethod(t)
	w.afServe(t)

	t.Run("(а) ограда на бесконечности = живое перечисление за вычетом классов Р30", func(t *testing.T) {
		for _, o := range objects {
			answer := w.afMustAudience(t, md, afVol(o.id, 1, rInf, o.facts))
			leaked, unexplained, classes := afParity(t, w.db, live[o.id], answer)
			require.Empty(t, leaked, "%s: субъекты ответа вне relverdict.Subjects", o.id)
			require.Empty(t, unexplained, "%s: субъекты relverdict.Subjects вне ответа без класса исключения Р30", o.id)
			require.Equal(t, "только уровень кластера", classes["user:usr-ca"], "%s: класс usr-ca", o.id)
			require.Equal(t, "сервисный аккаунт", classes["service_account:sva-1"], "%s: класс sva-1", o.id)
			t.Logf("%s: ответ %d, перечисление %d, исключено по классам %v", o.id, len(answer), len(live[o.id]), classes)
		}
	})
	t.Run("(б) правка строки права после токена (срок привязки) закрывает вопрос", func(t *testing.T) {
		e := afVol("vol-p", 1, w.afToken(t), afCreated(afProd))
		require.Contains(t, w.afMustAudience(t, md, e), "usr-B", "близнец — правки нет")
		afExec(t, w.db, "срок привязки usr-B", `UPDATE kaname.access_bindings SET expires_at = now() + interval '30 days' WHERE id = 'acb-k3-b'`)
		afRequireDoor(t, w.door, "user:usr-B", "v_get", afVolume+":vol-p", true)
		require.NotContains(t, w.afMustAudience(t, md, e), "usr-B", "право usr-B изменилось после R")
	})
}

// afAskWithContext — вопрос формы о v_get; satisfied — контекст, в котором
// условие `mfa_fresh` истинно (С25), иначе — только «сейчас».
func afAskWithContext(t *testing.T, w *afWorld, subject, volumeID string, satisfied bool) (bool, error) {
	t.Helper()
	ctx := context.Background()
	tx, err := w.db.fixture.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now().UTC()
	cond := map[string]any{"current_time": now}
	if satisfied {
		cond = map[string]any{"current_time": now, "mfa_at": now, "acr_value": "3", "amr_claims": []any{"webauthn"}}
	}
	v, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
		Subject: subject, ObjectType: afVolume, ObjectID: volumeID, Relation: "v_get", Context: cond,
	})
	return v == relverdict.Allow, err
}

// ── NTF3-168 (г): право, изменённое после R_E, закрывает Resolve{event} ─────

// af168g — vol-36 создан (поколение 1), затем переход в ERROR (поколение 2,
// токен R2); revoke — когда снимается привязка usr-A: "after" — после R2,
// "before" — до R2, "" — не снимается.
func af168g(t *testing.T, revoke string) (*afWorld, afEvent) {
	t.Helper()
	w := newAFWorld(t)
	w.afApply(t, afVolume, "vol-36", 1, afCreated(afNone))
	if revoke == "before" {
		w.afRevoke(t, "acb-k3-a")
	}
	r2 := w.afToken(t)
	w.afApply(t, afVolume, "vol-36", 2, afUpdated(afNone, afNone))
	if revoke == "after" {
		w.afRevoke(t, "acb-k3-a")
	}
	afRequireDoor(t, w.door, "user:usr-A", "v_get", afVolume+":vol-36", revoke == "")
	return w, afVol("vol-36", 2, r2, afUpdated(afNone, afNone))
}

func TestNTF3168g_RightChangedAfterTheEventDeniesTheAddressedRow(t *testing.T) {
	afSkipShort(t)
	for _, c := range []struct {
		name, revoke string
		address      bool
	}{
		{"привязка usr-A снята после R_E — AUDIENCE_DENIED", "after", false},
		{"близнец: привязка не снимается — ADDRESS", "", true},
		{"привязка снята до записи перехода — AUDIENCE_DENIED", "before", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, e := af168g(t, c.revoke)
			afRequireResolveForm(t, "event")
			afRequireListMethod(t)
			w.afServe(t)
			resp, err := w.afResolve(t, ntfNotifySAN, afResolveEvent(t, afNamespace, "user:usr-A", e, false))
			require.NoError(t, err)
			if c.address {
				rdRequireAddress(t, resp, "a@example.test")
				return
			}
			rdRequireOutcome(t, resp, iamv1.RecipientOutcome_RECIPIENT_OUTCOME_AUDIENCE_DENIED)
		})
	}
}

// ── NTF3-174 (а), (б), (в), (и): ограда поколений одного объекта ──────────

// af174 — порядок (а)–(в) на vol-41: v1 {env: prod}, v2 {}, v3 {}; затем
// (holderRevoked — выдача usr-O снята отдельным действием до снятия) выдача
// usr-O с закрытым набором [vol-41] и снятие v4. Токен Rn снят перед
// применением vn (С24).
func af174(t *testing.T, holderRevoked bool, opts ...afWorldOption) (w *afWorld, v1, v2, v3, v4 afEvent) {
	t.Helper()
	w = newAFWorld(t, opts...)
	r1 := w.afToken(t)
	w.afApply(t, afVolume, "vol-41", 1, afCreated(afProd))
	r2 := w.afToken(t)
	w.afApply(t, afVolume, "vol-41", 2, afUpdated(afProd, afNone))
	r3 := w.afToken(t)
	w.afApply(t, afVolume, "vol-41", 3, afUpdated(afNone, afNone))
	w.afClosedSet(t, "acb-k3-o", "usr-O", afRoleType, "vol-41")
	afRequireDoor(t, w.door, "user:usr-O", "v_get", afVolume+":vol-41", true)
	if holderRevoked {
		w.afRevoke(t, "acb-k3-o")
		afRequireDoor(t, w.door, "user:usr-O", "v_get", afVolume+":vol-41", false)
	}
	r4 := w.afToken(t)
	w.afUnapply(t, afVolume, "vol-41", 4)
	return w,
		afVol("vol-41", 1, r1, afCreated(afProd)),
		afVol("vol-41", 2, r2, afUpdated(afProd, afNone)),
		afVol("vol-41", 3, r3, afUpdated(afNone, afNone)),
		// DELETED — факты объекта до снятия (поколение v3).
		afVol("vol-41", 4, r4, afCreated(afNone))
}

func TestNTF3174_GenerationsOfOneObjectUnderTheFence(t *testing.T) {
	afSkipShort(t)
	w, v1, v2, v3, v4 := af174(t, false)
	// Миры близнецов — до вопроса о предмете.
	hw, _, _, _, h4 := af174(t, true)
	aw, a1, a2, a3, a4 := af174(t, false, afNoClusterAdmin(), afAdminOnAccount("acb-k3-ca", "usr-ca"))
	afRequireDoor(t, w.door, "user:usr-ca", "system_admin", "cluster:cluster_root", true)
	afRequireDoor(t, aw.door, "user:usr-ca", "v_get", "account:acc-1", true)

	md := afRequireListMethod(t)
	w.afServe(t)

	t.Run("(а) аудитория v1 — 9 по исходным строкам до R1; строки применения v1 не читаются", func(t *testing.T) {
		require.Equal(t, afSorted(afGW9...), w.afMustAudience(t, md, v1))
	})
	t.Run("(б) v2 — объединение до и после (с usr-L); v3 — без usr-L", func(t *testing.T) {
		require.Equal(t, afSorted(afGW9...), w.afMustAudience(t, md, v2))
		require.Equal(t, afMinus(afGW9, "usr-L"), w.afMustAudience(t, md, v3))
	})
	t.Run("(в) v4 — по фактам v3 и с держателем выдачи на сам объект, снятой каскадом", func(t *testing.T) {
		require.Equal(t, afPlus(afMinus(afGW9, "usr-L"), "usr-O"), w.afMustAudience(t, md, v4))
		afRequireDoor(t, w.door, "user:usr-O", "v_get", afVolume+":vol-41", false)
	})
	t.Run("(в) близнец: выдача usr-O снята отдельным действием до снятия объекта", func(t *testing.T) {
		hw.afServe(t)
		require.Equal(t, afMinus(afGW9, "usr-L"), hw.afMustAudience(t, md, h4))
	})
	t.Run("(и) администратор облака — ни в одном ответе v1–v4", func(t *testing.T) {
		for _, e := range []afEvent{v1, v2, v3, v4} {
			require.NotContains(t, w.afMustAudience(t, md, e), "usr-ca", "%s@%d: право только уровня кластера", e.object, e.gen)
		}
	})
	t.Run("(и) близнец: usr-ca — роль администратора на acc-1, а не на кластере", func(t *testing.T) {
		aw.afServe(t)
		for _, e := range []afEvent{a1, a2, a3, a4} {
			require.Contains(t, aw.afMustAudience(t, md, e), "usr-ca", "%s@%d: путь через account", e.object, e.gen)
		}
	})
}

// ── NTF3-183: досев старта службы доступа аудиторию не сужает ──────────────

// afRightsRevisions — `authz_rev` строк правил и глаголов ролей мира.
func afRightsRevisions(t *testing.T, db *ntfDB) map[string]string {
	t.Helper()
	rows, err := db.fixture.Query(context.Background(), `
		SELECT 'role_verb:' || role_id || ':' || object_type || ':' || verb, authz_rev::text FROM kaname.role_verb
		 UNION ALL
		SELECT 'role_rule_selectors:' || role_id || ':' || rule_fp, authz_rev::text FROM kaname.role_rule_selectors`)
	if err != nil {
		afBroken(t, "версии строк правил и глаголов: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			afBroken(t, "версии строк правил и глаголов: %v", err)
		}
		out[k] = v
	}
	if len(out) == 0 {
		afBroken(t, "строк правил и глаголов ролей 0 — сравнивать нечего")
	}
	return out
}

// afRestart — досев старта службы доступа теми же производителями, что в
// корне: выдача владельца и проекция селекторов, затем глаголы системных ролей.
func (w *afWorld) afRestart(t *testing.T) {
	t.Helper()
	if err := seed.BackfillOwnerBindings(context.Background(), w.db.fixture); err != nil {
		afBroken(t, "досев выдачи владельца: %v", err)
	}
	census, err := seed.ReseedSystemRoleVerbs(context.Background(), kanamepg.New(w.db.fixture, nil), w.db.fixture,
		catalogfixture.Facts(), nil)
	if err != nil || census.Failed > 0 {
		afBroken(t, "досев глаголов системных ролей: %+v, %v", census, err)
	}
}

func TestNTF3183_RestartBetweenEventAndQuestionDoesNotNarrowTheAudience(t *testing.T) {
	afSkipShort(t)
	build := func(t *testing.T, dropGet bool) (w *afWorld, e afEvent, before, after map[string]string) {
		t.Helper()
		w = newAFWorld(t)
		r1 := w.afToken(t)
		w.afApply(t, afVolume, "vol-41", 1, afCreated(afProd))
		before = afRightsRevisions(t, w.db)
		if dropGet {
			// Посев с иным содержимым: у роли привязки usr-M из набора глаголов
			// снят `get` (правило — кодером продукта).
			rules, err := domain.EncodeRules(domain.Rules{{Module: "storage", Resources: []string{"*"}, Verbs: []string{"list"}}})
			if err != nil {
				afBroken(t, "правило без get не кодируется: %v", err)
			}
			afExec(t, w.db, "правило роли usr-M без get", `UPDATE kaname.roles SET rules = $2::jsonb WHERE id = $1`,
				afRoleModuleM, string(rules))
		}
		w.afRestart(t)
		after = afRightsRevisions(t, w.db)
		afRequireDoor(t, w.door, "user:usr-M", "v_get", afVolume+":vol-41", !dropGet)
		return w, afVol("vol-41", 1, r1, afCreated(afProd)), before, after
	}
	w, e, before, after := build(t, false)
	tw, te, _, _ := build(t, true) // близнец — до вопроса
	require.Equal(t, before, after, "досев с прежним содержимым версию строк правил и глаголов не двигает")

	md := afRequireListMethod(t)
	w.afServe(t)
	require.Equal(t, afSorted(afGW9...), w.afMustAudience(t, md, e), "перезапуск после R1 аудиторию v1 не сужает")

	t.Run("близнец: досев снял get у роли usr-M", func(t *testing.T) {
		tw.afServe(t)
		require.Equal(t, afMinus(afGW9, "usr-M"), tw.afMustAudience(t, md, te),
			"пара «роль, get» снята посевом после R1 — право изменилось")
	})
}
