// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_audience_narrowing_test.go — перечень адресатов, названный заказчиком
// при выдаче, ЗАПИСЫВАЕТСЯ на строку ключа (задача #1136).
//
// # Зачем запись, если перечень и так уезжает в регистрацию
//
// Регистрация — у прежнего издателя, и на переведённом контуре её нет вовсе.
// Пока перечень существовал только в ней, на своей полосе выпуска у него не было
// читателя: поле принималось, возвращалось в ответе и не отвергало ни одного
// входа. Строка ключа — единственное место, откуда выпуск может его прочитать,
// не спрашивая постороннего.
//
// # Что здесь утверждается
//
// ЗАПИСАННОЕ ЗНАЧЕНИЕ, а не факт вызова: проба «репозиторий позвали» осталась бы
// зелёной на реализации, положившей туда пустой перечень, — то есть ровно на том
// дефекте, который эта работа снимает.
package sa_keys

import (
	"testing"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

const (
	audNarrowExternal = "https://sts.example.com"
	audNarrowRegistry = "registry.kacho.local"
)

// federatedSubjectsForNarrowing — федеративный вид ключа для проб этого файла.
func federatedSubjectsForNarrowing() []domain.TrustedSubject {
	return []domain.TrustedSubject{{
		Issuer:         "https://kube.cluster.local",
		SubjectPattern: "^system:serviceaccount:ci:deployer$",
		PublicKeyPEM:   testIssuerPublicKeyPEM,
		KeyAlgorithm:   "ES256",
	}}
}

// TestIssue_DeclaredAudienceIsRecordedOnTheKeyRow — перечень заказчика уезжает
// на строку ключа ДОСЛОВНО, и оба вида выдачи ведут себя одинаково.
//
// Разойдись они, федеративный ключ стал бы несужаемой дорогой внутрь — ровно та
// форма, которую ищут.
func TestIssue_DeclaredAudienceIsRecordedOnTheKeyRow(t *testing.T) {
	for name, subjects := range map[string][]domain.TrustedSubject{
		"с ключевым материалом": nil,
		"федеративный":          federatedSubjectsForNarrowing(),
	} {
		t.Run(name, func(t *testing.T) {
			h := newTTLHarness(t)
			h.uc.RegistryAudience = audNarrowRegistry

			err := h.issue(t, IssueInput{
				TrustedSubjects: subjects,
				Audience:        []string{audNarrowExternal},
			})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			waitForOp(t, h.ops)
			if !h.repo.insertOK {
				t.Fatal("предпосылка: строка ключа обязана быть закоммичена")
			}

			got := h.repo.inserted.DeclaredAudiences
			if len(got) != 1 || got[0] != audNarrowExternal {
				t.Fatalf("на строке записано %v, а заказчик назвал [%s]: сужение, не доехавшее до "+
					"строки, не имеет читателя на своей полосе выпуска", got, audNarrowExternal)
			}
			// Адресат реестра добавляется в перечень ЗЕРКАЛА (задача #320) и не
			// вправе попадать в сужение: он расширил бы ключ за пределы того,
			// что назвал заказчик, — молча и в сторону большего доступа.
			for _, a := range got {
				if a == audNarrowRegistry {
					t.Errorf("сужение %v несёт адресат зеркала %q — заказчик его не называл",
						got, audNarrowRegistry)
				}
			}
		})
	}
}

// TestIssue_WithoutDeclaredAudienceTheRowRecordsNoNarrowing — положительный
// контроль к предыдущей пробе.
//
// Без него отрицание зеленело бы на реализации, записывающей перечень ВСЕГДА:
// «сужения не объявлено» и «объявлено чем попало» на строке выглядят одинаково,
// пока не спросить оба входа.
func TestIssue_WithoutDeclaredAudienceTheRowRecordsNoNarrowing(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.RegistryAudience = audNarrowRegistry
	h.uc.AudiencePrefix = "https://internal.example/iam"

	if err := h.issue(t, IssueInput{}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, h.ops)

	if got := h.repo.inserted.DeclaredAudiences; len(got) != 0 {
		t.Fatalf("сужение %v записано ключу, который его не объявлял: перечень зеркала строится "+
			"иначе и сузил бы такой ключ до недостижимого", got)
	}
}

// TestIssue_DeclaredAudienceDropsEmptiesAndCollapsesDuplicates — форма
// записанного значения совпадает с объявленной контрактом.
//
// Пустой элемент — адресат, которого нельзя заказать ничем: он не совпал бы ни с
// одним запросом и молча сузил бы ключ до недостижимого.
func TestIssue_DeclaredAudienceDropsEmptiesAndCollapsesDuplicates(t *testing.T) {
	h := newTTLHarness(t)

	err := h.issue(t, IssueInput{
		Audience: []string{audNarrowExternal, "", audNarrowRegistry, audNarrowExternal, ""},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, h.ops)

	got := h.repo.inserted.DeclaredAudiences
	want := []string{audNarrowExternal, audNarrowRegistry}
	if len(got) != len(want) {
		t.Fatalf("записано %v; ожидалось %v (порядок сохраняется, пустые снимаются, повторы схлопываются)",
			got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("записано %v; ожидалось %v", got, want)
		}
	}
}

// TestIssue_OwnIssuance_ResponseEchoesTheRecordedNarrowing — ответ выдачи на
// переведённом контуре называет то, что ключ ДЕЙСТВИТЕЛЬНО сможет заказать.
//
// Прежде он эхом отдавал перечень зеркала — величину, которая на переведённом
// контуре не регистрируется нигде и не читается ничем. Ответ утверждал о ключе
// то, чего про него не верно.
func TestIssue_OwnIssuance_ResponseEchoesTheRecordedNarrowing(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.WithOwnIssuance()
	h.uc.RegistryAudience = audNarrowRegistry

	if err := h.issue(t, IssueInput{Audience: []string{audNarrowExternal}}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, h.ops)

	resp := &iamv1.IssueSAKeyResponse{}
	if err := anyUnmarshalTo(h.ops.lastResp, resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Audiences) != 1 || resp.Audiences[0] != audNarrowExternal {
		t.Fatalf("ответ называет %v, а ключ записан с сужением [%s]: перечень зеркала на "+
			"переведённом контуре не регистрируется нигде", resp.Audiences, audNarrowExternal)
	}
}

// TestIssue_MirroredContour_ResponseStillEchoesTheMirrorWhitelist —
// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к предыдущей пробе.
//
// Пока зеркало заводится, эхо перечня зеркала верно и обязано остаться: там он
// и вправду решает, какой обмен пройдёт. Без этой пары отрицание выше зеленело
// бы на правке, снявшей эхо со ВСЕХ посадок.
func TestIssue_MirroredContour_ResponseStillEchoesTheMirrorWhitelist(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.RegistryAudience = audNarrowRegistry

	if err := h.issue(t, IssueInput{Audience: []string{audNarrowExternal}}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, h.ops)

	resp := &iamv1.IssueSAKeyResponse{}
	if err := anyUnmarshalTo(h.ops.lastResp, resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Audiences) != 2 ||
		resp.Audiences[0] != audNarrowExternal || resp.Audiences[1] != audNarrowRegistry {
		t.Fatalf("ответ непереведённого контура = %v; ожидался перечень зеркала [%s %s]",
			resp.Audiences, audNarrowExternal, audNarrowRegistry)
	}
}

// TestIssue_OwnIssuance_ResponseWithoutNarrowingSaysSo — ключ, сужения не
// объявивший, получает ПУСТОЙ перечень в ответе, а не перечень зеркала.
//
// Пусто здесь — утверждение: «сужения нет, действует перечень посадки». Отдать
// вместо него перечень зеркала значило бы назвать адресатов, которых этот ключ
// заказать не сможет, и назвать не всех, кого сможет.
func TestIssue_OwnIssuance_ResponseWithoutNarrowingSaysSo(t *testing.T) {
	h := newTTLHarness(t)
	h.uc.WithOwnIssuance()
	h.uc.RegistryAudience = audNarrowRegistry
	h.uc.AudiencePrefix = "https://internal.example/iam"

	if err := h.issue(t, IssueInput{}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, h.ops)

	resp := &iamv1.IssueSAKeyResponse{}
	if err := anyUnmarshalTo(h.ops.lastResp, resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Audiences) != 0 {
		t.Fatalf("ответ называет %v, а сужения ключ не объявлял", resp.Audiences)
	}
}
