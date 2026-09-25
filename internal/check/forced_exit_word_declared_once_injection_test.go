// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// forced_exit_word_declared_once_injection_test.go — доказательство
// способности пробы KN-SER-10 упасть И смолчать (приёмка §6 п.12).
//
// Инъекция герметична: синтетический корпус подаётся прямо в разбор, поэтому
// роняет ТОЛЬКО проверяемое. Каждый отрицательный вход — законный близнец
// (`forcedExitLegalCorpus`) с ОДНИМ изменённым файлом; изменённый факт назван
// в имени случая и сверяется по координате находки, а не по её числу.
package check_test

import (
	"errors"
	"strings"
	"testing"
)

const forcedExitLegalDomain = `package domain

const (
	RevokeReasonLogout = "logout"
	// RevokeReasonAdminForceLogout — принудительный выход распорядителем.
	RevokeReasonAdminForceLogout = "admin-force-logout"
)
`

const forcedExitLegalVerb = `package internal_iam

import "github.com/PRO-Robotech/kaname/internal/domain"

func reasonOf(r string) string {
	if r == "" {
		return domain.RevokeReasonAdminForceLogout
	}
	return r
}

func teardownReason() string { return domain.RevokeReasonAdminForceLogout }
`

// forcedExitLegalContract — комментарий сгенерированного контракта несёт
// слово; литерала в нём нет (форма pb.go:808).
const forcedExitLegalContract = `package iamv1

// Reason — свободная причина; умолчание "admin-force-logout".
type ForceLogoutRequest struct{ Reason string }
`

func forcedExitLegalCorpus() map[string]string {
	return map[string]string{
		forcedExitDomainDeclRel: forcedExitLegalDomain,
		forcedExitVerbRel:       forcedExitLegalVerb,
		"pkg/api/kaname/cloud/iam/v1/internal_iam_service.pb.go": forcedExitLegalContract,
	}
}

func forcedExitJudge(t *testing.T, corpus map[string]string) forcedExitWordVerdict {
	t.Helper()
	v, err := judgeForcedExitWord(corpus)
	if err != nil {
		t.Fatalf("разбор инъекции отказал: %v", err)
	}
	if v.Files != len(corpus) {
		t.Fatalf("разобрано %d файлов из %d поданных — перепись не та", v.Files, len(corpus))
	}
	return v
}

// TestForcedExitWordGateStaysSilentOnLegalTwins — законные формы: молчание.
func TestForcedExitWordGateStaysSilentOnLegalTwins(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{"одно объявление домена, глагол ссылается, слово в комментарии контракта", func(map[string]string) {}},
		{"псевдоним импорта домена — та же ссылка", func(c map[string]string) {
			c[forcedExitVerbRel] = `package internal_iam

import d "github.com/PRO-Robotech/kaname/internal/domain"

func teardownReason() string { return d.RevokeReasonAdminForceLogout }
`
		}},
		{"одноимённый селектор ЧУЖОГО пакета — не селектор домена", func(c map[string]string) {
			c[forcedExitVerbRel] = `package internal_iam

import (
	"github.com/PRO-Robotech/kaname/internal/domain"
	other "example.invalid/other"
)

func reasons() []string { return []string{domain.RevokeReasonAdminForceLogout, other.RevokeReasonLogout} }
`
		}},
		{"слово в комментарии глагола — не литерал", func(c map[string]string) {
			c[forcedExitVerbRel] = forcedExitLegalVerb + "\n// причина — \"admin-force-logout\", см. домен\n"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			corpus := forcedExitLegalCorpus()
			tc.mutate(corpus)
			v := forcedExitJudge(t, corpus)
			if findings := v.Findings(); len(findings) != 0 {
				t.Fatalf("законный близнец дал находки: %v", findings)
			}
			if len(v.Literals) != 1 || v.DeclName != "RevokeReasonAdminForceLogout" || len(v.References) == 0 {
				t.Fatalf("молчание сказано не о предмете: литералов %d, объявление %q, ссылок %d",
					len(v.Literals), v.DeclName, len(v.References))
			}
		})
	}
}

// TestForcedExitWordGateRedsOnEveryDefect — один изменённый факт → находка с
// координатой этого факта.
func TestForcedExitWordGateRedsOnEveryDefect(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(map[string]string)
		// want — подстрока находки, называющая изменённый факт координатой.
		want string
	}{
		{"второй литерал слова в файле вне домена", func(c map[string]string) {
			c["internal/apps/kaname/api/user/reset_second_factor.go"] = `package user

func defaultReason() string { return "admin-force-logout" }
`
		}, "internal/apps/kaname/api/user/reset_second_factor.go:3"},
		{"литерал в глаголе при объявленном слове (естественный красный)", func(c map[string]string) {
			c[forcedExitVerbRel] = `package internal_iam

import "github.com/PRO-Robotech/kaname/internal/domain"

func reasonOf(r string) string {
	if r == "" {
		r = "admin-force-logout"
	}
	return r
}

func teardownReason() string { return domain.RevokeReasonAdminForceLogout }
`
		}, forcedExitVerbRel + ":7"},
		{"селектор domain.RevokeReasonLogout в глаголе", func(c map[string]string) {
			c[forcedExitVerbRel] = forcedExitLegalVerb + `
func legacy() string { return domain.RevokeReasonLogout }
`
		}, "селектор domain.RevokeReasonLogout в глаголе принудительного выхода: " + forcedExitVerbRel + ":14"},
		{"селектор RevokeReasonLogout через псевдоним импорта домена", func(c map[string]string) {
			c[forcedExitVerbRel] = `package internal_iam

import d "github.com/PRO-Robotech/kaname/internal/domain"

func teardownReason() string { return d.RevokeReasonAdminForceLogout }

func legacy() string { return d.RevokeReasonLogout }
`
		}, forcedExitVerbRel + ":7"},
		{"объявление домена есть, глагол на него не ссылается", func(c map[string]string) {
			c[forcedExitVerbRel] = `package internal_iam

func teardownReason() string { return "logout" }
`
		}, "не ссылается на объявление домена RevokeReasonAdminForceLogout"},
		{"слово объявлено переменной, а не константой домена", func(c map[string]string) {
			c[forcedExitDomainDeclRel] = `package domain

const RevokeReasonLogout = "logout"

var RevokeReasonAdminForceLogout = "admin-force-logout"
`
		}, "вне объявления домена (" + forcedExitDomainDeclRel + "): " + forcedExitDomainDeclRel + ":5"},
		{"слова нет вовсе", func(c map[string]string) {
			c[forcedExitDomainDeclRel] = `package domain

const RevokeReasonLogout = "logout"
`
			c[forcedExitVerbRel] = `package internal_iam

import "github.com/PRO-Robotech/kaname/internal/domain"

func teardownReason() string { return domain.RevokeReasonLogout }
`
		}, "узлов литерала \"admin-force-logout\" в дереве 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			corpus := forcedExitLegalCorpus()
			tc.mutate(corpus)
			v := forcedExitJudge(t, corpus)
			findings := v.Findings()
			if len(findings) == 0 {
				t.Fatalf("дефект НЕ найден: разбор промолчал (литералов %d, объявление %q, ссылок %d, запрещённых %d)",
					len(v.Literals), v.DeclName, len(v.References), len(v.Retired))
			}
			if !strings.Contains(strings.Join(findings, "\n"), tc.want) {
				t.Fatalf("находка не называет изменённый факт %q:\n  %s", tc.want, strings.Join(findings, "\n  "))
			}
		})
	}
}

// TestForcedExitWordGateRefusesAnEmptyWalk — пустой обход и обход без глагола
// — отказ, а не зелёное.
func TestForcedExitWordGateRefusesAnEmptyWalk(t *testing.T) {
	t.Parallel()
	if _, err := judgeForcedExitWord(map[string]string{}); !errors.Is(err, errForcedExitEmptyCorpus) {
		t.Fatalf("пустой корпус обязан давать отказ обхода, получено: %v", err)
	}
	withoutVerb := forcedExitLegalCorpus()
	delete(withoutVerb, forcedExitVerbRel)
	if _, err := judgeForcedExitWord(withoutVerb); err == nil || !strings.Contains(err.Error(), "предпосылка не выполнена") {
		t.Fatalf("корпус без глагола обязан давать отказ предпосылки, получено: %v", err)
	}
}
