// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package dto

import (
	"errors"
	"reflect"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Проверяем оба API на одном переводчике; реестр восстанавливается после пробы.
func TestConvertPreservesTransferResultsAndErrors(t *testing.T) {
	key := reflect.TypeFor[tag[domain.Account, *iamv1.Account]]()
	regMu.Lock()
	previous, present := transfersReg[key]
	delete(transfersReg, key)
	regMu.Unlock()
	t.Cleanup(func() {
		regMu.Lock()
		defer regMu.Unlock()
		if present {
			transfersReg[key] = previous
		} else {
			delete(transfersReg, key)
		}
	})

	src := domain.Account{ID: "account-source"}
	sentinel := errors.New("ошибка переводчика")
	result := &iamv1.Account{}
	for _, tc := range []struct {
		name string
		impl Interface[domain.Account, *iamv1.Account]
		want *iamv1.Account
		err  error
	}{
		{name: "missing"},
		{name: "success", impl: Fn[domain.Account, *iamv1.Account](func(domain.Account) (*iamv1.Account, error) { return result, nil }), want: result},
		{name: "nil_success", impl: Fn[domain.Account, *iamv1.Account](func(domain.Account) (*iamv1.Account, error) { return nil, nil })},
		{name: "partial_error", impl: Fn[domain.Account, *iamv1.Account](func(domain.Account) (*iamv1.Account, error) { return result, sentinel }), err: sentinel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			impl := tc.impl
			if impl != nil {
				impl = Fn[domain.Account, *iamv1.Account](func(got domain.Account) (*iamv1.Account, error) {
					calls++
					if !reflect.DeepEqual(got, src) {
						t.Fatal("переводчик получил другой источник")
					}
					return tc.impl.Transfer(got)
				})
			}
			regMu.Lock()
			if tc.impl == nil {
				delete(transfersReg, key)
			} else {
				transfersReg[key] = impl
			}
			regMu.Unlock()

			var previousAPI *iamv1.Account
			oldErr := Transfer(FromTo(src, &previousAPI))
			got, err := Convert[*iamv1.Account, domain.Account, *DTO[domain.Account, *iamv1.Account]](src)
			wantCalls := 0
			if tc.impl != nil {
				wantCalls = 2
			}
			if calls != wantCalls {
				t.Fatalf("число вызовов переводчика %d, ожидалось %d", calls, wantCalls)
			}
			if got != previousAPI || got != tc.want {
				t.Fatalf("результат: Convert=%p, Transfer=%p, ожидался %p", got, previousAPI, tc.want)
			}
			if tc.impl == nil {
				if err == nil || oldErr == nil || err.Error() != oldErr.Error() {
					t.Fatalf("отсутствующий переводчик: Convert=%v, Transfer=%v", err, oldErr)
				}
			} else if err != tc.err || oldErr != tc.err {
				t.Fatalf("ошибка должна сохранять identity: Convert=%v, Transfer=%v", err, oldErr)
			}
			if err != nil {
				untouched := result
				if err := FromTo(src, &untouched).Perform(); err == nil || untouched != result {
					t.Fatal("Perform изменил назначение при ошибке")
				}
			}
		})
	}
}
