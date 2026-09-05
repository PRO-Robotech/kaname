// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

import (
	stderrors "errors"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// Отказ «членство несёт права» на пути наружу (задача продукта #1686).
//
// # Почему эта полоса разбирается отдельно от прочих предусловий
//
// Общая классификация (`MapRepoErr`) отвечает только за КОД, а контракт
// RemoveFromAccount обещает больше: отказ приходит «with the grants named».
// Перечень добывается ОТДЕЛЬНЫМ чтением — триггер отложенный, на коммите
// транзакция уже мертва, — поэтому у отказа есть потребитель, который обязан
// отличить эту полосу машинно, а не догадкой по прозе.
//
// Форма — та же, что у отказа учёта рядом (`quota.go`): признак в
// `google.rpc.ErrorInfo`, величины в `metadata`, проза остаётся контрактом.
// Совпадение намеренное: клиенту не должно требоваться знать, какой отказ ему
// достался, прежде чем понять, ГДЕ искать машинный признак.

const (
	// reasonMembershipCarriesRights — исключить человека нельзя, пока в этом
	// аккаунте на нём висят живые выдачи. Действие вызывающего названо однозначно:
	// ОТОЗВАТЬ перечисленные выдачи и повторить.
	//
	// Признак существует и тогда, когда перечень дочитать не удалось: полоса —
	// свойство отказа, а перечень — то, чем его удалось дополнить. Приравняв их,
	// клиент, ключующийся на признак, терял бы полосу ровно в тот момент, когда
	// база отвечает хуже обычного.
	reasonMembershipCarriesRights = "MEMBERSHIP_CARRIES_RIGHTS"

	// metaBlockingIDs / metaBlockingCount — перечень и его ПОЛНАЯ величина.
	//
	// Две величины, а не одна: перечень ограничен сверху (см. MaxNamedBlockingGrants),
	// и клиент, читающий только его, принял бы «названо пять» за «их пять».
	metaBlockingIDs   = "blocking_binding_ids"
	metaBlockingCount = "blocking_binding_count"
)

// membershipReasonDomain — источник отказа в `ErrorInfo.domain`, как его видит
// клиент. Совпадает с доменом отказа учёта: сервис один.
const membershipReasonDomain = "iam.kacho.cloud"

// MaxNamedBlockingGrants — сколько выдач называется поимённо.
//
// Предел есть, и он не вкусовщина: число мешающих выдач НИЧЕМ не ограничено
// сверху, а сообщение об отказе читает человек. Отказ, вываливающий двести
// идентификаторов, перестают читать целиком — вместе с той частью, ради которой
// он написан. Полная величина при этом не теряется: она уезжает и прозой, и
// машинно.
const MaxNamedBlockingGrants = 5

// IsMembershipCarriesRights — отказ ли это полосы «членство несёт права».
//
// Спрашивается ПОСЛЕ `MapRepoErr`, поэтому смотрит на машинный признак, а не на
// цепочку sentinel'ов: `MapRepoErr` пересобирает статус и цепочку не сохраняет.
// Это же делает распознавание НЕЗАВИСИМЫМ ОТ ЯЗЫКА прозы — ровно то свойство,
// ради которого признак и заводится.
func IsMembershipCarriesRights(err error) bool {
	st, ok := status.FromError(err)
	if !ok {
		return stderrors.Is(err, iamerr.ErrMembershipCarriesRights)
	}
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok && ei.GetReason() == reasonMembershipCarriesRights {
			return true
		}
	}
	return stderrors.Is(err, iamerr.ErrMembershipCarriesRights)
}

// membershipRefusal собирает статус полосы, если err ей является; ok=false
// передаёт разбор общей классификации.
//
// Перечня здесь ещё НЕТ — на этом уровне его негде взять. Признак ставится всё
// равно: отказ без перечня остаётся отказом своей полосы, и потребитель отличает
// «дочитывать» от «не дочитывать» именно по нему.
func membershipRefusal(err error) (error, bool) {
	if !stderrors.Is(err, iamerr.ErrMembershipCarriesRights) {
		return nil, false
	}
	return withMembershipDetails(iamerr.StripSentinel(err), nil, 0), true
}

// NameBlockingGrants дополняет отказ полосы перечнем выдач, которые ДЕРЖАТ
// членство: тем же перечнем прозой и машинно.
//
// `total` — сколько их всего, `named` — сколько из них названо. Пустой перечень
// возвращает отказ КАК ЕСТЬ: дочитать не удалось (выдачи успели отозвать между
// отказом и чтением, либо база не ответила), и выдумывать перечень не из чего.
// Отказ при этом не портится — он просто остаётся прежним, а не превращается в
// утверждение «мешающих выдач ноль», которого база не делала.
func NameBlockingGrants(err error, named []string, total int) error {
	if len(named) == 0 || !IsMembershipCarriesRights(err) {
		return err
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	return withMembershipDetails(st.Message()+blockingSuffix(named, total), named, total)
}

// blockingSuffix — человекочитаемая половина: что именно мешает и что с этим
// делать. Следующий шаг называется ПРЯМО: отказ, не восстанавливающий следующий
// шаг клиента, и есть предмет задачи #1686.
func blockingSuffix(named []string, total int) string {
	s := ": " + strings.Join(named, ", ")
	if total > len(named) {
		s += fmt.Sprintf(" and %d more", total-len(named))
	}
	return s + fmt.Sprintf(" (%d total); revoke them before removing the membership", total)
}

func withMembershipDetails(msg string, named []string, total int) error {
	// FAILED_PRECONDITION — так называет полосу контракт RemoveFromAccount, и это
	// же требует конвенция: ввод вызывающего корректен, не выполнено предусловие
	// СОСТОЯНИЯ. INVALID_ARGUMENT обвинил бы его в том, чего он не присылал.
	st := status.New(codes.FailedPrecondition, msg)

	meta := map[string]string{}
	if len(named) > 0 {
		meta[metaBlockingIDs] = strings.Join(named, ",")
		meta[metaBlockingCount] = strconv.Itoa(total)
	}
	withDetails, derr := st.WithDetails(&errdetails.ErrorInfo{
		Reason:   reasonMembershipCarriesRights,
		Domain:   membershipReasonDomain,
		Metadata: meta,
	})
	if derr != nil {
		// Деталь не прикрепилась — код и текст важнее признака.
		return st.Err()
	}
	return withDetails.Err()
}
