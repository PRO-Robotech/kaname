// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// keystore_kid_prefix_test.go — приставка идентификатора ключа подписи и ПЕРЕХОД
// к ней (задача #2556, полоса Л3 разреза #2076).
//
// Ключ подписи чеканит САМА служба, в установке, где платформы нет вовсе,
// поэтому приставка идентификатора носит имя службы. Идентификатор при этом —
// ВНЕШНЕ ЧИТАЕМАЯ координата: он стоит в заголовке токена и в публичном наборе
// ключей. Значит одного «новое значение» мало: проба обязана утверждать ПЕРЕХОД
// — что предъявленное ДО смены продолжает вести себя ровно так, как объявлено.
//
// Объявленный переход — СОСУЩЕСТВОВАНИЕ, а не окно двух написаний:
//
//   - идентификатор ХРАНИТСЯ (`kaname.token_signing_keys.kid`), а не выводится,
//     поэтому уже выпущенные ключи своего идентификатора не меняют;
//   - ограничение хранилища и форма домена приставку НЕ ПИНЯТ — обе формы
//     законны в одной таблице и в одном наборе одновременно, поэтому новой
//     миграции переход не требует (ban #5 не задет);
//   - потребитель выбирает ключ ТОЧНЫМ совпадением идентификатора, а не его
//     формой (перепись прод-потребителей приставки по обоим модулям — ноль),
//     поэтому токен, подписанный прежним ключом, проверяется по-прежнему;
//   - окно сосуществования конечно и закрывается обычной ротацией.
//
// Проба держит все четыре утверждения: первое — прогоном чеканки, остальные —
// положительными близнецами на ПРЕЖНЕЙ форме. Без близнецов «новое значение»
// зеленело бы и на переходе, который ломает предъявленное.
package signingkeys_test

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// kidPrefixOwnedByTheService — приставка, которую служба чеканит сама.
const kidPrefixOwnedByTheService = "kaname-"

// kidPrefixMintedBefore — приставка, которую служба чеканила ДО смены. Она
// остаётся законной формой хранимого идентификатора: под ней выпущены ключи,
// которыми подписаны живые токены.
const kidPrefixMintedBefore = "kacho-"

// TestKidPrefixIsMintedWithTheServiceOwnName — чеканка называет СВОЮ службу.
func TestKidPrefixIsMintedWithTheServiceOwnName(t *testing.T) {
	store := newMemStore()
	k := mustKeystore(t, store, nil)

	pub, err := k.Generate(context.Background())
	require.NoError(t, err, "чеканка ключа")

	require.Truef(t, strings.HasPrefix(string(pub.KID), kidPrefixOwnedByTheService),
		"свежечеканенный kid = %q; приставка обязана называть службу (%q), а не платформу",
		pub.KID, kidPrefixOwnedByTheService)
}

// TestKidMintedBeforeTheRenameKeepsWorking — ПЕРЕХОД, сторона предъявленного.
//
// Ключ, выпущенный до смены, обязан остаться годным во всём, чем он был годен:
// форма домена его принимает, ключница его отдаёт, публичный набор его несёт.
// Это положительный близнец: без него проба выше зеленела бы и на переходе,
// который отбирает у прежних ключей их идентичность.
func TestKidMintedBeforeTheRenameKeepsWorking(t *testing.T) {
	legacy := domain.KeyID(kidPrefixMintedBefore + "aaaaaaaaaaaaaaaa")

	// Then — форма домена приставку не пинит: прежний идентификатор законен.
	require.NoErrorf(t, legacy.Validate(),
		"форма домена отвергла идентификатор прежней чеканки %q — переход ломает предъявленное", legacy)
	require.Truef(t, domain.ValidKeyIDForm(string(legacy)),
		"предикат приёмной стороны отверг %q", legacy)

	// And — ключница отдаёт его и держит в публикуемом наборе наравне с новым.
	store := newMemStore()
	k := mustKeystore(t, store, nil)
	ctx := context.Background()

	require.NoError(t, store.Insert(ctx, domain.SigningKeyRecord{
		KID: legacy, Algorithm: domain.SigningAlgRS256, State: domain.SigningKeyPublished,
		PublicKeyPEM: strongerRSAPublicPEM(t), PrivateKeyWrapped: []byte("wrapped"),
		CreatedAt: time.Now().UTC(), NotAfter: time.Now().UTC().Add(24 * time.Hour),
	}), "посев ключа прежней чеканки")

	fresh, err := k.Generate(ctx)
	require.NoError(t, err, "чеканка ключа новой формы рядом с прежним")

	set, err := k.PublishedSet(ctx)
	require.NoError(t, err, "публикуемый набор")
	require.Truef(t, publishedContains(set, legacy),
		"публикуемый набор потерял ключ прежней чеканки %q — токены, им подписанные, перестали бы проверяться", legacy)
	require.Truef(t, publishedContains(set, fresh.KID),
		"публикуемый набор не несёт свежий ключ %q", fresh.KID)

	got, err := store.Get(ctx, legacy)
	require.NoError(t, err, "ключница не отдала ключ прежней чеканки")
	require.Equal(t, legacy, got.KID, "идентификатор прежнего ключа изменён — так переход не объявлялся")
}

// TestStoredFormAdmitsBothMintings — ПЕРЕХОД держит СХЕМА, а не эта проза.
//
// Ограничение применённой миграции читается ИЗ НЕЁ, а не выписывается сюда
// второй копией: два места об одном предмете разошлись бы молча. Если
// ограничение когда-нибудь запинит приставку, проба покраснеет — и смена
// формы потребует новой миграции (ban #5), о чём тогда и скажет отказ.
func TestStoredFormAdmitsBothMintings(t *testing.T) {
	const applied = "../../../../migrations/0001_initial.sql"
	raw, err := os.ReadFile(applied)
	require.NoErrorf(t, err, "применённая миграция %s не прочитана", applied)

	m := regexp.MustCompile(`token_signing_keys_kid_ck CHECK \(\(kid ~ '([^']+)'`).FindSubmatch(raw)
	require.Lenf(t, m, 2, "в %s не найдено ограничение формы kid — предмет пробы исчез, а не сошёлся", applied)

	form, err := regexp.Compile(string(m[1]))
	require.NoErrorf(t, err, "ограничение %q не разбирается", m[1])

	for _, kid := range []string{
		kidPrefixOwnedByTheService + "aaaaaaaaaaaaaaaa",
		kidPrefixMintedBefore + "aaaaaaaaaaaaaaaa",
	} {
		require.Truef(t, form.MatchString(kid),
			"ограничение хранилища отвергает %q — переход требует новой миграции, а не смены литерала", kid)
	}
}
