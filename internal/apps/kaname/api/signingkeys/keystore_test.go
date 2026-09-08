// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// keystore_test.go — сценарии F1-01, F1-02, F1-04, F1-05 приёмки F1.
package signingkeys_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/signingkeys"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
	"github.com/PRO-Robotech/kaname/internal/signingkeygen"
)

// memStore — подставная ключница в памяти.
//
// Дублёр НЕ снисходительнее настоящего: он держит тот же инвариант «активный
// ровно один», который в производстве держит частичный уникальный индекс, и
// отвергает второго активного тем же отказом. Дублёр, глотающий вход, на
// котором настоящий отвечает отказом, сделал бы невидимым ровно тот дефект,
// ради которого его подставляют.
type memStore struct {
	rows map[domain.KeyID]domain.SigningKeyRecord
	err  error
}

func newMemStore() *memStore { return &memStore{rows: map[domain.KeyID]domain.SigningKeyRecord{}} }

var errTwoActive = errors.New("memstore: two signing keys would be active")

func (m *memStore) Insert(_ context.Context, rec domain.SigningKeyRecord) error {
	if m.err != nil {
		return m.err
	}
	if rec.State == domain.SigningKeyActive && m.activeKID() != "" {
		return errTwoActive
	}
	m.rows[rec.KID] = rec
	return nil
}

func (m *memStore) activeKID() domain.KeyID {
	for k, r := range m.rows {
		if r.State == domain.SigningKeyActive {
			return k
		}
	}
	return ""
}

func (m *memStore) Get(_ context.Context, kid domain.KeyID) (domain.SigningKeyRecord, error) {
	if m.err != nil {
		return domain.SigningKeyRecord{}, m.err
	}
	r, ok := m.rows[kid]
	if !ok {
		return domain.SigningKeyRecord{}, errors.New("memstore: no such key")
	}
	return r, nil
}

func (m *memStore) Active(_ context.Context) (domain.SigningKeyRecord, error) {
	if m.err != nil {
		return domain.SigningKeyRecord{}, m.err
	}
	if kid := m.activeKID(); kid != "" {
		return m.rows[kid], nil
	}
	return domain.SigningKeyRecord{}, errors.New("memstore: no active signing key")
}

func (m *memStore) KeySet(_ context.Context) ([]domain.SigningKeyRecord, error) {
	if m.err != nil {
		return nil, m.err
	}
	var out []domain.SigningKeyRecord
	for _, r := range m.rows {
		if r.State.InKeySet() {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memStore) Activate(_ context.Context, kid domain.KeyID, at time.Time) error {
	if m.err != nil {
		return m.err
	}
	r, ok := m.rows[kid]
	if !ok || !r.State.CanActivate() {
		return errors.New("memstore: key cannot become the signing key")
	}
	if cur := m.activeKID(); cur != "" && cur != kid {
		prev := m.rows[cur]
		prev.State = domain.SigningKeyRetired
		prev.RetiredAt = &at
		m.rows[cur] = prev
	}
	r.State = domain.SigningKeyActive
	r.ActivatedAt = &at
	m.rows[kid] = r
	return nil
}

func (m *memStore) Retire(_ context.Context, kid domain.KeyID, at time.Time) error {
	return m.set(kid, domain.SigningKeyRetired, &at, func(r *domain.SigningKeyRecord) { r.RetiredAt = &at })
}

func (m *memStore) Remove(_ context.Context, kid domain.KeyID, at time.Time) error {
	return m.set(kid, domain.SigningKeyRemoved, &at, func(r *domain.SigningKeyRecord) { r.RemovedAt = &at })
}

func (m *memStore) Compromise(_ context.Context, kid domain.KeyID, at time.Time) error {
	return m.set(kid, domain.SigningKeyCompromised, &at, func(r *domain.SigningKeyRecord) { r.CompromisedAt = &at })
}

func (m *memStore) set(kid domain.KeyID, st domain.SigningKeyState, _ *time.Time, stamp func(*domain.SigningKeyRecord)) error {
	if m.err != nil {
		return m.err
	}
	r, ok := m.rows[kid]
	if !ok {
		return errors.New("memstore: no such key")
	}
	r.State = st
	stamp(&r)
	m.rows[kid] = r
	return nil
}

func fixedClock(at time.Time) signingkeys.Clock { return func() time.Time { return at } }

func mustKeystore(t *testing.T, store *memStore, logBuf *bytes.Buffer) *signingkeys.Keystore {
	t.Helper()
	wrapper, err := keywrap.New(bytes.Repeat([]byte{7}, keywrap.KeySize))
	require.NoError(t, err)
	var logger *slog.Logger
	if logBuf != nil {
		logger = slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	ks, err := signingkeys.New(signingkeys.Config{
		Algorithm:    domain.SigningAlgRS256,
		KeyLifetime:  90 * 24 * time.Hour,
		RemovalGrace: tokenpolicy.KeyRemovalGrace,
		Clock:        fixedClock(time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)),
		Logger:       logger,
	}, store, store, wrapper)
	require.NoError(t, err)
	return ks
}

// TestKeystore_F1_01_AlgorithmComesFromConfigurationAndBindsToTheKey — F1-01.
func TestKeystore_F1_01_AlgorithmComesFromConfigurationAndBindsToTheKey(t *testing.T) {
	for _, alg := range domain.SigningAlgorithms() {
		store := newMemStore()
		wrapper, err := keywrap.New(bytes.Repeat([]byte{7}, keywrap.KeySize))
		require.NoError(t, err)
		ks, err := signingkeys.New(signingkeys.Config{
			Algorithm:    alg,
			KeyLifetime:  time.Hour,
			RemovalGrace: tokenpolicy.KeyRemovalGrace,
			Clock:        fixedClock(time.Now()),
		}, store, store, wrapper)
		require.NoError(t, err)

		// Then — порождённый ключ несёт ТОТ алгоритм, что назван конфигурацией.
		pub, err := ks.Generate(context.Background())
		require.NoError(t, err)
		require.Equal(t, alg, pub.Algorithm)

		// And — алгоритм закреплён за ключом 1:1 и хранится рядом с ним.
		rec, err := store.Get(context.Background(), pub.KID)
		require.NoError(t, err)
		require.Equal(t, alg, rec.Algorithm)

		// And — ни один вход запроса не может выбрать другой алгоритм: у
		// порождения нет входа алгоритма вовсе, он берётся только из настройки.
		gotAlg, _, err := signingkeygen.StrengthOf(rec.PublicKeyPEM)
		require.NoError(t, err)
		require.Equal(t, alg, gotAlg, "материал ключа обязан соответствовать закреплённому алгоритму")
	}
}

// TestKeystore_F1_02_StrengthThresholdIsDeclaredAndBoundedOnBothSides — F1-02.
func TestKeystore_F1_02_StrengthThresholdIsDeclaredAndBoundedOnBothSides(t *testing.T) {
	// Ключ СЛАБЕЕ порога отвергается, и текст называет И порог, И величину.
	weak := weakRSAPublicPEM(t)
	err := signingkeygen.CheckStrength(domain.SigningAlgRS256, weak)
	require.Error(t, err)
	require.Contains(t, err.Error(), "1024", "отказ обязан называть предъявленную величину")
	require.Contains(t, err.Error(), "2048", "отказ обязан называть порог")

	// Ключ РОВНО НА ПОРОГЕ и ключ выше порога принимаются — без этого проба
	// зелена на ключнице, отвергающей любой ключ.
	atThreshold, err := signingkeygen.Generate(domain.SigningAlgRS256)
	require.NoError(t, err)
	require.NoError(t, signingkeygen.CheckStrength(domain.SigningAlgRS256, atThreshold.PublicKeyPEM))
	_, bits, err := signingkeygen.StrengthOf(atThreshold.PublicKeyPEM)
	require.NoError(t, err)
	require.Equal(t, domain.SigningAlgRS256.MinBits(), bits, "порождение обязано выдавать ключ РОВНО на пороге")

	above := strongerRSAPublicPEM(t)
	require.NoError(t, signingkeygen.CheckStrength(domain.SigningAlgRS256, above))
}

// TestKeystore_F1_04_PrivateMaterialNeverLeavesTheProcess — F1-04, на уровне
// обсервабла.
func TestKeystore_F1_04_PrivateMaterialNeverLeavesTheProcess(t *testing.T) {
	ctx := context.Background()
	var logBuf bytes.Buffer
	store := newMemStore()
	ks := mustKeystore(t, store, &logBuf)

	// Given — полный цикл: порождение, запись, чтение, подпись.
	pub, err := ks.Generate(ctx)
	require.NoError(t, err)
	require.NoError(t, ks.Activate(ctx, pub.KID))
	mat, err := ks.ActiveSigningKey(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, mat.PrivateKeyPEM)

	// …и один цикл, завершившийся ошибкой.
	store.err = errors.New("store is unavailable")
	_, errCycle := ks.Generate(ctx)
	require.Error(t, errCycle)
	store.err = nil

	// Then — приватный материал не встречается НИ В ОДНОМ из трёх носителей.
	private := string(mat.PrivateKeyPEM)
	needle := strings.TrimSpace(strings.Split(private, "\n")[1]) // тело PEM, не заголовок
	require.NotEmpty(t, needle)

	require.NotContains(t, logBuf.String(), needle, "приватный материал в журнале")
	require.NotContains(t, errCycle.Error(), needle, "приватный материал в тексте ошибки")
	require.NotContains(t, ks.Stats().String(), needle, "приватный материал в снятых величинах")

	// And — в те же три носителя обязано найтись ЗАВЕДОМО ПРИСУТСТВУЮЩЕЕ
	// значение, и проба обязана его НАЙТИ: утверждение об отсутствии зелено на
	// читателе, который не читает ничего, поэтому объём осмотренного
	// доказывается положительной находкой.
	//
	// Подсаженное значение не выдумано и не вносится тестовым крючком в
	// прод-коде: это то, что ключница пишет САМА, — идентификатор ключа в
	// журнале, имя хранилища в тексте отказа и счётчик порождений в величинах.
	require.Contains(t, logBuf.String(), string(pub.KID),
		"журнал не читается пробой — отрицание было бы вакуумным")
	require.Contains(t, errCycle.Error(), "store is unavailable",
		"текст ошибки не читается пробой — отрицание было бы вакуумным")
	require.Contains(t, ks.Stats().String(), "generated=",
		"снятые величины не читаются пробой — отрицание было бы вакуумным")
	require.Equal(t, uint64(1), ks.Stats().Generated)

	// And — утверждение проверяет СОДЕРЖИМОЕ, а не только код возврата.
	require.NotContains(t, logBuf.String(), private)
	require.NotContains(t, ks.Stats().String(), private)
}

// TestKeystore_F1_05_PublishedFormCannotCarryThePrivateHalf — F1-05,
// исполняемая половина. Половина «гейт по дереву» — в internal/repohygiene.
func TestKeystore_F1_05_PublishedFormCannotCarryThePrivateHalf(t *testing.T) {
	// Then — положить приватную половину в публикуемый тип НЕ ВЫРАЖАЕТСЯ: у
	// типа нет такого поля, и это держит компилятор, а не внимание.
	published := domain.PublishedKey{KID: "kacho-a", Algorithm: domain.SigningAlgRS256, PublicKeyPEM: "pem"}
	require.Equal(t, 3, reflectFieldCount(published), "у публикуемого типа ровно три поля, и все — публичные")

	// And — у гейта есть место, которое он ОБЯЗАН находить: ХРАНИМЫЙ тип поле
	// приватной половины несёт. Без положительного близнеца проверка, предмет
	// которой — отсутствие, молчит одинаково и когда предмет исчез, и когда
	// сломалась она сама.
	stored := domain.SigningKeyRecord{PrivateKeyWrapped: []byte("wrapped")}
	require.NotEmpty(t, stored.PrivateKeyWrapped)

	// And — проекция односторонняя: из хранимой формы публикуемая получается,
	// обратного конструктора нет.
	rec := domain.SigningKeyRecord{
		KID: "kacho-a", Algorithm: domain.SigningAlgRS256,
		PublicKeyPEM: "pem", PrivateKeyWrapped: []byte("wrapped"),
	}
	require.Equal(t, published, rec.Published())
}

// TestKeystore_RefusesToBuildIncomplete — часы, алгоритм, срок ключа и
// отсрочка — входы, а не умолчания.
func TestKeystore_RefusesToBuildIncomplete(t *testing.T) {
	store := newMemStore()
	wrapper, err := keywrap.New(bytes.Repeat([]byte{7}, keywrap.KeySize))
	require.NoError(t, err)
	full := signingkeys.Config{
		Algorithm:    domain.SigningAlgRS256,
		KeyLifetime:  time.Hour,
		RemovalGrace: tokenpolicy.KeyRemovalGrace,
		Clock:        fixedClock(time.Now()),
	}
	for name, mutate := range map[string]func(*signingkeys.Config){
		"без алгоритма":  func(c *signingkeys.Config) { c.Algorithm = "" },
		"чужой алгоритм": func(c *signingkeys.Config) { c.Algorithm = "HS256" },
		"без часов":      func(c *signingkeys.Config) { c.Clock = nil },
		"без срока":      func(c *signingkeys.Config) { c.KeyLifetime = 0 },
		"без отсрочки":   func(c *signingkeys.Config) { c.RemovalGrace = 0 },
	} {
		cfg := full
		mutate(&cfg)
		if _, err := signingkeys.New(cfg, store, store, wrapper); err == nil {
			t.Fatalf("%s: ключница построилась на неполной настройке", name)
		}
	}
	// Положительный контроль — с полной настройкой строится.
	_, err = signingkeys.New(full, store, store, wrapper)
	require.NoError(t, err)
}

// reflectFieldCount — число полей типа. Отдельная функция, чтобы утверждение
// «у публикуемого типа нет поля приватной половины» читалось как утверждение о
// СОСТАВЕ, а не о том, что мы забыли его заполнить.
func reflectFieldCount(v any) int { return reflect.TypeOf(v).NumField() }

// weakRSAPublicPEM — ключ СЛАБЕЕ объявленного порога.
func weakRSAPublicPEM(t *testing.T) string { return rsaPublicPEM(t, 1024) }

// strongerRSAPublicPEM — ключ ВЫШЕ порога.
func strongerRSAPublicPEM(t *testing.T) string { return rsaPublicPEM(t, 3072) }

func rsaPublicPEM(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// TestKeystore_F1_30_SweepRemovesOnlyAfterTheComputedGrace — F1-30 на уровне
// ключницы: ключ, выведенный из подписи, ОСТАЁТСЯ в наборе всю отсрочку.
//
// Отсрочка ВЫЧИСЛЕНА, а не выбрана: она покрывает срок последнего подписанного
// токена плюс потолок кэша ключей у потребителя. Проба, укладывающаяся в срок
// кэша, этого свойства не измеряет — поэтому здесь двигаются часы, а не ждётся
// время.
func TestKeystore_F1_30_SweepRemovesOnlyAfterTheComputedGrace(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	at := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	wrapper, err := keywrap.New(bytes.Repeat([]byte{7}, keywrap.KeySize))
	require.NoError(t, err)

	clockAt := at
	ks, err := signingkeys.New(signingkeys.Config{
		Algorithm:    domain.SigningAlgRS256,
		KeyLifetime:  90 * 24 * time.Hour,
		RemovalGrace: tokenpolicy.KeyRemovalGrace,
		Clock:        func() time.Time { return clockAt },
	}, store, store, wrapper)
	require.NoError(t, err)

	old, err := ks.Generate(ctx)
	require.NoError(t, err)
	require.NoError(t, ks.Activate(ctx, old.KID))
	fresh, err := ks.Generate(ctx)
	require.NoError(t, err)
	require.NoError(t, ks.Activate(ctx, fresh.KID)) // старый выведен сменой

	// ВНУТРИ отсрочки ключ ещё в наборе: токены, подписанные им, живы, и
	// снимок набора у потребителя ещё может быть не обновлён.
	clockAt = at.Add(tokenpolicy.KeyRemovalGrace - time.Minute)
	n, err := ks.SweepRemovable(ctx)
	require.NoError(t, err)
	require.Equal(t, 0, n, "ключ снят раньше вычисленной отсрочки")
	set, err := ks.PublishedSet(ctx)
	require.NoError(t, err)
	require.True(t, publishedContains(set, old.KID), "выведенный ключ обязан оставаться в наборе всю отсрочку")

	// ЗА отсрочкой — снимается. Положительный контроль: без него «не снят»
	// зелено и на сметателе, который не снимает никогда.
	clockAt = at.Add(tokenpolicy.KeyRemovalGrace + time.Minute)
	n, err = ks.SweepRemovable(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	set, err = ks.PublishedSet(ctx)
	require.NoError(t, err)
	require.False(t, publishedContains(set, old.KID))
	require.True(t, publishedContains(set, fresh.KID), "подписывающий ключ снят вместе с выведенным")

	// Повторный обход — НЕ отказ: снятие идемпотентно по свойству оператора,
	// и сметатель соседней реплики не отменяет работу первого и не обрывает
	// собственный обход.
	n, err = ks.SweepRemovable(ctx)
	require.NoError(t, err, "повторный обход обязан быть безвредным: петля идёт в каждой реплике")
	require.Equal(t, 0, n)
}

func publishedContains(set []domain.PublishedKey, kid domain.KeyID) bool {
	for _, k := range set {
		if k.KID == kid {
			return true
		}
	}
	return false
}
