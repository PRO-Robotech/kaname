// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package signingkeys — ключница подписных ключей платформы (задача #897).
//
// # Что здесь решается, а что только выражается
//
// Инвариант «подписывает ровно один» здесь НЕ решается: его держит частичный
// уникальный индекс хранилища (ban #10). Этот пакет выражает жизненный цикл
// ключа — порождение, публикация, вступление в подпись, вывод, снятие и
// отдельный глагол объявления ключа утёкшим — и следит, чтобы порядок
// «в наборе → подписывает» выполнялся ПО ПОСТРОЕНИЮ: ключ рождается уже
// опубликованным.
//
// # Почему у «выведен» и «скомпрометирован» разные глаголы
//
// Первый оставляет ключ в наборе на отсрочку, и подписанные им токены доживают
// свой срок. Второй снимает его немедленно, отвергая живые токены. Это решения
// разной цены, и глагол, делающий и то и другое, лишает второе решение его цены.
//
// # Приватный материал не покидает процесс
//
// Ни в журнале, ни в тексте ошибки, ни в снятых величинах, ни в ответе.
// Требование усилено формой: публикуемый тип домена не имеет поля для
// приватной половины, поэтому «не заполнили» держит компилятор, а не внимание.
package signingkeys

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/signingkeygen"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// ErrWrappingKeyMismatch — предъявленный ключ обёртки не разворачивает то, что
// в ключнице уже записано.
//
// Отдельный сентинел, а не общий отказ: вызывающий обязан отличать «ключ
// обёртки не тот» от «хранилище недоступно». Первое повтором не лечится и
// означает потерю материала; второе — временно.
var ErrWrappingKeyMismatch = errors.New("signingkeys: the wrapping key does not open the stored signing keys")

// ErrSignerChanged — передача подписи не состоялась: подписывающий сменился
// между чтением и передачей (соседняя реплика успела раньше). Повтором не
// лечится и отказом не является — подпись уже у нового ключа.
var ErrSignerChanged = errors.New("signingkeys: the signing key changed before the hand-over")

// ErrNoSignerAfterCompromise — ЧАСТИЧНЫЙ исход реакции на утечку: утёкший ключ
// из набора снят, завести замену не удалось, и подписывающего нет — это
// ПРОЧИТАНО после отказа замены, а не выведено из него, — служба не подписывает.
//
// Отдельный сентинел, потому что вызывающий обязан отличить его от отказа
// снятия: снятие здесь СОСТОЯЛОСЬ и не откатывается, а повтор той же команды
// довершает замену.
var ErrNoSignerAfterCompromise = errors.New("signingkeys: the compromised key left the key set, but no replacement signs")

// ErrSignerUnknownAfterCompromise — утёкший ключ из набора снят, а подписывает
// ли служба, НЕ УСТАНОВЛЕНО: чтение подписывающего отказало сбоем хранилища
// либо вызов кончился, пока заводилась замена.
//
// Отдельный сентинел, а не ErrNoSignerAfterCompromise: «подписывающего нет» и
// «о подписывающем не известно» чинятся одинаково — повтором, — но говорят
// оператору разное, и первое при втором было бы ложью о службе, которая,
// возможно, подписывает. Снятие и здесь СОСТОЯЛОСЬ и не откатывается.
var ErrSignerUnknownAfterCompromise = errors.New("signingkeys: the compromised key left the key set, but whether a key signs is not established")

// Clock — источник времени ключницы. Вход, а не окружение.
type Clock func() time.Time

// KeyReader — читающий порт ключницы (CQRS-разделение: читатель отдельно от
// писателя, потому что публикатор читает и не пишет никогда).
type KeyReader interface {
	Get(ctx context.Context, kid domain.KeyID) (domain.SigningKeyRecord, error)
	Active(ctx context.Context) (domain.SigningKeyRecord, error)
	KeySet(ctx context.Context) ([]domain.SigningKeyRecord, error)
}

// KeyWriter — пишущий порт ключницы.
type KeyWriter interface {
	Insert(ctx context.Context, rec domain.SigningKeyRecord) error
	Activate(ctx context.Context, kid domain.KeyID, at time.Time) error
	// ReplaceActive передаёт подпись от `expected` к `next` одним переходом и
	// ТОЛЬКО если `expected` всё ещё подписывает; иначе — невыполненное
	// предусловие, и не меняется ничего. Условность держит хранилище: решение
	// «кого сменяем» не отделено от смены чужим исполнением.
	ReplaceActive(ctx context.Context, next, expected domain.KeyID, at time.Time) error
	Retire(ctx context.Context, kid domain.KeyID, at time.Time) error
	Remove(ctx context.Context, kid domain.KeyID, at time.Time) error
	Compromise(ctx context.Context, kid domain.KeyID, at time.Time) error
}

// Wrapper — обёртка приватной половины.
type Wrapper interface {
	Wrap(plain []byte) ([]byte, error)
	Unwrap(wrapped []byte) ([]byte, error)
}

// Config — настройка ключницы. Каждое поле обязательно.
type Config struct {
	// Algorithm — алгоритм подписи, закрепляемый за порождаемым ключом.
	Algorithm domain.SigningAlgorithm
	// KeyLifetime — срок ключа.
	KeyLifetime time.Duration
	// RemovalGrace — отсрочка снятия выведенного ключа из набора. Величина
	// ВЫЧИСЛЕНА (pkg/tokenpolicy), а не выбрана здесь.
	RemovalGrace time.Duration
	// RotationLead — за сколько до объявленного срока подписывающего подпись
	// переходит к новому ключу (RotateIfDue). Строго меньше срока ключа:
	// иначе ключ ротировался бы на каждом проходе.
	RotationLead time.Duration
	Clock        Clock
	Logger       *slog.Logger
}

// Stats — наблюдаемость ключницы: по счётчику на каждый исход.
//
// «Ноль порождений за всё время жизни» обязано быть отличимо от «ключница не
// исполнялась»: величины печатаются всегда, включая нулевые.
type Stats struct {
	Generated   uint64
	Activated   uint64
	Retired     uint64
	Removed     uint64
	Compromised uint64
	Failures    uint64
	// Sweeps — ЗАВЕРШЁННЫЕ проходы сметателя, включая проходы без единого
	// снятия. Без этой величины «снимать было нечего» и «сметатель не ходит»
	// дают одинаковый ноль снятий.
	Sweeps uint64
}

// String — вид величин для журнала и проб. Приватного материала здесь нет и
// быть не может: у структуры нет поля, куда его положить.
func (s Stats) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "generated=%d activated=%d retired=%d removed=%d compromised=%d failures=%d sweeps=%d",
		s.Generated, s.Activated, s.Retired, s.Removed, s.Compromised, s.Failures, s.Sweeps)
	return b.String()
}

// Keystore — ключница.
type Keystore struct {
	cfg     Config
	reader  KeyReader
	writer  KeyWriter
	wrapper Wrapper
	logger  *slog.Logger

	generated   atomic.Uint64
	activated   atomic.Uint64
	retired     atomic.Uint64
	removed     atomic.Uint64
	compromised atomic.Uint64
	failures    atomic.Uint64
	sweeps      atomic.Uint64
}

// New строит ключницу. Неполная настройка — отказ построения: ключница,
// собранная наполовину, порождала бы ключи, которыми нельзя подписать.
func New(cfg Config, reader KeyReader, writer KeyWriter, wrapper Wrapper) (*Keystore, error) {
	if _, err := domain.ParseSigningAlgorithm(string(cfg.Algorithm)); err != nil {
		return nil, fmt.Errorf("signingkeys: %w", err)
	}
	switch {
	case cfg.KeyLifetime <= 0:
		return nil, fmt.Errorf("signingkeys: key lifetime must be declared as a positive number")
	case cfg.RemovalGrace <= 0:
		return nil, fmt.Errorf("signingkeys: removal grace must be declared as a positive number")
	case cfg.RotationLead <= 0:
		return nil, fmt.Errorf("signingkeys: rotation lead must be declared as a positive number")
	case cfg.KeyLifetime <= cfg.RotationLead:
		return nil, fmt.Errorf("signingkeys: key lifetime %s must exceed the rotation lead %s — "+
			"otherwise every pass would rotate the signing key", cfg.KeyLifetime, cfg.RotationLead)
	case cfg.Clock == nil:
		return nil, fmt.Errorf("signingkeys: clock is required (time source is an input, not the environment)")
	case reader == nil || writer == nil || wrapper == nil:
		return nil, fmt.Errorf("signingkeys: reader, writer and wrapper are all required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Keystore{cfg: cfg, reader: reader, writer: writer, wrapper: wrapper, logger: logger}, nil
}

// Stats возвращает снятые величины.
func (k *Keystore) Stats() Stats {
	return Stats{
		Generated:   k.generated.Load(),
		Activated:   k.activated.Load(),
		Retired:     k.retired.Load(),
		Removed:     k.removed.Load(),
		Compromised: k.compromised.Load(),
		Failures:    k.failures.Load(),
		Sweeps:      k.sweeps.Load(),
	}
}

// Generate порождает ключ и кладёт его в набор в состоянии PUBLISHED.
//
// Ключ рождается УЖЕ ОПУБЛИКОВАННЫМ, поэтому порядок «в наборе раньше, чем им
// подписан первый токен» верен по построению: состояния, в котором ключ
// подписывает, а в наборе его нет, схема не допускает.
func (k *Keystore) Generate(ctx context.Context) (domain.PublishedKey, error) {
	mat, err := signingkeygen.Generate(k.cfg.Algorithm)
	if err != nil {
		k.failures.Add(1)
		return domain.PublishedKey{}, err
	}
	if err := signingkeygen.CheckStrength(k.cfg.Algorithm, mat.PublicKeyPEM); err != nil {
		k.failures.Add(1)
		return domain.PublishedKey{}, err
	}
	wrapped, err := k.wrapper.Wrap(mat.PrivateKeyPEM)
	if err != nil {
		k.failures.Add(1)
		// Причина обёртки наружу не пересказывается: она о материале.
		return domain.PublishedKey{}, fmt.Errorf("signingkeys: wrap generated key: %w", err)
	}
	kid, err := newKeyID()
	if err != nil {
		k.failures.Add(1)
		return domain.PublishedKey{}, err
	}
	now := k.now()
	rec := domain.SigningKeyRecord{
		KID:               kid,
		Algorithm:         k.cfg.Algorithm,
		State:             domain.SigningKeyPublished,
		PublicKeyPEM:      mat.PublicKeyPEM,
		PrivateKeyWrapped: wrapped,
		CreatedAt:         now,
		NotAfter:          now.Add(k.cfg.KeyLifetime),
	}
	if err := k.writer.Insert(ctx, rec); err != nil {
		k.failures.Add(1)
		return domain.PublishedKey{}, fmt.Errorf("signingkeys: store generated key: %w", err)
	}
	k.generated.Add(1)
	// В журнал идёт идентификатор ключа и алгоритм — то, по чему оператор
	// связывает событие с ключом. Материала здесь нет.
	k.logger.Info("signing key generated", "kid", string(rec.KID), "alg", string(rec.Algorithm),
		"not_after", rec.NotAfter.Format(time.RFC3339))
	return rec.Published(), nil
}

// Activate делает названный ключ подписывающим.
func (k *Keystore) Activate(ctx context.Context, kid domain.KeyID) error {
	if err := k.writer.Activate(ctx, kid, k.now()); err != nil {
		k.failures.Add(1)
		return err
	}
	k.activated.Add(1)
	k.logger.Info("signing key became the signer", "kid", string(kid))
	return nil
}

// Rotate порождает новый ключ и делает его подписывающим.
//
// Порядок здесь ЕДИНСТВЕННЫЙ возможный: порождение кладёт ключ в набор, и лишь
// потом он вступает в подпись. Обратный порядок не выражается — активировать
// нечего, пока строки нет.
func (k *Keystore) Rotate(ctx context.Context) (domain.PublishedKey, error) {
	pub, err := k.Generate(ctx)
	if err != nil {
		return domain.PublishedKey{}, err
	}
	if err := k.Activate(ctx, pub.KID); err != nil {
		k.abandon(ctx, pub.KID)
		return domain.PublishedKey{}, err
	}
	return pub, nil
}

// rotateReplacing порождает ключ и передаёт ему подпись от `expected` —
// УСЛОВНО на то, что `expected` всё ещё подписывает.
//
// Порождение идёт первым по той же причине, что в Rotate: ключ рождается
// опубликованным и лишь потом вступает в подпись. Ключ, проигравший передачу,
// выводится сразу (abandon): иначе он остался бы в наборе опубликованным без
// будущего — сметатель снимает только выведенные.
func (k *Keystore) rotateReplacing(ctx context.Context, expected domain.KeyID) (domain.PublishedKey, error) {
	pub, err := k.Generate(ctx)
	if err != nil {
		return domain.PublishedKey{}, err
	}
	if err := k.writer.ReplaceActive(ctx, pub.KID, expected, k.now()); err != nil {
		k.abandon(ctx, pub.KID)
		if errors.Is(err, iamerr.ErrFailedPrecondition) {
			return domain.PublishedKey{}, fmt.Errorf("%w: %w", ErrSignerChanged, err)
		}
		k.failures.Add(1)
		return domain.PublishedKey{}, err
	}
	k.activated.Add(1)
	k.retired.Add(1)
	k.logger.Info("signing handed over to a new key", "kid", string(pub.KID), "retired_kid", string(expected),
		"removable_after", k.now().Add(k.cfg.RemovalGrace).Format(time.RFC3339))
	return pub, nil
}

// abandon выводит порождённый ключ, так и не вступивший в подпись. Отказ здесь
// не прерывает вызывающего — его исход уже решён, — но звучит: ключ, оставшийся
// опубликованным, есть лишняя запись набора без срока снятия.
func (k *Keystore) abandon(ctx context.Context, kid domain.KeyID) {
	if err := k.writer.Retire(ctx, kid, k.now()); err != nil {
		k.failures.Add(1)
		k.logger.Warn("signing key generated for a hand-over that did not happen could not be retired",
			"kid", string(kid), "err", err.Error())
		return
	}
	k.retired.Add(1)
}

// LifecycleOutcome — исход действия оператора над ключом.
type LifecycleOutcome struct {
	// KID — ключ, над которым совершено действие.
	KID domain.KeyID
	// Replacement — ключ, к которому перешла подпись; пусто — подпись не
	// переходила.
	Replacement domain.KeyID
	// Signer — подписывающий, УСТАНОВЛЕННЫЙ ЧТЕНИЕМ после того, как замена,
	// заводимая этим вызовом, не легла. Кем он поставлен, вызов не знает:
	// соседней репликой на старте, вторым оператором с тем же повтором либо
	// записью самого вызова, чья фиксация отказала неоднозначно. Пусто — такого
	// чтения не было.
	Signer domain.KeyID
	// AlreadyDone — ключ уже был в целевом состоянии: повтор команды не отказ
	// и не второе действие.
	AlreadyDone bool
}

// requireDecider — действие оператора над ключом не бывает анонимным: событие
// называет ключ И того, кто решение принял.
func requireDecider(verb, decidedBy string) error {
	if strings.TrimSpace(decidedBy) == "" {
		return fmt.Errorf("signingkeys: %s requires naming who decided it", verb)
	}
	return nil
}

// Retire выводит ключ из обращения: он перестаёт подписывать и остаётся в
// наборе всю отсрочку, чтобы подписанные им токены дожили свой срок.
//
// Вывод ПОДПИСЫВАЮЩЕГО ключа — это передача подписи новому, а не снятие: служба
// без подписывающего не выдаёт ни одного токена, и «вывели ключ» не должно
// значить «остановили выдачу». Передача условна на то, что ключ всё ещё
// подписывает; проигравшая передача перечитывает состояние и отвечает по нему.
func (k *Keystore) Retire(ctx context.Context, kid domain.KeyID, decidedBy string) (LifecycleOutcome, error) {
	out := LifecycleOutcome{KID: kid}
	if err := requireDecider("retiring a signing key", decidedBy); err != nil {
		return out, err
	}
	rec, err := k.reader.Get(ctx, kid)
	if err != nil {
		return out, err
	}
	switch rec.State {
	case domain.SigningKeyActive:
		pub, rerr := k.rotateReplacing(ctx, kid)
		if errors.Is(rerr, ErrSignerChanged) {
			// Подписывающего сменили раньше нас: ответ — по тому, что стало.
			return k.retireOutcomeAfterRace(ctx, kid)
		}
		if rerr != nil {
			return out, rerr
		}
		out.Replacement = pub.KID
	case domain.SigningKeyPublished:
		if werr := k.writer.Retire(ctx, kid, k.now()); werr != nil {
			k.failures.Add(1)
			return out, werr
		}
		k.retired.Add(1)
	case domain.SigningKeyRetired:
		out.AlreadyDone = true
		return out, nil
	default:
		return out, fmt.Errorf("%w: signing key %s is %s — it is out of the key set and cannot be retired",
			iamerr.ErrFailedPrecondition, kid, rec.State)
	}
	k.logger.Info("signing key retired from signing", "kid", string(kid), "decided_by", decidedBy,
		"replacement_kid", string(out.Replacement),
		"removable_after", k.now().Add(k.cfg.RemovalGrace).Format(time.RFC3339))
	return out, nil
}

// retireOutcomeAfterRace отвечает по состоянию ключа после чужой передачи
// подписи: выведенный ключ — уже сделано, иной — невыполненное предусловие.
func (k *Keystore) retireOutcomeAfterRace(ctx context.Context, kid domain.KeyID) (LifecycleOutcome, error) {
	out := LifecycleOutcome{KID: kid}
	rec, err := k.reader.Get(ctx, kid)
	if err != nil {
		return out, err
	}
	if rec.State != domain.SigningKeyRetired {
		return out, fmt.Errorf("%w: signing key %s is %s after a concurrent hand-over",
			iamerr.ErrFailedPrecondition, kid, rec.State)
	}
	out.AlreadyDone = true
	return out, nil
}

// Compromise объявляет ключ утёкшим: он покидает набор немедленно, и
// подписанные им токены отвергаются. Это принятая цена, а не дефект.
//
// # Порядок: снять, потом заменить — и почему не наоборот
//
// Замена первой оставила бы утёкший ключ в наборе на время порождения нового,
// и всё это время токен, подписанный утёкшим материалом, проходил бы проверку.
// Снятие первым даёт обратное окно — служба какое-то время не подписывает, — и
// оно выбрано: отказ в выдаче виден сразу и чинится повтором, принятая подделка
// не видна никогда.
//
// # Частичный исход
//
// Снятие удалось, замена — нет: снятие НЕ откатывается (утёкший ключ в набор не
// возвращается ни при каком отказе), вызывающий получает
// ErrNoSignerAfterCompromise, а повтор той же команды отвечает AlreadyDone,
// довершает замену и называет её в Replacement. Замена заводится, только когда
// подписывающего нет: утечка не подписывающего ключа подпись не трогает.
//
// «Подписывающего нет» судится ЧТЕНИЕМ, а не отказом чтения и не отказом
// записи: сбой хранилища на чтении и вызов, кончившийся посреди замены, дают
// ErrSignerUnknownAfterCompromise — о подписи вердикта нет, и называть службу
// неподписывающей нечем. Не легшая замена при живом вызове сама ничего о подписи
// не говорит, поэтому подписывающий ПЕРЕЧИТЫВАЕТСЯ после неё: прочитан —
// исход без отказа и с подписывающим в Signer; прочитано, что его нет, —
// ErrNoSignerAfterCompromise; чтение отказало — ErrSignerUnknownAfterCompromise.
func (k *Keystore) Compromise(ctx context.Context, kid domain.KeyID, decidedBy string) (LifecycleOutcome, error) {
	out := LifecycleOutcome{KID: kid}
	if err := requireDecider("declaring a key compromised", decidedBy); err != nil {
		return out, err
	}
	if err := k.writer.Compromise(ctx, kid, k.now()); err != nil {
		if !errors.Is(err, iamerr.ErrFailedPrecondition) {
			k.failures.Add(1)
			return out, err
		}
		// Ноль строк условного перехода: ключа нет ЛИБО он уже снят. Различает
		// их чтение — ошибившийся в идентификаторе обязан об этом узнать.
		rec, gerr := k.reader.Get(ctx, kid)
		if gerr != nil {
			return out, gerr
		}
		if rec.State != domain.SigningKeyCompromised {
			return out, err
		}
		out.AlreadyDone = true
	} else {
		k.compromised.Add(1)
		k.logger.Warn("signing key declared compromised — it leaves the key set immediately",
			"kid", string(kid), "decided_by", decidedBy)
	}

	_, aerr := k.reader.Active(ctx)
	switch {
	case aerr == nil:
		return out, nil
	case !errors.Is(aerr, iamerr.ErrFailedPrecondition):
		k.failures.Add(1)
		return out, fmt.Errorf("%w: reading the signing key: %w", ErrSignerUnknownAfterCompromise, aerr)
	}
	pub, rerr := k.Rotate(ctx)
	if rerr != nil {
		if ctx.Err() != nil {
			// Вызов кончился посреди замены: запись её могла и лечь. Исход
			// замены не установлен, и «замены нет» было бы утверждением
			// без основания.
			return out, fmt.Errorf("%w: the call ended during the replacement: %w", ErrSignerUnknownAfterCompromise, rerr)
		}
		return k.compromiseOutcomeAfterFailedReplacement(ctx, out, decidedBy, rerr)
	}
	out.Replacement = pub.KID
	k.logger.Warn("signing handed over after a compromise", "compromised_kid", string(kid),
		"kid", string(pub.KID), "decided_by", decidedBy)
	return out, nil
}

// compromiseOutcomeAfterFailedReplacement выбирает исход утечки, когда замена,
// заводимая этим вызовом, не легла, — по подписывающему, ПЕРЕЧИТАННОМУ после
// отказа, а не по чтению, сделанному до него.
//
// Отказ замены о подписи не говорит ничего: повышение отказывает и тогда, когда
// подписывающим успел стать чужой ключ (реплика обеспечила подписывающего на
// старте, второй оператор гнал тот же повтор), и тогда, когда фиксация
// отказала неоднозначно. Исходов три, и у каждого своё основание: подписывающий
// прочитан — отказа нет, он назван; прочитано, что его нет, — частичный исход;
// чтение отказало — о подписи вердикта нет.
func (k *Keystore) compromiseOutcomeAfterFailedReplacement(
	ctx context.Context,
	out LifecycleOutcome,
	decidedBy string,
	replaceErr error,
) (LifecycleOutcome, error) {
	rec, aerr := k.reader.Active(ctx)
	switch {
	case aerr == nil:
		out.Signer = rec.KID
		k.logger.Warn("the replacement after a compromise failed, and the signing key read after the failure signs",
			"compromised_kid", string(out.KID), "kid", string(rec.KID), "decided_by", decidedBy,
			"replacement_err", replaceErr.Error())
		return out, nil
	case errors.Is(aerr, iamerr.ErrFailedPrecondition):
		return out, fmt.Errorf("%w: %w", ErrNoSignerAfterCompromise, replaceErr)
	default:
		k.failures.Add(1)
		return out, fmt.Errorf("%w: reading the signing key after the failed replacement: %w (replacement: %w)",
			ErrSignerUnknownAfterCompromise, aerr, replaceErr)
	}
}

// RotateIfDue передаёт подпись новому ключу, когда до объявленного срока
// подписывающего осталось не больше запаса ротации.
//
// # Решение: срок управляет РОТАЦИЕЙ, а не отбором подписывающего (#314)
//
// Объявленный срок ключа (`NotAfter`) можно было бы судить на отборе —
// отказываться подписывать ключом с истёкшим сроком. Выбрано другое: ротатор
// зовётся ДО срока. Отбор, отвергающий истёкший ключ, превращал бы любой
// пропуск ротации в остановку выдачи — отказ по календарю, а не по событию;
// ротация до срока держит выдачу и делает срок действующим. Запас ротации
// объявлен вызывающим с расчётом на пропущенные проходы.
//
// Проигранная гонка (соседняя реплика успела раньше) — не отказ: подпись уже у
// нового ключа, а свой порождённый ключ выведен.
func (k *Keystore) RotateIfDue(ctx context.Context) (bool, error) {
	rec, err := k.reader.Active(ctx)
	if err != nil {
		k.failures.Add(1)
		return false, fmt.Errorf("signingkeys: read the signing key: %w", err)
	}
	if k.now().Before(rec.NotAfter.Add(-k.cfg.RotationLead)) {
		return false, nil
	}
	if _, err := k.rotateReplacing(ctx, rec.KID); err != nil {
		if errors.Is(err, ErrSignerChanged) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// SweepRemovable снимает из набора выведенные ключи, чья отсрочка истекла.
//
// Отсрочка ВЫЧИСЛЕНА и передана настройкой; здесь она только применяется.
// Ключ снимается не «когда решили», а когда истёк последний подписанный им
// токен плюс потолок кэша самого медленного потребителя.
func (k *Keystore) SweepRemovable(ctx context.Context) (int, error) {
	set, err := k.reader.KeySet(ctx)
	if err != nil {
		k.failures.Add(1)
		return 0, err
	}
	now := k.now()
	var n int
	for _, rec := range set {
		if rec.State != domain.SigningKeyRetired || rec.RetiredAt == nil {
			continue
		}
		if now.Before(rec.RetiredAt.Add(k.cfg.RemovalGrace)) {
			continue
		}
		if err := k.writer.Remove(ctx, rec.KID, now); err != nil {
			if errors.Is(err, iamerr.ErrFailedPrecondition) {
				// Ключ уже снят — соседней репликой либо оператором. Это
				// НЕ отказ: снятие идемпотентно по существу, и прерывать из-за
				// него обход остальных ключей значило бы, что сметатель
				// работает тем хуже, чем больше реплик.
				continue
			}
			k.failures.Add(1)
			return n, err
		}
		k.removed.Add(1)
		n++
		k.logger.Info("signing key removed from the key set", "kid", string(rec.KID))
	}
	k.sweeps.Add(1)
	return n, nil
}

// EnsureSigningKey обеспечивает наличие подписывающего ключа при старте.
//
// Идемпотентна: при уже существующем подписывающем не делает ничего. Отказ
// хранилища НЕ подменяется порождением — иначе недоступная база на старте
// давала бы новый ключ на каждой реплике.
//
// ПОРЯДОК ЗДЕСЬ НЕСУЩИЙ, а не оформление (задача #1062): ключница читается
// ПЕРВОЙ, и предъявленный ключ обёртки обязан открыть уже записанное — прежде
// чем что бы то ни было порождается. Обратный порядок давал класс, в котором
// «пересоздали стенд» и «потеряли все подписи» неотличимы: приватная половина
// перестаёт разворачиваться, подписывающего «нет», ключница молча заводит
// новый, служба поднимается, набор отвечает — а каждый ранее выданный токен
// уже непроверяем, и ни одного сообщения о потере нет.
func (k *Keystore) EnsureSigningKey(ctx context.Context) error {
	// Недоступное хранилище — НЕ «ключница пуста»: порождение здесь дало бы
	// новый ключ на каждой реплике при первом же сбое сети.
	if err := k.VerifyWrappingKey(ctx); err != nil {
		return err
	}

	rec, aerr := k.reader.Active(ctx)
	if aerr == nil {
		k.logger.Info("signing key already present", "kid", string(rec.KID))
		return nil
	}
	pub, gerr := k.Rotate(ctx)
	if gerr != nil {
		return fmt.Errorf("signingkeys: no signing key and none could be created: %w", gerr)
	}
	k.logger.Info("signing key bootstrapped", "kid", string(pub.KID))
	return nil
}

// VerifyWrappingKey доказывает, что предъявленный ключ обёртки открывает уже
// записанное, и НИЧЕГО не меняет.
//
// Отдельно от EnsureSigningKey, потому что нужен и тому, кто подписывающего
// заводить НЕ вправе: действие оператора над ключом (#314) может породить
// замену, и порождённая с чужим ключом обёртки она была бы нечитаема каждой
// репликой, — а лечить подпись до глагола оно не должно, иначе глагол не видит
// того, что сделал, и отказ по ключу меняет набор.
func (k *Keystore) VerifyWrappingKey(ctx context.Context) error {
	set, err := k.reader.KeySet(ctx)
	if err != nil {
		k.failures.Add(1)
		return fmt.Errorf("signingkeys: read the key set: %w", err)
	}
	if err := k.assertWrappingKeyOpens(set); err != nil {
		return err
	}
	// Величина печатается ВСЕГДА, включая ноль: «ключ обёртки проверен на нуле
	// ключей» обязано быть отличимо от «проверка не исполнялась».
	k.logger.Info("wrapping key opens the stored key set", "keys_in_set", len(set))
	return nil
}

// assertWrappingKeyOpens доказывает, что предъявленный ключ обёртки
// разворачивает КАЖДЫЙ ключ набора.
//
// Почему весь набор, а не один подписывающий: опубликованный ключ вступает в
// подпись позже, и отложенный отказ пришёлся бы на ротацию — то есть на момент,
// который выбирает платформа, а не оператор. Выведенный ключ остаётся в наборе
// на отсрочку, и его нечитаемость есть тот же признак смены ключа обёртки.
// Снятые и объявленные утёкшими в набор не входят и здесь не рассматриваются:
// их приватная половина не нужна никогда, и требовать её читаемости значило бы
// сделать отказ невылечимым.
//
// Отказ называет ВСЕ нечитаемые ключи и их долю: одно имя из десяти читается
// как единичная поломка, тогда как предмет — смена ключа обёртки целиком.
func (k *Keystore) assertWrappingKeyOpens(set []domain.SigningKeyRecord) error {
	var unreadable []string
	for _, rec := range set {
		if _, err := k.wrapper.Unwrap(rec.PrivateKeyWrapped); err != nil {
			unreadable = append(unreadable, string(rec.KID))
		}
	}
	if len(unreadable) == 0 {
		return nil
	}
	k.failures.Add(1)
	// Текст отказа — рантайм-диагностика оператору, поднимающему стенд: он
	// обязан назвать предмет прямо. Материала здесь нет и быть не может —
	// названы только идентификаторы ключей, публикуемые в наборе.
	return fmt.Errorf(
		"%w: %d of %d keys in the key set do not open (%s); the store outlived the wrapping key that wrapped them. "+
			"Restore that wrapping key — a different one cannot be substituted, and generating a fresh signing key over "+
			"unreadable ones would void every token already issued without saying so",
		ErrWrappingKeyMismatch, len(unreadable), len(set), strings.Join(unreadable, ", "))
}

// PublishedSet возвращает набор в ПУБЛИКУЕМОЙ форме.
//
// Проекция строк ключницы; собственной копии набора публикатор не держит,
// поэтому состояния «ключ подписывает, а в ответе его нет» не существует.
func (k *Keystore) PublishedSet(ctx context.Context) ([]domain.PublishedKey, error) {
	set, err := k.reader.KeySet(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]domain.PublishedKey, 0, len(set))
	for _, rec := range set {
		out = append(out, rec.Published())
	}
	return out, nil
}

// ActiveSigningKey отдаёт подписной материал подписанту: приватная половина
// развёрнута здесь и дальше процесса не уходит.
//
// Реализует порт tokensigner.KeyProvider — и это ЕДИНСТВЕННЫЙ читатель
// приватной половины в производстве. Хранилище, у которого нет такого
// читателя, неотличимо от исправного: запись в него удаётся.
func (k *Keystore) ActiveSigningKey(ctx context.Context) (tokensigner.SigningMaterial, error) {
	rec, err := k.reader.Active(ctx)
	if err != nil {
		k.failures.Add(1)
		return tokensigner.SigningMaterial{}, err
	}
	plain, err := k.wrapper.Unwrap(rec.PrivateKeyWrapped)
	if err != nil {
		k.failures.Add(1)
		// Текст не несёт ни байта материала и не называет, чем именно
		// значение негодно.
		return tokensigner.SigningMaterial{}, fmt.Errorf("signingkeys: signing key %s is not readable back: %w", rec.KID, err)
	}
	return tokensigner.SigningMaterial{
		KID:           rec.KID,
		Algorithm:     rec.Algorithm,
		PrivateKeyPEM: plain,
		PublicKeyPEM:  rec.PublicKeyPEM,
	}, nil
}

var _ tokensigner.KeyProvider = (*Keystore)(nil)

func (k *Keystore) now() time.Time { return k.cfg.Clock().UTC().Truncate(time.Second) }

// newKeyID порождает идентификатор ключа объявленной формы.
//
// Значение уникально by construction (80 бит из системного источника
// случайности), поэтому «попарно различны» верно БЕЗ проверки-перед-вставкой:
// та была бы software check-then-act, запрещённый ban #10, и под конкуренцией
// два порождения увидели бы один и тот же свободный идентификатор.
//
// Пространство идентификаторов ресурсов (pkg/ids) здесь намеренно НЕ
// используется: `kid` ресурсом не является, и его появление в маршрутизаторе
// префиксов означало бы, что чужой идентификатор ключа выглядит нашим
// ресурсом.
func newKeyID() (domain.KeyID, error) {
	var raw [10]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("signingkeys: key id entropy: %w", err)
	}
	kid := domain.KeyID("kaname-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:])))
	if err := kid.Validate(); err != nil {
		return "", fmt.Errorf("signingkeys: generated key id: %w", err)
	}
	return kid, nil
}
