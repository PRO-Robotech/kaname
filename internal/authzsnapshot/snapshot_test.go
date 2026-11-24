// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzsnapshot

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
)

type snapshotSourceStub struct {
	load    func(context.Context) (Snapshot, error)
	confirm func(context.Context, *Snapshot) (time.Time, error)
}

func (s snapshotSourceStub) LoadActivePublication(ctx context.Context) (Snapshot, error) {
	return s.load(ctx)
}

func (s snapshotSourceStub) ConfirmActivePublication(ctx context.Context, snapshot *Snapshot) (time.Time, error) {
	return s.confirm(ctx, snapshot)
}

func testSnapshot(revision int64, at time.Time) Snapshot {
	return Snapshot{
		Revision: revision, Digest: "digest", CatalogID: "catalog", ConfirmedAt: at,
		Plans: &authzmodel.Plans{}, Facts: &catalog.Facts{},
	}
}

func TestFactsForRequestKeepsPinnedPublicationAcrossSourceRefresh(t *testing.T) {
	published := testSnapshot(1, time.Now())
	ctx, err := WithContext(context.Background(), &published)
	if err != nil {
		t.Fatal(err)
	}
	legacy := catalog.Fixed{F: &catalog.Facts{}}
	if got := FactsForRequest(ctx, legacy); got != published.Facts {
		t.Fatal("request did not use its published catalog")
	}
	legacy.F = &catalog.Facts{}
	if got := FactsForRequest(ctx, legacy); got != published.Facts {
		t.Fatal("source refresh changed the request catalog")
	}
	if got := FactsForRequest(ctx, nil); got != published.Facts {
		t.Fatal("pinned catalog requires a legacy source")
	}
	if got := FactsForRequest(context.Background(), legacy); got != legacy.F {
		t.Fatal("legacy request did not use its source")
	}
	if got := FactsForRequest(context.Background(), nil); got != nil {
		t.Fatal("missing legacy source produced catalog facts")
	}
}

func testSnapshotStore(t *testing.T, source Source, now *time.Time, window time.Duration) *Store {
	t.Helper()
	store, err := NewStore(source, window)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return *now }
	return store
}

func TestStorePinBeforeConfirmation(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := testSnapshotStore(t, snapshotSourceStub{}, &now, time.Minute)
	if _, err := store.Pin(context.Background()); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("Pin before refresh: got %v, want ErrUnconfirmed", err)
	}
	if err := store.ConfirmPin(context.Background()); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("ConfirmPin without snapshot: got %v, want ErrUnconfirmed", err)
	}
}

func TestStoreSameHeadConfirmationExtendsNewPins(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	initial := now
	loads := 0
	store := testSnapshotStore(t, snapshotSourceStub{
		load: func(context.Context) (Snapshot, error) {
			loads++
			return testSnapshot(1, initial), nil
		},
		confirm: func(_ context.Context, snapshot *Snapshot) (time.Time, error) {
			if snapshot.Revision != 1 {
				t.Fatalf("confirmed revision %d, want 1", snapshot.Revision)
			}
			return now, nil
		},
	}, &now, time.Minute)
	if err := store.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	oldPin, err := store.Pin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now = initial.Add(45 * time.Second)
	if err := store.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	newPin, err := store.Pin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	oldSnapshot, _ := FromContext(oldPin)
	newSnapshot, _ := FromContext(newPin)
	if !oldSnapshot.ConfirmedAt.Equal(initial) || !newSnapshot.ConfirmedAt.Equal(now) {
		t.Fatalf("confirmation times: old %v, new %v", oldSnapshot.ConfirmedAt, newSnapshot.ConfirmedAt)
	}
	if loads != 1 {
		t.Fatalf("loaded publication %d times, want 1", loads)
	}
	now = initial.Add(time.Minute)
	if err := store.ConfirmPin(oldPin); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("expired old pin: got %v, want ErrUnconfirmed", err)
	}
	if err := store.ConfirmPin(newPin); err != nil {
		t.Fatalf("renewed pin: %v", err)
	}
	if _, err := store.Pin(ctx); err != nil {
		t.Fatalf("Pin after original window: %v", err)
	}
}

func TestStoreSourceFailureRetainsOnlyOriginalWindow(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	initial := now
	unavailable := errors.New("source unavailable")
	store := testSnapshotStore(t, snapshotSourceStub{
		load:    func(context.Context) (Snapshot, error) { return testSnapshot(1, initial), nil },
		confirm: func(context.Context, *Snapshot) (time.Time, error) { return time.Time{}, unavailable },
	}, &now, time.Minute)
	if err := store.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	now = initial.Add(time.Minute - time.Nanosecond)
	if err := store.Refresh(ctx); !errors.Is(err, unavailable) {
		t.Fatalf("Refresh: got %v, want source error", err)
	}
	pin, err := store.Pin(ctx)
	if err != nil {
		t.Fatalf("Pin inside original window: %v", err)
	}
	if err := store.ConfirmPin(pin); err != nil {
		t.Fatal(err)
	}
	now = initial.Add(time.Minute)
	if _, err := store.Pin(ctx); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("Pin at window boundary: got %v, want ErrUnconfirmed", err)
	}
	if err := store.ConfirmPin(pin); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("ConfirmPin at window boundary: got %v, want ErrUnconfirmed", err)
	}
}

func TestStoreKnownHeadChangeInvalidatesPinEvenIfLoadFails(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	unavailable := errors.New("new publication unavailable")
	loads := 0
	store := testSnapshotStore(t, snapshotSourceStub{
		load: func(context.Context) (Snapshot, error) {
			loads++
			if loads > 1 {
				return Snapshot{}, unavailable
			}
			return testSnapshot(1, now), nil
		},
		confirm: func(context.Context, *Snapshot) (time.Time, error) { return time.Time{}, ErrUnconfirmed },
	}, &now, time.Minute)
	if err := store.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	pin, err := store.Pin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Refresh(ctx); !errors.Is(err, unavailable) {
		t.Fatalf("Refresh after head change: got %v, want load error", err)
	}
	if _, err := store.Pin(ctx); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("Pin after head change: got %v, want ErrUnconfirmed", err)
	}
	if err := store.ConfirmPin(pin); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("stale pin after head change: got %v, want ErrUnconfirmed", err)
	}
}

func TestStoreRejectsOlderRevision(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	revision := int64(2)
	store := testSnapshotStore(t, snapshotSourceStub{
		load:    func(context.Context) (Snapshot, error) { return testSnapshot(revision, now), nil },
		confirm: func(context.Context, *Snapshot) (time.Time, error) { return time.Time{}, ErrUnconfirmed },
	}, &now, time.Minute)
	if err := store.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	revision = 1
	if err := store.Refresh(ctx); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("Refresh with older revision: got %v, want ErrUnconfirmed", err)
	}
	if _, err := store.Pin(ctx); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("Pin after rejected revision: got %v, want ErrUnconfirmed", err)
	}
}

func TestStoreCommittedRevisionFencesOlderPinsAndRefreshes(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	revision := int64(1)
	digest := "digest"
	store := testSnapshotStore(t, snapshotSourceStub{
		load: func(context.Context) (Snapshot, error) {
			snapshot := testSnapshot(revision, now)
			snapshot.Digest = digest
			return snapshot, nil
		},
		confirm: func(context.Context, *Snapshot) (time.Time, error) { return time.Time{}, ErrUnconfirmed },
	}, &now, time.Minute)
	if err := store.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	old, err := store.Pin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store.ObserveCommittedRevision(3, "new-digest")
	if err := store.ConfirmPin(old); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("старый снимок после фиксации: %v", err)
	}
	revision = 2
	if err := store.Refresh(ctx); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("подтверждена редакция ниже зафиксированной: %v", err)
	}
	if _, err := store.Pin(ctx); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("отдан снимок ниже зафиксированной редакции: %v", err)
	}
	revision = 3
	if err := store.Refresh(ctx); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("подтверждена редакция с чужим отпечатком: %v", err)
	}
	digest = "new-digest"
	if err := store.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	current, err := store.Pin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store.ObserveCommittedRevision(2, "older-digest")
	if err := store.ConfirmPin(current); err != nil {
		t.Fatalf("более ранняя фиксация закрыла текущий снимок: %v", err)
	}
	store.ObserveCommittedRevision(3, "conflicting-digest")
	if err := store.ConfirmPin(current); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("конфликтующая фиксация сохранила текущий снимок: %v", err)
	}
	if err := store.Refresh(ctx); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("конфликтующая редакция снова подтверждена: %v", err)
	}
}

func TestStoreInvalidHeadKeepsOriginalWindow(t *testing.T) {
	ctx := context.Background()
	initial := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := initial
	invalid := false
	store := testSnapshotStore(t, snapshotSourceStub{
		load: func(context.Context) (Snapshot, error) {
			if invalid {
				return Snapshot{}, ErrInvalidPublication
			}
			return testSnapshot(1, now), nil
		},
		confirm: func(context.Context, *Snapshot) (time.Time, error) { return time.Time{}, ErrUnconfirmed },
	}, &now, time.Minute)
	if err := store.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	invalid = true
	now = initial.Add(45 * time.Second)
	if err := store.Refresh(ctx); !errors.Is(err, ErrInvalidPublication) {
		t.Fatalf("Refresh with damaged head: got %v, want ErrInvalidPublication", err)
	}
	pin, err := store.Pin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _ := FromContext(pin)
	if snapshot.Revision != 1 || !snapshot.ConfirmedAt.Equal(initial) {
		t.Fatalf("Pin after damaged head: got revision %d confirmed at %s", snapshot.Revision, snapshot.ConfirmedAt)
	}
	now = initial.Add(time.Minute)
	if _, err := store.Pin(ctx); !errors.Is(err, ErrUnconfirmed) {
		t.Fatalf("Pin at original boundary: got %v, want ErrUnconfirmed", err)
	}
}
