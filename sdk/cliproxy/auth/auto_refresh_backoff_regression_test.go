package auth

import (
	"testing"
	"time"
)

// startExpiredRefreshJob registers an expired credential and marks a refresh job
// pending for it, mirroring what the dispatcher does before handing it to a worker.
func startExpiredRefreshJob(t *testing.T) (*Manager, *authAutoRefreshLoop, *authRefreshJob) {
	t.Helper()
	now := time.Now()
	executor := &countingRefreshExecutor{id: issue6199RefreshProvider}
	manager, loop := newIssue6199RefreshLoop(executor)
	registerIssue6199ExpiredAuth(t, manager, "expired", now)

	manager.mu.RLock()
	auth := manager.auths["expired"]
	stillDue := manager.shouldRefresh(auth, now)
	epoch := auth.RegistrationEpoch
	manager.mu.RUnlock()
	if !stillDue {
		t.Fatal("fixture credential is not due for refresh")
	}

	job := manager.markRefreshPending(loop, "expired", epoch, now)
	if job == nil {
		t.Fatal("failed to mark refresh job pending")
	}
	return manager, loop, job
}

// assertRefreshBackedOff checks that the credential is not due again right away
// and that the dispatcher would not arm a zero-duration timer for it.
func assertRefreshBackedOff(t *testing.T, manager *Manager, loop *authAutoRefreshLoop, start time.Time) {
	t.Helper()
	manager.mu.RLock()
	next := manager.auths["expired"].NextRefreshAfter
	manager.mu.RUnlock()
	if !next.After(start.Add(refreshCheckInterval / 2)) {
		t.Fatalf("NextRefreshAfter = %v, want positive retry delay after %v", next, start)
	}

	loop.applyDirty(start)
	wait, ok := loop.nextWait(start)
	if !ok {
		t.Fatal("credential dropped from refresh queue")
	}
	if wait < refreshCheckInterval/2 {
		t.Fatalf("dispatcher wait = %v, want at least %v (zero wait spins the loop)", wait, refreshCheckInterval/2)
	}
}

// A refresh job that ends without recording a retry time must not leave an
// expired credential immediately due. Otherwise the dispatcher resets its
// timer to zero and spins on the same credential.
func TestFinishRefreshJobBacksOffWhenCredentialStillDue(t *testing.T) {
	start := time.Now()
	manager, loop, job := startExpiredRefreshJob(t)

	// Model an early refresh failure that returns before setting NextRefreshAfter.
	manager.finishRefreshJob(job, time.Time{}, false)

	assertRefreshBackedOff(t, manager, loop, start)
}

// Regression for the idle CPU burn seen on v8.0.64: the refresh path itself
// recorded a failure outcome with NextRefreshAfter cleared to zero while the
// credential stayed due (expired access token, refresh_outcome_unknown). The
// pending marker no longer matched, so finishRefreshJob left the zero in place,
// the dispatcher re-queued the credential with a zero wait, and dispatcher and
// worker spun at ~180% CPU with no traffic.
func TestFinishRefreshJobBacksOffWhenRefreshClearedNextRefreshAfter(t *testing.T) {
	start := time.Now()
	manager, loop, job := startExpiredRefreshJob(t)

	manager.mu.Lock()
	current := manager.auths["expired"]
	current.NextRefreshAfter = time.Time{}
	current.Generation++
	manager.mu.Unlock()

	manager.finishRefreshJob(job, time.Time{}, false)

	assertRefreshBackedOff(t, manager, loop, start)
}

// Jobs released at loop shutdown never ran, so they must stay due for the next loop.
func TestFinishRefreshJobQueuedOnlyKeepsCredentialDue(t *testing.T) {
	manager, _, job := startExpiredRefreshJob(t)

	manager.finishRefreshJob(job, time.Time{}, true)

	manager.mu.RLock()
	next := manager.auths["expired"].NextRefreshAfter
	manager.mu.RUnlock()
	if !next.IsZero() {
		t.Fatalf("NextRefreshAfter = %v, want zero for a job that never ran", next)
	}
}
