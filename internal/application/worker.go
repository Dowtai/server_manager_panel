package application

import (
	"awgpanel/internal/deployment"
	"awgpanel/internal/domain"
	"awgpanel/internal/storage"
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"slices"
	"time"
)

const deploymentTimeout = 10 * time.Minute
const operationLease = deploymentTimeout + time.Minute

type Worker struct {
	Store   *storage.Store
	Service *Service
	Runner  deployment.Runner
}

func lockKey(id string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("awgpanel:instance:" + id))
	return int64(h.Sum64())
}
func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	lastSweep := time.Time{}
	for {
		if time.Since(lastSweep) > time.Minute {
			if e := w.Sweep(ctx); e != nil {
				slog.Error("reconcile failed", "error", e)
			}
			w.refreshDNS(ctx)
			lastSweep = time.Now()
		}
		if e := w.Once(ctx); e != nil && ctx.Err() == nil {
			slog.Error("worker iteration failed", "error", e)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
func (w *Worker) Sweep(ctx context.Context) error {
	return w.Store.Update(ctx, func(s *domain.State) error {
		_, e := Reconcile(s, "worker")
		if e != nil {
			return e
		}
		for _, d := range s.Deployments {
			if d.Remove || d.AppliedRevision != d.DesiredRevision || time.Since(d.CheckedAt) > 5*time.Minute {
				failed := false
				var latest time.Time
				for _, o := range s.Operations {
					if o.DeploymentID == d.ID && !o.UpdatedAt.Before(latest) {
						latest = o.UpdatedAt
						failed = o.Status == "failed"
					}
				}
				if !failed {
					queue(s, d, "worker")
				}
			}
		}
		return nil
	})
}
func (w *Worker) Once(ctx context.Context) error {
	var candidates []domain.Operation
	e := w.Store.View(ctx, func(s *domain.State) error {
		for _, o := range s.Operations {
			if (o.Status == "queued" || o.Status == "retry" || o.Status == "running") && !o.AvailableAt.After(time.Now()) {
				candidates = append(candidates, o)
			}
		}
		return nil
	})
	if e != nil || len(candidates) == 0 {
		return e
	}
	slices.SortFunc(candidates, func(a, b domain.Operation) int { return a.CreatedAt.Compare(b.CreatedAt) })
	for _, candidate := range candidates {
		conn, e := w.Store.Pool.Acquire(ctx)
		if e != nil {
			return e
		}
		var locked bool
		e = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", lockKey(candidate.InstanceID)).Scan(&locked)
		if e != nil {
			conn.Release()
			return e
		}
		if !locked {
			conn.Release()
			continue
		}
		// Session lock survives short transactions and excludes every other worker for this instance.
		// It is released by PostgreSQL if the worker dies. Remote flock additionally serializes server changes.
		err := w.process(ctx, candidate)
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, unlockErr := conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", lockKey(candidate.InstanceID))
		cancel()
		if unlockErr != nil {
			_ = conn.Conn().Close(context.Background())
		}
		conn.Release()
		return err
	}
	return nil
}
func (w *Worker) process(ctx context.Context, candidate domain.Operation) error {
	var snap deployment.Snapshot
	var op domain.Operation
	found := false
	e := w.Store.Update(ctx, func(s *domain.State) error {
		current, ok := s.Operations[candidate.ID]
		if !ok || current.Status == "done" || current.Status == "failed" || current.AvailableAt.After(time.Now()) {
			return nil
		}
		d, ok := s.Deployments[current.DeploymentID]
		if !ok {
			current.Status = "done"
			s.Operations[current.ID] = current
			return nil
		}
		current.Status = "running"
		current.Stage = "applying"
		current.Attempts++
		current.UpdatedAt = time.Now().UTC()
		current.AvailableAt = time.Now().Add(operationLease).UTC()
		s.Operations[current.ID] = current
		op = current
		snap.Deployment = d
		snap.Instance = s.Instances[d.InstanceID]
		snap.Server = s.Servers[d.ServerID]
		snap.Pool = s.Pools[snap.Server.PoolID]
		for _, device := range s.Devices {
			if device.InstanceID == d.InstanceID && !device.Revoked {
				device.PrivateKey = ""
				snap.Devices = append(snap.Devices, device)
			}
		}
		slices.SortFunc(snap.Devices, func(a, b domain.Device) int { return a.CreatedAt.Compare(b.CreatedAt) })
		found = true
		return nil
	})
	if e != nil || !found {
		return e
	}
	open := w.Service.Vault.Open
	runErr := error(nil)
	if snap.Server.Credential, runErr = open(snap.Server.Credential, snap.Server.ID+":ssh"); runErr == nil && !snap.Deployment.Remove {
		snap.Instance.PrivateKey, runErr = open(snap.Instance.PrivateKey, snap.Instance.ID+":private")
	}
	if runErr == nil && !snap.Deployment.Remove {
		snap.Instance.Params.HeaderKey, runErr = open(snap.Instance.Params.HeaderKey, snap.Instance.ID+":header")
	}
	if runErr == nil && !snap.Deployment.Remove {
		snap.Instance.ProbePrivateKey, runErr = open(snap.Instance.ProbePrivateKey, snap.Instance.ID+":probe")
	}
	if runErr == nil && !snap.Deployment.Remove {
		snap.Instance.ProbePSK, runErr = open(snap.Instance.ProbePSK, snap.Instance.ID+":probe_psk")
	}
	if runErr == nil && !snap.Deployment.Remove {
		for n := range snap.Devices {
			snap.Devices[n].PSK, runErr = open(snap.Devices[n].PSK, snap.Devices[n].ID+":psk")
			if runErr != nil {
				break
			}
		}
	}
	applied := false
	verified := false
	runCtx, cancel := context.WithTimeout(ctx, deploymentTimeout)
	defer cancel()
	if runErr == nil {
		if snap.Deployment.Remove {
			runErr = w.Runner.Remove(runCtx, snap)
		} else {
			runErr = w.Runner.Apply(runCtx, snap)
			applied = runErr == nil
			if applied {
				runErr = w.Runner.Probe(runCtx, snap)
				verified = runErr == nil
			}
		}
	}
	finishCtx, finishCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer finishCancel()
	return w.Store.Update(finishCtx, func(s *domain.State) error {
		d, ok := s.Deployments[snap.Deployment.ID]
		o := s.Operations[op.ID]
		if o.Attempts != op.Attempts || o.Status != "running" {
			return nil
		}
		if !ok {
			o.Status = "done"
			s.Operations[o.ID] = o
			return nil
		}
		o.UpdatedAt = time.Now().UTC()
		d.CheckedAt = o.UpdatedAt
		if applied {
			d.AppliedRevision = snap.Instance.Revision
		}
		if runErr != nil {
			d.VerifiedRevision = 0
			d.Status = "error"
			d.Error = runErr.Error()
			o.Error = d.Error
			o.Status = "retry"
			o.Stage = "apply_or_probe_failed"
			if o.Attempts >= 5 {
				o.Status = "failed"
			}
			o.AvailableAt = time.Now().Add(time.Duration(1<<min(o.Attempts, 7)) * 5 * time.Second).UTC()
		} else if d.Remove == snap.Deployment.Remove && d.DesiredRevision == snap.Deployment.DesiredRevision {
			if d.Remove {
				delete(s.Deployments, d.ID)
				o.Status = "done"
				o.Stage = "removed"
				s.Operations[o.ID] = o
				audit(s, "worker", "remove_deployment", d.ID)
				return nil
			}
			d.Status = "ready"
			d.Error = ""
			if verified {
				d.VerifiedRevision = snap.Instance.Revision
				d.VerifiedAt = time.Now().UTC()
			}
			o.Status = "done"
			o.Stage = "verified"
			o.Error = ""
		} else {
			d.Status = "syncing"
			d.VerifiedRevision = 0
			o.Status = "queued"
			o.Stage = "new_revision"
			o.AvailableAt = time.Now().UTC()
		}
		s.Deployments[d.ID] = d
		s.Operations[o.ID] = o
		audit(s, "worker", fmt.Sprintf("operation_%s", o.Status), o.ID)
		return nil
	})
}

func (w *Worker) refreshDNS(ctx context.Context) {
	var endpoints []domain.Endpoint
	_ = w.Store.View(ctx, func(s *domain.State) error {
		for _, e := range s.Endpoints {
			if e.TargetServerID != "" {
				endpoints = append(endpoints, e)
			}
		}
		return nil
	})
	for _, e := range endpoints {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, _ = w.Service.CheckDNS(c, "worker", e.ID, e.TargetServerID)
		cancel()
	}
}
