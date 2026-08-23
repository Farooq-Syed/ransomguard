# External Validation Status

## Current evidence

RansomGuard has matched heuristic-versus-ML experiments on clean, noisy,
near-real, and walk-forward simulator workloads. Those experiments test detector
logic, calibration, false-positive behavior, and distribution shift inside a safe
filesystem sandbox. They do not establish performance against real ransomware
families or ordinary enterprise endpoint activity.

## Safe external-validation design

The next defensible experiment requires an isolated VM with disposable snapshots,
network egress disabled, and independently sourced benign endpoint traces. Real
ransomware execution must use institutionally approved samples and handling
procedures; this repository does not download or distribute live malware.

The evaluation unit should be a complete session, not a file. For each family or
benign workload, record time to first alert, files changed before alert, session
detection, false-positive session rate, and recovery outcome. Family identity,
sample hash, VM image hash, detector configuration, and random seed must accompany
every result.

## Claim boundary

Until that controlled replay is completed, the publishable claim is comparative:
v2 reduces false positives and exposes drift more clearly than v1 on matched
simulator workloads. The repository does not claim a real-family detection rate.
