# Pumpkin State and Safety

## Autonomy Modes
- `observer`: observe + propose only
- `operator`: auto-executes Lane A, proposes others
- `steward`: auto-executes Lane A and selected Lane B during policy hours

Default mode is configured in `modules/config.yaml` under `modules.autonomy.mode`.

## Safety Lanes
- Lane A (auto): low-risk, reversible actions
- Lane B (proposal): medium-risk changes
- Lane C (restricted): high-risk or destructive actions

Policy allowlists are enforced in `policy.yaml`.

## Kill Switch
Set `PUMPKIN_SAFE_MODE=true` to disable execution. Observation continues.

## Allowlisted Paths
- Log rotation: `PUMPKIN_LOG_PATHS`
- Cache cleanup: `PUMPKIN_CACHE_PATHS`

## Always Restricted (Lane C)
- New services, installs, networking changes
- Destructive operations
- Unbounded filesystem edits
