# Security and Responsible Use

This project can send raw network probes. Use it only in authorized environments.

## Authorization First

- Obtain explicit permission before scanning.
- Define scope (hosts, subnets, allowed time windows).
- Keep records of approvals.

## Legal and Policy Compliance

- Follow local and international law.
- Follow company policy and change-control procedures.
- Coordinate with security/network operations before wide scans.

## Operational Safety

- Start with small target ranges.
- Use conservative timeout and delay settings.
- Avoid scanning production systems during peak traffic windows.
- Monitor systems while scans are running.

## Data Sensitivity

Scan output may reveal:

- active hosts
- MAC addresses
- exposed ports
- environment topology hints

Treat output files and logs as sensitive data.

## Logging and Auditability

- Keep `logs/scanner.log` for traceability.
- Record scan purpose, operator, timestamp, and scope.
- Store reports in approved locations only.

## Incident Handling

If scanning causes disruption:

1. Stop scanning immediately.
2. Notify stakeholders.
3. Preserve logs and context.
4. Review root cause and adjust scan settings.

## Disclosure Guidance

If a scan identifies a likely vulnerability:

- Report through approved internal channels.
- Include reproducible evidence.
- Do not share findings outside authorized recipients.

## Practical Checklist

Before running a scan:

- [ ] I have written permission.
- [ ] Scope is documented.
- [ ] Timing is approved.
- [ ] I selected conservative defaults.
- [ ] I know where logs/output will be stored.
