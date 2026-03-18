# ThreatLens ATT&CK-Style Category Mapping

## Overview

ThreatLens maps each security event to the most likely
[MITRE ATT&CK](https://attack.mitre.org/) tactic category using a
**heuristic, rule-based approach**.

The mapping is implemented in `src/threatlens/mapper.py` and operates
entirely offline using only the event's features and raw fields.
No ATT&CK dataset download or network connection is required.

> **Important:** This mapping is heuristic and educational.  It is intended
> to orient analysts toward the most probable tactic category, not to provide
> authoritative ATT&CK technique IDs.  Always verify with a full ATT&CK
> navigator or formal threat intelligence workflow in a real SOC environment.

---

## Supported Categories

ThreatLens maps events to the following ATT&CK tactic categories (a subset
of the full MITRE ATT&CK framework):

| Category               | ATT&CK Tactic Equivalent        |
|------------------------|---------------------------------|
| Execution              | TA0002 – Execution              |
| Persistence            | TA0003 – Persistence            |
| Privilege Escalation   | TA0004 – Privilege Escalation   |
| Credential Access      | TA0006 – Credential Access      |
| Discovery              | TA0007 – Discovery              |
| Lateral Movement       | TA0008 – Lateral Movement       |
| Command and Control    | TA0011 – Command and Control    |
| Exfiltration           | TA0010 – Exfiltration           |
| Initial Access         | TA0001 – Initial Access         |
| Unknown                | No clear match                  |

---

## Mapping Rules

Rules are evaluated in priority order.  The **first matching rule** wins.
This mirrors the priority structure of the ATT&CK framework, where certain
tactics (like C2) are more specific and actionable than general Execution.

### 1. Command and Control
**Triggers when:** external connection + suspicious port **or** external
connection + encoded payload in command line.

**Rationale:** A process connecting outside the network on an unusual port
(e.g., 4444, 31337) while using encoded commands is a strong indicator of
C2 beacon activity.

### 2. Exfiltration
**Triggers when:** external connection + bulk-copy or web-upload keyword
in command line (e.g., `robocopy`, `Invoke-WebRequest`, `upload`, `scp`).

**Rationale:** Exfiltration typically involves moving data to an external
endpoint using standard tools or protocols to blend in.

### 3. Privilege Escalation
**Triggers when:** `privilege_escalation_flag` is set.

**Rationale:** This flag is set by events that match known priv-esc patterns
(e.g., `net localgroup administrators`, `mimikatz privilege::debug`).

### 4. Persistence
**Triggers when:** `persistence_flag` is set.

**Rationale:** Registry run keys, scheduled tasks, and similar persistence
mechanisms are identified in the raw event data and propagated via this flag.

### 5. Credential Access
**Triggers when:** `failed_logins` ≥ 5.

**Rationale:** Repeated failed authentication attempts are a classic
indicator of brute-force or credential-stuffing activity.

### 6. Lateral Movement
**Triggers when:** process is a known remote-execution tool (`psexec.exe`,
`wmic.exe`, `mstsc.exe`) or the command line contains patterns like `\\\\`
(UNC paths), `/node:`, `Invoke-Command`, or `Enter-PSSession`.

**Rationale:** Lateral movement often involves remote process execution or
remote desktop connections to spread through the network.

### 7. Discovery
**Triggers when:** the process name is a known recon tool (e.g., `whoami.exe`,
`net.exe`, `ipconfig.exe`, `systeminfo.exe`).

**Rationale:** Attackers routinely run enumeration tools immediately after
gaining a foothold to understand their environment.

### 8. Execution
**Triggers when:** encoded/obfuscated command **or** suspicious command-line
pattern is detected **or** suspicious parent→child chain is present.

**Rationale:** Script-based execution (PowerShell, WScript, MSHTA) with
encoded payloads or policy bypasses indicates active code execution.

### Fallback: Unknown
If none of the above rules match, the event is categorized as **Unknown**.
This commonly applies to routine, benign events with no detectable signals.

---

## Mapping Examples

| Process          | Parent         | Key Signals                      | Mapped Category        |
|------------------|----------------|----------------------------------|------------------------|
| `powershell.exe` | `cmd.exe`      | `-Enc`, external→port 4444       | Command and Control    |
| `schtasks.exe`   | `cmd.exe`      | `persistence_flag=True`          | Persistence            |
| `net.exe`        | `cmd.exe`      | `localgroup administrators`      | Privilege Escalation   |
| `whoami.exe`     | `cmd.exe`      | —                                | Discovery              |
| `psexec.exe`     | `cmd.exe`      | `\\192.168.1.x`                  | Lateral Movement       |
| `svchost.exe`    | `services.exe` | `failed_logins=14`               | Credential Access      |
| `chrome.exe`     | `explorer.exe` | none                             | Unknown                |

---

## Extending the Mapper

To add a new category or refine an existing rule, edit the `_RULES` list in
`src/threatlens/mapper.py`.  Each rule is a tuple of:

```python
(category_name: str, short_reason: str, predicate_function)
```

The predicate receives `(row_raw, row_feat)` — one row from the events
DataFrame and one row from the features DataFrame — and should return a bool.

Rules are evaluated top-to-bottom; insert higher-priority rules earlier in
the list.

---

## Limitations

- Mapping is rule-based and may misclassify events with ambiguous signals.
- A single event is assigned only one primary category; real attacks span
  multiple tactics simultaneously.
- The rule set covers the most common attack patterns in the synthetic dataset
  and is not exhaustive against all ATT&CK techniques.
- For production use, integrate with a full ATT&CK mapping library such as
  [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) or
  a commercial threat intelligence platform.
