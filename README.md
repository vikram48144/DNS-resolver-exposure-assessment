# Authorised DNS Resolver Exposure Assessment

## DNS Recursion Access Control Verification (RFC 5358)

[RFC 5358 section 4](https://www.rfc-editor.org/rfc/rfc5358.html#section-4)
recommends providing recursive lookup service only to intended clients. Open
recursive service can contribute to reflection attacks. This feature verifies
IP-based recursion and cache access using two real client containers, separately
from the existing four-class DNS behaviour assessment.

| Component | Trusted `dns-lab` (10.10.0.0/24) | Internal `external-test` (10.20.0.0/24) |
|---|---|---|
| Same recursive BIND instance | 10.10.0.2 | 10.20.0.2 |
| Assessment app / authorised client | 10.10.0.20 | Not attached |
| `unauthorized-dns-client` | Not attached | 10.20.0.30 |
| Authoritative / refusing DNS | 10.10.0.3 / 10.10.0.4 | Not attached |
| Existing packet-capture container | 10.10.0.10 | Not attached |

10.10.0.5 remains unused. `external-test` is an internal Docker bridge with no
published ports on its client. The resolver retains its non-internal trusted
network for outbound resolution and its existing Docker forwarder. The client
reuses the Python image and dnspython dependencies, drops all capabilities and
has a read-only root filesystem.

`lab/recursive/named.conf` defines `trusted_clients` as **only** 10.10.0.0/24.
Both `allow-recursion` and `allow-query-cache` use that ACL. `allow-query { any; };`
allows the untrusted client to receive an explicit refusal; it does not grant
recursion or cache access. BIND listens on both IPv4 interfaces. The authoritative
and refusing configurations are unchanged.

### Build and run

Run from `dns-resolver-assessment`:

```powershell
docker compose config
docker compose up -d --build
docker compose ps
docker compose exec -T recursive-dns named-checkconf /etc/bind/named.conf
docker compose exec -T dns-probe python -m security.recursion_access_test
```

Open http://localhost:5000 and click **Verify Recursion Access Control**. The
separate section displays the policy, two clients, query, response flags, RCODE,
answers, expected and observed access decisions, errors and overall status.
`POST /api/verify-recursion-acl` accepts an empty body or `{}` only. It never
accepts commands, client addresses, arbitrary targets or domains. Concurrent
dashboard ACL runs receive HTTP 429.

The application queries from its own 10.10.0.20 interface. A fixed worker in
`unauthorized-dns-client` queries from its own 10.20.0.30 interface. Binding a
local source address selects a real interface; it does not spoof an address.
The worker receives request IDs over the `acl-exchange` named volume, with
expiry, atomic writes and bounded waiting. No Docker socket, Docker execution
API, extra network attachment or HTTP listener is needed. Both queries are
fixed `example.com A`, UDP/53, RD=1, with a two-second DNS timeout and no retries.
The runner spaces tests by 0.5 seconds and the worker also paces requests.
Start the lab first and use `docker compose exec dns-probe`, rather than
`compose run`, to preserve the required authorised source address.

### Manual evidence and outcome rules

```powershell
docker compose exec -T dns-probe python -m security.recursion_access_test --client authorised
docker compose exec -T unauthorized-dns-client python -B -m security.recursion_access_test --client unauthorised
docker inspect recursive-dns dns-probe unauthorized-dns-client --format '{{.Name}} {{json .NetworkSettings.Networks}}'
docker network inspect dns-resolver-assessment_external-test
```

Expected authorised evidence: NOERROR, RD=1, RA=1 and a valid IPv4 answer,
classified ALLOWED. Expected untrusted evidence: REFUSED and no answers,
classified DENIED. RA alone is never proof of recursive access; a missing
response has unknown flags. A timeout, SERVFAIL, malformed/missing worker
response or network error is INCONCLUSIVE, not a successful denial.

Overall PASS requires ALLOWED for the authorised client and DENIED for the
unauthorised client. Explicit denial of the authorised client or demonstrated
recursive access for the unauthorised client produces FAIL, even when the
other test is inconclusive. Otherwise the result is INCONCLUSIVE.

Actual results, rather than expected values, are saved with UTC timestamp,
query, server/client addresses, subnets, probe evidence, errors and limitations
to `artifacts/results/recursion_access_control.json`. Download through
`/download/recursion-acl`. Existing assessment JSON/CSV and logs are preserved.
An authorised RECURSIVE classification alongside an ACL PASS is expected:
the classifier describes service from that client, while the ACL test compares
access from two different networks.

### Automated checks

```powershell
python -m pytest tests -v
docker compose exec -T dns-probe python -m pytest tests -v
node tests/acl-ui.cjs
node tests/lab-ui.cjs
node tests/evidence-ui.cjs
```

Unit tests cover allowed/denied policies, both failure cases, timeout, missing
worker, ambiguous responses, real-source argument selection, mailbox exchange,
input restrictions, safety configuration, report isolation and Compose topology.
They use mocked DNS evidence and do not claim live network verification. The
Node ACL check uses real backend results and checks the UI renderer and download;
the existing scripts exercise the original four targets and evidence rendering.

### Optional packet evidence

The existing capture container is on the trusted network only; it cannot be
assumed to see switched unicast traffic between other containers. To observe
both interfaces, start a temporary capture sharing the resolver's network
namespace (requires the netshoot image and capture capabilities):

```powershell
docker run --rm --name recursion-acl-capture --network container:recursive-dns --cap-add NET_RAW --cap-add NET_ADMIN -v "${PWD}/captures:/captures" nicolaka/netshoot tcpdump -i any -nn -U -w /captures/recursion-acl.pcap 'udp port 53 and (host 10.10.0.20 or host 10.20.0.30)'
```

Run the ACL verification in another terminal, then stop capture with Ctrl+C.
Inspect the actual packet source addresses and DNS responses in Wireshark.
This is an optional procedure; packet capture is not performed by the dashboard.

### Limits

This verifies IP-based access control for two IPv4 sources, one domain and UDP.
An answer may come from cache; the test does not prove a fresh upstream lookup.
It does not implement DNSSEC, authenticate identities, detect all IP spoofing,
test TCP/IPv6 policy, or prove resistance to every DNS attack. RFC 5358 also
discusses ingress filtering; source ACLs alone do not replace it. External
resolution depends on the host/upstream network. An unavailable upstream can
make the authorised test INCONCLUSIVE even when the ACL is correct.

The named volume is a trusted local lab coordination channel, not a boundary
against a compromised container or Docker administrator. Flask retains the
existing development-server deployment; do not expose this lab dashboard to
untrusted networks.

### Recorded verification — 21 November 2026

The Docker lab was built and started successfully. `docker compose config`
and `named-checkconf /etc/bind/named.conf` exited successfully. Docker inspection
confirmed the addresses above, the untrusted client's sole network attachment,
and `external-test` with `Internal=true`.

| Actual source → destination | RCODE | Response RD / RA | A answers | Observed |
|---|---|---|---|---|
| 10.10.0.20 → 10.10.0.2 | NOERROR | True / True | 104.20.23.154, 172.66.147.243 | ALLOWED |
| 10.20.0.30 → 10.20.0.2 | REFUSED | True / False | None | DENIED |

Overall live verification: **PASS**. The authorised query ran first, warming
the cache before the untrusted query; the untrusted client still received no
cached answers. These addresses are observed DNS data, not fixed test fixtures.
The original assessment classified all four targets correctly (4/4, 100%).
The Python suite passed 28 tests on the host and in the rebuilt Python 3.12
container. `acl-ui.cjs`, `lab-ui.cjs` and `evidence-ui.cjs` passed their live API
and JavaScript renderer checks. These checks do not measure visual layout in a
real browser. No packet capture was recorded during this verification.

## Interactive dashboard demonstrations

Start the lab and dashboard with `docker compose up -d --build`, then open
http://localhost:5000. The **External Domain Resolution Test** continues to
resolve your chosen domain through the fixed recursive resolver `10.10.0.2`.

The separate **Lab DNS Behaviour Test** lets you select one of the four
predefined lab targets and click **Probe DNS Server**. It sends `example.com A`
with RD=1 and `www.lab.example A` with RD=0, then uses the shared classifier.
Both responses, flags, records, attempts and errors appear below the selector.
The authoritative target should refuse the recursive query and return an
authoritative `10.10.0.100` answer for `www.lab.example`.

`POST /api/lab-probe` accepts only a JSON object such as
`{"target":"authoritative"}`. Allowed target names are `recursive`,
`authoritative`, `refused` and `inconclusive`. Arbitrary IPs and extra request
fields are rejected. The endpoint uses the configured timeout, retries and
query rate, including pacing retries. Concurrent lab requests receive HTTP 429
while a test is running. Lab demonstrations do not replace the saved assessment
reports. The existing assessment and external-domain endpoints are unchanged.

With the Docker lab running, verify all four live classifications, response
evidence, UI rendering and existing downloads with `node tests/lab-ui.cjs`.
The intentionally unused target takes longer because it exhausts timeout retries.

A reproducible cybersecurity tool for determining whether designated DNS servers provide recursive DNS resolution to an external lab client and for classifying their observed DNS behaviour.

The project creates a controlled Docker-based DNS laboratory containing known DNS configurations, probes each server using Python and `dnspython`, classifies the observed behaviour, validates the result against seeded ground truth, and generates machine-readable reports, logs, and packet-capture evidence.

---

## 1. Project Objective

The objective of this project is to safely determine whether an authorised DNS server exposes recursive resolution to an external client.

Each designated DNS server is classified as one of:

- `RECURSIVE`
- `AUTHORITATIVE_ONLY`
- `REFUSED`
- `INCONCLUSIVE`

The assessment is deliberately restricted to authorised systems and a controlled laboratory environment.

The project does **not** perform Internet-wide scanning, spoofed DNS traffic, amplification testing, or stress testing.

---

## 2. Problem Statement

DNS servers may operate as recursive resolvers, authoritative servers, or a combination of both.

An unnecessarily exposed recursive resolver can potentially be abused by external clients and may contribute to DNS-based amplification attacks. At the same time, simply receiving a DNS response is not sufficient evidence that recursion is available.

This project therefore uses multiple pieces of DNS evidence, including:

- Recursion Desired (`RD`) flag
- Recursion Available (`RA`) flag
- Authoritative Answer (`AA`) flag
- DNS response code (`RCODE`)
- Presence of answer records
- Response versus timeout behaviour
- Controlled authoritative-zone queries

The evidence is combined before assigning a behavioural classification.

---

## 3. Scope

The assessment covers one infrastructure class:

**DNS recursion exposure**

The tool is designed for:

- Up to 20 explicitly designated DNS servers
- A controlled test zone
- Low-rate DNS queries
- UDP DNS probing
- Reproducible classification
- Packet-level verification
- Ground-truth validation

The current laboratory uses four seeded test cases.

| Address | Role | Expected Classification |
|---|---|---|
| `10.10.0.2` | Recursive DNS resolver | `RECURSIVE` |
| `10.10.0.3` | Authoritative DNS server | `AUTHORITATIVE_ONLY` |
| `10.10.0.4` | DNS server configured to refuse queries | `REFUSED` |
| `10.10.0.5` | Intentionally unused address | `INCONCLUSIVE` |
| `10.10.0.20` | Assessment client | N/A |

---

## 4. Laboratory Architecture

The project uses Docker to create an isolated DNS laboratory.

```text
                         Docker DNS Lab
                       10.10.0.0/24
                              |
                +-------------+-------------+
                |                           |
         Assessment Client             DNS Targets
           10.10.0.20                      |
                                            |
                         +------------------+------------------+
                         |                  |                  |
                    10.10.0.2          10.10.0.3          10.10.0.4
                    Recursive           Authoritative       Refused
                       DNS                  DNS               DNS

                    10.10.0.5
                 intentionally unused
                 for INCONCLUSIVE case
```

The assessment client sends controlled DNS queries to each designated target and records the resulting DNS behaviour.

---

## 5. Controlled DNS Servers

### 5.1 Recursive Resolver — `10.10.0.2`

This server is configured to permit recursion for the controlled Docker laboratory.

The assessment sends a recursive query for:

```text
example.com A
```

Expected evidence:

```text
RCODE = NOERROR
RA    = 1
Answers > 0
```

A successful recursive answer provides evidence that the server offers recursive resolution to the designated lab client.

---

### 5.2 Authoritative-Only Server — `10.10.0.3`

This server hosts the controlled zone:

```text
lab.example
```

The seeded record used during testing is:

```text
www.lab.example A 10.10.0.100
```

Recursion is disabled.

The assessment therefore performs two different tests.

External recursive query:

```text
example.com A
```

Expected result:

```text
REFUSED
```

Controlled authoritative query:

```text
www.lab.example A
```

Expected result:

```text
NOERROR
AA = 1
A = 10.10.0.100
```

This combination demonstrates authoritative service without demonstrated external recursion.

---

### 5.3 Refused Server — `10.10.0.4`

This server is reachable but configured to refuse the tested DNS queries.

Expected result:

```text
Recursive query      -> REFUSED
Authoritative query  -> REFUSED
```

This is different from a timeout because `REFUSED` is an explicit DNS response from a reachable DNS service.

---

### 5.4 Inconclusive Target — `10.10.0.5`

No DNS server is intentionally assigned to this address.

The probe retries according to the configured retry policy and receives no usable DNS response.

The correct classification is:

```text
INCONCLUSIVE
```

A timeout, unreachable host, or absence of a DNS response must not be interpreted as evidence that recursion is disabled.

---

## 6. Probe Methodology

Two complementary probes are used.

### Recursive Probe

The recursive probe sends:

```text
example.com A
```

with the DNS `RD` flag enabled.

The probe records:

- Whether a response was received
- RCODE
- RD flag
- RA flag
- AA flag
- Number of answers
- Returned answer records
- Errors
- Number of attempts

### Authoritative Probe

The authoritative probe sends:

```text
www.lab.example A
```

with the `RD` flag cleared.

The probe records the same DNS response properties.

Using both probes reduces the risk of incorrectly classifying a server based on a single flag or response.

---

## 7. Classification Logic

The classifier combines evidence from both probes.

### RECURSIVE

A server is classified as `RECURSIVE` when the recursive test demonstrates successful recursive resolution.

Current decision criteria include:

```text
Response received
AND RCODE = NOERROR
AND RA = True
AND answer count > 0
```

### AUTHORITATIVE_ONLY

A server is classified as `AUTHORITATIVE_ONLY` when:

```text
Controlled-zone query:
    RCODE = NOERROR
    AA = True
    answer count > 0

AND

External recursive query:
    RCODE = REFUSED
```

### REFUSED

A server is classified as `REFUSED` when both test queries receive explicit DNS `REFUSED` responses.

### INCONCLUSIVE

A server is classified as `INCONCLUSIVE` when sufficient evidence does not exist to safely assign one of the other classifications.

Examples include:

- Timeouts
- Unreachable target
- `SERVFAIL`
- Ambiguous flag combinations
- `RA` without successful resolution
- Partial or inconsistent evidence

The classifier intentionally prefers `INCONCLUSIVE` over making an unsupported claim.

---

## 8. Retry and Rate Controls

The assessment includes explicit operational controls.

Example configuration:

```yaml
settings:
  timeout: 2
  retries: 2
  queries_per_second: 2
  protocol: "udp"
```

A retry count of `2` means that an unresponsive query can be attempted up to three times:

```text
1 initial attempt + 2 retries
```

Valid DNS responses such as:

- `NOERROR`
- `REFUSED`
- `NXDOMAIN`
- `SERVFAIL`

are treated as responses and are not repeatedly retried simply because the response is negative.

Rate limiting prevents rapid query generation.

---

## 9. Safety Controls

Safety is a core design requirement.

The project enforces or documents the following restrictions:

```text
Maximum targets          : 20
Rate limiting            : Enabled
Source spoofing          : Disabled
Stress testing           : Disabled
Internet-wide scanning   : Not permitted
Amplification testing    : Not performed
Controlled test zone     : Required
```

Example configuration:

```yaml
safety:
  max_targets: 20
  rate_limit_enabled: true
  allow_spoofing: false
  allow_stress_testing: false
```

The project is intended only for systems for which testing has been explicitly authorised.

---

## 10. Project Structure

```text
dns-resolver-assessment/
|-- app.py                 # Flask dashboard and API
|-- main.py                # Assessment command entry point
|-- classifier/            # Classification logic
|-- probes/                # Recursive and authoritative probes
|-- reporting/             # Report generation and logging code
|-- config/                # Target and runtime configuration
|-- lab/                   # BIND configurations and controlled zone
|-- templates/             # Dashboard HTML
|-- static/                # Dashboard CSS and JavaScript
|-- tests/                 # Classifier tests
|-- artifacts/
|   |-- results/           # Generated JSON and CSV reports
|   `-- logs/              # Assessment evidence logs
|-- captures/              # Packet captures and analysis
|-- Dockerfile
|-- docker-compose.yml
|-- requirements.txt
`-- README.md
```

Run the commands below from this directory. Generated evidence is separate
from Python source; existing reports, logs, and captures are preserved.

---
## 11. Requirements

The project was developed and tested using:

- Windows
- PowerShell
- Docker Desktop
- WSL2
- Python 3.12 container
- BIND 9
- dnspython
- PyYAML
- pytest
- tcpdump
- netshoot

Python dependencies are defined in:

```text
requirements.txt
```

---

## 12. Running the Laboratory

Start the Docker environment:

```powershell
docker compose up -d
```

Check the containers:

```powershell
docker compose ps
```

The expected DNS targets are:

```text
10.10.0.2
10.10.0.3
10.10.0.4
```

The address:

```text
10.10.0.5
```

must remain intentionally unused for the seeded `INCONCLUSIVE` test case.

---

## 13. Running the Assessment

Run:

```powershell
docker compose run --rm dns-probe python -u main.py
```

A successful ground-truth run produces:

```text
GROUND-TRUTH VALIDATION

Cases tested : 4
Correct      : 4
Incorrect    : 0
Accuracy     : 100.00%
```

The four expected classifications are:

```text
recursive-dns       -> RECURSIVE
authoritative-dns   -> AUTHORITATIVE_ONLY
refused-dns         -> REFUSED
inconclusive-dns    -> INCONCLUSIVE
```

---

## 14. Reports

The assessment generates machine-readable reports.

### JSON

```text
artifacts/results/assessment.json
```

The JSON report contains:

- Assessment metadata
- Timestamp
- Test zone
- Target count
- Safety and runtime settings
- Probe evidence
- Classification
- Expected classification
- Ground-truth validation

### CSV

```text
artifacts/results/assessment.csv
```

The CSV report provides a compact representation suitable for further analysis or importing into spreadsheet/data-analysis tools.

---

## 15. Evidence Logging

Probe activity and classification decisions are written to:

```text
artifacts/logs/dns_assessment.log
```

The evidence log records information such as:

- UTC timestamp
- Target name
- Target IP
- Probe type
- Query
- Whether the target responded
- RCODE
- RD
- RA
- AA
- Answer count
- Answers
- Number of attempts
- Error information
- Final classification
- Expected classification
- Validation result

This provides an operational audit trail for the assessment.

---

## 16. Automated Tests

Classifier behaviour is tested with `pytest`.

Run:

```powershell
docker compose run --rm dns-probe python -m pytest tests/test_classifier.py -v
```

The current test suite includes cases for:

- Recursive resolver
- Authoritative-only server
- Explicit refusal
- Timeout
- SERVFAIL
- RA flag without successful resolution
- Ambiguous recursive behaviour
- NOERROR/RA response without answers

Expected result:

```text
8 passed
```

These tests are particularly important for ensuring that ambiguous DNS behaviour is not incorrectly reported as confirmed recursion.

---

## 17. Packet Capture

Network-level evidence is stored in:

```text
captures/dns_assessment.pcap
```

The controlled assessment client uses:

```text
10.10.0.20
```

Packet capture includes DNS traffic and ICMP evidence associated with unreachable targets.

The human-readable analysis is stored in:

```text
captures/packet_analysis.txt
```

---

## 18. Packet-Level Results

### Recursive Resolver

Observed communication:

```text
10.10.0.20 -> 10.10.0.2
A? example.com

10.10.0.2 -> 10.10.0.20
A 104.20.23.154
A 172.66.147.243
```

Together with the probe's observation of `RA=True`, this demonstrates recursive resolution from the designated lab client.

### Authoritative-Only Server

Observed:

```text
example.com -> REFUSED
```

while:

```text
www.lab.example -> 10.10.0.100
```

was returned authoritatively.

The authoritative response contained the `AA` flag.

### Refused Server

Both test queries produced:

```text
REFUSED
```

This demonstrates an active DNS refusal rather than an unresponsive target.

### Inconclusive Target

Queries toward:

```text
10.10.0.5
```

received no usable DNS response.

The packet capture additionally contained:

```text
ICMP host 10.10.0.5 unreachable
```

The tool therefore correctly reports:

```text
INCONCLUSIVE
```

rather than assuming that recursion is disabled.

---

## 19. Ground-Truth Validation

The Docker laboratory provides known behaviour against which the classifier can be evaluated.

Final validated result:

| Target | Expected | Observed | Result |
|---|---|---|---|
| `10.10.0.2` | `RECURSIVE` | `RECURSIVE` | PASS |
| `10.10.0.3` | `AUTHORITATIVE_ONLY` | `AUTHORITATIVE_ONLY` | PASS |
| `10.10.0.4` | `REFUSED` | `REFUSED` | PASS |
| `10.10.0.5` | `INCONCLUSIVE` | `INCONCLUSIVE` | PASS |

```text
Accuracy = 4 / 4 = 100%
```

The 100% result refers specifically to the four seeded laboratory ground-truth cases and should not be interpreted as a general accuracy claim for arbitrary Internet DNS infrastructure.

---

## 20. RFC 5358 Relevance

RFC 5358, *Preventing Use of Recursive Nameservers in Reflector Attacks*, discusses the security risk associated with recursive DNS servers that provide recursion to unintended clients.

An exposed recursive resolver may be abused as part of DNS reflection/amplification activity, particularly when combined with spoofed source addresses.

This project addresses the measurement side of that problem by determining whether recursion can be demonstrated from a designated external lab client.

The project does **not** attempt to reproduce an amplification attack.

Instead, it safely evaluates observable resolver behaviour using low-rate DNS queries.

The methodology therefore focuses on:

- Identifying demonstrated recursive service
- Distinguishing recursion from authoritative service
- Recognising explicit refusal
- Avoiding assumptions when evidence is insufficient
- Restricting tests to authorised targets
- Avoiding spoofed traffic
- Avoiding amplification and stress testing

RFC 5358 provides the security motivation for restricting recursive resolver access to intended clients.

---

## 21. Reproducibility

The experiment is designed to be reproducible.

A researcher can:

1. Start the predefined Docker laboratory.
2. Use the same seeded DNS configurations.
3. Run the same Python probes.
4. Apply the same classification rules.
5. Compare classifications with the seeded ground truth.
6. Inspect JSON and CSV reports.
7. Inspect operational logs.
8. Review packet-level evidence.

The combination of configuration, code, ground truth, logs, reports, automated tests, and PCAP evidence makes the assessment repeatable and auditable.

---

## 22. Limitations

The current implementation intentionally has a narrow scope.

Important limitations include:

- UDP DNS is the primary assessment protocol.
- The laboratory contains a small number of controlled cases.
- The classifier uses deliberately conservative decision rules.
- A timeout does not establish that recursion is disabled.
- `SERVFAIL` does not establish that recursion is disabled.
- The presence of the `RA` flag alone does not prove successful recursive resolution.
- Network filtering may make an otherwise reachable DNS server appear inconclusive.
- Results describe behaviour observable from the assessment client's network position.
- The project does not attempt Internet-scale discovery.

These limitations are intentional and help prevent unsupported security conclusions.

---

## 23. Ethical and Operational Restrictions

This project must only be used against systems for which testing is authorised.

It must not be used for:

- Internet-wide resolver scanning
- Unauthorised infrastructure probing
- Source-address spoofing
- DNS reflection attacks
- DNS amplification attacks
- Denial-of-service testing
- High-volume DNS stress testing

The purpose of the project is defensive exposure assessment and reproducible cybersecurity research.

---

## 24. Evidence Produced

A completed assessment produces three complementary forms of evidence:

```text
Application evidence
    artifacts/results/assessment.json
    artifacts/results/assessment.csv

Operational evidence
    artifacts/logs/dns_assessment.log

Network evidence
    captures/dns_assessment.pcap
    captures/packet_analysis.txt
```

Together these allow the final classification to be traced back to the DNS responses that produced it.

---

## 25. Final Validated Result

The controlled laboratory successfully demonstrated all four required DNS behaviour classes:

```text
RECURSIVE
AUTHORITATIVE_ONLY
REFUSED
INCONCLUSIVE
```

Ground-truth validation:

```text
Cases tested : 4
Correct      : 4
Incorrect    : 0
Accuracy     : 100.00%
```

Automated classifier testing:

```text
8 passed
```

The resulting tool provides a safe and reproducible method for assessing DNS recursion exposure while retaining sufficient evidence to distinguish confirmed behaviour from inconclusive observations.

---

## Reference

RFC 5358 — Preventing Use of Recursive Nameservers in Reflector Attacks  
Internet Engineering Task Force (IETF)
