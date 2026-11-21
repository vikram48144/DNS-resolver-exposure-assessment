let assessmentData = null;

function renderAclResult(data) {
    document.getElementById("acl-policy").textContent =
        `Trusted: ${data.trusted_subnet}; untrusted: ${data.untrusted_subnet}. ` +
        `Query: ${data.query.domain} ${data.query.type}; requested RD=${Number(data.query.rd)}.`;
    const container = document.getElementById("acl-tests");
    container.innerHTML = "";
    for (const [role, test] of Object.entries(data.tests)) {
        const probe = test.probe;
        const card = document.createElement("div");
        card.className = "evidence-card";
        const heading = document.createElement("h3");
        heading.textContent = `${role === "authorised" ? "Authorised" : "Unauthorised"} client`;
        const evidence = document.createElement("pre");
        evidence.className = "acl-evidence";
        evidence.textContent = [
            `Client: ${test.client}`, `Recursive DNS server: ${test.server}:${test.port}`,
            `Response received: ${probe.responded}`,
            `Response RD: ${probe.responded ? probe.rd : "unknown"}`,
            `Response RA: ${probe.responded ? probe.ra : "unknown"}`,
            `RCODE: ${probe.rcode ?? "unknown"}`,
            `Returned answers: ${(probe.answers || []).join(", ") || "none"}`,
            `Access decision: ${test.access_decision}`, `Expected result: ${test.expected}`,
            `Observed result: ${test.observed}`, `Error: ${probe.error || "none"}`
        ].join("\n");
        card.append(heading, evidence);
        container.append(card);
    }
    document.getElementById("acl-overall").textContent = `Overall verification status: ${data.status}`;
    document.getElementById("acl-limitations").textContent = data.limitations.join(" ");
}

async function verifyRecursionAcl() {
    const button = document.getElementById("acl-button");
    const status = document.getElementById("acl-status");
    button.disabled = true;
    document.getElementById("acl-tests").innerHTML = "";
    document.getElementById("acl-overall").textContent = "";
    status.textContent = "Testing both Docker client origins...";
    try {
        const response = await fetch("/api/verify-recursion-acl", {method: "POST"});
        const payload = await response.json();
        if (!response.ok || !payload.success) throw new Error(payload.message || "Verification failed");
        renderAclResult(payload.data);
        status.textContent = `Completed: ${payload.data.timestamp_utc}`;
    } catch (error) {
        status.textContent = `Verification unavailable: ${error.message}`;
    } finally {
        button.disabled = false;
    }
}

document.addEventListener("DOMContentLoaded", () => {
    loadResults();
});


async function loadResults() {
    try {
        const response = await fetch("/api/results");
        const payload = await response.json();

        if (!response.ok || !payload.success) {
            showNoResults();
            return;
        }

        assessmentData = payload.data;
        renderAssessment(assessmentData);

    } catch (error) {
        console.error(error);
        showNoResults();
    }
}


function showNoResults() {
    document.getElementById("results-body").innerHTML = `
        <tr>
            <td colspan="7" class="empty-state">
                No assessment results available. Run an assessment.
            </td>
        </tr>
    `;
}


function getResultsArray(data) {
    /*
     * Allows the UI to tolerate a few sensible JSON layouts.
     * Our report generator should normally use "results".
     */
    if (Array.isArray(data.results)) {
        return data.results;
    }

    if (Array.isArray(data.targets)) {
        return data.targets;
    }

    if (Array.isArray(data.assessments)) {
        return data.assessments;
    }

    return [];
}


function renderAssessment(data) {
    const results = getResultsArray(data);
    const assessment = data.assessment || {};

    document.getElementById("target-count").textContent =
        assessment.target_count ?? results.length;

    const correct = results.filter(result =>
        String(result.validation).toUpperCase() === "PASS"
    ).length;

    document.getElementById("correct-count").textContent = correct;

    const accuracy = results.length
        ? ((correct / results.length) * 100).toFixed(2) + "%"
        : "--";

    document.getElementById("accuracy").textContent = accuracy;

    document.getElementById("rate-limit").textContent =
        assessment.queries_per_second ?? "--";

    document.getElementById("last-updated").textContent =
        assessment.timestamp_utc
            ? `Generated: ${assessment.timestamp_utc}`
            : "Latest assessment";

    renderTable(results);
}

function renderTable(results) {
    const body = document.getElementById("results-body");

    if (!results.length) {
        showNoResults();
        return;
    }

    body.innerHTML = "";

    results.forEach((result, index) => {

        const recursive = result.recursive_probe || {};
        const authoritative = result.authoritative_probe || {};

        const row = document.createElement("tr");

        row.innerHTML = `
            <td>${escapeHtml(result.name ?? "Unknown")}</td>

            <td>
                <code>${escapeHtml(result.ip ?? result.server ?? "--")}</code>
            </td>

            <td>
                ${escapeHtml(recursive.rcode ?? recursive.error ?? "--")}
            </td>

            <td>
                ${escapeHtml(
                    authoritative.rcode ??
                    authoritative.error ??
                    "--"
                )}
            </td>

            <td>
                ${classificationBadge(result.classification)}
            </td>

            <td>
                ${classificationBadge(result.expected)}
            </td>

            <td class="${
                String(result.validation).toUpperCase() === "PASS"
                    ? "pass"
                    : "fail"
            }">
                ${escapeHtml(result.validation ?? "--")}
            </td>
        `;

        row.addEventListener("click", () => {
            showEvidence(results[index]);
        });

        body.appendChild(row);
    });
}


function classificationBadge(value) {
    const classification = String(value ?? "UNKNOWN");

    let className = "badge-inconclusive";

    if (classification === "RECURSIVE") {
        className = "badge-recursive";
    }

    if (classification === "AUTHORITATIVE_ONLY") {
        className = "badge-authoritative";
    }

    if (classification === "REFUSED") {
        className = "badge-refused";
    }

    if (classification === "INCONCLUSIVE") {
        className = "badge-inconclusive";
    }

    return `
        <span class="badge ${className}">
            ${escapeHtml(classification)}
        </span>
    `;
}


function showEvidence(result) {
    const recursive = result.recursive_probe || {};
    const authoritative = result.authoritative_probe || {};

    document.getElementById("evidence-placeholder")
        .classList.add("hidden");

    document.getElementById("evidence-content")
        .classList.remove("hidden");

    document.getElementById("selected-target").textContent =
        `${result.name ?? "Target"} (${result.ip ?? "--"})`;

    document.getElementById("recursive-rcode").textContent =
        recursive.rcode ?? recursive.error ?? "--";

    document.getElementById("recursive-rd").textContent =
        formatBoolean(recursive.rd);

    document.getElementById("recursive-ra").textContent =
        formatBoolean(recursive.ra);

    document.getElementById("recursive-answers").textContent =
        recursive.answer_count ?? 0;

    document.getElementById("recursive-attempts").textContent =
        recursive.attempts ?? "--";

    document.getElementById("auth-rcode").textContent =
        authoritative.rcode ?? authoritative.error ?? "--";

    document.getElementById("auth-aa").textContent =
        formatBoolean(authoritative.aa);

    document.getElementById("auth-answers").textContent =
        authoritative.answer_count ?? 0;

    document.getElementById("auth-attempts").textContent =
        authoritative.attempts ?? "--";

    document.getElementById("recursive-answer-list").textContent =
        formatAnswers(recursive.answers);

    document.getElementById("recursive-error").textContent =
        recursive.error ?? "None";

    document.getElementById("auth-answer-list").textContent =
        formatAnswers(authoritative.answers);

    document.getElementById("auth-error").textContent =
        authoritative.error ?? "None";

    document.getElementById("evidence-classification").innerHTML =
        classificationBadge(result.classification);

    document.getElementById("evidence-interpretation").textContent =
        result.interpretation ??
        "Classification derived from the observed DNS probe evidence.";
}


async function runAssessment() {
    const button = document.getElementById("run-button");
    const panel = document.getElementById("progress-panel");
    const bar = document.getElementById("progress-bar");
    const status = document.getElementById("progress-status");
    const message = document.getElementById("progress-message");

    button.disabled = true;
    button.textContent = "Running...";

    panel.classList.remove("hidden");

    bar.style.width = "15%";
    status.textContent = "Running";
    message.textContent =
        "Sending rate-controlled DNS probes to authorised lab targets...";

    const timer = animateProgress(bar);

    try {
        const response = await fetch("/api/run", {
            method: "POST"
        });

        const payload = await response.json();

        clearInterval(timer);

        if (!response.ok || !payload.success) {
            throw new Error(
                payload.message || "Assessment failed."
            );
        }

        bar.style.width = "100%";
        status.textContent = "Complete";
        message.textContent =
            "Assessment completed and exposure report generated.";

        assessmentData = payload.data;
        renderAssessment(assessmentData);

    } catch (error) {
        clearInterval(timer);

        bar.style.width = "100%";
        status.textContent = "Failed";
        message.textContent = error.message;

        console.error(error);

    } finally {
        button.disabled = false;
        button.textContent = "Run Assessment";
    }
}


function animateProgress(bar) {
    let progress = 15;

    return setInterval(() => {
        if (progress < 85) {
            progress += 5;
            bar.style.width = `${progress}%`;
        }
    }, 450);
}


function formatBoolean(value) {
    if (value === true) {
        return "TRUE";
    }

    if (value === false) {
        return "FALSE";
    }

    return "--";
}

function formatAnswers(answers) {
    if (!Array.isArray(answers) || answers.length === 0) {
        return "No answers";
    }

    return answers.join("\n");
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function renderLabResult(payload) {
    document.getElementById("lab-selected-target").textContent = `${payload.name} (${payload.ip})`;
    document.getElementById("lab-classification").innerHTML = classificationBadge(payload.classification);
    for (const kind of ["recursive", "authoritative"]) {
        const probe = payload[`${kind}_probe`];
        for (const flag of ["rd", "ra", "aa"]) {
            document.getElementById(`lab-${kind}-${flag}`).textContent =
                probe.responded ? formatBoolean(probe[flag]) : "-- (no response)";
        }
        const values = {
            rcode: probe.rcode ?? "-- (no response)",
            "answer-count": probe.answer_count ?? 0,
            attempts: probe.attempts ?? 1,
            answers: formatAnswers(probe.answers),
            error: probe.error || "None"
        };
        for (const [key, value] of Object.entries(values)) {
            document.getElementById(`lab-${kind}-${key}`).textContent = value;
        }
    }
    const interpretations = {
        RECURSIVE: "The recursive probe returned NOERROR, RA=TRUE and answer records.",
        AUTHORITATIVE_ONLY: "The recursive query was refused. The controlled-zone query returned NOERROR, AA=TRUE and answer records. The seeded A record is www.lab.example = 10.10.0.100.",
        REFUSED: "Both queries received an explicit REFUSED response from the DNS service.",
        INCONCLUSIVE: "Insufficient evidence to establish a DNS behaviour. A timeout does not prove recursion is disabled."
    };
    document.getElementById("lab-interpretation").textContent = interpretations[payload.classification] || "";
    document.getElementById("lab-result").classList.remove("hidden");
}

async function probeLabServer() {
    const button = document.getElementById("lab-probe-button");
    const select = document.getElementById("lab-target");
    const status = document.getElementById("lab-status");
    button.disabled = true;
    select.disabled = true;
    button.textContent = "Probing...";
    document.getElementById("lab-result").classList.add("hidden");
    status.classList.remove("hidden");
    status.textContent = "Running both rate-controlled probes. Unresponsive targets require timeout retries.";
    try {
        const response = await fetch("/api/lab-probe", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target: select.value })
        });
        const payload = await response.json();
        if (!response.ok || !payload.success) throw new Error(payload.message || "Lab probe failed.");
        renderLabResult(payload);
        status.textContent = "Lab DNS behaviour test complete. Results reflect the responses received.";
    } catch (error) {
        status.textContent = `Lab probe failed: ${error.message}`;
    } finally {
        button.disabled = false;
        select.disabled = false;
        button.textContent = "Probe DNS Server";
    }
}

function setDomain(domain) {
    document.getElementById("domain-input").value = domain;
}


async function probeDomain() {
    const input = document.getElementById("domain-input");
    const button = document.getElementById("domain-probe-button");
    const status = document.getElementById("domain-status");
    const resultPanel = document.getElementById("domain-result");

    const domain = input.value.trim();

    if (!domain) {
        status.textContent = "Please enter a domain name.";
        status.classList.remove("hidden");
        resultPanel.classList.add("hidden");
        return;
    }

    button.disabled = true;
    button.textContent = "Probing...";

    status.textContent =
        `Resolving ${domain} through authorised resolver 10.10.0.2...`;

    status.classList.remove("hidden");
    resultPanel.classList.add("hidden");

    try {
        const response = await fetch("/api/domain-probe", {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                domain: domain
            })
        });

        const payload = await response.json();

        if (!response.ok || !payload.success) {
            throw new Error(
                payload.message || "Domain probe failed."
            );
        }

        const result = payload.result || {};

        document.getElementById("domain-result-name").textContent =
            payload.domain ?? domain;

        document.getElementById("domain-result-resolver").textContent =
            payload.resolver ?? "--";

        document.getElementById("domain-result-rcode").textContent =
            result.rcode ?? result.error ?? "--";

        document.getElementById("domain-result-ra").textContent =
            !result.responded
                ? "--"
                : result.ra === true
                ? "TRUE"
                : result.ra === false
                    ? "FALSE"
                    : "--";

        document.getElementById("domain-result-count").textContent =
            result.answer_count ?? 0;

        document.getElementById(
            "domain-result-classification"
        ).innerHTML = classificationBadge(
            payload.classification
        );

        const answers =
            Array.isArray(result.answers) &&
            result.answers.length > 0
                ? result.answers.join("\n")
                : "No answers returned.";

        document.getElementById("domain-result-answers").textContent =
            answers;

        if (!result.responded) {
            status.textContent =
                `No DNS response from ${payload.resolver} for ${payload.domain} ` +
                `(${result.error || "unknown network error"}). ` +
                "Ensure the Docker DNS lab is running and open the dashboard provided by docker compose.";
        } else if (result.rcode !== "NOERROR") {
            status.textContent =
                `Resolver responded with ${result.rcode} for ${payload.domain}.`;
        } else {
            status.textContent =
                `DNS response received for ${payload.domain}: ${result.answer_count ?? 0} answers.`;
        }

        resultPanel.classList.remove("hidden");

    } catch (error) {
        status.textContent = `Probe failed: ${error.message}`;
        resultPanel.classList.add("hidden");

        console.error(error);

    } finally {
        button.disabled = false;
        button.textContent = "Probe Domain";
    }
}


/*
 * Allow Enter to submit the domain probe.
 */
document.addEventListener("DOMContentLoaded", () => {
    const domainInput = document.getElementById("domain-input");

    if (domainInput) {
        domainInput.addEventListener("keydown", event => {
            if (event.key === "Enter") {
                probeDomain();
            }
        });
    }
});
