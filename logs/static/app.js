const $ = (id) => document.getElementById(id);

function safe(value) {
    const element = document.createElement("span");
    element.textContent = value == null ? "" : String(value);
    return element.innerHTML;
}

function formatDate(value) {
    if (!value) return "Unknown time";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function riskClass(risk) {
    const value = String(risk || "unknown").toLowerCase();
    return ["high", "medium", "low"].includes(value) ? value : "unknown";
}

function updateRiskBar(counts) {
    const high = counts.high || 0;
    const medium = counts.medium || 0;
    const low = counts.low || 0;
    const total = high + medium + low;

    $("bar-high").style.width = total ? `${high / total * 100}%` : "0%";
    $("bar-medium").style.width = total ? `${medium / total * 100}%` : "0%";
    $("bar-low").style.width = total ? `${low / total * 100}%` : "0%";
}

function renderTimeline(events) {
    $("event-count").textContent = `${events.length} EVENTS`;

    if (!events.length) {
        $("timeline").innerHTML = `
            <div class="empty-state">
                <span class="empty-icon">◎</span>
                <h4>No events recorded</h4>
                <p>DNS observations will appear here when received by the collector.</p>
            </div>`;
        return;
    }

    $("timeline").innerHTML = [...events].reverse().map(item => {
        const observation = item.observation || {};
        const assessment = item.assessment || {};
        const risk = riskClass(assessment.risk);
        const changes = Array.isArray(observation.changes)
            ? observation.changes.join(", ")
            : "No change details";

        return `
            <div class="event">
                <div class="event-marker"></div>
                <div class="event-main">
                    <strong>${safe(observation.domain || "Unknown domain")}</strong>
                    <p>${safe(changes)}</p>
                    <p>Event #${safe(item.index)}</p>
                </div>
                <div class="event-meta">
                    <span class="risk-tag risk-${risk}">${safe(risk.toUpperCase())}</span>
                    <div>${safe(formatDate(observation.observed_at))}</div>
                </div>
            </div>`;
    }).join("");
}

function renderLatest(item) {
    if (!item) {
        $("latest-event").innerHTML =
            '<p class="muted">Waiting for the first DNS observation.</p>';
        return;
    }

    const observation = item.observation || {};
    const assessment = item.assessment || {};
    const risk = riskClass(assessment.risk);

    const fields = [
        ["DOMAIN", observation.domain],
        ["OBSERVED AT", formatDate(observation.observed_at)],
        ["CHANGES", (observation.changes || []).join(", ")],
        ["RISK", risk.toUpperCase()],
        ["RULES VERSION", assessment.rules_version || "Unknown"],
        ["LEAF HASH", item.leaf_hash || "Unavailable"]
    ];

    $("latest-event").innerHTML = `
        <div class="detail-grid">
            ${fields.map(([label, value]) => `
                <div class="detail-item">
                    <span>${safe(label)}</span>
                    <strong>${safe(value || "—")}</strong>
                </div>
            `).join("")}
        </div>
        <div class="detail-item" style="margin-top:12px">
            <span>ASSESSMENT REASONS</span>
            <strong>${safe((assessment.reasons || []).join("; ") || "No reasons supplied")}</strong>
        </div>`;
}

function renderTreeHead(head) {
    if (!head) {
        $("signature-status").textContent = "No tree head";
        $("root-hash").textContent = "No tree head available";
        return;
    }

    $("signature-status").textContent =
        head.signature_valid ? "VALID" : "INVALID";
    $("signature-status").style.color =
        head.signature_valid ? "var(--green)" : "var(--red)";

    $("root-hash").textContent = head.root_hash || "Unavailable";
}

async function loadDashboard() {
    const button = $("refresh-button");
    button.disabled = true;

    try {
        const response = await fetch("/api/dashboard", {cache: "no-store"});
        if (!response.ok) throw new Error(`Dashboard API returned ${response.status}`);

        const data = await response.json();
        const stats = data.stats || {};
        const risks = stats.risk_counts || {};

        $("total-events").textContent = stats.total_events ?? 0;
        $("high-risk").textContent = risks.high ?? 0;
        $("medium-risk").textContent = risks.medium ?? 0;
        $("low-risk").textContent = risks.low ?? 0;
        $("tree-size").textContent = stats.tree_size ?? 0;
        $("tree-head-count").textContent = stats.tree_head_count ?? 0;
        $("assessment-count").textContent =
            `${stats.total_assessments ?? 0} assessments recorded`;

        updateRiskBar(risks);
        renderTimeline(data.events || []);
        renderLatest(data.latest_event);
        renderTreeHead(data.latest_tree_head);

        $("connection").textContent = "CONNECTED";
        $("connection").style.color = "var(--green)";
        $("last-updated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
    } catch (error) {
        $("connection").textContent = "API ERROR";
        $("connection").style.color = "var(--red)";
        console.error("Dashboard error:", error);
    } finally {
        button.disabled = false;
    }
}

loadDashboard();
setInterval(loadDashboard, 15000);
