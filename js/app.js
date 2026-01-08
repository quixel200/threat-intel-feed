import { API } from './api.js';

const api = new API();

// Formatting Utilities
function timeAgo(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);

    let interval = seconds / 31536000;
    if (interval > 1) return Math.floor(interval) + " years ago";
    interval = seconds / 2592000;
    if (interval > 1) return Math.floor(interval) + " months ago";
    interval = seconds / 86400;
    if (interval > 1) return Math.floor(interval) + " days ago";
    interval = seconds / 3600;
    if (interval > 1) return Math.floor(interval) + " hours ago";
    interval = seconds / 60;
    if (interval > 1) return Math.floor(interval) + " minutes ago";
    return Math.floor(seconds) + " seconds ago";
}

function truncate(str, n) {
    return (str.length > n) ? str.substr(0, n - 1) + '&hellip;' : str;
}

// Parsing Utilities
function getCvssScore(cve) {
    const checkMetrics = (metrics) => {
        if (!metrics) return null;
        for (const m of metrics) {
            if (m.cvssV3_1) return m.cvssV3_1.baseScore;
            if (m.cvssV3_0) return m.cvssV3_0.baseScore;
            if (m.cvssV4_0) return m.cvssV4_0.baseScore;
            if (m.cvssV2_0) return m.cvssV2_0.baseScore;
            if (m.cvssV3_1?.baseScore) return m.cvssV3_1.baseScore; // Handle if baseScore is direct property
        }
        return null;
    };

    // 0. Legacy flat format
    if (typeof cve.cvss === 'number') return cve.cvss;

    // 1. Check CNA (Primary Source)
    let score = checkMetrics(cve.containers?.cna?.metrics);
    if (score) return score;

    // 2. Check ADP (Additional Data Providers)
    if (cve.containers?.adp) {
        for (const adp of cve.containers.adp) {
            score = checkMetrics(adp.metrics);
            if (score) return score;
        }
    }

    return null;
}

function parseCVEData(cve) {
    // ID
    let id = cve.id || cve.cveMetadata?.cveId || 'Unknown ID';

    // Description
    let summary = cve.summary; // Legacy

    // Try CNA Description
    if (!summary && cve.containers?.cna?.descriptions) {
        const descObj = cve.containers.cna.descriptions.find(d => d.lang === 'en' || d.lang === 'en-US') || cve.containers.cna.descriptions[0];
        if (descObj) summary = descObj.value;
    }
    // Try CNA Title as fallback
    if (!summary && cve.containers?.cna?.title) {
        summary = cve.containers.cna.title;
    }
    // Try ADP Description
    if (!summary && cve.containers?.adp) {
        for (const adp of cve.containers.adp) {
            if (adp.descriptions) {
                const descObj = adp.descriptions.find(d => d.lang === 'en') || adp.descriptions[0];
                if (descObj) { summary = descObj.value; break; }
            }
        }
    }
    if (!summary) summary = "No description available.";

    // Date
    let date = cve.Modified || cve.Published;
    if (cve.cveMetadata?.dateUpdated) date = cve.cveMetadata.dateUpdated;
    else if (cve.cveMetadata?.datePublished) date = cve.cveMetadata.datePublished;

    // Safety check for date
    if (!date || isNaN(new Date(date).getTime())) {
        date = null;
    }

    // Score
    let score = getCvssScore(cve);

    return { id, summary, date, score };
}

// Rendering Functions
function renderItem(container, itemData, iconClass = 'fa-clock') {
    const { id, summary, date, score } = itemData;
    const item = document.createElement('a');
    item.href = `https://cve.circl.lu/cve/${id}`;
    item.target = "_blank";
    item.className = "list-group-item list-group-item-action";

    let badgeClass = 'badge-cvss-low';
    if (score) {
        if (score >= 9.0) badgeClass = 'badge-cvss-critical';
        else if (score >= 7.0) badgeClass = 'badge-cvss-high';
        else if (score >= 4.0) badgeClass = 'badge-cvss-medium';
    }

    const timeDisplay = date ? timeAgo(date) : 'Date Unknown';

    item.innerHTML = `
        <div class="d-flex w-100 justify-content-between mb-1">
            <h6 class="mb-0 text-info text-mono">${id}</h6>
            <span class="badge ${badgeClass} text-mono">${score || 'N/A'}</span>
        </div>
        <p class="mb-1 small text-secondary">${truncate(summary, 120)}</p>
        <small class="text-muted"><i class="far ${iconClass} me-1"></i>${timeDisplay}</small>
    `;
    container.appendChild(item);
}

function renderCVEs(cves) {
    const cveContainer = document.getElementById('cve-list');
    const malContainer = document.getElementById('mal-list');

    cveContainer.innerHTML = '';
    malContainer.innerHTML = '';

    // Filter out REJECTED CVEs and parse
    const validItems = cves
        .filter(cve => {
            if (cve.cveMetadata?.state === 'REJECTED') return false;
            if (cve.state === 'REJECTED') return false;
            const summary = cve.summary || cve.containers?.cna?.descriptions?.[0]?.value || "";
            if (summary.startsWith("** REJECT **")) return false;
            return true;
        })
        .map(rawCve => parseCVEData(rawCve));

    // Split into CVE and MAL
    const cveItems = validItems.filter(item => !item.id.startsWith('MAL-'));
    const malItems = validItems.filter(item => item.id.startsWith('MAL-'));

    cveItems.slice(0, 30).forEach(item => renderItem(cveContainer, item, 'fa-bug'));
    malItems.slice(0, 30).forEach(item => renderItem(malContainer, item, 'fa-spider'));

    // Empty states
    if (cveItems.length === 0) cveContainer.innerHTML = '<div class="p-3 text-center text-muted">No recent CVEs found.</div>';
    if (malItems.length === 0) malContainer.innerHTML = '<div class="p-3 text-center text-muted">No recent MAL entries found.</div>';
}

function renderNews(newsItems) {
    const container = document.getElementById('news-list');
    container.innerHTML = '';

    newsItems.slice(0, 20).forEach(item => {
        const div = document.createElement('a');
        div.href = item.link;
        div.target = "_blank";
        div.className = "list-group-item list-group-item-action";
        div.innerHTML = `
            <div class="d-flex w-100 justify-content-between">
                <h6 class="mb-1">${truncate(item.title, 60)}</h6>
                <small class="text-muted text-nowrap">${timeAgo(item.pubDate)}</small>
            </div>
            <p class="mb-1 small text-muted">${item.author || 'Unknown'}</p>
        `;
        container.appendChild(div);
    });
}

function renderHN(hits) {
    const container = document.getElementById('hn-list');
    container.innerHTML = '';

    hits.forEach(hit => {
        if (!hit.title) return;
        const div = document.createElement('a');
        div.href = `https://news.ycombinator.com/item?id=${hit.objectID}`;
        div.target = "_blank";
        div.className = "list-group-item list-group-item-action";
        div.innerHTML = `
            <div class="d-flex w-100 justify-content-between">
                <h6 class="mb-1 small fw-bold">${truncate(hit.title, 50)}</h6>
                <small class="text-success text-mono">${hit.points || 0} pts</small>
            </div>
            <div class="d-flex justify-content-between align-items-center">
                <small class="text-muted source-tag">by ${hit.author}</small>
                <small class="text-secondary" style="font-size: 0.7em">${timeAgo(hit.created_at)}</small>
            </div>
        `;
        container.appendChild(div);
    });
}

function renderMalware(items) {
    const container = document.getElementById('malware-list');
    container.innerHTML = '';

    items.slice(0, 15).forEach(item => {
        const div = document.createElement('a');
        div.href = item.link;
        div.target = "_blank";
        div.className = "list-group-item list-group-item-action";

        // Extrating title info 
        div.innerHTML = `
            <div class="d-flex w-100 justify-content-between">
                <h6 class="mb-1 small text-danger text-mono">${truncate(item.title, 50)}</h6>
            </div>
            <small class="text-muted"><i class="fa-solid fa-file-invoice me-1"></i>${timeAgo(item.pubDate)}</small>
        `;
        container.appendChild(div);
    });
}

// Main Init
async function init() {
    console.log("Initializing Dashboard...");

    const updateTime = () => {
        document.getElementById('last-updated').innerText = `Last Updated: ${new Date().toLocaleTimeString()}`;
    };

    // Parallel Fetching
    const [cves, news, hn, malware] = await Promise.all([
        api.getCVEs(),
        api.getThreatNews(),
        api.getHackerNewsSecurity(),
        api.getMalwareBazaar()
    ]);

    renderCVEs(cves);
    renderNews(news);
    renderHN(hn);
    renderMalware(malware);

    updateTime();

    // Auto-Refresh every 5 minutes
    setInterval(async () => {
        const cves = await api.getCVEs();
        renderCVEs(cves);
        updateTime();
    }, 300000); // 5 mins
}

// Start
document.addEventListener('DOMContentLoaded', init);
