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
    if (!summary) summary = "Rejected CVE";

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
function renderItem(container, itemData, iconClass = 'fa-clock', showDetails = true) {
    const { id, summary, date, score } = itemData;
    const item = document.createElement('a');
    
    // For CVE items, add click handler for modal instead of external link
    if (id.startsWith('CVE-')) {
        item.href = '#';
        item.onclick = (e) => {
            e.preventDefault();
            showCVEDetails(itemData);
        };
    } else {
        item.href = `https://cve.circl.lu/cve/${id}`;
        item.target = "_blank";
    }
    
    item.className = "list-group-item list-group-item-action";

    let badgeClass = 'badge-cvss-low';
    if (score) {
        if (score >= 9.0) badgeClass = 'badge-cvss-critical';
        else if (score >= 7.0) badgeClass = 'badge-cvss-high';
        else if (score >= 4.0) badgeClass = 'badge-cvss-medium';
    }

    const timeDisplay = date ? timeAgo(date) : 'Date Unknown';

    const scoreBadge = showDetails ? `<span class="badge ${badgeClass} text-mono">${score || 'N/A'}</span>` : '';
    const dateElement = showDetails ? `<small class="text-muted"><i class="far ${iconClass} me-1"></i>${timeDisplay}</small>` : '';

    item.innerHTML = `
        <div class="d-flex w-100 justify-content-between mb-1">
            <h6 class="mb-0 text-info text-mono">${id}</h6>
            ${scoreBadge}
        </div>
        <p class="mb-1 small text-secondary">${truncate(summary, 120)}</p>
        ${dateElement}
    `;
    container.appendChild(item);
}

// Function to show CVE details in modal
function showCVEDetails(cveData) {
    const { id, summary, date, score } = cveData;
    
    // Get severity level and color
    let severityLevel = 'Low';
    let severityColor = 'success';
    if (score >= 9.0) {
        severityLevel = 'Critical';
        severityColor = 'danger';
    } else if (score >= 7.0) {
        severityLevel = 'High';
        severityColor = 'warning';
    } else if (score >= 4.0) {
        severityLevel = 'Medium';
        severityColor = 'info';
    }

    const timeDisplay = date ? timeAgo(date) : 'Date Unknown';
    const publishDate = date ? new Date(date).toLocaleDateString() : 'Unknown';

    // Create modal HTML
    const modalHTML = `
        <div class="modal fade" id="cveModal" tabindex="-1" aria-hidden="true">
            <div class="modal-dialog modal-lg">
                <div class="modal-content bg-dark border-secondary">
                    <div class="modal-header bg-black border-secondary">
                        <h5 class="modal-title text-info">
                            <i class="fa-solid fa-bug me-2"></i>${id}
                        </h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <h6 class="text-muted mb-2">CVSS Score</h6>
                                <span class="badge bg-${severityColor} fs-6">${score || 'N/A'}</span>
                                <span class="text-${severityColor} ms-2 fw-bold">${severityLevel}</span>
                            </div>
                            <div class="col-md-6">
                                <h6 class="text-muted mb-2">Published Date</h6>
                                <p class="text-light mb-0">${publishDate}</p>
                                <small class="text-muted">${timeDisplay}</small>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <h6 class="text-muted mb-2">Description</h6>
                            <p class="text-light">${summary}</p>
                        </div>
                        
                        <div class="mb-3">
                            <h6 class="text-muted mb-2">CVE ID</h6>
                            <code class="text-info">${id}</code>
                        </div>
                    </div>
                    <div class="modal-footer bg-black border-secondary">
                        <a href="https://cve.circl.lu/cve/${id}" target="_blank" class="btn btn-info">
                            <i class="fa-solid fa-external-link-alt me-1"></i>View Full Details
                        </a>
                        <a href="https://nvd.nist.gov/vuln/detail/${id}" target="_blank" class="btn btn-secondary">
                            <i class="fa-solid fa-database me-1"></i>NVD Database
                        </a>
                        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
    `;

    // Remove existing modal if present
    const existingModal = document.getElementById('cveModal');
    if (existingModal) {
        existingModal.remove();
    }

    // Add modal to page
    document.body.insertAdjacentHTML('beforeend', modalHTML);

    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('cveModal'));
    modal.show();
}

function renderCVEs(cves, malwareData = []) {
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

    // Only get CVE items (no MAL filtering needed since CVE API doesn't have MAL data)
    const cveItems = validItems.sort((a, b) => (b.score || 0) - (a.score || 0));

    // Calculate CVE statistics
    const stats = calculateCVEStats(cveItems);
    updateCVEStats(stats);
    updateCVEChart(stats);

    // Render CVE items
    cveItems.slice(0, 30).forEach(item => renderItem(cveContainer, item, 'fa-bug', true));

    // Render MAL items (from malware data)
    if (malwareData && malwareData.length > 0) {
        malwareData.slice(0, 30).forEach(item => {
            const malItem = {
                id: `MAL-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                summary: item.title,
                date: item.pubDate,
                score: null
            };
            renderItem(malContainer, malItem, 'fa-spider', false);
        });
    }

    // Empty states
    if (cveItems.length === 0) cveContainer.innerHTML = '<div class="p-3 text-center text-muted">No recent CVEs found.</div>';
    if (!malwareData || malwareData.length === 0) malContainer.innerHTML = '<div class="p-3 text-center text-muted">No recent malware data found.</div>';
}

function calculateCVEStats(cveItems) {
    const stats = {
        total: cveItems.length,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0
    };

    cveItems.forEach(cve => {
        const score = cve.score;
        if (score === null || score === undefined) {
            stats.unknown++;
        } else if (score >= 9.0) {
            stats.critical++;
        } else if (score >= 7.0) {
            stats.high++;
        } else if (score >= 4.0) {
            stats.medium++;
        } else {
            stats.low++;
        }
    });

    return stats;
}

function updateCVEStats(stats) {
    document.getElementById('total-cves').textContent = stats.total;
    document.getElementById('critical-cves').textContent = stats.critical;
    document.getElementById('high-cves').textContent = stats.high;
    document.getElementById('medium-cves').textContent = stats.medium;
    document.getElementById('low-cves').textContent = stats.low;
}

let cveChart = null;

function updateCVEChart(stats) {
    const ctx = document.getElementById('cve-chart').getContext('2d');
    
    // Destroy existing chart if it exists
    if (cveChart) {
        cveChart.destroy();
    }

    const data = [stats.critical, stats.high, stats.medium, stats.low, stats.unknown];
    const labels = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
    const colors = ['#dc3545', '#ffc107', '#17a2b8', '#28a745', '#6c757d'];

    // Filter out zero values
    const filteredData = [];
    const filteredLabels = [];
    const filteredColors = [];
    
    data.forEach((value, index) => {
        if (value > 0) {
            filteredData.push(value);
            filteredLabels.push(labels[index]);
            filteredColors.push(colors[index]);
        }
    });

    cveChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: filteredLabels,
            datasets: [{
                data: filteredData,
                backgroundColor: filteredColors,
                borderWidth: 1,
                borderColor: '#343a40'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: '#212529',
                    titleColor: '#ffffff',
                    bodyColor: '#ffffff',
                    borderColor: '#6c757d',
                    borderWidth: 1
                }
            },
            elements: {
                arc: {
                    borderWidth: 2
                }
            }
        }
    });
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

    renderCVEs(cves, malware);
    renderNews(news);
    renderHN(hn);
    renderMalware(malware);

    updateTime();

}

// Start
document.addEventListener('DOMContentLoaded', init);
