// Incident Forensic Telemetry & Correlation Script

const FORENSIC_DATA = {
    notice: [
        {
            ts: "09:03:49.461",
            uid: "CjbXsRqWg8nivYnui",
            note: "SSRF::Metadata_Access",
            msg: "Possible SSRF: AWS EC2 metadata service accessed by 169.254.169.254",
            src: "169.254.169.254:46748",
            dst: "169.254.169.254:80"
        },
        {
            ts: "09:03:49.480",
            uid: "CCHznt2GFsuQhsfvsk",
            note: "SSRF::Metadata_Access",
            msg: "Possible SSRF: AWS EC2 metadata service accessed by 169.254.169.254",
            src: "169.254.169.254:46758",
            dst: "169.254.169.254:80"
        }
    ],
    http: [
        {
            ts: "09:03:49.439",
            uid: "CINDfJ27E2fRaKJzVf",
            method: "GET",
            host: "127.0.0.1:8080",
            uri: "/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production",
            status: "200 OK",
            ua: "curl/8.14.1"
        },
        {
            ts: "09:03:49.461",
            uid: "CjbXsRqWg8nivYnui",
            method: "GET",
            host: "169.254.169.254",
            uri: "/latest/meta-data/iam/security-credentials/WAF-Role-CapitalOne-Production",
            status: "200 OK",
            ua: "WAF-Proxy-Demo/1.0"
        },
        {
            ts: "09:03:49.479",
            uid: "C1AKQ61lPHgHJ1WiQg",
            method: "GET",
            host: "127.0.0.1:8080",
            uri: "/fetch?url=http://169.254.169.254/mock-s3-bucket/sync",
            status: "200 OK",
            ua: "curl/8.14.1"
        },
        {
            ts: "09:03:49.480",
            uid: "CCHznt2GFsuQhsfvsk",
            method: "GET",
            host: "169.254.169.254",
            uri: "/mock-s3-bucket/sync",
            status: "200 OK",
            ua: "WAF-Proxy-Demo/1.0"
        }
    ],
    conn: [
        {
            uid: "CjbXsRqWg8nivYnui",
            orig: "169.254.169.254:46748",
            resp: "169.254.169.254:80",
            proto: "tcp",
            state: "SF",
            tx: "191 B",
            rx: "478 B",
            duration: "0.0017s"
        },
        {
            uid: "CINDfJ27E2fRaKJzVf",
            orig: "127.0.0.1:44626",
            resp: "127.0.0.1:8080",
            proto: "tcp",
            state: "SF",
            tx: "183 B",
            rx: "478 B",
            duration: "0.0239s"
        },
        {
            uid: "CCHznt2GFsuQhsfvsk",
            orig: "169.254.169.254:46758",
            resp: "169.254.169.254:80",
            proto: "tcp",
            state: "SF",
            tx: "138 B",
            rx: "435 B",
            duration: "0.0007s"
        },
        {
            uid: "C1AKQ61lPHgHJ1WiQg",
            orig: "127.0.0.1:44640",
            resp: "127.0.0.1:8080",
            proto: "tcp",
            state: "SF",
            tx: "130 B",
            rx: "435 B",
            duration: "0.0015s"
        }
    ]
};

document.addEventListener("DOMContentLoaded", () => {
    renderAllTables();
    renderCorrelation();
    setupSegmentedControl();
    setupSearchFilter();
    setupCanaryProbe();
});

function renderAllTables() {
    renderNotice(FORENSIC_DATA.notice);
    renderHttp(FORENSIC_DATA.http);
    renderConn(FORENSIC_DATA.conn);
}

function renderNotice(items) {
    const tbody = document.getElementById("tbody-notice");
    if (!tbody) return;
    tbody.innerHTML = items.map(row => `
        <tr>
            <td class="mono">${row.ts}</td>
            <td class="mono clickable-uid" onclick="pivotUID('${row.uid}')">${row.uid}</td>
            <td class="mono">${row.note}</td>
            <td>${row.msg}</td>
            <td class="mono">${row.src}</td>
            <td class="mono">${row.dst}</td>
        </tr>
    `).join("");
}

function renderHttp(items) {
    const tbody = document.getElementById("tbody-http");
    if (!tbody) return;
    tbody.innerHTML = items.map(row => `
        <tr>
            <td class="mono">${row.ts}</td>
            <td class="mono clickable-uid" onclick="pivotUID('${row.uid}')">${row.uid}</td>
            <td class="mono">${row.method}</td>
            <td class="mono">${row.host}</td>
            <td class="mono" style="max-width:340px; overflow:hidden; text-overflow:ellipsis;" title="${row.uri}">${row.uri}</td>
            <td class="mono">${row.status}</td>
            <td>${row.ua}</td>
        </tr>
    `).join("");
}

function renderConn(items) {
    const tbody = document.getElementById("tbody-conn");
    if (!tbody) return;
    tbody.innerHTML = items.map(row => `
        <tr>
            <td class="mono clickable-uid" onclick="pivotUID('${row.uid}')">${row.uid}</td>
            <td class="mono">${row.orig}</td>
            <td class="mono">${row.resp}</td>
            <td class="mono">${row.proto}</td>
            <td class="mono">${row.state}</td>
            <td class="mono">${row.tx}</td>
            <td class="mono">${row.rx}</td>
            <td class="mono">${row.duration}</td>
        </tr>
    `).join("");
}

function renderCorrelation() {
    const container = document.getElementById("correlation-list");
    if (!container) return;

    const uids = ["CjbXsRqWg8nivYnui", "CCHznt2GFsuQhsfvsk"];
    container.innerHTML = uids.map(uid => {
        const notice = FORENSIC_DATA.notice.find(n => n.uid === uid) || {};
        const http = FORENSIC_DATA.http.find(h => h.uid === uid) || {};
        const conn = FORENSIC_DATA.conn.find(c => c.uid === uid) || {};

        return `
            <div class="correlation-group" id="corr-group-${uid}">
                <div class="correlation-group-header">
                    <span class="group-uid mono">${uid}</span>
                    <span class="group-tag">Correlated across transport, HTTP, and security alert</span>
                </div>
                <div class="correlation-triad">
                    <div class="triad-col">
                        <span class="triad-label">Security alert (notice.log)</span>
                        <span class="triad-primary mono">${notice.note || 'None'}</span>
                        <span class="triad-secondary">${notice.msg || ''}</span>
                    </div>
                    <div class="triad-col">
                        <span class="triad-label">HTTP transaction (http.log)</span>
                        <span class="triad-primary mono">${http.method || ''} ${http.uri || ''}</span>
                        <span class="triad-secondary mono">${http.host || ''}</span>
                    </div>
                    <div class="triad-col">
                        <span class="triad-label">Network transport (conn.log)</span>
                        <span class="triad-primary mono">${conn.orig || ''} &rarr; ${conn.resp || ''}</span>
                        <span class="triad-secondary mono">${conn.proto || ''} &bull; ${conn.tx || ''} sent &bull; ${conn.rx || ''} rcvd</span>
                    </div>
                </div>
            </div>
        `;
    }).join("");
}

function setupSegmentedControl() {
    const buttons = document.querySelectorAll(".seg-btn");
    buttons.forEach(btn => {
        btn.addEventListener("click", () => {
            buttons.forEach(b => {
                b.classList.remove("active");
                b.setAttribute("aria-selected", "false");
            });
            document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            btn.setAttribute("aria-selected", "true");

            const paneId = `pane-${btn.getAttribute("data-tab")}`;
            const targetPane = document.getElementById(paneId);
            if (targetPane) targetPane.classList.add("active");
        });
    });
}

function setupSearchFilter() {
    const searchInput = document.getElementById("log-search-input");
    if (!searchInput) return;

    searchInput.addEventListener("input", (e) => {
        const query = e.target.value.toLowerCase().trim();
        if (!query) {
            renderAllTables();
            return;
        }

        const filteredNotice = FORENSIC_DATA.notice.filter(r =>
            r.uid.toLowerCase().includes(query) ||
            r.msg.toLowerCase().includes(query) ||
            r.src.toLowerCase().includes(query) ||
            r.note.toLowerCase().includes(query)
        );

        const filteredHttp = FORENSIC_DATA.http.filter(r =>
            r.uid.toLowerCase().includes(query) ||
            r.uri.toLowerCase().includes(query) ||
            r.host.toLowerCase().includes(query) ||
            r.method.toLowerCase().includes(query)
        );

        const filteredConn = FORENSIC_DATA.conn.filter(r =>
            r.uid.toLowerCase().includes(query) ||
            r.orig.toLowerCase().includes(query) ||
            r.resp.toLowerCase().includes(query)
        );

        renderNotice(filteredNotice);
        renderHttp(filteredHttp);
        renderConn(filteredConn);
    });
}

function pivotUID(uid) {
    const corrBtn = document.querySelector('[data-tab="correlation"]');
    if (corrBtn) corrBtn.click();

    setTimeout(() => {
        const group = document.getElementById(`corr-group-${uid}`);
        if (group) {
            group.scrollIntoView({ behavior: 'smooth', block: 'center' });
            group.style.opacity = '0.5';
            setTimeout(() => {
                group.style.opacity = '1';
            }, 300);
        }
    }, 50);
}

function setupCanaryProbe() {
    const btn = document.getElementById("btn-trigger-canary");
    if (!btn) return;

    btn.addEventListener("click", () => {
        btn.textContent = "Executing probe...";
        btn.style.opacity = "0.6";

        setTimeout(() => {
            const now = new Date().toISOString().replace(/\.\d{3}/, "");
            const randomOctet = Math.floor(Math.random() * 100) + 50;
            const newIP = `198.51.100.${randomOctet}`;

            const cloudtrailObj = {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AIDATU7L4S6W5LRX4CBJF",
                    "arn": "arn:aws:iam::251213420461:user/azqjoxxwnbghiqrlgpsilbuqdrvuarunrsbsgtbgvlitxufczq",
                    "accountId": "251213420461",
                    "accessKeyId": "AKIATU7L4S6WVXD4O77Z"
                },
                "eventTime": now,
                "eventSource": "sts.amazonaws.com",
                "eventName": "GetCallerIdentity",
                "awsRegion": "us-east-1",
                "sourceIPAddress": newIP,
                "userAgent": "aws-cli/2.15.15 Python/3.11.6 Darwin/23.4.0",
                "eventType": "AwsApiCall"
            };

            const pre = document.getElementById("cloudtrail-pre");
            if (pre) pre.textContent = JSON.stringify(cloudtrailObj, null, 2);

            btn.textContent = "Probe recorded";
            btn.style.opacity = "1";

            setTimeout(() => {
                btn.textContent = "Simulate attacker probe";
            }, 2500);
        }, 500);
    });
}
