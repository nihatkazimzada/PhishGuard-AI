/* =============================================================
   PhishGuard AI — Dashboard logic
   ============================================================= */
(function () {
    'use strict';

    const VERDICT_COLORS = {
        SAFE: 'success',
        SUSPICIOUS: 'warning',
        PHISHING: 'danger',
    };

    const INDICATOR_LABELS = {
        urgency_language: 'Urgency language',
        suspicious_links: 'Suspicious links',
        impersonation_attempt: 'Impersonation attempt',
        grammar_errors: 'Grammar errors',
        unusual_sender_patterns: 'Unusual sender patterns',
        credential_request: 'Credential request',
        financial_pressure: 'Financial pressure',
    };

    const SAMPLE_EMAIL = {
        subject: 'URGENT: Your PayPal account has been LIMITED - Verify within 24 hours',
        body:
            "Dear Valued Customer,\n\n" +
            "We have detected unusual activity on your PayPal account. For your protection, " +
            "your account has been temporarily LIMITED.\n\n" +
            "You must verify your identity IMMEDIATELY to avoid permanent suspension. " +
            "Please click the link below and confirm your details within 24 hours:\n\n" +
            "http://paypa1-secure-verify.com/login?id=99213\n\n" +
            "Failure to act will result in your account being permanently closed and your funds " +
            "withheld pending legal review.\n\n" +
            "Please act now. This is your final notice.\n\n" +
            "PayPal Security Team"
    };

    const scanForm = document.getElementById('scan-form');
    const subjectInput = document.getElementById('email-subject');
    const bodyInput = document.getElementById('email-body');
    const analyzeBtn = document.getElementById('analyze-btn');
    const sampleBtn = document.getElementById('sample-btn');
    const btnLabel = analyzeBtn.querySelector('.btn-label');
    const btnSpinner = analyzeBtn.querySelector('.btn-spinner');

    const placeholder = document.getElementById('results-placeholder');
    const loadingPanel = document.getElementById('results-loading');
    const resultsContent = document.getElementById('results-content');
    const verdictBadge = document.getElementById('verdict-badge');
    const riskProgress = document.getElementById('risk-progress');
    const riskCircle = document.querySelector('.risk-circle');
    const riskScoreEl = document.getElementById('risk-score');
    const summaryEl = document.getElementById('summary');
    const indicatorsEl = document.getElementById('indicators-grid');
    const recommendationEl = document.getElementById('recommendation');
    const technicalEl = document.getElementById('technical-details');
    const scanAnotherBtn = document.getElementById('scan-another');

    const navItems = document.querySelectorAll('.nav-item');
    const views = {
        scan: document.getElementById('view-scan'),
        history: document.getElementById('view-history'),
        stats: document.getElementById('view-stats'),
    };

    const userName = document.getElementById('user-name');
    const userAvatar = document.getElementById('user-avatar');
    const logoutBtn = document.getElementById('logout-btn');

    const historyTbody = document.getElementById('history-tbody');
    const paginationEl = document.getElementById('pagination');
    const modal = document.getElementById('history-modal');
    const modalBody = document.getElementById('modal-body');

    const statTotal = document.getElementById('stat-total');
    const statPhishing = document.getElementById('stat-phishing');
    const statSafe = document.getElementById('stat-safe');
    const statMonth = document.getElementById('stat-month');
    const barChart = document.getElementById('bar-chart');

    const hamburger = document.getElementById('hamburger');
    const sidebar = document.getElementById('sidebar');

    const historyState = { page: 1, pageSize: 10, total: 0, lastData: null };

    /* ----------------- Auth bootstrap ----------------- */
    requireAuth().then((user) => {
        if (!user) return;
        userName.textContent = user.username;
        userAvatar.textContent = initials(user.username);
    });

    /* ----------------- Hamburger (mobile) ----------------- */
    if (hamburger && sidebar) {
        hamburger.addEventListener('click', () => {
            const isOpen = sidebar.classList.toggle('is-open');
            hamburger.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        });
        navItems.forEach((n) => n.addEventListener('click', () => {
            if (window.matchMedia('(max-width: 768px)').matches) {
                sidebar.classList.remove('is-open');
                hamburger.setAttribute('aria-expanded', 'false');
            }
        }));
        document.addEventListener('click', (e) => {
            if (!window.matchMedia('(max-width: 768px)').matches) return;
            if (!sidebar.classList.contains('is-open')) return;
            if (sidebar.contains(e.target) || hamburger.contains(e.target)) return;
            sidebar.classList.remove('is-open');
            hamburger.setAttribute('aria-expanded', 'false');
        });
    }

    /* ----------------- Try a Sample ----------------- */
    if (sampleBtn) {
        sampleBtn.addEventListener('click', () => {
            subjectInput.value = SAMPLE_EMAIL.subject;
            bodyInput.value = SAMPLE_EMAIL.body;
            subjectInput.focus();
            showToast('Sample phishing email loaded. Click "Analyze Email" to scan it.', 'info', 3000);
        });
    }

    /* ----------------- Navigation ----------------- */
    function switchView(name) {
        navItems.forEach((n) => n.classList.toggle('active', n.dataset.view === name));
        Object.entries(views).forEach(([k, el]) => {
            if (!el) return;
            el.classList.toggle('hidden', k !== name);
        });
        if (name === 'history') loadHistory();
        if (name === 'stats') loadStats();
    }
    navItems.forEach((n) => n.addEventListener('click', () => switchView(n.dataset.view)));

    /* ----------------- Logout ----------------- */
    logoutBtn.addEventListener('click', () => {
        clearToken();
        window.location.href = '/login';
    });

    /* ----------------- Scan ----------------- */
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const subject = subjectInput.value.trim();
        const body = bodyInput.value.trim();
        if (!body) {
            showToast('Please paste the email body first.', 'error');
            return;
        }
        setLoading(analyzeBtn, btnLabel, btnSpinner, true);
        placeholder.classList.add('hidden');
        resultsContent.classList.add('hidden');
        loadingPanel.classList.remove('hidden');

        try {
            const result = await apiFetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ subject, body }),
            });
            renderResult(result);
        } catch (err) {
            showToast(err.message || 'Scan failed. Please try again.', 'error');
            placeholder.classList.remove('hidden');
        } finally {
            loadingPanel.classList.add('hidden');
            setLoading(analyzeBtn, btnLabel, btnSpinner, false);
        }
    });

    scanAnotherBtn.addEventListener('click', () => {
        resultsContent.classList.add('hidden');
        placeholder.classList.remove('hidden');
        bodyInput.value = '';
        subjectInput.value = '';
        subjectInput.focus();
    });

    function renderResult(result) {
        const verdict = (result.verdict || 'SUSPICIOUS').toUpperCase();
        const risk = Math.max(0, Math.min(100, Number(result.risk_score) || 0));

        verdictBadge.textContent = verdict;
        verdictBadge.className = 'verdict-badge ' + verdict;

        const circumference = 2 * Math.PI * 52;
        const offset = circumference - (risk / 100) * circumference;
        riskProgress.style.strokeDasharray = circumference;
        riskProgress.style.strokeDashoffset = circumference;
        requestAnimationFrame(() => {
            riskProgress.style.strokeDashoffset = offset;
        });
        riskCircle.classList.remove('low', 'med', 'high');
        if (risk >= 70) riskCircle.classList.add('high');
        else if (risk >= 35) riskCircle.classList.add('med');
        else riskCircle.classList.add('low');

        animateNumber(riskScoreEl, risk, 1100);

        summaryEl.textContent = result.ai_explanation || result.summary || 'No summary provided.';

        indicatorsEl.innerHTML = '';
        const indicators = result.indicators || {};
        Object.keys(INDICATOR_LABELS).forEach((key) => {
            const val = !!indicators[key];
            const pill = document.createElement('div');
            pill.className = 'indicator-pill ' + (val ? 'on' : 'off');
            pill.innerHTML = `<span class="ico">${val ? '✗' : '✓'}</span><span>${INDICATOR_LABELS[key]}</span>`;
            indicatorsEl.appendChild(pill);
        });

        recommendationEl.textContent = result.recommendation || 'Exercise caution with this email.';
        technicalEl.textContent = result.technical_details || 'No additional technical details were returned.';

        loadingPanel.classList.add('hidden');
        placeholder.classList.add('hidden');
        resultsContent.classList.remove('hidden');
        resultsContent.style.animation = 'none';
        void resultsContent.offsetWidth;
        resultsContent.style.animation = '';
    }

    function animateNumber(el, target, duration) {
        const start = performance.now();
        const from = 0;
        function tick(now) {
            const t = Math.min(1, (now - start) / duration);
            const eased = 1 - Math.pow(1 - t, 3);
            el.textContent = Math.round(from + (target - from) * eased);
            if (t < 1) requestAnimationFrame(tick);
            else el.textContent = target;
        }
        requestAnimationFrame(tick);
    }

    /* ----------------- History ----------------- */
    async function loadHistory() {
        historyTbody.innerHTML = '<tr><td colspan="5" class="table-empty">Loading...</td></tr>';
        try {
            const data = await apiFetch(
                `/api/scan/history?page=${historyState.page}&page_size=${historyState.pageSize}`
            );
            historyState.lastData = data;
            historyState.total = data.total;
            renderHistory(data);
        } catch (err) {
            historyTbody.innerHTML = `<tr><td colspan="5" class="table-empty">${escapeHtml(err.message || 'Failed to load history.')}</td></tr>`;
            paginationEl.innerHTML = '';
        }
    }

    function renderHistory(data) {
        if (!data.items.length) {
            historyTbody.innerHTML = '<tr><td colspan="5" class="table-empty">No scans yet — analyze your first email!</td></tr>';
            paginationEl.innerHTML = '';
            return;
        }
        historyTbody.innerHTML = '';
        data.items.forEach((scan) => {
            const tr = document.createElement('tr');
            tr.dataset.id = scan.id;
            const verdict = (scan.verdict || 'SUSPICIOUS').toUpperCase();
            const subject = scan.email_subject || '(no subject)';
            tr.innerHTML = `
                <td>${escapeHtml(formatDate(scan.scanned_at))}</td>
                <td>${escapeHtml(subject)}</td>
                <td><span class="verdict-badge ${verdict}">${verdict}</span></td>
                <td>${Number(scan.risk_score) || 0}</td>
                <td><button class="btn btn-ghost btn-sm view-btn">View</button></td>
            `;
            tr.addEventListener('click', () => openModal(scan.id));
            historyTbody.appendChild(tr);
        });
        renderPagination();
    }

    function renderPagination() {
        const totalPages = Math.max(1, Math.ceil(historyState.total / historyState.pageSize));
        if (totalPages <= 1) {
            paginationEl.innerHTML = `<div class="page-info">${historyState.total} total</div><div></div>`;
            return;
        }
        const start = (historyState.page - 1) * historyState.pageSize + 1;
        const end = Math.min(historyState.page * historyState.pageSize, historyState.total);
        let buttons = '';
        buttons += `<button ${historyState.page === 1 ? 'disabled' : ''} data-page="${historyState.page - 1}">‹ Prev</button>`;
        for (let p = 1; p <= totalPages; p++) {
            if (p === 1 || p === totalPages || Math.abs(p - historyState.page) <= 1) {
                buttons += `<button class="${p === historyState.page ? 'active' : ''}" data-page="${p}">${p}</button>`;
            } else if (Math.abs(p - historyState.page) === 2) {
                buttons += `<span style="color:var(--text-muted)">…</span>`;
            }
        }
        buttons += `<button ${historyState.page === totalPages ? 'disabled' : ''} data-page="${historyState.page + 1}">Next ›</button>`;

        paginationEl.innerHTML = `
            <div class="page-info">Showing ${start}–${end} of ${historyState.total}</div>
            <div class="page-controls">${buttons}</div>
        `;
        paginationEl.querySelectorAll('button[data-page]').forEach((b) => {
            b.addEventListener('click', () => {
                const p = parseInt(b.dataset.page, 10);
                if (p >= 1 && p <= totalPages) {
                    historyState.page = p;
                    loadHistory();
                }
            });
        });
    }

    async function openModal(scanId) {
        modal.classList.remove('hidden');
        modalBody.innerHTML = '<p class="muted">Loading...</p>';
        try {
            const scan = await apiFetch(`/api/scan/${scanId}`);
            renderModal(scan);
        } catch (err) {
            modalBody.innerHTML = `<p class="muted">${escapeHtml(err.message || 'Failed to load scan.')}</p>`;
        }
    }

    function renderModal(scan) {
        const verdict = (scan.verdict || 'SUSPICIOUS').toUpperCase();
        const indicators = scan.indicators || {};
        let indicatorHtml = '<div class="indicators-grid">';
        Object.keys(INDICATOR_LABELS).forEach((key) => {
            const v = !!indicators[key];
            indicatorHtml += `<div class="indicator-pill ${v ? 'on' : 'off'}"><span class="ico">${v ? '✗' : '✓'}</span><span>${INDICATOR_LABELS[key]}</span></div>`;
        });
        indicatorHtml += '</div>';

        modalBody.innerHTML = `
            <div class="modal-section">
                <span class="verdict-badge ${verdict}">${verdict}</span>
                <span style="margin-left:12px;color:var(--text-muted);">Risk Score: <strong style="color:var(--text)">${scan.risk_score}</strong></span>
            </div>
            <div class="modal-section">
                <h4>Subject</h4>
                <p>${escapeHtml(scan.email_subject || '(no subject)')}</p>
            </div>
            <div class="modal-section">
                <h4>Body</h4>
                <pre>${escapeHtml(scan.email_body)}</pre>
            </div>
            <div class="modal-section">
                <h4>Analysis</h4>
                <p>${escapeHtml(scan.ai_explanation || '')}</p>
            </div>
            <div class="modal-section">
                <h4>Threat Indicators</h4>
                ${indicatorHtml}
            </div>
            <div class="modal-section">
                <h4>Scanned At</h4>
                <p>${escapeHtml(formatDate(scan.scanned_at))}</p>
            </div>
        `;
    }

    document.querySelectorAll('[data-close-modal]').forEach((el) => {
        el.addEventListener('click', () => modal.classList.add('hidden'));
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') modal.classList.add('hidden');
    });

    /* ----------------- Stats ----------------- */
    async function loadStats() {
        try {
            const data = await apiFetch('/api/user/stats');
            statTotal.textContent = data.total_scans || 0;
            statPhishing.textContent = data.phishing_caught || 0;
            statSafe.textContent = data.safe_emails || 0;
            statMonth.textContent = data.this_month || 0;
            renderBarChart(data.monthly_breakdown || []);
        } catch (err) {
            showToast(err.message || 'Failed to load stats.', 'error');
        }
    }

    function renderBarChart(monthly) {
        const months = ['J', 'F', 'M', 'A', 'M', 'J', 'J', 'A', 'S', 'O', 'N', 'D'];
        const max = Math.max(1, ...monthly);
        barChart.innerHTML = '';
        monthly.forEach((count, idx) => {
            const col = document.createElement('div');
            col.className = 'bar-col';
            const heightPct = max ? (count / max) * 100 : 0;
            col.innerHTML = `
                <div class="bar-value">${count}</div>
                <div class="bar ${count === 0 ? 'zero' : ''}" style="height:${heightPct}%"></div>
                <div class="bar-label">${months[idx]}</div>
            `;
            barChart.appendChild(col);
        });
    }
})();
