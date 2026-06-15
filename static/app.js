/* =============================================================
   PhishGuard AI — Shared frontend helpers
   Used by every page. Defines API base, token storage, and
   a small set of UI utilities.
   ============================================================= */
(function (global) {
    'use strict';

    const TOKEN_KEY = 'phishguard_token';
    const USER_KEY = 'phishguard_user';

    const config = global.PHISHGUARD_CONFIG || {};
    const API_BASE = (config.apiBase || '').replace(/\/+$/, '');

    function getToken() {
        try { return localStorage.getItem(TOKEN_KEY); }
        catch (e) { return null; }
    }

    function setToken(token) {
        if (!token) return;
        try { localStorage.setItem(TOKEN_KEY, token); }
        catch (e) { /* storage unavailable */ }
    }

    function clearToken() {
        try {
            localStorage.removeItem(TOKEN_KEY);
            localStorage.removeItem(USER_KEY);
            localStorage.removeItem('phishguard_remember_email');
        } catch (e) { /* noop */ }
    }

    function getUser() {
        try {
            const raw = localStorage.getItem(USER_KEY);
            return raw ? JSON.parse(raw) : null;
        } catch (e) { return null; }
    }

    function setUser(user) {
        try {
            if (user) localStorage.setItem(USER_KEY, JSON.stringify(user));
            else localStorage.removeItem(USER_KEY);
        } catch (e) { /* noop */ }
    }

    async function apiFetch(url, options) {
        options = options || {};
        const fullUrl = url.startsWith('http') ? url : (API_BASE + url);
        const headers = Object.assign({}, options.headers || {});

        const token = getToken();
        const skipAuth = options.skipAuth === true;
        if (token && !skipAuth && !headers.Authorization) {
            headers.Authorization = 'Bearer ' + token;
        }

        let response;
        try {
            response = await fetch(fullUrl, Object.assign({}, options, { headers }));
        } catch (networkErr) {
            throw new Error('Network error. Please check your connection.');
        }

        if (response.status === 401 && !skipAuth) {
            clearToken();
            const path = window.location.pathname;
            if (path !== '/login' && path !== '/register' && path !== '/') {
                window.location.href = '/login?expired=1';
            }
            throw new Error('Your session has expired. Please log in again.');
        }

        let payload = null;
        const text = await response.text();
        if (text) {
            try { payload = JSON.parse(text); }
            catch (e) { payload = { detail: text }; }
        }

        if (!response.ok) {
            const detail = (payload && (payload.detail || payload.message)) || `Request failed (${response.status}).`;
            const error = new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
            error.status = response.status;
            error.payload = payload;
            throw error;
        }
        return payload;
    }

    function showAlert(el, message, type) {
        if (!el) return;
        if (!message) {
            el.classList.add('hidden');
            el.textContent = '';
            return;
        }
        el.classList.remove('hidden');
        el.className = 'alert ' + (type || 'info');
        el.textContent = message;
    }

    function setLoading(btn, labelEl, spinnerEl, loading) {
        if (!btn) return;
        btn.disabled = !!loading;
        if (labelEl) labelEl.style.opacity = loading ? '0.7' : '1';
        if (spinnerEl) {
            if (loading) spinnerEl.classList.remove('hidden');
            else spinnerEl.classList.add('hidden');
        }
        if (btn) {
            if (loading) btn.classList.add('is-pulsing');
            else btn.classList.remove('is-pulsing');
        }
    }

    function getToastContainer() {
        let container = document.querySelector('.toast-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
        return container;
    }

    const TOAST_ICONS = {
        success: '✓',
        error: '!',
        info: 'i',
    };

    function showToast(message, type, duration) {
        type = type || 'info';
        duration = typeof duration === 'number' ? duration : 3000;
        const container = getToastContainer();
        const toast = document.createElement('div');
        toast.className = 'toast ' + type;
        toast.setAttribute('role', type === 'error' ? 'alert' : 'status');

        const icon = document.createElement('span');
        icon.className = 'toast-icon';
        icon.textContent = TOAST_ICONS[type] || TOAST_ICONS.info;

        const text = document.createElement('span');
        text.className = 'toast-text';
        text.textContent = message;

        toast.appendChild(icon);
        toast.appendChild(text);
        container.appendChild(toast);

        const timer = setTimeout(() => dismissToast(toast), duration);
        toast.addEventListener('click', () => {
            clearTimeout(timer);
            dismissToast(toast);
        });
        return toast;
    }

    function dismissToast(toast) {
        if (!toast || toast.classList.contains('is-leaving')) return;
        toast.classList.add('is-leaving');
        setTimeout(() => {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 260);
    }

    function formatDate(iso) {
        if (!iso) return '';
        const d = new Date(iso);
        if (isNaN(d.getTime())) return iso;
        return d.toLocaleString(undefined, {
            year: 'numeric', month: 'short', day: '2-digit',
            hour: '2-digit', minute: '2-digit',
        });
    }

    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function initials(name) {
        if (!name) return '?';
        const parts = name.trim().split(/\s+/);
        if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
        return (parts[0][0] + parts[1][0]).toUpperCase();
    }

    async function requireAuth() {
        const token = getToken();
        if (!token) {
            window.location.href = '/login';
            return null;
        }
        try {
            const user = await apiFetch('/api/auth/me');
            setUser(user);
            return user;
        } catch (err) {
            clearToken();
            window.location.href = '/login';
            return null;
        }
    }

    global.getToken = getToken;
    global.setToken = setToken;
    global.clearToken = clearToken;
    global.getUser = getUser;
    global.setUser = setUser;
    global.apiFetch = apiFetch;
    global.showAlert = showAlert;
    global.setLoading = setLoading;
    global.showToast = showToast;
    global.formatDate = formatDate;
    global.escapeHtml = escapeHtml;
    global.initials = initials;
    global.requireAuth = requireAuth;
    global.API_BASE = API_BASE;
})(window);
