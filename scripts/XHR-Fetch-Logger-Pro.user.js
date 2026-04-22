// ==UserScript==
// @name         XHR/Fetch Logger Pro
// @namespace    http://tampermonkey.net/
// @version      1.0.0
// @description  Log all XHR & Fetch requests. CSP-proof via unsafeWindow direct hook. Firefox + Chrome
// @author       TekMonts
// @match        *://*/*
// @grant        unsafeWindow
// @grant        GM_setClipboard
// @grant        GM_addStyle
// @run-at       document-start
// @noframes
// ==/UserScript==

(function () {
    'use strict';

    /* =========================================================
     * CORE: Hook direct unsafeWindow (page's real window).
     * Not using <script> tag → CSP cannot block.
     * ========================================================= */

    const W = (typeof unsafeWindow !== 'undefined') ? unsafeWindow : window;
    const isFirefox = (typeof exportFunction === 'function') && (typeof cloneInto === 'function');

    // Wrap function allowing page world calls (Firefox xray) or plain (Chrome)
    const exportFn = (fn) => isFirefox ? exportFunction(fn, W) : fn;
    const cloneObj = (obj) => isFirefox ? cloneInto(obj, W, { cloneFunctions: true }) : obj;

    const store = [];
    let hookOK = false;
    let hookMethod = 'pending';
    let hookError = null;

    const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);

    const truncate = (s, max) => {
        max = max || 500000;
        if (typeof s !== 'string') return s;
        return s.length > max ? s.slice(0, max) + '\n…[truncated ' + (s.length - max) + ' chars]' : s;
    };

    const parseHeaders = (raw) => {
        const h = {};
        if (!raw) return h;
        raw.trim().split(/[\r\n]+/).forEach(line => {
            const parts = line.split(': ');
            const key = parts.shift();
            const val = parts.join(': ');
            if (key) h[key] = val;
        });
        return h;
    };

    const pushLog = (log) => {
        store.push(log);
        scheduleRender();
    };

    /* =========================================================
     * HOOK XMLHttpRequest
     * ========================================================= */
    const installXHRHook = () => {
        const OrigXHR = W.XMLHttpRequest;
        if (!OrigXHR || !OrigXHR.prototype) throw new Error('No XHR in unsafeWindow');

        const proto = OrigXHR.prototype;
        const origOpen = proto.open;
        const origSend = proto.send;
        const origSetHeader = proto.setRequestHeader;

        const newOpen = exportFn(function (method, url) {
            try {
                const log = {
                    id: uid(), type: 'xhr',
                    method: (method || 'GET').toUpperCase(),
                    url: String(url), requestHeaders: {},
                    time: new Date().toISOString(),
                    startedAt: Date.now()
                };
                xhrLogMap.set(this, log);
            } catch (e) {}
            return origOpen.apply(this, arguments);
        });

        const newSetHeader = exportFn(function (k, v) {
            try {
                const log = xhrLogMap.get(this);
                if (log) log.requestHeaders[k] = String(v);
            } catch (e) {}
            return origSetHeader.apply(this, arguments);
        });

        const newSend = exportFn(function (body) {
            try {
                const log = xhrLogMap.get(this);
                if (log) {
                    try {
                        if (body == null) log.requestBody = null;
                        else if (typeof body === 'string') log.requestBody = truncate(body);
                        else if (body && body.constructor && body.constructor.name === 'FormData') log.requestBody = '[FormData]';
                        else if (body && body.constructor && body.constructor.name === 'Blob') log.requestBody = '[Blob]';
                        else log.requestBody = '[binary]';
                    } catch (_) { log.requestBody = '[unreadable]'; }

                    const xhr = this;
                    xhr.addEventListener('loadend', exportFn(function () {
                        try {
                            log.status = xhr.status;
                            log.statusText = xhr.statusText;
                            log.duration = Date.now() - log.startedAt;
                            try { log.responseHeaders = parseHeaders(xhr.getAllResponseHeaders()); } catch (_) { log.responseHeaders = {}; }
                            try {
                                if (xhr.responseType === '' || xhr.responseType === 'text') log.responseBody = truncate(xhr.responseText || '');
                                else if (xhr.responseType === 'json') log.responseBody = truncate(JSON.stringify(xhr.response));
                                else log.responseBody = '[' + (xhr.responseType || 'binary') + ']';
                            } catch (_) { log.responseBody = '[unreadable]'; }
                            pushLog(log);
                        } catch (e) {}
                    }));
                }
            } catch (e) {}
            return origSend.apply(this, arguments);
        });

        let assigned = false;
        try {
            proto.open = newOpen;
            proto.setRequestHeader = newSetHeader;
            proto.send = newSend;
            assigned = (proto.open !== origOpen);
        } catch (_) {}

        if (!assigned) {
            // Fallback: defineProperty
            Object.defineProperty(proto, 'open', { value: newOpen, writable: true, configurable: true });
            Object.defineProperty(proto, 'setRequestHeader', { value: newSetHeader, writable: true, configurable: true });
            Object.defineProperty(proto, 'send', { value: newSend, writable: true, configurable: true });
        }

        return true;
    };

    const xhrLogMap = new WeakMap();

    /* =========================================================
     * HOOK fetch
     * ========================================================= */
    const installFetchHook = () => {
        const origFetch = W.fetch;
        if (!origFetch) return false;

        const newFetch = exportFn(function (input, init) {
            const log = {
                id: uid(), type: 'fetch',
                time: new Date().toISOString(),
                startedAt: Date.now(),
                requestHeaders: {}
            };
            try {
                log.url = (typeof input === 'string') ? input : (input && input.url) || String(input);
                log.method = ((init && init.method) || (input && input.method) || 'GET').toUpperCase();
                const hdrs = (init && init.headers) || (input && input.headers);
                if (hdrs) {
                    if (typeof hdrs.forEach === 'function') {
                        hdrs.forEach(exportFn(function (v, k) { log.requestHeaders[k] = String(v); }));
                    } else if (typeof hdrs === 'object') {
                        try { Object.keys(hdrs).forEach(k => log.requestHeaders[k] = String(hdrs[k])); } catch (_) {}
                    }
                }
                if (init && init.body != null) {
                    if (typeof init.body === 'string') log.requestBody = truncate(init.body);
                    else log.requestBody = '[non-text]';
                }
            } catch (_) {}

            const promise = origFetch.apply(this, arguments);
            try {
                promise.then(exportFn(function (res) {
                    try {
                        const clone = res.clone();
                        log.status = clone.status;
                        log.statusText = clone.statusText;
                        log.duration = Date.now() - log.startedAt;
                        log.responseHeaders = {};
                        clone.headers.forEach(exportFn(function (v, k) { log.responseHeaders[k] = v; }));
                        clone.text().then(exportFn(function (t) {
                            log.responseBody = truncate(t);
                            pushLog(log);
                        }), exportFn(function () {
                            log.responseBody = '[unreadable]';
                            pushLog(log);
                        }));
                    } catch (_) { pushLog(log); }
                }), exportFn(function (err) {
                    log.status = 0;
                    log.error = String(err);
                    log.duration = Date.now() - log.startedAt;
                    pushLog(log);
                }));
            } catch (_) {}
            return promise;
        });

        try {
            W.fetch = newFetch;
        } catch (_) {
            Object.defineProperty(W, 'fetch', { value: newFetch, writable: true, configurable: true });
        }
        return true;
    };

    /* =========================================================
     * INSTALL HOOKS
     * ========================================================= */
    try {
        installXHRHook();
        installFetchHook();
        hookOK = true;
        hookMethod = isFirefox ? 'unsafeWindow+exportFunction (Firefox)' : 'unsafeWindow direct (Chrome)';
        console.log('[XHR Logger] Hook installed:', hookMethod);
    } catch (e) {
        hookError = String(e);
        console.error('[XHR Logger] Hook install failed:', e);

        // Fallback
        try {
            const src = '(' + function (TAG) {
                if (window.__XHR_LOGGER_FB__) return;
                window.__XHR_LOGGER_FB__ = true;
                const post = (p) => window.postMessage({ __tag: TAG, payload: p }, '*');
                const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
                const OrigXHR = window.XMLHttpRequest;
                const po = OrigXHR.prototype.open, ps = OrigXHR.prototype.send;
                OrigXHR.prototype.open = function (m, u) {
                    this.__l = { id: uid(), type: 'xhr', method: (m || 'GET').toUpperCase(), url: String(u), requestHeaders: {}, time: new Date().toISOString(), startedAt: Date.now() };
                    return po.apply(this, arguments);
                };
                OrigXHR.prototype.send = function (b) {
                    const l = this.__l;
                    if (l) {
                        l.requestBody = typeof b === 'string' ? b : (b ? '[binary]' : null);
                        const x = this;
                        x.addEventListener('loadend', function () {
                            l.status = x.status; l.duration = Date.now() - l.startedAt;
                            try { l.responseBody = x.responseText || ''; } catch (_) {}
                            post({ kind: 'log', data: l });
                        });
                    }
                    return ps.apply(this, arguments);
                };
                if (window.fetch) {
                    const of = window.fetch;
                    window.fetch = function (i, n) {
                        const l = { id: uid(), type: 'fetch', url: typeof i === 'string' ? i : (i && i.url), method: ((n && n.method) || 'GET').toUpperCase(), requestHeaders: {}, time: new Date().toISOString(), startedAt: Date.now() };
                        if (n && typeof n.body === 'string') l.requestBody = n.body;
                        return of.apply(this, arguments).then(r => {
                            const c = r.clone();
                            l.status = c.status; l.duration = Date.now() - l.startedAt;
                            l.responseHeaders = {};
                            c.headers.forEach((v, k) => l.responseHeaders[k] = v);
                            c.text().then(t => { l.responseBody = t; post({ kind: 'log', data: l }); });
                            return r;
                        });
                    };
                }
                post({ kind: 'ready' });
            }.toString() + ')("__XHR_LOGGER_MSG__");';

            const s = document.createElement('script');
            s.textContent = src;
            (document.head || document.documentElement).appendChild(s);
            s.remove();

            window.addEventListener('message', (e) => {
                if (e.source !== window || !e.data || e.data.__tag !== '__XHR_LOGGER_MSG__') return;
                if (e.data.payload.kind === 'log') pushLog(e.data.payload.data);
                else if (e.data.payload.kind === 'ready') { hookOK = true; hookMethod = 'script-tag fallback'; scheduleRender(); }
            });
            hookMethod = 'script-tag (fallback pending)';
        } catch (e2) {
            hookError += ' | fallback: ' + e2;
        }
    }

    /* =========================================================
     * UI
     * ========================================================= */
    GM_addStyle(`
        #xhr-logger-root, #xhr-logger-root * { box-sizing: border-box; font-family: ui-monospace, Menlo, Consolas, monospace; }
        #xhr-logger-fab {
            position: fixed; z-index: 2147483646; bottom: 20px; right: 20px;
            width: 48px; height: 48px; border-radius: 50%;
            background: linear-gradient(135deg,#6366f1,#8b5cf6); color: #fff;
            display: flex; align-items: center; justify-content: center;
            cursor: pointer; box-shadow: 0 6px 20px rgba(99,102,241,.5);
            font-weight: 700; font-size: 18px; user-select: none;
            transition: transform .2s;
        }
        #xhr-logger-fab:hover { transform: scale(1.08); }
        #xhr-logger-fab .badge {
            position: absolute; top: -4px; right: -4px; background: #ef4444;
            color: #fff; font-size: 11px; padding: 2px 6px; border-radius: 10px;
            min-width: 20px; text-align: center;
        }
        #xhr-logger-panel {
            position: fixed; z-index: 2147483647; bottom: 80px; right: 20px;
            width: 750px; max-width: 95vw; height: 520px; max-height: 85vh;
            background: #0f172a; color: #e2e8f0;
            border: 1px solid #334155; border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,.6);
            display: none; flex-direction: column; overflow: hidden;
            resize: both;
        }
        #xhr-logger-panel.open { display: flex; }
        .xhrl-header {
            display: flex; align-items: center; gap: 8px; padding: 10px 12px;
            background: #1e293b; border-bottom: 1px solid #334155; flex-wrap: wrap;
        }
        .xhrl-header .title { font-weight: 700; color: #a5b4fc; flex: 1; font-size: 13px; }
        .xhrl-btn {
            background: #334155; color: #e2e8f0; border: none; padding: 5px 10px;
            border-radius: 6px; font-size: 11px; cursor: pointer; font-family: inherit;
        }
        .xhrl-btn:hover { background: #475569; }
        .xhrl-btn.danger { background: #7f1d1d; }
        .xhrl-btn.danger:hover { background: #991b1b; }
        .xhrl-search {
            padding: 6px 10px; background: #0f172a; border: 1px solid #334155;
            color: #e2e8f0; border-radius: 6px; font-size: 12px; width: 160px;
            font-family: inherit;
        }
        .xhrl-body { display: flex; flex: 1; overflow: hidden; }
        .xhrl-list { width: 45%; overflow-y: auto; border-right: 1px solid #334155; }
        .xhrl-item {
            padding: 8px 10px; border-bottom: 1px solid #1e293b; cursor: pointer;
            font-size: 11px; display: flex; gap: 6px; align-items: center;
        }
        .xhrl-item:hover { background: #1e293b; }
        .xhrl-item.active { background: #312e81; }
        .xhrl-method {
            padding: 1px 6px; border-radius: 3px; font-weight: 700; font-size: 10px;
            min-width: 45px; text-align: center;
        }
        .m-GET { background: #065f46; color: #6ee7b7; }
        .m-POST { background: #1e40af; color: #93c5fd; }
        .m-PUT { background: #92400e; color: #fcd34d; }
        .m-DELETE { background: #991b1b; color: #fca5a5; }
        .m-PATCH { background: #5b21b6; color: #c4b5fd; }
        .xhrl-url { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .xhrl-status { font-weight: 700; font-size: 10px; }
        .s-2 { color: #6ee7b7; } .s-3 { color: #fcd34d; }
        .s-4 { color: #fca5a5; } .s-5 { color: #f87171; } .s-0 { color: #94a3b8; }
        .xhrl-detail {
            flex: 1; overflow-y: auto; padding: 10px; font-size: 11px;
            background: #020617;
        }
        .xhrl-detail h4 { color: #a5b4fc; margin: 8px 0 4px; font-size: 12px; }
        .xhrl-detail pre {
            background: #0f172a; padding: 8px; border-radius: 6px;
            overflow-x: auto; white-space: pre-wrap; word-break: break-all;
            border: 1px solid #1e293b; margin: 0; color: #cbd5e1; max-height: 300px;
        }
        .xhrl-detail .row { display: flex; gap: 8px; margin-bottom: 4px; word-break: break-all; }
        .xhrl-actions { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
        .xhrl-empty { padding: 20px; text-align: center; color: #64748b; font-size: 12px; }
        .xhrl-toast {
            position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%);
            background: #10b981; color: #fff; padding: 8px 16px; border-radius: 6px;
            font-size: 12px; z-index: 2147483647; font-family: ui-monospace,monospace;
        }
        .xhrl-diag { font-size: 10px; color: #94a3b8; padding: 6px 12px; background: #0b1120; border-top: 1px solid #1e293b; }
        .xhrl-diag.err { color: #fca5a5; }
    `);

    const fab = document.createElement('div');
    fab.id = 'xhr-logger-fab';
    fab.innerHTML = '🕸<span class="badge" style="display:none">0</span>';

    const panel = document.createElement('div');
    panel.id = 'xhr-logger-panel';
    panel.innerHTML = `
        <div class="xhrl-header">
            <span class="title">🕸 XHR/Fetch Logger Pro</span>
            <input class="xhrl-search" id="xhrl-search" placeholder="filter url..." />
            <button class="xhrl-btn" id="xhrl-export-json">JSON</button>
            <button class="xhrl-btn" id="xhrl-export-curl">cURL</button>
            <button class="xhrl-btn" id="xhrl-export-text">TEXT</button>
            <button class="xhrl-btn danger" id="xhrl-clear">Clear</button>
            <button class="xhrl-btn" id="xhrl-close">✕</button>
        </div>
        <div class="xhrl-body">
            <div class="xhrl-list" id="xhrl-list"><div class="xhrl-empty">No requests yet…</div></div>
            <div class="xhrl-detail" id="xhrl-detail"><div class="xhrl-empty">Select a request</div></div>
        </div>
        <div class="xhrl-diag" id="xhrl-diag"></div>
    `;

    const mount = () => {
        if (document.getElementById('xhr-logger-root')) return;
        const root = document.createElement('div');
        root.id = 'xhr-logger-root';
        root.appendChild(fab);
        root.appendChild(panel);
        (document.body || document.documentElement).appendChild(root);
    };
    if (document.body) mount();
    else {
        document.addEventListener('DOMContentLoaded', mount);
        const iv = setInterval(() => { if (document.body) { mount(); clearInterval(iv); } }, 100);
    }

    let selectedId = null;
    let filterText = '';
    let renderPending = false;

    function scheduleRender() {
        if (renderPending) return;
        renderPending = true;
        requestAnimationFrame(() => {
            renderPending = false;
            updateBadge();
            if (panel.classList.contains('open')) renderList();
        });
    }

    const updateBadge = () => {
        const badge = fab.querySelector('.badge');
        if (!badge) return;
        badge.style.display = store.length ? 'inline-block' : 'none';
        badge.textContent = store.length;
    };

    const toast = (msg) => {
        const t = document.createElement('div');
        t.className = 'xhrl-toast';
        t.textContent = msg;
        document.body.appendChild(t);
        setTimeout(() => t.remove(), 1600);
    };

    const toCurl = (log) => {
        let c = `curl '${log.url}' \\\n  -X ${log.method}`;
        Object.entries(log.requestHeaders || {}).forEach(([k, v]) => {
            c += ` \\\n  -H '${k}: ${String(v).replace(/'/g, "'\\''")}'`;
        });
        if (log.requestBody && typeof log.requestBody === 'string' && !log.requestBody.startsWith('[')) {
            c += ` \\\n  --data-raw '${log.requestBody.replace(/'/g, "'\\''")}'`;
        }
        return c;
    };

    const toText = (log) => {
        let s = `=== ${log.method} ${log.url}\n`;
        s += `Time: ${log.time}  |  Status: ${log.status || '-'} ${log.statusText || ''}  |  ${log.duration || 0}ms  |  ${log.type}\n\n`;
        s += `--- Request Headers ---\n`;
        Object.entries(log.requestHeaders || {}).forEach(([k, v]) => s += `${k}: ${v}\n`);
        if (log.requestBody) s += `\n--- Request Body ---\n${log.requestBody}\n`;
        s += `\n--- Response Headers ---\n`;
        Object.entries(log.responseHeaders || {}).forEach(([k, v]) => s += `${k}: ${v}\n`);
        s += `\n--- Response Body ---\n${log.responseBody || ''}\n`;
        return s;
    };

    const download = (filename, content, type = 'text/plain') => {
        const blob = new Blob([content], { type });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = filename;
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 2000);
    };

    const copy = (txt) => {
        try { GM_setClipboard(txt); toast('Copied!'); return; } catch (_) {}
        try { navigator.clipboard.writeText(txt).then(() => toast('Copied!')); } catch (_) { toast('Copy failed'); }
    };

    const esc = (s) => String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    const filtered = () => !filterText ? store : store.filter(l => l.url.toLowerCase().includes(filterText));

    const renderList = () => {
        const listEl = document.getElementById('xhrl-list');
        const diagEl = document.getElementById('xhrl-diag');
        if (diagEl) {
            diagEl.textContent = `v1.0 By TekMonts | Browser: ${isFirefox ? 'Firefox' : 'Chrome-like'} · unsafeWindow: ${W === window ? 'NO (same as window)' : 'YES'} · hook: ${hookMethod} · ok: ${hookOK} · logs: ${store.length}${hookError ? ' · err: ' + hookError : ''}`;
            diagEl.className = hookOK ? 'xhrl-diag' : 'xhrl-diag err';
        }
        if (!listEl) return;
        const logs = filtered();
        if (!logs.length) {
            let msg;
            if (!hookOK && hookError) msg = `⚠ Hook failed: ${hookError}`;
            else if (!hookOK) msg = `Installing hook (${hookMethod})…`;
            else msg = 'Hook active. Waiting for requests… (try interacting with page)';
            listEl.innerHTML = '<div class="xhrl-empty">' + esc(msg) + '</div>';
            return;
        }
        listEl.innerHTML = logs.slice().reverse().map(l => {
            const sClass = 's-' + String(l.status || 0).charAt(0);
            return `<div class="xhrl-item ${l.id === selectedId ? 'active' : ''}" data-id="${l.id}">
                <span class="xhrl-method m-${l.method}">${l.method}</span>
                <span class="xhrl-status ${sClass}">${l.status || '—'}</span>
                <span class="xhrl-url" title="${esc(l.url)}">${esc(l.url)}</span>
            </div>`;
        }).join('');
        listEl.querySelectorAll('.xhrl-item').forEach(el => {
            el.addEventListener('click', () => {
                selectedId = el.dataset.id;
                renderList(); renderDetail();
            });
        });
    };

    const renderDetail = () => {
        const detailEl = document.getElementById('xhrl-detail');
        if (!detailEl) return;
        const log = store.find(l => l.id === selectedId);
        if (!log) { detailEl.innerHTML = '<div class="xhrl-empty">Select a request</div>'; return; }
        detailEl.innerHTML = `
            <div class="row"><b>${log.method}</b> <span>${esc(log.url)}</span></div>
            <div class="row">Status: <b>${log.status || '-'} ${esc(log.statusText || '')}</b> · ${log.duration || 0}ms · ${log.type} · ${esc(log.time)}</div>
            <div class="xhrl-actions">
                <button class="xhrl-btn" data-act="copy-json">📋 JSON</button>
                <button class="xhrl-btn" data-act="copy-curl">📋 cURL</button>
                <button class="xhrl-btn" data-act="copy-text">📋 Text</button>
                <button class="xhrl-btn" data-act="copy-body">📋 Response</button>
            </div>
            <h4>Request Headers</h4>
            <pre>${esc(JSON.stringify(log.requestHeaders || {}, null, 2))}</pre>
            ${log.requestBody ? `<h4>Request Body</h4><pre>${esc(log.requestBody)}</pre>` : ''}
            <h4>Response Headers</h4>
            <pre>${esc(JSON.stringify(log.responseHeaders || {}, null, 2))}</pre>
            <h4>Response Body</h4>
            <pre>${esc(log.responseBody || '')}</pre>
        `;
        detailEl.querySelectorAll('[data-act]').forEach(b => {
            b.addEventListener('click', () => {
                const act = b.dataset.act;
                if (act === 'copy-json') copy(JSON.stringify(log, null, 2));
                else if (act === 'copy-curl') copy(toCurl(log));
                else if (act === 'copy-text') copy(toText(log));
                else if (act === 'copy-body') copy(log.responseBody || '');
            });
        });
    };

    document.addEventListener('click', (e) => {
        const t = e.target;
        if (!t) return;
        if (t === fab || (fab && fab.contains(t))) {
            panel.classList.toggle('open');
            renderList();
            return;
        }
        if (!t.id) return;
        if (t.id === 'xhrl-close') panel.classList.remove('open');
        else if (t.id === 'xhrl-clear') {
            store.length = 0; selectedId = null;
            updateBadge(); renderList(); renderDetail();
        }
        else if (t.id === 'xhrl-export-json') download('xhr-log.json', JSON.stringify(store, null, 2), 'application/json');
        else if (t.id === 'xhrl-export-curl') download('xhr-log.sh', store.map(toCurl).join('\n\n'), 'text/plain');
        else if (t.id === 'xhrl-export-text') download('xhr-log.txt', store.map(toText).join('\n\n'), 'text/plain');
    });

    document.addEventListener('input', (e) => {
        if (e.target && e.target.id === 'xhrl-search') {
            filterText = e.target.value.toLowerCase();
            renderList();
        }
    });

    setTimeout(scheduleRender, 500);
})();
