// ==UserScript==
// @name         XHR/Fetch/WS Logger Pro
// @namespace    http://tampermonkey.net/
// @version      2.1.0
// @description  XHR + Fetch + WebSocket logger with replay, diff, sensitive detection. Shadow DOM isolated. CSP-proof. Firefox + Chrome.
// @author       TekMonts
// @match        *://*/*
// @grant        unsafeWindow
// @grant        GM_setClipboard
// @grant        GM_setValue
// @grant        GM_getValue
// @run-at       document-start
// @noframes
// ==/UserScript==

(function () {
    'use strict';

    /* =========================================================
     * ⚙ CONFIG + STATE
     * ========================================================= */
    const CONFIG = {
        MAX_LOGS: 2000,
        MAX_BODY_BYTES: 200000,
        RENDER_CAP: 400,
        WS_MAX_FRAMES: 500,
        WS_FRAME_BYTES: 20000,
        AUTO_CLEAR_MS: 0,
    };

    const state = {
        store: [],
        paused: false,
        skipBody: false,
        groupByDomain: true,
        selectedId: null,
        baselineId: null,
        filter: '',
        hookOK: false,
        hookMethod: 'pending',
        hookError: null,
        autoClearTimer: null,
        autoClearNext: 0,
        hookActivatedAt: 0,
        panelPos: null,
        panelSize: null,
    };

    try {
        state.panelPos = JSON.parse(GM_getValue('panelPos', 'null'));
        state.panelSize = JSON.parse(GM_getValue('panelSize', 'null'));
    } catch (_) {}

    /* =========================================================
     * 🧩 ENV DETECTION
     * ========================================================= */
    const W = (typeof unsafeWindow !== 'undefined') ? unsafeWindow : window;
    const isFirefox = (typeof exportFunction === 'function') && (typeof cloneInto === 'function');
    const exportFn = (fn) => isFirefox ? exportFunction(fn, W) : fn;

    /* =========================================================
     * 🛠 UTILITIES
     * ========================================================= */
    const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);

    const truncate = (s, max) => {
        max = max || CONFIG.MAX_BODY_BYTES;
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

    const decodeBinary = (buf) => {
        try {
            let view;
            if (buf instanceof ArrayBuffer) view = new Uint8Array(buf);
            else if (ArrayBuffer.isView(buf)) view = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
            else return '[binary unknown]';

            const len = view.byteLength;
            const typeName = (buf.constructor && buf.constructor.name) || 'binary';

            try {
                const text = new TextDecoder('utf-8', { fatal: false }).decode(view);
                let nonPrintable = 0;
                const sampleLen = Math.min(text.length, 1024);
                for (let i = 0; i < sampleLen; i++) {
                    const c = text.charCodeAt(i);
                    if ((c < 0x20 && c !== 0x09 && c !== 0x0A && c !== 0x0D) || c === 0xFFFD) nonPrintable++;
                }
                if (nonPrintable / Math.max(sampleLen, 1) < 0.05) {
                    return truncate(text);
                }
            } catch (_) {}

            const hexLen = Math.min(64, len);
            const hex = Array.from(view.slice(0, hexLen))
                .map(b => b.toString(16).padStart(2, '0'))
                .join(' ');
            return `[${typeName} ${len}B] hex: ${hex}${len > hexLen ? '…' : ''}`;
        } catch (_) {
            return '[binary unreadable]';
        }
    };

    const serializeFormData = (fd) => {
        try {
            const parts = [];
            let count = 0;
            for (const [k, v] of fd.entries()) {
                if (count++ > 50) { parts.push('…[+more]'); break; }
                if (typeof v === 'string') parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(v));
                else if (v && v.name != null) parts.push(`${k}=[File ${v.name} ${v.size}B ${v.type || ''}]`);
                else parts.push(k + '=[?]');
            }
            return '[FormData] ' + truncate(parts.join('&'));
        } catch (_) { return '[FormData]'; }
    };

    const encodeBody = (body) => {
        if (body == null) return null;
        if (typeof body === 'string') return truncate(body);
        if (!body.constructor) return '[unknown]';
        const n = body.constructor.name;
        if (n === 'FormData') return serializeFormData(body);
        if (n === 'Blob') return `[Blob ${body.size}B type=${body.type || '?'}]`;
        if (n === 'URLSearchParams') return truncate(String(body));
        if (n === 'ArrayBuffer' || ArrayBuffer.isView(body)) return decodeBinary(body);
        if (n === 'ReadableStream') return '[ReadableStream]';
        if (n === 'Document') return truncate(new XMLSerializer().serializeToString(body));
        return '[' + n + ']';
    };

    const hostnameOf = (url) => {
        try { return new URL(url, location.href).hostname; }
        catch (_) { return url && url.startsWith && url.startsWith('ws') ? 'ws' : '(local)'; }
    };

    /* =========================================================
     * 🔐 SENSITIVE DETECTION
     * ========================================================= */
    const SENSITIVE_HEADERS = /^(authorization|cookie|set-cookie|x-auth|x-auth-token|x-api-key|x-csrf-token|x-xsrf-token|api-key|bearer|proxy-authorization|www-authenticate)$/i;
    const SENSITIVE_BODY_KEY = /\b(password|passwd|pwd|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|client[_-]?secret|jwt|bearer|ssn|credit[_-]?card|cvv|private[_-]?key)\b/i;

    const flagSensitive = (log) => {
        const flags = [];
        const scanHeaders = (obj, where) => {
            if (!obj) return;
            for (const k of Object.keys(obj)) {
                if (SENSITIVE_HEADERS.test(k)) flags.push(where + ':' + k.toLowerCase());
            }
        };
        scanHeaders(log.requestHeaders, 'req');
        scanHeaders(log.responseHeaders, 'res');

        const bodyMix = [log.requestBody, log.responseBody].filter(v => typeof v === 'string').join(' ');
        if (bodyMix && SENSITIVE_BODY_KEY.test(bodyMix)) flags.push('body');

        log.sensitive = flags.length > 0;
        log.sensitiveFlags = flags;
    };

    /* =========================================================
     * 📥 LOG PIPELINE
     * ========================================================= */
    const pushLog = (log) => {
        if (state.paused) return;

        try {
            if (log.url && !/^(https?|wss?|data|blob|file):/i.test(log.url)) {
                log.url = new URL(log.url, location.href).href;
            }
        } catch (_) {}

        log.hostname = hostnameOf(log.url);

        if (state.skipBody) {
            log.requestBody = log.requestBody ? '[skipped]' : null;
            log.responseBody = '[skipped]';
        }

        flagSensitive(log);

        state.store.push(log);

        if (state.store.length > CONFIG.MAX_LOGS) {
            const over = state.store.length - CONFIG.MAX_LOGS;
            let dropped = 0, i = 0;
            while (dropped < over && i < state.store.length) {
                if (state.store[i].id !== state.selectedId && state.store[i].id !== state.baselineId) {
                    state.store.splice(i, 1);
                    dropped++;
                } else {
                    i++;
                }
            }
        }

        scheduleRender();
    };

    /* =========================================================
     * 🪝 XHR HOOK
     * ========================================================= */
    const xhrLogMap = new WeakMap();

    const installXHRHook = () => {
        const OrigXHR = W.XMLHttpRequest;
        if (!OrigXHR || !OrigXHR.prototype) throw new Error('No XHR in unsafeWindow');

        const proto = OrigXHR.prototype;
        const origOpen = proto.open;
        const origSend = proto.send;
        const origSetHeader = proto.setRequestHeader;

        const newOpen = exportFn(function (method, url) {
            try {
                xhrLogMap.set(this, {
                    id: uid(), type: 'xhr',
                    method: (method || 'GET').toUpperCase(),
                    url: String(url), requestHeaders: {},
                    time: new Date().toISOString(),
                    startedAt: Date.now()
                });
            } catch (_) {}
            return origOpen.apply(this, arguments);
        });

        const newSetHeader = exportFn(function (k, v) {
            try {
                const log = xhrLogMap.get(this);
                if (log) log.requestHeaders[k] = String(v);
            } catch (_) {}
            return origSetHeader.apply(this, arguments);
        });

        const newSend = exportFn(function (body) {
            try {
                const log = xhrLogMap.get(this);
                if (log) {
                    log.requestBody = encodeBody(body);

                    const xhr = this;
                    xhr.addEventListener('loadend', exportFn(function () {
                        try {
                            log.status = xhr.status;
                            log.statusText = xhr.statusText;
                            log.duration = Date.now() - log.startedAt;
                            try { log.responseHeaders = parseHeaders(xhr.getAllResponseHeaders()); } catch (_) { log.responseHeaders = {}; }
                            try {
                                if (xhr.responseType === '' || xhr.responseType === 'text') {
                                    log.responseBody = truncate(xhr.responseText || '');
                                } else if (xhr.responseType === 'json') {
                                    log.responseBody = truncate(JSON.stringify(xhr.response));
                                } else {
                                    log.responseBody = '[' + (xhr.responseType || 'binary') + ']';
                                }
                            } catch (_) { log.responseBody = '[unreadable]'; }
                            pushLog(log);
                        } catch (_) {}
                    }));
                }
            } catch (_) {}
            return origSend.apply(this, arguments);
        });

        try {
            proto.open = newOpen;
            proto.setRequestHeader = newSetHeader;
            proto.send = newSend;
        } catch (_) {
            Object.defineProperty(proto, 'open', { value: newOpen, writable: true, configurable: true });
            Object.defineProperty(proto, 'setRequestHeader', { value: newSetHeader, writable: true, configurable: true });
            Object.defineProperty(proto, 'send', { value: newSend, writable: true, configurable: true });
        }
        return true;
    };

    /* =========================================================
     * 🪝 FETCH HOOK
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
                const isReq = (typeof Request !== 'undefined') && (input instanceof Request);
                log.url = isReq ? input.url : String(input);
                log.method = ((init && init.method) || (isReq && input.method) || 'GET').toUpperCase();

                const hdrs = (init && init.headers) || (isReq && input.headers);
                if (hdrs) {
                    if (typeof hdrs.forEach === 'function') {
                        hdrs.forEach(exportFn(function (v, k) { log.requestHeaders[k] = String(v); }));
                    } else if (typeof hdrs === 'object') {
                        try { Object.keys(hdrs).forEach(k => log.requestHeaders[k] = String(hdrs[k])); } catch (_) {}
                    }
                }

                if (init && init.body != null) {
                    log.requestBody = encodeBody(init.body);
                }
            } catch (_) {}

            const promise = origFetch.apply(this, arguments);

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
     * 🪝 WEBSOCKET HOOK
     * ========================================================= */
    const wsLogMap = new WeakMap();

    const installWSHook = () => {
        const OrigWS = W.WebSocket;
        if (!OrigWS) return false;

        const proto = OrigWS.prototype;
        const origSend = proto.send;

        const newSend = exportFn(function (data) {
            try {
                let log = wsLogMap.get(this);
                if (!log) {
                    log = createWSLog(this.url || '(unknown)');
                    wsLogMap.set(this, log);
                    state.store.push(log);
                }
                pushWSFrame(log, 'out', data);
                scheduleRender();
            } catch (_) {}
            return origSend.apply(this, arguments);
        });

        try { proto.send = newSend; }
        catch (_) { Object.defineProperty(proto, 'send', { value: newSend, writable: true, configurable: true }); }

        function HookedWS(url, protocols) {
            const ws = protocols !== undefined ? new OrigWS(url, protocols) : new OrigWS(url);

            let log = createWSLog(String(url));
            wsLogMap.set(ws, log);
            state.store.push(log);
            flagSensitive(log);
            scheduleRender();

            ws.addEventListener('open', exportFn(function () {
                log.status = 101;
                log.statusText = 'Switching Protocols';
                scheduleRender();
            }));

            ws.addEventListener('message', exportFn(function (e) {
                try { pushWSFrame(log, 'in', e.data); scheduleRender(); } catch (_) {}
            }));

            ws.addEventListener('close', exportFn(function (e) {
                log.closed = true;
                log.closeCode = e.code;
                log.closeReason = e.reason;
                log.duration = Date.now() - log.startedAt;
                scheduleRender();
            }));

            ws.addEventListener('error', exportFn(function () {
                log.error = 'WebSocket error';
                scheduleRender();
            }));

            return ws;
        }

        HookedWS.prototype = OrigWS.prototype;
        try {
            ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'].forEach(k => {
                if (k in OrigWS) HookedWS[k] = OrigWS[k];
            });
        } catch (_) {}

        const wrappedCtor = isFirefox ? exportFn(HookedWS) : HookedWS;
        try { wrappedCtor.prototype = OrigWS.prototype; } catch (_) {}
        try {
            ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'].forEach(k => {
                if (k in OrigWS) wrappedCtor[k] = OrigWS[k];
            });
        } catch (_) {}

        try { W.WebSocket = wrappedCtor; }
        catch (_) { Object.defineProperty(W, 'WebSocket', { value: wrappedCtor, writable: true, configurable: true }); }

        return true;
    };

    const createWSLog = (url) => ({
        id: uid(), type: 'ws',
        method: 'WS',
        url: String(url),
        requestHeaders: {}, responseHeaders: {},
        time: new Date().toISOString(),
        startedAt: Date.now(),
        frames: []
    });

    const pushWSFrame = (log, dir, data) => {
        if (state.paused) return;
        if (log.frames.length >= CONFIG.WS_MAX_FRAMES) log.frames.shift();
        let preview;
        try {
            if (data == null) preview = '';
            else if (typeof data === 'string') preview = truncate(data, CONFIG.WS_FRAME_BYTES);
            else if (data.byteLength != null) preview = '[binary ' + data.byteLength + 'B]';
            else preview = String(data);
        } catch (_) { preview = '[unreadable]'; }
        log.frames.push({ dir, time: Date.now(), data: preview });
    };

    /* =========================================================
     * 🎬 INSTALL ALL HOOKS
     * ========================================================= */
    (function installAll() {
        try {
            installXHRHook();
            installFetchHook();
            installWSHook();
            state.hookOK = true;
            state.hookActivatedAt = Date.now();
            state.hookMethod = isFirefox ? 'unsafeWindow+exportFunction (FF)' : 'unsafeWindow direct';
            console.log('[XHR Logger] Hooks installed via', state.hookMethod);
        } catch (e) {
            state.hookError = String(e);
            console.error('[XHR Logger] Hook install failed:', e);
        }
    })();

    /* =========================================================
     * 👁 SAFETY NET: PerformanceObserver
     * ========================================================= */
    (function installPerformanceObserver() {
        if (typeof PerformanceObserver === 'undefined') return;
        try {
            const po = new PerformanceObserver((list) => {
                for (const entry of list.getEntries()) {
                    if (entry.initiatorType !== 'fetch' && entry.initiatorType !== 'xmlhttprequest') continue;

                    const absTime = performance.timeOrigin + entry.startTime;

                    if (state.hookActivatedAt && absTime >= state.hookActivatedAt - 50) continue;

                    let url;
                    try { url = new URL(entry.name, location.href).href; } catch (_) { url = entry.name; }

                    const dup = state.store.some(l =>
                        l.url === url && Math.abs(l.startedAt - absTime) < 200
                    );
                    if (dup) continue;

                    const log = {
                        id: uid(),
                        type: entry.initiatorType === 'fetch' ? 'fetch' : 'xhr',
                        method: '?',
                        url,
                        requestHeaders: {},
                        responseHeaders: {},
                        requestBody: null,
                        responseBody: '[captured via PerformanceObserver — fired before hook installed. Headers/body unavailable. Reload page if you need full capture.]',
                        time: new Date(absTime).toISOString(),
                        startedAt: absTime,
                        duration: Math.round(entry.duration || 0),
                        status: entry.responseStatus || 0,
                        statusText: '',
                        _observed: true
                    };
                    pushLog(log);
                }
            });
            po.observe({ type: 'resource', buffered: true });
        } catch (e) {
            console.warn('[XHR Logger] PerformanceObserver setup failed:', e);
        }
    })();

    /* =========================================================
     * 🔁 REPLAY ENGINE
     * ========================================================= */
    const replay = (log) => {
        if (!log) throw new Error('replay: no log given');
        if (log.type === 'ws') throw new Error('replay: WebSocket replay not supported');

        const headers = {};
        const FORBIDDEN = /^(host|content-length|connection|accept-encoding|cookie|origin|referer|user-agent|sec-|proxy-|transfer-encoding|te|upgrade|keep-alive|expect|trailer)/i;
        for (const [k, v] of Object.entries(log.requestHeaders || {})) {
            if (!FORBIDDEN.test(k)) headers[k] = v;
        }

        const opts = {
            method: log.method,
            headers,
            credentials: 'include',
            mode: 'cors',
        };
        if (!['GET', 'HEAD'].includes(log.method) && log.requestBody && typeof log.requestBody === 'string' && !log.requestBody.startsWith('[')) {
            opts.body = log.requestBody;
        }

        return fetch(log.url, opts).then(async res => {
            const text = await res.text();
            return {
                status: res.status,
                statusText: res.statusText,
                headers: Object.fromEntries(res.headers.entries()),
                body: text
            };
        });
    };

    /* =========================================================
     * 🔬 DIFF ENGINE
     * ========================================================= */
    const safeParse = (s) => {
        if (typeof s !== 'string') return s;
        try { return JSON.parse(s); } catch (_) { return s; }
    };

    const diffValues = (a, b, path, acc) => {
        if (a === b) return;
        if (typeof a !== typeof b) { acc.push({ path, type: 'type', from: a, to: b }); return; }
        if (a === null || b === null || typeof a !== 'object') {
            acc.push({ path, type: 'value', from: a, to: b });
            return;
        }
        if (Array.isArray(a) && Array.isArray(b)) {
            const n = Math.max(a.length, b.length);
            for (let i = 0; i < n; i++) {
                const p = path + '[' + i + ']';
                if (i >= a.length) acc.push({ path: p, type: 'added', to: b[i] });
                else if (i >= b.length) acc.push({ path: p, type: 'removed', from: a[i] });
                else diffValues(a[i], b[i], p, acc);
            }
            return;
        }
        const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
        for (const k of keys) {
            const p = path ? path + '.' + k : k;
            if (!(k in a)) acc.push({ path: p, type: 'added', to: b[k] });
            else if (!(k in b)) acc.push({ path: p, type: 'removed', from: a[k] });
            else diffValues(a[k], b[k], p, acc);
        }
    };

    const diff = (a, b) => {
        if (typeof a === 'string') a = state.store.find(l => l.id === a);
        if (typeof b === 'string') b = state.store.find(l => l.id === b);
        if (!a || !b) throw new Error('diff: log(s) not found');
        const acc = [];
        diffValues(safeParse(a.responseBody), safeParse(b.responseBody), '', acc);
        return acc;
    };

    /* =========================================================
     * 🎛 AUTO-CLEAR
     * ========================================================= */
    const setAutoClear = (ms) => {
        CONFIG.AUTO_CLEAR_MS = ms;
        if (state.autoClearTimer) { clearInterval(state.autoClearTimer); state.autoClearTimer = null; }
        state.autoClearNext = 0;
        if (ms > 0) {
            state.autoClearNext = Date.now() + ms;
            state.autoClearTimer = setInterval(() => {
                state.store = state.store.filter(l =>
                    l.id === state.selectedId ||
                    l.id === state.baselineId
                );
                state.autoClearNext = Date.now() + ms;
                scheduleRender();
            }, ms);
        }
    };

    /* =========================================================
     * 🌐 PUBLIC API
     * ========================================================= */
    const api = {
        pause: () => { state.paused = true; updateStatusUI(); },
        resume: () => { state.paused = false; updateStatusUI(); },
        clear: () => { state.store.length = 0; state.selectedId = null; state.baselineId = null; scheduleRender(); },
        logs: () => state.store.slice(),
        replay,
        diff,
        setSkipBody: (v) => { state.skipBody = !!v; },
        setMaxLogs: (n) => { CONFIG.MAX_LOGS = n; },
        setAutoClear,
        config: CONFIG,
        state: () => ({ ...state, store: undefined })
    };

    try {
        if (isFirefox) W.__XHR_LOGGER__ = cloneInto(api, W, { cloneFunctions: true });
        else W.__XHR_LOGGER__ = api;
    } catch (e) { console.warn('[XHR Logger] Cannot expose global:', e); }
    window.__XHR_LOGGER__ = api;

    /* =========================================================
     * 🎨 SHADOW DOM UI
     * ========================================================= */
    const CSS = `
        :host { all: initial !important; }
        * { box-sizing: border-box; font-family: ui-monospace, Menlo, Consolas, monospace; }

        #fab {
            position: fixed; z-index: 2147483646; bottom: 20px; right: 20px;
            width: 48px; height: 48px; border-radius: 50%;
            background: linear-gradient(135deg,#6366f1,#8b5cf6); color: #fff;
            display: flex; align-items: center; justify-content: center;
            cursor: pointer; box-shadow: 0 6px 20px rgba(99,102,241,.5);
            font-weight: 700; font-size: 18px; user-select: none;
            transition: transform .2s; pointer-events: auto;
        }
        #fab:hover { transform: scale(1.08); }
        #fab.paused { background: linear-gradient(135deg,#ef4444,#f97316); }
        #fab .badge {
            position: absolute; top: -4px; right: -4px; background: #ef4444;
            color: #fff; font-size: 11px; padding: 2px 6px; border-radius: 10px;
            min-width: 20px; text-align: center; font-weight: 700;
        }
        #panel {
            position: fixed; z-index: 2147483647;
            width: 850px; max-width: 95vw; height: 560px; max-height: 85vh;
            background: #0f172a; color: #e2e8f0;
            border: 1px solid #334155; border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,.6);
            display: none; flex-direction: column; overflow: hidden;
            min-width: 500px; min-height: 300px; pointer-events: auto;
        }
        #panel.open { display: flex; }
        .header {
            display: flex; align-items: center; gap: 6px; padding: 8px 10px;
            background: #1e293b; border-bottom: 1px solid #334155; flex-wrap: wrap;
            cursor: move; user-select: none;
        }
        .header .title { font-weight: 700; color: #a5b4fc; flex: 1; font-size: 12px; }
        .header .title .ver { color: #64748b; font-weight: 400; font-size: 10px; margin-left: 4px; }
        .header input, .header button { cursor: auto; }
        .btn {
            background: #334155; color: #e2e8f0; border: none; padding: 4px 8px;
            border-radius: 5px; font-size: 11px; cursor: pointer; font-family: inherit;
            white-space: nowrap;
        }
        .btn:hover { background: #475569; }
        .btn.active { background: #6366f1; }
        .btn.danger { background: #7f1d1d; }
        .btn.danger:hover { background: #991b1b; }
        .btn.warn { background: #92400e; }
        .btn.warn:hover { background: #b45309; }
        .search {
            padding: 5px 8px; background: #0f172a; border: 1px solid #334155;
            color: #e2e8f0; border-radius: 5px; font-size: 11px; width: 140px;
            font-family: inherit;
        }
        .body { display: flex; flex: 1; overflow: hidden; }
        .list { width: 42%; overflow-y: auto; border-right: 1px solid #334155; }
        .group-hdr {
            padding: 4px 10px; background: #1e293b; color: #94a3b8;
            font-size: 10px; font-weight: 700; position: sticky; top: 0; z-index: 2;
            border-bottom: 1px solid #0f172a;
        }
        .item {
            padding: 6px 10px; border-bottom: 1px solid #1e293b; cursor: pointer;
            font-size: 11px; display: flex; gap: 5px; align-items: center;
        }
        .item:hover { background: #1e293b; }
        .item.active { background: #312e81; }
        .item.baseline { border-left: 3px solid #fbbf24; padding-left: 7px; }
        .method {
            padding: 1px 5px; border-radius: 3px; font-weight: 700; font-size: 9px;
            min-width: 40px; text-align: center;
        }
        .m-GET { background: #065f46; color: #6ee7b7; }
        .m-POST { background: #1e40af; color: #93c5fd; }
        .m-PUT { background: #92400e; color: #fcd34d; }
        .m-DELETE { background: #991b1b; color: #fca5a5; }
        .m-PATCH { background: #5b21b6; color: #c4b5fd; }
        .m-WS { background: #134e4a; color: #5eead4; }
        .url { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .status { font-weight: 700; font-size: 10px; min-width: 28px; }
        .s-2 { color: #6ee7b7; } .s-3 { color: #fcd34d; }
        .s-4 { color: #fca5a5; } .s-5 { color: #f87171; } .s-0 { color: #94a3b8; }
        .flag { font-size: 10px; }
        .detail {
            flex: 1; overflow-y: auto; padding: 10px; font-size: 11px;
            background: #020617;
        }
        .detail h4 { color: #a5b4fc; margin: 8px 0 4px; font-size: 12px; display: flex; align-items: center; gap: 6px; }
        .detail pre {
            background: #0f172a; padding: 8px; border-radius: 6px;
            overflow-x: auto; white-space: pre-wrap; word-break: break-all;
            border: 1px solid #1e293b; margin: 0; color: #cbd5e1; max-height: 300px;
        }
        .detail .row { display: flex; gap: 6px; margin-bottom: 4px; word-break: break-all; align-items: baseline; flex-wrap: wrap; }
        .actions { display: flex; gap: 5px; flex-wrap: wrap; margin: 8px 0; }
        .empty { padding: 20px; text-align: center; color: #64748b; font-size: 12px; }
        .toast {
            position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%);
            background: #10b981; color: #fff; padding: 8px 16px; border-radius: 6px;
            font-size: 12px; z-index: 2147483647; pointer-events: auto;
        }
        .diag { font-size: 10px; color: #94a3b8; padding: 5px 10px; background: #0b1120; border-top: 1px solid #1e293b; display: flex; justify-content: space-between; gap: 8px; }
        .diag.err { color: #fca5a5; }
        .sensitive-tag { background: #7f1d1d; color: #fecaca; padding: 1px 5px; border-radius: 3px; font-size: 9px; font-weight: 700; }
        .frame { padding: 4px 8px; margin: 2px 0; border-radius: 4px; font-size: 11px; white-space: pre-wrap; word-break: break-all; border-left: 3px solid; }
        .frame.in { background: #0c2e1a; border-color: #10b981; }
        .frame.out { background: #1e1b4b; border-color: #6366f1; }
        .frame .t { color: #64748b; font-size: 10px; margin-right: 6px; }
        .resize {
            position: absolute; right: 0; bottom: 0; width: 14px; height: 14px;
            cursor: nwse-resize; background: linear-gradient(135deg, transparent 50%, #475569 50%);
        }
        .diff-added { color: #6ee7b7; }
        .diff-removed { color: #fca5a5; text-decoration: line-through; }
        .diff-changed { color: #fcd34d; }
    `;

    /* === CREATE SHADOW HOST === */
    const host = document.createElement('div');
    host.id = '__xhr_logger_host__';
    // Host itself is invisible 0x0; children are position:fixed so they show in viewport
    // pointer-events:none on host so it doesn't block clicks on page beneath
    host.style.cssText = 'all:initial;position:fixed;top:0;left:0;width:0;height:0;z-index:2147483647;pointer-events:none;';
    const shadow = host.attachShadow({ mode: 'open' });

    // Helper: query within shadow
    const $ = (id) => shadow.getElementById(id);

    // Style
    const styleEl = document.createElement('style');
    styleEl.textContent = CSS;
    shadow.appendChild(styleEl);

    // FAB
    const fab = document.createElement('div');
    fab.id = 'fab';
    fab.innerHTML = '🕸<span class="badge" style="display:none">0</span>';
    shadow.appendChild(fab);

    // Panel
    const panel = document.createElement('div');
    panel.id = 'panel';
    panel.innerHTML = `
        <div class="header" id="drag-handle">
            <span class="title">🕸 XHR Logger<span class="ver">v2.1</span></span>
            <input class="search" id="search" placeholder="filter..." />
            <button class="btn" id="pause" title="Pause/Resume">⏸️</button>
            <button class="btn" id="skipbody" title="Skip body">Skip Body</button>
            <button class="btn" id="group" title="Group by domain">Group</button>
            <button class="btn" id="autoclean" title="Auto-clear every 60s">Auto Clean</button>
            <button class="btn" id="export-json">⬇️JSON</button>
            <button class="btn" id="export-curl">⬇️cURL</button>
            <button class="btn" id="export-text">⬇️TEXT</button>
            <button class="btn warn" id="clear-btn">🧹Clear</button>
            <button class="btn danger" id="close-btn">✕</button>
        </div>
        <div class="body">
            <div class="list" id="list"><div class="empty">No requests yet…</div></div>
            <div class="detail" id="detail"><div class="empty">Select a request</div></div>
        </div>
        <div class="diag" id="diag"></div>
        <div class="resize" id="resize"></div>
    `;
    shadow.appendChild(panel);

    function applyPersistedGeometry() {
        if (state.panelPos) {
            panel.style.left = state.panelPos.left + 'px';
            panel.style.top = state.panelPos.top + 'px';
            panel.style.right = 'auto'; panel.style.bottom = 'auto';
        } else {
            panel.style.right = '20px'; panel.style.bottom = '80px';
        }
        if (state.panelSize) {
            panel.style.width = state.panelSize.width + 'px';
            panel.style.height = state.panelSize.height + 'px';
        }
    }

    function mount() {
        if (document.getElementById('__xhr_logger_host__')) return;
        (document.body || document.documentElement).appendChild(host);
        applyPersistedGeometry();
        wireEvents();
    }

    if (document.body) mount();
    else {
        document.addEventListener('DOMContentLoaded', mount);
        const iv = setInterval(() => { if (document.body) { mount(); clearInterval(iv); } }, 100);
    }

    /* =========================================================
     * 🎯 DRAG + RESIZE + EVENT WIRING
     * ========================================================= */
    let eventsWired = false;
    function wireEvents() {
        if (eventsWired) return;
        eventsWired = true;

        // Click delegation - listen on shadow so e.target is the actual inner element
        shadow.addEventListener('click', (e) => {
            const t = e.target;
            if (!t) return;

            // FAB toggles panel
            if (t === fab || fab.contains(t)) {
                panel.classList.toggle('open');
                renderList(); renderDetail(); updateDiag();
                return;
            }

            if (!t.id) return;
            switch (t.id) {
                case 'close-btn': panel.classList.remove('open'); break;
                case 'clear-btn':
                    state.store.length = 0; state.selectedId = null; state.baselineId = null;
                    updateBadge(); renderList(); renderDetail(); updateDiag();
                    break;
                case 'pause':
                    state.paused ? api.resume() : api.pause();
                    updateStatusUI(); renderList(); updateDiag();
                    break;
                case 'skipbody':
                    state.skipBody = !state.skipBody;
                    updateStatusUI(); updateDiag();
                    toast('Skip body: ' + (state.skipBody ? 'ON' : 'OFF'));
                    break;
                case 'group':
                    state.groupByDomain = !state.groupByDomain;
                    updateStatusUI(); renderList();
                    break;
                case 'autoclean': {
                    const newMs = CONFIG.AUTO_CLEAR_MS > 0 ? 0 : 60000;
                    setAutoClear(newMs);
                    updateStatusUI(); updateDiag();
                    toast(newMs ? '🧹 Auto-clean ON (60s)' : '🧹 Auto-clean OFF');
                    break;
                }
                case 'export-json': download('xhr-log.json', JSON.stringify(state.store, null, 2), 'application/json'); break;
                case 'export-curl': download('xhr-log.sh', state.store.map(toCurl).join('\n\n'), 'text/plain'); break;
                case 'export-text': download('xhr-log.txt', state.store.map(toText).join('\n\n'), 'text/plain'); break;
            }
        });

        shadow.addEventListener('input', (e) => {
            if (e.target && e.target.id === 'search') {
                state.filter = e.target.value.toLowerCase();
                renderList();
            }
        });

        // Drag
        const handle = $('drag-handle');
        if (handle) {
            handle.addEventListener('mousedown', (e) => {
                if (e.target.closest('button,input')) return;
                const sx = e.clientX, sy = e.clientY;
                const r = panel.getBoundingClientRect();
                const ix = r.left, iy = r.top;
                e.preventDefault();
                const move = (ev) => {
                    let nx = ix + ev.clientX - sx;
                    let ny = iy + ev.clientY - sy;
                    nx = Math.max(0, Math.min(window.innerWidth - 50, nx));
                    ny = Math.max(0, Math.min(window.innerHeight - 30, ny));
                    panel.style.left = nx + 'px';
                    panel.style.top = ny + 'px';
                    panel.style.right = 'auto'; panel.style.bottom = 'auto';
                };
                const up = () => {
                    document.removeEventListener('mousemove', move);
                    document.removeEventListener('mouseup', up);
                    const r2 = panel.getBoundingClientRect();
                    state.panelPos = { left: r2.left, top: r2.top };
                    try { GM_setValue('panelPos', JSON.stringify(state.panelPos)); } catch (_) {}
                };
                document.addEventListener('mousemove', move);
                document.addEventListener('mouseup', up);
            });
        }

        // Resize
        const resize = $('resize');
        if (resize) {
            resize.addEventListener('mousedown', (e) => {
                const sx = e.clientX, sy = e.clientY;
                const r = panel.getBoundingClientRect();
                const iw = r.width, ih = r.height;
                e.preventDefault(); e.stopPropagation();
                const move = (ev) => {
                    panel.style.width = Math.max(500, iw + ev.clientX - sx) + 'px';
                    panel.style.height = Math.max(300, ih + ev.clientY - sy) + 'px';
                };
                const up = () => {
                    document.removeEventListener('mousemove', move);
                    document.removeEventListener('mouseup', up);
                    const r2 = panel.getBoundingClientRect();
                    state.panelSize = { width: r2.width, height: r2.height };
                    try { GM_setValue('panelSize', JSON.stringify(state.panelSize)); } catch (_) {}
                };
                document.addEventListener('mousemove', move);
                document.addEventListener('mouseup', up);
            });
        }
    }

    /* =========================================================
     * 🖼 RENDER
     * ========================================================= */
    let renderPending = false;

    function scheduleRender() {
        if (renderPending) return;
        renderPending = true;
        requestAnimationFrame(() => {
            renderPending = false;
            updateBadge();
            updateStatusUI();
            if (panel.classList.contains('open')) renderList();
        });
    }

    function updateBadge() {
        const badge = fab.querySelector('.badge');
        if (!badge) return;
        badge.style.display = state.store.length ? 'inline-block' : 'none';
        badge.textContent = state.store.length;
    }

    function updateStatusUI() {
        fab.classList.toggle('paused', state.paused);
        const pauseBtn = $('pause');
        if (pauseBtn) { pauseBtn.textContent = state.paused ? '▶️' : '⏸️'; pauseBtn.classList.toggle('active', state.paused); }
        const skipBtn = $('skipbody');
        if (skipBtn) skipBtn.classList.toggle('active', state.skipBody);
        const grpBtn = $('group');
        if (grpBtn) grpBtn.classList.toggle('active', state.groupByDomain);
        const autoBtn = $('autoclean');
        if (autoBtn) {
            const on = CONFIG.AUTO_CLEAR_MS > 0;
            autoBtn.classList.toggle('active', on);
            autoBtn.textContent = on ? '✓ Auto Clean' : 'Auto Clean';
        }
    }

    function toast(msg, color) {
        const t = document.createElement('div');
        t.className = 'toast';
        if (color) t.style.background = color;
        t.textContent = msg;
        shadow.appendChild(t);
        setTimeout(() => t.remove(), 1600);
    }

    const toCurl = (log) => {
        if (log.type === 'ws') return `# WebSocket: ${log.url}`;
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
        s += `Time: ${log.time}  |  Status: ${log.status || '-'} ${log.statusText || ''}  |  ${log.duration || 0}ms  |  ${log.type}`;
        if (log.sensitive) s += `  |  ⚠ SENSITIVE(${log.sensitiveFlags.join(',')})`;
        s += '\n\n--- Request Headers ---\n';
        Object.entries(log.requestHeaders || {}).forEach(([k, v]) => s += `${k}: ${v}\n`);
        if (log.requestBody) s += `\n--- Request Body ---\n${log.requestBody}\n`;
        s += `\n--- Response Headers ---\n`;
        Object.entries(log.responseHeaders || {}).forEach(([k, v]) => s += `${k}: ${v}\n`);
        if (log.type === 'ws') {
            s += `\n--- WS Frames (${(log.frames || []).length}) ---\n`;
            (log.frames || []).forEach(f => s += `[${new Date(f.time).toISOString()}] ${f.dir === 'in' ? '<' : '>'} ${f.data}\n`);
        } else {
            s += `\n--- Response Body ---\n${log.responseBody || ''}\n`;
        }
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
        try { navigator.clipboard.writeText(txt).then(() => toast('Copied!')); } catch (_) { toast('Copy failed', '#ef4444'); }
    };

    const esc = (s) => String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    const filtered = () => !state.filter ? state.store : state.store.filter(l => l.url.toLowerCase().includes(state.filter));

    function renderList() {
        const listEl = $('list');
        if (!listEl) return;
        const logs = filtered();

        if (!logs.length) {
            let msg;
            if (!state.hookOK && state.hookError) msg = `⚠ Hook failed: ${state.hookError}`;
            else if (!state.hookOK) msg = `Installing hook…`;
            else if (state.paused) msg = '⏸ Paused. Click ▶ to resume.';
            else msg = 'Hook active. Waiting for requests…';
            listEl.innerHTML = '<div class="empty">' + esc(msg) + '</div>';
            return;
        }

        const reversed = logs.slice(-CONFIG.RENDER_CAP).reverse();

        let html = '';
        if (state.groupByDomain) {
            const groups = {};
            for (const l of reversed) {
                (groups[l.hostname] = groups[l.hostname] || []).push(l);
            }
            for (const host of Object.keys(groups)) {
                html += `<div class="group-hdr">${esc(host)} · ${groups[host].length}</div>`;
                html += groups[host].map(itemHTML).join('');
            }
        } else {
            html = reversed.map(itemHTML).join('');
        }

        listEl.innerHTML = html;
        listEl.querySelectorAll('.item').forEach(el => {
            el.addEventListener('click', () => {
                state.selectedId = el.dataset.id;
                renderList(); renderDetail();
            });
        });
    }

    const itemHTML = (l) => {
        const sClass = 's-' + String(l.status || 0).charAt(0);
        const baseline = l.id === state.baselineId ? ' baseline' : '';
        const active = l.id === state.selectedId ? ' active' : '';
        const flag = l.sensitive ? '<span class="flag" title="Sensitive">🔒</span>' : '';
        const observed = l._observed ? '<span class="flag" title="Captured via PerformanceObserver - fired before hook installed">👁</span>' : '';
        const wsInfo = l.type === 'ws' ? ` · ${(l.frames || []).length}f` : '';

        let displayUrl = l.url;
        if (state.groupByDomain && l.hostname && l.hostname !== '(local)') {
            try {
                const u = new URL(l.url);
                displayUrl = (u.pathname || '/') + (u.search || '') + (u.hash || '');
            } catch (_) {}
        }

        return `<div class="item${active}${baseline}" data-id="${l.id}">
            <span class="method m-${l.method}">${l.method}</span>
            <span class="status ${sClass}">${l.status || '—'}</span>
            ${flag}${observed}
            <span class="url" title="${esc(l.url)}">${esc(displayUrl)}${wsInfo}</span>
        </div>`;
    };

    function renderDetail() {
        const detailEl = $('detail');
        if (!detailEl) return;
        const log = state.store.find(l => l.id === state.selectedId);
        if (!log) { detailEl.innerHTML = '<div class="empty">Select a request</div>'; return; }

        const sensitiveTag = log.sensitive ? `<span class="sensitive-tag" title="${esc(log.sensitiveFlags.join(', '))}">⚠ SENSITIVE</span>` : '';

        let frameHTML = '';
        if (log.type === 'ws') {
            frameHTML = `<h4>WS Frames (${(log.frames || []).length}${log.closed ? ' · closed ' + log.closeCode : ''})</h4>`;
            frameHTML += '<div>' + (log.frames || []).slice(-100).map(f =>
                `<div class="frame ${f.dir}"><span class="t">${new Date(f.time).toLocaleTimeString()}</span>${f.dir === 'in' ? '◀' : '▶'} ${esc(f.data)}</div>`
            ).join('') + '</div>';
        }

        const diffHTML = (state.baselineId && state.baselineId !== log.id)
            ? `<button class="btn warn" data-act="do-diff">🔬 Diff vs baseline</button>` : '';

        detailEl.innerHTML = `
            <div class="row"><b>${log.method}</b> <span>${esc(log.url)}</span> ${sensitiveTag}</div>
            <div class="row">Status: <b>${log.status || '-'} ${esc(log.statusText || '')}</b> · ${log.duration || 0}ms · ${log.type} · host: <b>${esc(log.hostname)}</b> · ${esc(log.time)}</div>
            <div class="actions">
                <button class="btn" data-act="copy-json">📋 JSON</button>
                <button class="btn" data-act="copy-curl">📋 cURL</button>
                <button class="btn" data-act="copy-text">📋 Text</button>
                <button class="btn" data-act="copy-body">📋 Response</button>
                ${log.type !== 'ws' ? '<button class="btn warn" data-act="replay">🔁 Replay</button>' : ''}
                <button class="btn" data-act="baseline">${log.id === state.baselineId ? '✓ Baseline' : '⭐ Set baseline'}</button>
                ${diffHTML}
            </div>
            <div id="diff-output"></div>
            <h4>Request Headers</h4>
            <pre>${esc(JSON.stringify(log.requestHeaders || {}, null, 2))}</pre>
            ${log.requestBody ? `<h4>Request Body</h4><pre>${esc(log.requestBody)}</pre>` : ''}
            <h4>Response Headers</h4>
            <pre>${esc(JSON.stringify(log.responseHeaders || {}, null, 2))}</pre>
            ${log.type === 'ws' ? frameHTML : `<h4>Response Body</h4><pre>${esc(log.responseBody || '')}</pre>`}
        `;

        detailEl.querySelectorAll('[data-act]').forEach(b => {
            b.addEventListener('click', () => handleDetailAction(b.dataset.act, log));
        });
    }

    const handleDetailAction = (act, log) => {
        switch (act) {
            case 'copy-json': copy(JSON.stringify(log, null, 2)); break;
            case 'copy-curl': copy(toCurl(log)); break;
            case 'copy-text': copy(toText(log)); break;
            case 'copy-body': copy(log.responseBody || ''); break;
            case 'replay':
                toast('Replaying…', '#6366f1');
                replay(log).then(r => {
                    toast(`Replay: ${r.status} ${r.statusText}`, r.status < 400 ? '#10b981' : '#ef4444');
                }).catch(e => toast('Replay failed: ' + e.message, '#ef4444'));
                break;
            case 'baseline':
                state.baselineId = (state.baselineId === log.id) ? null : log.id;
                toast(state.baselineId ? 'Baseline set' : 'Baseline cleared');
                renderList(); renderDetail();
                break;
            case 'do-diff': {
                const a = state.store.find(l => l.id === state.baselineId);
                if (!a) return toast('Baseline not found', '#ef4444');
                try {
                    const changes = diff(a, log);
                    const out = $('diff-output');
                    if (!changes.length) { out.innerHTML = '<pre style="color:#6ee7b7">✓ No differences</pre>'; return; }
                    const html = changes.slice(0, 100).map(c => {
                        if (c.type === 'added') return `<div class="diff-added">+ ${esc(c.path)}: ${esc(JSON.stringify(c.to))}</div>`;
                        if (c.type === 'removed') return `<div class="diff-removed">- ${esc(c.path)}: ${esc(JSON.stringify(c.from))}</div>`;
                        return `<div class="diff-changed">~ ${esc(c.path)}: ${esc(JSON.stringify(c.from))} → ${esc(JSON.stringify(c.to))}</div>`;
                    }).join('');
                    out.innerHTML = `<h4>Diff (${changes.length} change${changes.length !== 1 ? 's' : ''})</h4><pre>${html}</pre>`;
                } catch (e) { toast('Diff failed: ' + e.message, '#ef4444'); }
                break;
            }
        }
    };

    function updateDiag() {
        const diagEl = $('diag');
        if (!diagEl) return;

        let autoText = '';
        if (CONFIG.AUTO_CLEAR_MS > 0 && state.autoClearNext) {
            const remaining = Math.max(0, Math.ceil((state.autoClearNext - Date.now()) / 1000));
            const color = remaining < 10 ? '#f87171' : '#fcd34d';
            autoText = ` · 🧹<span style="color:${color}">AUTO sweep in ${remaining}s</span>`;
        }

        diagEl.innerHTML = `
            <span>TekMonts | ${isFirefox ? '🦊 Firefox' : '🌐 Chrome'} · ${state.hookMethod} · ${state.hookOK ? '✓' : '✗'} · ${state.store.length}/${CONFIG.MAX_LOGS} logs${state.paused ? ' · ⏸️ PAUSED' : ''}${state.skipBody ? ' · NO-BODY' : ''}${autoText}</span>
            <span>API: <code style="color:#a5b4fc">__XHR_LOGGER__</code></span>
        `;
        diagEl.className = state.hookOK ? 'diag' : 'diag err';
    }

    setInterval(updateDiag, 1000);
    setTimeout(() => { scheduleRender(); updateDiag(); }, 300);

    console.log(
        '%c[XHR Logger v2.1] %cShadow DOM isolated. API: %c__XHR_LOGGER__',
        'color:#a5b4fc;font-weight:700', 'color:#64748b', 'color:#6ee7b7;font-family:monospace'
    );
})();
