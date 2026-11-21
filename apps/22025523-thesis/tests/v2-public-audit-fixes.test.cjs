// Counterexample & regression tests for the 5 Codex-audited security & data-interpretation issues:
//   1 — Bearer token bound strictly to API origin (no cross-origin leakage, no default prod token)
//   2 — Scanner & liveScan must not infer 0 / NO_FINDINGS when both findings list and total are missing
//   3 — REFUTED (giữ OPEN) must count only findings that are BOTH validated_status=REFUTED AND human_review_state=OPEN
//   4 — History sync & HistoryPage must surface incomplete/mismatched lists (valid:false / COUNT_MISMATCH / truncated)
//       without marking supported:true or fabricating missing records
//   5 — Results scan picker & FindingDetail must fail-closed on missing/unverified/mock data_origin
//       (never default to REAL_SCAN)
//
// All tests run strictly offline via in-process fetch mocks (zero real network, zero real tokens).
const {test} = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const Module = require('node:module');

const APP_ROOT = path.join(__dirname, '..');

function mkStorage() {
  return {
    _map: new Map(),
    get length() { return this._map.size; },
    key(i) { return [...this._map.keys()][i] ?? null; },
    getItem(k) { return this._map.has(k) ? this._map.get(k) : null; },
    setItem(k, v) { this._map.set(k, String(v)); },
    removeItem(k) { this._map.delete(k); },
  };
}

function installMiniDom() {
  const prev = {
    window: global.window,
    document: global.document,
    Node: global.Node,
    Element: global.Element,
    HTMLElement: global.HTMLElement,
    HTMLInputElement: global.HTMLInputElement,
    HTMLIFrameElement: global.HTMLIFrameElement,
    HTMLTextAreaElement: global.HTMLTextAreaElement,
    HTMLSelectElement: global.HTMLSelectElement,
    HTMLFormElement: global.HTMLFormElement,
    HTMLButtonElement: global.HTMLButtonElement,
    ShadowRoot: global.ShadowRoot,
    SVGElement: global.SVGElement,
    Text: global.Text,
    Comment: global.Comment,
    Document: global.Document,
    Event: global.Event,
    CustomEvent: global.CustomEvent,
    requestAnimationFrame: global.requestAnimationFrame,
    cancelAnimationFrame: global.cancelAnimationFrame,
    MessageChannel: global.MessageChannel,
    IS_REACT_ACT_ENVIRONMENT: global.IS_REACT_ACT_ENVIRONMENT,
  };

  const NativeMessageChannel = global.MessageChannel;
  if (typeof NativeMessageChannel === 'function') {
    global.MessageChannel = class UnrefMessageChannel {
      constructor() {
        const ch = new NativeMessageChannel();
        const protoDesc = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(ch.port1), 'onmessage');
        if (protoDesc && protoDesc.set) {
          Object.defineProperty(ch.port1, 'onmessage', {
            configurable: true,
            get() { return protoDesc.get.call(ch.port1); },
            set(fn) {
              protoDesc.set.call(ch.port1, fn);
              ch.port1.unref?.();
              ch.port2.unref?.();
            },
          });
        }
        ch.port1?.unref?.();
        ch.port2?.unref?.();
        this.port1 = ch.port1;
        this.port2 = ch.port2;
      }
    };
  }

  class MiniEvent {
    constructor(type, init = {}) {
      this.type = String(type);
      this.bubbles = Boolean(init.bubbles);
      this.cancelable = Boolean(init.cancelable);
      this.defaultPrevented = false;
      this.cancelBubble = false;
      this.target = null;
      this.currentTarget = null;
      this.srcElement = null;
      this.eventPhase = 0;
      this.timeStamp = Date.now();
      this.detail = init.detail ?? null;
    }
    initEvent(type, bubbles = false, cancelable = false) {
      this.type = String(type);
      this.bubbles = Boolean(bubbles);
      this.cancelable = Boolean(cancelable);
    }
    preventDefault() { if (this.cancelable) this.defaultPrevented = true; }
    stopPropagation() { this.cancelBubble = true; }
    stopImmediatePropagation() { this.cancelBubble = true; }
  }

  class MiniNode {
    constructor(nodeType, nodeName, ownerDocument) {
      this.nodeType = nodeType;
      this.nodeName = nodeName;
      this.ownerDocument = ownerDocument;
      this.parentNode = null;
      this.childNodes = [];
      this._listeners = new Map();
    }
    get firstChild() { return this.childNodes[0] || null; }
    get lastChild() { return this.childNodes[this.childNodes.length - 1] || null; }
    get nextSibling() {
      if (!this.parentNode) return null;
      const idx = this.parentNode.childNodes.indexOf(this);
      return idx >= 0 && idx + 1 < this.parentNode.childNodes.length ? this.parentNode.childNodes[idx + 1] : null;
    }
    get previousSibling() {
      if (!this.parentNode) return null;
      const idx = this.parentNode.childNodes.indexOf(this);
      return idx > 0 ? this.parentNode.childNodes[idx - 1] : null;
    }
    get parentElement() { return this.parentNode && this.parentNode.nodeType === 1 ? this.parentNode : null; }
    appendChild(child) {
      if (child.nodeType === 11) {
        for (const c of [...child.childNodes]) this.appendChild(c);
        return child;
      }
      if (child.parentNode) child.parentNode.removeChild(child);
      child.parentNode = this;
      this.childNodes.push(child);
      return child;
    }
    insertBefore(child, before) {
      if (!before) return this.appendChild(child);
      if (child.nodeType === 11) {
        for (const c of [...child.childNodes]) this.insertBefore(c, before);
        return child;
      }
      if (child.parentNode) child.parentNode.removeChild(child);
      const idx = this.childNodes.indexOf(before);
      child.parentNode = this;
      if (idx === -1) this.childNodes.push(child);
      else this.childNodes.splice(idx, 0, child);
      return child;
    }
    removeChild(child) {
      const idx = this.childNodes.indexOf(child);
      if (idx >= 0) {
        this.childNodes.splice(idx, 1);
        child.parentNode = null;
      }
      return child;
    }
    contains(other) {
      let cur = other;
      while (cur) {
        if (cur === this) return true;
        cur = cur.parentNode;
      }
      return false;
    }
    getRootNode() {
      let cur = this;
      while (cur.parentNode) cur = cur.parentNode;
      return cur;
    }
    addEventListener(type, fn, options) {
      const capture = typeof options === 'boolean' ? options : Boolean(options?.capture);
      const key = `${type}:${capture ? 'c' : 'b'}`;
      if (!this._listeners.has(key)) this._listeners.set(key, []);
      const list = this._listeners.get(key);
      if (!list.includes(fn)) list.push(fn);
    }
    removeEventListener(type, fn, options) {
      const capture = typeof options === 'boolean' ? options : Boolean(options?.capture);
      const key = `${type}:${capture ? 'c' : 'b'}`;
      const list = this._listeners.get(key);
      if (!list) return;
      const idx = list.indexOf(fn);
      if (idx >= 0) list.splice(idx, 1);
    }
    dispatchEvent(event) {
      event.target = this;
      event.srcElement = this;
      const pathNodes = [];
      let cur = this;
      while (cur) {
        pathNodes.push(cur);
        cur = cur.parentNode;
      }
      if (this.ownerDocument && pathNodes[pathNodes.length - 1] !== this.ownerDocument) {
        pathNodes.push(this.ownerDocument);
      }
      const win = this.ownerDocument?.defaultView;
      if (win) pathNodes.push(win);
      for (let i = pathNodes.length - 1; i >= 0; i -= 1) {
        const node = pathNodes[i];
        event.currentTarget = node;
        const listeners = node._listeners?.get(`${event.type}:c`);
        if (listeners) for (const fn of [...listeners]) fn.call(node, event);
        if (event.cancelBubble) return !event.defaultPrevented;
      }
      for (let i = 0; i < pathNodes.length; i += 1) {
        if (i > 0 && !event.bubbles) break;
        const node = pathNodes[i];
        event.currentTarget = node;
        const listeners = node._listeners?.get(`${event.type}:b`);
        if (listeners) for (const fn of [...listeners]) fn.call(node, event);
        if (event.cancelBubble) break;
      }
      return !event.defaultPrevented;
    }
    get textContent() {
      if (this.nodeType === 3 || this.nodeType === 8) return this._data || '';
      return this.childNodes.map((c) => c.textContent).join('');
    }
    set textContent(val) {
      const str = val === null || val === undefined ? '' : String(val);
      if (this.nodeType === 3 || this.nodeType === 8) {
        this._data = str;
        return;
      }
      for (const c of [...this.childNodes]) this.removeChild(c);
      if (str) this.appendChild(this.ownerDocument.createTextNode(str));
    }
  }

  class MiniText extends MiniNode {
    constructor(data, ownerDocument) {
      super(3, '#text', ownerDocument);
      this._data = String(data ?? '');
    }
    get nodeValue() { return this._data; }
    set nodeValue(v) { this._data = String(v ?? ''); }
    get data() { return this._data; }
    set data(v) { this._data = String(v ?? ''); }
  }

  class MiniComment extends MiniNode {
    constructor(data, ownerDocument) {
      super(8, '#comment', ownerDocument);
      this._data = String(data ?? '');
    }
    get nodeValue() { return this._data; }
    set nodeValue(v) { this._data = String(v ?? ''); }
    get data() { return this._data; }
    set data(v) { this._data = String(v ?? ''); }
  }

  class MiniFragment extends MiniNode {
    constructor(ownerDocument) { super(11, '#document-fragment', ownerDocument); }
  }

  class MiniElement extends MiniNode {
    constructor(tagName, ownerDocument, namespaceURI = 'http://www.w3.org/1999/xhtml') {
      const normalized = namespaceURI === 'http://www.w3.org/1999/xhtml' ? String(tagName).toUpperCase() : String(tagName);
      super(1, normalized, ownerDocument);
      this.tagName = normalized;
      this.namespaceURI = namespaceURI;
      this._attrs = new Map();
      this._value = '';
      this._checked = false;
      this.selected = false;
      this.defaultSelected = false;
      this.files = [];
      this.style = {
        setProperty(k, v) { this[k] = v; },
        removeProperty(k) { delete this[k]; },
      };
    }
    get options() { return this.querySelectorAll('option'); }
    get value() { return this._value; }
    set value(v) { this._value = v === null || v === undefined ? '' : String(v); }
    get defaultValue() { return this._attrs.get('value') || ''; }
    set defaultValue(v) { this._attrs.set('value', String(v ?? '')); }
    get checked() { return this._checked; }
    set checked(v) { this._checked = Boolean(v); }
    get disabled() { return this._attrs.has('disabled'); }
    set disabled(v) { if (v) this._attrs.set('disabled', ''); else this._attrs.delete('disabled'); }
    get id() { return this._attrs.get('id') || ''; }
    set id(v) { this._attrs.set('id', String(v ?? '')); }
    get type() { return this._attrs.get('type') || ''; }
    set type(v) { this._attrs.set('type', String(v ?? '')); }
    get name() { return this._attrs.get('name') || ''; }
    set name(v) { this._attrs.set('name', String(v ?? '')); }
    get className() { return this._attrs.get('class') || ''; }
    set className(v) { this._attrs.set('class', String(v ?? '')); }
    get innerHTML() { return ''; }
    set innerHTML(v) {
      for (const c of [...this.childNodes]) this.removeChild(c);
      if (v) this.appendChild(this.ownerDocument.createTextNode(String(v)));
    }
    setAttribute(k, v) {
      const key = String(k).toLowerCase();
      this._attrs.set(key, String(v ?? ''));
      if (key === 'value') this._value = String(v ?? '');
    }
    setAttributeNS(_ns, k, v) { this.setAttribute(k, v); }
    getAttribute(k) {
      const key = String(k).toLowerCase();
      return this._attrs.has(key) ? this._attrs.get(key) : null;
    }
    hasAttribute(k) { return this._attrs.has(String(k).toLowerCase()); }
    removeAttribute(k) { this._attrs.delete(String(k).toLowerCase()); }
    focus() { if (this.ownerDocument) this.ownerDocument.activeElement = this; }
    blur() { if (this.ownerDocument && this.ownerDocument.activeElement === this) this.ownerDocument.activeElement = this.ownerDocument.body; }
    scrollIntoView() {}
    _walkElements(acc = []) {
      for (const child of this.childNodes) {
        if (child.nodeType === 1) {
          acc.push(child);
          child._walkElements(acc);
        }
      }
      return acc;
    }
    querySelectorAll(selector) {
      const s = String(selector || '').trim();
      return this._walkElements().filter((el) => {
        if (s.startsWith('.')) return el.className.split(/\s+/).includes(s.slice(1));
        if (s.startsWith('#')) return el.id === s.slice(1);
        return el.tagName.toLowerCase() === s.toLowerCase();
      });
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  }

  class MiniDocument extends MiniNode {
    constructor() {
      super(9, '#document', null);
      this.ownerDocument = this;
      this.defaultView = null;
      this.documentElement = new MiniElement('html', this);
      this.head = new MiniElement('head', this);
      this.body = new MiniElement('body', this);
      this.documentElement.appendChild(this.head);
      this.documentElement.appendChild(this.body);
      this.appendChild(this.documentElement);
      this.activeElement = this.body;
    }
    createElement(tag) { return new MiniElement(tag, this); }
    createElementNS(ns, tag) { return new MiniElement(tag, this, ns); }
    createTextNode(text) { return new MiniText(text, this); }
    createComment(text) { return new MiniComment(text, this); }
    createDocumentFragment() { return new MiniFragment(this); }
    createEvent() { return new MiniEvent(''); }
    querySelectorAll(selector) { return this.documentElement.querySelectorAll(selector); }
    querySelector(selector) { return this.documentElement.querySelector(selector); }
  }

  class MiniIFrameElement extends MiniElement {}
  class MiniShadowRoot extends MiniNode {}

  const doc = new MiniDocument();
  const winListeners = new Map();
  const activeTimeouts = new Set();
  const activeIntervals = new Set();
  const trackedSetTimeout = (fn, ms, ...args) => {
    const id = setTimeout((...a) => {
      activeTimeouts.delete(id);
      fn(...a);
    }, ms, ...args);
    id?.unref?.();
    activeTimeouts.add(id);
    return id;
  };
  const trackedClearTimeout = (id) => {
    activeTimeouts.delete(id);
    clearTimeout(id);
  };
  const trackedSetInterval = (fn, ms, ...args) => {
    const id = setInterval(fn, ms, ...args);
    id?.unref?.();
    activeIntervals.add(id);
    return id;
  };
  const trackedClearInterval = (id) => {
    activeIntervals.delete(id);
    clearInterval(id);
  };
  const win = {
    document: doc,
    Node: MiniNode,
    Element: MiniElement,
    HTMLElement: MiniElement,
    HTMLInputElement: MiniElement,
    HTMLIFrameElement: MiniIFrameElement,
    HTMLTextAreaElement: MiniElement,
    HTMLSelectElement: MiniElement,
    HTMLFormElement: MiniElement,
    HTMLButtonElement: MiniElement,
    ShadowRoot: MiniShadowRoot,
    SVGElement: MiniElement,
    Text: MiniText,
    Comment: MiniComment,
    Document: MiniDocument,
    Event: MiniEvent,
    CustomEvent: MiniEvent,
    location: {hash: '', href: 'http://127.0.0.1:5173/', origin: 'http://127.0.0.1:5173', pathname: '/', search: ''},
    history: {pushState() {}, replaceState() {}, state: null},
    sessionStorage: mkStorage(),
    localStorage: mkStorage(),
    setTimeout: trackedSetTimeout,
    clearTimeout: trackedClearTimeout,
    setInterval: trackedSetInterval,
    clearInterval: trackedClearInterval,
    requestAnimationFrame: (cb) => trackedSetTimeout(() => cb(Date.now()), 0),
    cancelAnimationFrame: (id) => trackedClearTimeout(id),
    _listeners: winListeners,
    addEventListener(type, fn, options) {
      const capture = typeof options === 'boolean' ? options : Boolean(options?.capture);
      const key = `${type}:${capture ? 'c' : 'b'}`;
      if (!winListeners.has(key)) winListeners.set(key, []);
      const list = winListeners.get(key);
      if (!list.includes(fn)) list.push(fn);
    },
    removeEventListener(type, fn, options) {
      const capture = typeof options === 'boolean' ? options : Boolean(options?.capture);
      const key = `${type}:${capture ? 'c' : 'b'}`;
      const list = winListeners.get(key);
      if (!list) return;
      const idx = list.indexOf(fn);
      if (idx >= 0) list.splice(idx, 1);
    },
    dispatchEvent(event) {
      event.target = event.target || win;
      event.currentTarget = win;
      const listeners = winListeners.get(`${event.type}:b`);
      if (listeners) for (const fn of [...listeners]) fn.call(win, event);
      return !event.defaultPrevented;
    },
    matchMedia: (q) => ({
      matches: String(q || '').includes('prefers-reduced-motion'),
      addEventListener() {},
      removeEventListener() {},
      addListener() {},
      removeListener() {},
    }),
    getComputedStyle: () => ({}),
  };
  doc.defaultView = win;

  global.window = win;
  global.document = doc;
  global.Node = MiniNode;
  global.Element = MiniElement;
  global.HTMLElement = MiniElement;
  global.HTMLInputElement = MiniElement;
  global.HTMLIFrameElement = MiniIFrameElement;
  global.HTMLTextAreaElement = MiniElement;
  global.HTMLSelectElement = MiniElement;
  global.HTMLFormElement = MiniElement;
  global.HTMLButtonElement = MiniElement;
  global.ShadowRoot = MiniShadowRoot;
  global.SVGElement = MiniElement;
  global.Text = MiniText;
  global.Comment = MiniComment;
  global.Document = MiniDocument;
  global.Event = MiniEvent;
  global.CustomEvent = MiniEvent;
  global.requestAnimationFrame = win.requestAnimationFrame;
  global.cancelAnimationFrame = win.cancelAnimationFrame;
  global.IS_REACT_ACT_ENVIRONMENT = true;

  return {
    window: win,
    document: doc,
    restore() {
      for (const id of [...activeTimeouts]) clearTimeout(id);
      activeTimeouts.clear();
      for (const id of [...activeIntervals]) clearInterval(id);
      activeIntervals.clear();
      for (const [k, v] of Object.entries(prev)) {
        if (v === undefined) delete global[k];
        else global[k] = v;
      }
    },
  };
}

function loadAppBundle() {
  const esbuild = require(path.join(APP_ROOT, 'node_modules', 'esbuild'));
  const entry = `
    import {createElement as h} from 'react';
    import {createRoot} from 'react-dom/client';
    import {MemoryRouter, Outlet, Route, Routes} from 'react-router-dom';
    import * as apiMod from './src/services/api.js';
    import * as liveScanMod from './src/services/liveScan.js';
    import * as scanOverviewMod from './src/services/scanOverview.js';
    import * as reportModelMod from './src/services/reportModel.js';
    import * as scanHistoryMod from './src/services/scanHistory.js';
    import * as historySyncMod from './src/services/historySync.js';
    import * as findingPresMod from './src/services/findingPresentation.js';
    import Scanner from './src/pages/Scanner.jsx';
    import HistoryPage from './src/pages/HistoryPage.jsx';
    import {Results, FindingDetail} from './src/pages/Results.jsx';
    import ReviewPage from './src/pages/ReviewPage.jsx';
    import ReportsPage from './src/pages/ReportsPage.jsx';
    import {LiveFindings} from './src/pages/LiveFindings.jsx';

    function mountWithOutlet(element, {initialEntry = '/', routePath = '*', outletContext = {}} = {}) {
      const container = document.createElement('div');
      document.body.appendChild(container);
      const root = createRoot(container);
      function Layout() {
        return h(Outlet, {context: outletContext});
      }
      root.render(
        h(MemoryRouter, {initialEntries: [initialEntry]},
          h(Routes, null,
            h(Route, {element: h(Layout)},
              h(Route, {path: routePath, element}),
              h(Route, {path: '*', element}),
            ),
          ),
        ),
      );
      return {
        container,
        unmount() {
          root.unmount();
          if (container.parentNode) container.parentNode.removeChild(container);
        },
      };
    }

    export {
      h,
      apiMod,
      liveScanMod,
      scanOverviewMod,
      reportModelMod,
      scanHistoryMod,
      historySyncMod,
      findingPresMod,
      Scanner,
      HistoryPage,
      Results,
      FindingDetail,
      ReviewPage,
      ReportsPage,
      LiveFindings,
      mountWithOutlet,
    };
  `;
  const out = esbuild.buildSync({
    stdin: {contents: entry, resolveDir: APP_ROOT, loader: 'jsx', sourcefile: 'public-audit-fixes-bundle.jsx'},
    bundle: true,
    platform: 'node',
    format: 'cjs',
    jsx: 'automatic',
    loader: {'.css': 'empty'},
    write: false,
    logLevel: 'silent',
    define: {'import.meta.env': '{}', 'process.env.NODE_ENV': '"production"'},
  });
  const m = new Module(`public-audit-fixes-${Math.random()}`, module);
  m.paths = module.paths;
  m._compile(out.outputFiles[0].text, path.join(APP_ROOT, 'public-audit-fixes-bundle.cjs'));
  return m.exports;
}

async function waitFor(predicate, timeoutMs = 1500) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 15));
  }
}

function jsonResp(status, body) {
  return new Response(JSON.stringify(body), {status, headers: {'Content-Type': 'application/json'}});
}

// =================================================================================================
// 1. Bearer token bound strictly to API origin (offline mock, zero real network)
// =================================================================================================
test('Audit Fix 1: Bearer token stays bound to its origin across path/port/scheme/host changes, reset, and rejects query/hash URLs', async () => {
  const dom = installMiniDom();
  const prevFetch = global.fetch;
  const seen = [];
  global.fetch = async (url, options = {}) => {
    seen.push({url: String(url), headers: {...(options.headers || {})}});
    return jsonResp(200, {status: 'OK'});
  };

  try {
    const {apiMod} = loadAppBundle();
    const tokenOriginA = 'synthetic-origin-a-token-111111';
    const tokenOriginB = 'synthetic-origin-b-token-222222';

    // Default startup must NEVER ship a pre-populated production or test token.
    assert.equal(apiMod.hasSessionToken(), false);
    assert.equal(apiMod.getSessionTokenOrigin(), '');

    // Set origin A with a base path and attach token A.
    apiMod.setApiBaseUrl('http://127.0.0.1:19201/gateway/v1/');
    assert.equal(apiMod.getApiBaseUrl(), 'http://127.0.0.1:19201/gateway/v1');
    apiMod.setSessionToken(tokenOriginA);
    assert.equal(apiMod.hasSessionToken(), true);
    assert.equal(apiMod.getSessionTokenOrigin(), 'http://127.0.0.1:19201');
    await apiMod.api.health();
    assert.equal(seen.at(-1).url, 'http://127.0.0.1:19201/gateway/v1/api/health');
    assert.equal(seen.at(-1).headers.Authorization, `Bearer ${tokenOriginA}`);

    // Same origin with different path keeps token valid (does not break auth on same origin).
    apiMod.setApiBaseUrl('http://127.0.0.1:19201/gateway/v2');
    assert.equal(apiMod.hasSessionToken(), true);
    await apiMod.api.health();
    assert.equal(seen.at(-1).url, 'http://127.0.0.1:19201/gateway/v2/api/health');
    assert.equal(seen.at(-1).headers.Authorization, `Bearer ${tokenOriginA}`);

    // Same origin with equivalent default port (:80 on http) keeps token valid.
    apiMod.setApiBaseUrl('http://127.0.0.1:80/api-proxy');
    apiMod.setSessionToken(tokenOriginA);
    apiMod.setApiBaseUrl('http://127.0.0.1/api-proxy');
    assert.equal(apiMod.hasSessionToken(), true);
    await apiMod.api.health();
    assert.equal(seen.at(-1).headers.Authorization, `Bearer ${tokenOriginA}`);

    // Different port (even with identical path) MUST clear token and NEVER leak Authorization.
    apiMod.setApiBaseUrl('http://127.0.0.1:19201/gateway/v1');
    apiMod.setSessionToken(tokenOriginA);
    apiMod.setApiBaseUrl('http://127.0.0.1:19202/gateway/v1');
    assert.equal(apiMod.hasSessionToken(), false);
    assert.equal(apiMod.getSessionTokenOrigin(), '');
    await apiMod.api.health();
    assert.equal(seen.at(-1).url, 'http://127.0.0.1:19202/gateway/v1/api/health');
    assert.equal(seen.at(-1).headers.Authorization, undefined);

    // Different scheme (http -> https, same host/port/path) MUST clear token and NEVER leak Authorization.
    apiMod.setSessionToken(tokenOriginB);
    assert.equal(apiMod.hasSessionToken(), true);
    apiMod.setApiBaseUrl('https://127.0.0.1:19202/gateway/v1');
    assert.equal(apiMod.hasSessionToken(), false);
    await apiMod.api.health();
    assert.equal(seen.at(-1).headers.Authorization, undefined);

    // Different hostname (127.0.0.1 -> localhost) via configureApiConnection without new token MUST clear token.
    apiMod.setSessionToken(tokenOriginB);
    const switched = apiMod.configureApiConnection({baseUrl: 'https://localhost:19202/gateway/v1', token: ''});
    assert.equal(switched.originChanged, true);
    assert.equal(switched.hasToken, false);
    assert.equal(switched.tokenClearedByOriginChange, true);
    await apiMod.api.health();
    assert.equal(seen.at(-1).headers.Authorization, undefined);

    // Returning to previous origin MUST NOT resurrect old token.
    apiMod.setApiBaseUrl('http://127.0.0.1:19201/gateway/v1');
    assert.equal(apiMod.hasSessionToken(), false);
    await apiMod.api.health();
    assert.equal(seen.at(-1).headers.Authorization, undefined);

    // resetApiBaseUrl() when on a non-default origin MUST clear token before calling default origin.
    apiMod.setSessionToken(tokenOriginA);
    assert.equal(apiMod.hasSessionToken(), true);
    apiMod.resetApiBaseUrl();
    assert.equal(apiMod.hasSessionToken(), false);
    await apiMod.api.health();
    assert.equal(seen.at(-1).headers.Authorization, undefined);

    // URLs containing query strings, fragments, embedded credentials, or forbidden port 8765 MUST be rejected.
    apiMod.setApiBaseUrl('http://127.0.0.1:19201');
    apiMod.setSessionToken(tokenOriginA);
    const countBeforeReject = seen.length;
    for (const badUrl of [
      'http://127.0.0.1:19201?token=leak',
      'http://127.0.0.1:19201#frag',
      'http://user:pass@127.0.0.1:19201',
      'http://127.0.0.1:8765',
      'javascript:alert(1)',
    ]) {
      assert.throws(() => apiMod.setApiBaseUrl(badUrl), `Must reject invalid API URL: ${badUrl}`);
    }
    assert.equal(seen.length, countBeforeReject, 'Rejected URLs must emit zero requests');
  } finally {
    global.fetch = prevFetch;
    dom.restore();
  }
});

// =================================================================================================
// 2. Scanner must NOT interpret missing findings + missing total as 0 / NO_FINDINGS
// =================================================================================================
test('Audit Fix 2: liveScan & Scanner never infer total=0 or NO_FINDINGS when findings list and totals are missing', async () => {
  const dom = installMiniDom();
  const prevFetch = global.fetch;

  try {
    const bundle = loadAppBundle();
    const {apiMod, liveScanMod, scanHistoryMod, Scanner, h, mountWithOutlet} = bundle;
    apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:19203', token: 'tok-fix2-123456'});

    // 2a. buildDataset with valid scan_id but missing findings array AND missing totals -> total MUST be null, NOT 0.
    const dsMissing = liveScanMod.buildDataset(
      'scan-missing-both',
      {scan_id: 'scan-missing-both'},
      {scan_id: 'scan-missing-both'},
    );
    assert.equal(dsMissing.counts.total, null, 'Missing findings + missing totals must NOT infer total = 0');
    assert.equal(dsMissing.counts.confirmedNoFindings, false, 'Missing data must NOT confirm NO_FINDINGS');
    assert.equal(dsMissing.incomplete, true, 'Missing data must be flagged incomplete');

    // 2b. buildDataset with valid scan_id + empty findings array [] BUT missing total_findings & total_count -> NOT confirmed zero.
    const dsNoTotal = liveScanMod.buildDataset(
      'scan-missing-total',
      {scan_id: 'scan-missing-total'},
      {scan_id: 'scan-missing-total', findings: []},
    );
    assert.equal(dsNoTotal.counts.total, null, 'Empty array without backend total must NOT infer total = 0');
    assert.equal(dsNoTotal.counts.confirmedNoFindings, false);
    assert.equal(dsNoTotal.incomplete, true);

    // 2c. api.allFindingsPages must NOT coerce null total_count/total_matching into 0 via Number(null).
    global.fetch = async () => jsonResp(200, {scan_id: 'scan-null-counts', total_count: null, total_matching: null});
    const allPages = await apiMod.api.allFindingsPages('scan-null-counts');
    assert.equal(allPages.complete, false, 'Null counts and missing findings array must NOT mark allFindingsPages complete');
    assert.equal(allPages.total, null, 'Null total_count must remain null, not 0');

    // 2d. loadLiveScan with missing findings and missing totals MUST reject and NOT record candidates=0 in history.
    global.fetch = async (url) => {
      const u = String(url);
      if (u.includes('/api/scans/scan-missing-both/findings')) return jsonResp(200, {scan_id: 'scan-missing-both'});
      if (u.includes('/api/scans/scan-missing-both')) return jsonResp(200, {scan_id: 'scan-missing-both'});
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    await assert.rejects(
      () => liveScanMod.loadLiveScan('scan-missing-both'),
      (err) => err instanceof apiMod.ApiError,
      'loadLiveScan must reject incomplete scan payload lacking findings list and totals',
    );
    assert.equal(
      scanHistoryMod.readHistory(apiMod.getApiOrigin(), {sessionScope: apiMod.getAuthSessionScope()})
        .some((r) => r.scanId === 'scan-missing-both' && r.candidates === 0),
      false,
      'Incomplete scan must never be recorded in history as 0 findings',
    );

    // 2e. Mounted Scanner component receiving COMPLETED job whose scan summary/findings omit findings & totals:
    //     MUST NOT display NO_FINDINGS or "0 cảnh báo"; MUST show error/incomplete status.
    window.sessionStorage.setItem('22025523-active-job', 'job-missing-1');
    global.fetch = async (url) => {
      const u = String(url);
      if (u.includes('/api/scan-jobs/job-missing-1')) {
        return jsonResp(200, {job_id: 'job-missing-1', state: 'COMPLETED', scan_id: 'scan-missing-ui', stages: []});
      }
      if (u.includes('/api/scans/scan-missing-ui/findings')) {
        return jsonResp(200, {scan_id: 'scan-missing-ui'});
      }
      if (u.includes('/api/scans/scan-missing-ui')) {
        return jsonResp(200, {scan_id: 'scan-missing-ui'});
      }
      if (u.includes('/api/scan-jobs')) {
        return jsonResp(200, {jobs: [], total_count: 0});
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedMissing = mountWithOutlet(h(Scanner), {
      initialEntry: '/scanner',
      outletContext: {
        backend: {status: 'CONNECTED', health: {status: 'OK', write_auth_required: true, authenticated: true}},
        apiOrigin: apiMod.getApiOrigin(),
        authSessionScope: apiMod.getAuthSessionScope(),
        apiRevision: apiMod.getApiConfigRevision(),
      },
    });
    try {
      await waitFor(() => /chưa tải được kết quả|không đầy đủ|thiếu danh sách/i.test(mountedMissing.container.textContent));
      const text = mountedMissing.container.textContent;
      assert.doesNotMatch(text, /NO_FINDINGS/, 'Scanner must NOT display NO_FINDINGS when findings and totals are missing');
      assert.doesNotMatch(text, /0 cảnh báo trong phạm vi/, 'Scanner must NOT claim 0 findings when data is missing');
      assert.match(text, /chưa tải được kết quả|thiếu|không đầy đủ/i);
    } finally {
      mountedMissing.unmount();
    }

    // 2f. Positive case: explicit valid zero evidence (total_findings: 0, total_count: 0, findings: []) DOES show NO_FINDINGS.
    const dsValidZero = liveScanMod.buildDataset(
      'scan-valid-zero',
      {
        scan_id: 'scan-valid-zero',
        data_origin: 'REAL_SCAN',
        total_findings: 0,
        by_validated_status: {SUPPORTED: 0, REFUTED: 0, UNDETERMINED: 0},
        by_human_review_state: {OPEN: 0, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0},
      },
      {scan_id: 'scan-valid-zero', total_count: 0, total_matching: 0, findings: []},
    );
    assert.equal(dsValidZero.counts.total, 0);
    assert.equal(dsValidZero.counts.confirmedNoFindings, true);
    assert.equal(dsValidZero.incomplete, false);

    window.sessionStorage.setItem('22025523-active-job', 'job-zero-1');
    global.fetch = async (url) => {
      const u = String(url);
      if (u.includes('/api/scan-jobs/job-zero-1')) {
        return jsonResp(200, {job_id: 'job-zero-1', state: 'COMPLETED', scan_id: 'scan-valid-zero', stages: []});
      }
      if (u.includes('/api/scans/scan-valid-zero/findings')) {
        return jsonResp(200, {scan_id: 'scan-valid-zero', total_count: 0, total_matching: 0, findings: []});
      }
      if (u.includes('/api/scans/scan-valid-zero')) {
        return jsonResp(200, {
          scan_id: 'scan-valid-zero',
          data_origin: 'REAL_SCAN',
          total_findings: 0,
          by_validated_status: {SUPPORTED: 0, REFUTED: 0, UNDETERMINED: 0},
          by_human_review_state: {OPEN: 0, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0},
        });
      }
      if (u.includes('/api/scan-jobs')) {
        return jsonResp(200, {jobs: [], total_count: 0});
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedZero = mountWithOutlet(h(Scanner), {
      initialEntry: '/scanner',
      outletContext: {
        backend: {status: 'CONNECTED', health: {status: 'OK', write_auth_required: true, authenticated: true}},
        apiOrigin: apiMod.getApiOrigin(),
        authSessionScope: apiMod.getAuthSessionScope(),
        apiRevision: apiMod.getApiConfigRevision(),
      },
    });
    try {
      await waitFor(() => /NO_FINDINGS/.test(mountedZero.container.textContent));
      assert.match(mountedZero.container.textContent, /NO_FINDINGS/);
    } finally {
      mountedZero.unmount();
    }
  } finally {
    global.fetch = prevFetch;
    dom.restore();
  }
});

// =================================================================================================
// 3. REFUTED (giữ OPEN) must satisfy BOTH Qwen REFUTED and human review OPEN
// =================================================================================================
test('Audit Fix 3: REFUTED (giữ OPEN) counts only findings that are BOTH REFUTED and OPEN, never total REFUTED', async () => {
  const dom = installMiniDom();
  const prevFetch = global.fetch;

  try {
    const {apiMod, liveScanMod, Scanner, h, mountWithOutlet} = loadAppBundle();
    apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:19204', token: 'tok-fix3-123456'});

    const mixedSummary = {
      scan_id: 'scan-refuted-axes',
      data_origin: 'REAL_SCAN',
      total_findings: 4,
      by_validated_status: {SUPPORTED: 1, REFUTED: 3, UNDETERMINED: 0},
      by_human_review_state: {OPEN: 2, CONFIRMED_TRUE: 1, CONFIRMED_FALSE: 1},
    };
    const mixedPage = {
      scan_id: 'scan-refuted-axes',
      total_count: 4,
      total_matching: 4,
      findings: [
        {finding_id: 'f1', cwe: 'CWE-22', validated_status: 'SUPPORTED', human_review_state: 'OPEN'},
        {finding_id: 'f2', cwe: 'CWE-22', validated_status: 'REFUTED', human_review_state: 'OPEN'},
        {finding_id: 'f3', cwe: 'CWE-89', validated_status: 'REFUTED', human_review_state: 'CONFIRMED_FALSE'},
        {finding_id: 'f4', cwe: 'CWE-89', validated_status: 'REFUTED', human_review_state: 'CONFIRMED_TRUE'},
      ],
    };

    // 3a. Two-axis separation in buildDataset
    const dsMixed = liveScanMod.buildDataset('scan-refuted-axes', mixedSummary, mixedPage);
    assert.equal(dsMixed.counts.refuted, 3, 'Total Qwen REFUTED across all review states is 3');
    assert.equal(dsMixed.counts.open, 2, 'Total human OPEN across all Qwen statuses is 2');
    assert.equal(dsMixed.counts.refutedOpen, 1, 'REFUTED AND OPEN intersection must be 1, NOT 3');

    // 3b. All REFUTED already confirmed false -> refutedOpen = 0
    const dsAllConfirmedFalse = liveScanMod.buildDataset(
      'scan-refuted-closed',
      {
        scan_id: 'scan-refuted-closed',
        data_origin: 'REAL_SCAN',
        total_findings: 2,
        by_validated_status: {SUPPORTED: 0, REFUTED: 2, UNDETERMINED: 0},
        by_human_review_state: {OPEN: 0, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 2},
      },
      {
        scan_id: 'scan-refuted-closed',
        total_count: 2,
        total_matching: 2,
        findings: [
          {finding_id: 'r1', cwe: 'CWE-22', validated_status: 'REFUTED', human_review_state: 'CONFIRMED_FALSE'},
          {finding_id: 'r2', cwe: 'CWE-89', validated_status: 'REFUTED', human_review_state: 'CONFIRMED_FALSE'},
        ],
      },
    );
    assert.equal(dsAllConfirmedFalse.counts.refuted, 2);
    assert.equal(dsAllConfirmedFalse.counts.refutedOpen, 0);

    // 3c. Paginated scan (only page 1 loaded, summary omits proposed_refuted_open_count) -> MUST NOT reuse total REFUTED!
    const dsPaginated = liveScanMod.buildDataset(
      'scan-refuted-paginated',
      {
        scan_id: 'scan-refuted-paginated',
        data_origin: 'REAL_SCAN',
        total_findings: 10,
        by_validated_status: {SUPPORTED: 2, REFUTED: 5, UNDETERMINED: 3},
        by_human_review_state: {OPEN: 4, CONFIRMED_TRUE: 2, CONFIRMED_FALSE: 4},
      },
      {
        scan_id: 'scan-refuted-paginated',
        total_count: 10,
        total_matching: 10,
        findings: [
          {finding_id: 'p1', cwe: 'CWE-22', validated_status: 'REFUTED', human_review_state: 'OPEN'},
          {finding_id: 'p2', cwe: 'CWE-22', validated_status: 'REFUTED', human_review_state: 'CONFIRMED_FALSE'},
        ],
      },
    );
    assert.equal(dsPaginated.counts.refuted, 5);
    assert.equal(dsPaginated.counts.refutedOpen, null, 'Paginated scan without proposed_refuted_open_count must NOT claim 5 for REFUTED (OPEN)');

    // 3d. Mounted real Scanner UI renders REFUTED (giữ OPEN): 1 (NOT 3).
    window.sessionStorage.setItem('22025523-active-job', 'job-refuted-1');
    global.fetch = async (url) => {
      const u = String(url);
      if (u.includes('/api/scan-jobs/job-refuted-1')) {
        return jsonResp(200, {job_id: 'job-refuted-1', state: 'COMPLETED', scan_id: 'scan-refuted-axes', stages: []});
      }
      if (u.includes('/api/scans/scan-refuted-axes/findings')) return jsonResp(200, mixedPage);
      if (u.includes('/api/scans/scan-refuted-axes')) return jsonResp(200, mixedSummary);
      if (u.includes('/api/scan-jobs')) return jsonResp(200, {jobs: [], total_count: 0});
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mounted = mountWithOutlet(h(Scanner), {
      initialEntry: '/scanner',
      outletContext: {
        backend: {status: 'CONNECTED', health: {status: 'OK', write_auth_required: true, authenticated: true}},
        apiOrigin: apiMod.getApiOrigin(),
        authSessionScope: apiMod.getAuthSessionScope(),
        apiRevision: apiMod.getApiConfigRevision(),
      },
    });
    try {
      await waitFor(() => (
        /REFUTED \(giữ OPEN\)/.test(mounted.container.textContent) &&
        /REFUTED \(OPEN\)/.test(mounted.container.textContent)
      ));
      const badges = mounted.container.querySelectorAll('.badge').map((b) => b.textContent.trim());
      assert.ok(badges.includes('REFUTED (Qwen): 3'), `Expected REFUTED (Qwen): 3 badge, got: ${JSON.stringify(badges)}`);
      assert.ok(badges.includes('REFUTED (giữ OPEN): 1'), `Expected REFUTED (giữ OPEN): 1 badge, got: ${JSON.stringify(badges)}`);
      assert.equal(badges.includes('REFUTED (giữ OPEN): 3'), false, 'Scanner badge must NOT show total REFUTED (3) as REFUTED (giữ OPEN)');
      const text = mounted.container.textContent;
      assert.match(text, /REFUTED \(OPEN\)1(?!\d)/, 'ScanStageVisual must also show REFUTED (OPEN) = 1');
      assert.doesNotMatch(text, /REFUTED \(OPEN\)3/, 'ScanStageVisual must NOT show REFUTED (OPEN) = 3');
    } finally {
      mounted.unmount();
    }
  } finally {
    global.fetch = prevFetch;
    dom.restore();
  }
});

// =================================================================================================
// 4. History must detect incomplete/mismatched lists without marking supported:true or fabricating rows
// =================================================================================================
test('Audit Fix 4: historySync & HistoryPage detect COUNT_MISMATCH / valid:false / truncated lists and preserve valid rows honestly', async () => {
  const dom = installMiniDom();
  const prevFetch = global.fetch;

  try {
    const {apiMod, historySyncMod, HistoryPage, h, mountWithOutlet} = loadAppBundle();
    const ORIGIN_H = 'http://127.0.0.1:19205';
    apiMod.configureApiConnection({baseUrl: ORIGIN_H, token: 'tok-fix4-123456'});

    // 4a. COUNT_MISMATCH on /api/scans (1 item returned, total_count=3)
    global.fetch = async (url) => {
      const u = new URL(url);
      if (u.pathname === '/api/scan-jobs') return jsonResp(200, {jobs: [], total_count: 0});
      if (u.pathname === '/api/scans') {
        return jsonResp(200, {
          total_count: 3,
          scans: [{
            scan_id: 'scan-real-present-1',
            data_origin: 'REAL_SCAN',
            repo_url: 'https://github.com/example/partial-demo',
            input_mode: 'GITHUB',
            total_findings: 2,
            completed_at: '2026-11-20T09:00:00Z',
          }],
        });
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };

    const mismatchSync = await historySyncMod.syncHistoryFromApi({origin: ORIGIN_H});
    assert.equal(mismatchSync.stale, false);
    assert.equal(mismatchSync.supported, false, 'COUNT_MISMATCH must NOT be confirmed as supported: true full sync');
    assert.equal(mismatchSync.incomplete, true, 'COUNT_MISMATCH must be flagged incomplete: true');
    assert.equal(mismatchSync.records.length, 1, 'Must preserve the 1 valid received record and NEVER fabricate 2 fake records');
    assert.equal(mismatchSync.records[0].scanId, 'scan-real-present-1');
    assert.ok(
      (mismatchSync.incompleteReasons || []).includes('COUNT_MISMATCH'),
      'incompleteReasons must include COUNT_MISMATCH',
    );

    // 4b. TRUNCATED_LIST (has_more: true) on /api/scans
    global.fetch = async (url) => {
      const u = new URL(url);
      if (u.pathname === '/api/scan-jobs') return jsonResp(200, {jobs: [], total_count: 0});
      if (u.pathname === '/api/scans') {
        return jsonResp(200, {
          total_count: 1,
          has_more: true,
          scans: [{scan_id: 'scan-trunc-1', data_origin: 'REAL_SCAN', completed_at: '2026-11-20T10:00:00Z'}],
        });
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const truncSync = await historySyncMod.syncHistoryFromApi({origin: ORIGIN_H});
    assert.equal(truncSync.supported, false);
    assert.equal(truncSync.incomplete, true);
    assert.equal(truncSync.backendRecords.length, 1);
    assert.ok((truncSync.incompleteReasons || []).includes('TRUNCATED_LIST'));

    // 4c. COUNT_MISMATCH on /api/scan-jobs even when /api/scans is valid -> still incomplete & supported:false
    global.fetch = async (url) => {
      const u = new URL(url);
      if (u.pathname === '/api/scan-jobs') {
        return jsonResp(200, {
          total_count: 4,
          jobs: [{job_id: 'job-only-1', state: 'RUNNING'}],
        });
      }
      if (u.pathname === '/api/scans') {
        return jsonResp(200, {total_count: 0, scans: []});
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const jobsMismatchSync = await historySyncMod.syncHistoryFromApi({origin: ORIGIN_H});
    assert.equal(jobsMismatchSync.supported, false);
    assert.equal(jobsMismatchSync.incomplete, true);
    assert.equal(jobsMismatchSync.backendRecords.length, 1);

    // 4d. Positive complete sync -> supported: true, incomplete: false
    global.fetch = async (url) => {
      const u = new URL(url);
      if (u.pathname === '/api/scan-jobs') return jsonResp(200, {jobs: [], total_count: 0});
      if (u.pathname === '/api/scans') {
        return jsonResp(200, {
          total_count: 1,
          scans: [{scan_id: 'scan-complete-1', data_origin: 'REAL_SCAN', completed_at: '2026-11-20T11:00:00Z'}],
        });
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const completeSync = await historySyncMod.syncHistoryFromApi({origin: ORIGIN_H});
    assert.equal(completeSync.supported, true);
    assert.equal(completeSync.incomplete, false);

    // 4e. Mounted HistoryPage displays incomplete warning AND preserves the valid received row
    apiMod.configureApiConnection({baseUrl: ORIGIN_H, token: 'tok-fix4-ui-999'});
    global.fetch = async (url) => {
      const u = new URL(url);
      if (u.pathname === '/api/scan-jobs') return jsonResp(200, {jobs: [], total_count: 0});
      if (u.pathname === '/api/scans') {
        return jsonResp(200, {
          total_count: 5,
          scans: [{
            scan_id: 'scan-partial-ui-1',
            data_origin: 'REAL_SCAN',
            repo_url: 'https://github.com/example/kept-record',
            input_mode: 'GITHUB',
            completed_at: '2026-11-20T12:00:00Z',
          }],
        });
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mounted = mountWithOutlet(h(HistoryPage), {
      initialEntry: '/history',
      outletContext: {
        apiOrigin: apiMod.getApiOrigin(),
        authSessionScope: apiMod.getAuthSessionScope(),
        apiRevision: apiMod.getApiConfigRevision(),
      },
    });
    try {
      await waitFor(() => /kept-record/.test(mounted.container.textContent) && /chưa đầy đủ|COUNT_MISMATCH|thiếu dữ liệu/i.test(mounted.container.textContent));
      const text = mounted.container.textContent;
      assert.match(text, /kept-record/, 'HistoryPage must preserve valid received record');
      assert.match(text, /chưa đầy đủ|COUNT_MISMATCH|thiếu dữ liệu/i, 'HistoryPage must show incomplete list warning');
      const rows = mounted.container.querySelectorAll('.history-compact-row');
      assert.equal(rows.length, 1, 'HistoryPage must NOT fabricate extra rows to match total_count=5');
    } finally {
      mounted.unmount();
    }
  } finally {
    global.fetch = prevFetch;
    dom.restore();
  }
});

// =================================================================================================
// 5. Results scan picker & FindingDetail must fail-closed on missing/unverified/mock data_origin
// =================================================================================================
test('Audit Fix 5: Results scan picker and FindingDetail never default missing/unverified/mock data_origin to REAL_SCAN', async () => {
  const dom = installMiniDom();
  const prevFetch = global.fetch;

  try {
    const {apiMod, Results, FindingDetail, h, mountWithOutlet} = loadAppBundle();
    const ORIGIN_R = 'http://127.0.0.1:19206';
    apiMod.configureApiConnection({baseUrl: ORIGIN_R, token: 'tok-fix5-123456'});

    // 5a. Scan picker with missing origin, imported origin, mock scan, and verified REAL_SCAN
    global.fetch = async (url) => {
      const u = new URL(url);
      if (u.pathname === '/api/scans') {
        return jsonResp(200, {
          total_count: 4,
          scans: [
            {
              scan_id: 'scan-missing-origin',
              repo_url: 'https://github.com/example/no-origin',
              input_mode: 'GITHUB',
              total_findings: 1,
            },
            {
              scan_id: 'scan-imported-origin',
              data_origin: 'IMPORTED_SCAN_UNVERIFIED_CAPTURE',
              repo_url: 'https://github.com/example/imported',
              input_mode: 'DIRECTORY',
              total_findings: 1,
            },
            {
              scan_id: 'scan-mock-leaked',
              data_origin: 'MOCK_SYNTHETIC_TEST',
              is_test_or_mock: true,
              repo_url: 'https://github.com/example/mock-should-hide',
              input_mode: 'GITHUB',
              total_findings: 1,
            },
            {
              scan_id: 'scan-verified-real',
              data_origin: 'REAL_SCAN',
              scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: true, exit_capture_verified: true, recorded_engine_exit: 0},
              repo_url: 'https://github.com/example/verified-real',
              input_mode: 'GITHUB',
              total_findings: 1,
            },
          ],
        });
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };

    const mountedPicker = mountWithOutlet(h(Results), {
      initialEntry: '/findings',
      outletContext: {
        apiOrigin: apiMod.getApiOrigin(),
        authSessionScope: apiMod.getAuthSessionScope(),
        apiRevision: apiMod.getApiConfigRevision(),
      },
    });
    try {
      await waitFor(() => /no-origin/.test(mountedPicker.container.textContent));
      const cards = mountedPicker.container.querySelectorAll('.v2-scan-picker-row');
      const cardTexts = cards.map((c) => c.textContent);

      const missingCard = cardTexts.find((t) => t.includes('no-origin'));
      assert.ok(missingCard, 'scan-missing-origin must be rendered');
      assert.doesNotMatch(missingCard, /REAL_SCAN/, 'Missing data_origin in Results picker MUST NOT default to REAL_SCAN');
      assert.match(missingCard, /UNVERIFIED_ORIGIN|Chưa xác minh/i);

      const importedCard = cardTexts.find((t) => t.includes('imported'));
      assert.ok(importedCard, 'scan-imported-origin must be rendered');
      assert.match(importedCard, /IMPORTED_SCAN_UNVERIFIED_CAPTURE/);
      assert.doesNotMatch(importedCard, /REAL_SCAN/);

      const mockCard = cardTexts.find((t) => t.includes('mock-should-hide'));
      assert.equal(mockCard, undefined, 'Mock/synthetic scan must be isolated from real scan picker');

      const realCard = cardTexts.find((t) => t.includes('verified-real'));
      assert.ok(realCard, 'scan-verified-real must be rendered');
      assert.match(realCard, /REAL_SCAN/);
    } finally {
      mountedPicker.unmount();
    }

    // 5b. FindingDetail with missing data_origin -> MUST NOT render REAL_SCAN
    global.fetch = async (url) => {
      const u = new URL(url);
      if (u.pathname === '/api/scans/scan-no-orig/findings/f-no-orig') {
        return jsonResp(200, {
          scan_id: 'scan-no-orig',
          finding_id: 'f-no-orig',
          cwe: 'CWE-22',
          file_path: 'src/Demo.java',
          start_line: 10,
          validated_status: 'UNDETERMINED',
          human_review_state: 'OPEN',
          evidence: {path: 'src/Demo.java', start: {line: 10}, snippets: [], snapshots: {}},
          assessment: {validated_status: 'UNDETERMINED', citations: []},
        });
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedDetailMissing = mountWithOutlet(h(FindingDetail), {
      initialEntry: '/finding/f-no-orig?scan_id=scan-no-orig',
      routePath: '/finding/:id',
      outletContext: {
        apiOrigin: apiMod.getApiOrigin(),
        authSessionScope: apiMod.getAuthSessionScope(),
        apiRevision: apiMod.getApiConfigRevision(),
      },
    });
    try {
      await waitFor(() => /CWE-22/.test(mountedDetailMissing.container.textContent));
      const text = mountedDetailMissing.container.textContent;
      assert.doesNotMatch(text, /REAL_SCAN/, 'FindingDetail with missing data_origin MUST NOT default to REAL_SCAN');
      assert.match(text, /UNVERIFIED_ORIGIN|Chưa xác minh nguồn gốc/i);
    } finally {
      mountedDetailMissing.unmount();
    }

    // 5c. FindingDetail claiming data_origin='REAL_SCAN' while evidence.scan_provenance shows unverified capture -> fail-closed!
    global.fetch = async (url) => {
      const u = new URL(url);
      if (u.pathname === '/api/scans/scan-contradict/findings/f-contradict') {
        return jsonResp(200, {
          scan_id: 'scan-contradict',
          finding_id: 'f-contradict',
          data_origin: 'REAL_SCAN',
          cwe: 'CWE-89',
          file_path: 'src/Sql.java',
          start_line: 15,
          validated_status: 'SUPPORTED',
          human_review_state: 'OPEN',
          evidence: {
            path: 'src/Sql.java',
            start: {line: 15},
            snippets: [],
            snapshots: {},
            scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: false, exit_capture_verified: false},
          },
          assessment: {validated_status: 'SUPPORTED', citations: []},
        });
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedDetailContradict = mountWithOutlet(h(FindingDetail), {
      initialEntry: '/finding/f-contradict?scan_id=scan-contradict',
      routePath: '/finding/:id',
      outletContext: {
        apiOrigin: apiMod.getApiOrigin(),
        authSessionScope: apiMod.getAuthSessionScope(),
        apiRevision: apiMod.getApiConfigRevision(),
      },
    });
    try {
      await waitFor(() => /CWE-89/.test(mountedDetailContradict.container.textContent));
      const badges = mountedDetailContradict.container.querySelectorAll('.badge').map((b) => b.textContent);
      assert.equal(
        badges.some((b) => b.trim() === 'REAL_SCAN'),
        false,
        'FindingDetail with unverified scan_provenance MUST NOT display REAL_SCAN badge',
      );
    } finally {
      mountedDetailContradict.unmount();
    }

    // 5d. FindingDetail with missing data_origin but assessment.runtime.origin='mock' -> blocked as mock!
    global.fetch = async (url) => {
      const u = new URL(url);
      if (u.pathname === '/api/scans/scan-mock-rt/findings/f-mock-rt') {
        return jsonResp(200, {
          scan_id: 'scan-mock-rt',
          finding_id: 'f-mock-rt',
          cwe: 'CWE-22',
          file_path: 'src/Mock.java',
          start_line: 5,
          validated_status: 'SUPPORTED',
          human_review_state: 'OPEN',
          evidence: {path: 'src/Mock.java', start: {line: 5}, snippets: [], snapshots: {}},
          assessment: {validated_status: 'SUPPORTED', citations: [], runtime: {origin: 'mock'}},
        });
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedDetailMock = mountWithOutlet(h(FindingDetail), {
      initialEntry: '/finding/f-mock-rt?scan_id=scan-mock-rt',
      routePath: '/finding/:id',
      outletContext: {
        apiOrigin: apiMod.getApiOrigin(),
        authSessionScope: apiMod.getAuthSessionScope(),
        apiRevision: apiMod.getApiConfigRevision(),
      },
    });
    try {
      await waitFor(() => /Dữ liệu mô phỏng \(mock\) bị chặn/.test(mountedDetailMock.container.textContent));
      const text = mountedDetailMock.container.textContent;
      assert.match(text, /Dữ liệu mô phỏng \(mock\) bị chặn/);
      assert.doesNotMatch(text, /REAL_SCAN/);
    } finally {
      mountedDetailMock.unmount();
    }
  } finally {
    global.fetch = prevFetch;
    dom.restore();
  }
});

// =================================================================================================
// ROOT-CAUSE INVARIANT SUITES (Groups A–E from independent re-audit)
// =================================================================================================

test('Root Cause A: API session tracks normalized baseUrl (same-origin path change invalidates in-flight/late responses & cache while keeping same-origin token) and rejects trailing ? / # delimiters', async () => {
  const dom = installMiniDom();
  const prevFetch = global.fetch;

  try {
    const {apiMod, historySyncMod, scanHistoryMod} = loadAppBundle();
    const tok = 'synthetic-same-origin-token-999999';

    // A1. Trailing empty query / fragment delimiters MUST be rejected even though URL.search/hash === ''.
    const delimiterCases = [
      'http://127.0.0.1:19210?',
      'http://127.0.0.1:19210#',
      'http://127.0.0.1:19210/api?',
      'http://127.0.0.1:19210/api#',
      'http://127.0.0.1:19210/?#',
      'http://127.0.0.1:19210/old?x=1',
      'http://127.0.0.1:19210/old#top',
      'http://127.0.0.1:19210/old\npath',
      'http://127.0.0.1:19210/old path',
    ];
    for (const bad of delimiterCases) {
      assert.throws(() => apiMod.setApiBaseUrl(bad), `Must reject URL containing query/fragment delimiter: ${bad}`);
    }

    // A2. Same-origin path switch (/old-path -> /new-path) MUST rotate sessionScope,
    //     reject in-flight/late responses from /old-path (even when transport ignores AbortSignal),
    //     clear prior session cache, AND preserve the valid same-origin Bearer token.
    const seen = [];
    let releaseOldHealth;
    let releaseOldHistory;
    global.fetch = (url, options = {}) => {
      const u = String(url);
      seen.push({url: u, auth: (options.headers || {}).Authorization});
      if (u.startsWith('http://127.0.0.1:19210/old-path/api/health')) {
        // Transport deliberately ignores AbortSignal and resolves AFTER path switch!
        return new Promise((resolve) => {
          releaseOldHealth = () => resolve(jsonResp(200, {status: 'OK', from: 'old-path'}));
        });
      }
      if (u.startsWith('http://127.0.0.1:19210/old-path/api/scans')) {
        return new Promise((resolve) => {
          releaseOldHistory = () => resolve(jsonResp(200, {
            total_count: 1,
            scans: [{scan_id: 'scan-from-old-path', repo_url: 'https://github.com/example/old-path-repo'}],
          }));
        });
      }
      if (u.startsWith('http://127.0.0.1:19210/old-path/api/scan-jobs')) {
        return Promise.resolve(jsonResp(200, {total_count: 0, jobs: []}));
      }
      if (u.startsWith('http://127.0.0.1:19210/new-path/api/health')) {
        return Promise.resolve(jsonResp(200, {status: 'OK', from: 'new-path'}));
      }
      return Promise.resolve(jsonResp(200, {total_count: 0, jobs: [], scans: []}));
    };

    const cfgOld = apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:19210/old-path/', token: tok});
    assert.equal(apiMod.getApiBaseUrl(), 'http://127.0.0.1:19210/old-path');
    assert.equal(apiMod.hasSessionToken(), true);
    scanHistoryMod.upsertHistory(
      {scanId: 'cached-old-path', repoUrl: 'https://github.com/example/old-cache'},
      {origin: 'http://127.0.0.1:19210', sessionScope: cfgOld.sessionScope},
    );

    // Start async requests on /old-path
    const oldHealthPromise = apiMod.api.health();
    const oldHistoryPromise = historySyncMod.syncHistoryFromApi({
      origin: 'http://127.0.0.1:19210',
      sessionScope: cfgOld.sessionScope,
    });
    await new Promise((r) => setTimeout(r, 20));

    // Switch to /new-path on the EXACT SAME origin
    const prevScope = apiMod.getAuthSessionScope();
    apiMod.setApiBaseUrl('http://127.0.0.1:19210/new-path');
    const nextScope = apiMod.getAuthSessionScope();
    assert.notEqual(nextScope, prevScope, 'Switching /old-path -> /new-path on same origin must rotate sessionScope');
    assert.equal(apiMod.hasSessionToken(), true, 'Same-origin path change must keep valid Bearer token');

    // Late responses from /old-path resolve AFTER switch
    releaseOldHealth();
    releaseOldHistory?.();

    await assert.rejects(
      () => oldHealthPromise,
      (err) => err instanceof apiMod.ApiError && err.abortedByConfigChange === true,
      'Late response from /old-path must be rejected as abortedByConfigChange',
    );
    const lateHist = await oldHistoryPromise;
    assert.deepEqual(lateHist, {stale: true}, 'Late history sync from /old-path must return {stale: true}');
    assert.equal(
      scanHistoryMod.readHistory('http://127.0.0.1:19210', {sessionScope: nextScope}).length,
      0,
      'Cache from /old-path must never leak into /new-path session',
    );

    // Fresh request on /new-path succeeds AND still carries the same-origin Bearer token
    const newHealth = await apiMod.api.health();
    assert.equal(newHealth.from, 'new-path');
    const newReq = seen.find((r) => r.url === 'http://127.0.0.1:19210/new-path/api/health');
    assert.ok(newReq);
    assert.equal(newReq.auth, `Bearer ${tok}`);

    // A3. Re-applying equivalent normalized URL (trailing slash / default port) does NOT rotate session unnecessarily
    apiMod.setApiBaseUrl('http://127.0.0.1:80/same');
    apiMod.setSessionToken(tok);
    const scopeBeforeNoop = apiMod.getAuthSessionScope();
    apiMod.setApiBaseUrl('http://127.0.0.1/same/');
    assert.equal(apiMod.getAuthSessionScope(), scopeBeforeNoop, 'Equivalent normalized baseUrl must preserve active session');
    assert.equal(apiMod.hasSessionToken(), true);

    // A4. resetApiBaseUrl() from same-origin subpath to default root rotates session and invalidates old in-flight request while preserving same-origin token
    let releaseSubpath;
    global.fetch = (url) => {
      if (String(url).includes('/sub/api/health')) {
        return new Promise((resolve) => {
          releaseSubpath = () => resolve(jsonResp(200, {status: 'OK', from: 'sub'}));
        });
      }
      return Promise.resolve(jsonResp(200, {status: 'OK', from: 'root'}));
    };
    apiMod.setApiBaseUrl('http://127.0.0.1:18765/sub');
    apiMod.setSessionToken(tok);
    const subScope = apiMod.getAuthSessionScope();
    const subReq = apiMod.api.health();
    apiMod.resetApiBaseUrl();
    assert.equal(apiMod.getApiBaseUrl(), 'http://127.0.0.1:18765');
    assert.notEqual(apiMod.getAuthSessionScope(), subScope, 'resetApiBaseUrl changing path must rotate sessionScope');
    assert.equal(apiMod.hasSessionToken(), true, 'resetApiBaseUrl staying on same origin preserves token');
    releaseSubpath();
    await assert.rejects(() => subReq, (err) => err instanceof apiMod.ApiError && err.abortedByConfigChange === true);
  } finally {
    global.fetch = prevFetch;
    dom.restore();
  }
});

test('Root Cause B: Scanner / liveScan / scanOverview enforce global consistency across total, status counters, and pagination before ever reporting NO_FINDINGS', async () => {
  const dom = installMiniDom();
  const prevFetch = global.fetch;

  try {
    const {apiMod, liveScanMod, scanOverviewMod, scanHistoryMod} = loadAppBundle();
    apiMod.configureApiConnection({baseUrl: 'http://127.0.0.1:19211', token: 'tok-rc-b-123456'});

    // Table of contradictory payloads that MUST NOT be treated as valid NO_FINDINGS or clean scans
    const contradictoryCases = [
      {
        name: 'Codex counterexample: total=0, findings=[], OPEN=1, total_pages=2',
        summary: {scan_id: 's-b1', total_findings: 0, by_human_review_state: {OPEN: 1, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0}},
        page: {scan_id: 's-b1', total_count: 0, total_matching: 0, page: 1, page_size: 50, total_pages: 2, findings: []},
      },
      {
        name: 'total=0, findings=[], total_pages=2 alone',
        summary: {scan_id: 's-b2', total_findings: 0},
        page: {scan_id: 's-b2', total_count: 0, total_pages: 2, findings: []},
      },
      {
        name: 'total=0, findings=[], by_validated_status.SUPPORTED=1',
        summary: {scan_id: 's-b3', total_findings: 0, by_validated_status: {SUPPORTED: 1, REFUTED: 0, UNDETERMINED: 0}},
        page: {scan_id: 's-b3', total_count: 0, total_pages: 1, findings: []},
      },
      {
        name: 'total=0, findings=[], by_cwe has CWE-22=1',
        summary: {scan_id: 's-b4', total_findings: 0, by_cwe: {'CWE-22': 1}},
        page: {scan_id: 's-b4', total_count: 0, findings: []},
      },
      {
        name: 'total=0, findings=[], has_more=true',
        summary: {scan_id: 's-b5', total_findings: 0},
        page: {scan_id: 's-b5', total_count: 0, has_more: true, findings: []},
      },
      {
        name: 'total=2, status breakdown sums to 3 (> total)',
        summary: {
          scan_id: 's-b6',
          total_findings: 2,
          by_validated_status: {SUPPORTED: 2, REFUTED: 1, UNDETERMINED: 0},
        },
        page: {
          scan_id: 's-b6',
          total_count: 2,
          findings: [
            {finding_id: 'f1', validated_status: 'SUPPORTED', human_review_state: 'OPEN'},
            {finding_id: 'f2', validated_status: 'REFUTED', human_review_state: 'OPEN'},
          ],
        },
      },
      {
        name: 'total=2, page_size=50, total_pages=3 (pagination mismatch)',
        summary: {scan_id: 's-b7', total_findings: 2},
        page: {
          scan_id: 's-b7',
          total_count: 2,
          page: 1,
          page_size: 50,
          total_pages: 3,
          findings: [
            {finding_id: 'f1', validated_status: 'SUPPORTED', human_review_state: 'OPEN'},
            {finding_id: 'f2', validated_status: 'REFUTED', human_review_state: 'OPEN'},
          ],
        },
      },
      {
        name: 'summary total_findings=2 vs page total_count=1',
        summary: {scan_id: 's-b8', total_findings: 2},
        page: {
          scan_id: 's-b8',
          total_count: 1,
          findings: [{finding_id: 'f1', validated_status: 'SUPPORTED', human_review_state: 'OPEN'}],
        },
      },
      {
        name: 'negative status counter (-1)',
        summary: {scan_id: 's-b9', total_findings: 0, by_human_review_state: {OPEN: -1}},
        page: {scan_id: 's-b9', total_count: 0, findings: []},
      },
      {
        name: 'total=1 with null finding item',
        summary: {scan_id: 's-b10', total_findings: 1},
        page: {scan_id: 's-b10', total_count: 1, findings: [null]},
      },
    ];

    for (const tc of contradictoryCases) {
      const ds = liveScanMod.buildDataset(tc.summary.scan_id, tc.summary, tc.page);
      assert.equal(ds.incomplete, true, `buildDataset must reject contradictory case: ${tc.name}`);
      assert.equal(ds.counts.confirmedNoFindings, false, `must never confirm NO_FINDINGS for: ${tc.name}`);

      // loadLiveScan must reject AND never write contradictory result into cache/history
      global.fetch = async (url) => {
        if (String(url).includes('/findings')) return jsonResp(200, tc.page);
        return jsonResp(200, tc.summary);
      };
      await assert.rejects(
        () => liveScanMod.loadLiveScan(tc.summary.scan_id),
        (err) => err instanceof apiMod.ApiError,
        `loadLiveScan must reject contradictory case: ${tc.name}`,
      );
      const cached = scanHistoryMod.readHistory(apiMod.getApiOrigin(), {sessionScope: apiMod.getAuthSessionScope()});
      assert.equal(
        cached.some((r) => r.scanId === tc.summary.scan_id),
        false,
        `Contradictory scan must not be written to history cache: ${tc.name}`,
      );
    }

    // verifyCompleteness (LiveFindings path) also rejects Codex counterexample (total=0, OPEN=1, total_pages=2)
    global.fetch = async () => jsonResp(200, {
      scan_id: 's-b1',
      total_count: 0,
      total_matching: 0,
      page: 1,
      page_size: 200,
      total_pages: 2,
      findings: [],
    });
    const foundB1 = await apiMod.api.allFindingsPages('s-b1');
    assert.equal(foundB1.complete, false, 'allFindingsPages must mark total=0 with total_pages=2 as incomplete');
    const checkB1 = scanOverviewMod.verifyCompleteness(
      {scan_id: 's-b1', total_findings: 0, by_human_review_state: {OPEN: 1}},
      [],
      {items: [], total: 0, totalMatching: 0, hasFindingsArray: true, complete: true, meta: {total_pages: 2}},
    );
    assert.equal(checkB1.complete, false, 'verifyCompleteness must reject contradictory summary counters and pagination');

    // Positive control: consistent empty scan (total=0, all counters=0, total_pages=1, findings=[])
    const dsCleanZero = liveScanMod.buildDataset(
      's-clean-zero',
      {
        scan_id: 's-clean-zero',
        total_findings: 0,
        by_validated_status: {SUPPORTED: 0, REFUTED: 0, UNDETERMINED: 0},
        by_human_review_state: {OPEN: 0, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0},
        proposed_refuted_open_count: 0,
        by_cwe: {},
      },
      {scan_id: 's-clean-zero', total_count: 0, total_matching: 0, page: 1, page_size: 50, total_pages: 1, findings: []},
    );
    assert.equal(dsCleanZero.incomplete, false);
    assert.equal(dsCleanZero.counts.total, 0);
    assert.equal(dsCleanZero.counts.confirmedNoFindings, true);
    assert.equal(dsCleanZero.counts.refutedOpen, 0);
  } finally {
    global.fetch = prevFetch;
    dom.restore();
  }
});

test('Root Cause C: REFUTED+OPEN validates numeric bounds against total/axes, refuses duplicate IDs, refuses missing human_review_state as OPEN, and preserves backward compatibility', async () => {
  const dom = installMiniDom();
  try {
    const {liveScanMod, reportModelMod} = loadAppBundle();

    // C1. Codex counterexample: total=0 with proposed_refuted_open_count=1 MUST be rejected as inconsistent
    const c1 = liveScanMod.buildDataset(
      's-c1',
      {
        scan_id: 's-c1',
        total_findings: 0,
        by_validated_status: {SUPPORTED: 0, REFUTED: 0, UNDETERMINED: 0},
        by_human_review_state: {OPEN: 0, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0},
        proposed_refuted_open_count: 1,
      },
      {scan_id: 's-c1', total_count: 0, total_matching: 0, page: 1, total_pages: 1, findings: []},
    );
    assert.equal(c1.incomplete, true, 'proposed_refuted_open_count=1 when total=0 must fail consistency check');
    assert.equal(c1.counts.refutedOpen, null, 'Out-of-bounds proposed_refuted_open_count must return null');
    assert.equal(c1.counts.confirmedNoFindings, false);

    // C2. proposed_refuted_open_count exceeding REFUTED or OPEN axis MUST be rejected
    const c2 = liveScanMod.buildDataset(
      's-c2',
      {
        scan_id: 's-c2',
        total_findings: 3,
        by_validated_status: {SUPPORTED: 2, REFUTED: 1, UNDETERMINED: 0},
        by_human_review_state: {OPEN: 3, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0},
        proposed_refuted_open_count: 2,
      },
      {
        scan_id: 's-c2',
        total_count: 3,
        findings: [
          {finding_id: 'a', validated_status: 'SUPPORTED', human_review_state: 'OPEN'},
          {finding_id: 'b', validated_status: 'SUPPORTED', human_review_state: 'OPEN'},
          {finding_id: 'c', validated_status: 'REFUTED', human_review_state: 'OPEN'},
        ],
      },
    );
    assert.equal(c2.incomplete, true);
    assert.equal(c2.counts.refutedOpen, null);

    // C3. Codex counterexample: duplicate finding_id in findings MUST NOT double-count REFUTED+OPEN
    const c3 = liveScanMod.buildDataset(
      's-c3',
      {
        scan_id: 's-c3',
        total_findings: 2,
        by_validated_status: {SUPPORTED: 0, REFUTED: 2, UNDETERMINED: 0},
        by_human_review_state: {OPEN: 2, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0},
      },
      {
        scan_id: 's-c3',
        total_count: 2,
        findings: [
          {finding_id: 'dup-id', validated_status: 'REFUTED', human_review_state: 'OPEN'},
          {finding_id: 'dup-id', validated_status: 'REFUTED', human_review_state: 'OPEN'},
        ],
      },
    );
    assert.equal(c3.counts.refutedOpen, null, 'Duplicate finding IDs must yield undetermined (null), never double-counted 2');

    // C4. Codex counterexample: missing human_review_state MUST NOT default to OPEN when counting REFUTED+OPEN
    const c4 = liveScanMod.buildDataset(
      's-c4',
      {
        scan_id: 's-c4',
        total_findings: 2,
        by_validated_status: {SUPPORTED: 0, REFUTED: 2, UNDETERMINED: 0},
        by_human_review_state: {OPEN: 1, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 1},
      },
      {
        scan_id: 's-c4',
        total_count: 2,
        findings: [
          {finding_id: 'f1', validated_status: 'REFUTED', human_review_state: 'CONFIRMED_FALSE'},
          {finding_id: 'f2', validated_status: 'REFUTED'}, // missing human_review_state!
        ],
      },
    );
    assert.equal(c4.counts.refutedOpen, null, 'Missing human_review_state must NOT be counted as OPEN');

    // C4b. Missing human_review_state AND omitted by_human_review_state MUST yield open=null and refutedOpen=null (never 0!)
    const c4b = liveScanMod.buildDataset(
      's-c4b',
      {scan_id: 's-c4b', total_findings: 1},
      {
        scan_id: 's-c4b',
        total_count: 1,
        findings: [{finding_id: 'f-no-human', validated_status: 'REFUTED'}],
      },
    );
    assert.equal(c4b.counts.open, null, 'Missing human_review_state with omitted summary breakdown must not fabricate open=0');
    assert.equal(c4b.counts.refutedOpen, null, 'Missing human_review_state with omitted summary breakdown must yield refutedOpen=null');

    // C5. reportModel also rejects missing human_review_state & duplicate IDs when computing refutedStillOpen
    const repMissingState = reportModelMod.buildReportViewModel({
      data_origin: 'REAL_SCAN',
      scan_summary: {
        scan_id: 's-rep-c5',
        total_findings: 1,
        by_validated_status: {SUPPORTED: 0, REFUTED: 1, UNDETERMINED: 0},
        by_human_review_state: {OPEN: 1, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0},
      },
      findings: [{finding_id: 'f1', validated_status: 'REFUTED'}], // missing human_review_state
    });
    assert.equal(repMissingState.humanReviewStats.refutedStillOpen, null);

    const repDupIds = reportModelMod.buildReportViewModel({
      data_origin: 'REAL_SCAN',
      scan_summary: {
        scan_id: 's-rep-c5b',
        total_findings: 2,
        by_validated_status: {SUPPORTED: 0, REFUTED: 2, UNDETERMINED: 0},
        by_human_review_state: {OPEN: 2, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0},
      },
      findings: [
        {finding_id: 'dup', validated_status: 'REFUTED', human_review_state: 'OPEN'},
        {finding_id: 'dup', validated_status: 'REFUTED', human_review_state: 'OPEN'},
      ],
    });
    assert.equal(repDupIds.humanReviewStats.refutedStillOpen, null);

    // C6. Backward compatibility: legacy backend WITHOUT proposed_refuted_open_count, full unique list with explicit states -> exact count
    const c6 = liveScanMod.buildDataset(
      's-c6',
      {
        scan_id: 's-c6',
        total_findings: 3,
        by_validated_status: {SUPPORTED: 1, REFUTED: 2, UNDETERMINED: 0},
        by_human_review_state: {OPEN: 2, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 1},
      },
      {
        scan_id: 's-c6',
        total_count: 3,
        findings: [
          {finding_id: 'u1', validated_status: 'SUPPORTED', human_review_state: 'OPEN'},
          {finding_id: 'u2', validated_status: 'REFUTED', human_review_state: 'OPEN'},
          {finding_id: 'u3', validated_status: 'REFUTED', human_review_state: 'CONFIRMED_FALSE'},
        ],
      },
    );
    assert.equal(c6.incomplete, false);
    assert.equal(c6.counts.refuted, 2);
    assert.equal(c6.counts.refutedOpen, 1);

    // C7. Backend WITH valid proposed_refuted_open_count on paginated scan (page 1 has 2/10) -> trusts validated bound
    const c7 = liveScanMod.buildDataset(
      's-c7',
      {
        scan_id: 's-c7',
        total_findings: 10,
        by_validated_status: {SUPPORTED: 3, REFUTED: 5, UNDETERMINED: 2},
        by_human_review_state: {OPEN: 6, CONFIRMED_TRUE: 1, CONFIRMED_FALSE: 3},
        proposed_refuted_open_count: 2,
      },
      {
        scan_id: 's-c7',
        total_count: 10,
        page: 1,
        page_size: 2,
        total_pages: 5,
        findings: [
          {finding_id: 'p1', validated_status: 'REFUTED', human_review_state: 'OPEN'},
          {finding_id: 'p2', validated_status: 'REFUTED', human_review_state: 'CONFIRMED_FALSE'},
        ],
      },
    );
    assert.equal(c7.incomplete, false);
    assert.equal(c7.counts.refutedOpen, 2);
  } finally {
    dom.restore();
  }
});

test('Root Cause D: History treats both /api/scan-jobs and /api/scans as required, validates every item without TypeError on [null]/[{}], and reports incomplete sync honestly', async () => {
  const dom = installMiniDom();
  const prevFetch = global.fetch;

  try {
    const {apiMod, historySyncMod, scanHistoryMod, HistoryPage, Results, h, mountWithOutlet} = loadAppBundle();
    const ORIGIN_D = 'http://127.0.0.1:19212';
    apiMod.configureApiConnection({baseUrl: ORIGIN_D, token: 'tok-rc-d-123456'});

    // D1. Codex counterexample: /api/scan-jobs returns 404 while /api/scans succeeds -> MUST NOT claim full sync!
    global.fetch = async (url) => {
      const u = new URL(url);
      if (u.pathname === '/api/scan-jobs') return jsonResp(404, {error_code: 'NOT_FOUND'});
      if (u.pathname === '/api/scans') {
        return jsonResp(200, {
          total_count: 1,
          scans: [{scan_id: 'scan-only-ok', repo_url: 'https://github.com/example/d1', completed_at: '2026-11-21T01:00:00Z'}],
        });
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const d1 = await historySyncMod.syncHistoryFromApi({origin: ORIGIN_D});
    assert.equal(d1.stale, false);
    assert.equal(d1.supported, false, 'When required /api/scan-jobs returns 404, sync must NOT report supported: true');
    assert.equal(d1.incomplete, true, 'Missing required endpoint /api/scan-jobs must set incomplete: true');
    assert.equal(d1.records.length, 1, 'Valid /api/scans record must still be preserved');
    assert.equal(d1.records[0].scanId, 'scan-only-ok');
    assert.ok(d1.endpointStatuses['/api/scan-jobs']?.status === 'UNSUPPORTED');
    assert.ok(d1.endpointStatuses['/api/scans']?.status === 'COMPLETE');

    // D2. Codex counterexample: total_count=1 with [{}] (zero valid records remaining) -> MUST NOT report full sync!
    global.fetch = async (url) => {
      const u = new URL(url);
      if (u.pathname === '/api/scan-jobs') return jsonResp(200, {total_count: 0, jobs: []});
      if (u.pathname === '/api/scans') return jsonResp(200, {total_count: 1, scans: [{}]});
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const d2 = await historySyncMod.syncHistoryFromApi({origin: ORIGIN_D});
    assert.equal(d2.supported, false, 'scans:[{}] with total_count=1 must NOT succeed as complete sync');
    assert.equal(d2.incomplete, true);
    assert.equal(d2.backendRecords.length, 0, 'Must never fabricate a placeholder record for {}');

    // D3. Codex counterexample: [null] and mixed [null, valid] MUST NOT throw TypeError!
    assert.equal(scanHistoryMod.historyRecordFromBackend(null, {origin: ORIGIN_D}), null);
    assert.equal(scanHistoryMod.historyRecordFromBackend(undefined, {origin: ORIGIN_D}), null);
    assert.equal(scanHistoryMod.historyRecordFromBackend('bad', {origin: ORIGIN_D}), null);

    for (const [label, scansPayload] of Object.entries({
      contractNull: {total_count: 1, scans: [null]},
      legacyArrayNull: [null],
      mixedNullAndValid: {
        total_count: 2,
        scans: [null, {scan_id: 'scan-valid-amid-null', repo_url: 'https://github.com/example/d3'}],
      },
    })) {
      global.fetch = async (url) => {
        const u = new URL(url);
        if (u.pathname === '/api/scan-jobs') return jsonResp(200, {total_count: 0, jobs: []});
        if (u.pathname === '/api/scans') return jsonResp(200, scansPayload);
        return jsonResp(404, {error_code: 'NOT_FOUND'});
      };
      const out = await historySyncMod.syncHistoryFromApi({origin: ORIGIN_D});
      assert.equal(out.supported, false, `${label}: must NOT report supported: true`);
      assert.equal(out.incomplete, true, `${label}: must report incomplete: true`);
      if (label === 'mixedNullAndValid') {
        assert.equal(out.backendRecords.length, 1, 'mixedNullAndValid must preserve the 1 valid scan without fabricating');
        assert.equal(out.backendRecords[0].scanId, 'scan-valid-amid-null');
      } else {
        assert.equal(out.backendRecords.length, 0);
      }
    }

    // D4. Mounted HistoryPage shows warning when /api/scan-jobs is 404 while still rendering the valid scan from /api/scans
    apiMod.configureApiConnection({baseUrl: ORIGIN_D, token: 'tok-rc-d-ui-777'});
    global.fetch = async (url) => {
      const u = new URL(url);
      if (u.pathname === '/api/scan-jobs') return jsonResp(404, {error_code: 'NOT_FOUND'});
      if (u.pathname === '/api/scans') {
        return jsonResp(200, {
          total_count: 1,
          scans: [{scan_id: 'scan-d4-ok', repo_url: 'https://github.com/example/d4-kept', completed_at: '2026-11-21T02:00:00Z'}],
        });
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedHist = mountWithOutlet(h(HistoryPage), {
      initialEntry: '/history',
      outletContext: {
        apiOrigin: apiMod.getApiOrigin(),
        authSessionScope: apiMod.getAuthSessionScope(),
        apiRevision: apiMod.getApiConfigRevision(),
      },
    });
    try {
      await waitFor(() => /d4-kept/.test(mountedHist.container.textContent) && /\/api\/scan-jobs|chưa đầy đủ/i.test(mountedHist.container.textContent));
      const text = mountedHist.container.textContent;
      assert.match(text, /d4-kept/);
      assert.match(text, /\/api\/scan-jobs|chưa đầy đủ|HTTP_404/i);
    } finally {
      mountedHist.unmount();
    }

    // D5. Results picker tolerates [null, {}] in /api/scans without crashing
    global.fetch = async (url) => {
      if (new URL(url).pathname === '/api/scans') return jsonResp(200, {total_count: 2, scans: [null, {}]});
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedRes = mountWithOutlet(h(Results), {
      initialEntry: '/findings',
      outletContext: {
        apiOrigin: apiMod.getApiOrigin(),
        authSessionScope: apiMod.getAuthSessionScope(),
        apiRevision: apiMod.getApiConfigRevision(),
      },
    });
    try {
      await waitFor(() => /Chưa có phiên phân tích nào|chưa đầy đủ/i.test(mountedRes.container.textContent));
      assert.match(mountedRes.container.textContent, /chưa đầy đủ|INVALID_LIST_ITEMS/i);
    } finally {
      mountedRes.unmount();
    }
  } finally {
    global.fetch = prevFetch;
    dom.restore();
  }
});

test('Root Cause E: Data provenance label REAL_SCAN never self-attests; missing capture proof, unverified/imported origin, or mock evidence flags fail-closed across Results, Review, LiveFindings, and reportModel', async () => {
  const dom = installMiniDom();
  const prevFetch = global.fetch;

  try {
    const {apiMod, findingPresMod, reportModelMod, Results, FindingDetail, ReviewPage, h, mountWithOutlet} = loadAppBundle();
    const {classifyDataOrigin} = findingPresMod;

    // E1. Self-attesting REAL_SCAN WITHOUT scan_provenance -> MUST fail-closed to UNVERIFIED_ORIGIN
    const missingProv = classifyDataOrigin({scan_id: 's1', data_origin: 'REAL_SCAN'});
    assert.equal(missingProv.isVerifiedRealScan, false);
    assert.notEqual(missingProv.code, 'REAL_SCAN');
    assert.equal(missingProv.code, 'UNVERIFIED_ORIGIN');

    // E2. REAL_SCAN with partial capture proof (missing exit_capture_verified: true) -> UNVERIFIED_ORIGIN
    const partialProv = classifyDataOrigin({
      scan_id: 's2',
      data_origin: 'REAL_SCAN',
      scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: true},
    });
    assert.equal(partialProv.isVerifiedRealScan, false);
    assert.equal(partialProv.code, 'UNVERIFIED_ORIGIN');

    // E3. REAL_SCAN whose scan_provenance.origin says imported/collection_only/declared_only/unverified -> NOT REAL_SCAN
    for (const badProvOrigin of ['collection_only', 'declared_only', 'imported_unverified', 'unverified_capture', 'manual_import', 'unknown']) {
      const res = classifyDataOrigin({
        scan_id: 's3',
        data_origin: 'REAL_SCAN',
        scan_provenance: {origin: badProvOrigin, source_capture_verified: true, exit_capture_verified: true},
      });
      assert.equal(res.isVerifiedRealScan, false, `scan_provenance.origin=${badProvOrigin} must NOT verify as REAL_SCAN`);
      assert.notEqual(res.code, 'REAL_SCAN');
    }

    // E4. REAL_SCAN whose evidence/runtime carries mock flags -> classified as MOCK_SYNTHETIC_TEST
    for (const [label, payload] of Object.entries({
      evidenceIsTestOrMock: {
        scan_id: 's4a',
        data_origin: 'REAL_SCAN',
        scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: true, exit_capture_verified: true},
        evidence: {is_test_or_mock: true, scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: true, exit_capture_verified: true}},
      },
      evidenceMockFlag: {
        scan_id: 's4b',
        data_origin: 'REAL_SCAN',
        evidence: {mock: true, scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: true, exit_capture_verified: true}},
      },
      evidenceIsMockFlag: {
        scan_id: 's4b2',
        data_origin: 'REAL_SCAN',
        evidence: {is_mock: true, scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: true, exit_capture_verified: true}},
      },
      runtimeSummaryMockRecords: {
        scan_id: 's4c',
        data_origin: 'REAL_SCAN',
        scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: true, exit_capture_verified: true},
        runtime_summary: {mock_records: 1},
      },
      assessmentRuntimeMockFlag: {
        scan_id: 's4d',
        data_origin: 'REAL_SCAN',
        evidence: {scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: true, exit_capture_verified: true}},
        assessment: {runtime: {mock: true}},
      },
    })) {
      const res = classifyDataOrigin(payload);
      assert.equal(res.isMockOrTest, true, `${label} must be classified as mock/test`);
      assert.equal(res.code, 'MOCK_SYNTHETIC_TEST');
      assert.equal(res.isVerifiedRealScan, false);
    }

    // E5. reportModel uses centralized provenance classifier: REAL_SCAN without capture proof cannot display REAL_SCAN;
    //     evidence mock flag blocks report export!
    const repNoProof = reportModelMod.buildReportViewModel({
      data_origin: 'REAL_SCAN',
      scan_summary: {scan_id: 's-rep-no-proof', total_findings: 0},
      findings: [],
    });
    assert.notEqual(repNoProof.dataOrigin, 'REAL_SCAN', 'Report without scan_provenance must not claim REAL_SCAN');
    assert.equal(repNoProof.isMockOrTest, false);

    const repEvidenceMock = reportModelMod.buildReportViewModel({
      data_origin: 'REAL_SCAN',
      scan_summary: {
        scan_id: 's-rep-mock-ev',
        scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: true, exit_capture_verified: true},
        total_findings: 1,
      },
      findings: [{finding_id: 'f1', evidence: {is_test_or_mock: true}}],
    });
    assert.equal(repEvidenceMock.isMockOrTest, true, 'Report with mock flag inside finding evidence must block export');
    assert.equal(repEvidenceMock.canExportReport, false);

    // E6. Valid complete runtime provenance stays REAL_SCAN without over-blocking!
    const validReal = classifyDataOrigin({
      scan_id: 's-valid-real',
      data_origin: 'REAL_SCAN',
      is_test_or_mock: false,
      scan_provenance: {
        origin: 'recorded_capture_unsigned',
        source_capture_verified: true,
        exit_capture_verified: true,
        recorded_engine_exit: 0,
      },
      runtime_summary: {mock_records: 0, warnings: 1},
    });
    assert.equal(validReal.code, 'REAL_SCAN');
    assert.equal(validReal.isVerifiedRealScan, true);
    assert.equal(validReal.isMockOrTest, false);

    // E7. Mounted Results picker & FindingDetail & ReviewPage enforce fail-closed provenance end-to-end
    const ORIGIN_E = 'http://127.0.0.1:19213';
    apiMod.configureApiConnection({baseUrl: ORIGIN_E, token: 'tok-rc-e-123456'});

    global.fetch = async (url) => {
      const u = new URL(url);
      if (u.pathname === '/api/scans') {
        return jsonResp(200, {
          total_count: 2,
          scans: [
            {scan_id: 'scan-self-attest', data_origin: 'REAL_SCAN', repo_url: 'https://github.com/example/self-attest'},
            {
              scan_id: 'scan-proven-real',
              data_origin: 'REAL_SCAN',
              scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: true, exit_capture_verified: true, recorded_engine_exit: 0},
              repo_url: 'https://github.com/example/proven-real',
            },
          ],
        });
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedPicker = mountWithOutlet(h(Results), {
      initialEntry: '/findings',
      outletContext: {
        apiOrigin: apiMod.getApiOrigin(),
        authSessionScope: apiMod.getAuthSessionScope(),
        apiRevision: apiMod.getApiConfigRevision(),
      },
    });
    try {
      await waitFor(() => /self-attest/.test(mountedPicker.container.textContent));
      const cards = mountedPicker.container.querySelectorAll('.v2-scan-picker-row').map((c) => c.textContent);
      const selfCard = cards.find((t) => t.includes('self-attest'));
      const realCard = cards.find((t) => t.includes('proven-real'));
      assert.ok(selfCard);
      assert.doesNotMatch(selfCard, /REAL_SCAN/, 'Self-attesting REAL_SCAN without scan_provenance must NOT display REAL_SCAN');
      assert.ok(realCard);
      assert.match(realCard, /REAL_SCAN/);
    } finally {
      mountedPicker.unmount();
    }

    // FindingDetail with data_origin=REAL_SCAN but evidence.is_test_or_mock=true -> blocked as mock!
    global.fetch = async (url) => {
      if (new URL(url).pathname === '/api/scans/s-evmock/findings/f-evmock') {
        return jsonResp(200, {
          scan_id: 's-evmock',
          finding_id: 'f-evmock',
          data_origin: 'REAL_SCAN',
          cwe: 'CWE-22',
          evidence: {
            is_test_or_mock: true,
            path: 'A.java',
            start: {line: 1},
            snippets: [],
            snapshots: {},
            scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: true, exit_capture_verified: true, recorded_engine_exit: 0},
          },
          assessment: {validated_status: 'SUPPORTED', citations: []},
        });
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedEvMock = mountWithOutlet(h(FindingDetail), {
      initialEntry: '/finding/f-evmock?scan_id=s-evmock',
      routePath: '/finding/:id',
      outletContext: {
        apiOrigin: apiMod.getApiOrigin(),
        authSessionScope: apiMod.getAuthSessionScope(),
        apiRevision: apiMod.getApiConfigRevision(),
      },
    });
    try {
      await waitFor(() => /Dữ liệu mô phỏng \(mock\) bị chặn/.test(mountedEvMock.container.textContent));
      assert.match(mountedEvMock.container.textContent, /Dữ liệu mô phỏng \(mock\) bị chặn/);
      assert.doesNotMatch(mountedEvMock.container.textContent, /REAL_SCAN/);
    } finally {
      mountedEvMock.unmount();
    }

    // ReviewPage blocks queue carrying mock evidence even if labeled REAL_SCAN
    global.fetch = async (url) => {
      const u = new URL(url);
      if (u.pathname === '/api/scans/s-rev-mock/review-queue') {
        return jsonResp(200, {
          scan_id: 's-rev-mock',
          data_origin: 'REAL_SCAN',
          scan_provenance: {origin: 'UNIT_TEST_MOCK_CAPTURE', source_capture_verified: true, exit_capture_verified: true},
          counts: {open_count: 1},
          warnings: [{finding_id: 'f1', scan_id: 's-rev-mock', cwe: 'CWE-22', validated_status: 'SUPPORTED', human_review_state: 'OPEN'}],
        });
      }
      if (u.pathname === '/api/scans/s-rev-mock/review-history') {
        return jsonResp(200, {scan_id: 's-rev-mock', events: [], rejected_decisions: []});
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedRevMock = mountWithOutlet(h(ReviewPage), {
      initialEntry: '/review?scan_id=s-rev-mock',
      outletContext: {
        apiOrigin: apiMod.getApiOrigin(),
        authSessionScope: apiMod.getAuthSessionScope(),
        apiRevision: apiMod.getApiConfigRevision(),
      },
    });
    try {
      await waitFor(() => /Dữ liệu mô phỏng \(mock\) bị chặn/.test(mountedRevMock.container.textContent));
      assert.match(mountedRevMock.container.textContent, /Dữ liệu mô phỏng \(mock\) bị chặn/);
    } finally {
      mountedRevMock.unmount();
    }
  } finally {
    global.fetch = prevFetch;
    dom.restore();
  }
});

// =================================================================================================
// THREE-CASE REAUDIT REGRESSION SUITE (Targeted Counterexamples B, C, E + Positive Controls)
// =================================================================================================

test('Three-Case Reaudit B: Pagination contradictions (total_count=1, total_pages=1, has_more=true) never complete or write cache/history while valid single/multi/empty scans pass', async () => {
  const dom = installMiniDom();
  const prevFetch = global.fetch;

  try {
    const {apiMod, liveScanMod, scanOverviewMod, scanHistoryMod, LiveFindings, h, mountWithOutlet} = loadAppBundle();
    const ORIGIN_B = 'http://127.0.0.1:19230';
    apiMod.configureApiConnection({baseUrl: ORIGIN_B, token: 'tok-3case-b-123456'});

    const cleanSummary = (scanId, totalFindings) => ({
      scan_id: scanId,
      data_origin: 'REAL_SCAN',
      scan_provenance: {
        origin: 'recorded_capture_unsigned',
        source_capture_verified: true,
        exit_capture_verified: true,
        recorded_engine_exit: 0,
      },
      total_findings: totalFindings,
      by_validated_status: {SUPPORTED: totalFindings, REFUTED: 0, UNDETERMINED: 0},
      by_human_review_state: {OPEN: totalFindings, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0},
      by_cwe: totalFindings ? {'CWE-22': totalFindings} : {},
    });
    const mkItem = (id) => ({finding_id: id, cwe: 'CWE-22', validated_status: 'SUPPORTED', human_review_state: 'OPEN'});

    // B-CE-1. Exact Codex counterexample: total_count=1, 1 finding, total_pages=1, has_more=true
    const sumB = cleanSummary('s-b-hasmore', 1);
    const pageB = {
      scan_id: 's-b-hasmore',
      page: 1,
      page_size: 50,
      total_pages: 1,
      total_count: 1,
      total_matching: 1,
      has_more: true,
      findings: [mkItem('f-b-1')],
    };

    assert.equal(
      liveScanMod.validateScanCountersAndPagination(sumB, pageB).valid,
      false,
      'validateScanCountersAndPagination must reject total_count=1, total_pages=1, has_more=true',
    );
    const dsB = liveScanMod.buildDataset('s-b-hasmore', sumB, pageB);
    assert.equal(dsB.incomplete, true, 'buildDataset must mark total_pages=1 with has_more=true as incomplete');

    global.fetch = async (url) => {
      if (String(url).includes('/findings')) return jsonResp(200, pageB);
      return jsonResp(200, sumB);
    };
    await assert.rejects(
      () => liveScanMod.loadLiveScan('s-b-hasmore'),
      (err) => err instanceof apiMod.ApiError,
      'loadLiveScan must reject contradictory pagination payload instead of caching/completing',
    );
    assert.equal(window.sessionStorage.getItem(liveScanMod.ACTIVE_KEY), null);
    assert.equal(
      scanHistoryMod.readHistory(apiMod.getApiOrigin(), {sessionScope: apiMod.getAuthSessionScope()})
        .some((r) => r.scanId === 's-b-hasmore'),
      false,
      'loadLiveScan must NOT record contradictory scan into history',
    );

    const foundB = await apiMod.api.allFindingsPages('s-b-hasmore');
    assert.equal(foundB.paginationInconsistent, true, 'allFindingsPages must flag total_pages=1 with has_more=true as inconsistent');
    assert.equal(foundB.complete, false, 'allFindingsPages must NOT return complete:true when has_more=true on final page');

    const compB = scanOverviewMod.verifyCompleteness(
      sumB,
      [mkItem('f-b-1')],
      {items: [mkItem('f-b-1')], total: 1, totalMatching: 1, hasFindingsArray: true, complete: true, meta: pageB},
    );
    assert.equal(compB.complete, false, 'verifyCompleteness must reject meta with total_pages=1 and has_more=true');

    // Mounted LiveFindings must warn incomplete rather than reporting complete explorer
    const mountedLiveB = mountWithOutlet(h(LiveFindings, {scanId: 's-b-hasmore'}), {
      initialEntry: '/findings?scan_id=s-b-hasmore',
      outletContext: {
        apiOrigin: apiMod.getApiOrigin(),
        authSessionScope: apiMod.getAuthSessionScope(),
        apiRevision: apiMod.getApiConfigRevision(),
      },
    });
    try {
      await waitFor(() => /Mới tải|chưa đầy đủ|mâu thuẫn|Tải lại/i.test(mountedLiveB.container.textContent));
      assert.match(mountedLiveB.container.textContent, /Mới tải|mâu thuẫn|chưa đầy đủ/i);
    } finally {
      mountedLiveB.unmount();
    }

    // B-CE-2. Matrix of pagination contradictions (next_page / next_cursor / truncated / premature has_more=false / dup IDs across pages)
    const badPages = [
      {label: 'next_page on last page', payload: {...pageB, has_more: false, next_page: 2}},
      {label: 'next_cursor on last page', payload: {...pageB, has_more: false, next_cursor: 'cursor-2'}},
      {label: 'truncated=true', payload: {...pageB, has_more: false, truncated: true}},
      {
        label: 'page 1 of 2 sets has_more=false',
        sum: cleanSummary('s-b-premature', 2),
        payload: {
          scan_id: 's-b-premature',
          page: 1,
          page_size: 1,
          total_pages: 2,
          total_count: 2,
          total_matching: 2,
          has_more: false,
          findings: [mkItem('f-p1')],
        },
      },
    ];
    for (const tc of badPages) {
      const s = tc.sum || sumB;
      assert.equal(
        liveScanMod.validateScanCountersAndPagination(s, tc.payload).valid,
        false,
        `validateScanCountersAndPagination must reject: ${tc.label}`,
      );
      global.fetch = async () => jsonResp(200, tc.payload);
      const af = await apiMod.api.allFindingsPages(s.scan_id);
      assert.equal(af.complete, false, `allFindingsPages must NOT complete for: ${tc.label}`);
    }

    // Multi-page duplicate finding_id across page 1 and page 2
    global.fetch = async (url) => {
      const u = new URL(url);
      const p = Number(u.searchParams.get('page') || 1);
      if (p === 1) {
        return jsonResp(200, {
          scan_id: 's-b-crossdup',
          page: 1,
          page_size: 1,
          total_pages: 2,
          total_count: 2,
          total_matching: 2,
          has_more: true,
          findings: [mkItem('dup-across')],
        });
      }
      return jsonResp(200, {
        scan_id: 's-b-crossdup',
        page: 2,
        page_size: 1,
        total_pages: 2,
        total_count: 2,
        total_matching: 2,
        has_more: false,
        findings: [mkItem('dup-across')],
      });
    };
    const crossDup = await apiMod.api.allFindingsPages('s-b-crossdup');
    assert.equal(crossDup.complete, false, 'Duplicate finding_id across pages must fail allFindingsPages completeness');

    // B-POS. Positive controls: valid empty, valid 1-page, valid 2-page!
    const emptySum = cleanSummary('s-b-pos-0', 0);
    const emptyPage = {scan_id: 's-b-pos-0', page: 1, page_size: 50, total_pages: 1, total_count: 0, total_matching: 0, has_more: false, findings: []};
    global.fetch = async (url) => (String(url).includes('/findings') ? jsonResp(200, emptyPage) : jsonResp(200, emptySum));
    const dsEmptyOk = await liveScanMod.loadLiveScan('s-b-pos-0');
    assert.equal(dsEmptyOk.incomplete, false);
    assert.equal(dsEmptyOk.counts.confirmedNoFindings, true);
    const allEmptyOk = await apiMod.api.allFindingsPages('s-b-pos-0');
    assert.equal(allEmptyOk.complete, true);

    const singleSum = cleanSummary('s-b-pos-1', 1);
    const singlePage = {scan_id: 's-b-pos-1', page: 1, page_size: 50, total_pages: 1, total_count: 1, total_matching: 1, has_more: false, next_page: null, next_cursor: null, findings: [mkItem('f-ok-1')]};
    global.fetch = async (url) => (String(url).includes('/findings') ? jsonResp(200, singlePage) : jsonResp(200, singleSum));
    const dsSingleOk = await liveScanMod.loadLiveScan('s-b-pos-1');
    assert.equal(dsSingleOk.incomplete, false);
    assert.equal(dsSingleOk.counts.total, 1);
    const allSingleOk = await apiMod.api.allFindingsPages('s-b-pos-1');
    assert.equal(allSingleOk.complete, true);
    assert.equal(scanOverviewMod.verifyCompleteness(singleSum, allSingleOk.items, allSingleOk).complete, true);

    const multiSum = cleanSummary('s-b-pos-multi', 3);
    const multiP1 = {scan_id: 's-b-pos-multi', page: 1, page_size: 2, total_pages: 2, total_count: 3, total_matching: 3, has_more: true, next_page: 2, findings: [mkItem('m-1'), mkItem('m-2')]};
    const multiP2 = {scan_id: 's-b-pos-multi', page: 2, page_size: 2, total_pages: 2, total_count: 3, total_matching: 3, has_more: false, next_page: null, findings: [mkItem('m-3')]};
    assert.equal(liveScanMod.validateScanCountersAndPagination(multiSum, multiP1).valid, true, 'Valid page 1 of 2 with has_more=true must pass');
    global.fetch = async (url) => {
      const u = new URL(url);
      if (u.pathname.endsWith('/findings')) {
        return Number(u.searchParams.get('page')) === 2 ? jsonResp(200, multiP2) : jsonResp(200, multiP1);
      }
      return jsonResp(200, multiSum);
    };
    const allMultiOk = await apiMod.api.allFindingsPages('s-b-pos-multi');
    assert.equal(allMultiOk.complete, true, 'Valid 2-page scan must complete cleanly');
    assert.equal(allMultiOk.items.length, 3);
    assert.equal(scanOverviewMod.verifyCompleteness(multiSum, allMultiOk.items, allMultiOk).complete, true);
  } finally {
    global.fetch = prevFetch;
    dom.restore();
  }
});

test('Three-Case Reaudit C: Paginated page 1/2 with duplicate finding_id and summary count=2 fails consistency and yields null while unique explicit data succeeds', async () => {
  const dom = installMiniDom();
  const prevFetch = global.fetch;

  try {
    const {apiMod, liveScanMod, reportModelMod} = loadAppBundle();
    const ORIGIN_C = 'http://127.0.0.1:19231';
    apiMod.configureApiConnection({baseUrl: ORIGIN_C, token: 'tok-3case-c-123456'});

    // C-CE-1. Exact Codex counterexample: page 1/2, two findings share finding_id, summary claims proposed_refuted_open_count=2
    const sumDup = {
      scan_id: 's-c-pag-dup',
      data_origin: 'REAL_SCAN',
      scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: true, exit_capture_verified: true, recorded_engine_exit: 0},
      total_findings: 3,
      by_validated_status: {SUPPORTED: 1, REFUTED: 2, UNDETERMINED: 0},
      by_human_review_state: {OPEN: 2, CONFIRMED_TRUE: 1, CONFIRMED_FALSE: 0},
      proposed_refuted_open_count: 2,
    };
    const pageDup = {
      scan_id: 's-c-pag-dup',
      total_count: 3,
      total_matching: 3,
      page: 1,
      page_size: 2,
      total_pages: 2,
      has_more: true,
      findings: [
        {finding_id: 'dup-id', validated_status: 'REFUTED', human_review_state: 'OPEN'},
        {finding_id: 'dup-id', validated_status: 'REFUTED', human_review_state: 'OPEN'},
      ],
    };
    const dsDup = liveScanMod.buildDataset('s-c-pag-dup', sumDup, pageDup);
    assert.equal(dsDup.incomplete, true, 'Page 1/2 with duplicate finding_id must NOT be incomplete:false');
    assert.equal(dsDup.counts.refutedOpen, null, 'Page 1/2 with duplicate finding_id must return refutedOpen=null, never 2');

    global.fetch = async (url) => (String(url).includes('/findings') ? jsonResp(200, pageDup) : jsonResp(200, sumDup));
    await assert.rejects(() => liveScanMod.loadLiveScan('s-c-pag-dup'), (err) => err instanceof apiMod.ApiError);

    // C-CE-2. Partial page mathematically impossible given summary proposed_refuted_open_count (pigeonhole bound)
    const dsImpossible = liveScanMod.buildDataset(
      's-c-pigeon',
      {
        scan_id: 's-c-pigeon',
        total_findings: 4,
        by_validated_status: {SUPPORTED: 2, REFUTED: 2, UNDETERMINED: 0},
        by_human_review_state: {OPEN: 2, CONFIRMED_TRUE: 1, CONFIRMED_FALSE: 1},
        proposed_refuted_open_count: 2,
      },
      {
        scan_id: 's-c-pigeon',
        total_count: 4,
        page: 1,
        page_size: 2,
        total_pages: 2,
        findings: [
          {finding_id: 'u1', validated_status: 'REFUTED', human_review_state: 'CONFIRMED_FALSE'},
          {finding_id: 'u2', validated_status: 'SUPPORTED', human_review_state: 'OPEN'},
        ],
      },
    );
    assert.equal(dsImpossible.incomplete, true);
    assert.equal(dsImpossible.counts.refutedOpen, null);

    // C-CE-3. Partial page with missing finding_id
    const dsMissingId = liveScanMod.buildDataset(
      's-c-missid',
      sumDup,
      {
        scan_id: 's-c-missid',
        total_count: 3,
        page: 1,
        page_size: 2,
        total_pages: 2,
        findings: [
          {validated_status: 'REFUTED', human_review_state: 'OPEN'},
          {finding_id: 'ok-2', validated_status: 'REFUTED', human_review_state: 'OPEN'},
        ],
      },
    );
    assert.equal(dsMissingId.incomplete, true);
    assert.equal(dsMissingId.counts.refutedOpen, null);

    // C-CE-4. reportModel with duplicate finding_id + summary.proposed_refuted_open_count=2 MUST yield refutedStillOpen=null
    const repDupSummary = reportModelMod.buildReportViewModel({
      data_origin: 'REAL_SCAN',
      scan_summary: {
        scan_id: 's-rep-dup-sum',
        scan_provenance: {origin: 'recorded_capture_unsigned', source_capture_verified: true, exit_capture_verified: true, recorded_engine_exit: 0},
        total_findings: 2,
        by_validated_status: {SUPPORTED: 0, REFUTED: 2, UNDETERMINED: 0},
        by_human_review_state: {OPEN: 2, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0},
        proposed_refuted_open_count: 2,
      },
      findings: [
        {finding_id: 'dup-id', validated_status: 'REFUTED', human_review_state: 'OPEN'},
        {finding_id: 'dup-id', validated_status: 'REFUTED', human_review_state: 'OPEN'},
      ],
    });
    assert.equal(repDupSummary.humanReviewStats.refutedStillOpen, null, 'reportModel must never accept proposed_refuted_open_count when findings contain duplicate IDs');

    // C-POS. Valid positive control (complete unique data with explicit states + consistent partial page)
    const dsValidFull = liveScanMod.buildDataset(
      's-c-valid',
      {
        scan_id: 's-c-valid',
        total_findings: 2,
        by_validated_status: {SUPPORTED: 0, REFUTED: 2, UNDETERMINED: 0},
        by_human_review_state: {OPEN: 1, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 1},
        proposed_refuted_open_count: 1,
      },
      {
        scan_id: 's-c-valid',
        total_count: 2,
        page: 1,
        page_size: 50,
        total_pages: 1,
        findings: [
          {finding_id: 'ok-1', validated_status: 'REFUTED', human_review_state: 'OPEN'},
          {finding_id: 'ok-2', validated_status: 'REFUTED', human_review_state: 'CONFIRMED_FALSE'},
        ],
      },
    );
    assert.equal(dsValidFull.incomplete, false);
    assert.equal(dsValidFull.counts.refutedOpen, 1);

    const dsValidPag = liveScanMod.buildDataset(
      's-c-pag-ok',
      {
        scan_id: 's-c-pag-ok',
        total_findings: 3,
        by_validated_status: {SUPPORTED: 1, REFUTED: 2, UNDETERMINED: 0},
        by_human_review_state: {OPEN: 2, CONFIRMED_TRUE: 1, CONFIRMED_FALSE: 0},
        proposed_refuted_open_count: 2,
      },
      {
        scan_id: 's-c-pag-ok',
        total_count: 3,
        page: 1,
        page_size: 2,
        total_pages: 2,
        has_more: true,
        findings: [
          {finding_id: 'ok-a', validated_status: 'REFUTED', human_review_state: 'OPEN'},
          {finding_id: 'ok-b', validated_status: 'REFUTED', human_review_state: 'OPEN'},
        ],
      },
    );
    assert.equal(dsValidPag.incomplete, false);
    assert.equal(dsValidPag.counts.refutedOpen, 2);
  } finally {
    global.fetch = prevFetch;
    dom.restore();
  }
});

test('Three-Case Reaudit E: evidence.snippets[0].metadata.mock=true and recorded_engine_exit=1 never certify REAL_SCAN or verified report export across Results, Review, and Reports', async () => {
  const dom = installMiniDom();
  const prevFetch = global.fetch;

  try {
    const {apiMod, findingPresMod, reportModelMod, Results, FindingDetail, ReviewPage, ReportsPage, h, mountWithOutlet} = loadAppBundle();
    const {classifyDataOrigin} = findingPresMod;
    const ORIGIN_E = 'http://127.0.0.1:19232';
    apiMod.configureApiConnection({baseUrl: ORIGIN_E, token: 'tok-3case-e-123456'});

    const fullValidProv = {
      origin: 'recorded_capture_unsigned',
      source_capture_verified: true,
      exit_capture_verified: true,
      recorded_engine_exit: 0,
      manifest_sha256: 'a'.repeat(64),
    };
    const exitOneProv = {
      origin: 'recorded_capture_unsigned',
      source_capture_verified: true,
      exit_capture_verified: true,
      recorded_engine_exit: 1,
    };

    // E-CE-1. evidence.snippets[0].metadata.mock = true MUST be detected as MOCK_SYNTHETIC_TEST everywhere
    const snippetMockFinding = {
      scan_id: 's-e-snipmock',
      finding_id: 'f-e-snipmock',
      id: 'f-e-snipmock',
      cwe: 'CWE-22',
      validated_status: 'SUPPORTED',
      human_review_state: 'OPEN',
      data_origin: 'REAL_SCAN',
      is_test_or_mock: false,
      scan_provenance: fullValidProv,
      evidence: {
        id: 'f-e-snipmock',
        path: 'src/FileDemo.java',
        start: {line: 5},
        snapshots: {'src/FileDemo.java': {sha256: 'b'.repeat(64), size: 120}},
        scan_provenance: fullValidProv,
        snippets: [
          {
            role: 'finding',
            path: 'src/FileDemo.java',
            start: {line: 5},
            end: {line: 5},
            metadata: {mock: true},
          },
        ],
      },
      assessment: {validated_status: 'SUPPORTED', citations: [], runtime: {origin: 'unverified', model_runtime_verified: false}},
    };

    const clsSnip = classifyDataOrigin(snippetMockFinding);
    assert.equal(clsSnip.isMockOrTest, true, 'evidence.snippets[0].metadata.mock=true must be classified as mock/test');
    assert.equal(clsSnip.isVerifiedRealScan, false);
    assert.equal(clsSnip.code, 'MOCK_SYNTHETIC_TEST');

    // Also in FindingDetail UI
    global.fetch = async (url) => {
      if (new URL(url).pathname === '/api/scans/s-e-snipmock/findings/f-e-snipmock') {
        return jsonResp(200, snippetMockFinding);
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedFdSnip = mountWithOutlet(h(FindingDetail), {
      initialEntry: '/finding/f-e-snipmock?scan_id=s-e-snipmock',
      routePath: '/finding/:id',
      outletContext: {apiOrigin: ORIGIN_E, authSessionScope: apiMod.getAuthSessionScope(), apiRevision: apiMod.getApiConfigRevision()},
    });
    try {
      await waitFor(() => /Dữ liệu mô phỏng \(mock\) bị chặn/.test(mountedFdSnip.container.textContent));
      assert.match(mountedFdSnip.container.textContent, /Dữ liệu mô phỏng \(mock\) bị chặn/);
      assert.doesNotMatch(mountedFdSnip.container.textContent, /REAL_SCAN/);
    } finally {
      mountedFdSnip.unmount();
    }

    // Also in ReviewPage UI (both when review-queue carries snippet metadata mock and when expanding detail)
    global.fetch = async (url) => {
      const u = new URL(url);
      if (u.pathname === '/api/scans/s-e-snipmock/review-queue') {
        return jsonResp(200, {
          scan_id: 's-e-snipmock',
          data_origin: 'REAL_SCAN',
          scan_provenance: fullValidProv,
          counts: {open_count: 1},
          warnings: [snippetMockFinding],
        });
      }
      if (u.pathname === '/api/scans/s-e-snipmock/review-history') {
        return jsonResp(200, {scan_id: 's-e-snipmock', events: [], rejected_decisions: []});
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedRevSnip = mountWithOutlet(h(ReviewPage), {
      initialEntry: '/review?scan_id=s-e-snipmock',
      outletContext: {apiOrigin: ORIGIN_E, authSessionScope: apiMod.getAuthSessionScope(), apiRevision: apiMod.getApiConfigRevision()},
    });
    try {
      await waitFor(() => /Dữ liệu mô phỏng \(mock\) bị chặn/.test(mountedRevSnip.container.textContent));
      assert.match(mountedRevSnip.container.textContent, /Dữ liệu mô phỏng \(mock\) bị chặn/);
    } finally {
      mountedRevSnip.unmount();
    }

    // Also in reportModel & ReportsPage UI
    const repDocSnipMock = {
      report_schema: 'ntk-report-v1',
      data_origin: 'REAL_SCAN',
      contains_mock_or_test_data: false,
      scan_summary: {scan_id: 's-e-snipmock', total_findings: 1, scan_provenance: fullValidProv},
      audit_trail: {events_count: 0, rejected_decisions_count: 0, events: [], rejected_decisions: []},
      findings: [snippetMockFinding],
    };
    const vmSnipMock = reportModelMod.buildReportViewModel(repDocSnipMock, {expectedScanId: 's-e-snipmock'});
    assert.equal(vmSnipMock.isMockOrTest, true, 'reportModel must catch evidence.snippets[0].metadata.mock=true');
    assert.equal(vmSnipMock.canExportReport, false);
    assert.equal(vmSnipMock.canExportVerifiedReport, false);
    assert.equal(vmSnipMock.dataOrigin, 'MOCK_SYNTHETIC_TEST');

    global.fetch = async (url) => {
      if (new URL(url).pathname === '/api/scans/s-e-snipmock/report') return jsonResp(200, repDocSnipMock);
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedRepSnip = mountWithOutlet(h(ReportsPage), {
      initialEntry: '/reports?scan_id=s-e-snipmock',
      outletContext: {apiOrigin: ORIGIN_E, authSessionScope: apiMod.getAuthSessionScope(), apiRevision: apiMod.getApiConfigRevision()},
    });
    try {
      await waitFor(() => /Dữ liệu mô phỏng \(mock\) bị chặn xuất báo cáo/.test(mountedRepSnip.container.textContent));
      assert.match(mountedRepSnip.container.textContent, /Dữ liệu mô phỏng \(mock\) bị chặn xuất báo cáo/);
      assert.doesNotMatch(mountedRepSnip.container.textContent, /Tải báo cáo JSON/);
    } finally {
      mountedRepSnip.unmount();
    }

    // E-CE-2. recorded_engine_exit = 1 with both capture flags true MUST NOT verify REAL_SCAN, MUST NOT label mock, and MUST block verified export
    const exitOneScan = {
      scan_id: 's-e-exit1',
      data_origin: 'REAL_SCAN',
      is_test_or_mock: false,
      scan_provenance: exitOneProv,
      repo_url: 'https://github.com/example/exit-one-scan',
      total_findings: 1,
    };
    const clsExitOne = classifyDataOrigin(exitOneScan);
    assert.equal(clsExitOne.isMockOrTest, false, 'Nonzero recorded_engine_exit must NOT be misclassified as mock');
    assert.equal(clsExitOne.isVerifiedRealScan, false, 'recorded_engine_exit=1 must NOT verify as REAL_SCAN');
    assert.equal(clsExitOne.code, 'UNVERIFIED_ORIGIN');
    assert.equal(clsExitOne.captureRecorded, true);
    assert.equal(clsExitOne.sourceVerified, true);
    assert.equal(clsExitOne.engineSucceeded, false);

    // Results picker must NOT render REAL_SCAN for recorded_engine_exit=1
    global.fetch = async (url) => {
      if (new URL(url).pathname === '/api/scans') {
        return jsonResp(200, {total_count: 1, scans: [exitOneScan]});
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedPickerExit1 = mountWithOutlet(h(Results), {
      initialEntry: '/findings',
      outletContext: {apiOrigin: ORIGIN_E, authSessionScope: apiMod.getAuthSessionScope(), apiRevision: apiMod.getApiConfigRevision()},
    });
    try {
      await waitFor(() => /exit-one-scan/.test(mountedPickerExit1.container.textContent));
      const cards = mountedPickerExit1.container.querySelectorAll('.v2-scan-picker-row').map((c) => c.textContent);
      assert.equal(cards.length, 1);
      assert.doesNotMatch(cards[0], /REAL_SCAN/, 'Results picker must NOT label recorded_engine_exit=1 as REAL_SCAN');
      assert.match(cards[0], /UNVERIFIED_ORIGIN/);
    } finally {
      mountedPickerExit1.unmount();
    }

    // ReviewPage with recorded_engine_exit=1 must NOT show REAL_SCAN badge
    global.fetch = async (url) => {
      const u = new URL(url);
      if (u.pathname === '/api/scans/s-e-exit1/review-queue') {
        return jsonResp(200, {
          scan_id: 's-e-exit1',
          data_origin: 'REAL_SCAN',
          scan_provenance: exitOneProv,
          counts: {open_count: 1, proposed_refuted_open_count: 0, undetermined_open_count: 1, confirmed_true_count: 0, confirmed_false_count: 0, total_in_scan: 1},
          warnings: [{finding_id: 'f-e1', scan_id: 's-e-exit1', cwe: 'CWE-22', validated_status: 'UNDETERMINED', human_review_state: 'OPEN'}],
        });
      }
      if (u.pathname === '/api/scans/s-e-exit1/review-history') {
        return jsonResp(200, {scan_id: 's-e-exit1', events: [], rejected_decisions: []});
      }
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedRevExit1 = mountWithOutlet(h(ReviewPage), {
      initialEntry: '/review?scan_id=s-e-exit1',
      outletContext: {apiOrigin: ORIGIN_E, authSessionScope: apiMod.getAuthSessionScope(), apiRevision: apiMod.getApiConfigRevision()},
    });
    try {
      await waitFor(() => /UNVERIFIED_ORIGIN/.test(mountedRevExit1.container.textContent));
      assert.match(mountedRevExit1.container.textContent, /UNVERIFIED_ORIGIN/);
      assert.doesNotMatch(mountedRevExit1.container.textContent, /REAL_SCAN/);
    } finally {
      mountedRevExit1.unmount();
    }

    // ReportsPage + reportModel with recorded_engine_exit=1 must NOT certify REAL_SCAN and must disable JSON export
    const repDocExit1 = {
      report_schema: 'ntk-report-v1',
      data_origin: 'REAL_SCAN',
      contains_mock_or_test_data: false,
      scan_summary: {scan_id: 's-e-exit1', total_findings: 0, scan_provenance: exitOneProv},
      audit_trail: {events_count: 0, rejected_decisions_count: 0, events: [], rejected_decisions: []},
      findings: [],
    };
    const vmExit1 = reportModelMod.buildReportViewModel(repDocExit1, {expectedScanId: 's-e-exit1'});
    assert.equal(vmExit1.isMockOrTest, false);
    assert.equal(vmExit1.isVerifiedRealScan, false);
    assert.equal(vmExit1.dataOrigin, 'UNVERIFIED_ORIGIN');
    assert.equal(vmExit1.canExportVerifiedReport, false);
    assert.equal(vmExit1.canExportReport, false);

    global.fetch = async (url) => {
      if (new URL(url).pathname === '/api/scans/s-e-exit1/report') return jsonResp(200, repDocExit1);
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedRepExit1 = mountWithOutlet(h(ReportsPage), {
      initialEntry: '/reports?scan_id=s-e-exit1',
      outletContext: {apiOrigin: ORIGIN_E, authSessionScope: apiMod.getAuthSessionScope(), apiRevision: apiMod.getApiConfigRevision()},
    });
    try {
      await waitFor(() => /UNVERIFIED_ORIGIN/.test(mountedRepExit1.container.textContent));
      assert.match(mountedRepExit1.container.textContent, /UNVERIFIED_ORIGIN/);
      assert.doesNotMatch(mountedRepExit1.container.textContent, /NGUỒN DỮ LIỆUREAL_SCAN/);
      const dlBtn = mountedRepExit1.container.querySelectorAll('button').find((b) => /Tải báo cáo JSON/.test(b.textContent));
      assert.ok(dlBtn);
      assert.equal(dlBtn.disabled, true, 'ReportsPage must disable JSON export when provenance fails (recorded_engine_exit=1)');
    } finally {
      mountedRepExit1.unmount();
    }

    // E-POS. Positive control: valid backend-created REAL_SCAN payload works consistently across all surfaces
    const validFinding = {
      scan_id: 's-e-real',
      finding_id: 'f-e-real',
      id: 'f-e-real',
      cwe: 'CWE-89',
      validated_status: 'REFUTED',
      human_review_state: 'OPEN',
      data_origin: 'REAL_SCAN',
      is_test_or_mock: false,
      scan_provenance: fullValidProv,
      evidence: {
        id: 'f-e-real',
        path: 'src/SqlDemo.java',
        start: {line: 10},
        snapshots: {'src/SqlDemo.java': {sha256: 'c'.repeat(64), size: 150}},
        scan_provenance: fullValidProv,
        snippets: [{role: 'finding', path: 'src/SqlDemo.java', start: {line: 10}, end: {line: 10}, lines: [{line: 10, text: 'String sql = "SELECT 1";'}]}],
      },
      assessment: {validated_status: 'REFUTED', citations: [], runtime: {origin: 'unverified', model_runtime_verified: false}},
    };
    const clsValid = classifyDataOrigin(validFinding);
    assert.equal(clsValid.code, 'REAL_SCAN');
    assert.equal(clsValid.isVerifiedRealScan, true);
    assert.equal(clsValid.isMockOrTest, false);
    assert.equal(clsValid.captureRecorded, true);
    assert.equal(clsValid.sourceVerified, true);
    assert.equal(clsValid.engineSucceeded, true);

    const validReportDoc = {
      report_schema: 'ntk-report-v1',
      data_origin: 'REAL_SCAN',
      contains_mock_or_test_data: false,
      scan_summary: {
        scan_id: 's-e-real',
        scan_sha256: 'd'.repeat(64),
        total_findings: 1,
        by_validated_status: {SUPPORTED: 0, REFUTED: 1, UNDETERMINED: 0},
        by_human_review_state: {OPEN: 1, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0},
        proposed_refuted_open_count: 1,
        scan_provenance: fullValidProv,
      },
      audit_trail: {events_count: 0, rejected_decisions_count: 0, events: [], rejected_decisions: []},
      findings: [validFinding],
    };
    const vmValid = reportModelMod.buildReportViewModel(validReportDoc, {expectedScanId: 's-e-real'});
    assert.equal(vmValid.dataOrigin, 'REAL_SCAN');
    assert.equal(vmValid.isVerifiedRealScan, true);
    assert.equal(vmValid.canExportReport, true);
    assert.equal(vmValid.canExportVerifiedReport, true);

    global.fetch = async (url) => {
      if (new URL(url).pathname === '/api/scans/s-e-real/report') return jsonResp(200, validReportDoc);
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedRepReal = mountWithOutlet(h(ReportsPage), {
      initialEntry: '/reports?scan_id=s-e-real',
      outletContext: {apiOrigin: ORIGIN_E, authSessionScope: apiMod.getAuthSessionScope(), apiRevision: apiMod.getApiConfigRevision()},
    });
    try {
      await waitFor(() => /NGUỒN DỮ LIỆUREAL_SCAN/.test(mountedRepReal.container.textContent));
      assert.match(mountedRepReal.container.textContent, /NGUỒN DỮ LIỆUREAL_SCAN/);
      const dlBtn = mountedRepReal.container.querySelectorAll('button').find((b) => /Tải báo cáo JSON/.test(b.textContent));
      assert.ok(dlBtn);
      assert.equal(dlBtn.disabled, false, 'Valid backend REAL_SCAN report must allow download');
    } finally {
      mountedRepReal.unmount();
    }
  } finally {
    global.fetch = prevFetch;
    dom.restore();
  }
});

test('Single-Blocker Reaudit: Conflicting explicit component data_origin blocks verified REAL_SCAN & download while preserving inherited REAL_SCAN components', async () => {
  const dom = installMiniDom();
  const prevFetch = global.fetch;
  const origCreateObjectURL = global.URL.createObjectURL;
  const origRevokeObjectURL = global.URL.revokeObjectURL;
  const origCreateElement = global.document.createElement.bind(global.document);

  const createdBlobs = [];
  const revokedUrls = [];
  const clickedAnchors = [];
  global.URL.createObjectURL = (blob) => {
    createdBlobs.push(blob);
    return `blob:audit-report-${createdBlobs.length}`;
  };
  global.URL.revokeObjectURL = (url) => {
    revokedUrls.push(url);
  };
  global.document.createElement = (tag) => {
    const el = origCreateElement(tag);
    if (String(tag).toLowerCase() === 'a') {
      el.click = () => clickedAnchors.push({href: el.href, download: el.download});
    }
    return el;
  };

  try {
    const bundle = loadAppBundle();
    const {h, apiMod, reportModelMod, findingPresMod, ReportsPage, mountWithOutlet} = bundle;
    const {classifyDataOrigin} = findingPresMod;
    const ORIGIN = 'http://127.0.0.1:18510';
    apiMod.configureApiConnection({baseUrl: ORIGIN, token: 'tok-single-blocker-123456'});

    const validProv = {
      origin: 'recorded_capture_unsigned',
      source_capture_verified: true,
      exit_capture_verified: true,
      recorded_engine_exit: 0,
      source_hashes: {'src/Demo.java': 'e'.repeat(64)},
    };

    const mkFinding = (scanId, fid, extra = {}) => ({
      scan_id: scanId,
      finding_id: fid,
      id: fid,
      cwe: 'CWE-22',
      rule_id: 'v2.g1.java.cwe22.path-traversal',
      file_path: 'src/Demo.java',
      start_line: 14,
      validated_status: 'REFUTED',
      human_review_state: 'OPEN',
      is_test_or_mock: false,
      scan_provenance: validProv,
      evidence: {
        id: fid,
        path: 'src/Demo.java',
        start: {line: 14},
        snapshots: {'src/Demo.java': {sha256: 'e'.repeat(64), size: 220}},
        scan_provenance: validProv,
        snippets: [{role: 'finding', path: 'src/Demo.java', start: {line: 14}, end: {line: 14}, lines: [{line: 14, text: 'new File(base, name);'}]}],
      },
      assessment: {
        validated_status: 'REFUTED',
        citations: [{path: 'src/Demo.java', start_line: 14, end_line: 14, quote: 'new File(base, name);', sha256: 'e'.repeat(64)}],
        citation_check: 'MATCHED',
        runtime: {origin: 'unverified', model_runtime_verified: false},
      },
      ...extra,
    });

    const mkReport = (scanId, findings, extra = {}) => ({
      report_schema: 'ntk-report-v1',
      data_origin: 'REAL_SCAN',
      contains_mock_or_test_data: false,
      scan_summary: {
        scan_id: scanId,
        scan_sha256: 'f'.repeat(64),
        total_findings: findings.length,
        by_validated_status: {SUPPORTED: 0, REFUTED: findings.length, UNDETERMINED: 0},
        by_human_review_state: {OPEN: findings.length, CONFIRMED_TRUE: 0, CONFIRMED_FALSE: 0},
        proposed_refuted_open_count: findings.length,
        scan_provenance: validProv,
      },
      audit_trail: {events_count: 0, rejected_decisions_count: 0, events: [], rejected_decisions: []},
      findings,
      ...extra,
    });

    // 1. Exact counterexample: REAL_SCAN report + valid overall provenance + findings[0].data_origin = IMPORTED_SCAN_UNVERIFIED_CAPTURE
    const conflictFinding = mkFinding('s-conflict-1', 'f-conf-1', {data_origin: 'IMPORTED_SCAN_UNVERIFIED_CAPTURE'});
    const conflictReport = mkReport('s-conflict-1', [conflictFinding]);

    // validateReportForScan checks scan binding so ReportsPage still renders the unverified notice and preserves original findings
    assert.equal(reportModelMod.validateReportForScan(conflictReport, 's-conflict-1').valid, true);

    const vmConflict = reportModelMod.buildReportViewModel(conflictReport, {expectedScanId: 's-conflict-1'});
    assert.equal(vmConflict.isMockOrTest, false, 'Conflicting imported origin must NOT be rewritten to mock');
    assert.equal(vmConflict.isVerifiedRealScan, false, 'Conflicting finding origin must revoke REAL_SCAN');
    assert.equal(vmConflict.isUnverified, true);
    assert.equal(vmConflict.dataOrigin, 'UNVERIFIED_ORIGIN');
    assert.equal(vmConflict.canExportVerifiedReport, false);
    assert.equal(vmConflict.canExportReport, false);
    assert.equal(vmConflict.provenanceStatus.reason, 'CONFLICTING_DATA_ORIGIN');
    assert.equal(vmConflict.findingRows.length, 1, 'Original finding data must be preserved');
    assert.equal(vmConflict.findingRows[0].id, 'f-conf-1');
    assert.equal(vmConflict.findingRows[0].cwe, 'CWE-22');
    assert.equal(vmConflict.findingRows[0].citations.length, 1);

    const clsConflict = classifyDataOrigin(conflictReport);
    assert.equal(clsConflict.code, 'UNVERIFIED_ORIGIN');
    assert.equal(clsConflict.isVerifiedRealScan, false);
    assert.equal(clsConflict.isMockOrTest, false);
    assert.equal(clsConflict.reason, 'CONFLICTING_DATA_ORIGIN');

    global.fetch = async (url) => {
      if (new URL(url).pathname === '/api/scans/s-conflict-1/report') return jsonResp(200, conflictReport);
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };
    const mountedConflict = mountWithOutlet(h(ReportsPage), {
      initialEntry: '/reports?scan_id=s-conflict-1',
      outletContext: {apiOrigin: ORIGIN, authSessionScope: apiMod.getAuthSessionScope(), apiRevision: apiMod.getApiConfigRevision()},
    });
    try {
      await waitFor(() => /UNVERIFIED_ORIGIN/.test(mountedConflict.container.textContent));
      assert.match(mountedConflict.container.textContent, /UNVERIFIED_ORIGIN/);
      assert.match(mountedConflict.container.textContent, /f-conf-1/);
      assert.doesNotMatch(mountedConflict.container.textContent, /NGUỒN DỮ LIỆUREAL_SCAN/);
      assert.doesNotMatch(mountedConflict.container.textContent, /MOCK_SYNTHETIC_TEST/);
      const dlBtn = mountedConflict.container.querySelectorAll('button').find((b) => /Tải báo cáo JSON/.test(b.textContent));
      assert.ok(dlBtn);
      assert.equal(dlBtn.disabled, true, 'Download JSON button must be disabled when report-vs-finding provenance conflicts');
      createdBlobs.length = 0;
      revokedUrls.length = 0;
      clickedAnchors.length = 0;
      dlBtn.dispatchEvent(new global.Event('click', {bubbles: true}));
      assert.equal(createdBlobs.length, 0, 'JSON Blob must NOT be generated on conflicting report even if click event fires');
    } finally {
      mountedConflict.unmount();
    }

    // 2. Multi-finding partial conflict + arbitrary non-hardcoded unverified/custom string in nested evidence.data_origin
    const mixedReport = mkReport('s-conflict-mix', [
      mkFinding('s-conflict-mix', 'f-ok-1', {data_origin: 'REAL_SCAN'}),
      {
        ...mkFinding('s-conflict-mix', 'f-bad-2'),
        evidence: {
          ...mkFinding('s-conflict-mix', 'f-bad-2').evidence,
          data_origin: 'CUSTOM_IMPORTED_PARTNER_FEED',
        },
      },
    ]);
    const vmMixed = reportModelMod.buildReportViewModel(mixedReport, {expectedScanId: 's-conflict-mix'});
    assert.equal(vmMixed.isMockOrTest, false);
    assert.equal(vmMixed.isVerifiedRealScan, false);
    assert.equal(vmMixed.dataOrigin, 'UNVERIFIED_ORIGIN');
    assert.equal(vmMixed.canExportVerifiedReport, false);
    assert.equal(vmMixed.canExportReport, false);
    assert.equal(vmMixed.findingRows.length, 2, 'Both findings must remain preserved in mixed provenance report');
    assert.equal(classifyDataOrigin(mixedReport).code, 'UNVERIFIED_ORIGIN');

    // 3. Multi-finding with mock flag on one child finding -> isolated as MOCK_SYNTHETIC_TEST
    const mixedMockReport = mkReport('s-conflict-mock', [
      mkFinding('s-conflict-mock', 'f-real-1', {data_origin: 'REAL_SCAN'}),
      mkFinding('s-conflict-mock', 'f-mock-2', {is_test_or_mock: true}),
    ]);
    const vmMixedMock = reportModelMod.buildReportViewModel(mixedMockReport, {expectedScanId: 's-conflict-mock'});
    assert.equal(vmMixedMock.isMockOrTest, true);
    assert.equal(vmMixedMock.dataOrigin, 'MOCK_SYNTHETIC_TEST');
    assert.equal(vmMixedMock.canExportVerifiedReport, false);
    assert.equal(vmMixedMock.canExportReport, false);

    // 4. Child REAL_SCAN must NOT promote a report whose top-level & summary omit data_origin; malformed non-string field must fail closed
    const childOnlyReport = mkReport('s-no-top-origin', [mkFinding('s-no-top-origin', 'f-child-only', {data_origin: 'REAL_SCAN'})]);
    delete childOnlyReport.data_origin;
    const vmChildOnly = reportModelMod.buildReportViewModel(childOnlyReport, {expectedScanId: 's-no-top-origin'});
    assert.equal(vmChildOnly.isVerifiedRealScan, false);
    assert.equal(vmChildOnly.dataOrigin, 'UNVERIFIED_ORIGIN');
    assert.equal(vmChildOnly.canExportVerifiedReport, false);

    const nonStringOriginReport = mkReport('s-non-str', [mkFinding('s-non-str', 'f-nonstr', {data_origin: {forged: true}})]);
    const vmNonStr = reportModelMod.buildReportViewModel(nonStringOriginReport, {expectedScanId: 's-non-str'});
    assert.equal(vmNonStr.isVerifiedRealScan, false);
    assert.equal(vmNonStr.dataOrigin, 'UNVERIFIED_ORIGIN');
    assert.equal(vmNonStr.canExportReport, false);
    assert.equal(vmNonStr.canExportVerifiedReport, false);

    // 5a. Positive control: Finding omitting data_origin legitimately inherits verified REAL_SCAN report provenance & downloads JSON
    const inheritedFinding = mkFinding('s-inherit-ok', 'f-inh-1');
    delete inheritedFinding.data_origin;
    delete inheritedFinding.scan_provenance;
    delete inheritedFinding.evidence.scan_provenance;
    const inheritedReport = mkReport('s-inherit-ok', [inheritedFinding]);
    const vmInherit = reportModelMod.buildReportViewModel(inheritedReport, {expectedScanId: 's-inherit-ok'});
    assert.equal(vmInherit.dataOrigin, 'REAL_SCAN', 'Finding omitting data_origin must inherit verified REAL_SCAN provenance');
    assert.equal(vmInherit.isVerifiedRealScan, true);
    assert.equal(vmInherit.isMockOrTest, false);
    assert.equal(vmInherit.canExportReport, true);
    assert.equal(vmInherit.canExportVerifiedReport, true);
    assert.equal(classifyDataOrigin(inheritedReport).code, 'REAL_SCAN');

    // 5b. Positive control: Valid explicit REAL_SCAN finding also renders and exports JSON cleanly
    const explicitRealReport = mkReport('s-explicit-ok', [
      mkFinding('s-explicit-ok', 'f-exp-1', {data_origin: 'REAL_SCAN'}),
      inheritedFinding.scan_id ? {...inheritedFinding, scan_id: 's-explicit-ok', finding_id: 'f-inh-2', id: 'f-inh-2'} : null,
    ].filter(Boolean));
    const vmExplicit = reportModelMod.buildReportViewModel(explicitRealReport, {expectedScanId: 's-explicit-ok'});
    assert.equal(vmExplicit.dataOrigin, 'REAL_SCAN');
    assert.equal(vmExplicit.isVerifiedRealScan, true);
    assert.equal(vmExplicit.canExportReport, true);
    assert.equal(vmExplicit.canExportVerifiedReport, true);

    global.fetch = async (url) => {
      const path = new URL(url).pathname;
      if (path === '/api/scans/s-inherit-ok/report') return jsonResp(200, inheritedReport);
      if (path === '/api/scans/s-explicit-ok/report') return jsonResp(200, explicitRealReport);
      return jsonResp(404, {error_code: 'NOT_FOUND'});
    };

    for (const [scanId, expectedFindingsCount] of [['s-inherit-ok', 1], ['s-explicit-ok', 2]]) {
      const mountedOk = mountWithOutlet(h(ReportsPage), {
        initialEntry: `/reports?scan_id=${scanId}`,
        outletContext: {apiOrigin: ORIGIN, authSessionScope: apiMod.getAuthSessionScope(), apiRevision: apiMod.getApiConfigRevision()},
      });
      try {
        await waitFor(() => /NGUỒN DỮ LIỆUREAL_SCAN/.test(mountedOk.container.textContent));
        const dlBtn = mountedOk.container.querySelectorAll('button').find((b) => /Tải báo cáo JSON/.test(b.textContent));
        assert.ok(dlBtn);
        assert.equal(dlBtn.disabled, false, `Valid report ${scanId} must allow JSON download`);
        createdBlobs.length = 0;
        revokedUrls.length = 0;
        clickedAnchors.length = 0;
        dlBtn.dispatchEvent(new global.Event('click', {bubbles: true}));
        assert.equal(createdBlobs.length, 1, `Clicking download on valid ${scanId} must create JSON Blob`);
        assert.equal(clickedAnchors.length, 1);
        assert.equal(clickedAnchors[0].download, `${scanId}-report.json`);
        assert.equal(revokedUrls.length, 1);
        const exported = JSON.parse(await createdBlobs[0].text());
        assert.equal(exported.scan_summary.scan_id, scanId);
        assert.equal(exported.findings.length, expectedFindingsCount);
      } finally {
        mountedOk.unmount();
      }
    }
  } finally {
    global.fetch = prevFetch;
    global.URL.createObjectURL = origCreateObjectURL;
    global.URL.revokeObjectURL = origRevokeObjectURL;
    global.document.createElement = origCreateElement;
    dom.restore();
  }
});



