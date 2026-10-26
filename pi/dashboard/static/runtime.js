/* One non-overlapping polling cycle for all dashboard views. */
(() => {
  'use strict';
  const jobs = new Set(), failures = new Map(), controllers = new Set();
  let timer, running = false, rerun = false, stopped = false, failedCycles = 0;
  const interval = () => {
    try { const n = Number(localStorage.getItem('soc-interval')); return [3, 5, 10, 30].includes(n) ? n * 1000 : 3000; }
    catch (_) { return 3000; }
  };
  function connectionState() {
    const badge = document.getElementById('connection-status');
    const banner = document.getElementById('connection-banner');
    if (!badge || !banner) return;
    badge.textContent = failures.size ? '● DATA STALE' : '● LIVE API';
    badge.classList.toggle('offline', failures.size > 0);
    banner.hidden = !failures.size;
    const message = document.getElementById('connection-message');
    if (message) message.textContent = `Could not update ${[...failures.keys()].join(', ')}. Keeping the last snapshot.`;
  }
  async function request(url, options = {}) {
    const {raw = false, ...fetchOptions} = options;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const key = new URL(url, location.href).pathname;
    controllers.add(controller);
    try {
      const response = await fetch(url, {cache: 'no-store', ...fetchOptions, signal: controller.signal});
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        const error = new Error(body.error || `Request failed (${response.status})`);
        error.status = response.status;
        throw error;
      }
      const data = raw ? response : await response.json();
      failures.delete(key);
      connectionState();
      return data;
    } catch (error) {
      if (!stopped) { failures.set(key, error.message); connectionState(); }
      throw error;
    } finally { clearTimeout(timeout); controllers.delete(controller); }
  }
  async function tick() {
    clearTimeout(timer);
    if (stopped || document.hidden) return;
    if (running) { rerun = true; return; }
    running = true;
    await Promise.allSettled([...jobs].map(callback => Promise.resolve().then(callback)));
    running = false;
    failedCycles = failures.size ? failedCycles + 1 : 0;
    const next = rerun ? 0 : Math.min(30000, interval() * 2 ** Math.min(failedCycles, 3));
    rerun = false;
    if (!stopped) timer = setTimeout(tick, next);
  }
  function sortRows(table, heading, ascending) {
    if (!heading) return;
    const column = [...heading.parentElement.children].indexOf(heading);
    const rows = [...table.tBodies[0].rows];
    rows.sort((left, right) => {
      const a = left.cells[column]?.dataset.sortValue ?? left.cells[column]?.textContent.trim() ?? '';
      const b = right.cells[column]?.dataset.sortValue ?? right.cells[column]?.textContent.trim() ?? '';
      const comparison = a !== '' && b !== '' && Number.isFinite(Number(a)) && Number.isFinite(Number(b))
        ? Number(a) - Number(b) : a.localeCompare(b, undefined, {numeric: true, sensitivity: 'base'});
      return ascending ? comparison : -comparison;
    });
    rows.forEach(row => table.tBodies[0].append(row));
  }
  window.soc = {
    request, get: url => request(url), refresh: tick, sortRows,
    forget: url => { failures.delete(url); connectionState(); },
    setTheme: theme => {
      document.documentElement.dataset.theme = theme;
      try { localStorage.setItem('soc-theme', theme); } catch (_) { /* session still works */ }
      document.dispatchEvent(new Event('soc-theme'));
    }
  };
  window.socInterval = interval;
  window.socPoll = callback => { jobs.add(callback); };
  document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); else clearTimeout(timer); });
  window.addEventListener('pagehide', () => { stopped = true; clearTimeout(timer); controllers.forEach(c => c.abort()); });
  window.addEventListener('pageshow', event => { if (event.persisted) { stopped = false; tick(); } });
  document.addEventListener('soc-preferences', tick);
  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('retry-connection')?.addEventListener('click', tick);
    document.querySelectorAll('table.sortable th[data-sort]').forEach(heading => {
      heading.tabIndex = 0;
      heading.setAttribute('aria-sort', 'none');
      const sort = () => {
        const ascending = heading.dataset.direction !== 'asc', table = heading.closest('table');
        table.querySelectorAll('th[data-sort]').forEach(h => { delete h.dataset.direction; h.setAttribute('aria-sort', 'none'); });
        heading.dataset.direction = ascending ? 'asc' : 'desc';
        heading.setAttribute('aria-sort', ascending ? 'ascending' : 'descending');
        sortRows(table, heading, ascending);
      };
      heading.addEventListener('click', sort);
      heading.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sort(); } });
    });
    tick();
  });
})();
