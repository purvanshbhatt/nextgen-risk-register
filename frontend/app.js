/* NextGen Risk Register - front end. No framework, no build step. */
'use strict';

// ------------------------------------------------------------------ state & helpers
const PERSONAS = {
  business:  { actor: 'u-ciso',  label: 'Business owner',    technical: false, blurb: 'Plain-English view. Scores are explained in words; technical fields are tucked away.' },
  engineer:  { actor: 'u-eng',   label: 'Security engineer', technical: true,  blurb: 'Full detail: MITRE ATT&CK / ATLAS, CVSS, framework mappings, control evidence tiers.' },
  executive: { actor: 'u-ceo',   label: 'Executive',         technical: false, blurb: 'Headlines first. You can accept risks; everything else is read-only.' },
  auditor:   { actor: 'u-audit', label: 'Auditor',           technical: true,  blurb: 'Read-only. Every change is in the hash-chained audit trail.' },
};
const S = { meta: null, persona: localStorage.getItem('ngrr.persona') || 'business', me: null, draft: null, filters: {} };
const $ = (sel, root = document) => root.querySelector(sel);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const money = (v) => { if (v === null || v === undefined || v === '') return '–'; v = Number(v); if (v >= 1e6) return '$' + (v / 1e6).toFixed(v >= 1e7 ? 0 : 1) + 'M'; if (v >= 1e3) return '$' + Math.round(v / 1e3) + 'k'; return '$' + Math.round(v); };
const pct = (v) => Math.round(v * 100) + '%';
const date = (s) => (s ? String(s).slice(0, 10) : '–');
const chip = (band) => `<span class="chip ${esc(band)}">${esc(band)}</span>`;
const tier = (t) => { const d = S.meta.evidence_tiers.find((x) => x.tier === Number(t)); return d ? `<span class="tier t${t}" title="${esc(d.plain)}">T${t} ${esc(d.name)}</span>` : ''; };
const lik = (n) => S.meta.likelihood_scale[n - 1];
const imp = (n) => S.meta.impact_scale[n - 1];
const can = (perm) => S.me && S.me.permissions.includes(perm);
const persona = () => PERSONAS[S.persona];

function toast(msg, err = false) {
  const t = $('#toast'); t.textContent = msg; t.className = 'toast' + (err ? ' err' : ''); t.classList.remove('hidden');
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.add('hidden'), err ? 6000 : 3000);
}

async function api(path, opts = {}) {
  const headers = { 'X-Actor': persona().actor, ...(opts.headers || {}) };
  if (opts.json !== undefined) { headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(opts.json); }
  const res = await fetch('/api' + path, { ...opts, headers });
  if (!res.ok) {
    let msg = res.statusText;
    try { const j = await res.json(); msg = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail); } catch (_) { /* ignore */ }
    toast(msg, true); throw new Error(msg);
  }
  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? res.json() : res.text();
}

function modal(html) { $('#modalCard').innerHTML = html; $('#modal').classList.remove('hidden'); }
function closeModal() { $('#modal').classList.add('hidden'); }
$('#modal').addEventListener('click', (e) => { if (e.target.id === 'modal') closeModal(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

function formData(form) {
  const o = {};
  new FormData(form).forEach((v, k) => { if (k in o) { o[k] = [].concat(o[k], v); } else { o[k] = v; } });
  return o;
}
const numOrNull = (v) => (v === '' || v === undefined || v === null ? null : Number(v));

// ------------------------------------------------------------------ canvas charts
function drawExceedance(canvas, series) {
  // series: [{label, color, curve:[{loss, probability_exceeding}]}]
  const ctx = canvas.getContext('2d'); const W = canvas.width = canvas.clientWidth * 2; const H = canvas.height = 220 * 2; ctx.scale(2, 2);
  const w = W / 2, h = H / 2, pad = { l: 46, r: 12, t: 12, b: 34 };
  const maxLoss = Math.max(1, ...series.flatMap((s) => s.curve.map((p) => p.loss)));
  const x = (loss) => pad.l + (loss / maxLoss) * (w - pad.l - pad.r);
  const y = (p) => pad.t + (1 - p) * (h - pad.t - pad.b);
  ctx.clearRect(0, 0, w, h);
  ctx.strokeStyle = getComputedStyle(document.body).getPropertyValue('--line'); ctx.lineWidth = 1; ctx.font = '11px sans-serif';
  ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--muted');
  for (let i = 0; i <= 4; i++) { const p = i / 4; ctx.beginPath(); ctx.moveTo(pad.l, y(p)); ctx.lineTo(w - pad.r, y(p)); ctx.stroke(); ctx.fillText(pct(p), 6, y(p) + 4); }
  for (let i = 0; i <= 4; i++) { const l = (maxLoss * i) / 4; ctx.fillText(money(l), x(l) - 14, h - pad.b + 16); }
  ctx.fillText('Probability that annual loss exceeds X', pad.l, h - 4);
  series.forEach((s) => {
    ctx.strokeStyle = s.color; ctx.lineWidth = 2; ctx.beginPath();
    const pts = [...s.curve].sort((a, b) => a.loss - b.loss);
    pts.forEach((p, i) => { const X = x(p.loss), Y = y(p.probability_exceeding); i ? ctx.lineTo(X, Y) : ctx.moveTo(X, Y); });
    ctx.stroke();
  });
  let lx = pad.l + 8;
  series.forEach((s) => { ctx.fillStyle = s.color; ctx.fillRect(lx, pad.t + 2, 12, 4); ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--text'); ctx.fillText(s.label, lx + 16, pad.t + 8); lx += 16 + ctx.measureText(s.label).width + 14; });
}

function sparkline(readings, warning, critical, direction) {
  if (!readings || !readings.length) return '';
  const w = 120, h = 30, vals = readings.map((r) => r.value);
  const lo = Math.min(...vals, warning, critical), hi = Math.max(...vals, warning, critical) || 1;
  const X = (i) => (i / Math.max(1, vals.length - 1)) * (w - 4) + 2, Y = (v) => h - 2 - ((v - lo) / (hi - lo || 1)) * (h - 4);
  const path = vals.map((v, i) => `${i ? 'L' : 'M'}${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join(' ');
  const last = vals[vals.length - 1];
  const bad = direction === 'above_is_bad' ? last >= critical : last <= critical;
  const warn = direction === 'above_is_bad' ? last >= warning : last <= warning;
  const color = bad ? 'var(--bad)' : warn ? 'var(--warn)' : 'var(--ok)';
  return `<svg class="spark" width="${w}" height="${h}"><line x1="2" x2="${w - 2}" y1="${Y(warning)}" y2="${Y(warning)}" stroke="var(--warn)" stroke-dasharray="3 3"/><line x1="2" x2="${w - 2}" y1="${Y(critical)}" y2="${Y(critical)}" stroke="var(--bad)" stroke-dasharray="3 3"/><path d="${path}" fill="none" stroke="${color}" stroke-width="2"/></svg>`;
}

function heatmapHTML(matrix, selected, mode = 'count') {
  // matrix[L-1][I-1] = [risk ids]
  const bandColor = (s) => S.meta.bands.find((b) => s >= b.min && s <= b.max).color;
  let html = '<div class="heat">';
  for (let L = 5; L >= 1; L--) {
    html += `<div class="lab" title="${esc(lik(L).plain)}">L${L}<br><small>${esc(lik(L).label)}</small></div>`;
    for (let I = 1; I <= 5; I++) {
      const ids = matrix[L - 1][I - 1]; const s = L * I; const sel = selected && selected[0] === L && selected[1] === I ? 'sel' : '';
      html += `<div class="cell ${sel}" data-l="${L}" data-i="${I}" style="background:${bandColor(s)}${ids.length ? 'cc' : '44'}" title="Score ${s}: ${ids.join(', ') || 'no risks'}">${mode === 'count' ? (ids.length || '') : s}<small>${mode === 'count' ? 'score ' + s : ''}</small></div>`;
    }
  }
  html += '<div></div>';
  for (let I = 1; I <= 5; I++) html += `<div class="lab" title="${esc(imp(I).plain)}">I${I}<br><small>${esc(imp(I).label)}</small></div>`;
  return html + '</div>';
}

// ------------------------------------------------------------------ boot & routing
async function boot() {
  S.meta = await api('/meta');
  $('#personaSelect').value = S.persona;
  $('#personaSelect').addEventListener('change', async (e) => { S.persona = e.target.value; localStorage.setItem('ngrr.persona', S.persona); await refreshMe(); route(); });
  await refreshMe();
  window.addEventListener('hashchange', route);
  route();
}

async function refreshMe() {
  S.me = await api('/whoami');
  $('#orgName').textContent = S.meta.settings.org_name || '';
  $('#whoami').textContent = `${S.me.name} · ${S.me.role}`;
  document.querySelectorAll('#nav a[data-needs]').forEach((a) => a.classList.toggle('hidden', !can(a.dataset.needs)));
}

function route() {
  const hash = location.hash.replace(/^#\/?/, '') || 'dashboard';
  const [name, id] = hash.split('/');
  document.querySelectorAll('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.route === name));
  const views = { dashboard: viewDashboard, risks: viewRisks, risk: viewRisk, new: viewWizard, edit: viewWizard, controls: viewControls, reports: viewReports, audit: viewAudit, settings: viewSettings };
  const fn = views[name] || viewDashboard;
  $('#view').innerHTML = '<div class="loading">Loading…</div>';
  fn(id).catch((e) => { $('#view').innerHTML = `<div class="banner bad">${esc(e.message)}</div>`; });
}

// ------------------------------------------------------------------ dashboard
async function viewDashboard() {
  const d = await api('/dashboard');
  const c = d.counts; const p = persona();
  const kpi = (n, l, tone = '') => `<div class="card kpi ${tone}"><span class="n">${n}</span><span class="l">${l}</span></div>`;
  const tiers = c.evidence_tiers;
  const rows = d.top_risks.map((r) => `<tr class="clickable" onclick="location.hash='#/risk/${r.id}'"><td class="nowrap">${r.id}</td><td><b>${esc(r.title)}</b>${p.technical ? '' : `<div class="small muted">${esc(r.business_impact.slice(0, 120))}${r.business_impact.length > 120 ? '…' : ''}</div>`}</td><td>${esc(r.owner)}</td><td>${r.residual_score} ${chip(r.residual_band)}</td><td class="nowrap">${money(r.ale_p90)}</td><td>${r.appetite.breach ? '<span class="chip bad">Outside</span>' : '<span class="chip ok">Inside</span>'}</td></tr>`).join('');
  $('#view').innerHTML = `
    <div class="toolbar"><h1 style="margin:0">Risk posture</h1><span class="muted small">${esc(p.blurb)}</span></div>
    <div class="grid g4" style="margin-bottom:16px">
      ${kpi(c.breaches, 'risks outside appetite', c.breaches ? 'bad' : 'ok')}
      ${kpi((c.bands.Critical || 0) + (c.bands.High || 0), 'critical + high residual risks', (c.bands.Critical || 0) ? 'bad' : 'warn')}
      ${kpi(d.portfolio ? money(d.portfolio.residual.ale_p90) : '–', 'annual loss in a bad year (P90)', '')}
      ${kpi(c.overdue_treatments + c.overdue_reviews, 'overdue actions + stale reviews', (c.overdue_treatments + c.overdue_reviews) ? 'warn' : 'ok')}
    </div>
    <div class="split">
      <div class="card"><h3>What you need to know</h3><ul class="headlines">${d.headlines.map((h) => `<li class="${h.tone}">${esc(h.text)}</li>`).join('')}</ul>
        <p class="small muted" style="margin-top:8px">Sentences are generated from the numbers by fixed rules, not by an AI model, so they say the same thing every time.</p></div>
      <div class="card"><h3>Residual heat map <span class="muted small">(after controls, evidence-weighted)</span></h3>${heatmapHTML(d.heatmap.residual)}
        <p class="small muted" style="margin-top:8px">Click a cell to list its risks. Rows = how likely, columns = how bad.</p></div>
    </div>
    <div class="grid g2" style="margin-top:16px">
      <div class="card"><h3>Top risks</h3><table><tr><th>ID</th><th>Risk</th><th>Owner</th><th>Residual</th><th>P90 loss</th><th>Appetite</th></tr>${rows}</table></div>
      <div class="card"><h3>Loss exceedance (portfolio)</h3>${d.portfolio ? `<canvas id="lec"></canvas>
        <div class="stat"><span>Expected annual loss (after controls)</span><b>${money(d.portfolio.residual.ale_mean)}</b></div>
        <div class="stat"><span>1-in-10 bad year (P90)</span><b>${money(d.portfolio.residual.ale_p90)}</b></div>
        <div class="stat"><span>Expected loss with no controls</span><b>${money(d.portfolio.inherent.ale_mean)}</b></div>
        <div class="stat"><span>Value of current control estate / year</span><b>${money(d.portfolio.inherent.ale_mean - d.portfolio.residual.ale_mean)}</b></div>
        <p class="small muted" style="margin-top:6px">${d.portfolio.risks_quantified} of ${d.portfolio.risks_total} open risks are quantified. Monte Carlo, seeded: re-running gives identical numbers.</p>` : '<p class="muted">No quantified risks yet. Add FAIR inputs to a risk to see this.</p>'}</div>
    </div>
    <div class="grid g3" style="margin-top:16px">
      <div class="card"><h3>Overdue treatment actions (${d.overdue_treatments.length})</h3>${d.overdue_treatments.length ? d.overdue_treatments.map((t) => `<div class="stat"><span><a href="#/risk/${t.risk_id}">${esc(t.title)}</a><br><span class="small muted">${esc(t.owner)} · due ${date(t.due_date)}</span></span><b>${t.progress}%</b></div>`).join('') : '<p class="muted">None</p>'}</div>
      <div class="card"><h3>Key risk indicators needing attention (${d.kri_alerts.length})</h3>${d.kri_alerts.length ? d.kri_alerts.map((k) => `<div class="stat"><span><a href="#/risk/${k.risk_id}">${esc(k.name)}</a><br><span class="small muted">${k.current_value} ${esc(k.unit)} · warn ${k.warning} · crit ${k.critical}</span></span><span>${sparkline(k.readings, k.warning, k.critical, k.direction)} <span class="chip ${k.status === 'Critical' ? 'bad' : 'warn'}">${k.status}</span></span></div>`).join('') : '<p class="muted">All indicators inside thresholds</p>'}</div>
      <div class="card"><h3>Reviews, acceptances, evidence</h3>
        ${d.overdue_reviews.map((r) => `<div class="stat"><span><a href="#/risk/${r.id}">${esc(r.title.slice(0, 60))}</a></span><span class="chip warn">review overdue</span></div>`).join('')}
        ${d.acceptances.map((a) => `<div class="stat"><span><a href="#/risk/${a.risk_id}">${esc(a.risk_title.slice(0, 60))}</a><br><span class="small muted">accepted by ${esc(a.accepted_by)} until ${date(a.expires_at)}</span></span><span class="chip ${a.expired ? 'bad' : 'info'}">${a.expired ? 'acceptance expired' : 'accepted'}</span></div>`).join('')}
        <div class="stat" style="margin-top:8px"><span>Control evidence quality</span><span>${tier(1)} ${tiers[1]} &nbsp; ${tier(2)} ${tiers[2]} &nbsp; ${tier(3)} ${tiers[3]}</span></div>
        <div class="stat"><span>Treatments done</span><b>${c.treatments_done} / ${c.treatments_total}</b></div>
      </div>
    </div>`;
  if (d.portfolio) drawExceedance($('#lec'), [{ label: 'After controls', color: '#1f5eff', curve: d.portfolio.residual.exceedance_curve }, { label: 'No controls', color: '#c62828', curve: d.portfolio.inherent.exceedance_curve }]);
  document.querySelectorAll('.heat .cell').forEach((el) => el.addEventListener('click', () => { S.filters = { cell: [Number(el.dataset.l), Number(el.dataset.i)] }; location.hash = '#/risks'; }));
}

// ------------------------------------------------------------------ risks list
async function viewRisks() {
  const f = S.filters; const qs = new URLSearchParams(); ['q', 'category', 'status', 'band'].forEach((k) => f[k] && qs.set(k, f[k]));
  let risks = await api('/risks?' + qs.toString());
  if (f.cell) risks = risks.filter((r) => r.residual_likelihood === f.cell[0] && r.residual_impact === f.cell[1]);
  const p = persona();
  const opt = (list, cur) => list.map((v) => `<option ${v === cur ? 'selected' : ''}>${esc(v)}</option>`).join('');
  const rows = risks.map((r) => `<tr class="clickable" onclick="location.hash='#/risk/${r.id}'">
      <td class="nowrap">${r.id}</td>
      <td><b>${esc(r.title)}</b><div class="small muted">${p.technical ? esc(r.attack_techniques.join(', ') || '') : esc(r.business_impact.slice(0, 110)) + (r.business_impact.length > 110 ? '…' : '')}</div></td>
      <td class="small">${esc(r.category)}</td><td class="small">${esc(r.owner)}</td>
      <td class="nowrap">${r.inherent_score} ${chip(r.inherent_band)}</td>
      <td class="nowrap">${r.residual_score} ${chip(r.residual_band)}</td>
      <td class="nowrap">${r.fair ? money(r.fair.residual.ale_p90) : '<span class="muted">not quantified</span>'}</td>
      <td>${r.appetite.breach ? '<span class="chip bad">Outside</span>' : '<span class="chip ok">Inside</span>'}</td>
      <td class="small">${esc(r.status)}${r.review_overdue ? ' <span class="chip warn">stale</span>' : ''}${r.treatments_summary.overdue ? ' <span class="chip warn">late action</span>' : ''}${r.kri_status === 'Critical' ? ' <span class="chip bad">KRI</span>' : r.kri_status === 'Warning' ? ' <span class="chip warn">KRI</span>' : ''}</td>
      <td class="small nowrap">${r.control_count} ${r.weakest_evidence_tier ? tier(r.weakest_evidence_tier) : ''}</td>
    </tr>`).join('');
  $('#view').innerHTML = `
    <div class="toolbar"><h1 style="margin:0">Risks <span class="muted small">${risks.length}</span></h1>
      <input id="fq" placeholder="Search title, impact, tags…" value="${esc(f.q || '')}" style="min-width:240px">
      <select id="fcat"><option value="">All categories</option>${opt(S.meta.categories, f.category)}</select>
      <select id="fstatus"><option value="">All statuses</option>${opt(S.meta.risk_statuses, f.status)}</select>
      <select id="fband"><option value="">All bands</option>${opt(S.meta.bands.map((b) => b.name), f.band)}</select>
      ${f.cell ? `<span class="chip info">heat cell L${f.cell[0]} × I${f.cell[1]} <a href="#" id="clearCell" style="color:#fff">✕</a></span>` : ''}
      ${can('risk:write') ? '<a class="btn primary" href="#/new" style="margin-left:auto">+ New risk</a>' : ''}
    </div>
    <div class="card"><table><tr><th>ID</th><th>Risk</th><th>Category</th><th>Owner</th><th>Inherent</th><th>Residual</th><th>P90 loss</th><th>Appetite</th><th>Status</th><th>Controls</th></tr>${rows || '<tr><td colspan="10" class="muted">No risks match.</td></tr>'}</table></div>`;
  const apply = () => { S.filters = { ...S.filters, q: $('#fq').value, category: $('#fcat').value, status: $('#fstatus').value, band: $('#fband').value }; viewRisks(); };
  $('#fq').addEventListener('change', apply); ['#fcat', '#fstatus', '#fband'].forEach((s) => $(s).addEventListener('change', apply));
  const cc = $('#clearCell'); if (cc) cc.addEventListener('click', (e) => { e.preventDefault(); delete S.filters.cell; viewRisks(); });
}

// ------------------------------------------------------------------ risk detail
async function viewRisk(id, tab) {
  const r = await api('/risks/' + id);
  const p = persona(); tab = tab || S.tab || 'overview';
  const fw = (refs) => refs.map(([f, i]) => { const cat = S.meta.frameworks.find((x) => x.key === f); const item = cat && cat.items.find((x) => x.id === i); return `<span class="tag" title="${esc(item ? item.name : '')}">${esc(cat ? cat.short : f)} ${esc(i)}</span>`; }).join('');
  const tech = (ids) => ids.map((t) => { const n = S.meta.attack_techniques.find((x) => x.id === t); return `<span class="tag" title="${esc(n ? n.name : '')}">${esc(t)}${n ? ' ' + esc(n.name) : ''}</span>`; }).join('');
  const tabs = [['overview', 'Overview'], ['scoring', 'Scoring'], ['controls', `Controls (${r.controls.length})`], ['treatment', `Treatment (${r.treatments.length})`], ['kris', `Indicators (${r.kris.length})`], ['acceptance', 'Acceptance'], ['history', 'History']];
  const appetite = r.appetite.breach ? `<div class="banner bad"><b>Outside risk appetite.</b> ${esc(r.appetite.reasons.join('. '))}. Someone has to decide: treat it, transfer it, or formally accept it.</div>` : r.appetite.defined ? '<div class="banner ok">Inside the risk appetite set for this category.</div>' : '';
  const stale = r.review_overdue ? `<div class="banner bad">Review overdue since ${r.next_review_at}. The score may no longer reflect reality.</div>` : '';
  const acc = r.active_acceptance ? `<div class="banner ${r.active_acceptance.expired ? 'bad' : 'info'}">${r.active_acceptance.expired ? 'Acceptance EXPIRED on' : 'Accepted by'} ${esc(r.active_acceptance.accepted_by)} ${r.active_acceptance.expired ? '' : 'until'} ${date(r.active_acceptance.expires_at)}.</div>` : '';
  $('#view').innerHTML = `
    <div class="toolbar"><a href="#/risks" class="muted">← Risks</a><span class="muted">${r.id}</span>
      <span style="margin-left:auto"></span>
      ${can('risk:write') ? `<button class="btn" id="btnReview">Mark reviewed</button><a class="btn" href="#/edit/${r.id}">Edit</a>` : ''}
      ${can('risk:delete') ? '<button class="btn danger" id="btnDelete">Delete</button>' : ''}
    </div>
    <h1>${esc(r.title)}</h1>
    <div class="toolbar small muted"><span>${esc(r.category)}</span><span>Owner: <b>${esc(r.owner) || '–'}</b></span><span>Status: <b>${esc(r.status)}</b></span>
      <span>Inherent ${r.inherent_score} ${chip(r.inherent_band)}</span><span>Residual ${r.residual_score} ${chip(r.residual_band)}</span>
      ${r.fair ? `<span>Bad-year loss ${money(r.fair.residual.ale_p90)}</span>` : ''}<span>Next review ${r.next_review_at}</span>${r.tags.map((t) => `<span class="tag">${esc(t)}</span>`).join('')}</div>
    ${appetite}${stale}${acc}
    <div class="tabs">${tabs.map(([k, l]) => `<button data-tab="${k}" class="${k === tab ? 'active' : ''}">${l}</button>`).join('')}</div>
    <div id="tab"></div>`;
  document.querySelectorAll('.tabs button').forEach((b) => b.addEventListener('click', () => { S.tab = b.dataset.tab; viewRisk(id, b.dataset.tab); }));
  const btnR = $('#btnReview'); if (btnR) btnR.addEventListener('click', async () => { const note = prompt('Review note (optional):', '') ; if (note === null) return; await api(`/risks/${id}/review`, { method: 'POST', json: { note } }); toast('Marked as reviewed'); viewRisk(id, tab); });
  const btnD = $('#btnDelete'); if (btnD) btnD.addEventListener('click', async () => { if (!confirm(`Delete ${r.id}? The deletion is recorded in the audit trail.`)) return; await api('/risks/' + id, { method: 'DELETE' }); toast('Deleted'); location.hash = '#/risks'; });
  const T = $('#tab');

  if (tab === 'overview') {
    T.innerHTML = `<div class="split">
      <div class="card"><h3>What could go wrong</h3><p>${esc(r.description) || '<span class="muted">No description</span>'}</p>
        <h3 style="margin-top:14px">What it would mean for the business</h3><p>${esc(r.business_impact) || '<span class="muted">Not described yet</span>'}</p>
        <dl class="kv" style="margin-top:14px"><dt>What is at stake</dt><dd>${esc(r.asset) || '–'}</dd><dt>Who or what causes it</dt><dd>${esc(r.threat_source) || '–'}</dd><dt>Why we are exposed</dt><dd>${esc(r.vulnerability) || '–'}</dd>
        <dt>Review cadence</dt><dd>every ${r.review_frequency_days} days · last ${date(r.last_reviewed_at) || 'never'} · next ${r.next_review_at}</dd><dt>Created</dt><dd>${date(r.created_at)} by ${esc(r.created_by)}</dd></dl></div>
      <div class="card">${p.technical ? `<h3>Engineer view</h3>
        <dl class="kv"><dt>ATT&amp;CK / ATLAS</dt><dd>${tech(r.attack_techniques) || '–'}</dd><dt>CVSS</dt><dd>${r.cvss ?? '–'}</dd><dt>Frameworks</dt><dd>${fw(r.framework_refs) || '–'}</dd><dt>Scenario</dt><dd>${esc(r.scenario_key || '–')}</dd></dl>` : `<h3>In plain terms</h3>
        <p><b>How likely:</b> ${esc(lik(r.residual_likelihood).label)} — ${esc(lik(r.residual_likelihood).plain)}.</p>
        <p><b>How bad:</b> ${esc(imp(r.residual_impact).label)} — ${esc(imp(r.residual_impact).plain)}.</p>
        <p class="small muted">These are the <i>residual</i> levels: what is left after the ${r.controls.length} control${r.controls.length === 1 ? '' : 's'} we have evidence for.</p>`}
        <h3 style="margin-top:14px">Evidence files (${r.evidence.length})</h3>
        ${r.evidence.map((e) => `<div class="stat"><span><a href="/api/evidence/${e.id}/download">${esc(e.filename)}</a> ${tier(e.tier)}<br><span class="small muted">${esc(e.note)} · ${(e.size / 1024).toFixed(1)} KB · sha256 ${e.sha256.slice(0, 12)}… · ${esc(e.uploaded_by)} ${date(e.uploaded_at)}</span></span></div>`).join('') || '<p class="muted small">No files attached.</p>'}
        ${can('evidence:write') ? `<form id="evForm" style="margin-top:10px" class="row"><input type="file" name="file" required><select name="tier"><option value="1">T1 Self-declared</option><option value="2">T2 Scanner-observed</option><option value="3">T3 SIEM-verified</option></select><input name="note" placeholder="What this proves"><button class="btn sm">Attach</button></form>` : ''}
      </div></div>`;
    const ef = $('#evForm'); if (ef) ef.addEventListener('submit', async (e) => { e.preventDefault(); const fd = new FormData(ef); fd.append('entity_type', 'risk'); fd.append('entity_id', id); await api('/evidence', { method: 'POST', body: fd }); toast('Evidence attached and hashed'); viewRisk(id, tab); });
  }

  if (tab === 'scoring') {
    const sug = r.suggested_residual; const f = r.fair;
    const mini = (L, I) => { const m = Array.from({ length: 5 }, () => Array.from({ length: 5 }, () => [])); m[L - 1][I - 1] = [r.id]; return heatmapHTML(m, [L, I], 'score'); };
    T.innerHTML = `<div class="grid g2">
      <div class="card"><h3>Inherent (no controls)</h3>${mini(r.inherent_likelihood, r.inherent_impact)}<p class="small" style="margin-top:8px"><b>${esc(lik(r.inherent_likelihood).label)}</b> × <b>${esc(imp(r.inherent_impact).label)}</b> = ${r.inherent_score} ${chip(r.inherent_band)}</p></div>
      <div class="card"><h3>Residual (after evidence-weighted controls)</h3>${mini(r.residual_likelihood, r.residual_impact)}<p class="small" style="margin-top:8px"><b>${esc(lik(r.residual_likelihood).label)}</b> × <b>${esc(imp(r.residual_impact).label)}</b> = ${r.residual_score} ${chip(r.residual_band)} ${r.residual_override ? '<span class="chip gray">manual override</span>' : '<span class="chip info">derived from controls</span>'}</p>
        <div class="stat"><span>Likelihood reduction from preventive controls</span><b>${pct(sug.likelihood_reduction)} → ×${sug.likelihood_scale}</b></div>
        <div class="stat"><span>Impact reduction from detective/corrective controls</span><b>${pct(sug.impact_reduction)} → ×${sug.impact_scale}</b></div>
        <div class="stat"><span>Suggested residual</span><b>L${sug.likelihood} × I${sug.impact}</b></div>
        <p class="small muted" style="margin-top:6px">Controls cannot drop likelihood by more than 60% or impact by more than 40%, and controls that are only "self-declared" earn half credit. See docs/METHODOLOGY.md.</p></div>
    </div>
    <div class="card" style="margin-top:16px"><h3>Put a number on it (FAIR-style)</h3>
      ${f ? `<div class="split"><div><canvas id="lec1"></canvas></div><div>
        <table><tr><th></th><th>No controls</th><th>After controls</th></tr>
        <tr><td>Chance of at least one loss this year</td><td>${pct(f.inherent.probability_of_loss)}</td><td>${pct(f.residual.probability_of_loss)}</td></tr>
        <tr><td>Expected annual loss (ALE, mean)</td><td>${money(f.inherent.ale_mean)}</td><td><b>${money(f.residual.ale_mean)}</b></td></tr>
        <tr><td>Typical year (median)</td><td>${money(f.inherent.ale_median)}</td><td>${money(f.residual.ale_median)}</td></tr>
        <tr><td>Bad year, 1-in-10 (P90)</td><td>${money(f.inherent.ale_p90)}</td><td><b>${money(f.residual.ale_p90)}</b></td></tr>
        <tr><td>Very bad year, 1-in-20 (P95)</td><td>${money(f.inherent.ale_p95)}</td><td>${money(f.residual.ale_p95)}</td></tr>
        <tr><td>Textbook ALE = ARO × SLE</td><td>${money(f.inherent.ale_simple)}</td><td>${money(f.residual.ale_simple)}</td></tr></table>
        <p class="small muted" style="margin-top:8px">Inputs: ${r.lef_min}–${r.lef_likely}–${r.lef_max} events/year; ${money(r.lm_min)}–${money(r.lm_likely)}–${money(r.lm_max)} per event. PERT distributions, ${f.residual.samples.toLocaleString()} simulations, seeded on the risk ID.</p></div></div>`
      : `<p class="muted">Not quantified yet. ${can('risk:write') ? `<a href="#/edit/${r.id}">Edit the risk</a> and fill in the "Put a number on it" step.` : ''}</p>`}
    </div>`;
    if (f) drawExceedance($('#lec1'), [{ label: 'After controls', color: '#1f5eff', curve: f.residual.exceedance_curve }, { label: 'No controls', color: '#c62828', curve: f.inherent.exceedance_curve }]);
  }

  if (tab === 'controls') {
    const all = await api('/controls'); const linked = new Set(r.controls.map((c) => c.id));
    T.innerHTML = `<div class="card"><p class="small muted">Preventive controls lower <b>likelihood</b>; detective and corrective controls lower <b>impact</b>. Credit = effectiveness × implementation × evidence tier (T1 ×0.5, T2 ×0.8, T3 ×1.0).</p>
      <table><tr><th>Control</th><th>Type</th><th>Implementation</th><th>Effectiveness</th><th>Evidence</th><th>Credit</th>${can('risk:write') ? '<th></th>' : ''}</tr>
      ${r.controls.map((c) => `<tr><td><b>${esc(c.name)}</b><div class="small muted">${esc(c.evidence_source || 'no evidence source named')}${p.technical ? '<br>' + fw(c.framework_refs) : ''}</div></td><td>${esc(c.control_type)}</td><td>${esc(c.implementation_status)}</td><td>${c.effectiveness}%</td><td>${tier(c.evidence_tier)}</td><td><b>${pct(c.credit)}</b></td>${can('risk:write') ? `<td><button class="btn sm" data-unlink="${c.id}">Unlink</button></td>` : ''}</tr>`).join('') || '<tr><td colspan="7" class="muted">No controls linked: residual = inherent.</td></tr>'}</table>
      ${can('risk:write') ? `<div class="toolbar" style="margin-top:12px"><select id="addCtl"><option value="">Link an existing control…</option>${all.filter((c) => !linked.has(c.id)).map((c) => `<option value="${c.id}">${esc(c.name)} (${esc(c.control_type)}, T${c.evidence_tier})</option>`).join('')}</select><a class="btn" href="#/controls">Manage library</a></div>` : ''}</div>`;
    document.querySelectorAll('[data-unlink]').forEach((b) => b.addEventListener('click', async () => { await api(`/risks/${id}/controls/${b.dataset.unlink}`, { method: 'DELETE' }); viewRisk(id, tab); }));
    const sel = $('#addCtl'); if (sel) sel.addEventListener('change', async () => { if (!sel.value) return; await api(`/risks/${id}/controls/${sel.value}`, { method: 'POST' }); toast('Control linked; residual recomputed'); viewRisk(id, tab); });
  }

  if (tab === 'treatment') {
    const today = new Date().toISOString().slice(0, 10);
    T.innerHTML = `<div class="card"><table><tr><th>Action</th><th>Strategy</th><th>Owner</th><th>Due</th><th>Status</th><th style="width:160px">Progress</th><th>Cost</th>${can('treatment:write') ? '<th></th>' : ''}</tr>
      ${r.treatments.map((t) => { const late = ['Planned', 'In Progress'].includes(t.status) && t.due_date && t.due_date < today; return `<tr><td><b>${esc(t.title)}</b><div class="small muted">${esc(t.description)}</div></td><td>${esc(t.strategy)}</td><td>${esc(t.owner)}</td><td class="nowrap">${date(t.due_date)} ${late ? '<span class="chip warn">late</span>' : ''}</td><td>${esc(t.status)}</td><td><div class="progress"><div class="bar"><i style="width:${t.progress}%"></i></div><span class="small">${t.progress}%</span></div></td><td class="nowrap">${t.cost != null ? money(t.cost) : '–'}</td>${can('treatment:write') ? `<td class="nowrap"><button class="btn sm" data-edit-t="${t.id}">Edit</button> <button class="btn sm danger" data-del-t="${t.id}">✕</button></td>` : ''}</tr>`; }).join('') || '<tr><td colspan="8" class="muted">No treatment actions yet.</td></tr>'}</table>
      ${can('treatment:write') ? '<button class="btn primary" id="addT" style="margin-top:12px">+ Add action</button>' : ''}</div>`;
    const openT = (t) => treatmentForm(id, t, () => viewRisk(id, tab));
    const a = $('#addT'); if (a) a.addEventListener('click', () => openT(null));
    document.querySelectorAll('[data-edit-t]').forEach((b) => b.addEventListener('click', () => openT(r.treatments.find((t) => t.id === b.dataset.editT))));
    document.querySelectorAll('[data-del-t]').forEach((b) => b.addEventListener('click', async () => { if (!confirm('Delete this action?')) return; await api('/treatments/' + b.dataset.delT, { method: 'DELETE' }); viewRisk(id, tab); }));
  }

  if (tab === 'kris') {
    T.innerHTML = `<div class="card"><p class="small muted">Key risk indicators are the early-warning numbers for this risk. Thresholds turn them amber or red before the risk itself materialises.</p>
      <table><tr><th>Indicator</th><th>Current</th><th>Trend</th><th>Warning</th><th>Critical</th><th>Status</th><th>Source</th>${can('kri:write') ? '<th></th>' : ''}</tr>
      ${r.kris.map((k) => `<tr><td><b>${esc(k.name)}</b></td><td class="nowrap">${k.current_value ?? '–'} ${esc(k.unit)}</td><td>${sparkline(k.readings, k.warning, k.critical, k.direction)}</td><td>${k.warning}</td><td>${k.critical}</td><td><span class="chip ${k.status === 'Critical' ? 'bad' : k.status === 'Warning' ? 'warn' : k.status === 'OK' ? 'ok' : 'gray'}">${k.status}</span></td><td class="small">${esc(k.source)}</td>${can('kri:write') ? `<td class="nowrap"><button class="btn sm" data-read="${k.id}">+ Reading</button> <button class="btn sm danger" data-del-k="${k.id}">✕</button></td>` : ''}</tr>`).join('') || '<tr><td colspan="8" class="muted">No indicators yet.</td></tr>'}</table>
      ${can('kri:write') ? '<button class="btn primary" id="addK" style="margin-top:12px">+ Add indicator</button>' : ''}</div>`;
    const a = $('#addK'); if (a) a.addEventListener('click', () => kriForm(id, () => viewRisk(id, tab)));
    document.querySelectorAll('[data-read]').forEach((b) => b.addEventListener('click', async () => { const v = prompt('New reading value:'); if (v === null || v === '') return; await api(`/kris/${b.dataset.read}/readings`, { method: 'POST', json: { value: Number(v) } }); viewRisk(id, tab); }));
    document.querySelectorAll('[data-del-k]').forEach((b) => b.addEventListener('click', async () => { if (!confirm('Delete this indicator?')) return; await api('/kris/' + b.dataset.delK, { method: 'DELETE' }); viewRisk(id, tab); }));
  }

  if (tab === 'acceptance') {
    const max = new Date(Date.now() + 364 * 864e5).toISOString().slice(0, 10);
    T.innerHTML = `<div class="split"><div class="card"><h3>Acceptance history</h3>
      ${r.acceptances.map((a) => `<div class="stat"><span><b>${esc(a.accepted_by)}</b> (${esc(a.role)}) on ${date(a.created_at)}<br><span class="small">${esc(a.rationale)}</span></span><span class="nowrap"><span class="chip ${a.status === 'Active' ? (a.expires_at < new Date().toISOString().slice(0, 10) ? 'bad' : 'ok') : 'gray'}">${a.status}</span><br><span class="small muted">until ${date(a.expires_at)}</span></span></div>`).join('') || '<p class="muted">Never formally accepted.</p>'}</div>
      <div class="card"><h3>Accept this risk</h3><p class="small muted">Accepting means the business knowingly lives with it. Acceptances expire (max 12 months) so forgotten risks resurface.</p>
      ${can('accept') ? `<form id="accForm"><div class="field"><label>Why is this acceptable?</label><textarea name="rationale" required minlength="10" placeholder="e.g. Residual exposure is below appetite and the cost of further controls exceeds the benefit this year."></textarea></div>
        <div class="field"><label>Re-decide by</label><input type="date" name="expires_at" required max="${max}" value="${new Date(Date.now() + 180 * 864e5).toISOString().slice(0, 10)}"></div>
        <button class="btn primary">Record acceptance as ${esc(S.me.name)}</button></form>` : `<p class="muted">Only Executives and Risk Analysts can accept risks. You are viewing as ${esc(S.me.role)}.</p>`}</div></div>`;
    const f = $('#accForm'); if (f) f.addEventListener('submit', async (e) => { e.preventDefault(); await api(`/risks/${id}/accept`, { method: 'POST', json: formData(f) }); toast('Acceptance recorded'); viewRisk(id, tab); });
  }

  if (tab === 'history') {
    T.innerHTML = `<div class="card"><table><tr><th>When</th><th>Who</th><th>What</th><th>Detail</th><th>Hash</th></tr>
      ${r.history.map((h) => `<tr><td class="nowrap small">${esc(h.ts.replace('T', ' ').slice(0, 16))}</td><td class="small">${esc(h.actor)}<br><span class="muted">${esc(h.role)}</span></td><td class="small nowrap">${esc(h.entity_type)} ${esc(h.action)}<br><span class="muted">${esc(h.entity_id)}</span></td><td class="small">${fmtDetail(h.detail)}</td><td class="small muted">${esc(h.hash.slice(0, 10))}…</td></tr>`).join('')}</table></div>`;
  }
}

function fmtDetail(d) {
  if (!d || typeof d !== 'object') return esc(d);
  return Object.entries(d).map(([k, v]) => (v && typeof v === 'object' && 'from' in v && 'to' in v)
    ? `<div><b>${esc(k)}</b>: <s class="muted">${esc(JSON.stringify(v.from))}</s> → ${esc(JSON.stringify(v.to))}</div>`
    : `<div><b>${esc(k)}</b>: ${esc(typeof v === 'object' ? JSON.stringify(v) : v)}</div>`).join('');
}

function treatmentForm(riskId, t, done) {
  const opt = (list, cur) => list.map((v) => `<option ${v === cur ? 'selected' : ''}>${esc(v)}</option>`).join('');
  modal(`<h2>${t ? 'Edit' : 'Add'} treatment action</h2><form id="tf">
    <div class="field"><label>What will be done</label><input name="title" required value="${esc(t?.title || '')}"></div>
    <div class="field"><label>Detail</label><textarea name="description">${esc(t?.description || '')}</textarea></div>
    <div class="row"><div class="field"><label>Strategy</label><select name="strategy">${opt(S.meta.strategies, t?.strategy || 'Mitigate')}</select></div>
    <div class="field"><label>Owner</label><input name="owner" value="${esc(t?.owner || '')}"></div></div>
    <div class="row"><div class="field"><label>Due date</label><input type="date" name="due_date" value="${t?.due_date || ''}"></div>
    <div class="field"><label>Status</label><select name="status">${opt(S.meta.treatment_statuses, t?.status || 'Planned')}</select></div>
    <div class="field"><label>Progress %</label><input type="number" name="progress" min="0" max="100" value="${t?.progress ?? 0}"></div>
    <div class="field"><label>Cost (USD)</label><input type="number" name="cost" min="0" value="${t?.cost ?? ''}"></div></div>
    <div class="toolbar"><button class="btn primary">Save</button><button type="button" class="btn" onclick="closeModal()">Cancel</button></div></form>`);
  $('#tf').addEventListener('submit', async (e) => {
    e.preventDefault(); const d = formData($('#tf')); d.risk_id = riskId; d.progress = Number(d.progress); d.cost = numOrNull(d.cost); d.due_date = d.due_date || null;
    await api(t ? '/treatments/' + t.id : '/treatments', { method: t ? 'PUT' : 'POST', json: d }); closeModal(); toast('Saved'); done();
  });
}

function kriForm(riskId, done) {
  modal(`<h2>Add key risk indicator</h2><form id="kf">
    <div class="field"><label>Name</label><input name="name" required placeholder="e.g. Endpoints without EDR agent"></div>
    <div class="row"><div class="field"><label>Unit</label><input name="unit" placeholder="%, count, days, ms"></div>
    <div class="field"><label>Direction</label><select name="direction"><option value="above_is_bad">Higher is worse</option><option value="below_is_bad">Lower is worse</option></select></div></div>
    <div class="row"><div class="field"><label>Warning threshold</label><input type="number" step="any" name="warning" required></div>
    <div class="field"><label>Critical threshold</label><input type="number" step="any" name="critical" required></div>
    <div class="field"><label>Current value</label><input type="number" step="any" name="current_value"></div></div>
    <div class="field"><label>Where the number comes from</label><input name="source" placeholder="e.g. Wiz, Splunk saved search, KnowBe4"></div>
    <div class="toolbar"><button class="btn primary">Save</button><button type="button" class="btn" onclick="closeModal()">Cancel</button></div></form>`);
  $('#kf').addEventListener('submit', async (e) => {
    e.preventDefault(); const d = formData($('#kf')); d.risk_id = riskId; d.warning = Number(d.warning); d.critical = Number(d.critical); d.current_value = numOrNull(d.current_value);
    await api('/kris', { method: 'POST', json: d }); closeModal(); done();
  });
}

// ------------------------------------------------------------------ wizard (create & edit)
const BLANK = () => ({ title: '', description: '', business_impact: '', category: 'Cyber Security', asset: '', threat_source: '', vulnerability: '', owner: '', status: 'Identified',
  inherent_likelihood: 3, inherent_impact: 3, residual_override: false, residual_likelihood: null, residual_impact: null,
  lef_min: null, lef_likely: null, lef_max: null, lm_min: null, lm_likely: null, lm_max: null, cvss: null, attack_techniques: [], framework_refs: [], tags: [], scenario_key: null, review_frequency_days: 90, control_ids: [] });

async function viewWizard(editId) {
  if (!can('risk:write')) { $('#view').innerHTML = `<div class="banner bad">Your current persona (${esc(S.me.role)}) cannot create or edit risks. Switch to Business owner or Security engineer.</div>`; return; }
  const p = persona();
  if (editId) {
    const r = await api('/risks/' + editId);
    S.draft = { ...BLANK(), ...Object.fromEntries(Object.keys(BLANK()).map((k) => [k, r[k]])), control_ids: r.controls.map((c) => c.id), residual_override: !!r.residual_override, _editId: editId };
    if (!S.draft.residual_override) { S.draft.residual_likelihood = null; S.draft.residual_impact = null; }
    S.step = 1;
  } else if (!S.draft || S.draft._editId) { S.draft = BLANK(); S.step = 0; }
  renderWizard(p);
}

function renderWizard(p) {
  const d = S.draft; const editing = !!d._editId;
  const steps = [['Start', !editing], ['Describe', true], ['How likely & how bad', true], ['Put a number on it', true], ['Technical details', p.technical], ['Review & save', true]];
  const visible = steps.map((s, i) => ({ i, name: s[0], on: s[1] })).filter((s) => s.on);
  if (!steps[S.step][1]) S.step = visible.find((v) => v.i > S.step)?.i ?? 5;
  const stepBar = `<div class="steps">${visible.map((v) => `<div class="${v.i === S.step ? 'active' : v.i < S.step ? 'done' : ''}">${v.name}</div>`).join('')}</div>`;
  const nav = (backOk = true) => `<div class="toolbar" style="margin-top:16px">${backOk && visible[0].i < S.step ? '<button type="button" class="btn" id="wBack">← Back</button>' : ''}<span style="flex:1"></span>${S.step < 5 ? '<button class="btn primary" id="wNext">Continue →</button>' : `<button class="btn primary" id="wNext">${editing ? 'Save changes' : 'Create risk'}</button>`}</div>`;
  const opt = (list, cur) => list.map((v) => `<option ${v === cur ? 'selected' : ''}>${esc(v)}</option>`).join('');
  let body = '';

  if (S.step === 0) {
    body = `<p>Start from a ready-made scenario (recommended) or describe a new risk from scratch. Scenarios come with plain-English wording, realistic numbers and the right technical references already attached.</p>
      <div class="toolbar"><input id="scq" placeholder="Filter scenarios…" style="max-width:300px"><button type="button" class="btn" id="blank">Start blank instead</button></div>
      <div class="cards" id="scen">${S.meta.scenarios.map((s) => `<div class="scen" data-k="${s.key}"><div class="cat">${esc(s.category)}</div><b>${esc(s.title)}</b><small class="muted">${esc(s.business_impact.slice(0, 110))}…</small><div style="margin-top:6px">${chip(S.meta.bands.find((b) => s.likelihood * s.impact >= b.min && s.likelihood * s.impact <= b.max).name)} <span class="small muted">${s.suggested_control_keys.length} suggested controls</span></div></div>`).join('')}</div>`;
  }
  if (S.step === 1) {
    body = `<div class="help">Write it the way you would explain it to your CEO in the lift. No jargon needed.</div>
      <div class="field"><label>Give the risk a short name</label><input name="title" required value="${esc(d.title)}" placeholder="e.g. Ransomware takes the product offline"></div>
      <div class="field"><label>What could go wrong?</label><textarea name="description" placeholder="Describe the event: who does what, to which system, how.">${esc(d.description)}</textarea></div>
      <div class="field"><label>If it happened, what would it mean for the business?</label><textarea name="business_impact" placeholder="Money, customers, regulators, reputation, people. Be concrete.">${esc(d.business_impact)}</textarea><div class="hint">This sentence is what executives will read on the dashboard.</div></div>
      <div class="row"><div class="field"><label>Category</label><select name="category">${opt(S.meta.categories, d.category)}</select></div><div class="field"><label>Who owns this risk?</label><input name="owner" value="${esc(d.owner)}" list="owners" placeholder="A person, not a team"><datalist id="owners">${S.meta.users.map((u) => `<option value="${esc(u.name)}">`).join('')}</datalist></div></div>
      <div class="row"><div class="field"><label>What is at stake? (asset)</label><input name="asset" value="${esc(d.asset)}" placeholder="Customer database, inference API…"></div><div class="field"><label>Who or what causes it? (threat)</label><input name="threat_source" value="${esc(d.threat_source)}" placeholder="Criminal group, careless insider, regulator…"></div><div class="field"><label>Why are we exposed? (weakness)</label><input name="vulnerability" value="${esc(d.vulnerability)}" placeholder="No MFA, flat network, no DPIA…"></div></div>`;
  }
  if (S.step === 2) {
    const cards = (scale, key, cur, extra) => `<div class="cards">${scale.map((s) => `<label class="pick ${s.level === cur ? 'sel' : ''}"><input type="radio" name="${key}" value="${s.level}" ${s.level === cur ? 'checked' : ''} style="display:none"><b>${s.level} · ${esc(s.label)}</b><small>${esc(s.plain)}</small><small><i>${esc(s[extra])}</i></small></label>`).join('')}</div>`;
    body = `<div class="help">Think about the risk <b>before</b> any controls, as if nothing protected you. The register works out what your controls are worth afterwards, so you cannot talk yourself into a low score.</div>
      <h3>How likely is it in the next 12 months?</h3>${cards(S.meta.likelihood_scale, 'inherent_likelihood', Number(d.inherent_likelihood), 'annual_probability')}
      <h3 style="margin-top:18px">How bad would it be?</h3>${cards(S.meta.impact_scale, 'inherent_impact', Number(d.inherent_impact), 'financial')}
      <details style="margin-top:14px"><summary>Not sure? Use the translator</summary><div class="row" style="margin-top:8px"><div class="field"><label>If it cost roughly this much…</label><input type="number" id="trDollars" placeholder="e.g. 250000"></div><div class="field"><label>…and happened about this many times a year</label><input type="number" step="any" id="trEvents" placeholder="e.g. 0.5 = once every two years"></div><div class="field"><label>&nbsp;</label><button type="button" class="btn" id="trGo">Suggest levels</button></div></div><div id="trOut" class="small"></div></details>`;
  }
  if (S.step === 3) {
    const has = d.lef_likely !== null && d.lm_likely !== null;
    body = `<div class="help">Optional but powerful: three guesses each for <b>how often</b> and <b>how much</b>. The register runs thousands of simulated years and turns that into money the board understands. Leave it blank if you honestly have no idea.</div>
      <div class="toolbar"><label><input type="checkbox" id="useFair" ${has ? 'checked' : ''} style="width:auto"> Put a number on this risk</label><button type="button" class="btn sm" id="fairSuggest">Suggest numbers from my likelihood / impact answers</button></div>
      <div id="fairBox" class="${has ? '' : 'hidden'}">
      <div class="row"><div class="card flat"><h3>How often, per year?</h3><div class="row"><div class="field"><label>Best case</label><input type="number" step="any" min="0" name="lef_min" value="${d.lef_min ?? ''}"></div><div class="field"><label>Most likely</label><input type="number" step="any" min="0" name="lef_likely" value="${d.lef_likely ?? ''}"></div><div class="field"><label>Worst case</label><input type="number" step="any" min="0" name="lef_max" value="${d.lef_max ?? ''}"></div></div><div class="hint">0.1 = once a decade · 1 = yearly · 12 = monthly</div></div>
      <div class="card flat"><h3>How much per event, USD?</h3><div class="row"><div class="field"><label>Best case</label><input type="number" min="0" name="lm_min" value="${d.lm_min ?? ''}"></div><div class="field"><label>Most likely</label><input type="number" min="0" name="lm_likely" value="${d.lm_likely ?? ''}"></div><div class="field"><label>Worst case</label><input type="number" min="0" name="lm_max" value="${d.lm_max ?? ''}"></div></div><div class="hint">Include response cost, downtime, fines, churn, legal.</div></div></div>
      <div class="toolbar"><button type="button" class="btn" id="simGo">Run simulation preview</button><span class="small muted">Preview assumes no controls; the saved risk also simulates the residual.</span></div><div id="simOut"></div></div>`;
  }
  if (S.step === 4) {
    const tq = (d.attack_techniques || []);
    body = `<div class="help">Engineer-only step. Everything here is optional and shows up in the Engineer and Auditor views.</div>
      <div class="row"><div class="field"><label>CVSS base score (if a specific vulnerability)</label><input type="number" step="0.1" min="0" max="10" name="cvss" value="${d.cvss ?? ''}"></div><div class="field"><label>Tags (comma separated)</label><input name="tags" value="${esc((d.tags || []).join(', '))}"></div></div>
      <div class="field"><label>MITRE ATT&amp;CK / ATLAS techniques</label><input id="tq" placeholder="Filter techniques…" style="margin-bottom:6px"><div class="checklist" id="tlist">${S.meta.attack_techniques.map((t) => `<label data-s="${esc((t.id + ' ' + t.name).toLowerCase())}"><input type="checkbox" name="attack_techniques" value="${t.id}" ${tq.includes(t.id) ? 'checked' : ''}><span><b>${t.id}</b> ${esc(t.name)}</span></label>`).join('')}</div></div>
      <div class="field"><label>Framework references</label>${S.meta.frameworks.map((f) => `<details ${d.framework_refs.some((r) => r[0] === f.key) ? 'open' : ''}><summary>${esc(f.name)} (${d.framework_refs.filter((r) => r[0] === f.key).length})</summary><div class="checklist" style="margin:6px 0 10px">${f.items.map((i) => `<label><input type="checkbox" name="fw" value="${f.key}|${esc(i.id)}" ${d.framework_refs.some((r) => r[0] === f.key && r[1] === i.id) ? 'checked' : ''}><span><b>${esc(i.id)}</b> ${esc(i.name)}</span></label>`).join('')}</div></details>`).join('')}</div>`;
  }
  if (S.step === 5) {
    body = `<div class="split"><div><div class="card flat"><h2>${esc(d.title) || '<span class="muted">Untitled</span>'}</h2><p>${esc(d.description)}</p><p><b>Business impact:</b> ${esc(d.business_impact)}</p>
      <dl class="kv"><dt>Category</dt><dd>${esc(d.category)}</dd><dt>Owner</dt><dd>${esc(d.owner) || '–'}</dd><dt>Inherent</dt><dd>L${d.inherent_likelihood} ${esc(lik(d.inherent_likelihood).label)} × I${d.inherent_impact} ${esc(imp(d.inherent_impact).label)} = ${d.inherent_likelihood * d.inherent_impact} ${chip(S.meta.bands.find((b) => d.inherent_likelihood * d.inherent_impact >= b.min && d.inherent_likelihood * d.inherent_impact <= b.max).name)}</dd>
      <dt>Quantified</dt><dd>${d.lef_likely !== null ? `${d.lef_min}–${d.lef_likely}–${d.lef_max} events/yr · ${money(d.lm_min)}–${money(d.lm_likely)}–${money(d.lm_max)} per event` : 'no'}</dd>
      ${p.technical ? `<dt>Techniques</dt><dd>${esc(d.attack_techniques.join(', ')) || '–'}</dd><dt>Frameworks</dt><dd>${d.framework_refs.map((r) => `<span class="tag">${esc(r[1])}</span>`).join('') || '–'}</dd>` : ''}</dl></div></div>
      <div><div class="card flat"><h3>Housekeeping</h3><div class="row"><div class="field"><label>Status</label><select name="status">${opt(S.meta.risk_statuses, d.status)}</select></div><div class="field"><label>Review every (days)</label><input type="number" name="review_frequency_days" min="7" max="730" value="${d.review_frequency_days}"></div></div>
      <details ${d.residual_override ? 'open' : ''}><summary>Override the derived residual score (discouraged)</summary><div class="row" style="margin-top:6px"><div class="field"><label><input type="checkbox" name="residual_override" ${d.residual_override ? 'checked' : ''} style="width:auto"> Use manual residual</label></div><div class="field"><label>Likelihood</label><select name="residual_likelihood">${[1, 2, 3, 4, 5].map((n) => `<option ${n === d.residual_likelihood ? 'selected' : ''}>${n}</option>`).join('')}</select></div><div class="field"><label>Impact</label><select name="residual_impact">${[1, 2, 3, 4, 5].map((n) => `<option ${n === d.residual_impact ? 'selected' : ''}>${n}</option>`).join('')}</select></div></div><p class="small muted">Overrides are flagged on the risk and in the audit trail.</p></details></div>
      <div class="card flat" style="margin-top:12px"><h3>Controls already in place</h3><p class="small muted">Tick what genuinely exists. The residual score is derived from these and their evidence tier.</p><div class="checklist" id="ctlList">Loading…</div></div></div></div>`;
  }

  $('#view').innerHTML = `<div class="wizard"><h1>${editing ? 'Edit risk ' + esc(d._editId) : 'New risk'}</h1>${stepBar}<form id="wf">${body}${nav()}</form></div>`;
  const form = $('#wf');

  // step-specific wiring
  if (S.step === 0) {
    $('#scq').addEventListener('input', (e) => { const q = e.target.value.toLowerCase(); document.querySelectorAll('.scen').forEach((el) => el.classList.toggle('hidden', !el.textContent.toLowerCase().includes(q))); });
    $('#blank').addEventListener('click', () => { S.draft = BLANK(); S.step = 1; renderWizard(p); });
    document.querySelectorAll('.scen').forEach((el) => el.addEventListener('click', async () => {
      const s = S.meta.scenarios.find((x) => x.key === el.dataset.k);
      const ctls = await api('/controls');
      S.draft = { ...BLANK(), title: s.title, description: s.description, business_impact: s.business_impact, category: s.category, asset: s.asset, threat_source: s.threat_source, vulnerability: s.vulnerability,
        inherent_likelihood: s.likelihood, inherent_impact: s.impact, ...s.fair, attack_techniques: [...s.attack_techniques], framework_refs: s.framework_refs.map((r) => [...r]), tags: [...s.tags], scenario_key: s.key,
        control_ids: ctls.filter((c) => s.suggested_control_keys.includes((S.meta.control_keys || {})[c.id])).map((c) => c.id), _suggested_keys: s.suggested_control_keys };
      S.step = 1; renderWizard(p);
    }));
    $('#wNext').classList.add('hidden');
  }
  if (S.step === 2) {
    document.querySelectorAll('.pick input').forEach((i) => i.addEventListener('change', () => { document.querySelectorAll(`.pick input[name=${i.name}]`).forEach((x) => x.closest('.pick').classList.toggle('sel', x.checked)); }));
    $('#trGo').addEventListener('click', async () => {
      const body = {}; if ($('#trDollars').value) body.loss_dollars = Number($('#trDollars').value); if ($('#trEvents').value) body.events_per_year = Number($('#trEvents').value);
      const t = await api('/translate', { method: 'POST', json: body }); let out = '';
      if (t.likelihood) { out += `<p>Likelihood → <b>${t.likelihood.level} ${esc(t.likelihood.label)}</b> (${esc(t.likelihood.plain)})</p>`; const el = form.querySelector(`input[name=inherent_likelihood][value="${t.likelihood.level}"]`); el.checked = true; el.dispatchEvent(new Event('change')); }
      if (t.impact) { out += `<p>Impact → <b>${t.impact.level} ${esc(t.impact.label)}</b> (${esc(t.impact.plain)})</p>`; const el = form.querySelector(`input[name=inherent_impact][value="${t.impact.level}"]`); el.checked = true; el.dispatchEvent(new Event('change')); }
      $('#trOut').innerHTML = out || '<span class="muted">Enter at least one number.</span>';
    });
  }
  if (S.step === 3) {
    $('#useFair').addEventListener('change', (e) => $('#fairBox').classList.toggle('hidden', !e.target.checked));
    $('#fairSuggest').addEventListener('click', async () => { const s = await api(`/fair-defaults?likelihood=${d.inherent_likelihood}&impact=${d.inherent_impact}`); Object.entries(s).forEach(([k, v]) => { form.querySelector(`[name=${k}]`).value = v; }); $('#useFair').checked = true; $('#fairBox').classList.remove('hidden'); });
    $('#simGo').addEventListener('click', async () => {
      const v = formData(form); const body = {}; ['lef_min', 'lef_likely', 'lef_max', 'lm_min', 'lm_likely', 'lm_max'].forEach((k) => body[k] = Number(v[k] || 0));
      const s = await api('/simulate', { method: 'POST', json: body });
      $('#simOut').innerHTML = `<div class="split" style="margin-top:10px"><canvas id="lecw"></canvas><div><div class="stat"><span>Chance of at least one loss this year</span><b>${pct(s.inherent.probability_of_loss)}</b></div><div class="stat"><span>Expected annual loss</span><b>${money(s.inherent.ale_mean)}</b></div><div class="stat"><span>Bad year (P90)</span><b>${money(s.inherent.ale_p90)}</b></div><div class="stat"><span>Very bad year (P95)</span><b>${money(s.inherent.ale_p95)}</b></div><div class="stat"><span>Implied qualitative levels</span><b>L${s.suggested_likelihood} × I${s.suggested_impact}</b></div><p class="small muted">If the implied levels disagree a lot with your word-based answers, one of them is wrong. That disagreement is the point.</p></div></div>`;
      drawExceedance($('#lecw'), [{ label: 'No controls', color: '#c62828', curve: s.inherent.exceedance_curve }]);
    });
  }
  if (S.step === 4) {
    $('#tq').addEventListener('input', (e) => { const q = e.target.value.toLowerCase(); document.querySelectorAll('#tlist label').forEach((l) => l.classList.toggle('hidden', q && !l.dataset.s.includes(q) && !l.querySelector('input').checked)); });
  }
  if (S.step === 5) {
    api('/controls').then((ctls) => {
      const sug = new Set(d._suggested_keys || []);
      $('#ctlList').innerHTML = ctls.map((c) => `<label><input type="checkbox" name="control_ids" value="${c.id}" ${d.control_ids.includes(c.id) ? 'checked' : ''}><span><b>${esc(c.name)}</b><br><span class="muted">${esc(c.control_type)} · ${esc(c.implementation_status)} · ${c.effectiveness}% · ${tier(c.evidence_tier)}</span></span></label>`).join('') || '<span class="muted">No controls in the library yet.</span>';
      void sug;
    });
  }

  const collect = () => {
    const v = formData(form);
    if (S.step === 1) ['title', 'description', 'business_impact', 'category', 'owner', 'asset', 'threat_source', 'vulnerability'].forEach((k) => d[k] = (v[k] ?? '').trim());
    if (S.step === 2) { d.inherent_likelihood = Number(v.inherent_likelihood || d.inherent_likelihood); d.inherent_impact = Number(v.inherent_impact || d.inherent_impact); }
    if (S.step === 3) { const on = $('#useFair').checked; ['lef_min', 'lef_likely', 'lef_max', 'lm_min', 'lm_likely', 'lm_max'].forEach((k) => d[k] = on ? numOrNull(v[k]) : null); }
    if (S.step === 4) { d.cvss = numOrNull(v.cvss); d.tags = String(v.tags || '').split(',').map((t) => t.trim()).filter(Boolean); d.attack_techniques = [].concat(v.attack_techniques || []); d.framework_refs = [].concat(v.fw || []).map((x) => x.split('|')); }
    if (S.step === 5) { d.status = v.status; d.review_frequency_days = Number(v.review_frequency_days); d.residual_override = !!v.residual_override; d.residual_likelihood = d.residual_override ? Number(v.residual_likelihood) : null; d.residual_impact = d.residual_override ? Number(v.residual_impact) : null; d.control_ids = [].concat(v.control_ids || []); }
  };
  const back = $('#wBack'); if (back) back.addEventListener('click', () => { collect(); S.step = visible.filter((x) => x.i < S.step).pop().i; renderWizard(p); });
  form.addEventListener('submit', async (e) => {
    e.preventDefault(); collect();
    if (S.step === 1 && d.title.length < 3) { toast('Give the risk a name', true); return; }
    if (S.step === 3 && $('#useFair').checked) { const ks = ['lef_min', 'lef_likely', 'lef_max', 'lm_min', 'lm_likely', 'lm_max']; if (ks.some((k) => d[k] === null)) { toast('Fill all six numbers or untick "Put a number on this risk"', true); return; } if (!(d.lef_min <= d.lef_likely && d.lef_likely <= d.lef_max && d.lm_min <= d.lm_likely && d.lm_likely <= d.lm_max)) { toast('Best case ≤ most likely ≤ worst case', true); return; } }
    if (S.step < 5) { S.step = visible.find((x) => x.i > S.step).i; renderWizard(p); return; }
    const payload = { ...d }; delete payload._editId; delete payload._suggested_keys;
    const r = await api(editing ? '/risks/' + d._editId : '/risks', { method: editing ? 'PUT' : 'POST', json: payload });
    toast(editing ? 'Risk updated' : `Created ${r.id}: residual ${r.residual_score} (${r.residual_band})`); S.draft = null; S.tab = 'scoring'; location.hash = '#/risk/' + r.id;
  });
}

// ------------------------------------------------------------------ controls library
async function viewControls() {
  const ctls = await api('/controls'); const p = persona();
  const fw = (refs) => refs.map(([f, i]) => `<span class="tag">${esc((S.meta.frameworks.find((x) => x.key === f) || { short: f }).short)} ${esc(i)}</span>`).join('');
  $('#view').innerHTML = `<div class="toolbar"><h1 style="margin:0">Controls <span class="muted small">${ctls.length}</span></h1><span class="muted small">A control only reduces risk in proportion to the evidence that it works.</span>${can('control:write') ? '<button class="btn primary" id="addC" style="margin-left:auto">+ New control</button>' : ''}</div>
    <div class="card"><table><tr><th>Control</th><th>Type</th><th>Implementation</th><th>Effectiveness</th><th>Evidence</th><th>Credit</th><th>Risks</th><th>Owner</th>${can('control:write') ? '<th></th>' : ''}</tr>
    ${ctls.map((c) => `<tr><td><b>${esc(c.name)}</b><div class="small muted">${esc(c.description)}${c.evidence_source ? `<br>Evidence: ${esc(c.evidence_source)}` : ''}${p.technical ? '<br>' + fw(c.framework_refs) : ''}</div></td><td>${esc(c.control_type)}</td><td>${esc(c.implementation_status)}</td><td>${c.effectiveness}%</td><td>${tier(c.evidence_tier)}</td><td><b>${pct(c.credit)}</b></td><td>${c.linked_risks}</td><td class="small">${esc(c.owner)}</td>${can('control:write') ? `<td class="nowrap"><button class="btn sm" data-edit="${c.id}">Edit</button> <button class="btn sm danger" data-del="${c.id}">✕</button></td>` : ''}</tr>`).join('')}</table></div>`;
  const a = $('#addC'); if (a) a.addEventListener('click', () => controlForm(null, viewControls));
  document.querySelectorAll('[data-edit]').forEach((b) => b.addEventListener('click', () => controlForm(ctls.find((c) => c.id === b.dataset.edit), viewControls)));
  document.querySelectorAll('[data-del]').forEach((b) => b.addEventListener('click', async () => { if (!confirm('Delete this control? Linked risks lose its credit.')) return; await api('/controls/' + b.dataset.del, { method: 'DELETE' }); viewControls(); }));
}

function controlForm(c, done) {
  const opt = (list, cur) => list.map((v) => `<option ${v === cur ? 'selected' : ''}>${esc(v)}</option>`).join('');
  modal(`<h2>${c ? 'Edit' : 'New'} control</h2><form id="cf">
    <div class="field"><label>Name</label><input name="name" required value="${esc(c?.name || '')}"></div>
    <div class="field"><label>Description</label><textarea name="description">${esc(c?.description || '')}</textarea></div>
    <div class="row"><div class="field"><label>Type</label><select name="control_type">${opt(S.meta.control_types, c?.control_type || 'Preventive')}</select><div class="hint">Preventive → likelihood. Detective / Corrective → impact.</div></div>
    <div class="field"><label>Implementation</label><select name="implementation_status">${opt(S.meta.implementation_statuses, c?.implementation_status || 'Not Implemented')}</select></div>
    <div class="field"><label>Design effectiveness %</label><input type="number" name="effectiveness" min="0" max="100" value="${c?.effectiveness ?? 50}"></div></div>
    <div class="row"><div class="field"><label>Evidence tier</label><select name="evidence_tier">${S.meta.evidence_tiers.map((t) => `<option value="${t.tier}" ${Number(c?.evidence_tier || 1) === t.tier ? 'selected' : ''}>T${t.tier} ${esc(t.name)} (×${t.credit})</option>`).join('')}</select><div class="hint">${S.meta.evidence_tiers.map((t) => `T${t.tier}: ${esc(t.plain)}`).join(' ')}</div></div>
    <div class="field"><label>Evidence source (required for T2/T3)</label><input name="evidence_source" value="${esc(c?.evidence_source || '')}" placeholder="Wiz export 2026-10-30, Splunk search llm_*…"></div></div>
    <div class="row"><div class="field"><label>Owner</label><input name="owner" value="${esc(c?.owner || '')}"></div><div class="field"><label>Last tested</label><input type="date" name="last_tested_at" value="${c?.last_tested_at ? c.last_tested_at.slice(0, 10) : ''}"></div></div>
    <div class="field"><label>Framework references</label>${S.meta.frameworks.map((f) => `<details ${(c?.framework_refs || []).some((r) => r[0] === f.key) ? 'open' : ''}><summary>${esc(f.short)}</summary><div class="checklist" style="margin:6px 0">${f.items.map((i) => `<label><input type="checkbox" name="fw" value="${f.key}|${esc(i.id)}" ${(c?.framework_refs || []).some((r) => r[0] === f.key && r[1] === i.id) ? 'checked' : ''}><span><b>${esc(i.id)}</b> ${esc(i.name)}</span></label>`).join('')}</div></details>`).join('')}</div>
    <div class="toolbar"><button class="btn primary">Save</button><button type="button" class="btn" onclick="closeModal()">Cancel</button></div></form>`);
  $('#cf').addEventListener('submit', async (e) => {
    e.preventDefault(); const v = formData($('#cf'));
    const body = { name: v.name, description: v.description, control_type: v.control_type, implementation_status: v.implementation_status, effectiveness: Number(v.effectiveness), evidence_tier: Number(v.evidence_tier), evidence_source: v.evidence_source, owner: v.owner, last_tested_at: v.last_tested_at || null, framework_refs: [].concat(v.fw || []).map((x) => x.split('|')) };
    await api(c ? '/controls/' + c.id : '/controls', { method: c ? 'PUT' : 'POST', json: body }); closeModal(); toast('Saved; residual scores recomputed'); done();
  });
}

// ------------------------------------------------------------------ reports
async function viewReports() {
  $('#view').innerHTML = `<h1>Reports & data</h1><div class="grid g3">
    <div class="card"><h3>Board report</h3><p class="small">Printable, self-contained HTML: headlines, appetite, heat map, every open risk, overdue actions, control assurance, audit integrity.</p><a class="btn primary" href="/api/reports/board" target="_blank">Open board report</a></div>
    <div class="card"><h3>Export</h3><p class="small">Take the register with you. CSV for spreadsheets, JSON for everything including controls, KRIs and audit verification.</p><a class="btn" href="/api/export/csv">Download CSV</a> <a class="btn" href="/api/export/json">Download JSON</a> <a class="btn" href="/docs" target="_blank">API docs</a></div>
    <div class="card"><h3>Import from a spreadsheet</h3><p class="small">Already have a register in Excel or Sheets? Save it as CSV with these columns and bring it across. Bad rows are reported, not dropped silently.</p><a class="btn" href="/api/import/template">Download template</a>
      ${can('import') ? '<form id="impForm" style="margin-top:10px"><input type="file" name="file" accept=".csv" required><button class="btn primary" style="margin-top:8px">Import</button></form><div id="impOut" class="small" style="margin-top:8px"></div>' : '<p class="muted small">Only Risk Analysts can import.</p>'}</div></div>`;
  const f = $('#impForm'); if (f) f.addEventListener('submit', async (e) => { e.preventDefault(); const res = await api('/import/csv', { method: 'POST', body: new FormData(f) }); $('#impOut').innerHTML = `<div class="banner ${res.errors.length ? 'bad' : 'ok'}">Created ${res.created.length} risk(s).${res.errors.length ? ' ' + res.errors.length + ' row(s) rejected:' : ''}</div>${res.errors.map((x) => `<div>Row ${x.row}: ${esc(x.error)}</div>`).join('')}`; });
}

// ------------------------------------------------------------------ audit trail
async function viewAudit() {
  const [log, v] = await Promise.all([api('/audit?limit=300'), api('/audit/verify')]);
  $('#view').innerHTML = `<div class="toolbar"><h1 style="margin:0">Audit trail</h1><span class="chip ${v.ok ? 'ok' : 'bad'}">${esc(v.message)}</span><span class="muted small">${v.entries} entries · chain head ${esc((v.head || '').slice(0, 16))}…</span><input id="aq" placeholder="Filter…" style="margin-left:auto;max-width:260px"></div>
    <div class="help">Every write goes through this log. Each entry's hash includes the previous entry's hash, so editing or deleting history breaks the chain and the verify check fails.</div>
    <div class="card"><table id="alog"><tr><th>#</th><th>When</th><th>Who</th><th>Entity</th><th>Action</th><th>Detail</th><th>Hash</th></tr>
    ${log.map((h) => `<tr><td class="small muted">${h.seq}</td><td class="nowrap small">${esc(h.ts.replace('T', ' ').slice(0, 19))}</td><td class="small">${esc(h.actor)}<br><span class="muted">${esc(h.role)}</span></td><td class="small nowrap">${esc(h.entity_type)} <a href="#/risk/${esc(h.entity_type === 'risk' ? h.entity_id : (h.detail && h.detail.risk_id) || '')}">${esc(h.entity_id)}</a></td><td class="small">${esc(h.action)}</td><td class="small">${fmtDetail(h.detail)}</td><td class="small muted" title="prev ${esc(h.prev_hash)}">${esc(h.hash.slice(0, 10))}…</td></tr>`).join('')}</table></div>`;
  $('#aq').addEventListener('input', (e) => { const q = e.target.value.toLowerCase(); document.querySelectorAll('#alog tr').forEach((tr, i) => { if (i) tr.classList.toggle('hidden', q && !tr.textContent.toLowerCase().includes(q)); }); });
}

// ------------------------------------------------------------------ settings
async function viewSettings() {
  const m = await api('/meta'); S.meta = m; const w = can('settings:write');
  $('#view').innerHTML = `<h1>Settings</h1><div class="grid g2">
    <div class="card"><h3>Organisation</h3><form id="sf"><div class="field"><label>Name</label><input name="org_name" value="${esc(m.settings.org_name || '')}" ${w ? '' : 'disabled'}></div><div class="field"><label>Risk appetite statement</label><textarea name="appetite_statement" ${w ? '' : 'disabled'}>${esc(m.settings.appetite_statement || '')}</textarea><div class="hint">One paragraph the board signed off. It is printed on every report.</div></div>${w ? '<button class="btn primary">Save</button>' : ''}</form>
      <h3 style="margin-top:18px">People & roles</h3><table><tr><th>Name</th><th>Role</th><th>Can</th></tr>${m.users.map((u) => `<tr><td>${esc(u.name)}<br><span class="small muted">${esc(u.title || '')}</span></td><td>${esc(u.role)}</td><td class="small muted">${Object.entries(m.permissions).filter(([, roles]) => roles.includes(u.role)).map(([p]) => p).join(', ') || 'read only'}</td></tr>`).join('')}</table></div>
    <div class="card"><h3>Risk appetite by category</h3><p class="small muted">A risk is "outside appetite" when its residual score <b>or</b> its 1-in-10 bad-year loss exceeds the tolerance.</p>
      <form id="af"><table><tr><th>Category</th><th>Max residual score</th><th>Max P90 loss</th></tr>${m.categories.map((c) => { const a = m.appetite.find((x) => x.category === c) || { max_residual_score: 9, max_ale: 500000, statement: '' }; return `<tr><td>${esc(c)}<input type="hidden" name="category" value="${esc(c)}"><input type="hidden" name="statement" value="${esc(a.statement || '')}"></td><td><input type="number" name="max_residual_score" min="1" max="25" value="${a.max_residual_score}" ${w ? '' : 'disabled'}></td><td><input type="number" name="max_ale" min="0" step="1000" value="${a.max_ale}" ${w ? '' : 'disabled'}></td></tr>`; }).join('')}</table>${w ? '<button class="btn primary" style="margin-top:10px">Save appetite</button>' : ''}</form></div></div>`;
  $('#sf').addEventListener('submit', async (e) => { e.preventDefault(); await api('/settings', { method: 'PUT', json: formData($('#sf')) }); toast('Saved'); S.meta = await api('/meta'); refreshMe(); });
  $('#af').addEventListener('submit', async (e) => { e.preventDefault(); const v = formData($('#af')); const items = [].concat(v.category).map((c, i) => ({ category: c, max_residual_score: Number([].concat(v.max_residual_score)[i]), max_ale: Number([].concat(v.max_ale)[i]), statement: [].concat(v.statement)[i] })); await api('/appetite', { method: 'PUT', json: items }); toast('Appetite saved'); });
}

boot().catch((e) => { $('#view').innerHTML = `<div class="banner bad">Could not load: ${esc(e.message)}</div>`; });
