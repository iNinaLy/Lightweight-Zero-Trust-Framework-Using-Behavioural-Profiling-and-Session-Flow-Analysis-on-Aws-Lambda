import {signIn, signOut, resumeSignIn} from './auth.js';
const $ = (id) => document.getElementById(id);
const state = {config: null, token: null, session: null, summary: null, register: [], reviews: [], audit: [], requests: [], errors: {}, view: 'overview', busy: false};
const paths = {summary: '/api/v1/hr/summary', register: '/api/v1/hr/payroll', reviews: '/api/v1/hr/reviews', audit: '/api/v1/hr/audit'};
const titles = {
  overview: ['THE PEOPLE BEHIND THE NUMBERS', 'HR overview', 'Company-wide payroll, confidential records, and the care they deserve.', 'Overview'],
  payroll: ['CONFIDENTIAL · COMPANY-WIDE', 'Payroll register', 'Salaries and payment information, protected on every request.', 'Payroll'],
  employees: ['PERSONNEL FILES · HR ONLY', 'Employee records', 'Sensitive identity, address, and payment details. Handle with care.', 'Employee records'],
  reviews: ['RESTRICTED PERSONNEL INFORMATION', 'Confidential reviews', 'Private management notes, ratings, and fictional disciplinary records.', 'Reviews'],
  audit: ['ACCOUNTABILITY, BUILT IN', 'Access audit', 'Actual reads, exports, and role denials recorded by the HR service.', 'Audit'],
  access: ['THE RIGHT ROLE. THE RIGHT CONTEXT.', 'Session & access', 'Independent role permissions and behavioural checks protect every HR record.', 'Access'],
};
const escapeHTML = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[character]));
const icon = (name) => `<svg class="icon" aria-hidden="true"><use href="#i-${name}"/></svg>`;
const money = (cents) => new Intl.NumberFormat('en-MY', {style: 'currency', currency: 'MYR'}).format(cents / 100);
const localTime = (value) => new Intl.DateTimeFormat('en-MY', {timeZone: 'Asia/Kuala_Lumpur', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'}).format(new Date(value));
const periodLabel = (value) => value ? new Intl.DateTimeFormat('en-MY', {month: 'long', year: 'numeric', timeZone: 'UTC'}).format(new Date(`${value}-01T12:00:00Z`)) : 'Not loaded';
const signedIn = () => Boolean(state.token);
const allowed = () => signedIn() && state.session?.decision === 'Allow' && state.session?.roleAllowed === true;
let toastTimer;

function toast(message, error = false) {clearTimeout(toastTimer); $('toast').textContent = message; $('toast').classList.toggle('error', error); $('toast').hidden = false; toastTimer = setTimeout(() => {$('toast').hidden = true;}, error ? 10000 : 5000);}
function notice(title, description, kind = '', action = null) {$('notice').className = `notice ${kind}`; $('notice').querySelector('strong').textContent = title; $('notice').querySelector('p').textContent = description; $('notice-action').hidden = !action; if (action) $('notice-action').textContent = action;}
function navigate(view) {
  if (!(view in titles)) return; state.view = view;
  Object.keys(titles).forEach((key) => {$(`${key}-view`).hidden = key !== view;});
  document.querySelectorAll('.nav-item').forEach((button) => {button.classList.toggle('active', button.dataset.view === view); if (button.dataset.view === view) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');});
  const [eyebrow, title, description, crumb] = titles[view]; $('page-eyebrow').textContent = eyebrow; $('page-title').innerHTML = `${escapeHTML(title)}<span>.</span>`; $('page-description').textContent = description; $('breadcrumb-current').textContent = crumb; document.title = `${crumb} · Northstar HR`; $('sidebar').classList.remove('open');
}
function clearRecords() {state.summary = null; state.register = []; state.reviews = []; state.audit = [];}
function renderAccess() {
  const session = state.session;
  $('account-label').textContent = signedIn() ? (session?.staffName?.split(' ')[0] || 'Staff account') : 'Staff sign-in';
  $('account-avatar').textContent = signedIn() ? (session?.staffName?.split(' ').slice(0, 2).map((word) => word[0]).join('') || 'HR') : '↗';
  $('signout-button').hidden = !signedIn(); $('check-access').disabled = !signedIn() || state.busy;
  $('refresh-payroll').disabled = !allowed() || state.busy; $('refresh-audit').disabled = !allowed() || state.busy;
  document.querySelectorAll('[data-requires-access]').forEach((button) => {button.disabled = !allowed() || state.busy;});
  if (!session) {$('session-details').innerHTML = `<p>${signedIn() ? 'Sign-in succeeded. Check access to retrieve your staff role and context.' : 'Sign in to check your HR access.'}</p>`; return;}
  const reasons = {unknown_ip: 'Unfamiliar network', off_hours: 'Outside learned UTC hours', unknown_user_agent: 'Unfamiliar browser or device', unusual_sensitive_action: 'Unfamiliar sensitive action', missing_profile: 'No configured baseline', invalid_profile: 'Invalid baseline', identity_mismatch: 'Identity mismatch'};
  const values = [['Identity', 'Verified by Cognito'], ['Staff account', session.staffName], ['Portal role', session.roleAllowed ? 'HR staff · role permitted' : `${session.role || 'employee'} · HR access denied`], ['Behavioural context', session.decision === 'Allow' ? 'Current context matches baseline' : session.anomalies.map((reason) => reasons[reason] || reason).join(', ')], ['Observed IP', session.observed.sourceIp], ['Observed UTC hour', String(session.observed.utcHour).padStart(2, '0') + ':00–' + String(session.observed.utcHour).padStart(2, '0') + ':59 UTC'], ['Browser / device', session.observed.userAgent]];
  $('session-details').innerHTML = `<dl>${values.map(([key, value]) => `<dt>${escapeHTML(key)}</dt><dd class="${key === 'Browser / device' ? 'device-value' : ''}">${escapeHTML(value)}</dd>`).join('')}</dl>`;
  if (!session.roleAllowed) notice('HR staff permission is required.', 'Your identity is signed in, but this account does not have the trusted HR role. Familiar behaviour cannot grant that role.', 'denied', 'View access');
  else if (session.decision !== 'Allow') notice('HR role verified. Context requires attention.', session.anomalies.map((reason) => reasons[reason] || reason).join(' · ') + '. Confidential access remains restricted.', 'denied', 'View access');
  else notice('HR staff identity and current context verified.', 'Sensitive reads and exports receive their own behavioural and backend role checks. All records here are fictional.');
}
function emptyMessage(key) {return !signedIn() ? 'Staff sign-in is required to access confidential company data.' : !allowed() ? 'Access is restricted. Check Session & access for your role and context.' : state.errors[key] || 'No records match this view.';}
function filteredRegister(searchId, department = 'all') {const query = $(searchId).value.trim().toLowerCase(); return state.register.filter((item) => `${item.name} ${item.employeeId} ${item.jobTitle}`.toLowerCase().includes(query) && (department === 'all' || item.department === department));}
function renderOverview() {
  $('stat-employees').textContent = state.summary?.employeeCount ?? '—'; $('nav-count').textContent = state.summary?.employeeCount ?? '—';
  $('stat-departments').textContent = state.summary ? `${state.summary.departmentCount} departments · company-wide` : 'Company-wide confidential data';
  $('stat-gross').textContent = state.summary ? money(state.summary.grossPayrollCents).replaceAll('\u00a0', ' ') : '—';
  $('stat-reviews').textContent = state.reviews.length || (state.summary ? 0 : '—');
  $('pay-period').textContent = state.summary?.period ? periodLabel(state.summary.period).toUpperCase() : 'PAYROLL PERIOD';
  $('recent-audit').innerHTML = state.audit.length ? state.audit.slice(0, 4).map((item) => `<div class="activity-row"><span class="stat-icon ${item.verdict === 'Deny' ? 'sand' : 'mint'}">${icon(item.action === 'payroll_export' ? 'download' : 'shield')}</span><div><p>${escapeHTML(actionLabel(item.action))}</p><small>${escapeHTML(item.actor)} · ${item.recordCount} records · ${escapeHTML(item.verdict)}</small></div><time datetime="${escapeHTML(item.time)}">${escapeHTML(localTime(item.time))}</time></div>`).join('') : `<div class="empty-inline">${icon('lock')}<p>${escapeHTML(emptyMessage('audit'))}</p></div>`;
}
function renderRegister() {
  const previous = $('payroll-department').value;
  const departments = [...new Set(state.register.map((item) => item.department))].sort();
  $('payroll-department').innerHTML = `<option value="all">All departments</option>${departments.map((department) => `<option>${escapeHTML(department)}</option>`).join('')}`;
  $('payroll-department').value = departments.includes(previous) ? previous : 'all';
  const rows = filteredRegister('payroll-search', $('payroll-department').value);
  $('payroll-count').textContent = state.register.length || '—'; $('register-period').textContent = state.summary?.period ? periodLabel(state.summary.period) : 'No payroll loaded';
  $('payroll-rows').innerHTML = rows.map((item) => `<tr><td><span class="strong">${escapeHTML(item.name)}</span><span class="row-subtitle">${escapeHTML(item.employeeId)} · ${escapeHTML(item.jobTitle)}</span></td><td>${escapeHTML(item.department)}</td><td>${money(item.grossPayCents)}</td><td><span class="strong">${money(item.netPayCents)}</span></td><td><span class="status">${escapeHTML(item.status)}</span></td><td><button class="icon-button" data-record="${escapeHTML(item.employeeId)}" aria-label="View ${escapeHTML(item.name)} confidential record" title="View confidential file">${icon('eye')}</button></td></tr>`).join('');
  $('payroll-empty').hidden = rows.length > 0; $('payroll-empty').querySelector('p').textContent = emptyMessage('register'); $('payroll-result').textContent = `${rows.length} of ${state.register.length} confidential records`;
}
function renderEmployees() {
  const rows = filteredRegister('employee-search');
  $('employee-grid').innerHTML = rows.map((item) => `<article class="employee-card"><div class="employee-card-top"><span class="employee-initials">${escapeHTML(item.name.split(' ').slice(0, 2).map((word) => word[0]).join(''))}</span><div><h3>${escapeHTML(item.name)}</h3><small>${escapeHTML(item.employeeId)} · ${escapeHTML(item.department)}</small></div></div><p>${escapeHTML(item.jobTitle)}</p><div class="employee-card-footer"><button class="text-button" data-record="${escapeHTML(item.employeeId)}">Open confidential file ${icon('arrow')}</button><span class="mini-classification">${icon('lock')}HR ONLY</span></div></article>`).join('');
  $('employee-empty').hidden = rows.length > 0; $('employee-empty').querySelector('p').textContent = emptyMessage('register');
}
function renderReviews() {
  $('review-rows').innerHTML = state.reviews.map((item) => `<tr><td><span class="strong">${escapeHTML(item.name)}</span><small class="row-subtitle">${escapeHTML(item.employeeId)}</small></td><td>${escapeHTML(item.department)}</td><td>${escapeHTML(item.period)}</td><td>${item.rating} / 5</td><td><span class="status pending">Confidential</span></td><td><button class="icon-button" data-review="${escapeHTML(item.employeeId)}" aria-label="Read ${escapeHTML(item.name)} confidential review">${icon('eye')}</button></td></tr>`).join('');
  $('review-empty').hidden = state.reviews.length > 0; $('review-empty').querySelector('p').textContent = emptyMessage('reviews');
}
function actionLabel(action) {return ({hr_overview: 'HR overview read', payroll_register_view: 'Payroll register viewed', employee_record_view: 'Confidential employee file read', reviews_list: 'Review register viewed', review_record_view: 'Restricted review read', payroll_export: 'Full payroll exported'})[action] || action;}
function renderAudit() {
  $('audit-rows').innerHTML = state.audit.map((item) => `<tr><td>${escapeHTML(localTime(item.time))}</td><td><span class="strong">${escapeHTML(item.actor)}</span><small class="row-subtitle">${escapeHTML(item.role)} · ${escapeHTML(item.sourceIp)}</small></td><td><span class="audit-operation">${escapeHTML(actionLabel(item.action))}</span><small class="row-subtitle">${escapeHTML(item.reason || item.requestId)}</small></td><td>${item.recordCount}</td><td><span class="status ${item.verdict === 'Deny' ? 'denied' : 'allow'}">${escapeHTML(item.verdict)}</span></td></tr>`).join('');
  $('audit-empty').hidden = state.audit.length > 0; $('audit-empty').querySelector('p').textContent = emptyMessage('audit');
}
function renderRequests() {$('request-list').innerHTML = state.requests.length ? state.requests.slice(-30).reverse().map((item) => `<div class="request-row"><span class="http-status ${item.status >= 400 || !item.status ? 'denied' : ''}">${item.status || 'Network error'}</span><code>${escapeHTML(item.method)} ${escapeHTML(item.path)}</code><time datetime="${item.time}">${escapeHTML(new Date(item.time).toLocaleTimeString())}</time></div>`).join('') : '<p class="panel-message">No requests yet.</p>';}
function render() {renderAccess(); renderOverview(); renderRegister(); renderEmployees(); renderReviews(); renderAudit(); navigate(state.view);}
async function api(path, options = {}) {
  if (!state.token) throw new Error('Staff sign-in is required.');
  const method = options.method || 'GET'; let response;
  try {response = await fetch(state.config.apiBase + path, {method, headers: {Authorization: `Bearer ${state.token}`}, cache: 'no-store', signal: AbortSignal.timeout(30000)});}
  catch {state.requests.push({method, path, status: null, time: new Date().toISOString()}); renderRequests(); throw new Error('Could not reach the HR service. Check your connection and retry.');}
  state.requests.push({method, path, status: response.status, time: new Date().toISOString()}); renderRequests();
  let result; try {result = await response.json();} catch {throw new Error('The service returned an unexpected response.');}
  if (!response.ok) {
    if (result.reason === 'hr_role_required') {if (state.session) state.session.roleAllowed = false; clearRecords(); render();}
    if (response.status === 401) throw new Error('Your sign-in could not be verified. Sign out and sign in again.');
    if (response.status === 403 && !result.reason) throw new Error('Access denied by the authorizer. The context or sensitive action may not match your baseline.');
    throw new Error(result.message || `Request failed (${response.status}).`);
  }
  return result;
}
async function loadWorkspace() {
  const definitions = [['summary', 'summary'], ['register', 'items'], ['reviews', 'items'], ['audit', 'items']];
  const results = await Promise.allSettled(definitions.map(([key]) => api(paths[key])));
  if (!allowed()) {clearRecords(); render(); return;}
  results.forEach((result, index) => {const [key, field] = definitions[index]; state[key] = result.status === 'fulfilled' ? (key === 'summary' ? result.value : result.value[field]) : key === 'summary' ? null : []; if (result.status === 'rejected') state.errors[key] = result.reason.message; else delete state.errors[key];});
  render(); if (Object.keys(state.errors).length) toast('Some confidential sections could not be loaded. Each section shows its access status.', true);
}
async function checkAccess() {state.session = await api('/session'); if (allowed()) await loadWorkspace(); else {clearRecords(); render();}}
async function runTask(task) {if (state.busy) return; state.busy = true; renderAccess(); try {await task();} catch (error) {toast(error.message || 'The request failed.', true);} finally {state.busy = false; renderAccess();}}
async function refreshAudit() {if (!allowed()) return; state.audit = (await api(paths.audit)).items; delete state.errors.audit; renderAudit(); renderOverview();}
async function openRecord(employeeId) {
  const record = (await api(`/api/v1/hr/employees/${encodeURIComponent(employeeId)}`)).record;
  $('record-title').textContent = record.name;
  const fields = (pairs) => `<dl class="record-fields">${pairs.map(([key, value, wide]) => `<div class="${wide ? 'full-width' : ''}"><dt>${escapeHTML(key)}</dt><dd>${escapeHTML(value)}</dd></div>`).join('')}</dl>`;
  $('record-details').innerHTML = `<div class="record-top"><div><strong>${escapeHTML(record.name)}</strong><small>${escapeHTML(record.employeeId)} · ${escapeHTML(record.jobTitle)}</small></div><span class="tag">CONFIDENTIAL · SYNTHETIC</span></div><h3 class="record-section-title">Employment & identity</h3>${fields([['Department', record.department], ['Work email', record.email], ['Identity placeholder', record.nationalId], ['Tax identifier', record.taxId], ['Home address', record.homeAddress, true]])}<h3 class="record-section-title">Pay & payment details · ${escapeHTML(periodLabel(record.period))}</h3>${fields([['Basic salary', money(record.basicPayCents)], ['Allowances', money(record.allowanceCents)], ['Gross pay', money(record.grossPayCents)], ['Net pay', money(record.netPayCents)], ['Bank', record.bankName], ['Account placeholder', record.bankAccount]])}<h3 class="record-section-title">Illustrative deductions</h3>${fields(Object.entries(record.deductionsCents).map(([name, cents]) => [name, money(cents)]))}<p class="record-disclaimer">Every identity, address, account, and amount above is fictional. The bank and tax placeholders are deliberately invalid. This is the confidential-data target for the LZTA demonstration.</p>`;
  $('record-dialog').showModal();
}
async function openReview(employeeId) {
  const record = (await api(`/api/v1/hr/reviews/${encodeURIComponent(employeeId)}`)).record;
  $('review-title').textContent = record.name;
  $('review-details').innerHTML = `<div class="record-top"><div><strong>${escapeHTML(record.period)}</strong><small>${escapeHTML(record.department)} · ${escapeHTML(record.employeeId)}</small></div><span class="status pending">Rating ${record.rating} / 5</span></div><h3>Confidential management notes</h3><p>${escapeHTML(record.managerNotes)}</p><div class="review-highlight"><h3>Disciplinary / coaching record</h3><p>${escapeHTML(record.disciplinaryRecord)}</p></div><h3>Background screening placeholder</h3><p>${escapeHTML(record.backgroundCheck)}</p><p class="record-disclaimer">Fictional personnel record. No real performance assessment, disciplinary case, or background check is represented.</p>`;
  $('review-dialog').showModal();
}
function openExport() {if (!allowed() || state.busy) return; $('export-description').textContent = `Export all ${state.register.length} company records, including employees hidden by your current search or filter. The file is clearly labelled DEMO and contains fictional confidential data.`; $('export-error').textContent = ''; $('export-dialog').showModal();}
async function exportPayroll() {
  if (state.busy) return; state.busy = true; $('confirm-export').disabled = true; $('export-error').textContent = '';
  try {
    const result = await api('/api/v1/hr/payroll/export', {method: 'POST'});
    const bytes = Uint8Array.from(atob(result.contentBase64), (character) => character.charCodeAt(0));
    const url = URL.createObjectURL(new Blob([bytes], {type: result.contentType}));
    const link = document.createElement('a'); link.href = url; link.download = result.name; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 10000);
    $('export-dialog').close(); toast(`${result.recordCount} synthetic confidential records exported. The export is recorded in the access audit.`); await refreshAudit();
  } catch (error) {$('export-error').textContent = error.message;}
  finally {state.busy = false; $('confirm-export').disabled = false; renderAccess();}
}
function bindEvents() {
  document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => {navigate(button.dataset.view); if (button.dataset.view === 'audit' && allowed()) runTask(refreshAudit);}));
  document.querySelectorAll('[data-close]').forEach((button) => button.addEventListener('click', () => $(button.dataset.close).close()));
  $('menu-button').addEventListener('click', () => $('sidebar').classList.toggle('open'));
  $('account-button').addEventListener('click', () => signedIn() ? navigate('access') : runTask(() => signIn(state.config)));
  $('notice-action').addEventListener('click', () => signedIn() ? navigate('access') : runTask(() => signIn(state.config)));
  $('signout-button').addEventListener('click', () => signOut(state.config)); $('check-access').addEventListener('click', () => runTask(checkAccess));
  $('refresh-payroll').addEventListener('click', () => allowed() && runTask(loadWorkspace)); $('refresh-audit').addEventListener('click', () => runTask(refreshAudit));
  $('payroll-search').addEventListener('input', renderRegister); $('payroll-department').addEventListener('change', renderRegister); $('employee-search').addEventListener('input', renderEmployees);
  document.querySelectorAll('.export-trigger').forEach((button) => button.addEventListener('click', openExport)); $('confirm-export').addEventListener('click', exportPayroll);
  for (const id of ['payroll-rows', 'employee-grid']) $(id).addEventListener('click', (event) => {const button = event.target.closest('[data-record]'); if (button) runTask(() => openRecord(button.dataset.record));});
  $('review-rows').addEventListener('click', (event) => {const button = event.target.closest('[data-review]'); if (button) runTask(() => openReview(button.dataset.review));});
}
async function boot() {
  bindEvents(); render();
  try {const response = await fetch('./config.json', {cache: 'no-store'}); if (!response.ok) throw new Error('HR workspace configuration is unavailable. Reload and retry.'); state.config = await response.json(); state.token = await resumeSignIn(state.config); if (state.token) await runTask(checkAccess); else render();}
  catch (error) {notice('Could not open the HR workspace.', error.message, 'error', signedIn() ? 'View access' : 'Staff sign-in'); toast(error.message, true);}
}
boot();
