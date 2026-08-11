// 综合防御平台 前端主逻辑
const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[c]));

const UI = {
  toast(msg, isErr) {
    const t = $('#toast');
    t.textContent = msg;
    t.className = 'toast' + (isErr ? ' err' : '');
    clearTimeout(t._t);
    t._t = setTimeout(() => t.classList.add('hidden'), 3000);
  },
  showLogin() {
    $('#app').classList.add('hidden');
    $('#login-page').classList.remove('hidden');
  },
  enterApp() {
    $('#login-page').classList.add('hidden');
    $('#app').classList.remove('hidden');
  },
  openModal(title, html) {
    $('#modal-title').textContent = title;
    $('#modal-body').innerHTML = html;
    $('#modal-mask').classList.remove('hidden');
  },
  closeModal() { $('#modal-mask').classList.add('hidden'); },
  confirm(title, html, onOk) {
    this.openModal(title, html + '<div class="mt flex" style="justify-content:flex-end">' +
      '<button class="btn" onclick="UI.closeModal()">取消</button>' +
      '<button class="btn danger" id="modal-ok">确认</button></div>');
    $('#modal-ok').onclick = () => { this.closeModal(); onOk(); };
  },
  setConn(ok, text) {
    $('#conn-dot').className = 'dot ' + (ok ? 'on' : 'off');
    $('#conn-text').textContent = text || (ok ? '实时连接中' : '未连接');
  },
  severityTag(sev) {
    return `<span class="tag ${esc(sev)}">${esc(sev)}</span>`;
  },
  timeAgo(ts) {
    if (!ts) return '-';
    const d = Math.floor(Date.now() / 1000) - ts;
    if (d < 60) return d + 's前';
    if (d < 3600) return Math.floor(d / 60) + 'm前';
    if (d < 86400) return Math.floor(d / 3600) + 'h前';
    return new Date(ts * 1000).toLocaleString();
  },
  fmtTime(ts) {
    return ts ? new Date(ts * 1000).toLocaleString('zh-CN', { hour12: false }) : '-';
  },
};

// ===== 状态 =====
const State = {
  targets: [],
  rules: [],
  alerts: [],
  currentTarget: localStorage.getItem('shield_sel_target') || '',
  ws: null,
  hardenItems: [],
  kbDocs: [],
  wafCatFilter: '全部',
  wafOnlyBlock: false,
  ragTag: '全部',
  ragKw: '',
};

// ===== WebSocket 实时推送 =====
function connectWS() {
  const token = API.token || localStorage.getItem('shield_token') || '';
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${proto}://${location.host}/ws/panel?token=${encodeURIComponent(token)}`);
  State.ws = ws;
  ws.onopen = () => UI.setConn(true, '实时连接中');
  ws.onclose = () => { UI.setConn(false, '实时连接已断开'); setTimeout(connectWS, 3000); };
  ws.onerror = () => ws.close();
  ws.onmessage = (e) => {
    try {
      const m = JSON.parse(e.data);
      if (m.type === 'push') handlePush(m.data);
      if (m.type === 'ping') return;
    } catch (err) { /* ignore */ }
  };
}

function handlePush(d) {
  if (!d) return;
  if (d.type === 'heartbeat') {
    if (State.currentTarget === d.target_id) renderMonitorLive(d.data);
    refreshTargetsSilent();
  }
  if (d.type === 'scan_result') {
    UI.toast('收到靶机扫描报告');
    renderScanReport(d.data);
    loadAlerts(true);
  }
  if (d.type === 'alerts_updated') loadAlerts(true);
  if (d.type === 'cmd_result') {
    UI.toast('命令执行结果已返回');
    if (State.currentTarget) renderCmdResult(d.data);
  }
  if (d.type === 'harden_result') {
    UI.toast('加固任务执行完成');
    renderHardenResult(d.data);
  }
  if (d.type === 'deploy_waf_result' || d.type === 'disable_waf_result') {
    UI.toast(d.type === 'deploy_waf_result' ? 'WAF 部署结果已返回' : 'WAF 已停用');
  }
  if (d.type === 'defense_finding') {
    UI.toast('防御告警: ' + (d.message || d.category || ''));
    loadAlerts(true);
    refreshAudit();
  }
  if (d.type === 'kill_result') UI.toast('终止进程结果已返回');
  if (d.type === 'scan_web_result') {
    UI.toast('Web 后门扫描完成');
    renderScanWebResult(d.data);
  }
  if (d.type === 'backup_web_result') UI.toast(d.data && d.data.ok ? '备份完成: ' + (d.data.msg || '') : '备份失败');
  if (d.type === 'rollback_web_result') UI.toast(d.data && d.data.ok ? '回滚完成' : '回滚失败');
  if (d.type === 'ban_ip_result') UI.toast('IP 封禁结果已返回');
  if (d.type === 'unban_ip_result') UI.toast('IP 解封结果已返回');
  if (d.type === 'refresh_result') renderRefreshResult(d.data);
  if (d.type === 'defense_now_result') {
    UI.toast('防御检查完成');
    renderDefenseNowResult(d.data);
  }
  if (d.type === 'deploy_revproxy_result') {
    UI.toast(d.data && d.data.ok ? '反向代理 WAF 已部署' : '反向代理 WAF 部署失败');
    renderRevproxyResult(d.data);
  }
  if (d.type === 'defense_status') {
    UI.toast(d.data && d.data.running ? '防御守护已启动' : '防御守护已停止');
    if (d.data && d.data.running && d.data.watch_paths) {
      const el = $('#defense-state');
      if (el) el.innerHTML = '<div class="card-title">靶机运行状态</div><div class="small muted">防御守护运行中 · 监控目录: ' + esc((d.data.watch_paths || []).join(', ')) + '</div>';
    }
  }
  if (d.type === 'list_ports_result') renderListResult('ports', d.data);
  if (d.type === 'list_conns_result') renderListResult('conns', d.data);
}

// ===== 导航 =====
function navigate(page) {
  document.querySelectorAll('.nav-item').forEach((n) => n.classList.toggle('active', n.dataset.page === page));
  document.querySelectorAll('.page').forEach((p) => p.id === 'page-' + page ? p.classList.remove('hidden') : p.classList.add('hidden'));
  renderPage(page);
}

function renderPage(page) {
  switch (page) {
    case 'dashboard': renderDashboard(); break;
    case 'targets': renderTargets(); break;
    case 'monitor': renderMonitor(); break;
    case 'harden': renderHarden(); break;
    case 'waf': renderWAF(); break;
    case 'terminal': renderTerminal(); break;
    case 'alerts': renderAlerts(); break;
    case 'defense': renderDefense(); break;
    case 'rag': renderRAG(); break;
    case 'settings': renderSettings(); break;
  }
}

// ===== 总览 =====
async function renderDashboard() {
  const el = $('#page-dashboard');
  el.innerHTML = '<div class="loading">加载中...</div>';
  try {
    const [status, targets, alerts] = await Promise.all([API.status(), API.targets(), API.alerts(10)]);
    State.targets = targets.data || [];
    State.alerts = alerts.data || [];
    const now = Date.now() / 1000;
    const online = State.targets.filter((t) => now - t.last_seen < 30);

    let rows = State.targets.map((t) => `
      <tr>
        <td class="mono">${esc(t.id.slice(0, 8))}</td>
        <td>${esc(t.name)}</td>
        <td>${esc(t.os)}/${esc(t.arch)}</td>
        <td>${esc(t.ip || '-')}</td>
        <td><span class="status ${now - t.last_seen < 30 ? 'online' : 'offline'}"><span class="dot"></span>${now - t.last_seen < 30 ? '在线' : '离线'}</span></td>
        <td>${UI.timeAgo(t.last_seen)}</td>
        <td><button class="btn sm" onclick="selectTarget('${esc(t.id)}','${esc(t.name)}')">进入</button></td>
      </tr>`).join('') || '<tr><td colspan="7" class="empty">暂无靶机接入，请在靶机部署 Agent</td></tr>';

    el.innerHTML = `
      <div class="page-head">
        <div><div class="page-title">总览</div><div class="page-desc">靶标接入与告警态势</div></div>
        <div class="page-actions"><button class="btn" onclick="navigate('targets')">靶机管理</button></div>
      </div>
      <div class="grid cols-4">
        <div class="card"><div class="stat-value">${State.targets.length}</div><div class="stat-label">靶机总数</div></div>
        <div class="card"><div class="stat-value" style="color:var(--green)">${online.length}</div><div class="stat-label">在线靶机</div></div>
        <div class="card"><div class="stat-value" style="color:${(status.data.alerts_unhandled||0)>0?'var(--red)':'var(--text)'}">${status.data.alerts_unhandled||0}</div><div class="stat-label">未处理告警</div></div>
        <div class="card"><div class="stat-value" style="color:var(--purple)">${status.data.llm_enabled?'已启用':'本地模式'}</div><div class="stat-label">LLM 增强</div></div>
      </div>
      <div class="grid cols-2">
        <div class="card">
          <div class="card-title">靶机列表</div>
          <table><thead><tr><th>ID</th><th>名称</th><th>系统</th><th>IP</th><th>状态</th><th>心跳</th><th></th></tr></thead><tbody>${rows}</tbody></table>
        </div>
        <div class="card">
          <div class="card-title">最新告警 <button class="btn sm" onclick="navigate('alerts')">全部</button></div>
          <table><thead><tr><th>级别</th><th>类别</th><th>标题</th><th>时间</th></tr></thead><tbody>
          ${(alerts.data||[]).slice(0,8).map((a)=>`<tr><td>${UI.severityTag(a.severity)}</td><td>${esc(a.category)}</td><td>${esc(a.title)}</td><td class="small">${UI.timeAgo(a.time)}</td></tr>`).join('') || '<tr><td colspan="4" class="empty">暂无告警</td></tr>'}
          </tbody></table>
        </div>
      </div>`;
  } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
}

// ===== 靶机管理 =====
async function renderTargets() {
  const el = $('#page-targets');
  el.innerHTML = '<div class="loading">加载中...</div>';
  try {
    const res = await API.targets();
    State.targets = res.data || [];
    const now = Date.now() / 1000;
    const rows = State.targets.map((t) => {
      const on = now - t.last_seen < 30;
      return `
      <tr>
        <td class="mono">${esc(t.id.slice(0,8))}</td>
        <td>${esc(t.name)}</td>
        <td>${esc(t.os)}/${esc(t.arch)} v${esc(t.version||'')}</td>
        <td>${esc(t.ip || '-')}</td>
        <td>${esc(t.web_root || '-')}</td>
        <td><span class="status ${on?'online':'offline'}"><span class="dot"></span>${on?'在线':'离线'}</span></td>
        <td>${UI.timeAgo(t.last_seen)}</td>
        <td>
          <button class="btn sm" onclick="openTargetOps('${esc(t.id)}')">操作</button>
          <button class="btn sm danger" onclick="delTarget('${esc(t.id)}')">移除</button>
        </td>
      </tr>`;
    }).join('');

    el.innerHTML = `
      <div class="page-head">
        <div><div class="page-title">靶机管理</div><div class="page-desc">Agent 回连的靶机列表</div></div>
        <div class="page-actions"><button class="btn" onclick="refreshPage('targets')">刷新</button></div>
      </div>
      <div class="card">
        <div class="card-title">接入的靶机</div>
        <table><thead><tr><th>ID</th><th>名称</th><th>系统</th><th>IP</th><th>Web目录</th><th>状态</th><th>心跳</th><th>操作</th></tr></thead><tbody>${rows}</tbody></table>
      </div>`;
  } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
}

function selectTarget(id, name) {
  State.currentTarget = id;
  localStorage.setItem('shield_sel_target', id);
  UI.toast('已选择靶机: ' + name);
  navigate('monitor');
}

async function delTarget(id) {
  UI.confirm('移除靶机', '确认移除该靶机记录？(不停止其 Agent)', async () => {
    await API.delTarget(id);
    UI.toast('已移除');
    renderPage('targets');
  });
}

function openTargetOps(id) {
  const t = State.targets.find((x) => x.id === id);
  if (!t) return;
  UI.openModal('靶机操作 · ' + esc(t.name), `
    <div class="grid cols-2">
      <button class="btn primary" onclick="doTarget('${esc(id)}','scan',{},'扫描已触发')">快速检测</button>
      <button class="btn" onclick="UI.closeModal();navigate('terminal');State.currentTarget='${esc(id)}';localStorage.setItem('shield_sel_target','${esc(id)}')">远程执行</button>
      <button class="btn warn" onclick="doTarget('${esc(id)}','harden',{},'一键加固已触发')">一键加固</button>
      <button class="btn success" onclick="doTarget('${esc(id)}','deploy_waf',{},'软WAF部署已触发')">部署软WAF</button>
      <button class="btn danger" onclick="doTarget('${esc(id)}','disable_waf',{},'停用软WAF已触发')">停用软WAF</button>
      <button class="btn" onclick="doTarget('${esc(id)}','backup_web',{},'Web备份已触发')">Web备份</button>
      <button class="btn warn" onclick="doTarget('${esc(id)}','rollback_web',{},'Web回滚已触发')">Web回滚</button>
      <button class="btn danger" onclick="doTarget('${esc(id)}','kill',{},'可疑进程清理已触发')">清理进程</button>
      <button class="btn" onclick="doTarget('${esc(id)}','defense_now',{},'防御检查已触发')">防御检查</button>
      <button class="btn success" onclick="deployRevproxy('${esc(id)}')">反向代理WAF</button>
      <button class="btn" onclick="banIPForm('${esc(id)}')">封禁IP</button>
      <button class="btn" onclick="UI.closeModal()">关闭</button>
    </div>`);
}

async function doTarget(id, action, body, okMsg) {
  try {
    await API.targetAction(id, action, body);
    UI.toast(okMsg);
    UI.closeModal();
  } catch (e) { UI.toast(e.message, true); }
}

// ===== 实时监测 =====
function targetSelectHTML() {
  const opts = State.targets.map((t) => `<option value="${esc(t.id)}" ${t.id===State.currentTarget?'selected':''}>${esc(t.name)} (${esc(t.os)})</option>`).join('');
  return `<select id="monitor-target" onchange="switchMonitorTarget(this.value)">${opts}</select>`;
}

function renderMonitor() {
  const el = $('#page-monitor');
  const t = State.targets.find((x) => x.id === State.currentTarget);
  el.innerHTML = `
    <div class="page-head">
      <div><div class="page-title">实时监测</div><div class="page-desc">靶机运行状态与扫描报告</div></div>
    </div>
    <div class="toolbar">
      <div style="min-width:200px">${targetSelectHTML()}</div>
      <button class="btn primary" onclick="runScan()">执行全面检测</button>
      <button class="btn sm" onclick="refreshPage('monitor')">刷新</button>
    </div>
    <div id="monitor-live" class="grid cols-4"></div>
    <div class="card"><div class="card-title">检测报告</div><div id="monitor-report"><div class="empty">点击「执行全面检测」获取靶机安全状态</div></div></div>
  `;
  if (t) renderMonitorLive({});
}

function switchMonitorTarget(id) {
  State.currentTarget = id;
  localStorage.setItem('shield_sel_target', id);
  renderPage('monitor');
}

function renderMonitorLive(d) {
  const el = $('#monitor-live');
  if (!el) return;
  const t = State.targets.find((x) => x.id === State.currentTarget) || {};
  el.innerHTML = `
    <div class="card"><div class="stat-value" style="font-size:22px">${esc(t.name||'-')}</div><div class="stat-label">${esc(t.os||'')} ${esc(t.ip||'')}</div></div>
    <div class="card"><div class="stat-value" style="font-size:20px;color:var(--green)">${esc((d&&d.cpu)||'-')}</div><div class="stat-label">CPU/负载</div></div>
    <div class="card"><div class="stat-value" style="font-size:20px;color:var(--accent)">${esc((d&&d.mem)||'-')}</div><div class="stat-label">内存</div></div>
    <div class="card"><div class="stat-value" style="font-size:20px;color:var(--purple)">${esc((d&&d.estab)||'-')}</div><div class="stat-label">活动连接 ${d&&d.waf?'· WAF已部署':''}</div></div>`;
}

async function runScan() {
  if (!State.currentTarget) return UI.toast('请先选择靶机', true);
  $('#monitor-report').innerHTML = '<div class="loading">扫描执行中，请稍候...</div>';
  try {
    await API.targetAction(State.currentTarget, 'scan', {});
    UI.toast('扫描指令已下发，结果通过实时推送返回');
  } catch (e) { $('#monitor-report').innerHTML = '<div class="empty">' + esc(e.message) + '</div>'; }
}

function renderScanReport(rep) {
  const el = $('#monitor-report');
  if (!el) return;
  if (!rep || !rep.findings) { el.innerHTML = '<div class="empty">无数据</div>'; return; }
  const rows = rep.findings.map((f) => `
    <tr>
      <td>${UI.severityTag(f.severity)}</td>
      <td>${esc(f.category)}</td>
      <td>${esc(f.title)}</td>
      <td class="mono">${esc(f.detail)}</td>
    </tr>`).join('');
  el.innerHTML = `
    <div class="mb small muted">靶机 ${esc(rep.host||'')} · 耗时 ${rep.duration_ms||0}ms · 发现 ${rep.findings.length} 项</div>
    <table><thead><tr><th>级别</th><th>类别</th><th>标题</th><th>详情</th></tr></thead><tbody>${rows}</tbody></table>`;
}

// ===== 加固 =====
async function renderHarden() {
  const el = $('#page-harden');
  el.innerHTML = '<div class="loading">加载中...</div>';
  try {
    const items = (await API.hardenItems()).data || [];
    State.hardenItems = items;
    const groups = {};
    items.forEach((it) => { (groups[it.category] = groups[it.category] || []).push(it); });
    const cats = Object.keys(groups).sort();
    const highRisk = items.filter((it) => it.risk === 'high').length;
    const cards = cats.map((cat) => `
      <div class="card" style="margin-bottom:10px">
        <div class="card-title">${esc(cat)} <span class="small muted">${groups[cat].length} 项</span></div>
        ${groups[cat].map((it) => `
          <div class="harden-item flex-between">
            <div><b>${esc(it.name)}</b> <span class="tag ${esc(it.risk)}">${it.risk === 'high' ? '高风险' : it.risk === 'medium' ? '中风险' : '低风险'}</span> <span class="small muted">${esc(it.desc)}</span></div>
            <div class="flex gap">
              <label class="small flex" style="gap:4px"><input type="checkbox" class="harden-check" value="${esc(it.id)}" checked> 选中</label>
              <button class="btn sm primary" onclick="runHardenOne('${esc(it.id)}')">执行</button>
            </div>
          </div>`).join('')}
      </div>`).join('');
    el.innerHTML = `
      <div class="page-head">
        <div><div class="page-title">一键加固</div><div class="page-desc">在选中靶机执行基线加固（${items.length} 项 / ${cats.length} 类，其中高风险 ${highRisk} 项，注意可能影响业务）</div></div>
        <div class="page-actions">
          <select id="harden-target" style="width:200px">${State.targets.map((t)=>`<option value="${esc(t.id)}">${esc(t.name)}</option>`).join('')}</select>
          <button class="btn danger" onclick="runHardenAll()">一键全部加固</button>
        </div>
      </div>
      <div class="toolbar">
        <button class="btn sm" onclick="setAllChecks(true)">全选</button>
        <button class="btn sm" onclick="setAllChecks(false)">全不选</button>
        <button class="btn sm primary" onclick="runHardenSelected()">执行选中项</button>
        <span class="small muted">⚠ 加固在靶机端本地执行，选择项请根据靶机业务确认后再执行</span>
      </div>
      <div id="harden-results"></div>
      ${cards}`;
  } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
}

function setAllChecks(v) {
  document.querySelectorAll('.harden-check').forEach((c) => { c.checked = v; });
}

async function runHardenSelected() {
  const ids = [...document.querySelectorAll('.harden-check:checked')].map((c) => c.value);
  if (!ids.length) return UI.toast('未选中任何加固项', true);
  const tid = hardenTargetID();
  if (!tid) return UI.toast('请先选择靶机', true);
  UI.confirm('执行选中加固', '将对目标靶机执行 ' + ids.length + ' 项加固。确认继续？', async () => {
    try {
      await API.targetAction(tid, 'harden', { items: ids });
      UI.toast('加固指令已下发 ' + ids.length + ' 项');
    } catch (e) { UI.toast(e.message, true); }
  });
}

function hardenTargetID() {
  const s = $('#harden-target');
  return s ? s.value : State.currentTarget;
}

async function runHardenOne(id) {
  const tid = hardenTargetID();
  if (!tid) return UI.toast('请先选择靶机', true);
  try {
    await API.targetAction(tid, 'harden', { items: [id] });
    UI.toast('加固指令已下发');
  } catch (e) { UI.toast(e.message, true); }
}

async function runHardenAll() {
  const tid = hardenTargetID();
  if (!tid) return UI.toast('请先选择靶机', true);
  UI.confirm('一键全部加固', '将对目标靶机执行全部加固项，含 SSH 配置、防火墙、账号锁定等高危操作。确认继续？', async () => {
    try {
      await API.targetAction(tid, 'harden', {});
      UI.toast('全部加固指令已下发');
    } catch (e) { UI.toast(e.message, true); }
  });
}

function renderHardenResult(results) {
  const el = $('#harden-results');
  if (!el || !results) return;
  const rows = results.map((r) => `
    <tr>
      <td>${esc(r.name)}</td>
      <td>${r.exit_code === 0 ? '<span class="tag green">成功</span>' : '<span class="tag red">失败(' + r.exit_code + ')</span>'}</td>
      <td class="mono small">${esc((r.output || '').slice(0, 300))}</td>
      <td>${r.duration_ms || 0}ms</td>
    </tr>`).join('');
  el.innerHTML = `<div class="card"><div class="card-title">加固结果</div><table><thead><tr><th>项目</th><th>状态</th><th>输出</th><th>耗时</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

// ===== WAF 规则 =====
async function renderWAF() {
  const el = $('#page-waf');
  el.innerHTML = '<div class="loading">加载中...</div>';
  try {
    const res = await API.rules();
    State.rules = res.data || [];
    const cats = [...new Set(State.rules.map((r) => r.category || '未分类'))].sort();
    const catFilter = State.wafCatFilter || '全部';
    const onlyBlock = State.wafOnlyBlock || false;
    const shown = State.rules.filter((r) => {
      if (catFilter !== '全部' && (r.category || '未分类') !== catFilter) return false;
      if (onlyBlock && r.action !== 'block') return false;
      return true;
    });
    const groups = {};
    shown.forEach((r) => { (groups[r.category || '未分类'] = groups[r.category || '未分类'] || []).push(r); });
    const total = State.rules.length, enabled = State.rules.filter((r) => r.enabled).length;
    const blocked = State.rules.filter((r) => r.action === 'block').length;

    const catBtns = cats.map((c) => `<button class="chip ${catFilter === c ? 'on' : ''}" onclick="State.wafCatFilter='${esc(c)}';renderPage('waf')">${esc(c)}</button>`).join('');

    const cards = Object.keys(groups).map((cat) => `
      <div class="card">
        <div class="card-title">${esc(cat)} <span class="small muted">${groups[cat].length} 条</span></div>
        <table><thead><tr><th>级别</th><th>名称</th><th>动作</th><th>状态</th><th>操作</th></tr></thead><tbody>
        ${groups[cat].map((r) => `
          <tr>
            <td>${levelTag(r.level)}</td>
            <td class="small" title="${esc(r.pattern)}">${esc(r.name)}</td>
            <td>${r.action === 'block' ? '<span class="tag red">拦截</span>' : '<span class="tag info">记录</span>'}</td>
            <td>${r.enabled ? '<span class="tag green">启用</span>' : '<span class="tag">停用</span>'}</td>
            <td>
              <button class="btn sm" onclick="toggleRule('${esc(r.id)}')">${r.enabled ? '停用' : '启用'}</button>
              <button class="btn sm danger" onclick="delRule('${esc(r.id)}')">删除</button>
            </td>
          </tr>`).join('')}
        </tbody></table>
      </div>`).join('') || '<div class="card"><div class="empty">该筛选下无规则</div></div>';

    el.innerHTML = `
      <div class="page-head">
        <div><div class="page-title">WAF 规则</div><div class="page-desc">部署到靶机软 WAF 的检测规则（${total} 条规则，${enabled} 启用，${blocked} 拦截，${total - blocked} 记录）</div></div>
        <div class="page-actions">
          <button class="btn" onclick="importDefaultRules()">补种默认规则</button>
          <button class="btn primary" onclick="UI.openModal('添加规则', ruleFormHTML())">添加规则</button>
        </div>
      </div>
      <div class="toolbar">
        <button class="chip ${catFilter === '全部' ? 'on' : ''}" onclick="State.wafCatFilter='全部';renderPage('waf')">全部</button>
        ${catBtns}
        <span class="spacer"></span>
        <label class="inline"><input type="checkbox" ${onlyBlock ? 'checked' : ''} onchange="State.wafOnlyBlock=this.checked;renderPage('waf')"> 仅看拦截规则</label>
        <button class="btn sm ${onlyBlock ? '' : ''}" onclick="batchToggle('enable')">全部启用</button>
        <button class="btn sm" onclick="batchToggle('disable')">全部停用</button>
      </div>
      ${cards}`;
  } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
}

function levelTag(lv) {
  if (lv >= 2) return '<span class="tag red">高</span>';
  if (lv === 1) return '<span class="tag" style="background:#f39c12">中</span>';
  return '<span class="tag green">低</span>';
}

async function toggleRule(id) {
  const r = State.rules.find((x) => x.id === id);
  if (!r) return;
  try {
    await API.addRule({ id, name: r.name, category: r.category, pattern: r.pattern, action: r.action, level: r.level, enabled: r.enabled ? 0 : 1 });
    UI.toast(r.enabled ? '已停用' : '已启用');
    renderPage('waf');
  } catch (e) { UI.toast(e.message, true); }
}

async function batchToggle(mode) {
  let n = 0;
  for (const r of State.rules) {
    const want = mode === 'enable' ? 1 : 0;
    if (r.enabled === want) continue;
    try { await API.addRule({ id: r.id, name: r.name, category: r.category, pattern: r.pattern, action: r.action, level: r.level, enabled: want }); n++; } catch (e) {}
  }
  UI.toast(mode === 'enable' ? '已启用 ' + n + ' 条' : '已停用 ' + n + ' 条');
  renderPage('waf');
}

function ruleFormHTML(rule) {
  const r = rule || {};
  return `
    <div class="form-row"><label>名称</label><input id="rule-name" type="text" value="${esc(r.name||'')}" placeholder="如: SQL注入-堆叠查询"></div>
    <div class="form-row"><label>类别</label><input id="rule-category" type="text" value="${esc(r.category||'SQL注入')}" placeholder="SQL注入/命令执行/XSS/WebShell"></div>
    <div class="form-row"><label>正则</label><input id="rule-pattern" type="text" value="${esc(r.pattern||'')}" placeholder="(?i)pattern" class="mono"></div>
    <div class="form-row"><label>动作</label><select id="rule-action"><option value="block">拦截 block</option><option value="log">仅记录 log</option></select></div>
    <div class="form-row"><label>级别</label><select id="rule-level"><option value="0">低 (基础)</option><option value="1">中 (中级)</option><option value="2">高 (严格)</option></select></div>
    <div class="flex-between mt"><span></span><button class="btn primary" onclick="submitRule()">保存</button></div>`;
}

async function submitRule() {
  const name = $('#rule-name').value.trim();
  const pattern = $('#rule-pattern').value.trim();
  if (!name || !pattern) return UI.toast('名称与正则为必填', true);
  try {
    await API.addRule({ name, category: $('#rule-category').value.trim() || '自定义', pattern, action: $('#rule-action').value, level: parseInt($('#rule-level').value, 10) || 0, enabled: 1 });
    UI.closeModal();
    UI.toast('规则已保存');
    renderPage('waf');
  } catch (e) { UI.toast(e.message, true); }
}

async function delRule(id) {
  await API.delRule(id);
  UI.toast('规则已删除');
  renderPage('waf');
}

async function importDefaultRules() {
  // 由服务端按 ID 增量补种内置规则（幂等，不产生重复）
  try {
    const res = await API.post('/api/rules/seed', {});
    UI.toast('补种完成：新增 ' + (res.added || 0) + ' 条，共 ' + (res.total || 0) + ' 条');
    renderPage('waf');
  } catch (e) { UI.toast(e.message, true); }
}

// ===== 远程执行 =====
const QUICK_COMMANDS = [
  {
    group: '进程排查',
    items: [
      ['进程 TOP20', 'ps aux --sort=-%cpu | head -20'],
      ['僵尸进程', "ps aux | awk '$8~/^Z/{print}'"],
      ['异常进程关联', 'ps -ef | grep -vE "\\[.*\\]" | grep -iE "shell|nc |perl|python|/tmp|curl|wget|base64|bash -i"'],
      ['按内存排序', 'ps aux --sort=-%mem | head -15'],
      ['线程/父子关系', 'pstree -ap | head -40'],
    ],
  },
  {
    group: '网络排查',
    items: [
      ['监听端口', 'ss -tlnp'],
      ['全部连接', 'ss -tanp'],
      ['外联连接', "ss -tanp | awk '$5 ~ /^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:[0-9]+$/ && $5 !~ /^(127\\.|10\\.|192\\.168\\.|172\\.)/'"],
      ['ESTABLISHED 连接', 'ss -tn state established'],
      ['异常端口扫描', "ss -tln | awk 'NR>1{print $4}' | sort -u"],
      ['网卡流量', 'ip -s link | grep -A1 "^[0-9]"'],
    ],
  },
  {
    group: '后门排查',
    items: [
      ['SSH 后门文件', 'find / -name "ssh_config" -o -name "sshd" -type f 2>/dev/null | grep -vE "^/(usr|bin|etc)"'],
      ['可疑隐藏目录', 'find / -maxdepth 3 -name ".*" -type d -newer /tmp 2>/dev/null'],
      ['RC 脚本检查', 'ls -la /etc/rc*.d /etc/init.d 2>/dev/null | head -40'],
      ['LD_PRELOAD', 'cat /etc/ld.so.preload 2>/dev/null; echo "---"; env | grep -i ld_preload'],
      ['系统库劫持', 'find /lib /usr/lib -name "*.so*" -mtime -7 2>/dev/null | head -20'],
      ['SUID 后门', 'find / -perm -4000 -type f 2>/dev/null'],
      ['Rootkit 目录', 'ls -la /lib/udev /lib/modules 2>/dev/null | head -30'],
    ],
  },
  {
    group: 'Web 排查',
    items: [
      ['Web 目录列表', 'ls -la /var/www/html/'],
      ['最新 PHP 文件', 'find /var/www/html -name "*.php" -mtime -3 2>/dev/null'],
      ['可疑一句话', 'grep -rlE "(eval\\s*\\(\\s*\\$_|assert\\s*\\(\\s*\\$_|system\\s*\\(\\s*\\$_)" /var/www/html 2>/dev/null'],
      ['Base64 加密文件', 'grep -rlE "base64_decode|gzinflate|str_rot13" /var/www/html 2>/dev/null'],
      ['Web 服务器进程', 'ps aux | grep -E "(apache|nginx|php-fpm|tomcat)" | grep -v grep'],
      ['访问日志 TOP', 'tail -5000 /var/log/nginx/access.log 2>/dev/null | awk \'{print $1}\' | sort | uniq -c | sort -rn | head -10'],
      ['user.ini 检查', 'cat /var/www/html/.user.ini 2>/dev/null; find /var/www/html -name ".user.ini" 2>/dev/null'],
    ],
  },
  {
    group: '账号与登录',
    items: [
      ['最近登录', 'last -15'],
      ['当前在线', 'who; echo "---"; w'],
      ['登录失败尝试', 'grep -i "failed password" /var/log/auth.log 2>/dev/null | tail -20'],
      ['UID 0 账号', 'awk -F: \'$3==0{print $1":"$3}\' /etc/passwd'],
      ['可登录账号', "awk -F: '$7 !~ /(nologin|false)/{print $1\":\"$3\":\"$7}' /etc/passwd"],
      ['空密码用户', "sudo awk -F: '$2==\"\"{print $1}' /etc/shadow 2>/dev/null"],
      ['SSH 公钥', 'cat /root/.ssh/authorized_keys 2>/dev/null; ls -la /root/.ssh 2>/dev/null'],
    ],
  },
  {
    group: '计划任务与启动项',
    items: [
      ['当前用户 cron', 'crontab -l 2>/dev/null'],
      ['系统 cron', 'cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ /etc/cron.daily/ 2>/dev/null'],
      ['systemd timer', 'systemctl list-timers --all 2>/dev/null | head -20'],
      ['systemd 单元', 'systemctl list-unit-files --state=enabled 2>/dev/null | head -30'],
      ['at 任务', 'atq 2>/dev/null'],
      ['profile 注入', 'grep -rE "curl|wget|base64 -d|/dev/tcp|python -c" /etc/profile /etc/profile.d/ 2>/dev/null'],
    ],
  },
  {
    group: '系统信息',
    items: [
      ['系统与内核', 'uname -a; cat /etc/os-release 2>/dev/null | head -3'],
      ['运行时长', 'uptime'],
      ['内存状态', 'free -h'],
      ['磁盘占用', 'df -h'],
      ['最近文件变化', 'find / -xdev -mtime -1 -type f 2>/dev/null | grep -vE "^/(proc|sys|run|var/log|var/lib|usr/share)" | head -30'],
      ['已装软件', 'dpkg -l 2>/dev/null | wc -l; rpm -qa 2>/dev/null | wc -l'],
    ],
  },
  {
    group: '安全加固',
    items: [
      ['防火墙状态', 'ufw status 2>/dev/null; iptables -L -n 2>/dev/null | head -30'],
      ['SELinux/AppArmor', 'getenforce 2>/dev/null; aa-status 2>/dev/null | head -10'],
      ['SSH 配置关键项', 'grep -E "PermitRootLogin|PasswordAuthentication|Port " /etc/ssh/sshd_config 2>/dev/null'],
      ['危险函数禁用', 'php -i 2>/dev/null | grep -i disable_functions'],
      ['打开文件数', 'cat /proc/sys/fs/file-max; ulimit -n'],
      ['隐藏进程探测', 'cat /proc/1/status 2>/dev/null | grep -E "^(Name|Pid)"'],
    ],
  },
  {
    group: 'Windows 专用',
    items: [
      ['网络连接', 'netstat -ano | findstr ESTABLISHED'],
      ['启动项', 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"'],
      ['计划任务', 'schtasks /query /fo csv | findstr /v "Microsoft"'],
      ['管理员组', 'net localgroup administrators'],
      ['可疑进程', 'tasklist /v | findstr /i "shell nc powershell perl python"'],
    ],
  },
];

function renderTerminal() {
  const el = $('#page-terminal');
  const opts = State.targets.map((t) => `<option value="${esc(t.id)}" ${t.id===State.currentTarget?'selected':''}>${esc(t.name)} (${esc(t.os)})</option>`).join('');
  const groups = QUICK_COMMANDS.map((g) => `
    <div class="cmd-group">
      <div class="cmd-group-title">${esc(g.group)}</div>
      <div class="flex gap" style="flex-wrap:wrap">
        ${g.items.map(([label, cmd]) => `<button class="btn sm" onclick="quickCmd(${JSON.stringify(cmd)})">${esc(label)}</button>`).join('')}
      </div>
    </div>`).join('');
  el.innerHTML = `
    <div class="page-head"><div><div class="page-title">远程执行</div><div class="page-desc">在靶机执行任意命令（结果实时回传，操作留痕）</div></div></div>
    <div class="toolbar">
      <select id="term-target" style="width:200px" onchange="State.currentTarget=this.value;localStorage.setItem('shield_sel_target',this.value)">${opts}</select>
      <input id="term-cmd" type="text" class="mono" placeholder="如: ps aux | grep -i shell 或 tail -20 /var/log/auth.log" onkeydown="if(event.key==='Enter')execCmd()">
      <button class="btn primary" onclick="execCmd()">执行</button>
      <button class="btn" onclick="$('#term-cmd').value=''">清空</button>
    </div>
    <div class="card"><div class="card-title">输出</div><div id="term-out" class="term">等待执行命令...</div></div>
    <div class="card"><div class="card-title">常用命令库（${QUICK_COMMANDS.reduce((n,g)=>n+g.items.length,0)} 条 · 点击即执行）</div>
      ${groups}
    </div>`;
}

function quickCmd(cmd) { $('#term-cmd').value = cmd; execCmd(); }

async function execCmd() {
  const cmd = $('#term-cmd').value.trim();
  const tid = $('#term-target').value;
  if (!cmd) return;
  if (!tid) return UI.toast('请先选择靶机', true);
  $('#term-out').className = 'term';
  $('#term-out').textContent = '> ' + cmd + '\n执行中...';
  try {
    await API.targetAction(tid, 'exec', { command: cmd });
  } catch (e) { $('#term-out').className = 'term err'; $('#term-out').textContent = e.message; }
}

function renderCmdResult(data) {
  const el = $('#term-out');
  if (!el || !data) return;
  el.className = 'term' + ((data.exit_code && data.exit_code !== 0) ? ' err' : '');
  el.textContent = '> ' + data.command + '\n' + data.output + '\n\n[退出码 ' + data.exit_code + ' · ' + data.duration_ms + 'ms]';
}

// ===== 告警中心 =====
async function renderAlerts() {
  const el = $('#page-alerts');
  el.innerHTML = '<div class="loading">加载中...</div>';
  try {
    await loadAlerts(false);
  } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
}

async function loadAlerts(silent) {
  const el = $('#page-alerts');
  const res = await API.alerts(200);
  State.alerts = res.data || [];
  const badge = $('#alert-badge');
  const unhandled = State.alerts.filter((a) => !a.handled).length;
  badge.textContent = unhandled;
  badge.classList.toggle('hidden', unhandled === 0);
  if (!silent && el) {
    const nameMap = {};
    State.targets.forEach((t) => nameMap[t.id] = t.name);
    const rows = State.alerts.map((a) => `
      <tr>
        <td>${UI.severityTag(a.severity)}</td>
        <td>${esc(a.category)}</td>
        <td>${esc(a.title)}</td>
        <td class="mono small">${esc((a.message || '').slice(0, 160))}</td>
        <td class="small">${esc(nameMap[a.target_id] || a.target_id.slice(0,8))}</td>
        <td class="small">${UI.fmtTime(a.time)}</td>
        <td>
          <button class="btn sm" onclick="toggleAlertDetail('${esc(a.id)}')">${State.expandedAlert === a.id ? '收起' : '展开'}</button>
          ${a.handled ? '<span class="tag green">已处理</span>' : `<button class="btn sm" onclick="markAlert('${esc(a.id)}')">处理</button>`}
        </td>
      </tr>
      ${State.expandedAlert === a.id ? `
      <tr class="alert-detail-row">
        <td colspan="7">
          <div class="alert-detail">
            <div class="alert-detail-title">完整详情</div>
            <pre class="alert-detail-pre">${esc(a.message || '')}</pre>
            ${(a.data && a.data !== '') ? `<div class="alert-detail-title">原始数据</div><pre class="alert-detail-pre">${esc(a.data)}</pre>` : ''}
          </div>
        </td>
      </tr>` : ''}`).join('');
    el.innerHTML = `
      <div class="page-head"><div><div class="page-title">告警中心</div><div class="page-desc">来自靶机检测与 WAF 的告警，点击「展开」查看完整数据原文</div></div>
      <div class="page-actions"><button class="btn" onclick="refreshPage('alerts')">刷新</button></div></div>
      <div class="card">
        <table><thead><tr><th>级别</th><th>类别</th><th>标题</th><th>详情</th><th>靶机</th><th>时间</th><th>操作</th></tr></thead><tbody>
        ${rows || '<tr><td colspan="7" class="empty">暂无告警</td></tr>'}
        </tbody></table>
      </div>`;
  }
}

function toggleAlertDetail(id) {
  State.expandedAlert = (State.expandedAlert === id) ? '' : id;
  loadAlerts(true);
  renderPage('alerts');
}

async function markAlert(id) {
  await API.markAlert(id);
  loadAlerts(true);
  renderPage('alerts');
}

// ===== RAG 知识库 =====
async function renderRAG() {
  const el = $('#page-rag');
  el.innerHTML = '<div class="loading">加载中...</div>';
  try {
    const docs = (await API.kbList()).data || [];
    State.kbDocs = docs;
    const tagFilter = State.ragTag || '全部';
    const kw = (State.ragKw || '').toLowerCase();
    const allTags = [...new Set(docs.flatMap((d) => (d.tags || '').split(/[,，、\s]+/).filter(Boolean)))].sort();
    const filtered = docs.filter((d) => {
      if (tagFilter !== '全部' && !(d.tags || '').includes(tagFilter)) return false;
      if (kw && !(d.title + d.content).toLowerCase().includes(kw)) return false;
      return true;
    });
    const rows = filtered.map((d) => `
      <tr>
        <td class="mono small">${esc(d.id.slice(0,8))}</td>
        <td><a class="link" href="javascript:void(0)" onclick="viewKB('${esc(d.id)}')">${esc(d.title)}</a></td>
        <td class="small">${esc((d.content||'').length)} 字</td>
        <td class="small">${esc(d.source || '-')}</td>
        <td class="small">${(d.tags||'').split(/[,，、\s]+/).filter(Boolean).map((t) => `<span class="tag">${esc(t)}</span>`).join('')}</td>
        <td class="small">${UI.fmtTime(d.created_at)}</td>
        <td><button class="btn sm danger" onclick="delKB('${esc(d.id)}')">删除</button></td>
      </tr>`).join('');

    el.innerHTML = `
      <div class="page-head"><div><div class="page-title">RAG 知识库</div><div class="page-desc">应急响应/加固知识检索（${docs.length} 篇内置手册），支持本地检索与 LLM 增强回答</div></div>
      <div class="page-actions"><button class="btn primary" onclick="UI.openModal('导入知识', kbFormHTML())">导入知识</button></div></div>
      <div class="toolbar">
        <input id="rag-kw" type="text" class="mono" placeholder="关键词过滤..." value="${esc(State.ragKw||'')}" style="width:180px" onkeydown="if(event.key==='Enter'){State.ragKw=this.value;renderPage('rag')}">
        <button class="btn sm" onclick="State.ragKw=$('#rag-kw').value;renderPage('rag')">过滤</button>
        <button class="chip ${tagFilter==='全部'?'on':''}" onclick="State.ragTag='全部';renderPage('rag')">全部</button>
        ${allTags.map((t) => `<button class="chip ${tagFilter===t?'on':''}" onclick="State.ragTag='${esc(t)}';renderPage('rag')">${esc(t)}</button>`).join('')}
        <span class="spacer"></span>
        <span class="small muted">命中 ${filtered.length}/${docs.length}</span>
      </div>
      <div class="grid cols-2">
        <div class="card">
          <div class="card-title">知识文档 (${filtered.length})</div>
          <table><thead><tr><th>ID</th><th>标题</th><th>字数</th><th>来源</th><th>标签</th><th>时间</th><th></th></tr></thead><tbody>${rows || '<tr><td colspan="7" class="empty">暂无知识，请导入应急响应文档</td></tr>'}</tbody></table>
        </div>
        <div class="card">
          <div class="card-title">知识问答</div>
          <textarea id="rag-question" placeholder="例如：靶机发现不死马怎么清除？SSH被爆破如何加固？"></textarea>
          <div class="mt flex"><button class="btn primary" onclick="askRAG()">检索 + 回答</button>
          <button class="btn" onclick="searchRAG()">仅检索</button></div>
          <div id="rag-answer" class="term mt" style="max-height:420px">回答将显示在这里（可配置 USER_LLM_API_KEY 启用 LLM 增强）</div>
        </div>
      </div>`;
  } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
}

function viewKB(id) {
  const d = (State.kbDocs || []).find((x) => x.id === id);
  if (!d) { UI.toast('文档不存在'); return; }
  UI.openModal(esc(d.title), `<div class="term" style="max-height:70vh;white-space:pre-wrap">${esc(d.content)}</div>`);
}

function delKB(id) {
  if (!confirm('确认删除该知识文档？')) return;
  API.kbDel(id).then(() => { UI.toast('已删除'); renderPage('rag'); }).catch((e) => UI.toast(e.message, true));
}

function kbFormHTML() {
  return `
    <div class="form-row"><label>标题</label><input id="kb-title" type="text" placeholder="如: Linux 应急响应手册"></div>
    <div class="form-row"><label>标签(逗号分隔)</label><input id="kb-tags" type="text" placeholder="应急响应,加固,Linux"></div>
    <div class="form-row"><label>内容(支持 Markdown/文本)</label><textarea id="kb-content" rows="10" placeholder="粘贴知识内容..."></textarea></div>
    <div class="flex-between mt"><span class="small muted">同一内容重复导入将自动跳过</span><button class="btn primary" onclick="submitKB()">导入</button></div>`;
}

async function submitKB() {
  const title = $('#kb-title').value.trim();
  const content = $('#kb-content').value.trim();
  if (!content) return UI.toast('内容不能为空', true);
  try {
    await API.kbAdd({ title, content, source: 'manual', tags: $('#kb-tags').value.trim() });
    UI.closeModal();
    UI.toast('知识已导入');
    renderPage('rag');
  } catch (e) { UI.toast(e.message, true); }
}

async function searchRAG() {
  const q = $('#rag-question').value.trim();
  if (!q) return UI.toast('请输入问题', true);
  const res = await API.kbSearch(q, 5);
  const ans = $('#rag-answer');
  ans.className = 'term';
  ans.textContent = (res.data || []).map((d, i) => `[${i+1}] ${d.title} (score=${d.score.toFixed(2)})\n${d.content}\n`).join('\n---\n') || '未检索到相关内容';
}

async function askRAG() {
  const q = $('#rag-question').value.trim();
  if (!q) return UI.toast('请输入问题', true);
  const ans = $('#rag-answer');
  ans.className = 'term';
  ans.textContent = '检索中...';
  try {
    const res = await API.kbAsk(q);
    ans.textContent = res.data;
  } catch (e) { ans.className = 'term err'; ans.textContent = '错误: ' + e.message; }
}

// ===== 设置 =====
async function renderSettings() {
  const el = $('#page-settings');
  try {
    const status = (await API.status()).data;
    el.innerHTML = `
      <div class="page-head"><div><div class="page-title">设置</div><div class="page-desc">面板状态与 Agent 接入信息</div></div></div>
      <div class="grid cols-2">
        <div class="card">
          <div class="card-title">面板状态</div>
          <table>
            <tr><td>版本</td><td class="mono">${esc(status.version)}</td></tr>
            <tr><td>服务端时间</td><td class="mono">${UI.fmtTime(status.server_time)}</td></tr>
            <tr><td>靶机总数</td><td>${status.targets_total}</td></tr>
            <tr><td>在线靶机</td><td style="color:var(--green)">${status.targets_online}</td></tr>
            <tr><td>未处理告警</td><td>${status.alerts_unhandled}</td></tr>
            <tr><td>LLM 增强</td><td>${status.llm_enabled ? '<span class="tag green">已启用</span>' : '<span class="tag">未配置(本地检索)</span>'}</td></tr>
          </table>
        </div>
        <div class="card">
          <div class="card-title">Agent 接入说明</div>
          <div class="small muted mb">在靶机上传 agent 二进制并执行：</div>
          <div class="term">
./shield-agent -s "ws://&lt;本机IP&gt;:8080/ws/agent" -k "&lt;面板Agent密钥&gt;" -n "靶机名称" -debug
          </div>
          <div class="mt small muted">跨平台编译（本机执行）：</div>
          <div class="term">
# Linux 靶机
GOOS=linux GOARCH=amd64 go build -o shield-agent-linux ./cmd/agent
# Windows 靶机
GOOS=windows GOARCH=amd64 go build -o shield-agent.exe ./cmd/agent
          </div>
          <div class="mt small muted">软 WAF 部署依赖 PHP-FPM/FastCGI 模式的 .user.ini auto_prepend_file 机制。</div>
        </div>
      </div>`;
  } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
}

// ===== 防御作战 =====
function defenseTargetHTML() {
  return `<select id="defense-target" onchange="State.currentTarget=this.value;localStorage.setItem('shield_sel_target',this.value)">
    ${State.targets.map((t) => `<option value="${esc(t.id)}" ${t.id===State.currentTarget?'selected':''}>${esc(t.name)} (${esc(t.os)})</option>`).join('')}
  </select>`;
}

async function renderDefense() {
  const el = $('#page-defense');
  el.innerHTML = '<div class="loading">加载中...</div>';
  try {
    const [targetsRes] = await Promise.all([API.targets()]);
    State.targets = targetsRes.data || [];
    const target = State.targets.find((t) => t.id === State.currentTarget) || State.targets[0];
    if (target) { State.currentTarget = target.id; }
    const now = Date.now() / 1000;
    const online = State.targets.filter((t) => now - t.last_seen < 30);

    el.innerHTML = `
      <div class="page-head">
        <div><div class="page-title">防御作战</div><div class="page-desc">人机协同：持续防御守护 / 反向代理WAF / 封禁 / 备份回滚 / 操作审计（所有动作可见可追溯，可选自动或手动触发）</div></div>
        <div class="page-actions"><button class="btn" onclick="refreshPage('defense')">刷新</button></div>
      </div>
      <div class="grid cols-4">
        <div class="card"><div class="stat-value">${State.targets.length}</div><div class="stat-label">靶机总数</div></div>
        <div class="card"><div class="stat-value" style="color:var(--green)">${online.length}</div><div class="stat-label">在线靶机</div></div>
        <div class="card"><div class="stat-value" style="color:var(--accent)">${online.length}</div><div class="stat-label">可下发指令</div></div>
        <div class="card"><div class="stat-value" style="color:var(--purple)">${online.length}</div><div class="stat-label">可广播</div></div>
      </div>
      <div class="toolbar">
        <div style="min-width:200px">${defenseTargetHTML()}</div>
        <button class="btn primary" onclick="refreshTargetState()">获取状态</button>
        <button class="btn" onclick="doTarget(State.currentTarget,'start_defense',{},'防御守护启动已触发')">启动守护</button>
        <button class="btn danger" onclick="doTarget(State.currentTarget,'stop_defense',{},'防御守护停止已触发')">停止守护</button>
        <button class="btn" onclick="doTarget(State.currentTarget,'defense_now',{},'防御检查已触发')">立即检查</button>
        <button class="btn warn" onclick="doTarget(State.currentTarget,'scan_web',{},'Web后门扫描已触发')">Web后门扫描</button>
      </div>
      <div id="defense-state" class="card"><div class="card-title">靶机运行状态</div><div class="empty">选择靶机后点击「获取状态」查看</div></div>
      <div id="defense-action" class="grid cols-2">
        <div class="card">
          <div class="card-title">广播指令（一键下发到所有在线靶机）</div>
          <div class="bcast-grid">
            <div class="bcast-group">
              <div class="cmd-group-title">检测与防护</div>
              <div class="flex gap" style="flex-wrap:wrap">
                <button class="btn" onclick="confirmBroadcast('scan',{},'对全部在线靶机执行风险检测')">广播风险检测</button>
                <button class="btn" onclick="confirmBroadcast('scan_web',{},'对全部在线靶机扫描 Web 后门')">广播Web后门扫描</button>
                <button class="btn" onclick="confirmBroadcast('defense_now',{},'对全部在线靶机立即执行防御检查')">广播防御检查</button>
                <button class="btn" onclick="confirmBroadcast('list_ports',{},'收集全部在线靶机监听端口')">广播端口清单</button>
                <button class="btn" onclick="confirmBroadcast('list_conns',{},'收集全部在线靶机网络连接')">广播连接清单</button>
              </div>
            </div>
            <div class="bcast-group">
              <div class="cmd-group-title">部署与加固</div>
              <div class="flex gap" style="flex-wrap:wrap">
                <button class="btn success" onclick="confirmBroadcast('deploy_waf',{},'为全部在线靶机部署软 WAF')">广播部署WAF</button>
                <button class="btn warn" onclick="confirmBroadcast('harden',{},'对全部在线靶机执行一键加固(25项)')">广播一键加固</button>
                <button class="btn" onclick="confirmBroadcast('backup_web',{},'备份全部在线靶机 Web 目录')">广播Web备份</button>
              </div>
            </div>
            <div class="bcast-group">
              <div class="cmd-group-title">应急响应</div>
              <div class="flex gap" style="flex-wrap:wrap">
                <button class="btn" onclick="confirmBroadcast('unban_ip',{},'清空全部在线靶机动态封禁列表')">广播解除封禁</button>
                <button class="btn danger" onclick="broadcastExec()">广播执行命令</button>
              </div>
            </div>
          </div>
          <div class="mt small muted">广播动作会写入操作审计，可在下方追溯；下发前会二次确认。</div>
        </div>
        <div class="card">
          <div class="card-title">操作审计（人机协同 · 全部动作留痕）</div>
          <div id="audit-log" class="audit-log"><div class="empty">加载中...</div></div>
        </div>
      </div>`;
    loadAudit();
  } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
}

function refreshTargetState() {
  const el = $('#defense-state');
  el.innerHTML = '<div class="card-title">靶机运行状态</div><div class="loading">查询中...</div>';
  doTarget(State.currentTarget, 'refresh', {}, '状态查询已触发');
}

function renderRefreshResult(d) {
  const el = $('#defense-state');
  if (!el || !d) return;
  const ban = d.revproxy_snapshot || {};
  const hits = (d.revproxy_hits || []).slice(0, 10);
  el.innerHTML = `<div class="card-title">靶机运行状态</div>
    <div class="grid cols-4 mb">
      <div class="stat-label">WAF ${d.waf?'<span class="tag green">已部署</span>':'<span class="tag">未部署</span>'}</div>
      <div class="stat-label">防御守护 ${d.defense?'<span class="tag green">运行中</span>':'<span class="tag">停止</span>'}</div>
      <div class="stat-label">反向代理 ${d.revproxy?'<span class="tag green">运行中</span>':'<span class="tag">未启用</span>'}</div>
      <div class="stat-label">规则数 ${d.rules_count||0}</div>
    </div>
    ${ban.bans && ban.bans.length ? `<div class="mb small"><b>动态封禁:</b> ${ban.bans.map((b)=>esc(b.ip)+'('+b.reason+','+b.expire_in+'s)').join(' · ')}</div>` : ''}
    ${hits.length ? `<div class="small"><b>最近WAF命中:</b></div><div class="audit-log">${hits.map((h)=>`<div class="audit-item"><span class="tag ${h.severity==='critical'?'red':''}">${esc(h.side)}</span> ${esc(h.name)} <span class="mono small muted">${esc(h.pattern)}</span></div>`).join('')}</div>` : ''}`;
}

async function loadAudit() {
  const el = $('#audit-log');
  if (!el) return;
  try {
    const res = await API.audit(100);
    const evs = (res.data.events || []).slice(0, 60);
    el.innerHTML = evs.map((e) => {
      let payload = '';
      try { payload = JSON.stringify(JSON.parse(e.payload), null, 0).slice(0, 180); } catch (err) { payload = esc(e.payload); }
      return `<div class="audit-item">
        <span class="small muted mono">${UI.fmtTime(e.time)}</span>
        <span class="tag info">${esc(e.type)}</span>
        <span class="mono small">${esc((e.target_id||'').slice(0,8))}</span>
        <span class="small">${esc(payload)}</span>
      </div>`;
    }).join('') || '<div class="empty">暂无操作记录</div>';
  } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
}

function refreshAudit() {
  if (document.querySelector('#page-defense') && !document.querySelector('#page-defense').classList.contains('hidden')) loadAudit();
}

async function broadcastAction(type, body, msg) {
  try {
    const res = await API.broadcast(type, body || {}, msg);
    UI.toast('广播已下发到 ' + (res.sent||0) + ' 台在线靶机');
    setTimeout(loadAudit, 300);
  } catch (e) { UI.toast(e.message, true); }
}

function confirmBroadcast(type, body, desc) {
  UI.openModal('确认广播指令', `
    <div class="small muted mb">${esc(desc)}</div>
    <div class="form-row"><label>动作</label><span class="mono">${esc(type)}</span></div>
    <div class="flex-between mt"><span class="small muted">将下发到全部在线靶机</span>
      <button class="btn primary" onclick="broadcastAction('${esc(type)}', ${JSON.stringify(body||{}).replace(/"/g,'&quot;')}, '${esc(desc)}')">确认广播</button>
    </div>`);
}

function broadcastExec() {
  UI.openModal('广播执行命令', `
    <div class="form-row"><label>命令</label><input id="bcast-cmd" type="text" placeholder="如: chmod o-w /var/www/html -R" class="mono"></div>
    <div class="form-row"><label>说明(写入审计)</label><input id="bcast-msg" type="text" placeholder="如: 广播收紧Web目录权限"></div>
    <div class="flex-between mt"><span></span><button class="btn primary" onclick="doBroadcastExec()">广播执行</button></div>`);
}

async function doBroadcastExec() {
  const cmd = $('#bcast-cmd').value.trim();
  if (!cmd) return UI.toast('请输入命令', true);
  try {
    const res = await API.broadcast('exec', { command: cmd }, $('#bcast-msg').value.trim() || ('广播命令: ' + cmd));
    UI.closeModal();
    UI.toast('广播已下发到 ' + (res.sent||0) + ' 台在线靶机');
    setTimeout(loadAudit, 300);
  } catch (e) { UI.toast(e.message, true); }
}

function deployRevproxy(id) {
  UI.openModal('反向代理 WAF 部署 · ' + id.slice(0,8), `
    <div class="small muted mb">反向代理前置拦截全部进出 Web 流量，含多层解码检测、响应Flag替换、动态封禁与CC限速。软WAF(.user.ini)与反向代理双模式可并存。</div>
    <div class="form-row"><label>监听地址</label><input id="rv-listen" type="text" value=":8080" class="mono"></div>
    <div class="form-row"><label>上游地址</label><input id="rv-host" type="text" value="127.0.0.1" class="mono"></div>
    <div class="form-row"><label>上游端口</label><input id="rv-port" type="number" value="80"></div>
    <div class="form-row"><label>拦截模式</label><select id="rv-block"><option value="true">拦截 block</option><option value="false">仅告警 alert</option></select></div>
    <div class="form-row"><label>响应Flag替换</label><select id="rv-flag"><option value="true">启用</option><option value="false">停用</option></select></div>
    <div class="flex-between mt"><span></span>
      <div class="flex gap">
        <button class="btn danger" onclick="doTarget('${esc(id)}','disable_revproxy',{},'反向代理已停用')">停用</button>
        <button class="btn primary" onclick="doDeployRevproxy('${esc(id)}')">部署</button>
      </div>
    </div>`);
}

async function doDeployRevproxy(id) {
  const body = {
    enabled: true,
    listen_addr: $('#rv-listen').value.trim() || ':8080',
    upstream_host: $('#rv-host').value.trim() || '127.0.0.1',
    upstream_port: parseInt($('#rv-port').value) || 80,
    block_mode: $('#rv-block').value === 'true',
    flag_protect: $('#rv-flag').value === 'true',
    threshold: 5, ttl_seconds: 300, rate_limit: 100, rate_window: 10,
  };
  try {
    await API.targetAction(id, 'deploy_revproxy', body);
    UI.closeModal();
    UI.toast('反向代理 WAF 部署指令已下发');
  } catch (e) { UI.toast(e.message, true); }
}

function renderRevproxyResult(d) {
  if (!d) return;
  UI.toast(d.ok ? '反向代理 WAF ' + d.listen + ' -> ' + d.upstream : '部署失败: ' + (d.error||''));
}

function banIPForm(id) {
  UI.openModal('封禁 / 解封 IP · ' + id.slice(0,8), `
    <div class="form-row"><label>IP 地址</label><input id="ban-ip" type="text" placeholder="如: 192.168.1.100" class="mono"></div>
    <div class="form-row"><label>封禁时长(秒)</label><input id="ban-ttl" type="number" value="300"></div>
    <div class="form-row"><label>真实防火墙封禁</label><select id="ban-fw"><option value="true">启用(iptables/netsh)</option><option value="false">仅WAF动态封禁</option></select></div>
    <div class="flex-between mt"><span></span>
      <div class="flex gap">
        <button class="btn danger" onclick="doBanIP('${esc(id)}',true)">解封</button>
        <button class="btn primary" onclick="doBanIP('${esc(id)}',false)">封禁</button>
      </div>
    </div>`);
}

async function doBanIP(id, unban) {
  const ip = $('#ban-ip').value.trim();
  if (!ip) return UI.toast('请输入 IP', true);
  const body = { ip, firewall: $('#ban-fw').value === 'true' };
  if (!unban) body.ttl_seconds = parseInt($('#ban-ttl').value) || 300;
  try {
    await API.targetAction(id, unban ? 'unban_ip' : 'ban_ip', body);
    UI.closeModal();
    UI.toast((unban ? '解封' : '封禁') + '指令已下发: ' + ip);
  } catch (e) { UI.toast(e.message, true); }
}

function renderDefenseNowResult(d) {
  if (!d || !d.checks) return;
  const rows = Object.entries(d.checks).map(([k, v]) => `
    <tr><td>${esc(k)}</td><td>${v === 'ok' ? '<span class="tag green">正常</span>' : '<span class="tag red">' + esc(v) + '</span>'}</td></tr>`).join('');
  UI.openModal('防御检查结果', `<table><thead><tr><th>检查项</th><th>状态</th></tr></thead><tbody>${rows}</tbody></table>`);
}

function renderScanWebResult(d) {
  if (!d) return;
  const hits = (d.backdoor_hits || []).map((h) => `<tr><td class="mono small">${esc(h.file)}</td><td class="mono small">${esc(h.sig)}</td></tr>`).join('');
  UI.openModal('Web 后门扫描结果', `
    <div class="mb">扫描 <b>${d.scanned||0}</b> 个文件 · 新增 <b>${(d.new_files||[]).length}</b> · 变更 <b>${(d.changed||[]).length}</b> · 后门命中 <b style="color:var(--red)">${(d.backdoor_hits||[]).length}</b></div>
    ${hits ? `<table><thead><tr><th>文件</th><th>特征</th></tr></thead><tbody>${hits}</tbody></table>` : '<div class="small muted">未发现后门特征</div>'}`);
}

function renderListResult(kind, data) {
  if (!data) return;
  if (kind === 'ports') {
    UI.openModal('监听端口', `<table><thead><tr><th>地址</th><th>端口</th><th>进程</th></tr></thead><tbody>${data.map((p)=>`<tr><td class="mono">${esc(p.addr)}</td><td>${esc(p.port)}</td><td class="small">${esc(p.process||'')}</td></tr>`).join('')||'<tr><td colspan="3" class="empty">无</td></tr>'}</tbody></table>`);
  } else {
    UI.openModal('出站连接', `<table><thead><tr><th>本地</th><th>远程</th></tr></thead><tbody>${data.map((c)=>`<tr><td class="mono">${esc(c.local)}</td><td class="mono">${esc(c.remote)}</td></tr>`).join('')||'<tr><td colspan="2" class="empty">无</td></tr>'}</tbody></table>`);
  }
}

// ===== 公共 =====
function refreshPage(page) { renderPage(page); }

async function refreshTargetsSilent() {
  try {
    const res = await API.targets();
    State.targets = res.data || [];
  } catch (e) { /* ignore */ }
}

// ===== 启动 =====
async function init() {
  // 事件绑定
  $('#login-btn').onclick = async () => {
    const token = $('#login-token').value.trim();
    if (!token) return;
    try { await API.login(token); UI.enterApp(); navigate('dashboard'); connectWS(); }
    catch (e) { $('#login-err').textContent = e.message; }
  };
  $('#login-token').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#login-btn').click(); });
  $('#modal-mask').addEventListener('click', (e) => { if (e.target.id === 'modal-mask') UI.closeModal(); });
  window.addEventListener('hashchange', () => {
    const page = location.hash.replace('#', '') || 'dashboard';
    navigate(page);
  });

  // 尝试恢复会话
  const token = localStorage.getItem('shield_token');
  if (token) {
    API.token = token;
    try {
      await API.status();
      UI.enterApp();
      navigate(location.hash.replace('#', '') || 'dashboard');
      connectWS();
      return;
    } catch (e) { /* fall through to login */ }
  }
  UI.showLogin();
}

document.addEventListener('DOMContentLoaded', init);
