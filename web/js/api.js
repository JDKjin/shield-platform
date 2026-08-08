// API 客户端
const API = {
  token: null,

  async request(method, path, body) {
    const opts = { method, headers: {} };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const token = this.token || localStorage.getItem('shield_token') || '';
    if (token) opts.headers['Authorization'] = 'Bearer ' + token;

    let res;
    try {
      res = await fetch(path, opts);
    } catch (e) {
      throw new Error('网络错误: ' + e.message);
    }
    let data = null;
    try { data = await res.json(); } catch (e) { /* non-json */ }
    if (res.status === 401) {
      UI.showLogin();
      throw new Error('未授权，请重新登录');
    }
    if (!res.ok) throw new Error((data && data.error) || ('HTTP ' + res.status));
    return data;
  },

  get(path) { return this.request('GET', path); },
  post(path, body) { return this.request('POST', path, body); },
  del(path) { return this.request('DELETE', path); },

  async login(token) {
    const data = await this.request('POST', '/api/login', { token });
    this.token = token;
    localStorage.setItem('shield_token', token);
    return data;
  },

  status() { return this.get('/api/status'); },
  targets() { return this.get('/api/targets'); },
  alerts(limit) { return this.get('/api/alerts' + (limit ? '?limit=' + limit : '')); },
  markAlert(id) { return this.post('/api/alerts/' + id, {}); },
  rules() { return this.get('/api/rules'); },
  addRule(r) { return this.post('/api/rules', r); },
  delRule(id) { return this.del('/api/rules/' + id); },
  hardenItems() { return this.get('/api/harden/items'); },
  detectChecks() { return this.get('/api/detect/checks'); },
  events(limit) { return this.get('/api/events' + (limit ? '?limit=' + limit : '')); },

  targetAction(id, action, body) { return this.post('/api/targets/' + id + '/' + action, body || {}); },
  delTarget(id) { return this.del('/api/targets/' + id); },

  kbList() { return this.get('/api/kb'); },
  kbAdd(doc) { return this.post('/api/kb', doc); },
  kbDel(id) { return this.del('/api/kb/' + id); },
  kbSearch(q, top) { return this.get('/api/kb/search?q=' + encodeURIComponent(q) + '&top=' + (top || 5)); },
  kbAsk(question) { return this.post('/api/kb/ask', { question }); },

  broadcast(type, data, message) { return this.post('/api/broadcast', { type, data, message }); },
  audit(limit) { return this.get('/api/audit' + (limit ? '?limit=' + limit : '')); },
};
