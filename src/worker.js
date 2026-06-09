// CloudflareSub Enhanced Worker
// Features added:
// 1) Admin page: /admin
// 2) List / get / update / delete subscriptions in KV
// 3) Fixed subscription ID support
// 4) Long TTL by default via SUB_TTL_DAYS, default 3650 days
//
// Required binding:
// - KV namespace: SUB_STORE
// Recommended secret:
// - SUB_ACCESS_TOKEN

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
      'access-control-allow-headers': 'content-type',
    },
  });
}

function text(body, status = 200, contentType = 'text/plain; charset=utf-8') {
  return new Response(body, {
    status,
    headers: {
      'content-type': contentType,
      'access-control-allow-origin': '*',
    },
  });
}

function html(body, status = 200) {
  return text(body, status, 'text/html; charset=utf-8');
}

function b64EncodeUtf8(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

function b64DecodeUtf8(str) {
  return decodeURIComponent(escape(atob(str)));
}

function escapeYaml(str = '') {
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, ' ');
}

function escapeHtml(str = '') {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function parsePreferredEndpoints(input) {
  return String(input || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [raw, ...remarkParts] = line.split('#');
      const value = raw.trim();
      const hashRemark = remarkParts.join('#').trim();

      // IPv6 with port should be [2606:4700::]:443#remark
      const ipv6WithPort = value.match(/^\[([^\]]+)\]:(\d+)$/);
      if (ipv6WithPort) {
        return {
          server: ipv6WithPort[1],
          port: Number(ipv6WithPort[2]),
          remark: hashRemark,
        };
      }

      const match = value.match(/^(.*?)(?::(\d+))?$/);
      return {
        server: match?.[1] || value,
        port: match?.[2] ? Number(match[2]) : undefined,
        remark: hashRemark,
      };
    });
}

function parseVmess(link) {
  const raw = link.slice('vmess://'.length).trim();
  const obj = JSON.parse(b64DecodeUtf8(raw));
  return {
    type: 'vmess',
    name: obj.ps || 'vmess',
    server: obj.add,
    port: Number(obj.port || 443),
    uuid: obj.id,
    cipher: obj.scy || 'auto',
    network: obj.net || 'ws',
    tls: obj.tls === 'tls',
    host: obj.host || '',
    path: obj.path || '/',
    sni: obj.sni || obj.host || '',
    alpn: obj.alpn || '',
    fp: obj.fp || '',
  };
}

function parseUrlLike(link, type) {
  const u = new URL(link);
  return {
    type,
    name: decodeURIComponent(u.hash.replace(/^#/, '')) || type,
    server: u.hostname,
    port: Number(u.port || 443),
    password: type === 'trojan' ? decodeURIComponent(u.username) : undefined,
    uuid: type === 'vless' ? decodeURIComponent(u.username) : undefined,
    network: u.searchParams.get('type') || 'tcp',
    tls: (u.searchParams.get('security') || '').toLowerCase() === 'tls',
    host: u.searchParams.get('host') || u.searchParams.get('sni') || '',
    path: u.searchParams.get('path') || '/',
    sni: u.searchParams.get('sni') || u.searchParams.get('host') || '',
    fp: u.searchParams.get('fp') || '',
    alpn: u.searchParams.get('alpn') || '',
    flow: u.searchParams.get('flow') || '',
  };
}

function parseRawLinks(input) {
  const lines = String(input || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const result = [];
  for (const line of lines) {
    if (line.startsWith('vmess://')) {
      result.push(parseVmess(line));
      continue;
    }
    if (line.startsWith('vless://')) {
      result.push(parseUrlLike(line, 'vless'));
      continue;
    }
    if (line.startsWith('trojan://')) {
      result.push(parseUrlLike(line, 'trojan'));
      continue;
    }
    try {
      const decoded = b64DecodeUtf8(line);
      if (/^(vmess|vless|trojan):\/\//m.test(decoded)) {
        result.push(...parseRawLinks(decoded));
      }
    } catch {}
  }
  return result;
}

function buildNodes(baseNodes, preferredEndpoints, options = {}) {
  const output = [];
  const prefix = (options.namePrefix || '').trim();
  let counter = 0;

  for (const node of baseNodes) {
    for (const ep of preferredEndpoints) {
      counter += 1;
      const nameParts = [];
      if (node.name) nameParts.push(node.name);
      if (prefix) nameParts.push(prefix);
      if (ep.remark) nameParts.push(ep.remark);
      else nameParts.push(String(counter));

      output.push({
        ...node,
        name: nameParts.join(' | '),
        server: ep.server,
        port: ep.port || node.port,
        host: options.keepOriginalHost ? node.host : '',
        sni: options.keepOriginalHost ? node.sni : '',
      });
    }
  }
  return output;
}

function encodeVmess(node) {
  const obj = {
    v: '2',
    ps: node.name,
    add: node.server,
    port: String(node.port),
    id: node.uuid,
    aid: '0',
    scy: node.cipher || 'auto',
    net: node.network || 'ws',
    type: 'none',
    host: node.host || '',
    path: node.path || '/',
    tls: node.tls ? 'tls' : '',
    sni: node.sni || '',
    alpn: node.alpn || '',
    fp: node.fp || '',
  };
  return 'vmess://' + b64EncodeUtf8(JSON.stringify(obj));
}

function encodeVless(node) {
  const url = new URL(`vless://${encodeURIComponent(node.uuid)}@${node.server}:${node.port}`);
  url.searchParams.set('type', node.network || 'ws');
  if (node.tls) url.searchParams.set('security', 'tls');
  if (node.host) url.searchParams.set('host', node.host);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  if (node.flow) url.searchParams.set('flow', node.flow);
  url.hash = node.name;
  return url.toString();
}

function encodeTrojan(node) {
  const url = new URL(`trojan://${encodeURIComponent(node.password)}@${node.server}:${node.port}`);
  if (node.network) url.searchParams.set('type', node.network);
  if (node.tls) url.searchParams.set('security', 'tls');
  if (node.host) url.searchParams.set('host', node.host);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  url.hash = node.name;
  return url.toString();
}

function renderRaw(nodes) {
  const lines = nodes
    .map((node) => {
      if (node.type === 'vmess') return encodeVmess(node);
      if (node.type === 'vless') return encodeVless(node);
      if (node.type === 'trojan') return encodeTrojan(node);
      return '';
    })
    .filter(Boolean);
  return b64EncodeUtf8(lines.join('\n'));
}

function renderClash(nodes) {
  const proxies = nodes
    .map((node) => {
      if (node.type === 'vmess') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: vmess`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    uuid: ${node.uuid}`,
          `    alterId: 0`,
          `    cipher: ${node.cipher || 'auto'}`,
          `    udp: true`,
          `    tls: ${node.tls ? 'true' : 'false'}`,
          `    network: ${node.network || 'ws'}`,
        ];
        if (node.sni) lines.push(`    servername: "${escapeYaml(node.sni)}"`);
        if ((node.network || 'ws') === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }
        return lines.join('\n');
      }

      if (node.type === 'vless') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: vless`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    uuid: ${node.uuid}`,
          `    udp: true`,
          `    tls: ${node.tls ? 'true' : 'false'}`,
          `    network: ${node.network || 'ws'}`,
        ];
        if (node.sni) lines.push(`    servername: "${escapeYaml(node.sni)}"`);
        if ((node.network || 'ws') === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }
        return lines.join('\n');
      }

      if (node.type === 'trojan') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: trojan`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    password: "${escapeYaml(node.password || '')}"`,
          `    udp: true`,
        ];
        if (node.sni) lines.push(`    sni: "${escapeYaml(node.sni)}"`);
        if (node.tls !== false) lines.push(`    tls: true`);
        if (node.network) lines.push(`    network: ${node.network}`);
        if (node.network === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }
        return lines.join('\n');
      }
      return '';
    })
    .filter(Boolean);

  const proxyNames = nodes.map((node) => `      - "${escapeYaml(node.name)}"`);
  const allGroupMembers = [`      - "自动选择"`, ...proxyNames, `      - DIRECT`];
  const autoGroupMembers = proxyNames.length ? proxyNames : [`      - DIRECT`];

  return [
    `mixed-port: 7890`,
    `allow-lan: false`,
    `mode: rule`,
    `log-level: info`,
    `ipv6: true`,
    ``,
    `proxies:`,
    ...(proxies.length ? proxies : []),
    ``,
    `proxy-groups:`,
    `  - name: "自动选择"`,
    `    type: url-test`,
    `    url: "http://www.gstatic.com/generate_204"`,
    `    interval: 300`,
    `    tolerance: 50`,
    `    proxies:`,
    ...autoGroupMembers,
    ``,
    `  - name: "节点选择"`,
    `    type: select`,
    `    proxies:`,
    ...allGroupMembers,
    ``,
    `rules:`,
    `  - MATCH,节点选择`,
  ].join('\n');
}

function renderSurge(nodes, baseUrl, accessToken) {
  const compatible = nodes.filter((node) => node.type === 'vmess' || node.type === 'trojan');
  const proxies = compatible.map((node) => {
    if (node.type === 'vmess') {
      return `${node.name} = vmess, ${node.server}, ${node.port}, username=${node.uuid}, ws=true, ws-path=${node.path || '/'}, ws-headers=Host:${node.host || ''}, tls=${node.tls ? 'true' : 'false'}, sni=${node.sni || ''}`;
    }
    return `${node.name} = trojan, ${node.server}, ${node.port}, password=${node.password || ''}, sni=${node.sni || ''}`;
  });
  return [
    '[General]',
    'skip-proxy = 127.0.0.1, localhost',
    '',
    '[Proxy]',
    ...proxies,
    '',
    '[Proxy Group]',
    'Proxy = url-test, ' + compatible.map((n) => n.name).join(', ') + ', url=http://www.gstatic.com/generate_204, interval=300, tolerance=50',
    '',
    '[Rule]',
    'FINAL,Proxy',
    '',
    '; token-protected subscription',
    `; ${baseUrl}?token=${accessToken}`,
  ].join('\n');
}

function createShortId(length = 10) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = '';
  for (let i = 0; i < length; i++) out += chars[bytes[i] % chars.length];
  return out;
}

async function createUniqueShortId(env, tries = 8) {
  for (let i = 0; i < tries; i++) {
    const id = createShortId(10);
    const exists = await env.SUB_STORE.get(`sub:${id}`);
    if (!exists) return id;
  }
  throw new Error('无法生成唯一短链接，请稍后再试');
}

function normalizeLines(value = '') {
  return String(value)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .sort()
    .join('\n');
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function buildDedupHash(body) {
  const normalized = {
    nodeLinks: normalizeLines(body.nodeLinks || ''),
    preferredIps: normalizeLines(body.preferredIps || ''),
    namePrefix: String(body.namePrefix || '').trim(),
    keepOriginalHost: body.keepOriginalHost !== false,
  };
  return sha256Hex(JSON.stringify(normalized));
}

function getTtlSeconds(env) {
  // SUB_TTL_DAYS=0 means no expiration.
  const raw = env.SUB_TTL_DAYS;
  if (raw === undefined || raw === null || raw === '') return 60 * 60 * 24 * 3650;
  const days = Number(raw);
  if (!Number.isFinite(days) || days < 0) return 60 * 60 * 24 * 3650;
  if (days === 0) return 0;
  return Math.floor(days * 24 * 60 * 60);
}

function kvPutOptions(env) {
  const ttl = getTtlSeconds(env);
  return ttl > 0 ? { expirationTtl: ttl } : undefined;
}

function validateAccessToken(url, env) {
  const expected = env.SUB_ACCESS_TOKEN;
  if (!expected) return { ok: true };
  const provided = url.searchParams.get('token') || '';
  if (!provided || provided !== expected) {
    return { ok: false, response: text('Forbidden: invalid token', 403) };
  }
  return { ok: true };
}

function validateAdminToken(url, env) {
  const expected = env.SUB_ACCESS_TOKEN;
  if (!expected) {
    return { ok: false, response: json({ ok: false, error: '请先配置 SUB_ACCESS_TOKEN，否则不开放管理接口' }, 403) };
  }
  const provided = url.searchParams.get('token') || '';
  if (!provided || provided !== expected) {
    return { ok: false, response: json({ ok: false, error: 'invalid token' }, 403) };
  }
  return { ok: true };
}

function isValidId(id = '') {
  return /^[A-Za-z0-9_-]{3,64}$/.test(id);
}

function buildPayloadFromInput(body) {
  const baseNodes = parseRawLinks(body.nodeLinks || '');
  const preferredEndpoints = parsePreferredEndpoints(body.preferredIps || '');

  if (!baseNodes.length) throw new Error('没有识别到可用节点');
  if (!preferredEndpoints.length) throw new Error('没有识别到可用优选地址');

  const options = {
    namePrefix: body.namePrefix || '',
    keepOriginalHost: body.keepOriginalHost !== false,
  };
  const nodes = buildNodes(baseNodes, preferredEndpoints, options);

  return {
    version: 2,
    createdAt: body.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    options,
    input: {
      nodeLinks: String(body.nodeLinks || ''),
      preferredIps: String(body.preferredIps || ''),
      namePrefix: String(body.namePrefix || ''),
      keepOriginalHost: body.keepOriginalHost !== false,
    },
    nodes,
  };
}

function makeUrls(origin, id, accessToken) {
  const withToken = (target) =>
    `${origin}/sub/${id}${target ? `?target=${target}&token=${encodeURIComponent(accessToken)}` : `?token=${encodeURIComponent(accessToken)}`}`;

  return {
    auto: withToken(''),
    raw: withToken('raw'),
    clash: withToken('clash'),
    surge: withToken('surge'),
  };
}

async function handleGenerate(request, env, url) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: '请求体不是合法 JSON' }, 400);
  }

  let payload;
  try {
    payload = buildPayloadFromInput(body);
  } catch (e) {
    return json({ ok: false, error: e.message }, 400);
  }

  const customId = String(body.customId || body.id || '').trim();
  let id;

  // If customId is provided, require token and overwrite that fixed subscription.
  if (customId) {
    if (!isValidId(customId)) return json({ ok: false, error: 'customId 只能包含字母、数字、_、-，长度 3-64' }, 400);
    const tokenCheck = validateAdminToken(url, env);
    if (!tokenCheck.ok) return tokenCheck.response;
    id = customId;
  } else {
    const dedupHash = await buildDedupHash(body);
    const dedupKey = `dedup:${dedupHash}`;
    id = await env.SUB_STORE.get(dedupKey);
    if (!id) id = await createUniqueShortId(env);
    await env.SUB_STORE.put(dedupKey, id, kvPutOptions(env));
  }

  await env.SUB_STORE.put(`sub:${id}`, JSON.stringify(payload), kvPutOptions(env));

  const origin = url.origin;
  const accessToken = env.SUB_ACCESS_TOKEN || '';

  return json({
    ok: true,
    storage: 'kv',
    shortId: id,
    fixed: Boolean(customId),
    urls: makeUrls(origin, id, accessToken),
    counts: {
      inputNodes: parseRawLinks(body.nodeLinks || '').length,
      preferredEndpoints: parsePreferredEndpoints(body.preferredIps || '').length,
      outputNodes: payload.nodes.length,
    },
    preview: payload.nodes.slice(0, 20).map((node) => ({
      name: node.name,
      type: node.type,
      server: node.server,
      port: node.port,
      host: node.host || '',
      sni: node.sni || '',
    })),
    warnings: accessToken ? [] : ['未检测到 SUB_ACCESS_TOKEN，订阅链接将没有第二层访问保护，且管理后台不可用。'],
  });
}

async function handleSub(url, env) {
  const tokenCheck = validateAccessToken(url, env);
  if (!tokenCheck.ok) return tokenCheck.response;

  const id = url.pathname.split('/').pop();
  if (!id) return text('missing id', 400);

  const raw = await env.SUB_STORE.get(`sub:${id}`);
  if (!raw) return text('not found', 404);

  const record = JSON.parse(raw);
  const nodes = record.nodes || [];
  const target = (url.searchParams.get('target') || 'raw').toLowerCase();

  if (target === 'clash') return text(renderClash(nodes), 200, 'text/yaml; charset=utf-8');
  if (target === 'surge') {
    return text(renderSurge(nodes, url.origin + url.pathname, env.SUB_ACCESS_TOKEN || ''), 200, 'text/plain; charset=utf-8');
  }
  return text(renderRaw(nodes), 200, 'text/plain; charset=utf-8');
}

function nodesToPreferredIps(nodes = []) {
  return nodes
    .map((n, index) => `${n.server}:${n.port || 443}#${String(n.name || `CF-${index + 1}`).split('|').pop().trim()}`)
    .join('\n');
}

async function handleAdminList(url, env) {
  const tokenCheck = validateAdminToken(url, env);
  if (!tokenCheck.ok) return tokenCheck.response;

  const list = await env.SUB_STORE.list({ prefix: 'sub:' });
  const items = list.keys.map((k) => ({
    id: k.name.replace(/^sub:/, ''),
    name: k.name,
    expiration: k.expiration || null,
    metadata: k.metadata || null,
  }));
  return json({ ok: true, count: items.length, items, list_complete: list.list_complete, cursor: list.cursor || null });
}

async function handleAdminGet(url, env) {
  const tokenCheck = validateAdminToken(url, env);
  if (!tokenCheck.ok) return tokenCheck.response;

  const id = url.searchParams.get('id') || '';
  if (!isValidId(id)) return json({ ok: false, error: 'id 不合法' }, 400);

  const raw = await env.SUB_STORE.get(`sub:${id}`);
  if (!raw) return json({ ok: false, error: 'not found' }, 404);

  const record = JSON.parse(raw);
  return json({
    ok: true,
    id,
    record,
    editable: {
      nodeLinks: record.input?.nodeLinks || '',
      preferredIps: record.input?.preferredIps || nodesToPreferredIps(record.nodes || []),
      namePrefix: record.input?.namePrefix ?? record.options?.namePrefix ?? '',
      keepOriginalHost: record.input?.keepOriginalHost ?? record.options?.keepOriginalHost ?? true,
      hasOriginalInput: Boolean(record.input?.nodeLinks),
    },
    urls: makeUrls(url.origin, id, env.SUB_ACCESS_TOKEN || ''),
  });
}

async function handleAdminUpdate(request, env, url) {
  const tokenCheck = validateAdminToken(url, env);
  if (!tokenCheck.ok) return tokenCheck.response;

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: '请求体不是合法 JSON' }, 400);
  }

  const id = String(body.id || '').trim();
  if (!isValidId(id)) return json({ ok: false, error: 'id 不合法' }, 400);

  let payload;
  try {
    payload = buildPayloadFromInput(body);
  } catch (e) {
    return json({ ok: false, error: e.message }, 400);
  }

  await env.SUB_STORE.put(`sub:${id}`, JSON.stringify(payload), kvPutOptions(env));

  return json({
    ok: true,
    id,
    urls: makeUrls(url.origin, id, env.SUB_ACCESS_TOKEN || ''),
    counts: {
      outputNodes: payload.nodes.length,
      preferredEndpoints: parsePreferredEndpoints(body.preferredIps || '').length,
    },
  });
}

async function handleAdminDelete(request, env, url) {
  const tokenCheck = validateAdminToken(url, env);
  if (!tokenCheck.ok) return tokenCheck.response;

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: '请求体不是合法 JSON' }, 400);
  }

  const id = String(body.id || '').trim();
  if (!isValidId(id)) return json({ ok: false, error: 'id 不合法' }, 400);

  await env.SUB_STORE.delete(`sub:${id}`);
  return json({ ok: true, deleted: id });
}

function renderAdminPage() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>CloudflareSub 管理后台</title>
  <style>
    body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;max-width:1050px;margin:24px auto;padding:0 16px;background:#f7f7f8;color:#111}
    h1{font-size:24px}
    .card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:16px;margin:14px 0;box-shadow:0 1px 2px rgba(0,0,0,.04)}
    label{display:block;margin:10px 0 6px;font-weight:600}
    input,textarea{width:100%;box-sizing:border-box;border:1px solid #d1d5db;border-radius:8px;padding:9px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
    textarea{min-height:120px}
    button{border:0;border-radius:8px;padding:9px 13px;margin:6px 6px 6px 0;cursor:pointer;background:#111827;color:#fff}
    button.secondary{background:#374151}
    button.danger{background:#b91c1c}
    pre{white-space:pre-wrap;background:#111827;color:#e5e7eb;border-radius:8px;padding:12px;overflow:auto}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    @media(max-width:780px){.row{grid-template-columns:1fr}}
    .muted{color:#6b7280;font-size:13px}
  </style>
</head>
<body>
  <h1>CloudflareSub 管理后台</h1>
  <p class="muted">用于固定订阅 ID、添加/更换优选 IP、保持 v2rayN/小火箭订阅 URL 不变。</p>

  <div class="card">
    <label>管理 Token（SUB_ACCESS_TOKEN）</label>
    <input id="token" placeholder="输入 SUB_ACCESS_TOKEN" />
    <button onclick="saveToken()">保存 Token</button>
    <button class="secondary" onclick="listSubs()">列出订阅</button>
  </div>

  <div class="card">
    <div class="row">
      <div>
        <label>订阅 ID</label>
        <input id="subId" placeholder="例如 auto / mycf / AbC123xYz9" />
      </div>
      <div>
        <label>名称前缀 namePrefix</label>
        <input id="namePrefix" value="CF" />
      </div>
    </div>

    <label><input type="checkbox" id="keepOriginalHost" checked style="width:auto"> 保留原始 Host/SNI（建议开启）</label>

    <label>原始节点链接 nodeLinks</label>
    <textarea id="nodeLinks" placeholder="粘贴 vless:// / vmess:// / trojan:// 原始节点。旧订阅如果没有保存原始节点，需要你手动补填。"></textarea>

    <label>优选 IP preferredIps</label>
    <textarea id="preferredIps" placeholder="104.16.1.2:443#CF-01&#10;104.17.2.3:443#CF-02"></textarea>

    <button onclick="loadSub()">读取订阅</button>
    <button onclick="updateSub()">保存/更新这个 ID</button>
    <button class="danger" onclick="deleteSub()">删除这个 ID</button>
  </div>

  <div class="card">
    <h3>结果</h3>
    <pre id="result">等待操作...</pre>
  </div>

<script>
const $ = id => document.getElementById(id);
$('token').value = localStorage.getItem('sub_token') || '';

function tokenQS() {
  return '?token=' + encodeURIComponent($('token').value.trim());
}
function saveToken(){
  localStorage.setItem('sub_token', $('token').value.trim());
  out('已保存 Token 到浏览器 localStorage。');
}
function out(x){
  $('result').textContent = typeof x === 'string' ? x : JSON.stringify(x, null, 2);
}
async function listSubs(){
  const r = await fetch('/api/admin/list' + tokenQS());
  const j = await r.json();
  out(j);
}
async function loadSub(){
  const id = $('subId').value.trim();
  const r = await fetch('/api/admin/get' + tokenQS() + '&id=' + encodeURIComponent(id));
  const j = await r.json();
  if(j.ok){
    $('nodeLinks').value = j.editable.nodeLinks || '';
    $('preferredIps').value = j.editable.preferredIps || '';
    $('namePrefix').value = j.editable.namePrefix || '';
    $('keepOriginalHost').checked = j.editable.keepOriginalHost !== false;
  }
  out(j);
}
async function updateSub(){
  const payload = {
    id: $('subId').value.trim(),
    nodeLinks: $('nodeLinks').value,
    preferredIps: $('preferredIps').value,
    namePrefix: $('namePrefix').value,
    keepOriginalHost: $('keepOriginalHost').checked
  };
  const r = await fetch('/api/admin/update' + tokenQS(), {
    method:'POST',
    headers:{'content-type':'application/json'},
    body: JSON.stringify(payload)
  });
  const j = await r.json();
  out(j);
}
async function deleteSub(){
  if(!confirm('确认删除这个订阅？')) return;
  const r = await fetch('/api/admin/delete' + tokenQS(), {
    method:'POST',
    headers:{'content-type':'application/json'},
    body: JSON.stringify({ id: $('subId').value.trim() })
  });
  const j = await r.json();
  out(j);
}
</script>
</body>
</html>`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET,POST,OPTIONS',
          'access-control-allow-headers': 'content-type',
        },
      });
    }

    if (!env.SUB_STORE) {
      return text('Missing KV binding: SUB_STORE', 500);
    }

    if (request.method === 'GET' && url.pathname === '/admin') {
      return html(renderAdminPage());
    }

    if (request.method === 'POST' && url.pathname === '/api/generate') {
      return handleGenerate(request, env, url);
    }

    if (request.method === 'GET' && url.pathname === '/api/admin/list') {
      return handleAdminList(url, env);
    }

    if (request.method === 'GET' && url.pathname === '/api/admin/get') {
      return handleAdminGet(url, env);
    }

    if (request.method === 'POST' && url.pathname === '/api/admin/update') {
      return handleAdminUpdate(request, env, url);
    }

    if (request.method === 'POST' && url.pathname === '/api/admin/delete') {
      return handleAdminDelete(request, env, url);
    }

    if (request.method === 'GET' && url.pathname.startsWith('/sub/')) {
      return handleSub(url, env);
    }

    // Pages deployment has env.ASSETS; direct Workers deployment may not.
    // Keep the original static assets when available, otherwise show /admin on root and 404 for unknown paths.
    if (env.ASSETS && typeof env.ASSETS.fetch === 'function') {
      return env.ASSETS.fetch(request);
    }
    if (request.method === 'GET' && url.pathname === '/') {
      return html(renderAdminPage());
    }
    return text('Not found. Visit /admin for the enhanced management page.', 404);
  },
};
