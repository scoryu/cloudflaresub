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

function cleanBaseNodeName(name = '') {
  const parts = String(name || '').split('|').map((x) => x.trim()).filter(Boolean);
  return parts[0] || String(name || 'node').trim() || 'node';
}

function deriveBaseNodesFromRecord(record) {
  if (record?.input?.nodeLinks) {
    const parsed = parseRawLinks(record.input.nodeLinks);
    if (parsed.length) return parsed;
  }

  const nodes = Array.isArray(record?.nodes) ? record.nodes : [];
  const seen = new Set();
  const bases = [];

  for (const n of nodes) {
    const key = [
      n.type || '',
      n.uuid || n.password || '',
      n.network || '',
      n.tls ? 'tls' : 'notls',
      n.host || '',
      n.sni || '',
      n.path || '',
      n.cipher || '',
      n.flow || '',
    ].join('\u0001');

    if (seen.has(key)) continue;
    seen.add(key);
    bases.push({
      ...n,
      name: cleanBaseNodeName(n.name),
    });
  }

  return bases;
}

function buildPayloadFromBaseNodes(baseNodes, body, existingRecord) {
  const preferredEndpoints = parsePreferredEndpoints(body.preferredIps || '');
  if (!baseNodes.length) throw new Error('没有可用的原始节点。请先填写原始节点链接 nodeLinks');
  if (!preferredEndpoints.length) throw new Error('没有识别到可用优选地址');

  const options = {
    namePrefix: body.namePrefix || existingRecord?.options?.namePrefix || '',
    keepOriginalHost: body.keepOriginalHost !== false,
  };
  const nodes = buildNodes(baseNodes, preferredEndpoints, options);

  return {
    version: 3,
    createdAt: existingRecord?.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    options,
    input: {
      nodeLinks: String(body.nodeLinks || existingRecord?.input?.nodeLinks || ''),
      preferredIps: String(body.preferredIps || ''),
      namePrefix: String(options.namePrefix || ''),
      keepOriginalHost: options.keepOriginalHost,
    },
    nodes,
  };
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

  let existingRecord = null;
  const existingRaw = await env.SUB_STORE.get(`sub:${id}`);
  if (existingRaw) {
    try { existingRecord = JSON.parse(existingRaw); } catch {}
  }

  let payload;
  try {
    if (String(body.nodeLinks || '').trim()) {
      payload = buildPayloadFromInput({ ...body, createdAt: existingRecord?.createdAt });
    } else {
      // 允许旧订阅只改 IP：没有原始节点链接时，从旧 nodes 里反推基础节点。
      const baseNodes = deriveBaseNodesFromRecord(existingRecord);
      payload = buildPayloadFromBaseNodes(baseNodes, body, existingRecord);
    }
  } catch (e) {
    return json({ ok: false, error: e.message }, 400);
  }

  await env.SUB_STORE.put(`sub:${id}`, JSON.stringify(payload), kvPutOptions(env));

  return json({
    ok: true,
    id,
    message: String(body.nodeLinks || '').trim() ? '已用原始节点重新生成订阅' : '已基于旧订阅直接更新优选 IP',
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


function injectAdminEntryIntoHomePage(pageHtml) {
  const adminEntry = `
<style>
  .cfsub-admin-entry{position:fixed;right:22px;bottom:22px;z-index:99999;display:flex;gap:10px;align-items:center;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
  .cfsub-admin-entry a{display:inline-flex;align-items:center;justify-content:center;text-decoration:none;border-radius:999px;padding:11px 15px;font-weight:700;font-size:14px;box-shadow:0 10px 30px rgba(0,0,0,.24);border:1px solid rgba(255,255,255,.18)}
  .cfsub-admin-entry .main{background:#2563eb;color:#fff}
  .cfsub-admin-entry .fallback{background:rgba(15,23,42,.88);color:#e5e7eb}
  @media(max-width:640px){.cfsub-admin-entry{right:14px;bottom:14px;flex-direction:column;align-items:flex-end}.cfsub-admin-entry a{font-size:13px;padding:10px 13px}}
</style>
<div class="cfsub-admin-entry">
  <a class="main" href="/admin" title="进入 CloudflareSub 管理后台">管理后台</a>
  <a class="fallback" href="/api/admin/ui" title="如果 /admin 被静态页拦截，可点这里">备用入口</a>
</div>`;
  if (pageHtml.includes('cfsub-admin-entry')) return pageHtml;
  if (pageHtml.includes('</body>')) return pageHtml.replace('</body>', adminEntry + '\n</body>');
  return pageHtml + adminEntry;
}

async function fetchAssetWithAdminEntry(request, env) {
  const response = await env.ASSETS.fetch(request);
  const url = new URL(request.url);
  const contentType = response.headers.get('content-type') || '';
  const shouldInject = request.method === 'GET' &&
    (url.pathname === '/' || url.pathname === '/index.html') &&
    contentType.toLowerCase().includes('text/html');

  if (!shouldInject) return response;

  const body = await response.text();
  const headers = new Headers(response.headers);
  headers.delete('content-length');
  headers.set('content-type', 'text/html; charset=utf-8');
  headers.set('cache-control', 'no-store');
  return new Response(injectAdminEntryIntoHomePage(body), {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function renderAdminPage() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>CloudflareSub 管理后台</title>
  <style>
    :root{--bg:#f7f7f8;--card:#fff;--text:#111827;--muted:#6b7280;--border:#e5e7eb;--primary:#111827;--blue:#2563eb;--red:#b91c1c;--green:#047857;--yellow:#92400e}
    body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;max-width:1120px;margin:24px auto;padding:0 16px;background:var(--bg);color:var(--text)}
    h1{font-size:28px;margin:0 0 8px}.sub{color:var(--muted);margin:0 0 18px}.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:16px;margin:14px 0;box-shadow:0 1px 2px rgba(0,0,0,.04)}
    label{display:block;margin:10px 0 6px;font-weight:650}input,textarea{width:100%;box-sizing:border-box;border:1px solid #d1d5db;border-radius:9px;padding:10px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;background:#fff}textarea{min-height:116px}button{border:0;border-radius:9px;padding:10px 14px;margin:6px 6px 6px 0;cursor:pointer;background:var(--primary);color:#fff;font-weight:650}button.secondary{background:#374151}button.blue{background:var(--blue)}button.danger{background:var(--red)}button.green{background:var(--green)}button:disabled{opacity:.5;cursor:not-allowed}pre{white-space:pre-wrap;background:#111827;color:#e5e7eb;border-radius:10px;padding:12px;overflow:auto;max-height:360px}.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:820px){.row{grid-template-columns:1fr}}.muted{color:var(--muted);font-size:13px}.ok{color:var(--green);font-weight:700}.bad{color:var(--red);font-weight:700}.pill{display:inline-block;border:1px solid var(--border);border-radius:999px;padding:4px 9px;margin:3px;background:#f9fafb;font-size:12px}table{width:100%;border-collapse:collapse;margin-top:10px}td,th{border-bottom:1px solid var(--border);padding:8px;text-align:left;font-size:13px}code{background:#eef2ff;padding:2px 5px;border-radius:5px}.small{font-size:12px}.status{padding:10px 12px;border-radius:10px;background:#eef2ff;color:#1e3a8a;margin-top:10px}.status.err{background:#fef2f2;color:#991b1b}.status.ok{background:#ecfdf5;color:#065f46}.status.warn{background:#fffbeb;color:#92400e}.toolbar{display:flex;gap:8px;flex-wrap:wrap}.right{float:right}.link{color:#2563eb;cursor:pointer;text-decoration:underline}.banner{background:#eff6ff;border:1px solid #bfdbfe;color:#1e40af;border-radius:12px;padding:10px 12px;margin:12px 0}
  </style>
</head>
<body>
  <h1>CloudflareSub 管理后台</h1>
  <p class="sub">可直接粘贴完整订阅链接，自动提取订阅 ID 和 Token；也可以读取 KV 中已有订阅并一键载入、修改优选 IP、保存回原订阅 ID。</p>
  <div class="banner">推荐入口：<code>/api/admin/ui</code>。如果 <code>/admin</code> 被静态页面拦截，仍可使用备用入口。</div>

  <div class="card">
    <label>① 粘贴完整订阅链接，一键提取</label>
    <input id="subUrl" placeholder="例如：https://你的域名/sub/BSEMXUeWJK?target=raw&token=xxxx" />
    <div class="toolbar">
      <button class="blue" id="btnExtract">从订阅链接提取 ID 和 Token</button>
      <button class="secondary" id="btnTestSub">测试这个订阅是否可访问</button>
      <button class="secondary" id="btnOpenApiUi">打开备用入口</button>
    </div>
    <div id="status" class="status">等待操作。</div>
  </div>

  <div class="card">
    <label>② 管理 Token（SUB_ACCESS_TOKEN）</label>
    <input id="token" placeholder="输入 SUB_ACCESS_TOKEN；也可以从上面的订阅链接自动提取" />
    <div class="toolbar">
      <button id="btnSaveToken">保存 Token</button>
      <button class="secondary" id="btnListSubs">列出已有订阅</button>
    </div>
    <p class="muted">“保存 Token”只是保存到当前浏览器 localStorage，不会修改 Cloudflare 变量。</p>
    <div id="subList"></div>
  </div>

  <div class="card">
    <div class="row">
      <div>
        <label>③ 订阅 ID</label>
        <input id="subId" placeholder="例如 auto / mycf / BSEMXUeWJK" />
      </div>
      <div>
        <label>名称前缀 namePrefix</label>
        <input id="namePrefix" value="CF" />
      </div>
    </div>

    <label><input type="checkbox" id="keepOriginalHost" checked style="width:auto"> 保留原始 Host/SNI（建议开启）</label>

    <label>原始节点链接 nodeLinks</label>
    <textarea id="nodeLinks" placeholder="粘贴 vless:// / vmess:// / trojan:// 原始节点。旧订阅若没有保存原始节点，这里可以为空，系统会尝试从旧订阅 nodes 反推基础节点。"></textarea>

    <label>优选 IP preferredIps</label>
    <textarea id="preferredIps" placeholder="104.16.1.2:443#CF-01\n104.17.2.3:443#CF-02"></textarea>

    <div class="toolbar">
      <button id="btnLoadSub">读取订阅</button>
      <button class="green" id="btnUpdateSub">保存/更新这个 ID</button>
      <button class="danger" id="btnDeleteSub">删除这个 ID</button>
    </div>
  </div>

  <div class="card">
    <h3>结果</h3>
    <pre id="result">等待操作...</pre>
  </div>

<script>
(function(){
'use strict';
var $ = function(id){ return document.getElementById(id); };
var safeJson = function(x){ try { return JSON.stringify(x, null, 2); } catch(e) { return String(x); } };
var out = function(x){ $('result').textContent = typeof x === 'string' ? x : safeJson(x); };
var setStatus = function(msg, type){ var el = $('status'); el.textContent = msg; el.className = 'status ' + (type || ''); };
var origin = function(){ return location.origin; };
var getToken = function(){ return ($('token').value || '').trim(); };
var tokenQS = function(){ return '?token=' + encodeURIComponent(getToken()); };
var rawUrl = function(id){ return origin() + '/sub/' + encodeURIComponent(id) + '?target=raw&token=' + encodeURIComponent(getToken()); };
var escapeHtml = function(s){ return String(s || '').replace(/[&<>\"]/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]; }); };

function requireToken(){
  if(!getToken()){
    setStatus('请先填写 Token，或从完整订阅链接中自动提取。', 'err');
    return false;
  }
  return true;
}

function saveToken(){
  var t = getToken();
  if(!t){ setStatus('Token 为空。请先填 SUB_ACCESS_TOKEN，或从订阅链接提取。','err'); return; }
  localStorage.setItem('sub_token', t);
  setStatus('Token 已保存到当前浏览器。现在可以点击“列出已有订阅”。','ok');
  out({ok:true,message:'Token 已保存到浏览器 localStorage。'});
}

function extractFromUrl(){
  var v = ($('subUrl').value || '').trim();
  if(!v){ setStatus('请先粘贴完整订阅链接。','err'); return; }
  var u;
  try { u = new URL(v, location.origin); } catch(e) { setStatus('订阅链接格式不正确。','err'); out(String(e)); return; }
  var parts = u.pathname.split('/').filter(Boolean);
  var subIndex = parts.indexOf('sub');
  var id = subIndex >= 0 ? parts[subIndex + 1] : '';
  var token = u.searchParams.get('token') || '';
  if(!id){ setStatus('没有从链接里识别到 /sub/订阅ID。','err'); return; }
  $('subId').value = id;
  if(token){ $('token').value = token; localStorage.setItem('sub_token', token); }
  setStatus('已提取：订阅 ID = ' + id + (token ? '，Token 已填入并保存。' : '。但链接里没有 token。'), 'ok');
  out({ok:true,id:id,token: token ? '已提取' : '未找到'});
}

async function testCurrentSub(){
  if(!$('subId').value.trim()) extractFromUrl();
  var id = $('subId').value.trim();
  if(!id || !requireToken()) return;
  try{
    var r = await fetch(rawUrl(id));
    var txt = await r.text();
    setStatus(r.ok ? '订阅可访问。HTTP ' + r.status : '订阅不可访问。HTTP ' + r.status, r.ok ? 'ok' : 'err');
    out(txt.slice(0, 1000));
  }catch(e){ setStatus('测试失败：' + e.message, 'err'); out(String(e)); }
}

function renderList(items){
  if(!items || !items.length){ $('subList').innerHTML = '<p class="muted">没有找到订阅。</p>'; return; }
  var html = '<table><thead><tr><th>订阅 ID</th><th>过期时间</th><th>操作</th></tr></thead><tbody>';
  items.forEach(function(it){
    var id = it.id;
    var exp = it.expiration ? new Date(it.expiration * 1000).toLocaleString() : '无/未知';
    html += '<tr>' +
      '<td><code>' + escapeHtml(id) + '</code></td>' +
      '<td class="small">' + escapeHtml(exp) + '</td>' +
      '<td>' +
        '<button class="secondary" type="button" data-action="load" data-id="' + escapeHtml(id) + '">载入</button>' +
        '<button type="button" data-action="copy" data-url="' + escapeHtml(rawUrl(id)) + '">复制 raw 链接</button>' +
      '</td>' +
    '</tr>';
  });
  html += '</tbody></table>';
  $('subList').innerHTML = html;
}

async function listSubs(){
  if(!requireToken()) return;
  try{
    var r = await fetch('/api/admin/list' + tokenQS());
    var j = await r.json();
    out(j);
    if(j.ok){ setStatus('已列出 ' + j.count + ' 条订阅。点击“载入”即可编辑。','ok'); renderList(j.items || []); }
    else { setStatus('列出失败：' + (j.error || '未知错误'), 'err'); }
  }catch(e){ setStatus('列出失败：' + e.message, 'err'); out(String(e)); }
}

async function loadSub(idOverride){
  if(!requireToken()) return;
  var id = (idOverride || $('subId').value || '').trim();
  if(!id){ setStatus('请先填写订阅 ID，或粘贴订阅链接提取。','err'); return; }
  $('subId').value = id;
  try{
    var r = await fetch('/api/admin/get' + tokenQS() + '&id=' + encodeURIComponent(id));
    var j = await r.json();
    if(j.ok){
      $('nodeLinks').value = (j.editable && j.editable.nodeLinks) || '';
      $('preferredIps').value = (j.editable && j.editable.preferredIps) || '';
      $('namePrefix').value = (j.editable && j.editable.namePrefix) || 'CF';
      $('keepOriginalHost').checked = !j.editable || j.editable.keepOriginalHost !== false;
      setStatus(j.editable && j.editable.hasOriginalInput ? '读取成功。可直接修改 IP 后保存。' : '读取成功。旧订阅没有保存原始节点，但新版支持直接修改 IP 后保存。', 'ok');
    } else { setStatus('读取失败：' + (j.error || '未知错误'), 'err'); }
    out(j);
  }catch(e){ setStatus('读取失败：' + e.message, 'err'); out(String(e)); }
}

async function updateSub(){
  if(!requireToken()) return;
  var payload = {
    id: $('subId').value.trim(),
    nodeLinks: $('nodeLinks').value || '',
    preferredIps: $('preferredIps').value || '',
    namePrefix: $('namePrefix').value || '',
    keepOriginalHost: $('keepOriginalHost').checked
  };
  if(!payload.id){ setStatus('订阅 ID 不能为空。','err'); return; }
  if(!payload.preferredIps.trim()){ setStatus('优选 IP 不能为空。','err'); return; }
  try{
    var r = await fetch('/api/admin/update' + tokenQS(), { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload) });
    var j = await r.json();
    if(j.ok){ setStatus('保存成功。旧订阅链接不变，客户端更新订阅即可。', 'ok'); }
    else { setStatus('保存失败：' + (j.error || '未知错误'), 'err'); }
    out(j);
  }catch(e){ setStatus('保存失败：' + e.message, 'err'); out(String(e)); }
}

async function deleteSub(){
  if(!requireToken()) return;
  var id = $('subId').value.trim();
  if(!id){ setStatus('请先填写订阅 ID。','err'); return; }
  if(!confirm('确认删除这个订阅？')) return;
  try{
    var r = await fetch('/api/admin/delete' + tokenQS(), { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ id: id }) });
    var j = await r.json();
    if(j.ok){ setStatus('已删除订阅：' + j.deleted, 'ok'); listSubs(); }
    else { setStatus('删除失败：' + (j.error || '未知错误'), 'err'); }
    out(j);
  }catch(e){ setStatus('删除失败：' + e.message, 'err'); out(String(e)); }
}

function openApiUi(){ location.href = '/api/admin/ui'; }
async function copyText(t){ try{ await navigator.clipboard.writeText(t); setStatus('已复制：' + t, 'ok'); }catch(e){ setStatus('复制失败，请手动复制。', 'err'); out(t); } }

window.addEventListener('DOMContentLoaded', function(){
  $('token').value = localStorage.getItem('sub_token') || '';
  $('btnExtract').addEventListener('click', extractFromUrl);
  $('btnTestSub').addEventListener('click', testCurrentSub);
  $('btnOpenApiUi').addEventListener('click', openApiUi);
  $('btnSaveToken').addEventListener('click', saveToken);
  $('btnListSubs').addEventListener('click', listSubs);
  $('btnLoadSub').addEventListener('click', function(){ loadSub(); });
  $('btnUpdateSub').addEventListener('click', updateSub);
  $('btnDeleteSub').addEventListener('click', deleteSub);
  $('subList').addEventListener('click', function(ev){
    var btn = ev.target.closest('button[data-action]');
    if(!btn) return;
    var action = btn.getAttribute('data-action');
    if(action === 'load') loadSub(btn.getAttribute('data-id'));
    if(action === 'copy') copyText(btn.getAttribute('data-url'));
  });
  setStatus('后台脚本已加载。可以粘贴订阅链接，或输入 Token 后列出已有订阅。','ok');
});
})();
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

    // Management UI. /api/admin/ui is deliberately placed under /api because
    // some Workers + Assets deployments serve the old SPA for /admin before the script runs.
    // /api/admin/ui is stable in that deployment mode because /api routes enter the Worker.
    if (request.method === 'GET' && (url.pathname === '/admin' || url.pathname === '/api/admin' || url.pathname === '/api/admin/ui')) {
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
      return fetchAssetWithAdminEntry(request, env);
    }
    if (request.method === 'GET' && url.pathname === '/') {
      return html(renderAdminPage());
    }
    return text('Not found. Visit /api/admin/ui for the enhanced management page.', 404);
  },
};
