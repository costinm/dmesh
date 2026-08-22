const MCP_URL = new URL('../../proxy/mcp/lmesh?tools=mesh/radio-tools.json', window.location.href).toString();

const state = {
    tools: [],
    nextId: 1,
};

const toolsEl = document.getElementById('tools');
const resultEl = document.getElementById('result');
const notificationsEl = document.getElementById('notifications');
const statusEl = document.getElementById('status');
const neighborsEl = document.getElementById('neighbors');
const neighborHoursEl = document.getElementById('neighbor-hours');

document.getElementById('refresh').addEventListener('click', loadTools);
document.getElementById('ping-all').addEventListener('click', pingAllMedia);
neighborHoursEl.addEventListener('change', loadNeighbors);
document.getElementById('history').addEventListener('click', () => callTool({
    name: 'messages.history',
    inputSchema: {
        properties: {
            keys: { default: 'messages,net,wifi,BLE,N' },
            limit: { default: 40 },
        },
    },
}, { keys: 'messages,net,wifi,BLE,N', limit: 40 }));

function setStatus(text, cls = '') {
    statusEl.textContent = text;
    statusEl.className = `status ${cls}`.trim();
}

async function mcp(method, params = {}) {
    const response = await fetch(MCP_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            jsonrpc: '2.0',
            id: state.nextId++,
            method,
            params,
        }),
    });
    const data = await response.json();
    if (!response.ok || data.error) {
        throw new Error(data.error?.message || data.error || `HTTP ${response.status}`);
    }
    return data.result === undefined ? data : data.result;
}

async function loadTools() {
    setStatus('Loading command registry');
    toolsEl.textContent = '';
    try {
        const result = await mcp('tools/list');
        state.tools = Array.isArray(result.tools) ? result.tools : [];
        renderTools(state.tools);
        await loadNeighbors();
        setStatus(`${state.tools.length} commands loaded`, 'ok');
    } catch (error) {
        setStatus(`Registry error: ${error.message}`, 'warn');
        resultEl.textContent = error.stack || String(error);
    }
}

async function pingAllMedia() {
    const tool = state.tools.find(tool => tool.name === 'discovery.ping') || {
        name: 'discovery.ping',
        inputSchema: { properties: { medium: { default: 'all' } } },
    };
    await callTool(tool, { medium: 'all' });
    await loadNeighbors();
}

async function loadNeighbors() {
    const hours = Math.max(1, parseInt(neighborHoursEl.value || '6', 10));
    neighborHoursEl.value = hours;
    try {
        const result = await mcp('tools/call', {
            name: 'neighbors',
            arguments: { seen_within_sec: hours * 3600 },
        });
        const data = result.structuredContent || result.content?.[0]?.json || result;
        renderNeighbors(Array.isArray(data.neighbors) ? data.neighbors : []);
    } catch (error) {
        neighborsEl.innerHTML = '';
        const empty = document.createElement('div');
        empty.className = 'empty';
        empty.textContent = `Neighbor query failed: ${error.message}`;
        neighborsEl.appendChild(empty);
    }
}

function renderNeighbors(neighbors) {
    neighborsEl.innerHTML = '';
    if (!neighbors.length) {
        const empty = document.createElement('div');
        empty.className = 'empty';
        empty.textContent = 'No neighbors in the selected window.';
        neighborsEl.appendChild(empty);
        return;
    }
    const table = document.createElement('table');
    const head = document.createElement('thead');
    const headRow = document.createElement('tr');
    for (const label of ['Node', 'Last seen', 'Medium', 'Network', 'Radio', 'RSSI/SNR', 'Source', 'Last event']) {
        const th = document.createElement('th');
        th.textContent = label;
        headRow.appendChild(th);
    }
    head.appendChild(headRow);
    table.appendChild(head);
    const body = document.createElement('tbody');
    for (const neighbor of neighbors) {
        const row = document.createElement('tr');
        const values = [
            neighbor.node,
            formatAge(neighbor.last_seen_ms),
            neighbor.medium || '',
            neighbor.network || '',
            neighbor.radio_id || '',
            [neighbor.rssi, neighbor.snr].filter(value => value !== undefined && value !== null).join(' / '),
            neighbor.source || '',
            neighbor.last_event || '',
        ];
        for (const value of values) {
            const td = document.createElement('td');
            td.textContent = value;
            td.title = value;
            row.appendChild(td);
        }
        body.appendChild(row);
    }
    table.appendChild(body);
    neighborsEl.appendChild(table);
}

function formatAge(timestampMs) {
    const ageSec = Math.max(0, Math.floor((Date.now() - Number(timestampMs || 0)) / 1000));
    if (ageSec < 60) return `${ageSec}s ago`;
    const ageMin = Math.floor(ageSec / 60);
    if (ageMin < 60) return `${ageMin}m ago`;
    const ageHours = Math.floor(ageMin / 60);
    return `${ageHours}h ago`;
}

function renderTools(tools) {
    const grouped = new Map();
    for (const tool of tools) {
        const group = tool.group || groupFromName(tool.name);
        if (!grouped.has(group)) grouped.set(group, []);
        grouped.get(group).push(tool);
    }
    toolsEl.textContent = '';
    for (const [group, groupTools] of grouped.entries()) {
        const section = document.createElement('div');
        section.className = 'group';
        const heading = document.createElement('h2');
        heading.textContent = group;
        section.appendChild(heading);
        for (const tool of groupTools) {
            section.appendChild(renderTool(tool));
        }
        toolsEl.appendChild(section);
    }
}

function renderTool(tool) {
    const card = document.createElement('div');
    card.className = 'tool';

    const title = document.createElement('div');
    title.className = 'tool-title';
    const name = document.createElement('strong');
    name.textContent = tool.title || tool.name;
    const run = document.createElement('button');
    run.type = 'button';
    run.className = 'primary';
    run.textContent = 'Run';
    title.append(name, run);
    card.appendChild(title);

    if (tool.description) {
        const description = document.createElement('p');
        description.textContent = tool.description;
        card.appendChild(description);
    }

    const form = document.createElement('form');
    const toolResult = document.createElement('pre');
    toolResult.className = 'tool-result';
    form.addEventListener('submit', event => {
        event.preventDefault();
        callTool(tool, readForm(form, tool), toolResult);
    });
    renderFields(form, tool);
    card.appendChild(form);
    card.appendChild(toolResult);
    run.addEventListener('click', () => callTool(tool, readForm(form, tool), toolResult));
    return card;
}

function renderFields(form, tool) {
    const schema = tool.inputSchema || {};
    const properties = schema.properties || {};
    for (const [key, spec] of Object.entries(properties)) {
        const type = Array.isArray(spec.type) ? spec.type.find(t => t !== 'null') : spec.type;
        const label = document.createElement('label');
        label.dataset.key = key;
        label.dataset.type = type || 'string';
        if (type === 'boolean') {
            label.className = 'check';
            const input = document.createElement('input');
            input.type = 'checkbox';
            input.name = key;
            input.checked = Boolean(spec.default);
            label.append(input, document.createTextNode(spec.title || key));
        } else {
            label.textContent = spec.title || key;
            const input = spec.enum ? document.createElement('select') : document.createElement('input');
            input.name = key;
            if (spec.enum) {
                for (const optionValue of spec.enum) {
                    const option = document.createElement('option');
                    option.value = optionValue;
                    option.textContent = optionValue;
                    input.appendChild(option);
                }
            } else {
                input.type = type === 'integer' || type === 'number' ? 'number' : 'text';
            }
            if (spec.default !== undefined) input.value = spec.default;
            label.appendChild(input);
        }
        form.appendChild(label);
    }
}

function readForm(form, tool) {
    const args = {};
    const schema = tool.inputSchema || {};
    const required = new Set(schema.required || []);
    for (const label of form.querySelectorAll('label[data-key]')) {
        const key = label.dataset.key;
        const type = label.dataset.type;
        const input = label.querySelector('input, select');
        if (!input) continue;
        if (type === 'boolean') {
            args[key] = input.checked;
            continue;
        }
        if (!input.value && !required.has(key)) continue;
        if (type === 'integer') {
            args[key] = parseInt(input.value, 10);
        } else if (type === 'number') {
            args[key] = parseFloat(input.value);
        } else {
            args[key] = input.value;
        }
    }
    return args;
}

async function callTool(tool, args, localResultEl = resultEl) {
    const running = `Running ${tool.name}...\n${JSON.stringify(args, null, 2)}`;
    resultEl.textContent = running;
    localResultEl.textContent = running;
    try {
        const result = await mcp('tools/call', { name: tool.name, arguments: args });
        const text = JSON.stringify(result, null, 2);
        resultEl.textContent = text;
        localResultEl.textContent = text;
        appendNotification(`${new Date().toISOString()} ${tool.name}\n${text}`);
        if (result.isError) {
            setStatus(`${tool.name} returned an error`, 'warn');
        } else {
            setStatus(`${tool.name} complete`, 'ok');
        }
    } catch (error) {
        const text = error.stack || String(error);
        resultEl.textContent = text;
        localResultEl.textContent = text;
        appendNotification(`${new Date().toISOString()} ${tool.name} failed: ${error.message}`);
        setStatus(`${tool.name} failed`, 'warn');
    }
}

function appendNotification(text) {
    notificationsEl.textContent = `${text}\n\n${notificationsEl.textContent}`.slice(0, 12000);
}

function groupFromName(name) {
    const prefix = String(name || '').split('.')[0];
    if (!prefix) return 'Other';
    return prefix.toUpperCase();
}

loadTools();
