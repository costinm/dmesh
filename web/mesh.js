// ============================================================================
// Shared utility functions for the mesh web UI
// ============================================================================

const MESH_INIT_PROXY = new URL('../../proxy/jsonl/mesh-init', window.location.href).toString();

async function meshCall(method, params = {}) {
    const response = await fetch(MESH_INIT_PROXY, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            method,
            ...params,
        }),
    });
    const data = await response.json();
    if (!response.ok || data.error) {
        throw new Error(data.error || `Request failed: ${response.status}`);
    }
    return data;
}

// Format bytes to human-readable memory size
function formatMemory(bytes) {
    if (bytes === 0) return '0 B';
    const isNegative = bytes < 0;
    const absBytes = Math.abs(bytes);
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(absBytes) / Math.log(k));
    return (isNegative ? '-' : '') + parseFloat((absBytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Format number with locale-specific thousand separators
function formatCount(num) {
    return (num || 0).toLocaleString();
}

// Format memory.high values which can be "max" or very large numbers
function formatMemoryOrMax(val) {
    if (val === 'max' || !val) return 'max';
    const num = parseInt(val);
    if (isNaN(num)) return val;
    // If it's a huge number (e.g. 2^63-1), it's essentially max
    if (num > 1e15) return 'max';
    return formatMemory(num);
}

// Setup refresh timer and pause/play functionality
function setupRefreshTimer(options) {
    const {
        statusBar,
        pausedLabel,
        refreshTimerEl,
        refreshInterval = 5,
        onRefresh
    } = options;

    let timeLeft = refreshInterval;
    let isPaused = true;

    statusBar.addEventListener('click', () => {
        isPaused = !isPaused;
        statusBar.classList.toggle('paused', isPaused);
        pausedLabel.style.display = isPaused ? 'inline' : 'none';
    });

    setInterval(() => {
        if (isPaused) return;
        timeLeft--;
        if (timeLeft <= 0) {
            onRefresh();
            timeLeft = refreshInterval;
        }
        refreshTimerEl.textContent = timeLeft + 's';
    }, 1000);

    return { isPaused: () => isPaused };
}

// Setup keyboard shortcut for refresh
function setupRefreshShortcut(callback) {
    document.addEventListener('keydown', (event) => {
        // Trigger on 'R' or 'r' if not typing in an input field
        if ((event.key === 'r' || event.key === 'R') &&
            event.target.tagName !== 'INPUT' &&
            event.target.tagName !== 'TEXTAREA') {
            callback();
        }
    });
}

// Close dropdowns when clicking outside
function setupDropdownClose() {
    window.onclick = function (event) {
        if (!event.target.matches('.action-btn')) {
            document.querySelectorAll('.dropdown-content').forEach(d => d.style.display = 'none');
        }
    }
}

// Toggle dropdown menu
function toggleDropdown(event, btn) {
    event.stopPropagation();
    const content = btn.nextElementSibling;
    const isOpen = content.style.display === 'block';

    // Close all other dropdowns
    document.querySelectorAll('.dropdown-content').forEach(d => d.style.display = 'none');

    content.style.display = isOpen ? 'none' : 'block';
}
