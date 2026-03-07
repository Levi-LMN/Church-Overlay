// User Panel JavaScript
let currentState = {};
let authCheckInterval;
let lastOverlay = null;

function showAlert(message, type = 'success') {
    const alert = document.createElement('div');
    const colors = {
        success: 'bg-green-100 text-green-800 border-green-500',
        error: 'bg-red-100 text-red-800 border-red-500',
        warning: 'bg-yellow-100 text-yellow-800 border-yellow-500'
    };
    alert.className = `fixed top-5 right-5 z-[9999] min-w-[280px] max-w-[90vw] md:min-w-[300px] md:max-w-[400px] px-4 md:px-5 py-3 rounded-lg shadow-xl border-2 text-xs md:text-sm font-medium ${colors[type] || colors.success}`;
    alert.style.animation = 'slideInRight 0.3s ease-out';
    alert.textContent = message;
    document.body.appendChild(alert);
    setTimeout(() => {
        alert.style.animation = 'slideOutRight 0.3s ease-out';
        setTimeout(() => alert.remove(), 300);
    }, 3000);
}

async function checkAuthStatus() {
    try {
        const res = await fetch('/api/auth/check');
        const data = await res.json();
        if (data.auth_required && !data.authenticated) {
            clearInterval(authCheckInterval);
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Error checking auth:', error);
    }
}

function updatePreview(state) {
    const previewMobile = document.getElementById('preview');
    const previewDesktop = document.getElementById('preview-desktop');
    const toggleBtnMobile = document.getElementById('toggle-overlay-btn-mobile');
    const toggleBtnDesktop = document.getElementById('toggle-overlay-btn-desktop');

    if (state.mode !== 'hidden') lastOverlay = state;

    let previewHTML = '';
    let btnClass = '';
    let btnText = '';
    let btnAction = null;
    let btnDisabled = false;

    if (state.mode === 'hidden') {
        previewHTML = `
            <div class="flex items-start justify-between gap-3">
                <div class="flex-1 min-w-0">
                    <div class="text-xs uppercase tracking-wider opacity-80 mb-1 font-semibold">Current Overlay</div>
                    <div class="text-lg md:text-xl font-bold mb-1 leading-tight truncate">Hidden</div>
                    <div class="text-xs md:text-sm opacity-90 truncate">No overlay displayed</div>
                </div>
                <div class="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-bold tracking-wider bg-gray-500 flex-shrink-0">HIDDEN</div>
            </div>
        `;
        if (lastOverlay) {
            btnClass = 'bg-blue-600 hover:bg-blue-700';
            btnText = '👁️ Show Last Overlay';
            btnAction = showLastOverlay;
            btnDisabled = false;
        } else {
            btnClass = 'bg-gray-400 opacity-50 cursor-not-allowed';
            btnText = '👁️ No Overlay Yet';
            btnAction = null;
            btnDisabled = true;
        }
    } else if (state.mode === 'minister' && state.minister) {
        previewHTML = `
            <div class="flex items-start justify-between gap-3">
                <div class="flex-1 min-w-0">
                    <div class="text-xs uppercase tracking-wider opacity-80 mb-1 font-semibold">Minister Display</div>
                    <div class="text-lg md:text-xl font-bold mb-1 leading-tight truncate">${state.minister.name}</div>
                    <div class="text-xs md:text-sm opacity-90 truncate">${state.minister.title || 'No title'}</div>
                </div>
                <div class="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-bold tracking-wider bg-green-600 animate-pulse-slow flex-shrink-0">
                    <span class="w-2 h-2 rounded-full bg-white animate-blink"></span>
                    LIVE
                </div>
            </div>
        `;
        btnClass = 'bg-red-600 hover:bg-red-700';
        btnText = '⭕ Hide Overlay';
        btnAction = hideOverlay;
        btnDisabled = false;
    } else if (state.mode === 'sermon' && state.sermon) {
        previewHTML = `
            <div class="flex items-start justify-between gap-3">
                <div class="flex-1 min-w-0">
                    <div class="text-xs uppercase tracking-wider opacity-80 mb-1 font-semibold">Sermon Display</div>
                    <div class="text-lg md:text-xl font-bold mb-1 leading-tight truncate">${state.sermon.title}</div>
                    <div class="text-xs md:text-sm opacity-90 truncate">${state.sermon.minister_name || 'No minister'} ${state.sermon.bible_verse ? '• ' + state.sermon.bible_verse : ''}</div>
                </div>
                <div class="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-bold tracking-wider bg-green-600 animate-pulse-slow flex-shrink-0">
                    <span class="w-2 h-2 rounded-full bg-white animate-blink"></span>
                    LIVE
                </div>
            </div>
        `;
        btnClass = 'bg-red-600 hover:bg-red-700';
        btnText = '⭕ Hide Overlay';
        btnAction = hideOverlay;
        btnDisabled = false;
    }

    previewMobile.innerHTML = previewHTML;
    if (previewDesktop) {
        const desktopHTML = previewHTML.replace('items-start', 'items-center')
                                      .replace('flex-shrink-0', '')
                                      .replace('px-3 py-1.5', 'px-4 py-2')
                                      .replace(/text-xs md:text-sm/g, 'text-sm')
                                      .replace(/text-lg md:text-xl/g, 'text-xl');
        previewDesktop.innerHTML = `
            <div class="flex items-center justify-between gap-4 flex-wrap">
                ${desktopHTML}
            </div>
        `;
    }

    toggleBtnMobile.className = `w-full px-4 py-3.5 ${btnClass} text-white rounded-lg text-base font-bold shadow-md transition active:scale-98 flex items-center justify-center gap-2 min-h-[48px]`;
    toggleBtnMobile.innerHTML = btnText;
    toggleBtnMobile.onclick = btnAction;
    toggleBtnMobile.disabled = btnDisabled;

    if (toggleBtnDesktop) {
        toggleBtnDesktop.className = `w-full px-4 py-3.5 ${btnClass} text-white rounded-lg text-sm font-bold shadow-md transition active:scale-98 flex items-center justify-center gap-2`;
        toggleBtnDesktop.innerHTML = btnText;
        toggleBtnDesktop.onclick = btnAction;
        toggleBtnDesktop.disabled = btnDisabled;
    }
}

function switchTab(tabName) {
    document.querySelectorAll('.tab').forEach(t => {
        t.classList.remove('active', 'border-blue-600', 'bg-white', 'text-blue-600', 'shadow-sm');
        const icon = t.querySelector('span:first-child');
        if (icon) icon.style.transform = 'scale(1)';
    });
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

    const targetTab = Array.from(document.querySelectorAll('.tab')).find(tab => {
        return tab.getAttribute('onclick').includes(`'${tabName}'`);
    });

    if (targetTab) {
        targetTab.classList.add('active', 'border-blue-600', 'bg-white', 'text-blue-600', 'shadow-sm');
        const icon = targetTab.querySelector('span:first-child');
        if (icon) icon.style.transform = 'scale(1.1)';
    }

    document.getElementById(tabName + '-tab').classList.add('active');
}

function loadMinisterToCustom() {
    const select = document.getElementById('minister-select');
    const option = select.options[select.selectedIndex];
    if (!select.value) {
        showAlert('⚠️ Please select a minister first', 'error');
        return;
    }
    document.getElementById('custom-minister-name').value = option.dataset.name;
    document.getElementById('custom-minister-title').value = option.dataset.title;
    switchTab('custom');

    setTimeout(() => {
        const ministerSection = document.getElementById('custom-minister-name').closest('.border-dashed');
        ministerSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
        ministerSection.classList.add('ring-4', 'ring-blue-400');
        setTimeout(() => ministerSection.classList.remove('ring-4', 'ring-blue-400'), 2000);
    }, 100);

    showAlert('✅ Loaded minister to custom section!');
}

function loadSermonToCustom() {
    const select = document.getElementById('sermon-select');
    const option = select.options[select.selectedIndex];
    if (!select.value) {
        showAlert('⚠️ Please select a sermon first', 'error');
        return;
    }
    document.getElementById('custom-sermon-title').value = option.dataset.title;
    document.getElementById('custom-sermon-minister').value = option.dataset.minister;
    document.getElementById('custom-sermon-verse').value = option.dataset.verse;
    switchTab('custom');

    setTimeout(() => {
        const sermonSection = document.getElementById('custom-sermon-title').closest('.border-dashed');
        sermonSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
        sermonSection.classList.add('ring-4', 'ring-blue-400');
        setTimeout(() => sermonSection.classList.remove('ring-4', 'ring-blue-400'), 2000);
    }, 100);

    showAlert('✅ Loaded sermon to custom section!');
}

async function goLiveMinister() {
    const select = document.getElementById('minister-select');
    if (!select.value) {
        showAlert('⚠️ Please select a minister', 'error');
        return;
    }
    const res = await fetch('/api/overlay/update', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            mode: 'minister',
            minister_id: parseInt(select.value)
        })
    });
    if (res.ok) {
        const result = await res.json();
        currentState = result.state;
        updatePreview(currentState);
        showAlert('✅ Minister is now live!');
    } else {
        showAlert('❌ Failed to go live', 'error');
    }
}

async function goLiveTempMinister(id) {
    const res = await fetch('/api/overlay/update', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            mode: 'minister',
            temp_minister_id: id
        })
    });
    if (res.ok) {
        const result = await res.json();
        currentState = result.state;
        updatePreview(currentState);
        showAlert('✅ Saved minister is now live!');
    } else {
        showAlert('❌ Failed to go live', 'error');
    }
}

async function goLiveSermon() {
    const select = document.getElementById('sermon-select');
    if (!select.value) {
        showAlert('⚠️ Please select a sermon', 'error');
        return;
    }
    const res = await fetch('/api/overlay/update', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            mode: 'sermon',
            sermon_id: parseInt(select.value)
        })
    });
    if (res.ok) {
        const result = await res.json();
        currentState = result.state;
        updatePreview(currentState);
        showAlert('✅ Sermon is now live!');
    } else {
        showAlert('❌ Failed to go live', 'error');
    }
}

async function goLiveTempSermon(id) {
    const res = await fetch('/api/overlay/update', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            mode: 'sermon',
            temp_sermon_id: id
        })
    });
    if (res.ok) {
        const result = await res.json();
        currentState = result.state;
        updatePreview(currentState);
        showAlert('✅ Saved sermon is now live!');
    } else {
        showAlert('❌ Failed to go live', 'error');
    }
}

async function showCustomMinister() {
    const name = document.getElementById('custom-minister-name').value.trim();
    if (!name) {
        showAlert('⚠️ Please enter a minister name', 'error');
        return;
    }
    const res = await fetch('/api/overlay/update', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            mode: 'minister',
            minister_name: name,
            minister_title: document.getElementById('custom-minister-title').value.trim()
        })
    });
    if (res.ok) {
        const result = await res.json();
        currentState = result.state;
        updatePreview(currentState);
        showAlert('✅ Custom minister is now live and saved!');
        setTimeout(() => location.reload(), 1500);
    }
}

async function showCustomSermon() {
    const title = document.getElementById('custom-sermon-title').value.trim();
    if (!title) {
        showAlert('⚠️ Please enter a sermon title', 'error');
        return;
    }
    const res = await fetch('/api/overlay/update', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            mode: 'sermon',
            sermon_title: title,
            minister_name: document.getElementById('custom-sermon-minister').value.trim(),
            bible_verse: document.getElementById('custom-sermon-verse').value.trim()
        })
    });
    if (res.ok) {
        const result = await res.json();
        currentState = result.state;
        updatePreview(currentState);
        showAlert('✅ Custom sermon is now live and saved!');
        setTimeout(() => location.reload(), 1500);
    }
}

async function deleteTempContent(id) {
    if (!confirm('Delete this saved item?')) return;

    const res = await fetch(`/api/temporary-content/${id}`, { method: 'DELETE' });
    if (res.ok) {
        showAlert('✅ Item deleted');
        setTimeout(() => location.reload(), 1000);
    } else {
        showAlert('❌ Failed to delete', 'error');
    }
}

async function hideOverlay() {
    const res = await fetch('/api/overlay/update', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({mode: 'hidden'})
    });
    if (res.ok) {
        const data = await res.json();
        currentState = data.state;
        updatePreview(currentState);
        showAlert('✅ Overlay hidden');
    }
}

async function showLastOverlay() {
    if (!lastOverlay) {
        showAlert('⚠️ No previous overlay to show', 'error');
        return;
    }

    const res = await fetch('/api/overlay/update', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(lastOverlay)
    });

    if (res.ok) {
        const result = await res.json();
        currentState = result.state;
        updatePreview(currentState);
        showAlert('✅ Overlay restored!');
    } else {
        showAlert('❌ Failed to restore overlay', 'error');
    }
}

function toggleOverlay() {
    if (currentState.mode === 'hidden') {
        showLastOverlay();
    } else {
        hideOverlay();
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    // Get initial state from template
    const stateElement = document.getElementById('initial-state');
    if (stateElement) {
        try {
            currentState = JSON.parse(stateElement.textContent);
        } catch (e) {
            console.error('Error parsing initial state:', e);
            currentState = { mode: 'hidden' };
        }
    }

    updatePreview(currentState);
    switchTab('ministers');

    // Start auth check interval
    authCheckInterval = setInterval(checkAuthStatus, 5000);
});