// background.js
// Service worker for AutoShield Chrome Extension
// Handles side panel opening and message routing between content script and side panel

chrome.runtime.onInstalled.addListener(async () => {
  console.log('[AutoShield] Extension installed / updated');

  try {
    await chrome.sidePanel.setPanelBehavior({
      openPanelOnActionClick: true
    });
    console.log('[AutoShield] Side panel behavior set');
  } catch (e) {
    console.error('[AutoShield] Failed to set panel behavior:', e);
  }
});

// Open side panel when the toolbar icon is clicked
chrome.action.onClicked.addListener(async (tab) => {
  try {
    await chrome.sidePanel.open({ tabId: tab.id });
  } catch (e) {
    console.warn('[AutoShield] Side panel open failed:', e);
  }
});

// Enable side panel for all URLs
chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});

// ─── Message Router ─────────────────────────────────────────────────────────
// Routes messages from content script → side panel and vice versa

let sidePanelPort = null;

chrome.runtime.onConnect.addListener((port) => {
  if (port.name === 'autoshield-sidepanel') {
    sidePanelPort = port;
    port.onDisconnect.addListener(() => {
      sidePanelPort = null;
    });
    port.onMessage.addListener((msg) => {
      // Side panel → content script (e.g., trigger extraction)
      handleSidePanelMessage(msg);
    });
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Content script → side panel
  if (msg.source === 'autoshield-content') {
    if (sidePanelPort) {
      sidePanelPort.postMessage(msg);
    }
    sendResponse({ ok: true });
    return true;
  }
});

function sendStep(step) {
  if (sidePanelPort) {
    sidePanelPort.postMessage({ type: 'progress', step });
  }
}

async function handleSidePanelMessage(msg) {
  if (msg.type === 'RUN_RUNTIME_SCAN') {
    await runRuntimeScan();
    return;
  }

  if (msg.type === 'RUN_MEDIA_COMPLIANCE_SCAN') {
    await runMediaComplianceScanFromActiveTab();
    return;
  }

  if (msg.type === 'triggerExtraction') {
    try {
      sendStep('Starting scan...');
      
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

      if (tab?.id) {
        sendStep('Extracting page data...');

        chrome.tabs.sendMessage(tab.id, { type: 'extractPageData', useLLM: !!msg.useLLM }, (response) => {

          if (chrome.runtime.lastError) {
            sendStep('Injecting content script...');

            chrome.scripting.executeScript({
              target: { tabId: tab.id },
              files: ['content.js']
            }).then(() => {
              setTimeout(() => {
                sendStep('Extracting after injection...');
                chrome.tabs.sendMessage(tab.id, { type: 'extractPageData', useLLM: !!msg.useLLM });
              }, 500);
            });

          } else {
            sendStep('Page data extracted');
          }
        });
      }

    } catch (e) {
      sendStep('Extraction failed');
      console.warn('[AutoShield BG] triggerExtraction error:', e);
    }
  }
}

async function runMediaComplianceScanFromActiveTab() {
  try {
    sendStep('Starting live media compliance scan...');
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab?.id || !tab.url) {
      postMediaComplianceError('No active tab available.');
      return;
    }

    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
      postMediaComplianceError('Cannot scan browser internal pages.');
      return;
    }

    sendStep('Collecting live media URLs...');
    const mediaData = await collectLiveMediaData(tab.id);

    sendStep(`Sending ${mediaData.image_urls.length} media URL(s) to backend...`);
    const response = await fetch('http://127.0.0.1:8000/api/compliance/media-license/scan-live', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        page_url: mediaData.page_url || tab.url,
        image_urls: mediaData.image_urls || [],
        enable_reverse_search: true,
        max_images: 5,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || `Backend returned ${response.status}`);
    }

    const report = await response.json();
    if (sidePanelPort) {
      sidePanelPort.postMessage({ type: 'mediaComplianceResult', report });
    }
  } catch (error) {
    postMediaComplianceError(error.message || String(error));
  }
}

async function collectLiveMediaData(tabId) {
  let response = await sendTabMessage(tabId, { type: 'COLLECT_MEDIA_COMPLIANCE_DATA' });
  if (response?.ok && response.data) {
    return response.data;
  }

  if (chrome.scripting) {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const imageUrls = new Set();

        document.querySelectorAll('img').forEach((img) => {
          if (img.src) imageUrls.add(img.src);
          if (img.currentSrc) imageUrls.add(img.currentSrc);
        });

        document.querySelectorAll('source').forEach((source) => {
          if (source.src) imageUrls.add(source.src);
        });

        document.querySelectorAll('*').forEach((el) => {
          const style = window.getComputedStyle(el);
          const bg = style.backgroundImage;

          if (bg && bg !== 'none') {
            const matches = [...bg.matchAll(/url\(["']?(.*?)["']?\)/g)];

            matches.forEach((match) => {
              if (match[1]) {
                try {
                  const absoluteUrl = new URL(match[1], location.href).href;
                  imageUrls.add(absoluteUrl);
                } catch (_) {}
              }
            });
          }
        });

        const cleanImageUrls = [...imageUrls].filter((url) => {
          return (
            url &&
            !url.startsWith('data:') &&
            !url.startsWith('blob:') &&
            /\.(jpg|jpeg|png|webp|gif|bmp)(\?|#|$)/i.test(url)
          );
        });

        return {
          page_url: location.href,
          image_urls: cleanImageUrls,
        };
      }
    });

    return result?.result || { page_url: '', image_urls: [] };
  }

  throw new Error(response?.error || 'Unable to collect media URLs from the page.');
}

async function runRuntimeScan() {
  try {
    sendStep('Starting runtime browser scan...');
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id || !tab.url) {
      postRuntimeError('No active tab available.');
      return;
    }
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
      postRuntimeError('Cannot scan browser internal pages.');
      return;
    }

    sendStep('Collecting DOM runtime evidence...');
    const pageData = await collectRuntimeData(tab.id);

    sendStep('Collecting response headers...');
    const headers = await collectHeaders(tab.url);

    sendStep('Sending runtime evidence to backend...');
    const response = await fetch('http://127.0.0.1:8000/api/agent/full-scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_path: '',
        runtime_url: tab.url,
        runtime_page_data: pageData,
        runtime_headers: headers,
      }),
    });

    if (!response.ok) {
      throw new Error(`Backend returned ${response.status}`);
    }

    const result = await response.json();
    if (sidePanelPort) {
      sidePanelPort.postMessage({ type: 'runtimeScanResult', result });
    }
  } catch (error) {
    postRuntimeError(error.message || String(error));
  }
}

async function collectRuntimeData(tabId) {
  let response = await sendTabMessage(tabId, { type: 'collectRuntimeData' });
  if (!response?.ok && chrome.scripting) {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content.js']
    });
    await new Promise((resolve) => setTimeout(resolve, 300));
    response = await sendTabMessage(tabId, { type: 'collectRuntimeData' });
  }
  if (!response?.ok) {
    throw new Error(response?.error || 'Content script did not return runtime data.');
  }
  return response.data;
}

function sendTabMessage(tabId, message) {
  return new Promise((resolve) => {
    chrome.tabs.sendMessage(tabId, message, (response) => {
      if (chrome.runtime.lastError) {
        resolve({ ok: false, error: chrome.runtime.lastError.message });
        return;
      }
      resolve(response);
    });
  });
}

async function collectHeaders(url) {
  const headers = {};
  try {
    let response = await fetch(url, {
      method: 'HEAD',
      cache: 'no-store',
      credentials: 'include',
    });
    if (!response.ok && response.status === 405) {
      response = await fetch(url, {
        method: 'GET',
        cache: 'no-store',
        credentials: 'include',
      });
    }
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
  } catch (error) {
    headers.__error = error.message || String(error);
  }
  return headers;
}

function postRuntimeError(error) {
  if (sidePanelPort) {
    sidePanelPort.postMessage({ type: 'runtimeScanError', error });
  }
}

function postMediaComplianceError(error) {
  if (sidePanelPort) {
    sidePanelPort.postMessage({ type: 'mediaComplianceError', error });
  }
}
