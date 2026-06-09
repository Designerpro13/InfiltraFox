/**
 * InfiltraFox - Background Service Worker
 * Maintains scan state and coordinates analysis requests.
 */

const STORAGE_KEYS = {
  analysisMode: 'analysisMode',
  scanHistory: 'scanHistory',
  lastScanRecord: 'lastScanRecord'
};

const DEFAULT_MODE = 'redTeam';
const MAX_HISTORY = 20;

async function ensureDefaults() {
  const stored = await browser.storage.local.get([
    STORAGE_KEYS.analysisMode,
    STORAGE_KEYS.scanHistory,
    STORAGE_KEYS.lastScanRecord
  ]);

  const nextState = {};

  if (!stored[STORAGE_KEYS.analysisMode]) {
    nextState[STORAGE_KEYS.analysisMode] = DEFAULT_MODE;
  }

  if (!Array.isArray(stored[STORAGE_KEYS.scanHistory])) {
    nextState[STORAGE_KEYS.scanHistory] = [];
  }

  if (!(STORAGE_KEYS.lastScanRecord in stored)) {
    nextState[STORAGE_KEYS.lastScanRecord] = null;
  }

  if (Object.keys(nextState).length > 0) {
    await browser.storage.local.set(nextState);
  }
}

async function getCurrentMode() {
  const stored = await browser.storage.local.get(STORAGE_KEYS.analysisMode);
  return stored[STORAGE_KEYS.analysisMode] || DEFAULT_MODE;
}

async function getActiveTab() {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  return tabs[0] || null;
}

function isSupportedTab(tab) {
  return Boolean(tab && tab.id && tab.url && /^https?:/i.test(tab.url));
}

async function storeScanRecord(scanRecord) {
  const stored = await browser.storage.local.get(STORAGE_KEYS.scanHistory);
  const history = Array.isArray(stored[STORAGE_KEYS.scanHistory])
    ? stored[STORAGE_KEYS.scanHistory]
    : [];

  history.push(scanRecord);

  while (history.length > MAX_HISTORY) {
    history.shift();
  }

  await browser.storage.local.set({
    [STORAGE_KEYS.scanHistory]: history,
    [STORAGE_KEYS.lastScanRecord]: scanRecord
  });
}

async function startAnalysis() {
  const tab = await getActiveTab();

  if (!isSupportedTab(tab)) {
    return {
      success: false,
      error: 'Open a regular HTTP or HTTPS page before running analysis.'
    };
  }

  let response;

  try {
    response = await browser.tabs.sendMessage(tab.id, { action: 'analyze' });
  } catch (error) {
    return {
      success: false,
      error: `Unable to reach the page scanner: ${error.message}`
    };
  }

  if (!response || !response.success) {
    return {
      success: false,
      error: response?.error || 'Page analysis failed.'
    };
  }

  const analysisMode = await getCurrentMode();
  const scanRecord = {
    timestamp: new Date().toISOString(),
    url: tab.url,
    title: tab.title || response.results?.meta?.title || 'Untitled Page',
    analysisMode,
    results: response.results
  };

  await storeScanRecord(scanRecord);

  return {
    success: true,
    analysisMode,
    record: scanRecord,
    results: response.results
  };
}

browser.runtime.onInstalled.addListener(() => {
  ensureDefaults().catch(error => {
    console.error('Failed to initialize extension state', error);
  });
});

browser.runtime.onStartup.addListener(() => {
  ensureDefaults().catch(error => {
    console.error('Failed to restore extension state', error);
  });
});

browser.runtime.onMessage.addListener((message) => {
  if (message.action === 'setAnalysisMode') {
    return browser.storage.local
      .set({ [STORAGE_KEYS.analysisMode]: message.mode || DEFAULT_MODE })
      .then(async () => ({
        success: true,
        mode: await getCurrentMode()
      }));
  }

  if (message.action === 'startAnalysis') {
    return startAnalysis();
  }

  if (message.action === 'getLastResults') {
    return Promise.all([
      getCurrentMode(),
      browser.storage.local.get(STORAGE_KEYS.lastScanRecord)
    ]).then(([analysisMode, stored]) => ({
      success: true,
      analysisMode,
      record: stored[STORAGE_KEYS.lastScanRecord] || null,
      results: stored[STORAGE_KEYS.lastScanRecord]?.results || null
    }));
  }

  if (message.action === 'contentScriptLoaded') {
    console.debug('InfiltraFox content script ready:', message.url);
  }

  return undefined;
});
