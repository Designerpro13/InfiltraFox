/**
 * InfiltraFox - Background Script
 * Manages extension state and content script communication
 */

// Store current analysis mode
let analysisMode = 'redTeam'; // Default to Red Team mode
let lastScanResults = null;

// Initialize extension when installed
browser.runtime.onInstalled.addListener(() => {
  console.log('InfiltraFox extension installed');
  
  // Initialize storage with default settings
  browser.storage.local.set({
    analysisMode: analysisMode,
    scanHistory: []
  });
});

// Listen for messages from popup or content scripts
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("Message received in background:", message);
  // Handle analysis mode toggle
  if (message.action === 'setAnalysisMode') {
    analysisMode = message.mode;
    browser.storage.local.set({ analysisMode: analysisMode });
    sendResponse({ success: true, mode: analysisMode });
  }
  
  // Handle scan request from popup
  else if (message.action === 'startAnalysis') {
    // Get active tab and trigger content script
    browser.tabs.query({ active: true, currentWindow: true })
      .then(tabs => {
        if (tabs[0]) {
          browser.tabs.sendMessage(
            tabs[0].id,
            { action: 'analyze' }
          ).then(response => {
            if (response && response.success) {
              lastScanResults = response.results;
              
              // Add timestamp and URL to results
              const scanRecord = {
                timestamp: new Date().toISOString(),
                url: tabs[0].url,
                results: response.results
              };
              
              // Update scan history
              browser.storage.local.get('scanHistory')
                .then(data => {
                  const history = data.scanHistory || [];
                  // Keep last 20 scans
                  if (history.length >= 20) {
                    history.shift();
                  }
                  history.push(scanRecord);
                  
                  browser.storage.local.set({ scanHistory: history });
                });
          
              
              sendResponse({
                success: true,
                results: response.results,
                analysisMode: analysisMode
              });
            } else {
              sendResponse({
                success: false, 
                error: 'Content script analysis failed'
              });
            }
          }).catch(error => {
            sendResponse({
              success: false,
              error: 'Error communicating with content script: ' + error.message
            });
          });
        } else {
          sendResponse({
            success: false,
            error: 'No active tab found'
          });
        }
      });
    return true; // Indicates async response
  }
  
  // Handle content script loaded notification
  else if (message.action === 'contentScriptLoaded') {
    console.log('Content script loaded for: ' + message.url);
  }
  
  // Handle request for last scan results
  else if (message.action === 'getLastResults') {
    sendResponse({
      success: true,
      results: lastScanResults,
      analysisMode: analysisMode
    });
  }
});

// Listen for tab updates to reset the icon state
browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete') {
    // Reset icon to default
    browser.browserAction.setIcon({
      path: {
        16: "icons/icon16.png",
        48: "icons/icon48.png"
      }
    });
  }
});