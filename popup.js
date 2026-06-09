/**
 * InfiltraFox - Popup Script
 * Handles user interaction with the extension popup
 */

// DOM Elements
const redTeamBtn = document.getElementById('redTeamBtn');
const blueTeamBtn = document.getElementById('blueTeamBtn');
const scanButton = document.getElementById('scanButton');
const loadingIndicator = document.getElementById('loadingIndicator');
const resultsContainer = document.getElementById('resultsContainer');
const tabs = document.querySelectorAll('.tab');
const tabContents = document.querySelectorAll('.tab-content');
const exportButton = document.getElementById('exportButton');

// Badge elements
const sqliBadge = document.getElementById('sqliBadge');
const xssBadge = document.getElementById('xssBadge');
const cookiesBadge = document.getElementById('cookiesBadge');

// Tab content containers
const sqliContent = document.getElementById('sqliContent');
const xssContent = document.getElementById('xssContent');
const cookiesContent = document.getElementById('cookiesContent');

// Current analysis mode
let currentMode = 'redTeam';
let scanResults = null;

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
  // Get stored analysis mode
  const data = await browser.storage.local.get('analysisMode');
  if (data.analysisMode) {
    currentMode = data.analysisMode;
    updateUIForMode(currentMode);
  }
  
  // Check if there are recent results
  const message = await browser.runtime.sendMessage({
    action: 'getLastResults'
  });
  
  if (message && message.results) {
    scanResults = message.results;
    displayResults(scanResults);
  }
});

// Handle mode toggle
redTeamBtn.addEventListener('click', () => {
  if (currentMode !== 'redTeam') {
    setAnalysisMode('redTeam');
  }
});

blueTeamBtn.addEventListener('click', () => {
  if (currentMode !== 'blueTeam') {
    setAnalysisMode('blueTeam');
  }
});

// Update UI based on selected mode
function updateUIForMode(mode) {
  if (mode === 'redTeam') {
    redTeamBtn.classList.add('active');
    blueTeamBtn.classList.remove('active');
    scanButton.classList.remove('blue-mode');
    document.querySelectorAll('.tab.active').forEach(tab => {
      tab.classList.remove('blue-mode');
    });
  } else {
    blueTeamBtn.classList.add('active');
    redTeamBtn.classList.remove('active');
    scanButton.classList.add('blue-mode');
    document.querySelectorAll('.tab.active').forEach(tab => {
      tab.classList.add('blue-mode');
    });
  }
  
  // Update recommendations if results are already displayed
  if (scanResults) {
    displayResults(scanResults);
  }
}

// Set analysis mode and update UI
async function setAnalysisMode(mode) {
  currentMode = mode;
  updateUIForMode(currentMode);
  
  // Send mode to background script
  await browser.runtime.sendMessage({
    action: 'setAnalysisMode',
    mode: currentMode
  });
}

// Handle tab switching
tabs.forEach(tab => {
  tab.addEventListener('click', () => {
    // Remove active class from all tabs and contents
    tabs.forEach(t => t.classList.remove('active'));
    tabContents.forEach(content => content.classList.remove('active'));
    
    // Add active class to clicked tab
    tab.classList.add('active');
    
    // Add blue-mode class if in blue team mode
    if (currentMode === 'blueTeam') {
      tab.classList.add('blue-mode');
    } else {
      tab.classList.remove('blue-mode');
    }
    
    // Show corresponding content
    const tabName = tab.getAttribute('data-tab');
    document.getElementById(`${tabName}Content`).classList.add('active');
  });
});

// Handle scan button click
scanButton.addEventListener('click', async () => {
  // Show loading indicator
  scanButton.disabled = true;
  loadingIndicator.style.display = 'block';
  resultsContainer.style.display = 'none';
  
  // Request analysis from background script
  try {
    const response = await browser.runtime.sendMessage({
      action: 'startAnalysis'
    });
    
    if (response && response.success) {
      scanResults = response.results;
      displayResults(scanResults);
    } else {
      showError('Analysis failed: ' + (response?.error || 'Unknown error'));
    }
  } catch (error) {
    showError('Error: ' + error.message);
  }
  
  // Hide loading indicator
  scanButton.disabled = false;
  loadingIndicator.style.display = 'none';
});

// Display results in the UI
function displayResults(results) {
  // Clear previous results
  sqliContent.innerHTML = '';
  xssContent.innerHTML = '';
  cookiesContent.innerHTML = '';
  
  // Update badges
  const sqliCount = results.sqli.length;
  const xssCount = results.xss.length;
  const cookiesCount = results.cookies.length;
  
  sqliBadge.textContent = sqliCount;
  xssBadge.textContent = xssCount;
  cookiesBadge.textContent = cookiesCount;
  
  // Set badge colors based on findings severity
  updateBadgeColor(sqliBadge, sqliCount > 0 ? getHighestSeverity(results.sqli, 'riskLevel') : 'low');
  updateBadgeColor(xssBadge, xssCount > 0 ? getHighestSeverity(results.xss, 'riskLevel') : 'low');
  updateBadgeColor(cookiesBadge, cookiesCount > 0 ? getHighestSeverity(results.cookies, 'riskLevel') : 'low');
  
  // Display SQL Injection findings
  if (sqliCount > 0) {
    results.sqli.forEach((finding, index) => {
      sqliContent.appendChild(createFindingElement('sqli', finding, index));
    });
  } else {
    sqliContent.innerHTML = '<div class="no-findings">No SQL Injection vulnerabilities detected.</div>';
  }
  
  // Display XSS findings
  if (xssCount > 0) {
    results.xss.forEach((finding, index) => {
      xssContent.appendChild(createFindingElement('xss', finding, index));
    });
  } else {
    xssContent.innerHTML = '<div class="no-findings">No XSS vulnerabilities detected.</div>';
  }
  
  // Display Cookie security findings
  if (cookiesCount > 0) {
    results.cookies.forEach((finding, index) => {
      cookiesContent.appendChild(createFindingElement('cookies', finding, index));
    });
  } else {
    cookiesContent.innerHTML = '<div class="no-findings">No cookie security issues detected.</div>';
  }
  
  // Show results container
  resultsContainer.style.display = 'block';
}

// Create a finding element
function createFindingElement(type, finding, index) {
  const findingElement = document.createElement('div');
  findingElement.className = 'finding';
  
  // Set border color based on risk level
  const riskLevel = finding.riskLevel.toLowerCase();
  findingElement.style.borderLeftColor = 
    riskLevel === 'critical' ? '#d32f2f' :
    riskLevel === 'high' ? '#f44336' :
    riskLevel === 'medium' ? '#f57c00' : '#ffb74d';
  
  // Create finding content based on type
  let findingTitle = '';
  let findingDetails = '';
  let recommendation = '';
  
  switch (type) {
    case 'sqli':
      findingTitle = `Potential SQL Injection in ${finding.formId ? `Form #${finding.formId}` : `Form ${index + 1}`}`;
      findingDetails = `
        <div>Risk Level: <strong>${finding.riskLevel}</strong></div>
        <div>POST Method: <strong>${finding.isPostMethod ? 'Yes' : 'No'}</strong></div>
        <div>Password Field: <strong>${finding.hasPasswordField ? 'Yes' : 'No'}</strong></div>
        <div>CSRF Protection: <strong>${!finding.hasNoCSRFToken ? 'Yes' : 'No'}</strong></div>
        <div>Unsafe Inputs: <strong>${finding.unsafeInputs.length}</strong></div>
        ${finding.unsafeInputs.map(input => `
          <div class="code-snippet">
            Input: ${input.inputName || input.inputId || 'unnamed'} (${input.inputType})
          </div>
        `).join('')}
      `;
      
      recommendation = currentMode === 'redTeam'
        ? `
          <div class="recommendation">
            <strong>Exploitation:</strong> Try basic SQL payloads like <code>' OR 1=1 --</code>, <code>' UNION SELECT 1,2,3 --</code> in these fields. Missing CSRF protection means successful injections can be triggered remotely.
          </div>
        `
        : `
          <div class="recommendation">
            <strong>Mitigation:</strong> Implement prepared statements or parameterized queries. Add server-side input validation and sanitization. Implement CSRF tokens for form submissions.
          </div>
        `;
      break;
      
    case 'xss':
      findingTitle = `Potential XSS Vulnerability (${finding.type})`;
      
      if (finding.type === 'inlineScript') {
        findingDetails = `
          <div>Risk Level: <strong>${finding.riskLevel}</strong></div>
          <div>Location: <strong>${finding.location}</strong></div>
          <div>Script content:</div>
          <div class="code-snippet">${escapeHTML(finding.content)}</div>
        `;
      } else if (finding.type === 'eventHandler') {
        findingDetails = `
          <div>Risk Level: <strong>${finding.riskLevel}</strong></div>
          <div>Element: <strong>${finding.element}</strong></div>
          <div>Event: <strong>${finding.attribute}</strong></div>
          <div>Handler content:</div>
          <div class="code-snippet">${escapeHTML(finding.content)}</div>
        `;
      } else if (finding.type === 'domXss') {
        findingDetails = `
          <div>Risk Level: <strong>${finding.riskLevel}</strong></div>
          <div>Location: <strong>${finding.location}</strong></div>
          <div>Uses document location in script:</div>
          <div class="code-snippet">${escapeHTML(finding.content)}</div>
        `;
      }
      
      recommendation = currentMode === 'redTeam'
        ? `
          <div class="recommendation">
            <strong>Exploitation:</strong> Test payload delivery via URL parameters or form inputs. For DOM-based XSS, focus on URL fragments that might be processed by JavaScript.
          </div>
        `
        : `
          <div class="recommendation">
            <strong>Mitigation:</strong> Use Content-Security-Policy headers to restrict script execution. Sanitize user input before rendering in HTML context. Validate and encode all output.
          </div>
        `;
      break;
      
    case 'cookies':
      findingTitle = `Cookie Security Issue: ${finding.name}`;
      findingDetails = `
        <div>Risk Level: <strong>${finding.riskLevel}</strong></div>
        <div>Missing HttpOnly Flag: <strong>${finding.missingHttpOnly ? 'Yes' : 'No'}</strong></div>
        <div>Secure Flag Set: <strong>${finding.isSecure ? 'Yes' : 'No'}</strong></div>
        <div>Missing SameSite Attribute: <strong>${finding.missingSameSite ? 'Yes' : 'No'}</strong></div>
      `;
      
      recommendation = currentMode === 'redTeam'
        ? `
          <div class="recommendation">
            <strong>Exploitation:</strong> ${finding.missingHttpOnly ? 'Cookie accessible via JavaScript, potential for session hijacking via XSS attacks.' : ''}
            ${!finding.isSecure ? 'Cookie transmitted over HTTP, vulnerable to network sniffing.' : ''}
            ${finding.missingSameSite ? 'Vulnerable to CSRF attacks that can force cookie submission to the target site.' : ''}
          </div>
        `
        : `
          <div class="recommendation">
            <strong>Mitigation:</strong> Set the HttpOnly flag to prevent JavaScript access. Enable the Secure flag to ensure cookies are only sent over HTTPS. Set SameSite=Strict or SameSite=Lax to prevent CSRF attacks.
          </div>
        `;
      break;
  }
  
  // Build the finding element HTML
  findingElement.innerHTML = `
    <div class="finding-header">
      <div class="finding-title">${findingTitle}</div>
      <div class="risk-level ${riskLevel}">${finding.riskLevel}</div>
    </div>
    <div class="finding-details">${findingDetails}</div>
    ${recommendation}
  `;
  
  return findingElement;
}

// Update badge color based on severity
function updateBadgeColor(badgeElement, severity) {
  // Remove all existing classes
  badgeElement.classList.remove('critical', 'high', 'medium', 'low');
  
  // Add appropriate class
  severity = severity.toLowerCase();
  if (severity === 'critical') {
    badgeElement.classList.add('critical');
  } else if (severity === 'high') {
    badgeElement.classList.add('high');
  } else if (severity === 'medium') {
    badgeElement.classList.add('medium');
  } else {
    badgeElement.classList.add('low');
  }
}

// Get highest severity from an array of findings
function getHighestSeverity(findings, propertyName) {
  const severityOrder = {
    'critical': 4,
    'high': 3,
    'medium': 2,
    'low': 1
  };
  
  let highestSeverity = 'low';
  
  findings.forEach(finding => {
    const severity = finding[propertyName].toLowerCase();
    if (severityOrder[severity] > severityOrder[highestSeverity]) {
      highestSeverity = severity;
    }
  });
  
  return highestSeverity;
}

// Handle export button click
exportButton.addEventListener('click', () => {
  if (!scanResults) return;
  
  // Prepare export data
  const exportData = {
    timestamp: new Date().toISOString(),
    url: window.location.href,
    mode: currentMode,
    findings: scanResults
  };
  
  // Create a blob and download link
  const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  
  // Create and trigger download
  const a = document.createElement('a');
  a.href = url;
  a.download = `infiltrafox-report-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  
  // Clean up
  setTimeout(() => {
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  }, 0);
});

// Helper function to escape HTML
function escapeHTML(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Show error message
function showError(message) {
  resultsContainer.style.display = 'block';
  resultsContainer.innerHTML = `
    <div style="color: #ef5350; padding: 15px; text-align: center;">
      ${message}
    </div>
  `;
}