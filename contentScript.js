/**
 * InfiltraFox - Content Script
 * Analyzes current webpage for security vulnerabilities
*/

// Main vulnerability scanner
class VulnerabilityScanner {
    constructor() {
        this.findings = {
            sqli: [],
            xss: [],
            cookies: []
        };
    }
    
    // Master scan function
    async scanPage() {
        this.scanForSQLi();
        this.scanForXSS();
        this.scanForCookieIssues();
            //EXPRIMENTAL FEATURES
        // this.scanForCSPIssues();
        // this.scanForCORSIssues();
        // this.scanForInfoLeakage();
        // this.scanForVulnerableLibraries();
        return this.findings;
    }
    
// _______________________EXPREMENTAL______________________
    // CSP scanning
    // scanForCSPIssues() {
    //     // This requires the webRequest API and proper permissions
    //     // For now, we'll analyze meta tags for CSP
    //     const cspMetaTags = document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]');
        
    //     if (cspMetaTags.length === 0) {
    //       this.findings.csp = {
    //         present: false,
    //         riskLevel: 'High',
    //         details: 'No Content Security Policy found. CSP helps prevent XSS attacks by controlling what resources can be loaded.'
    //       };
    //       return;
    //     }
        
    //     // Analyze CSP directives
    //     const cspContent = cspMetaTags[0].getAttribute('content');
    //     const hasUnsafeInline = cspContent.includes("'unsafe-inline'");
    //     const hasUnsafeEval = cspContent.includes("'unsafe-eval'");
    //     const hasWildcards = cspContent.includes('*');
        
    //     this.findings.csp = {
    //       present: true,
    //       content: cspContent,
    //       riskLevel: hasUnsafeInline || hasUnsafeEval ? 'Medium' : 'Low',
    //       details: [],
    //     };
        
    //     if (hasUnsafeInline) {
    //       this.findings.csp.details.push("CSP allows 'unsafe-inline' which reduces protection against XSS attacks.");
    //     }
        
    //     if (hasUnsafeEval) {
    //       this.findings.csp.details.push("CSP allows 'unsafe-eval' which can execute potentially dangerous code dynamically.");
    //     }
        
    //     if (hasWildcards) {
    //       this.findings.csp.details.push("CSP includes wildcards (*) which may weaken the policy's effectiveness.");
    //     }
    // }
    
    // // scan for CORS misconfigurations
    // scanForCORSIssues() {
    // // Look for CORS-related tags
    // const corsMetaTags = document.querySelectorAll('meta[name="Access-Control-Allow-Origin"]');
    
    // if (corsMetaTags.length > 0) {
    //     const corsValue = corsMetaTags[0].getAttribute('content');
        
    //     this.findings.cors = {
    //     type: 'metaTag',
    //     value: corsValue,
    //     riskLevel: corsValue === '*' ? 'High' : 'Medium',
    //     details: corsValue === '*' ? 
    //         'CORS policy set to allow all origins (*) in meta tag, which is insecure and may lead to cross-origin attacks.' :
    //         'CORS policy found in meta tag. Note that CORS should be configured server-side via HTTP headers, not via meta tags.'
    //     };
    // } else {
    //     // Can't fully check CORS without network requests, but we can look for API endpoints
    //     const scripts = document.querySelectorAll('script');
    //     const apiEndpoints = [];
        
    //     scripts.forEach(script => {
    //     const content = script.innerHTML;
        
    //     // Look for potential API patterns
    //     const apiPatterns = [
    //         /\b(api|rest)\b.*\.(get|post|put|delete)\(/i,
    //         /\bfetch\(['"`]([^'"`]+)['"`]/gi,
    //         /\burl\s*:\s*['"`]([^'"`]+)['"`]/gi,
    //         /\bxhr\.open\(['"`]GET['"`],\s*['"`]([^'"`]+)['"`]/gi
    //     ];
        
    //     apiPatterns.forEach(pattern => {
    //         const matches = content.match(pattern);
    //         if (matches) {
    //         apiEndpoints.push(...matches);
    //         }
    //     });
    //     });
        
    //     if (apiEndpoints.length > 0) {
    //     this.findings.cors = {
    //         type: 'apiDetection',
    //         apiEndpoints: apiEndpoints.slice(0, 5), // Limit to first 5
    //         riskLevel: 'Info',
    //         details: 'Potential API endpoints detected. Consider reviewing CORS settings on the server to prevent cross-origin attacks.'
    //     };
    //     }
    // }
    // }
    
    
    // SQL Injection scanning
    scanForSQLi() {
      // Find all forms, especially login forms
      const forms = document.querySelectorAll('form');
      
      forms.forEach((form, formIndex) => {
        // Check for POST method (higher risk)
        const isPostMethod = form.method.toLowerCase() === 'post';
        
        // Find input fields
        const inputs = form.querySelectorAll('input');
        const hasPasswordField = Array.from(inputs).some(input => input.type === 'password');
        const hasNoCSRFToken = !Array.from(inputs).some(input => 
          input.type === 'hidden' && 
          (input.name.toLowerCase().includes('token') || 
           input.name.toLowerCase().includes('csrf'))
        );
  
        // Check for input validation attributes
        const unsafeInputs = Array.from(inputs).filter(input => {
            // Text inputs without pattern or min/maxlength are potentially vulnerable
            return (input.type === 'text' || input.type === 'search' || !input.type) && 
            !input.pattern && 
                 !input.maxLength;
        });
  
        if (unsafeInputs.length > 0) {
          this.findings.sqli.push({
            formIndex,
            formId: form.id || null,
            formAction: form.action || null,
            isPostMethod,
            hasPasswordField,
            hasNoCSRFToken,
            riskLevel: this.calculateSQLiRiskLevel(isPostMethod, hasPasswordField, hasNoCSRFToken),
            unsafeInputs: unsafeInputs.map(input => ({
              inputName: input.name,
              inputId: input.id,
              inputType: input.type
            }))
          });
        }
    });
    }
  
    // Calculate SQLi risk level
    calculateSQLiRiskLevel(isPostMethod, hasPasswordField, hasNoCSRFToken) {
      if (isPostMethod && hasPasswordField && hasNoCSRFToken) {
        return 'High';
    } else if ((isPostMethod && hasPasswordField) || (isPostMethod && hasNoCSRFToken)) {
        return 'Medium';
      } else {
          return 'Low';
        }
    }
  
    // XSS vulnerability scanning
    scanForXSS() {
      // Check for inline scripts
      const inlineScripts = document.querySelectorAll('script:not([src])');
      inlineScripts.forEach((script, index) => {
        this.findings.xss.push({
          type: 'inlineScript',
          index,
          content: script.innerHTML.substring(0, 100) + (script.innerHTML.length > 100 ? '...' : ''),
          riskLevel: 'Medium',
          location: this.getElementPath(script)
        });
      });
  
      // Check for event handler attributes
      const eventHandlerAttrs = [
        'onclick', 'onmouseover', 'onload', 'onerror', 'onkeyup', 'onkeydown', 
        'onsubmit', 'onmouseout', 'onchange', 'onfocus', 'onblur'
      ];
      
      const allElements = document.querySelectorAll('*');
      allElements.forEach(element => {
        for (const attr of eventHandlerAttrs) {
          if (element.hasAttribute(attr)) {
            this.findings.xss.push({
              type: 'eventHandler',
              element: element.tagName.toLowerCase(),
              attribute: attr,
              content: element.getAttribute(attr),
              riskLevel: 'High',
              location: this.getElementPath(element)
            });
          }
        }
      });
  
      // Check for data parameters accepted from URL (potential DOM XSS)
      const documentLocation = document.location.href;
      if (documentLocation.includes('?') || documentLocation.includes('#')) {
        const scriptTags = document.querySelectorAll('script');
        scriptTags.forEach((script, index) => {
          const content = script.innerHTML;
          if (content.includes('location') || 
              content.includes('document.URL') || 
              content.includes('document.documentURI') ||
              content.includes('document.referrer')) {
            this.findings.xss.push({
              type: 'domXss',
              index,
              content: content.substring(0, 100) + (content.length > 100 ? '...' : ''),
              riskLevel: 'High',
              location: this.getElementPath(script)
            });
          }
        });
      }
    }
  
    // Cookie security analysis
    scanForCookieIssues() {
      const cookies = document.cookie.split(';');
      
      cookies.forEach(cookie => {
        // Skip empty cookies
        if (!cookie.trim()) return;
        
        const cookieParts = cookie.trim().split('=');
        const cookieName = cookieParts[0];
        
        // Check if HttpOnly flag exists (can only be inferred from absence in JS-accessible cookies)
        const missingHttpOnly = true; // If we can see it in JS, it's not HttpOnly
        
        // Check if Secure flag exists (can be inferred from document.cookie in HTTPS)
        const isSecure = document.location.protocol === 'https:';
        
        // SameSite can't be directly checked via JS, assume missing for accessible cookies
        const missingSameSite = true;
        
        this.findings.cookies.push({
          name: cookieName,
          missingHttpOnly,
          isSecure,
          missingSameSite,
          riskLevel: this.calculateCookieRiskLevel(missingHttpOnly, isSecure, missingSameSite)
        });
      });
    }
  
    // Calculate cookie risk level
    calculateCookieRiskLevel(missingHttpOnly, isSecure, missingSameSite) {
      if (missingHttpOnly && !isSecure && missingSameSite) {
        return 'Critical';
      } else if ((missingHttpOnly && !isSecure) || (missingHttpOnly && missingSameSite)) {
        return 'High';
      } else if (missingHttpOnly || !isSecure || missingSameSite) {
        return 'Medium';
      } else {
        return 'Low';
      }
    }
  
    // Helper to get element path for reporting
    getElementPath(element) {
      if (!element) return '';
      
      let path = element.tagName.toLowerCase();
      if (element.id) {
        path += `#${element.id}`;
      } else if (element.className) {
        path += `.${element.className.replace(/\s+/g, '.')}`;
      }
      
      return path;
    }
  }
  
  // Listen for messages from popup/background scripts
  browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'analyze') {
      const scanner = new VulnerabilityScanner();
      scanner.scanPage().then(results => {
        sendResponse({
          success: true,
          results: results
        });
      });
      return true; // Indicates async response
    }
  });
  
  // Notify that content script is loaded
  browser.runtime.sendMessage({
    action: 'contentScriptLoaded',
    url: window.location.href
  });