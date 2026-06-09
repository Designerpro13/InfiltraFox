/**
 * InfiltraFox - Content Script
 * Analyzes the active page for common security signals.
 */

class VulnerabilityScanner {
  constructor() {
    this.findings = {
      meta: {
        title: document.title || 'Untitled Page',
        url: window.location.href,
        forms: document.forms.length,
        scripts: document.scripts.length,
        cookieCount: this.getAccessibleCookies().length
      },
      sqli: [],
      xss: [],
      cookies: [],
      headers: [],
      mixedContent: [],
      openRedirects: [],
      sri: []
    };
  }

  async scanPage() {
    this.scanForSQLi();
    this.scanForXSS();
    this.scanForCookieIssues();
    this.scanForHeaderIssues();
    this.scanForMixedContent();
    this.scanForOpenRedirects();
    this.scanForSRIIssues();
    return this.findings;
  }

  getAccessibleCookies() {
    return document.cookie.split(';').map(c => c.trim()).filter(Boolean);
  }

  // ─── SQLi ──────────────────────────────────────────────────────────────────

  scanForSQLi() {
    const candidateTypes = new Set(['', 'text', 'search', 'email', 'url', 'tel', 'number']);

    Array.from(document.querySelectorAll('form')).forEach((form, formIndex) => {
      const method = (form.getAttribute('method') || 'get').toLowerCase();
      const action = form.getAttribute('action') || window.location.href;
      const inputs = Array.from(form.querySelectorAll('input, textarea'));
      const hasPasswordField = inputs.some(i => i.type === 'password');
      const hasNoCSRFToken = !inputs.some(i =>
        i.type === 'hidden' && /csrf|token|nonce/i.test(`${i.name || ''} ${i.id || ''}`)
      );

      const unsafeInputs = inputs.filter(i => {
        const type = (i.getAttribute('type') || '').toLowerCase();
        return (i.tagName.toLowerCase() === 'textarea' || candidateTypes.has(type))
          && !i.pattern && !i.maxLength;
      });

      if (!unsafeInputs.length) return;

      this.findings.sqli.push({
        formIndex,
        formId: form.id || null,
        formAction: action,
        method: method.toUpperCase(),
        isPostMethod: method === 'post',
        hasPasswordField,
        hasNoCSRFToken,
        riskLevel: this.sqliRisk({ method, hasPasswordField, hasNoCSRFToken, count: unsafeInputs.length }),
        unsafeInputs: unsafeInputs.map(i => ({
          inputName: i.name || null,
          inputId: i.id || null,
          inputType: i.tagName.toLowerCase() === 'textarea' ? 'textarea' : (i.type || 'text')
        }))
      });
    });
  }

  sqliRisk({ method, hasPasswordField, hasNoCSRFToken, count }) {
    let s = 0;
    if (method === 'post') s += 2;
    if (hasPasswordField) s += 2;
    if (hasNoCSRFToken) s += 2;
    if (count >= 3) s += 1;
    return s >= 6 ? 'High' : s >= 3 ? 'Medium' : 'Low';
  }

  // ─── XSS ───────────────────────────────────────────────────────────────────

  scanForXSS() {
    const sourcePattern = /location|document\.URL|document\.documentURI|document\.referrer|window\.name|localStorage|sessionStorage/;
    const sinkPattern = /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval|setTimeout\s*\(|setInterval\s*\(|Function\s*\(/;
    const handlerAttrs = ['onclick','onmouseover','onload','onerror','onkeyup','onkeydown','onsubmit','onmouseout','onchange','onfocus','onblur'];

    document.querySelectorAll('script:not([src])').forEach((script, index) => {
      const content = script.textContent || '';
      const hasSink = sinkPattern.test(content);
      const hasSource = sourcePattern.test(content);
      if (!hasSink && !hasSource) return;

      this.findings.xss.push({
        type: hasSink && hasSource ? 'domXss' : 'inlineScript',
        index,
        content: this.truncate(content),
        riskLevel: hasSink && hasSource ? 'High' : 'Medium',
        location: this.getElementPath(script)
      });
    });

    document.querySelectorAll('*').forEach(el => {
      for (const attr of handlerAttrs) {
        if (!el.hasAttribute(attr)) continue;
        this.findings.xss.push({
          type: 'eventHandler',
          element: el.tagName.toLowerCase(),
          attribute: attr,
          content: this.truncate(el.getAttribute(attr) || ''),
          riskLevel: 'High',
          location: this.getElementPath(el)
        });
      }

      if (el.tagName.toLowerCase() === 'a') {
        const href = el.getAttribute('href') || '';
        if (/^\s*javascript:/i.test(href)) {
          this.findings.xss.push({
            type: 'javascriptUrl',
            element: 'a',
            attribute: 'href',
            content: this.truncate(href),
            riskLevel: 'Medium',
            location: this.getElementPath(el)
          });
        }
      }
    });
  }

  // ─── Cookies ───────────────────────────────────────────────────────────────

  scanForCookieIssues() {
    this.getAccessibleCookies().forEach(cookie => {
      const [name] = cookie.split('=');
      this.findings.cookies.push({
        name,
        jsAccessible: true,
        flags: { httpOnly: false, secure: null, sameSite: null },
        riskLevel: window.location.protocol === 'https:' ? 'Medium' : 'High',
        details: 'Cookie readable from JavaScript — HttpOnly is absent. Secure and SameSite cannot be verified from document.cookie.'
      });
    });
  }

  // ─── Security Headers (via <meta http-equiv>) ──────────────────────────────

  scanForHeaderIssues() {
    const isHttps = window.location.protocol === 'https:';

    // Check meta http-equiv tags for security headers
    const metaMap = {};
    document.querySelectorAll('meta[http-equiv]').forEach(m => {
      metaMap[(m.getAttribute('http-equiv') || '').toLowerCase()] = m.getAttribute('content') || '';
    });

    // CSP
    const csp = metaMap['content-security-policy'];
    if (!csp) {
      this.findings.headers.push({
        header: 'Content-Security-Policy',
        present: false,
        value: null,
        riskLevel: 'High',
        details: 'No CSP meta tag found. Without a CSP the browser places no restrictions on script sources, greatly easing XSS exploitation.'
      });
    } else {
      const issues = [];
      if (/unsafe-inline/i.test(csp)) issues.push("'unsafe-inline' allows inline scripts");
      if (/unsafe-eval/i.test(csp)) issues.push("'unsafe-eval' allows eval()");
      if (/\*/i.test(csp)) issues.push('wildcard (*) permits any source');
      if (issues.length) {
        this.findings.headers.push({
          header: 'Content-Security-Policy',
          present: true,
          value: this.truncate(csp, 120),
          riskLevel: 'Medium',
          details: `Weak CSP directives: ${issues.join('; ')}.`
        });
      }
    }

    // X-Frame-Options
    const xfo = metaMap['x-frame-options'];
    if (!xfo) {
      this.findings.headers.push({
        header: 'X-Frame-Options',
        present: false,
        value: null,
        riskLevel: 'Medium',
        details: 'No X-Frame-Options meta tag. Page may be embeddable in iframes, enabling clickjacking.'
      });
    }

    // Referrer-Policy
    const refMeta = document.querySelector('meta[name="referrer"]');
    const referrerPolicy = refMeta ? (refMeta.getAttribute('content') || '') : null;
    if (!referrerPolicy) {
      this.findings.headers.push({
        header: 'Referrer-Policy',
        present: false,
        value: null,
        riskLevel: 'Low',
        details: 'No Referrer-Policy meta tag. The browser default may leak full URLs to third parties.'
      });
    } else if (/^(unsafe-url|no-referrer-when-downgrade)$/i.test(referrerPolicy)) {
      this.findings.headers.push({
        header: 'Referrer-Policy',
        present: true,
        value: referrerPolicy,
        riskLevel: 'Low',
        details: `"${referrerPolicy}" can leak sensitive URL parameters to cross-origin destinations.`
      });
    }

    // HSTS (only meaningful on HTTPS)
    if (isHttps) {
      const hsts = metaMap['strict-transport-security'];
      if (!hsts) {
        this.findings.headers.push({
          header: 'Strict-Transport-Security',
          present: false,
          value: null,
          riskLevel: 'Medium',
          details: 'No HSTS meta tag on an HTTPS page. Browsers will not enforce HTTPS on subsequent visits via meta policy.'
        });
      }
    }

    // Permissions-Policy / Feature-Policy
    const pp = metaMap['permissions-policy'] || metaMap['feature-policy'];
    if (!pp) {
      this.findings.headers.push({
        header: 'Permissions-Policy',
        present: false,
        value: null,
        riskLevel: 'Low',
        details: 'No Permissions-Policy meta tag. Sensitive browser features (camera, microphone, geolocation) remain unrestricted for embedded content.'
      });
    }
  }

  // ─── Mixed Content ─────────────────────────────────────────────────────────

  scanForMixedContent() {
    if (window.location.protocol !== 'https:') return;

    const httpPattern = /^http:/i;

    const checks = [
      { selector: 'script[src]', attr: 'src', type: 'script', riskLevel: 'High' },
      { selector: 'iframe[src]', attr: 'src', type: 'iframe', riskLevel: 'High' },
      { selector: 'img[src]', attr: 'src', type: 'image', riskLevel: 'Low' },
      { selector: 'link[href]', attr: 'href', type: 'stylesheet', riskLevel: 'Medium' },
      { selector: 'audio[src],video[src]', attr: 'src', type: 'media', riskLevel: 'Low' },
      { selector: 'object[data]', attr: 'data', type: 'object', riskLevel: 'High' }
    ];

    checks.forEach(({ selector, attr, type, riskLevel }) => {
      document.querySelectorAll(selector).forEach(el => {
        const val = el.getAttribute(attr) || '';
        if (!httpPattern.test(val)) return;
        this.findings.mixedContent.push({
          type,
          riskLevel,
          url: this.truncate(val, 120),
          location: this.getElementPath(el),
          details: `Active mixed content (${type}) loaded over HTTP on an HTTPS page.`
        });
      });
    });

    // Forms posting to http://
    document.querySelectorAll('form[action]').forEach(form => {
      const action = form.getAttribute('action') || '';
      if (httpPattern.test(action)) {
        this.findings.mixedContent.push({
          type: 'form',
          riskLevel: 'High',
          url: this.truncate(action, 120),
          location: this.getElementPath(form),
          details: 'Form submits credentials or data over plain HTTP from an HTTPS page.'
        });
      }
    });
  }

  // ─── Open Redirects ────────────────────────────────────────────────────────

  scanForOpenRedirects() {
    const redirectParams = /[?&](url|redirect|redirectUrl|redirect_url|next|return|returnUrl|return_url|goto|dest|destination|forward|continue|target|redir|location|path|callback|ref)=/i;

    const check = (rawUrl, sourceEl) => {
      if (!rawUrl || !redirectParams.test(rawUrl)) return;
      try {
        const url = new URL(rawUrl, window.location.href);
        const suspiciousParams = Array.from(url.searchParams.entries()).filter(([k]) =>
          redirectParams.test(`?${k}=`)
        );
        if (!suspiciousParams.length) return;

        this.findings.openRedirects.push({
          riskLevel: 'Medium',
          url: this.truncate(rawUrl, 120),
          location: this.getElementPath(sourceEl),
          params: suspiciousParams.map(([k, v]) => `${k}=${this.truncate(v, 60)}`).join(', '),
          details: `URL contains a redirect parameter. If the destination value is not validated server-side, an attacker can craft a link that redirects victims to an arbitrary external site.`
        });
      } catch (_) { /* relative or invalid URL, skip */ }
    };

    document.querySelectorAll('a[href]').forEach(a => check(a.getAttribute('href'), a));
    document.querySelectorAll('form[action]').forEach(f => check(f.getAttribute('action'), f));
  }

  // ─── Subresource Integrity ─────────────────────────────────────────────────

  scanForSRIIssues() {
    const isCrossOrigin = src => {
      try {
        return new URL(src, window.location.href).origin !== window.location.origin;
      } catch (_) {
        return false;
      }
    };

    document.querySelectorAll('script[src]').forEach(el => {
      const src = el.getAttribute('src') || '';
      if (!isCrossOrigin(src)) return;
      if (el.getAttribute('integrity')) return;

      this.findings.sri.push({
        tagType: 'script',
        riskLevel: 'High',
        src: this.truncate(src, 120),
        location: this.getElementPath(el),
        details: 'External script loaded without an integrity hash. A compromised CDN or MITM attacker could serve malicious JavaScript.'
      });
    });

    document.querySelectorAll('link[rel~="stylesheet"][href]').forEach(el => {
      const href = el.getAttribute('href') || '';
      if (!isCrossOrigin(href)) return;
      if (el.getAttribute('integrity')) return;

      this.findings.sri.push({
        tagType: 'stylesheet',
        riskLevel: 'Medium',
        src: this.truncate(href, 120),
        location: this.getElementPath(el),
        details: 'External stylesheet loaded without an integrity hash. A tampered stylesheet can exfiltrate data or alter page rendering.'
      });
    });
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  truncate(value, limit = 160) {
    return value.length <= limit ? value : `${value.slice(0, limit)}...`;
  }

  getElementPath(element) {
    if (!element) return '';
    let path = element.tagName.toLowerCase();
    if (element.id) {
      path += `#${element.id}`;
    } else if (typeof element.className === 'string' && element.className.trim()) {
      path += `.${element.className.trim().replace(/\s+/g, '.')}`;
    }
    return path;
  }
}

browser.runtime.onMessage.addListener((message) => {
  if (message.action === 'analyze') {
    const scanner = new VulnerabilityScanner();
    return scanner.scanPage().then(results => ({ success: true, results }));
  }
  return undefined;
});

browser.runtime.sendMessage({ action: 'contentScriptLoaded', url: window.location.href })
  .catch(() => {});
