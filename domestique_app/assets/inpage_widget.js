/*
 * Domestique in-page block widget.
 * Injected by the browser-mode MITM addon into top-level HTML pages of
 * intercepted LLM hosts. It ONLY observes responses to surface Domestique's
 * own block message in the page. It is intentionally inert:
 *   - reads only Domestique's `firewall_block` 403 response,
 *   - never reads/stores/transmits page content or the AI's replies,
 *   - makes no network calls of its own, uses no eval,
 *   - renders inside a Shadow DOM so it can't clobber or be clobbered.
 * If anything here throws, the 403 block still holds — this is presentation only.
 */
(function () {
  if (window.__domestiqueWidgetInstalled) return;
  window.__domestiqueWidgetInstalled = true;

  var FIREWALL_TYPE = "firewall_block";

  function humanize(detail) {
    // "secret_scanner:us_ssn (92%)" -> "US SSN (92%)"
    try {
      var s = String(detail);
      var afterColon = s.indexOf(":") >= 0 ? s.slice(s.indexOf(":") + 1) : s;
      return afterColon
        .replace(/_/g, " ")
        .replace(/\b([a-z]{2,4})\b/g, function (w) { return w.toUpperCase(); })
        .trim();
    } catch (e) {
      return String(detail);
    }
  }

  function showOverlay(message, details) {
    try {
      var detailText =
        details && details.length ? details.map(humanize).join(", ") : "sensitive data";
      var hostEl = document.createElement("div");
      hostEl.setAttribute("data-domestique-overlay", "1");
      var root = hostEl.attachShadow ? hostEl.attachShadow({ mode: "open" }) : hostEl;
      root.innerHTML =
        '<style>' +
        '.d-card{position:fixed;top:20px;right:20px;z-index:2147483647;max-width:360px;' +
        'font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;' +
        'background:#1b1f24;color:#f5f7fa;border:1px solid #3a4149;border-radius:10px;' +
        'box-shadow:0 8px 30px rgba(0,0,0,.35);padding:14px 34px 14px 16px;}' +
        '.d-title{font-weight:600;margin:0 0 4px;}' +
        '.d-body{margin:0;opacity:.92;}' +
        '.d-x{position:absolute;top:6px;right:8px;cursor:pointer;background:none;border:none;' +
        'color:#9aa4af;font-size:18px;line-height:1;}' +
        '</style>' +
        '<div class="d-card" role="alert" aria-live="assertive">' +
        '<button class="d-x" aria-label="Dismiss">×</button>' +
        '<p class="d-title">🛡️ Domestique blocked this message</p>' +
        '<p class="d-body">Detected: <strong></strong> · Nothing was sent.</p>' +
        '</div>';
      root.querySelector(".d-body strong").textContent = detailText;
      (document.body || document.documentElement).appendChild(hostEl);
      var remove = function () {
        if (hostEl.parentNode) hostEl.parentNode.removeChild(hostEl);
      };
      root.querySelector(".d-x").addEventListener("click", remove);
      setTimeout(remove, 8000);
    } catch (e) {
      /* never break the page */
    }
  }

  function inspect(status, bodyText) {
    if (status !== 403 || !bodyText) return;
    var data;
    try {
      data = JSON.parse(bodyText);
    } catch (e) {
      return;
    }
    var err = data && data.error;
    if (!err || err.type !== FIREWALL_TYPE) return;
    showOverlay(err.message, err.details);
  }

  if (window.fetch) {
    var origFetch = window.fetch;
    window.fetch = function () {
      return origFetch.apply(this, arguments).then(function (resp) {
        try {
          if (resp && resp.status === 403) {
            resp
              .clone()
              .text()
              .then(function (t) { inspect(403, t); })
              .catch(function () {});
          }
        } catch (e) {}
        return resp;
      });
    };
  }

  if (window.XMLHttpRequest) {
    var origOpen = XMLHttpRequest.prototype.open;
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function () {
      this.__domestiqueWatch = true;
      return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function () {
      var xhr = this;
      if (xhr.__domestiqueWatch) {
        xhr.addEventListener("load", function () {
          try {
            if (xhr.status === 403) inspect(403, xhr.responseText);
          } catch (e) {}
        });
      }
      return origSend.apply(this, arguments);
    };
  }
})();
