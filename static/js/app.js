/* UI behaviour. No inline scripts and no HTML string injection; text is set with textContent (strict CSP). */
(function () {
  "use strict";

  // ---- mobile navigation -------------------------------------------------
  var toggle = document.getElementById("menuToggle");
  var sidebar = document.getElementById("sidebar");
  if (toggle && sidebar) {
    toggle.addEventListener("click", function () {
      var open = sidebar.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && sidebar.classList.contains("open")) {
        sidebar.classList.remove("open");
        toggle.setAttribute("aria-expanded", "false");
        toggle.focus();
      }
    });
  }

  // ---- toasts -------------------------------------------------------------
  var stack = document.getElementById("toastStack");
  function dismiss(toast) { if (toast && toast.parentNode) { toast.parentNode.removeChild(toast); } }
  if (stack) {
    stack.addEventListener("click", function (e) {
      if (e.target.classList && e.target.classList.contains("toast-close")) { dismiss(e.target.closest(".toast")); }
    });
    Array.prototype.forEach.call(stack.querySelectorAll(".toast"), function (t) {
      if (!t.classList.contains("toast-danger")) { setTimeout(function () { dismiss(t); }, 12000); }
    });
  }

  // ---- confirmation dialog -----------------------------------------------
  // Forms with data-confirm get a dialog. On acceptance a hidden confirm=yes
  // field is added; the SERVER refuses destructive actions without it.
  var dialog = document.getElementById("confirmDialog");
  var pendingForm = null;
  var messageEl = document.getElementById("confirmMessage");
  var okBtn = document.getElementById("confirmOk");
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (!(form instanceof HTMLFormElement)) { return; }
    if (form.dataset.confirm && dialog && typeof dialog.showModal === "function" && !form.dataset.confirmed) {
      e.preventDefault();
      pendingForm = form;
      messageEl.textContent = form.dataset.confirm;          // textContent: safe
      okBtn.textContent = form.dataset.confirmLabel || "Confirm";
      dialog.showModal();
      okBtn.focus();
      return;
    }
    if (form.hasAttribute("data-loading") || form.dataset.confirmed) {
      var btn = form.querySelector("button[type=submit]");
      if (btn) { btn.classList.add("loading"); btn.setAttribute("aria-busy", "true"); }
      var bar = document.getElementById("loadingBar");
      if (!bar) { bar = document.createElement("div"); bar.id = "loadingBar"; bar.className = "loading-bar"; document.body.appendChild(bar); }
      requestAnimationFrame(function () { bar.classList.add("on"); });
      // Prevent double submission (e.g. two overlapping scans)
      setTimeout(function () { if (btn) { btn.disabled = true; } }, 0);
    }
  });
  if (dialog) {
    dialog.addEventListener("close", function () {
      if (dialog.returnValue === "ok" && pendingForm) {
        var form = pendingForm; pendingForm = null;
        var hidden = document.createElement("input");
        hidden.type = "hidden"; hidden.name = "confirm"; hidden.value = "yes";
        form.appendChild(hidden);
        form.dataset.confirmed = "1";
        if (typeof form.requestSubmit === "function") { form.requestSubmit(); } else { form.submit(); }
      } else { pendingForm = null; }
      dialog.returnValue = "";
    });
  }

  // ---- dashboard chart (plain canvas; data comes from the database) -------
  var box = document.getElementById("activityChart");
  if (box) {
    var data;
    try { data = JSON.parse(box.dataset.chart || "{}"); } catch (err) { data = {}; }
    var labels = data.labels || [];
    var series = [
      { key: "modified", color: "#EF4444" }, { key: "new", color: "#FB923C" },
      { key: "deleted", color: "#F472B6" }, { key: "errors", color: "#F59E0B" }
    ];
    var draw = function () {
      var canvas = box.querySelector("canvas");
      var dpr = window.devicePixelRatio || 1;
      var w = box.clientWidth, h = box.clientHeight;
      canvas.width = w * dpr; canvas.height = h * dpr;
      var c = canvas.getContext("2d");
      c.setTransform(dpr, 0, 0, dpr, 0, 0);
      c.clearRect(0, 0, w, h);
      var pad = { l: 34, r: 8, t: 10, b: 26 };
      var max = 1;
      series.forEach(function (s) { (data[s.key] || []).forEach(function (v) { if (v > max) { max = v; } }); });
      var plotW = w - pad.l - pad.r, plotH = h - pad.t - pad.b;
      c.strokeStyle = "#223452"; c.fillStyle = "#94A3B8"; c.font = "11px system-ui, sans-serif"; c.lineWidth = 1;
      var ticks = Math.min(4, max);
      for (var i = 0; i <= ticks; i++) {
        var val = Math.round(max * i / ticks);
        var y = pad.t + plotH - (plotH * i / ticks);
        c.beginPath(); c.moveTo(pad.l, y); c.lineTo(w - pad.r, y); c.stroke();
        c.textAlign = "right"; c.fillText(String(val), pad.l - 6, y + 4);
      }
      var groupW = plotW / labels.length;
      var barW = Math.max(3, Math.min(14, (groupW - 8) / series.length));
      labels.forEach(function (label, idx) {
        var x0 = pad.l + groupW * idx + (groupW - barW * series.length) / 2;
        series.forEach(function (s, j) {
          var v = (data[s.key] || [])[idx] || 0;
          var bh = plotH * v / max;
          c.fillStyle = s.color;
          c.fillRect(x0 + j * barW, pad.t + plotH - bh, barW - 1, bh);
        });
        c.fillStyle = "#94A3B8"; c.textAlign = "center";
        if (labels.length <= 12 || idx % 2 === 0) { c.fillText(label, pad.l + groupW * idx + groupW / 2, h - 8); }
      });
    };
    if (labels.length) {
      draw();
      var timer;
      window.addEventListener("resize", function () { clearTimeout(timer); timer = setTimeout(draw, 120); });
    }
  }

  // ---- live-filter helper: submit filter forms on select change ----------
  Array.prototype.forEach.call(document.querySelectorAll("form[data-autosubmit] select"), function (sel) {
    sel.addEventListener("change", function () { sel.form.submit(); });
  });
})();
