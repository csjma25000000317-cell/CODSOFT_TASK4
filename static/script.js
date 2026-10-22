
document.addEventListener("DOMContentLoaded", () => {
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => document.querySelectorAll(selector);

  const sidebar = $("#sidebar");
  const toast = $("#toast");
  let toastTimer;
  let protocolChart = null;
  let currentPage = "overview";

  const pageNames = {
    overview: "Overview",
    traffic: "Network Traffic",
    threats: "Threat Intelligence",
    rules: "Detection Rules",
    reports: "Reports & Logs",
    about: "About Project"
  };

  function showToast(message) {
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove("show"), 3000);
  }

  function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;"
    })[char]);
  }

  function formatTime(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return escapeHTML(value);
    return date.toLocaleString();
  }

  function shortTime(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    return date.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    });
  }

  async function apiRequest(url, options = {}) {
    const response = await fetch(url, {
      ...options,
      headers: {
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...(options.headers || {})
      }
    });

    const contentType = response.headers.get("content-type") || "";
    const data = contentType.includes("application/json")
      ? await response.json()
      : await response.text();

    if (!response.ok) {
      throw new Error(data?.error || `Request failed (${response.status})`);
    }

    return data;
  }

  function navigate(page) {
    if (!pageNames[page]) return;

    currentPage = page;

    $$(".page").forEach((section) => {
      section.classList.toggle("active", section.id === `page-${page}`);
    });

    $$(".nav-item[data-page]").forEach((button) => {
      const active = button.dataset.page === page;
      button.classList.toggle("active", active);
      if (active) {
        button.setAttribute("aria-current", "page");
      } else {
        button.removeAttribute("aria-current");
      }
    });

    const breadcrumb = $("#page-breadcrumb");
    if (breadcrumb) {
      breadcrumb.innerHTML = `Workspace <span> / </span> <strong>${escapeHTML(pageNames[page])}</strong>`;
    }

    if (sidebar) sidebar.classList.remove("open");

    if (page === "overview") refreshDashboard();
    if (page === "traffic") refreshEvents();
    if (page === "threats") refreshAlerts();
    if (page === "reports") refreshReportCounts();

    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  $$(".nav-item[data-page]").forEach((button) => {
    button.addEventListener("click", () => navigate(button.dataset.page));
  });

  $$("[data-go]").forEach((button) => {
    button.addEventListener("click", () => navigate(button.dataset.go));
  });

  const menuToggle = $("#menu-toggle");
  if (menuToggle && sidebar) {
    menuToggle.addEventListener("click", () => {
      sidebar.classList.toggle("open");
    });
  }

  document.addEventListener("click", (event) => {
    if (
      sidebar &&
      sidebar.classList.contains("open") &&
      !sidebar.contains(event.target) &&
      !event.target.closest("#menu-toggle")
    ) {
      sidebar.classList.remove("open");
    }
  });

  function updateText(selector, value) {
    const element = $(selector);
    if (element) element.textContent = value;
  }

  function renderProtocolChart(protocols = {}) {
    const canvas = $("#protocol-chart");
    const emptyMessage = $("#chart-empty");

    if (!canvas || typeof Chart === "undefined") {
      if (emptyMessage) {
        emptyMessage.textContent = "Chart library unavailable. Check your internet connection.";
      }
      return;
    }

    const labels = ["TCP", "UDP", "ICMP"];
    const values = labels.map((name) => Number(protocols[name] || 0));
    const hasData = values.some((value) => value > 0);

    if (emptyMessage) {
      emptyMessage.style.display = hasData ? "none" : "block";
      emptyMessage.textContent = hasData
        ? ""
        : "No traffic events yet. Analyze a sample event to populate this chart.";
    }

    if (protocolChart) {
      protocolChart.data.labels = labels;
      protocolChart.data.datasets[0].data = values;
      protocolChart.update();
      return;
    }

    protocolChart = new Chart(canvas, {
      type: "doughnut",
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: ["#42e8e0", "#6488ff", "#ffbd69"],
          borderColor: "#101827",
          borderWidth: 4,
          hoverOffset: 7
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "70%",
        animation: {
          duration: 700,
          animateRotate: true
        },
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color: "#a8b7ce",
              padding: 18,
              usePointStyle: true,
              pointStyle: "circle",
              font: { family: "Inter", size: 11 }
            }
          },
          tooltip: {
            callbacks: {
              label(context) {
                return ` ${context.label}: ${context.raw} events`;
              }
            }
          }
        }
      }
    });
  }

  function renderRecentEvents(events = []) {
    const container = $("#recent-events");
    if (!container) return;

    if (!events.length) {
      container.innerHTML = `
        <div class="empty-state">
          <span class="empty-icon">⌁</span>
          No events recorded yet.<br>
          Analyze a sample network event to get started.
        </div>`;
      return;
    }

    container.innerHTML = events.slice(0, 5).map((event) => `
      <div class="activity-item">
        <div class="activity-icon">⌁</div>
        <div class="activity-content">
          <div class="activity-title">${escapeHTML(event.protocol)} traffic event</div>
          <div class="activity-meta">
            ${escapeHTML(event.src_ip)} → ${escapeHTML(event.dst_ip)}
            · Port ${escapeHTML(event.dst_port)}
          </div>
        </div>
        <div class="activity-time">${escapeHTML(shortTime(event.timestamp))}</div>
      </div>
    `).join("");
  }

  async function refreshDashboard() {
    try {
      const [status, events] = await Promise.all([
        apiRequest("/api/status"),
        apiRequest("/api/events")
      ]);

      updateText("#total-events", status.total_events ?? 0);
      updateText("#total-alerts", status.total_alerts ?? 0);
      updateText("#tcp-events", status.protocols?.TCP ?? 0);
      updateText("#udp-events", status.protocols?.UDP ?? 0);

      const engineStatus = $("#engine-status");
      if (engineStatus) {
        engineStatus.textContent = status.status === "ready" ? "Engine Ready" : "Unavailable";
      }

      const alertCount = $("#nav-alert-count");
      if (alertCount) {
        const count = Number(status.total_alerts || 0);
        alertCount.textContent = count;
        alertCount.style.display = count ? "inline-flex" : "none";
      }

      renderProtocolChart(status.protocols || {});
      renderRecentEvents(events);
      refreshReportCounts(status, events);
    } catch (error) {
      console.error("Dashboard refresh failed:", error);
      showToast("Could not load dashboard. Check that the Flask server is running.");
    }
  }

  function renderEventsTable(events = []) {
    const tbody = $("#traffic-events");
    if (!tbody) return;

    if (!events.length) {
      tbody.innerHTML = `
        <tr><td colspan="6">
          <div class="empty-state">No traffic events yet. Use the analysis form above.</div>
        </td></tr>`;
      return;
    }

    tbody.innerHTML = events.map((event) => `
      <tr>
        <td>${escapeHTML(formatTime(event.timestamp))}</td>
        <td class="code-text">${escapeHTML(event.src_ip)}</td>
        <td class="code-text">${escapeHTML(event.dst_ip)}</td>
        <td><span class="pill">${escapeHTML(event.protocol)}</span></td>
        <td>${escapeHTML(event.dst_port)}</td>
        <td>${escapeHTML(event.source || "network-event")}</td>
      </tr>
    `).join("");
  }

  async function refreshEvents() {
    const button = $("#traffic-refresh");
    if (button) button.classList.add("loading");

    try {
      const events = await apiRequest("/api/events");
      renderEventsTable(events);
    } catch (error) {
      showToast(error.message || "Could not load network events.");
    } finally {
      if (button) button.classList.remove("loading");
    }
  }

  function severityClass(severity) {
    const value = String(severity || "LOW").toLowerCase();
    return ["low", "medium", "high", "critical"].includes(value) ? value : "low";
  }

  function renderAlertsTable(alerts = []) {
    const tbody = $("#alerts-table");
    if (!tbody) return;

    if (!alerts.length) {
      tbody.innerHTML = `
        <tr><td colspan="6">
          <div class="empty-state">No alerts recorded. This does not mean all network activity is safe.</div>
        </td></tr>`;
      return;
    }

    tbody.innerHTML = alerts.map((alert) => `
      <tr>
        <td>${escapeHTML(formatTime(alert.timestamp))}</td>
        <td><span class="severity ${severityClass(alert.severity)}">${escapeHTML(alert.severity)}</span></td>
        <td>${escapeHTML(alert.type)}</td>
        <td class="code-text">${escapeHTML(alert.src_ip)}</td>
        <td class="code-text">${escapeHTML(alert.dst_ip)}</td>
        <td>${escapeHTML(alert.description)}</td>
      </tr>
    `).join("");
  }

  async function refreshAlerts() {
    const button = $("#alerts-refresh");
    if (button) button.classList.add("loading");

    try {
      const alerts = await apiRequest("/api/alerts");
      renderAlertsTable(alerts);
      updateText("#alert-summary", `${alerts.length} alert(s) recorded`);
      updateText("#nav-alert-count", alerts.length);
    } catch (error) {
      showToast(error.message || "Could not load alerts.");
    } finally {
      if (button) button.classList.remove("loading");
    }
  }

  function refreshReportCounts(status, events) {
    if (status && events) {
      updateText("#report-events", events.length);
      updateText("#report-alerts", status.total_alerts ?? 0);
      return;
    }

    Promise.all([
      apiRequest("/api/status"),
      apiRequest("/api/events")
    ]).then(([latestStatus, latestEvents]) => {
      updateText("#report-events", latestStatus.total_events ?? latestEvents.length);
      updateText("#report-alerts", latestStatus.total_alerts ?? 0);
    }).catch((error) => {
      console.warn("Report counts unavailable:", error);
    });
  }

  const analyzeForm = $("#analyze-form");
  if (analyzeForm) {
    analyzeForm.addEventListener("submit", async (event) => {
      event.preventDefault();

      const submitButton = analyzeForm.querySelector('[type="submit"]');
      const resultBox = $("#analysis-result");
      const formData = new FormData(analyzeForm);

      const payload = {
        src_ip: String(formData.get("src_ip") || "").trim(),
        dst_ip: String(formData.get("dst_ip") || "").trim(),
        protocol: String(formData.get("protocol") || "TCP").toUpperCase(),
        dst_port: Number(formData.get("dst_port") || 0)
      };

      if (!payload.src_ip || !payload.dst_ip) {
        showResult("Please enter both source and destination IP addresses.", "error");
        return;
      }

      if (!Number.isInteger(payload.dst_port) ||
          payload.dst_port < 0 || payload.dst_port > 65535) {
        showResult("Destination port must be a whole number from 0 to 65535.", "error");
        return;
      }

      if (submitButton) {
        submitButton.disabled = true;
        submitButton.classList.add("loading");
      }

      try {
        const result = await apiRequest("/api/analyze", {
          method: "POST",
          body: JSON.stringify(payload)
        });

        if (result.alert) {
          showResult(
            `Event analyzed. Detection alert: ${result.alert.type} (${result.alert.severity}). ${result.alert.description}`,
            "warning"
          );
        } else {
          showResult(
            "Event analyzed successfully. No configured detection threshold was triggered for this event.",
            "success"
          );
        }

        await Promise.all([refreshDashboard(), refreshEvents(), refreshAlerts()]);
      } catch (error) {
        showResult(error.message || "Event analysis failed.", "error");
      } finally {
        if (submitButton) {
          submitButton.disabled = false;
          submitButton.classList.remove("loading");
        }
      }
    });
  }

  function showResult(message, type) {
    const resultBox = $("#analysis-result");
    if (!resultBox) {
      showToast(message);
      return;
    }

    resultBox.textContent = message;
    resultBox.className = `result-box visible ${type}`;
  }

  const refreshButton = $("#refresh-btn");
  if (refreshButton) {
    refreshButton.addEventListener("click", async () => {
      refreshButton.classList.add("loading");
      await Promise.all([refreshDashboard(), refreshEvents(), refreshAlerts()]);
      refreshButton.classList.remove("loading");
      showToast("Dashboard data refreshed.");
    });
  }

  const trafficRefresh = $("#traffic-refresh");
  if (trafficRefresh) {
    trafficRefresh.addEventListener("click", refreshEvents);
  }

  const alertsRefresh = $("#alerts-refresh");
  if (alertsRefresh) {
    alertsRefresh.addEventListener("click", refreshAlerts);
  }

  // Export is handled by the Flask CSV endpoint through the report page link.
  const exportLink = $('[href="/api/export"]');
  if (exportLink) {
    exportLink.addEventListener("click", () => {
      showToast("Preparing CSV event report…");
    });
  }

  // Initial load and lightweight refresh while the dashboard is open.
  refreshDashboard();
  refreshEvents();
  refreshAlerts();

  window.setInterval(() => {
    if (document.visibilityState !== "visible") return;
    if (currentPage === "overview") refreshDashboard();
    if (currentPage === "traffic") refreshEvents();
    if (currentPage === "threats") refreshAlerts();
  }, 10000);
});
