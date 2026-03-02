let token = "";
let chart = null;

function fmtTime(epoch) {
  const d = new Date(epoch * 1000);
  return d.toLocaleString();
}

function pill(sev) {
  const cls = sev || "info";
  return `<span class="pill ${cls}">${cls}</span>`;
}

async function login() {
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value.trim();

  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });

  const el = document.getElementById("loginStatus");
  if (!res.ok) {
    el.textContent = "Login failed";
    return;
  }

  const data = await res.json();
  token = data.token;
  el.textContent = "Logged in";
  await refreshAll();
  setInterval(refreshAll, 5000);
}

function getFilters() {
  return {
    severity: document.getElementById("severity").value,
    label: document.getElementById("label").value,
    src_ip: document.getElementById("src_ip").value.trim(),
    dst_ip: document.getElementById("dst_ip").value.trim(),
    minutes: document.getElementById("minutes").value
  };
}

async function apiGet(path) {
  const res = await fetch(path, {
    headers: { "Authorization": `Bearer ${token}` }
  });
  if (!res.ok) throw new Error("api error");
  return await res.json();
}

async function refreshAll() {
  if (!token) return;
  await Promise.all([loadDetections(), loadStats()]);
}

async function loadDetections() {
  const f = getFilters();
  const qs = new URLSearchParams({
    limit: "250",
    minutes: f.minutes,
    severity: f.severity,
    label: f.label,
    src_ip: f.src_ip,
    dst_ip: f.dst_ip
  });

  const data = await apiGet(`/api/detections?${qs.toString()}`);
  const tbody = document.getElementById("rows");
  tbody.innerHTML = "";

  for (const item of data.items) {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.onclick = () => loadDetail(item.id);

    tr.innerHTML = `
      <td>${fmtTime(item.ts_epoch)}</td>
      <td>${pill(item.severity)}</td>
      <td>${item.label}</td>
      <td>${(item.src_ip || "")}:${(item.src_port || "")}</td>
      <td>${(item.dst_ip || "")}:${(item.dst_port || "")}</td>
      <td>${item.proto || ""}</td>
      <td>${(item.score ?? 0).toFixed(4)}</td>
      <td>${item.corr_reason || ""}</td>
    `;
    tbody.appendChild(tr);
  }
}

async function loadDetail(id) {
  const data = await apiGet(`/api/detections/${id}`);
  document.getElementById("detailHint").style.display = "none";
  const pre = document.getElementById("detail");
  pre.style.display = "block";
  pre.textContent = JSON.stringify(data, null, 2);
}

async function loadStats() {
  const f = getFilters();
  const data = await apiGet(`/api/stats?minutes=${encodeURIComponent(f.minutes)}`);

  const labels = data.anomalies_per_minute.map(x => new Date(x.t * 1000).toLocaleTimeString());
  const values = data.anomalies_per_minute.map(x => x.count);

  const ctx = document.getElementById("chart1").getContext("2d");
  if (chart) chart.destroy();
  chart = new Chart(ctx, {
    type: "line",
    data: {
      labels: labels,
      datasets: [{ label: "anomalies", data: values }]
    },
    options: {
      responsive: true,
      animation: false,
      scales: { y: { beginAtZero: true } }
    }
  });

  const topSources = document.getElementById("topSources");
  topSources.innerHTML = data.top_sources.map(x => `<div>${x.src_ip} : ${x.count}</div>`).join("");

  const topPorts = document.getElementById("topPorts");
  topPorts.innerHTML = data.top_ports.map(x => `<div>${x.dst_port} : ${x.count}</div>`).join("");
}
