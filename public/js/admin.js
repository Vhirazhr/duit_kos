(() => {
  "use strict";

  const state = {
    currentView: "overview",
    currentAdmin: null,
    users: { page: 1, limit: 20, total: 0 },
    logins: { page: 1, limit: 30, total: 0 },
    audit: { page: 1, limit: 40, total: 0 },
    categories: [],
  };

  const viewMeta = {
    overview: {
      title: "Ringkasan Sistem",
      subtitle: "Pantau platform tanpa membuka isi keuangan pribadi pengguna.",
    },
    users: {
      title: "Manajemen Pengguna",
      subtitle: "Kelola status akun, role, Telegram, dan session pengguna.",
    },
    reviews: {
      title: "Ulasan Landing",
      subtitle: "Komentar langsung tampil. Admin dapat menyembunyikan atau menghapusnya.",
    },
    security: {
      title: "Keamanan Sistem",
      subtitle: "Lihat login, IP, perangkat, dan aktivitas yang perlu diperiksa.",
    },
    categories: {
      title: "Kategori Bawaan",
      subtitle: "Atur kategori yang akan disalin ke akun pengguna baru.",
    },
    services: {
      title: "Status Layanan",
      subtitle: "Periksa koneksi layanan utama VHYROX.",
    },
    settings: {
      title: "Pengaturan Sistem",
      subtitle: "Kelola fitur platform tanpa menampilkan secret atau token.",
    },
    audit: {
      title: "Audit Log Admin",
      subtitle: "Setiap tindakan penting admin tercatat di sini.",
    },
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function formatNumber(value) {
    return Number(value || 0).toLocaleString("id-ID");
  }

  function formatDate(value, includeTime = true) {
    if (!value) return "-";

    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);

    return new Intl.DateTimeFormat("id-ID", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      ...(includeTime
        ? { hour: "2-digit", minute: "2-digit", hour12: false }
        : {}),
    }).format(date);
  }

  function buildReminderHourOptions() {
  const select = $("#reminderHourSelect");

  if (!select) {
    return;
  }

  const periodLabel = (hour) => {
    if (hour === 0) return "tengah malam";
    if (hour >= 1 && hour < 6) return "dini hari";
    if (hour >= 6 && hour < 11) return "pagi";
    if (hour >= 11 && hour < 15) return "siang";
    if (hour >= 15 && hour < 18) return "sore";
    return "malam";
  };

  select.innerHTML = Array.from(
    { length: 24 },
    (_, hour) => {
      const label =
        `${String(hour).padStart(2, "0")}.00 ` +
        `${periodLabel(hour)}`;

      return `
        <option value="${hour}">
          ${label}
        </option>
      `;
    },
  ).join("");
}

function toDateTimeLocal(value) {
  const raw = String(value || "").trim();

  if (!raw) {
    return "";
  }

  return raw
    .replace(" ", "T")
    .slice(0, 16);
}

  function initials(value) {
    const words = String(value || "A").trim().split(/\s+/).filter(Boolean);
    return words.slice(0, 2).map((word) => word[0]).join("").toUpperCase() || "A";
  }

  function avatarHtml(user, className = "table-avatar") {
    const name = user?.nama || user?.reviewer_name || "User";
    const url = String(user?.avatar_url || "").trim();

    if (url) {
      return `<span class="${className}"><img src="${escapeHtml(url)}" alt="" referrerpolicy="no-referrer"></span>`;
    }

    return `<span class="${className}">${escapeHtml(initials(name))}</span>`;
  }

  function badge(text, className = "") {
    return `<span class="badge ${escapeHtml(className)}">${escapeHtml(text)}</span>`;
  }

  let toastTimer = null;

  function showToast(message, type = "success") {
    const toast = $("#toast");
    toast.textContent = String(message || "Selesai");
    toast.className = `toast show${type === "error" ? " error" : ""}`;

    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toast.className = "toast";
    }, 3500);
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...(options.headers || {}),
      },
      ...options,
    });

    const raw = await response.text();
    let data = {};

    if (raw) {
      try {
        data = JSON.parse(raw);
      } catch {
        data = { error: raw };
      }
    }

    if (response.status === 401) {
      window.location.href = "/login.html?returnTo=%2Fadmin";
      throw new Error("Sesi login berakhir.");
    }

    if (!response.ok) {
      throw new Error(data.error || "Permintaan gagal diproses.");
    }

    return data;
  }

  function debounce(fn, wait = 350) {
    let timer;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), wait);
    };
  }

  async function loadSession() {
    const data = await api("/api/auth/session");

    if (!data.authenticated || String(data.user?.role || "") !== "admin") {
      document.body.innerHTML = "<main style='padding:40px;color:white'>Akses admin ditolak.</main>";
      throw new Error("Akses admin ditolak.");
    }

    state.currentAdmin = data.user;
    $("#adminName").textContent = data.user.nama || "Admin";
    $("#adminEmail").textContent = data.user.email || "";
    $("#adminAvatar").textContent = initials(data.user.nama);
  }

  function setView(view) {
    if (!viewMeta[view]) return;

    state.currentView = view;
    $$(".nav-item").forEach((item) => {
      item.classList.toggle("active", item.dataset.view === view);
    });
    $$(".view").forEach((item) => {
      item.classList.toggle("active", item.id === `view-${view}`);
    });

    $("#pageTitle").textContent = viewMeta[view].title;
    $("#pageSubtitle").textContent = viewMeta[view].subtitle;
    $("#sidebar").classList.remove("open");

    loadCurrentView().catch((error) => showToast(error.message, "error"));
  }

  async function loadCurrentView() {
    switch (state.currentView) {
      case "overview": return loadOverview();
      case "users": return loadUsers();
      case "reviews": return loadReviews();
      case "security": return loadSecurityEvents();
      case "categories": return loadCategories();
      case "services": return loadServices();
      case "settings": return loadSettings();
      case "audit": return loadAuditLogs();
      default: return undefined;
    }
  }

  async function loadOverview() {
    const data = await api("/api/admin/summary");
    const users = data.users || {};
    const reviews = data.reviews || {};
    const logins = data.logins || {};
    const security = data.security || {};

    const cards = [
      ["♟", "Total Pengguna", users.total_users, `${formatNumber(users.new_users_month)} baru bulan ini`],
      ["✓", "Pengguna Aktif", users.active_users, `${formatNumber(users.inactive_users)} akun nonaktif`],
      ["▤", "Total Transaksi", data.transactions?.total_transactions, "Jumlah catatan, tanpa membuka isinya"],
      ["★", "Ulasan Landing", reviews.published_reviews, `${formatNumber(reviews.hidden_reviews)} disembunyikan`],
      ["↗", "Login Hari Ini", logins.successful_logins_today, `${formatNumber(logins.failed_logins_24h)} gagal dalam 24 jam`],
      ["⌁", "Peringatan Aktif", security.open_events, `${formatNumber(security.high_risk_events)} berisiko tinggi`],
      ["✈", "Telegram Terhubung", users.telegram_connected, "Akun dengan bot aktif"],
      ["♜", "Admin Aktif", users.admin_users, "Pengelola sistem"],
    ];

    $("#summaryCards").innerHTML = cards.map(([icon, label, value, note]) => `
      <article class="stat-card">
        <div class="stat-icon">${icon}</div>
        <p class="stat-label">${escapeHtml(label)}</p>
        <h2 class="stat-value">${formatNumber(value)}</h2>
        <p class="stat-note">${escapeHtml(note)}</p>
      </article>
    `).join("");

    $("#recentUsers").innerHTML = data.recent_users?.length
      ? data.recent_users.map((user) => `
          <div class="stack-item">
            ${avatarHtml(user)}
            <div class="content">
              <strong>${escapeHtml(user.nama)}</strong>
              <span>${escapeHtml(user.email)} · bergabung ${escapeHtml(formatDate(user.created_at, false))}</span>
            </div>
            ${badge(user.role === "admin" ? "Admin" : "User", user.role)}
          </div>
        `).join("")
      : '<div class="empty-state">Belum ada pengguna.</div>';

    $("#securitySummary").innerHTML = `
      <div class="security-box"><strong>${formatNumber(logins.failed_logins_24h)}</strong><span>Login gagal 24 jam</span></div>
      <div class="security-box"><strong>${formatNumber(security.open_events)}</strong><span>Peringatan belum selesai</span></div>
      <div class="security-box"><strong>${formatNumber(security.high_risk_events)}</strong><span>Risiko tinggi/kritis</span></div>
      <div class="security-box"><strong>${formatNumber(users.login_today)}</strong><span>User login hari ini</span></div>
    `;
  }

  function renderPagination(container, pagination, onChange) {
    const totalPages = Math.max(1, Math.ceil(pagination.total / pagination.limit));
    container.innerHTML = `
      <button class="small-button" data-page="prev" ${pagination.page <= 1 ? "disabled" : ""}>←</button>
      <span>Halaman ${pagination.page} dari ${totalPages} · ${formatNumber(pagination.total)} data</span>
      <button class="small-button" data-page="next" ${pagination.page >= totalPages ? "disabled" : ""}>→</button>
    `;

    container.onclick = (event) => {
      const button = event.target.closest("[data-page]");
      if (!button || button.disabled) return;
      const nextPage = button.dataset.page === "prev"
        ? pagination.page - 1
        : pagination.page + 1;
      onChange(nextPage);
    };
  }

  async function loadUsers() {
    const search = $("#userSearch").value.trim();
    const role = $("#userRoleFilter").value;
    const status = $("#userStatusFilter").value;
    const params = new URLSearchParams({
      page: state.users.page,
      limit: state.users.limit,
      status,
    });
    if (search) params.set("search", search);
    if (role) params.set("role", role);

    const data = await api(`/api/admin/users?${params}`);
    state.users.total = data.total;

    $("#usersTableBody").innerHTML = data.users.length
      ? data.users.map((user) => {
          const isSelf = Number(user.id) === Number(state.currentAdmin?.id);
          return `
            <tr>
              <td>
                <div class="user-cell">
                  ${avatarHtml(user)}
                  <div>
                    <strong>${escapeHtml(user.nama)}</strong>
                    <span>#${user.id} · ${escapeHtml(user.email)}</span>
                  </div>
                </div>
              </td>
              <td>${badge(user.role === "admin" ? "Admin" : "User", user.role)}</td>
              <td>${badge(user.is_active ? "Aktif" : "Nonaktif", user.is_active ? "active" : "inactive")}</td>
              <td>
                ${formatNumber(user.total_transactions)} transaksi<br>
                <span style="color:var(--muted)">${formatNumber(user.active_sessions)} session · ${formatNumber(user.open_security_events)} alert</span>
              </td>
              <td>${escapeHtml(formatDate(user.last_login_at))}</td>
              <td>
                <div class="actions">
                  <button class="small-button" data-user-action="role" data-id="${user.id}" data-role="${user.role}" ${isSelf ? "disabled" : ""}>${user.role === "admin" ? "Jadikan User" : "Jadikan Admin"}</button>
                  <button class="small-button" data-user-action="status" data-id="${user.id}" data-active="${user.is_active}" ${isSelf ? "disabled" : ""}>${user.is_active ? "Nonaktifkan" : "Aktifkan"}</button>
                  ${user.telegram_connected ? `<button class="small-button" data-user-action="telegram" data-id="${user.id}">Putus Telegram</button>` : ""}
                  <button class="danger-button" data-user-action="logout" data-id="${user.id}" ${isSelf ? "disabled" : ""}>Paksa Logout</button>
                </div>
              </td>
            </tr>
          `;
        }).join("")
      : '<tr><td colspan="6"><div class="empty-state">Pengguna tidak ditemukan.</div></td></tr>';

    renderPagination($("#usersPagination"), state.users, (page) => {
      state.users.page = page;
      loadUsers().catch((error) => showToast(error.message, "error"));
    });
  }

  async function handleUserAction(button) {
    const id = Number(button.dataset.id);
    const action = button.dataset.userAction;

    if (action === "role") {
      const nextRole = button.dataset.role === "admin" ? "user" : "admin";
      if (!confirm(`Ubah role pengguna menjadi ${nextRole}? Pengguna akan logout.`)) return;
      await api(`/api/admin/users/${id}/role`, {
        method: "PATCH",
        body: JSON.stringify({ role: nextRole }),
      });
    }

    if (action === "status") {
      const nextActive = button.dataset.active !== "true";
      if (!confirm(nextActive ? "Aktifkan akun ini?" : "Nonaktifkan akun dan cabut seluruh session?")) return;
      await api(`/api/admin/users/${id}/status`, {
        method: "PATCH",
        body: JSON.stringify({ is_active: nextActive }),
      });
    }

    if (action === "telegram") {
      if (!confirm("Putuskan koneksi Telegram pengguna ini?")) return;
      await api(`/api/admin/users/${id}/disconnect-telegram`, {
        method: "POST",
        body: JSON.stringify({}),
      });
    }

    if (action === "logout") {
      if (!confirm("Paksa logout seluruh perangkat pengguna ini?")) return;
      await api(`/api/admin/users/${id}/force-logout`, {
        method: "POST",
        body: JSON.stringify({}),
      });
    }

    showToast("Perubahan pengguna berhasil disimpan.");
    await loadUsers();
  }

  async function loadReviews() {
    const params = new URLSearchParams({
      status: $("#reviewStatusFilter").value,
    });
    const search = $("#reviewSearch").value.trim();
    if (search) params.set("search", search);

    const data = await api(`/api/admin/reviews?${params}`);

    $("#reviewsGrid").innerHTML = data.reviews.length
      ? data.reviews.map((review) => {
          const statusLabel = review.status === "published"
            ? "Tampil"
            : review.status === "hidden"
              ? "Disembunyikan"
              : "Dihapus";
          const stars = "★".repeat(review.rating) + "☆".repeat(5 - review.rating);

          return `
            <article class="review-card">
              <div class="review-top">
                <div>
                  <div class="stars">${stars}</div>
                  <div style="margin-top:8px">${badge(statusLabel, review.status)} ${review.is_featured ? badge("Unggulan", "admin") : ""}</div>
                </div>
                ${avatarHtml(review)}
              </div>
              <p class="review-text">${escapeHtml(review.review_text)}</p>
              <div class="review-meta">
                <span>${escapeHtml(review.nama)}<br>${escapeHtml(review.email)}</span>
                <span>${escapeHtml(formatDate(review.updated_at))}</span>
              </div>
              <div class="review-actions">
                ${review.status !== "published" ? `<button class="small-button" data-review-action="status" data-status="published" data-id="${review.id}">Tampilkan</button>` : ""}
                ${review.status === "published" ? `<button class="small-button" data-review-action="status" data-status="hidden" data-id="${review.id}">Sembunyikan</button>` : ""}
                ${review.status !== "deleted" ? `<button class="danger-button" data-review-action="status" data-status="deleted" data-id="${review.id}">Hapus</button>` : ""}
                ${review.status === "published" ? `<button class="small-button" data-review-action="featured" data-featured="${!review.is_featured}" data-id="${review.id}">${review.is_featured ? "Batal Unggulan" : "Jadikan Unggulan"}</button>` : ""}
              </div>
            </article>
          `;
        }).join("")
      : '<div class="empty-state" style="grid-column:1/-1">Belum ada ulasan pada filter ini.</div>';
  }

  async function handleReviewAction(button) {
    const id = Number(button.dataset.id);
    const action = button.dataset.reviewAction;

    if (action === "status") {
      const status = button.dataset.status;
      const message = status === "deleted"
        ? "Hapus komentar ini dari landing? Data tetap tersimpan sebagai audit."
        : status === "hidden"
          ? "Sembunyikan komentar ini dari landing?"
          : "Tampilkan komentar ini di landing?";
      if (!confirm(message)) return;

      await api(`/api/admin/reviews/${id}/status`, {
        method: "PATCH",
        body: JSON.stringify({ status }),
      });
    }

    if (action === "featured") {
      await api(`/api/admin/reviews/${id}/featured`, {
        method: "PATCH",
        body: JSON.stringify({ is_featured: button.dataset.featured === "true" }),
      });
    }

    showToast("Ulasan berhasil diperbarui.");
    await loadReviews();
  }

  async function loadSecurityEvents() {
    const params = new URLSearchParams({
      resolved: $("#securityResolvedFilter").value,
      severity: $("#securitySeverityFilter").value,
    });
    const data = await api(`/api/admin/security-events?${params}`);

    $("#securityEventsList").innerHTML = data.events.length
      ? data.events.map((event) => `
          <article class="event-card" data-severity="${escapeHtml(event.severity)}">
            <span class="event-indicator"></span>
            <div>
              <h3>${escapeHtml(event.title)}</h3>
              <p>${escapeHtml(event.description || "Tidak ada keterangan.")}</p>
              <div class="event-meta">
                ${badge(event.severity.toUpperCase(), event.severity)}
                <span>${escapeHtml(event.nama || event.email || "Pengguna tidak diketahui")}</span>
                <span>IP ${escapeHtml(event.ip_address || "-")}</span>
                <span>${escapeHtml(formatDate(event.created_at))}</span>
              </div>
            </div>
            <button class="small-button" data-security-action="resolve" data-id="${event.id}" data-resolved="${!event.is_resolved}">${event.is_resolved ? "Buka Kembali" : "Tandai Selesai"}</button>
          </article>
        `).join("")
      : '<div class="empty-state">Tidak ada peringatan pada filter ini.</div>';
  }

  async function loadLoginActivity() {
    const params = new URLSearchParams({
      page: state.logins.page,
      limit: state.logins.limit,
      status: $("#loginStatusFilter").value,
    });
    const search = $("#loginSearch").value.trim();
    if (search) params.set("search", search);

    const data = await api(`/api/admin/login-activity?${params}`);
    state.logins.total = data.total;

    $("#loginTableBody").innerHTML = data.activities.length
      ? data.activities.map((item) => `
          <tr>
            <td>${escapeHtml(formatDate(item.created_at))}</td>
            <td>
              <strong>${escapeHtml(item.nama || item.email_attempted || "Tidak diketahui")}</strong><br>
              <span style="color:var(--muted)">${escapeHtml(item.email || item.email_attempted || "-")}</span>
            </td>
            <td>
              ${escapeHtml(item.ip_address)}<br>
              <span style="color:var(--muted)">${escapeHtml(item.location_label)} · lokasi perkiraan</span>
            </td>
            <td>${escapeHtml(item.device_type || "-")}<br><span style="color:var(--muted)">${escapeHtml(item.browser || "-")} · ${escapeHtml(item.operating_system || "-")}</span></td>
            <td>${escapeHtml(item.provider || "-")}</td>
            <td>${badge(item.status === "success" ? "Berhasil" : "Gagal", item.status)}${item.failure_reason ? `<br><span style="color:var(--muted)">${escapeHtml(item.failure_reason)}</span>` : ""}</td>
          </tr>
        `).join("")
      : '<tr><td colspan="6"><div class="empty-state">Belum ada aktivitas login.</div></td></tr>';

    renderPagination($("#loginPagination"), state.logins, (page) => {
      state.logins.page = page;
      loadLoginActivity().catch((error) => showToast(error.message, "error"));
    });
  }

  async function handleSecurityAction(button) {
    await api(`/api/admin/security-events/${Number(button.dataset.id)}/resolve`, {
      method: "PATCH",
      body: JSON.stringify({ resolved: button.dataset.resolved === "true" }),
    });
    showToast("Peringatan keamanan diperbarui.");
    await loadSecurityEvents();
  }

  async function loadCategories() {
    const data = await api("/api/admin/categories");
    state.categories = data.categories;

    $("#categoriesGrid").innerHTML = data.categories.length
      ? data.categories.map((category) => `
          <article class="category-card">
            <div style="display:flex;justify-content:space-between;gap:10px">
              <h3>${escapeHtml(category.nama)}</h3>
              ${badge(category.is_active ? "Aktif" : "Nonaktif", category.is_active ? "active" : "inactive")}
            </div>
            <p class="category-meta">${escapeHtml(category.jenis)} · prioritas ${category.prioritas}</p>
            <div class="alias-list">
              ${category.aliases.length
                ? category.aliases.slice(0, 12).map((alias) => `<span class="alias-chip">${escapeHtml(alias)}</span>`).join("")
                : '<span class="alias-chip">Tanpa alias</span>'}
              ${category.aliases.length > 12 ? `<span class="alias-chip">+${category.aliases.length - 12}</span>` : ""}
            </div>
            <div class="actions">
              <button class="small-button" data-category-edit="${category.id}">Ubah</button>
            </div>
          </article>
        `).join("")
      : '<div class="empty-state" style="grid-column:1/-1">Belum ada kategori bawaan.</div>';
  }

  function openCategoryModal(category = null) {
    const form = $("#categoryForm");
    form.reset();
    form.elements.id.value = category?.id || "";
    form.elements.nama.value = category?.nama || "";
    form.elements.jenis.value = category?.jenis || "pengeluaran";
    form.elements.prioritas.value = category?.prioritas || 100;
    form.elements.aliases.value = category?.aliases?.join(", ") || "";
    form.elements.is_active.checked = category ? Boolean(category.is_active) : true;
    $("#categoryModalTitle").textContent = category ? "Ubah Kategori" : "Tambah Kategori";
    $("#categoryModal").hidden = false;
  }

  function closeCategoryModal() {
    $("#categoryModal").hidden = true;
  }

  async function saveCategory(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const id = Number(form.elements.id.value || 0);
    const body = {
      nama: form.elements.nama.value,
      jenis: form.elements.jenis.value,
      prioritas: Number(form.elements.prioritas.value),
      aliases: form.elements.aliases.value,
      is_active: form.elements.is_active.checked,
    };

    await api(id ? `/api/admin/categories/${id}` : "/api/admin/categories", {
      method: id ? "PUT" : "POST",
      body: JSON.stringify(body),
    });

    closeCategoryModal();
    showToast("Kategori bawaan berhasil disimpan.");
    await loadCategories();
  }

  async function loadServices() {
    const data = await api("/api/admin/services");
    $("#serviceCheckedAt").textContent = `Pemeriksaan terakhir: ${formatDate(data.checked_at)}`;

    const labels = {
      database: ["Database", "MySQL dan penyimpanan data"],
      telegram: ["Telegram Bot", "Input transaksi dan notifikasi"],
      firebase: ["Firebase Auth", "Autentikasi akun"],
      smtp: ["SMTP Email", "Pengiriman OTP"],
      gemini: ["Gemini AI", "Konsultasi keuangan"],
      cron: ["Cron Reminder", "Jadwal pengingat otomatis"],
    };

    $("#servicesGrid").innerHTML = Object.entries(data.services).map(([key, service]) => `
      <article class="service-card" data-status="${escapeHtml(service.status)}">
        <span class="service-dot"></span>
        <h3>${escapeHtml(labels[key]?.[0] || key)}</h3>
        <p class="service-detail">${escapeHtml(labels[key]?.[1] || "")}</p>
        <div style="margin-top:14px">${badge(service.status, service.status)}</div>
        <p class="service-detail">${escapeHtml(service.detail || "-")}</p>
      </article>
    `).join("");
  }

async function loadSettings() {
  const data =
    await api("/api/admin/settings");

  const settings =
    data.settings || {};

  const form =
    $("#settingsForm");

  for (
    const [key, value]
    of Object.entries(settings)
  ) {
    const field =
      form.elements[key];

    if (!field) {
      continue;
    }

    if (
      key === "announcement_start_at" ||
      key === "announcement_end_at"
    ) {
      field.value =
        toDateTimeLocal(value);

      continue;
    }

    if (field.type === "checkbox") {
      field.checked =
        Boolean(value);
    } else {
      field.value =
        value ?? "";
    }
  }
}

  async function saveSettings(event) {
    event.preventDefault();
    const form = event.currentTarget;
   const body = {
  app_name:
    form.elements.app_name.value,

  announcement:
    form.elements.announcement.value,

  announcement_enabled:
    form.elements
      .announcement_enabled
      .checked,

  announcement_type:
    form.elements
      .announcement_type
      .value,

  announcement_start_at:
    form.elements
      .announcement_start_at
      .value || null,

  announcement_end_at:
    form.elements
      .announcement_end_at
      .value || null,

  maintenance_mode:
    form.elements
      .maintenance_mode
      .checked,

  registration_enabled:
    form.elements
      .registration_enabled
      .checked,

  ai_chat_enabled:
    form.elements
      .ai_chat_enabled
      .checked,

  telegram_enabled:
    form.elements
      .telegram_enabled
      .checked,

  reminder_enabled:
    form.elements
      .reminder_enabled
      .checked,

  reminder_hour:
    Number(
      form.elements
        .reminder_hour
        .value,
    ),

  ai_daily_limit:
    Number(
      form.elements
        .ai_daily_limit
        .value,
    ),

  max_transaction_amount:
    Number(
      form.elements
        .max_transaction_amount
        .value,
    ),
};

    await api("/api/admin/settings", {
      method: "PUT",
      body: JSON.stringify(body),
    });
    showToast("Pengaturan sistem berhasil disimpan.");
  }

  const AUDIT_ACTION_LABELS = {
    UPDATE_SYSTEM_SETTINGS: "Mengubah pengaturan sistem",
    CHANGE_REVIEW_STATUS: "Mengubah status ulasan",
    CHANGE_USER_ROLE: "Mengubah peran pengguna",
    ACTIVATE_USER: "Mengaktifkan pengguna",
    DEACTIVATE_USER: "Menonaktifkan pengguna",
    DISCONNECT_TELEGRAM: "Memutus koneksi Telegram",
    DELETE_USER_SESSIONS: "Mengeluarkan pengguna dari semua perangkat",
    CREATE_DEFAULT_CATEGORY: "Menambah kategori bawaan",
    UPDATE_DEFAULT_CATEGORY: "Mengubah kategori bawaan",
    RESOLVE_SECURITY_EVENT: "Menandai peringatan keamanan selesai",
  };

  const AUDIT_FIELD_LABELS = {
    status: "Status",
    is_featured: "Ulasan unggulan",
    role: "Peran",
    is_active: "Status akun",
    maintenance_mode: "Mode pemeliharaan",
    registration_enabled: "Pendaftaran pengguna",
    ai_chat_enabled: "AI Chat",
    telegram_enabled: "Telegram Bot",
    reminder_enabled: "Reminder tagihan",
    reminder_hour: "Jam reminder",
    ai_daily_limit: "Batas AI harian",
    max_transaction_amount: "Batas nominal transaksi",
    app_name: "Nama aplikasi",
    announcement: "Pengumuman sistem",
    nama: "Nama kategori",
    jenis: "Jenis kategori",
    prioritas: "Prioritas",
    announcement_enabled:
  "Tampilkan pengumuman",

announcement_type:
  "Jenis pengumuman",

announcement_start_at:
  "Mulai pengumuman",

announcement_end_at:
  "Selesai pengumuman",
  };

  const AUDIT_TARGET_LABELS = {
    review: "Ulasan",
    user: "Pengguna",
    settings: "Pengaturan sistem",
    category: "Kategori",
    security_event: "Peringatan keamanan",
  };

  function parseAuditData(value) {
    if (!value) return {};

    if (typeof value === "object") {
      return value;
    }

    try {
      const parsed = JSON.parse(value);
      return parsed && typeof parsed === "object" ? parsed : {};
    } catch {
      return { value: String(value) };
    }
  }

  function auditActionLabel(action) {
    const key = String(action || "").trim().toUpperCase();
    return AUDIT_ACTION_LABELS[key] || key
      .toLowerCase()
      .replace(/_/g, " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());
  }

  function auditTargetLabel(type, id) {
    const key = String(type || "").trim().toLowerCase();
    const label = AUDIT_TARGET_LABELS[key] || key || "Data";
    return id ? `${label} #${id}` : label;
  }

  function auditFieldLabel(field) {
    return AUDIT_FIELD_LABELS[field] || String(field || "")
      .replace(/_/g, " ")
      .replace(/\b\w/g, (letter) => letter.toUpperCase());
  }

  function auditValue(value, field = "") {
    if (value === null || value === undefined || value === "") return "Kosong";
    if (typeof value === "boolean") return value ? "Aktif" : "Tidak aktif";

    const normalized = String(value).toLowerCase();
    const valueLabels = {
      published: "Dipublikasikan",
      hidden: "Disembunyikan",
      deleted: "Dihapus",
      admin: "Admin",
      user: "Pengguna",
      pemasukan: "Pemasukan",
      pengeluaran: "Pengeluaran",
      true: "Aktif",
      false: "Tidak aktif",
    };

    if (field === "max_transaction_amount") {
      return `Rp${formatNumber(value)}`;
    }

    if (field === "reminder_hour") {
      return `${String(value).padStart(2, "0")}.00`;
    }

    return valueLabels[normalized] || String(value);
  }

  function renderAuditChanges(oldValue, newValue) {
    const oldData = parseAuditData(oldValue);
    const newData = parseAuditData(newValue);
    const fields = [...new Set([...Object.keys(oldData), ...Object.keys(newData)])];

    const changedFields = fields.filter(
      (field) => JSON.stringify(oldData[field]) !== JSON.stringify(newData[field])
    );

    if (changedFields.length === 0) {
      return '<span class="audit-no-change">Tidak ada perubahan nilai.</span>';
    }

    return `
      <div class="audit-change-list">
        ${changedFields.map((field) => `
          <div class="audit-change-row">
            <strong>${escapeHtml(auditFieldLabel(field))}</strong>
            <span class="audit-old-value">${escapeHtml(auditValue(oldData[field], field))}</span>
            <span class="audit-arrow">→</span>
            <span class="audit-new-value">${escapeHtml(auditValue(newData[field], field))}</span>
          </div>
        `).join("")}
      </div>
    `;
  }

  async function loadAuditLogs() {
    const params = new URLSearchParams({
      page: state.audit.page,
      limit: state.audit.limit,
    });
    const search = $("#auditSearch").value.trim();
    if (search) params.set("search", search);

    const data = await api(`/api/admin/audit-logs?${params}`);
    state.audit.total = data.total;

    $("#auditTableBody").innerHTML = data.logs.length
      ? data.logs.map((log) => `
          <tr>
            <td>${escapeHtml(formatDate(log.created_at))}</td>
            <td>
              <strong>${escapeHtml(log.admin_name)}</strong><br>
              <span style="color:var(--muted)">${escapeHtml(log.admin_email)}</span>
            </td>
            <td>${badge(auditActionLabel(log.action), "admin")}</td>
            <td>${escapeHtml(auditTargetLabel(log.target_type, log.target_id))}</td>
            <td>${escapeHtml(log.ip_address || "-")}</td>
            <td>
              <details class="audit-details">
                <summary>Lihat perubahan</summary>
                ${renderAuditChanges(log.old_data, log.new_data)}
              </details>
            </td>
          </tr>
        `).join("")
      : '<tr><td colspan="6"><div class="empty-state">Belum ada audit log.</div></td></tr>';

    renderPagination($("#auditPagination"), state.audit, (page) => {
      state.audit.page = page;
      loadAuditLogs().catch((error) => showToast(error.message, "error"));
    });
  }

  function bindEvents() {
    $$(".nav-item").forEach((item) => {
      item.addEventListener("click", () => setView(item.dataset.view));
    });

    $$('[data-jump]').forEach((item) => {
      item.addEventListener("click", () => setView(item.dataset.jump));
    });

    $("#menuButton").addEventListener("click", () => {
      $("#sidebar").classList.toggle("open");
    });

    $("#refreshButton").addEventListener("click", () => {
      loadCurrentView()
        .then(() => showToast("Data berhasil dimuat ulang."))
        .catch((error) => showToast(error.message, "error"));
    });

    const reloadUsers = debounce(() => {
      state.users.page = 1;
      loadUsers().catch((error) => showToast(error.message, "error"));
    });
    $("#userSearch").addEventListener("input", reloadUsers);
    $("#userRoleFilter").addEventListener("change", reloadUsers);
    $("#userStatusFilter").addEventListener("change", reloadUsers);
    $("#usersTableBody").addEventListener("click", (event) => {
      const button = event.target.closest("[data-user-action]");
      if (!button) return;
      handleUserAction(button).catch((error) => showToast(error.message, "error"));
    });

    const reloadReviews = debounce(() => loadReviews().catch((error) => showToast(error.message, "error")));
    $("#reviewSearch").addEventListener("input", reloadReviews);
    $("#reviewStatusFilter").addEventListener("change", reloadReviews);
    $("#reviewsGrid").addEventListener("click", (event) => {
      const button = event.target.closest("[data-review-action]");
      if (!button) return;
      handleReviewAction(button).catch((error) => showToast(error.message, "error"));
    });

    $$(".subtab").forEach((item) => {
      item.addEventListener("click", () => {
        $$(".subtab").forEach((tab) => tab.classList.toggle("active", tab === item));
        const target = item.dataset.securityTab;
        $("#security-events-pane").classList.toggle("active", target === "events");
        $("#security-logins-pane").classList.toggle("active", target === "logins");
        if (target === "events") loadSecurityEvents().catch((error) => showToast(error.message, "error"));
        else loadLoginActivity().catch((error) => showToast(error.message, "error"));
      });
    });

    $("#securityResolvedFilter").addEventListener("change", () => loadSecurityEvents().catch((error) => showToast(error.message, "error")));
    $("#securitySeverityFilter").addEventListener("change", () => loadSecurityEvents().catch((error) => showToast(error.message, "error")));
    $("#securityEventsList").addEventListener("click", (event) => {
      const button = event.target.closest("[data-security-action]");
      if (!button) return;
      handleSecurityAction(button).catch((error) => showToast(error.message, "error"));
    });

    const reloadLogins = debounce(() => {
      state.logins.page = 1;
      loadLoginActivity().catch((error) => showToast(error.message, "error"));
    });
    $("#loginSearch").addEventListener("input", reloadLogins);
    $("#loginStatusFilter").addEventListener("change", reloadLogins);

    $("#addCategoryButton").addEventListener("click", () => openCategoryModal());
    $("#categoriesGrid").addEventListener("click", (event) => {
      const button = event.target.closest("[data-category-edit]");
      if (!button) return;
      const category = state.categories.find((item) => Number(item.id) === Number(button.dataset.categoryEdit));
      openCategoryModal(category);
    });
    $("#closeCategoryModal").addEventListener("click", closeCategoryModal);
    $("#cancelCategoryModal").addEventListener("click", closeCategoryModal);
    $("#categoryModal").addEventListener("click", (event) => {
      if (event.target === $("#categoryModal")) closeCategoryModal();
    });
    $("#categoryForm").addEventListener("submit", (event) => {
      saveCategory(event).catch((error) => showToast(error.message, "error"));
    });

    $("#checkServicesButton").addEventListener("click", () => {
      loadServices()
        .then(() => showToast("Status layanan selesai diperiksa."))
        .catch((error) => showToast(error.message, "error"));
    });

    $("#settingsForm").addEventListener("submit", (event) => {
      saveSettings(event).catch((error) => showToast(error.message, "error"));
    });

    const reloadAudit = debounce(() => {
      state.audit.page = 1;
      loadAuditLogs().catch((error) => showToast(error.message, "error"));
    });
    $("#auditSearch").addEventListener("input", reloadAudit);
  }

 async function init() {
  buildReminderHourOptions();
  bindEvents();

  await loadSession();
  await loadOverview();
}

  init().catch((error) => {
    console.error(error);
    showToast(error.message || "Admin gagal dimuat.", "error");
  });
})();