const DEFAULT_SETTINGS = Object.freeze({
  app_name: "VHYROX Money",

  announcement: "",
  announcement_enabled: false,
  announcement_type: "info",
  announcement_start_at: null,
  announcement_end_at: null,

  maintenance_mode: false,
  registration_enabled: true,
  ai_chat_enabled: true,
  telegram_enabled: true,

  reminder_enabled: true,
  reminder_hour: 7,

  ai_daily_limit: 100,
  max_transaction_amount: 9999999999,
});

function normalizeStoredValue(value) {
  if (value === null || value === undefined) return null;

  if (typeof value !== "string") return value;

  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function createSystemSettings({ q, cacheMs = 30_000 }) {
  if (typeof q !== "function") {
    throw new TypeError("createSystemSettings memerlukan fungsi q");
  }

  let cache = null;
  let cacheUntil = 0;

  async function loadAll(force = false) {
    const now = Date.now();

    if (!force && cache && cacheUntil > now) {
      return { ...cache };
    }

    const rows = await q(
      `SELECT setting_key, setting_value
       FROM system_settings
       ORDER BY setting_key ASC`,
    );

    const values = { ...DEFAULT_SETTINGS };

    for (const row of rows) {
      values[String(row.setting_key)] = normalizeStoredValue(row.setting_value);
    }

    cache = values;
    cacheUntil = now + Math.max(1_000, Number(cacheMs || 30_000));

    return { ...values };
  }

  async function get(key, fallback = undefined) {
    const values = await loadAll();

    if (Object.prototype.hasOwnProperty.call(values, key)) {
      return values[key];
    }

    return fallback;
  }

  async function getBoolean(key, fallback = false) {
    const value = await get(key, fallback);

    if (typeof value === "boolean") return value;
    if (typeof value === "number") return value !== 0;

    const normalized = String(value ?? "").trim().toLowerCase();

    if (["1", "true", "yes", "on"].includes(normalized)) return true;
    if (["0", "false", "no", "off"].includes(normalized)) return false;

    return Boolean(fallback);
  }

  async function setMany(entries) {
    const items = Object.entries(entries || {});

    for (const [key, value] of items) {
      await q(
        `INSERT INTO system_settings
          (setting_key, setting_value, updated_at)
         VALUES (?, ?, CURRENT_TIMESTAMP)
         ON DUPLICATE KEY UPDATE
           setting_value = VALUES(setting_value),
           updated_at = CURRENT_TIMESTAMP`,
        [String(key).slice(0, 100), JSON.stringify(value)],
      );
    }

    cache = null;
    cacheUntil = 0;

    return loadAll(true);
  }

  function clearCache() {
    cache = null;
    cacheUntil = 0;
  }

  return {
    defaults: { ...DEFAULT_SETTINGS },
    loadAll,
    get,
    getBoolean,
    setMany,
    clearCache,
  };
}

module.exports = {
  DEFAULT_SETTINGS,
  createSystemSettings,
};