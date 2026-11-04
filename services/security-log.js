const crypto = require("crypto");

let geoip = null;

try {
  // Opsional. Jalankan: npm install geoip-lite
  // Sistem tetap berjalan walaupun paket belum dipasang.
  geoip = require("geoip-lite");
} catch {
  geoip = null;
}

function normalizeIp(value) {
  const raw = String(value || "").trim();

  if (!raw) return "unknown";

  const first = raw.split(",")[0].trim();

  if (first.startsWith("::ffff:")) {
    return first.slice(7);
  }

  return first;
}

function getRequestIp(req) {
  return normalizeIp(
    req?.ip ||
      req?.headers?.["x-forwarded-for"] ||
      req?.socket?.remoteAddress ||
      "unknown",
  );
}

function parseUserAgent(value) {
  const ua = String(value || "").slice(0, 1000);

  let browser = "Lainnya";
  let os = "Lainnya";
  let deviceType = "Desktop";

  if (/edg\//i.test(ua)) browser = "Microsoft Edge";
  else if (/opr\//i.test(ua)) browser = "Opera";
  else if (/chrome\//i.test(ua)) browser = "Google Chrome";
  else if (/firefox\//i.test(ua)) browser = "Mozilla Firefox";
  else if (/safari\//i.test(ua) && !/chrome\//i.test(ua)) browser = "Safari";

  if (/windows nt/i.test(ua)) os = "Windows";
  else if (/android/i.test(ua)) os = "Android";
  else if (/iphone|ipad|ipod/i.test(ua)) os = "iOS/iPadOS";
  else if (/mac os x/i.test(ua)) os = "macOS";
  else if (/linux/i.test(ua)) os = "Linux";

  if (/ipad|tablet/i.test(ua)) deviceType = "Tablet";
  else if (/mobile|android|iphone|ipod/i.test(ua)) deviceType = "Mobile";

  return {
    raw: ua,
    browser,
    os,
    deviceType,
  };
}

function getApproximateLocation(ip) {
  if (!geoip || !ip || ip === "unknown") {
    return {
      country: null,
      region: null,
      city: null,
    };
  }

  try {
    const result = geoip.lookup(ip);

    return {
      country: result?.country || null,
      region: result?.region || null,
      city: result?.city || null,
    };
  } catch {
    return {
      country: null,
      region: null,
      city: null,
    };
  }
}

function buildDeviceHash(req, parsedUa) {
  const fingerprint = [
    parsedUa?.raw || "",
    String(req?.headers?.["accept-language"] || ""),
    String(req?.headers?.["sec-ch-ua-platform"] || ""),
    String(req?.headers?.["sec-ch-ua-mobile"] || ""),
  ].join("|");

  return crypto
    .createHash("sha256")
    .update(fingerprint)
    .digest("hex");
}

function safeJson(value) {
  if (value === undefined) return null;

  try {
    return JSON.stringify(value);
  } catch {
    return JSON.stringify({ value: String(value) });
  }
}

function createSecurityLogger({ q, pool }) {
  if (typeof q !== "function") {
    throw new TypeError("createSecurityLogger memerlukan fungsi q");
  }

  async function createSecurityEvent({
    userId = null,
    eventType,
    severity = "medium",
    title,
    description,
    ipAddress = null,
    deviceHash = null,
    dedupeMinutes = 30,
  }) {
    const normalizedUserId = Number(userId);
    const safeUserId = Number.isInteger(normalizedUserId) && normalizedUserId > 0
      ? normalizedUserId
      : null;

    const duplicate = await q(
      `SELECT id
       FROM security_events
       WHERE event_type = ?
         AND COALESCE(user_id, 0) = COALESCE(?, 0)
         AND COALESCE(ip_address, '') = COALESCE(?, '')
         AND is_resolved = FALSE
         AND created_at >= DATE_SUB(NOW(), INTERVAL ? MINUTE)
       LIMIT 1`,
      [
        String(eventType || "UNKNOWN").slice(0, 80),
        safeUserId,
        ipAddress,
        Math.max(1, Number(dedupeMinutes || 30)),
      ],
    );

    if (duplicate.length > 0) {
      return Number(duplicate[0].id);
    }

    const result = await q(
      `INSERT INTO security_events
        (
          user_id,
          event_type,
          severity,
          title,
          description,
          ip_address,
          device_hash,
          is_resolved
        )
       VALUES (?, ?, ?, ?, ?, ?, ?, FALSE)`,
      [
        safeUserId,
        String(eventType || "UNKNOWN").slice(0, 80),
        ["low", "medium", "high", "critical"].includes(severity)
          ? severity
          : "medium",
        String(title || "Aktivitas keamanan").slice(0, 200),
        String(description || "").slice(0, 2000),
        ipAddress,
        deviceHash,
      ],
    );

    return Number(result.insertId || 0);
  }

  async function recordActivity({
    req,
    userId = null,
    email = null,
    provider = "unknown",
    eventType = "login_failure",
    status = "failure",
    failureReason = null,
    sessionId = null,
  }) {
    const ipAddress = getRequestIp(req);
    const parsedUa = parseUserAgent(req?.headers?.["user-agent"]);
    const deviceHash = buildDeviceHash(req, parsedUa);
    const location = getApproximateLocation(ipAddress);

    const normalizedUserId = Number(userId);
    const safeUserId = Number.isInteger(normalizedUserId) && normalizedUserId > 0
      ? normalizedUserId
      : null;

    let hadPreviousSuccess = false;
    let knownIp = false;
    let knownDevice = false;

    if (safeUserId && status === "success") {
      const previousRows = await q(
        `SELECT
           COUNT(*) AS total_success,
           SUM(ip_address = ?) AS same_ip,
           SUM(device_hash = ?) AS same_device
         FROM login_activity
         WHERE user_id = ?
           AND status = 'success'`,
        [ipAddress, deviceHash, safeUserId],
      );

      const previous = previousRows[0] || {};
      hadPreviousSuccess = Number(previous.total_success || 0) > 0;
      knownIp = Number(previous.same_ip || 0) > 0;
      knownDevice = Number(previous.same_device || 0) > 0;
    }

    const result = await q(
      `INSERT INTO login_activity
        (
          user_id,
          email_attempted,
          event_type,
          provider,
          ip_address,
          user_agent,
          device_hash,
          device_type,
          browser,
          operating_system,
          country,
          region_name,
          city,
          status,
          failure_reason,
          session_id
        )
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        safeUserId,
        email ? String(email).toLowerCase().slice(0, 190) : null,
        eventType,
        String(provider || "unknown").slice(0, 40),
        ipAddress,
        parsedUa.raw,
        deviceHash,
        parsedUa.deviceType,
        parsedUa.browser,
        parsedUa.os,
        location.country,
        location.region,
        location.city,
        status,
        failureReason ? String(failureReason).slice(0, 500) : null,
        sessionId ? String(sessionId).slice(0, 128) : null,
      ],
    );

    if (safeUserId && status === "success" && hadPreviousSuccess) {
      if (!knownIp) {
        await createSecurityEvent({
          userId: safeUserId,
          eventType: "NEW_IP_LOGIN",
          severity: "medium",
          title: "Login dari IP baru",
          description:
            `Akun login dari IP ${ipAddress}. ` +
            "Lokasi hanya perkiraan berdasarkan IP.",
          ipAddress,
          deviceHash,
          dedupeMinutes: 1440,
        });
      }

      if (!knownDevice) {
        await createSecurityEvent({
          userId: safeUserId,
          eventType: "NEW_DEVICE_LOGIN",
          severity: "medium",
          title: "Login dari perangkat baru",
          description:
            `${parsedUa.deviceType}, ${parsedUa.browser}, ${parsedUa.os}.`,
          ipAddress,
          deviceHash,
          dedupeMinutes: 1440,
        });
      }
    }

    if (status === "failure") {
      const failureRows = await q(
        `SELECT COUNT(*) AS total
         FROM login_activity
         WHERE ip_address = ?
           AND status = 'failure'
           AND created_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE)`,
        [ipAddress],
      );

      const totalFailures = Number(failureRows[0]?.total || 0);

      if (totalFailures >= 5) {
        await createSecurityEvent({
          userId: safeUserId,
          eventType: "REPEATED_LOGIN_FAILURE",
          severity: totalFailures >= 10 ? "critical" : "high",
          title: "Percobaan login gagal berulang",
          description:
            `${totalFailures} percobaan login gagal dari IP ${ipAddress} ` +
            "dalam 10 menit terakhir.",
          ipAddress,
          deviceHash,
          dedupeMinutes: 30,
        });
      }
    }

    return {
      id: Number(result.insertId || 0),
      ipAddress,
      deviceHash,
      browser: parsedUa.browser,
      operatingSystem: parsedUa.os,
      deviceType: parsedUa.deviceType,
      location,
    };
  }

  async function logLoginSuccess({ req, userId, email, provider }) {
    return recordActivity({
      req,
      userId,
      email,
      provider,
      eventType: "login_success",
      status: "success",
      sessionId: req?.sessionID || null,
    });
  }

  async function logLoginFailure({
    req,
    userId = null,
    email = null,
    provider = "unknown",
    reason = "Login gagal",
  }) {
    return recordActivity({
      req,
      userId,
      email,
      provider,
      eventType: "login_failure",
      status: "failure",
      failureReason: reason,
      sessionId: null,
    });
  }

  async function logLogout({ req, userId, email = null }) {
    return recordActivity({
      req,
      userId,
      email,
      provider: "session",
      eventType: "logout",
      status: "success",
      sessionId: req?.sessionID || null,
    });
  }

  async function writeAdminAudit({
    req,
    adminUserId,
    action,
    targetType,
    targetId = null,
    oldData = null,
    newData = null,
  }) {
    const ipAddress = getRequestIp(req);
    const userAgent = String(req?.headers?.["user-agent"] || "").slice(0, 1000);

    const result = await q(
      `INSERT INTO admin_audit_logs
        (
          admin_user_id,
          action,
          target_type,
          target_id,
          old_data,
          new_data,
          ip_address,
          user_agent
        )
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        Number(adminUserId),
        String(action || "UNKNOWN").slice(0, 100),
        String(targetType || "system").slice(0, 80),
        targetId === null ? null : String(targetId).slice(0, 100),
        safeJson(oldData),
        safeJson(newData),
        ipAddress,
        userAgent,
      ],
    );

    return Number(result.insertId || 0);
  }

  async function cleanupOldActivity(retentionDays = 90) {
    const days = Math.max(7, Math.min(730, Number(retentionDays || 90)));

    return q(
      `DELETE FROM login_activity
       WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)`,
      [days],
    );
  }

  async function forceLogoutUser(userId) {
    const safeUserId = Number(userId);

    if (!Number.isInteger(safeUserId) || safeUserId <= 0) {
      throw new Error("User ID tidak valid");
    }

    // express-mysql-session menyimpan data session sebagai JSON text.
    // JSON_EXTRACT dipakai agar tidak salah mencocokkan userId 1 dengan 10/11.
    return q(
      `DELETE FROM web_sessions
       WHERE CAST(
         JSON_UNQUOTE(
           JSON_EXTRACT(data, '$.userId')
         ) AS UNSIGNED
       ) = ?`,
      [safeUserId],
    );
  }

  return {
    getRequestIp,
    parseUserAgent,
    getApproximateLocation,
    createSecurityEvent,
    recordActivity,
    logLoginSuccess,
    logLoginFailure,
    logLogout,
    writeAdminAudit,
    cleanupOldActivity,
    forceLogoutUser,
  };
}

module.exports = {
  createSecurityLogger,
  getRequestIp,
  parseUserAgent,
};