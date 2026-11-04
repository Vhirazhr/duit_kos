const express = require("express");

function asPositiveInt(value, fallback, max = Number.MAX_SAFE_INTEGER) {
  const parsed = Number(value);

  if (!Number.isInteger(parsed) || parsed <= 0) {
    return fallback;
  }

  return Math.min(parsed, max);
}

function asBoolean(value) {
  return [true, 1, "1", "true", "yes", "on"].includes(value);
}

function normalizeDateTimeSetting(value) {
  const raw = String(value ?? "")
    .trim()
    .replace("T", " ");

  if (!raw) {
    return null;
  }

  const match = raw.match(
    /^(\d{4})-(\d{2})-(\d{2})[ ](\d{2}):(\d{2})(?::(\d{2}))?$/,
  );

  if (!match) {
    return null;
  }

  const [, year, month, day, hour, minute, second = "00"] = match;

  const normalized =
    `${year}-${month}-${day} ` +
    `${hour}:${minute}:${second}`;

  const date = new Date(
    `${year}-${month}-${day}T${hour}:${minute}:${second}`,
  );

  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return normalized;
}

function normalizeAnnouncementType(value) {
  const type = String(value || "")
    .trim()
    .toLowerCase();

  return ["info", "warning", "critical"].includes(type)
    ? type
    : "info";
}

function normalizeReviewStatus(value) {
  const status = String(value || "").trim().toLowerCase();
  return ["published", "hidden", "deleted"].includes(status)
    ? status
    : null;
}

function normalizeRole(value) {
  const role = String(value || "").trim().toLowerCase();
  return ["admin", "user"].includes(role) ? role : null;
}

function normalizeCategoryType(value) {
  const type = String(value || "").trim().toLowerCase();
  return ["pemasukan", "pengeluaran"].includes(type) ? type : null;
}

function normalizeAliases(value) {
  const source = Array.isArray(value)
    ? value
    : String(value || "")
        .split(",")
        .map((item) => item.trim());

  const unique = new Map();

  for (const item of source) {
    const alias = String(item || "")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 100);

    if (alias) unique.set(alias.toLowerCase(), alias);
  }

  return [...unique.values()].slice(0, 100);
}

module.exports = function createAdminRouter({
  q,
  pool,
  bot,
  firebaseAuth,
  writeLimiter,
  requireWriteAccess,
  securityLogger,
  systemSettings,
}) {
  if (typeof q !== "function" || !pool) {
    throw new TypeError("Admin router memerlukan q dan pool");
  }

  const router = express.Router();
  const templateUserId = asPositiveInt(
    process.env.DEFAULT_CATEGORY_TEMPLATE_USER_ID,
    1,
  );

  function requireAdmin(req, res, next) {
    const role = String(req.auth?.role || req.session?.role || "")
      .trim()
      .toLowerCase();

    if (role !== "admin") {
      return res.status(403).json({
        error: "Akses khusus admin.",
      });
    }

    return next();
  }

  async function audit(req, action, targetType, targetId, oldData, newData) {
    if (!securityLogger?.writeAdminAudit) return;

    await securityLogger.writeAdminAudit({
      req,
      adminUserId: req.auth.userId,
      action,
      targetType,
      targetId,
      oldData,
      newData,
    });
  }

  async function attachFirebaseAvatars(rows = []) {
    const sourceRows = Array.isArray(rows) ? rows : [];

    if (
      sourceRows.length === 0 ||
      !firebaseAuth ||
      typeof firebaseAuth.getUsers !== "function"
    ) {
      return sourceRows;
    }

    const identifiers = [];
    const seenUids = new Set();

    for (const row of sourceRows) {
      const uid = String(row?.firebase_uid || "").trim();

      if (!uid || seenUids.has(uid)) {
        continue;
      }

      seenUids.add(uid);
      identifiers.push({ uid });
    }

    if (identifiers.length === 0) {
      return sourceRows;
    }

    const firebasePhotos = new Map();

    try {
      // Firebase Admin membatasi getUsers maksimal 100 identifier per request.
      for (let index = 0; index < identifiers.length; index += 100) {
        const batch = identifiers.slice(index, index + 100);
        const result = await firebaseAuth.getUsers(batch);

        for (const firebaseUser of result.users || []) {
          const photoURL = String(firebaseUser.photoURL || "").trim();

          if (photoURL) {
            firebasePhotos.set(String(firebaseUser.uid), photoURL);
          }
        }
      }
    } catch (error) {
      console.warn(
        "Avatar Firebase gagal dimuat untuk admin:",
        error?.message || error,
      );
    }

    return sourceRows.map((row) => {
      const uid = String(row?.firebase_uid || "").trim();
      const databaseAvatar = String(row?.avatar_url || "").trim();
      const firebaseAvatar = firebasePhotos.get(uid) || "";

      return {
        ...row,
        avatar_url: databaseAvatar || firebaseAvatar || null,
      };
    });
  }

  async function getUserForUpdate(connection, userId) {
    const [rows] = await connection.execute(
      `SELECT
         id,
         nama,
         email,
         role,
         is_active,
         telegram_chat_id,
         firebase_uid,
         last_login_at,
         created_at
       FROM users
       WHERE id = ?
       LIMIT 1
       FOR UPDATE`,
      [userId],
    );

    return rows[0] || null;
  }

  router.use(requireAdmin);

  // =======================================================
  // RINGKASAN SISTEM
  // =======================================================
  router.get("/summary", async (req, res) => {
    try {
      const [
        userRows,
        transactionRows,
        reviewRows,
        loginRows,
        securityRows,
        recentUsers,
      ] = await Promise.all([
        q(
          `SELECT
             COUNT(*) AS total_users,
             SUM(is_active = TRUE) AS active_users,
             SUM(is_active = FALSE) AS inactive_users,
             SUM(role = 'admin') AS admin_users,
             SUM(created_at >= DATE_FORMAT(CURDATE(), '%Y-%m-01')) AS new_users_month,
             SUM(DATE(last_login_at) = CURDATE()) AS login_today,
             SUM(telegram_chat_id IS NOT NULL AND TRIM(telegram_chat_id) <> '') AS telegram_connected
           FROM users`,
        ),
        q(
          `SELECT
             COUNT(*) AS total_transactions,
             COUNT(DISTINCT user_id) AS users_with_transactions
           FROM transaksi`,
        ),
        q(
          `SELECT
             COUNT(*) AS total_reviews,
             SUM(status = 'published') AS published_reviews,
             SUM(status = 'hidden') AS hidden_reviews,
             SUM(status = 'deleted') AS deleted_reviews,
             SUM(is_featured = TRUE AND status = 'published') AS featured_reviews
           FROM app_reviews`,
        ),
        q(
          `SELECT
             SUM(status = 'success' AND event_type = 'login_success' AND DATE(created_at) = CURDATE()) AS successful_logins_today,
             SUM(status = 'failure' AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)) AS failed_logins_24h
           FROM login_activity`,
        ),
        q(
          `SELECT
             COUNT(*) AS open_events,
             SUM(severity IN ('high', 'critical')) AS high_risk_events
           FROM security_events
           WHERE is_resolved = FALSE`,
        ),
        q(
          `SELECT
             id,
             nama,
             email,
             avatar_url,
             firebase_uid,
             role,
             is_active,
             created_at
           FROM users
           ORDER BY created_at DESC, id DESC
           LIMIT 5`,
        ),
      ]);

      const recentUsersWithAvatars =
        await attachFirebaseAvatars(recentUsers);

      return res.json({
        status: "ok",
        users: userRows[0] || {},
        transactions: transactionRows[0] || {},
        reviews: reviewRows[0] || {},
        logins: loginRows[0] || {},
        security: securityRows[0] || {},
        recent_users: recentUsersWithAvatars.map((user) => ({
          ...user,
          firebase_uid: undefined,
        })),
      });
    } catch (error) {
      console.error("Admin summary error:", error);
      return res.status(500).json({
        error: "Ringkasan admin gagal dimuat.",
      });
    }
  });

  // =======================================================
  // PENGGUNA
  // =======================================================
  router.get("/users", async (req, res) => {
    try {
      const page = asPositiveInt(req.query.page, 1, 100000);
      const limit = asPositiveInt(req.query.limit, 20, 100);
      const offset = (page - 1) * limit;
      const search = String(req.query.search || "").trim().slice(0, 190);
      const role = normalizeRole(req.query.role);
      const status = String(req.query.status || "all").toLowerCase();

      const where = [];
      const params = [];

      if (search) {
        where.push("(u.nama LIKE ? OR u.email LIKE ? OR CAST(u.id AS CHAR) = ?)");
        params.push(`%${search}%`, `%${search}%`, search);
      }

      if (role) {
        where.push("u.role = ?");
        params.push(role);
      }

      if (status === "active") where.push("u.is_active = TRUE");
      if (status === "inactive") where.push("u.is_active = FALSE");

      const whereSql = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";

      const countRows = await q(
        `SELECT COUNT(*) AS total
         FROM users u
         ${whereSql}`,
        params,
      );

      const users = await q(
        `SELECT
           u.id,
           u.nama,
           u.email,
           u.avatar_url,
           u.auth_provider,
           u.role,
           u.is_active,
           u.telegram_chat_id,
           u.firebase_uid,
           u.email_verified_at,
           u.last_login_at,
           u.created_at,
           (SELECT COUNT(*) FROM transaksi t WHERE t.user_id = u.id) AS total_transactions,
           (SELECT COUNT(*) FROM web_sessions ws
             WHERE CAST(JSON_UNQUOTE(JSON_EXTRACT(ws.data, '$.userId')) AS UNSIGNED) = u.id
               AND ws.expires > UNIX_TIMESTAMP()) AS active_sessions,
           (SELECT COUNT(*) FROM security_events se
             WHERE se.user_id = u.id AND se.is_resolved = FALSE) AS open_security_events
         FROM users u
         ${whereSql}
         ORDER BY u.created_at DESC, u.id DESC
         LIMIT ${limit} OFFSET ${offset}`,
        params,
      );

      const usersWithAvatars =
        await attachFirebaseAvatars(users);

      return res.json({
        status: "ok",
        page,
        limit,
        total: Number(countRows[0]?.total || 0),
        users: usersWithAvatars.map((item) => ({
          ...item,
          id: Number(item.id),
          is_active: Boolean(Number(item.is_active)),
          telegram_connected: Boolean(String(item.telegram_chat_id || "").trim()),
          firebase_connected: Boolean(String(item.firebase_uid || "").trim()),
          total_transactions: Number(item.total_transactions || 0),
          active_sessions: Number(item.active_sessions || 0),
          open_security_events: Number(item.open_security_events || 0),
          telegram_chat_id: undefined,
          firebase_uid: undefined,
        })),
      });
    } catch (error) {
      console.error("Admin users error:", error);
      return res.status(500).json({
        error: "Daftar pengguna gagal dimuat.",
      });
    }
  });

  router.patch(
    "/users/:id/status",
    writeLimiter,
    requireWriteAccess,
    async (req, res) => {
      const connection = await pool.getConnection();

      try {
        const userId = Number(req.params.id);
        const nextActive = asBoolean(req.body?.is_active);

        if (!Number.isInteger(userId) || userId <= 0) {
          return res.status(400).json({ error: "ID pengguna tidak valid." });
        }

        if (userId === Number(req.auth.userId) && !nextActive) {
          return res.status(409).json({
            error: "Admin tidak bisa menonaktifkan akunnya sendiri.",
          });
        }

        await connection.beginTransaction();
        const existing = await getUserForUpdate(connection, userId);

        if (!existing) {
          await connection.rollback();
          return res.status(404).json({ error: "Pengguna tidak ditemukan." });
        }

        if (existing.role === "admin" && !nextActive) {
          const [adminRows] = await connection.execute(
            `SELECT COUNT(*) AS total
             FROM users
             WHERE role = 'admin'
               AND is_active = TRUE`,
          );

          if (Number(adminRows[0]?.total || 0) <= 1) {
            await connection.rollback();
            return res.status(409).json({
              error: "Admin aktif terakhir tidak boleh dinonaktifkan.",
            });
          }
        }

        await connection.execute(
          `UPDATE users
           SET is_active = ?
           WHERE id = ?`,
          [nextActive ? 1 : 0, userId],
        );

        if (!nextActive) {
          await connection.execute(
            `DELETE FROM web_sessions
             WHERE CAST(
               JSON_UNQUOTE(JSON_EXTRACT(data, '$.userId')) AS UNSIGNED
             ) = ?`,
            [userId],
          );
        }

        await connection.commit();

        await audit(
          req,
          nextActive ? "ACTIVATE_USER" : "DEACTIVATE_USER",
          "user",
          userId,
          { is_active: Boolean(Number(existing.is_active)) },
          { is_active: nextActive },
        );

        return res.json({
          status: "ok",
          message: nextActive
            ? "Pengguna berhasil diaktifkan."
            : "Pengguna dinonaktifkan dan seluruh session-nya dicabut.",
        });
      } catch (error) {
        await connection.rollback();
        console.error("Admin user status error:", error);
        return res.status(500).json({
          error: "Status pengguna gagal diubah.",
        });
      } finally {
        connection.release();
      }
    },
  );

  router.patch(
    "/users/:id/role",
    writeLimiter,
    requireWriteAccess,
    async (req, res) => {
      const connection = await pool.getConnection();

      try {
        const userId = Number(req.params.id);
        const role = normalizeRole(req.body?.role);

        if (!Number.isInteger(userId) || userId <= 0 || !role) {
          return res.status(400).json({ error: "Role atau ID tidak valid." });
        }

        if (userId === Number(req.auth.userId) && role !== "admin") {
          return res.status(409).json({
            error: "Admin tidak bisa menurunkan role akunnya sendiri.",
          });
        }

        await connection.beginTransaction();
        const existing = await getUserForUpdate(connection, userId);

        if (!existing) {
          await connection.rollback();
          return res.status(404).json({ error: "Pengguna tidak ditemukan." });
        }

        if (existing.role === "admin" && role === "user") {
          const [adminRows] = await connection.execute(
            `SELECT COUNT(*) AS total
             FROM users
             WHERE role = 'admin'
               AND is_active = TRUE`,
          );

          if (Number(adminRows[0]?.total || 0) <= 1) {
            await connection.rollback();
            return res.status(409).json({
              error: "Role admin aktif terakhir tidak boleh diturunkan.",
            });
          }
        }

        await connection.execute(
          `UPDATE users
           SET role = ?
           WHERE id = ?`,
          [role, userId],
        );

        await connection.execute(
          `DELETE FROM web_sessions
           WHERE CAST(
             JSON_UNQUOTE(JSON_EXTRACT(data, '$.userId')) AS UNSIGNED
           ) = ?`,
          [userId],
        );

        await connection.commit();

        await audit(
          req,
          "CHANGE_USER_ROLE",
          "user",
          userId,
          { role: existing.role },
          { role },
        );

        return res.json({
          status: "ok",
          message: "Role pengguna diubah. Pengguna harus login ulang.",
        });
      } catch (error) {
        await connection.rollback();
        console.error("Admin role error:", error);
        return res.status(500).json({ error: "Role pengguna gagal diubah." });
      } finally {
        connection.release();
      }
    },
  );

  router.post(
    "/users/:id/disconnect-telegram",
    writeLimiter,
    requireWriteAccess,
    async (req, res) => {
      try {
        const userId = Number(req.params.id);

        if (!Number.isInteger(userId) || userId <= 0) {
          return res.status(400).json({ error: "ID pengguna tidak valid." });
        }

        const rows = await q(
          `SELECT id, telegram_chat_id
           FROM users
           WHERE id = ?
           LIMIT 1`,
          [userId],
        );

        if (!rows[0]) {
          return res.status(404).json({ error: "Pengguna tidak ditemukan." });
        }

        await q(
          `UPDATE users
           SET telegram_chat_id = NULL
           WHERE id = ?`,
          [userId],
        );

        await q(
          `UPDATE telegram_link_tokens
           SET used_at = COALESCE(used_at, CURRENT_TIMESTAMP)
           WHERE user_id = ?
             AND used_at IS NULL`,
          [userId],
        );

        await audit(
          req,
          "DISCONNECT_TELEGRAM",
          "user",
          userId,
          { telegram_connected: Boolean(rows[0].telegram_chat_id) },
          { telegram_connected: false },
        );

        return res.json({
          status: "ok",
          message: "Koneksi Telegram pengguna berhasil diputus.",
        });
      } catch (error) {
        console.error("Disconnect Telegram error:", error);
        return res.status(500).json({ error: "Telegram gagal diputus." });
      }
    },
  );

  router.post(
    "/users/:id/force-logout",
    writeLimiter,
    requireWriteAccess,
    async (req, res) => {
      try {
        const userId = Number(req.params.id);

        if (!Number.isInteger(userId) || userId <= 0) {
          return res.status(400).json({ error: "ID pengguna tidak valid." });
        }

        if (userId === Number(req.auth.userId)) {
          return res.status(409).json({
            error: "Gunakan tombol logout biasa untuk session admin sendiri.",
          });
        }

        const result = securityLogger?.forceLogoutUser
          ? await securityLogger.forceLogoutUser(userId)
          : await q(
              `DELETE FROM web_sessions
               WHERE CAST(
                 JSON_UNQUOTE(JSON_EXTRACT(data, '$.userId')) AS UNSIGNED
               ) = ?`,
              [userId],
            );

        await audit(
          req,
          "FORCE_LOGOUT_USER",
          "user",
          userId,
          null,
          { removed_sessions: Number(result.affectedRows || 0) },
        );

        return res.json({
          status: "ok",
          message: `${Number(result.affectedRows || 0)} session berhasil dicabut.`,
        });
      } catch (error) {
        console.error("Force logout error:", error);
        return res.status(500).json({ error: "Session pengguna gagal dicabut." });
      }
    },
  );

  // =======================================================
  // ULASAN LANDING
  // =======================================================
  router.get("/reviews", async (req, res) => {
    try {
      const status = String(req.query.status || "all").trim().toLowerCase();
      const search = String(req.query.search || "").trim().slice(0, 190);
      const where = [];
      const params = [];

      if (["published", "hidden", "deleted"].includes(status)) {
        where.push("ar.status = ?");
        params.push(status);
      }

      if (search) {
        where.push("(u.nama LIKE ? OR u.email LIKE ? OR ar.review_text LIKE ?)");
        params.push(`%${search}%`, `%${search}%`, `%${search}%`);
      }

      const whereSql = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";

      const reviews = await q(
        `SELECT
           ar.id,
           ar.user_id,
           ar.rating,
           ar.review_text,
           ar.status,
           ar.is_featured,
           ar.created_at,
           ar.updated_at,
           u.nama,
           u.email,
           u.avatar_url
         FROM app_reviews ar
         INNER JOIN users u ON u.id = ar.user_id
         ${whereSql}
         ORDER BY
           ar.is_featured DESC,
           ar.updated_at DESC,
           ar.id DESC
         LIMIT 300`,
        params,
      );

      return res.json({
        status: "ok",
        reviews: reviews.map((review) => ({
          ...review,
          id: Number(review.id),
          user_id: Number(review.user_id),
          rating: Number(review.rating),
          is_featured: Boolean(Number(review.is_featured)),
        })),
      });
    } catch (error) {
      console.error("Admin reviews error:", error);
      return res.status(500).json({ error: "Ulasan gagal dimuat." });
    }
  });

  router.patch(
    "/reviews/:id/status",
    writeLimiter,
    requireWriteAccess,
    async (req, res) => {
      try {
        const reviewId = Number(req.params.id);
        const status = normalizeReviewStatus(req.body?.status);

        if (!Number.isInteger(reviewId) || reviewId <= 0 || !status) {
          return res.status(400).json({ error: "Status atau ID ulasan tidak valid." });
        }

        const rows = await q(
          `SELECT id, user_id, rating, review_text, status, is_featured
           FROM app_reviews
           WHERE id = ?
           LIMIT 1`,
          [reviewId],
        );

        const existing = rows[0];

        if (!existing) {
          return res.status(404).json({ error: "Ulasan tidak ditemukan." });
        }

        await q(
          `UPDATE app_reviews
           SET
             status = ?,
             is_featured = CASE WHEN ? = 'published' THEN is_featured ELSE FALSE END,
             updated_at = CURRENT_TIMESTAMP
           WHERE id = ?`,
          [status, status, reviewId],
        );

        await audit(
          req,
          "CHANGE_REVIEW_STATUS",
          "review",
          reviewId,
          { status: existing.status, is_featured: Boolean(existing.is_featured) },
          { status, is_featured: status === "published" ? Boolean(existing.is_featured) : false },
        );

        return res.json({
          status: "ok",
          message:
            status === "published"
              ? "Ulasan ditampilkan di landing."
              : status === "hidden"
                ? "Ulasan disembunyikan dari landing."
                : "Ulasan dihapus secara lunak.",
        });
      } catch (error) {
        console.error("Review status error:", error);
        return res.status(500).json({ error: "Status ulasan gagal diubah." });
      }
    },
  );

  router.patch(
    "/reviews/:id/featured",
    writeLimiter,
    requireWriteAccess,
    async (req, res) => {
      try {
        const reviewId = Number(req.params.id);
        const isFeatured = asBoolean(req.body?.is_featured);

        if (!Number.isInteger(reviewId) || reviewId <= 0) {
          return res.status(400).json({ error: "ID ulasan tidak valid." });
        }

        const rows = await q(
          `SELECT id, status, is_featured
           FROM app_reviews
           WHERE id = ?
           LIMIT 1`,
          [reviewId],
        );

        const existing = rows[0];

        if (!existing) {
          return res.status(404).json({ error: "Ulasan tidak ditemukan." });
        }

        if (isFeatured && existing.status !== "published") {
          return res.status(409).json({
            error: "Hanya ulasan yang tampil yang bisa dijadikan unggulan.",
          });
        }

        await q(
          `UPDATE app_reviews
           SET is_featured = ?
           WHERE id = ?`,
          [isFeatured ? 1 : 0, reviewId],
        );

        await audit(
          req,
          isFeatured ? "FEATURE_REVIEW" : "UNFEATURE_REVIEW",
          "review",
          reviewId,
          { is_featured: Boolean(existing.is_featured) },
          { is_featured: isFeatured },
        );

        return res.json({
          status: "ok",
          message: isFeatured
            ? "Ulasan dijadikan unggulan."
            : "Status unggulan dibatalkan.",
        });
      } catch (error) {
        console.error("Featured review error:", error);
        return res.status(500).json({ error: "Status unggulan gagal diubah." });
      }
    },
  );

  // =======================================================
  // LOGIN & KEAMANAN
  // =======================================================
  router.get("/login-activity", async (req, res) => {
    try {
      const page = asPositiveInt(req.query.page, 1, 100000);
      const limit = asPositiveInt(req.query.limit, 30, 100);
      const offset = (page - 1) * limit;
      const status = String(req.query.status || "all").toLowerCase();
      const search = String(req.query.search || "").trim().slice(0, 190);
      const where = [];
      const params = [];

      if (["success", "failure"].includes(status)) {
        where.push("la.status = ?");
        params.push(status);
      }

      if (search) {
        where.push(
          "(u.nama LIKE ? OR u.email LIKE ? OR la.email_attempted LIKE ? OR la.ip_address LIKE ?)",
        );
        params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
      }

      const whereSql = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
      const countRows = await q(
        `SELECT COUNT(*) AS total
         FROM login_activity la
         LEFT JOIN users u ON u.id = la.user_id
         ${whereSql}`,
        params,
      );

      const rows = await q(
        `SELECT
           la.id,
           la.user_id,
           la.email_attempted,
           la.event_type,
           la.provider,
           la.ip_address,
           la.device_type,
           la.browser,
           la.operating_system,
           la.country,
           la.region_name,
           la.city,
           la.status,
           la.failure_reason,
           la.created_at,
           u.nama,
           u.email
         FROM login_activity la
         LEFT JOIN users u ON u.id = la.user_id
         ${whereSql}
         ORDER BY la.created_at DESC, la.id DESC
         LIMIT ${limit} OFFSET ${offset}`,
        params,
      );

      return res.json({
        status: "ok",
        page,
        limit,
        total: Number(countRows[0]?.total || 0),
        activities: rows.map((item) => ({
          ...item,
          id: Number(item.id),
          user_id: item.user_id ? Number(item.user_id) : null,
          location_label: [item.city, item.region_name, item.country]
            .filter(Boolean)
            .join(", ") || "Tidak diketahui",
        })),
      });
    } catch (error) {
      console.error("Login activity error:", error);
      return res.status(500).json({ error: "Aktivitas login gagal dimuat." });
    }
  });

  router.get("/security-events", async (req, res) => {
    try {
      const resolved = String(req.query.resolved || "false").toLowerCase() === "true";
      const severity = String(req.query.severity || "all").toLowerCase();
      const where = ["se.is_resolved = ?"];
      const params = [resolved ? 1 : 0];

      if (["low", "medium", "high", "critical"].includes(severity)) {
        where.push("se.severity = ?");
        params.push(severity);
      }

      const events = await q(
        `SELECT
           se.id,
           se.user_id,
           se.event_type,
           se.severity,
           se.title,
           se.description,
           se.ip_address,
           se.is_resolved,
           se.resolved_at,
           se.created_at,
           u.nama,
           u.email,
           resolver.nama AS resolved_by_name
         FROM security_events se
         LEFT JOIN users u ON u.id = se.user_id
         LEFT JOIN users resolver ON resolver.id = se.resolved_by
         WHERE ${where.join(" AND ")}
         ORDER BY
           FIELD(se.severity, 'critical', 'high', 'medium', 'low'),
           se.created_at DESC,
           se.id DESC
         LIMIT 300`,
        params,
      );

      return res.json({
        status: "ok",
        events: events.map((item) => ({
          ...item,
          id: Number(item.id),
          user_id: item.user_id ? Number(item.user_id) : null,
          is_resolved: Boolean(Number(item.is_resolved)),
        })),
      });
    } catch (error) {
      console.error("Security events error:", error);
      return res.status(500).json({ error: "Peringatan keamanan gagal dimuat." });
    }
  });

  router.patch(
    "/security-events/:id/resolve",
    writeLimiter,
    requireWriteAccess,
    async (req, res) => {
      try {
        const eventId = Number(req.params.id);
        const resolved = req.body?.resolved === undefined
          ? true
          : asBoolean(req.body.resolved);

        if (!Number.isInteger(eventId) || eventId <= 0) {
          return res.status(400).json({ error: "ID peringatan tidak valid." });
        }

        const rows = await q(
          `SELECT id, is_resolved, title
           FROM security_events
           WHERE id = ?
           LIMIT 1`,
          [eventId],
        );

        if (!rows[0]) {
          return res.status(404).json({ error: "Peringatan tidak ditemukan." });
        }

        await q(
          `UPDATE security_events
           SET
             is_resolved = ?,
             resolved_by = ?,
             resolved_at = CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE NULL END
           WHERE id = ?`,
          [resolved ? 1 : 0, resolved ? req.auth.userId : null, resolved ? 1 : 0, eventId],
        );

        await audit(
          req,
          resolved ? "RESOLVE_SECURITY_EVENT" : "REOPEN_SECURITY_EVENT",
          "security_event",
          eventId,
          { is_resolved: Boolean(rows[0].is_resolved) },
          { is_resolved: resolved },
        );

        return res.json({
          status: "ok",
          message: resolved ? "Peringatan ditandai selesai." : "Peringatan dibuka kembali.",
        });
      } catch (error) {
        console.error("Resolve security event error:", error);
        return res.status(500).json({ error: "Peringatan gagal diperbarui." });
      }
    },
  );

  // =======================================================
  // KATEGORI TEMPLATE AKUN BARU
  // =======================================================
  router.get("/categories", async (req, res) => {
    try {
      const categories = await q(
        `SELECT
           k.id,
           k.nama,
           k.jenis,
           k.is_active,
           k.prioritas,
           k.created_at,
           k.updated_at,
           GROUP_CONCAT(ka.alias ORDER BY ka.alias SEPARATOR '|||') AS aliases
         FROM kategori k
         LEFT JOIN kategori_alias ka ON ka.kategori_id = k.id
         WHERE k.user_id = ?
         GROUP BY
           k.id,
           k.nama,
           k.jenis,
           k.is_active,
           k.prioritas,
           k.created_at,
           k.updated_at
         ORDER BY k.prioritas ASC, k.nama ASC`,
        [templateUserId],
      );

      return res.json({
        status: "ok",
        template_user_id: templateUserId,
        categories: categories.map((item) => ({
          ...item,
          id: Number(item.id),
          is_active: Boolean(Number(item.is_active)),
          prioritas: Number(item.prioritas || 100),
          aliases: item.aliases ? String(item.aliases).split("|||") : [],
        })),
      });
    } catch (error) {
      console.error("Admin categories error:", error);
      return res.status(500).json({ error: "Kategori bawaan gagal dimuat." });
    }
  });

  router.post(
    "/categories",
    writeLimiter,
    requireWriteAccess,
    async (req, res) => {
      const connection = await pool.getConnection();

      try {
        const nama = String(req.body?.nama || "")
          .replace(/\s+/g, " ")
          .trim()
          .slice(0, 100);
        const jenis = normalizeCategoryType(req.body?.jenis);
        const prioritas = asPositiveInt(req.body?.prioritas, 100, 9999);
        const isActive = req.body?.is_active === undefined
          ? true
          : asBoolean(req.body.is_active);
        const aliases = normalizeAliases(req.body?.aliases);

        if (!nama || !jenis) {
          return res.status(400).json({
            error: "Nama dan jenis kategori wajib diisi.",
          });
        }

        await connection.beginTransaction();

        const [duplicates] = await connection.execute(
          `SELECT id
           FROM kategori
           WHERE user_id = ?
             AND LOWER(TRIM(nama)) = LOWER(TRIM(?))
           LIMIT 1
           FOR UPDATE`,
          [templateUserId, nama],
        );

        if (duplicates.length > 0) {
          await connection.rollback();
          return res.status(409).json({ error: "Nama kategori sudah digunakan." });
        }

        const [result] = await connection.execute(
          `INSERT INTO kategori
            (user_id, nama, jenis, is_active, prioritas)
           VALUES (?, ?, ?, ?, ?)`,
          [templateUserId, nama, jenis, isActive ? 1 : 0, prioritas],
        );

        for (const alias of aliases) {
          await connection.execute(
            `INSERT INTO kategori_alias (kategori_id, alias)
             VALUES (?, ?)`,
            [result.insertId, alias],
          );
        }

        await connection.commit();

        await audit(
          req,
          "CREATE_DEFAULT_CATEGORY",
          "category",
          result.insertId,
          null,
          { nama, jenis, prioritas, is_active: isActive, aliases },
        );

        return res.status(201).json({
          status: "ok",
          id: Number(result.insertId),
          message: "Kategori bawaan berhasil dibuat.",
        });
      } catch (error) {
        await connection.rollback();
        console.error("Create default category error:", error);
        return res.status(500).json({ error: "Kategori bawaan gagal dibuat." });
      } finally {
        connection.release();
      }
    },
  );

  router.put(
    "/categories/:id",
    writeLimiter,
    requireWriteAccess,
    async (req, res) => {
      const connection = await pool.getConnection();

      try {
        const categoryId = Number(req.params.id);
        const nama = String(req.body?.nama || "")
          .replace(/\s+/g, " ")
          .trim()
          .slice(0, 100);
        const jenis = normalizeCategoryType(req.body?.jenis);
        const prioritas = asPositiveInt(req.body?.prioritas, 100, 9999);
        const isActive = req.body?.is_active === undefined
          ? true
          : asBoolean(req.body.is_active);
        const aliases = normalizeAliases(req.body?.aliases);

        if (!Number.isInteger(categoryId) || categoryId <= 0 || !nama || !jenis) {
          return res.status(400).json({ error: "Data kategori tidak valid." });
        }

        await connection.beginTransaction();

        const [rows] = await connection.execute(
          `SELECT id, nama, jenis, is_active, prioritas
           FROM kategori
           WHERE id = ?
             AND user_id = ?
           LIMIT 1
           FOR UPDATE`,
          [categoryId, templateUserId],
        );

        const existing = rows[0];

        if (!existing) {
          await connection.rollback();
          return res.status(404).json({ error: "Kategori bawaan tidak ditemukan." });
        }

        await connection.execute(
          `UPDATE kategori
           SET
             nama = ?,
             jenis = ?,
             is_active = ?,
             prioritas = ?
           WHERE id = ?
             AND user_id = ?`,
          [nama, jenis, isActive ? 1 : 0, prioritas, categoryId, templateUserId],
        );

        await connection.execute(
          `DELETE FROM kategori_alias
           WHERE kategori_id = ?`,
          [categoryId],
        );

        for (const alias of aliases) {
          await connection.execute(
            `INSERT INTO kategori_alias (kategori_id, alias)
             VALUES (?, ?)`,
            [categoryId, alias],
          );
        }

        await connection.commit();

        await audit(
          req,
          "UPDATE_DEFAULT_CATEGORY",
          "category",
          categoryId,
          existing,
          { nama, jenis, is_active: isActive, prioritas, aliases },
        );

        return res.json({
          status: "ok",
          message: "Kategori bawaan berhasil diperbarui.",
        });
      } catch (error) {
        await connection.rollback();
        console.error("Update default category error:", error);
        return res.status(500).json({ error: "Kategori bawaan gagal diperbarui." });
      } finally {
        connection.release();
      }
    },
  );

  // =======================================================
  // STATUS LAYANAN
  // =======================================================
  router.get("/services", async (req, res) => {
    const checkedAt = new Date().toISOString();

    const services = {
      database: { status: "unknown", detail: "Belum diperiksa" },
      telegram: { status: "unknown", detail: "Belum diperiksa" },
      firebase: { status: "unknown", detail: "Belum diperiksa" },
      smtp: { status: "unknown", detail: "Belum diperiksa" },
      gemini: { status: "unknown", detail: "Belum diperiksa" },
      cron: { status: "online", detail: "Scheduler Node aktif" },
    };

    try {
      await q("SELECT 1 AS ok");
      services.database = { status: "online", detail: "Koneksi MySQL berhasil" };
    } catch (error) {
      services.database = { status: "error", detail: error.message };
    }

    try {
      if (!bot?.getMe) throw new Error("Bot belum tersedia");
      const info = await bot.getMe();
      services.telegram = {
        status: "online",
        detail: `@${info.username || "bot"}`,
      };
    } catch (error) {
      services.telegram = { status: "error", detail: error.message };
    }

    try {
      const projectId = firebaseAuth?.app?.options?.projectId;
      services.firebase = projectId
        ? { status: "online", detail: `Project ${projectId}` }
        : { status: "warning", detail: "Project ID tidak terbaca" };
    } catch (error) {
      services.firebase = { status: "error", detail: error.message };
    }

    services.smtp =
      process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS
        ? { status: "configured", detail: `${process.env.SMTP_HOST}:${process.env.SMTP_PORT || 465}` }
        : { status: "warning", detail: "Konfigurasi SMTP belum lengkap" };

    services.gemini = process.env.GEMINI_API_KEY
      ? {
          status: "configured",
          detail: String(process.env.GEMINI_MODEL || "gemini-3.5-flash"),
        }
      : { status: "warning", detail: "GEMINI_API_KEY belum tersedia" };

    return res.json({
      status: "ok",
      checked_at: checkedAt,
      services,
    });
  });

  // =======================================================
  // PENGATURAN SISTEM
  // =======================================================
  router.get("/settings", async (req, res) => {
    try {
      const settings = systemSettings
        ? await systemSettings.loadAll()
        : {};

      return res.json({ status: "ok", settings });
    } catch (error) {
      console.error("Admin settings error:", error);
      return res.status(500).json({ error: "Pengaturan sistem gagal dimuat." });
    }
  });

  router.put(
    "/settings",
    writeLimiter,
    requireWriteAccess,
    async (req, res) => {
      try {
        if (!systemSettings) {
          return res.status(503).json({ error: "Layanan pengaturan belum aktif." });
        }

        const oldSettings = await systemSettings.loadAll();
        const source = req.body || {};

      const announcementStartAt =
  normalizeDateTimeSetting(
    source.announcement_start_at,
  );

const announcementEndAt =
  normalizeDateTimeSetting(
    source.announcement_end_at,
  );

if (
  announcementStartAt &&
  announcementEndAt &&
  announcementEndAt <= announcementStartAt
) {
  return res.status(400).json({
    error:
      "Waktu selesai pengumuman harus setelah waktu mulai.",
  });
}

const nextSettings = {
  app_name: String(
    source.app_name ??
    oldSettings.app_name ??
    "VHYROX Money",
  )
    .trim()
    .slice(0, 100),

  announcement: String(
    source.announcement ??
    oldSettings.announcement ??
    "",
  )
    .trim()
    .slice(0, 1000),

  announcement_enabled:
    asBoolean(source.announcement_enabled),

  announcement_type:
    normalizeAnnouncementType(
      source.announcement_type,
    ),

  announcement_start_at:
    announcementStartAt,

  announcement_end_at:
    announcementEndAt,

  maintenance_mode:
    asBoolean(source.maintenance_mode),

  registration_enabled:
    asBoolean(source.registration_enabled),

  ai_chat_enabled:
    asBoolean(source.ai_chat_enabled),

  telegram_enabled:
    asBoolean(source.telegram_enabled),

  reminder_enabled:
    asBoolean(source.reminder_enabled),

  reminder_hour:
    Math.max(
      0,
      Math.min(
        23,
        Number(source.reminder_hour ?? 7),
      ),
    ),

  ai_daily_limit:
    Math.max(
      1,
      Math.min(
        100000,
        Number(source.ai_daily_limit ?? 100),
      ),
    ),

  max_transaction_amount:
    Math.max(
      1,
      Math.min(
        999999999999,
        Number(
          source.max_transaction_amount ??
          9999999999,
        ),
      ),
    ),
};

        const saved = await systemSettings.setMany(nextSettings);

        await audit(
          req,
          "UPDATE_SYSTEM_SETTINGS",
          "system_settings",
          "global",
          oldSettings,
          nextSettings,
        );

        return res.json({
          status: "ok",
          message: "Pengaturan sistem berhasil disimpan.",
          settings: saved,
        });
      } catch (error) {
        console.error("Save admin settings error:", error);
        return res.status(500).json({ error: "Pengaturan sistem gagal disimpan." });
      }
    },
  );

  // =======================================================
  // AUDIT LOG
  // =======================================================
  router.get("/audit-logs", async (req, res) => {
    try {
      const page = asPositiveInt(req.query.page, 1, 100000);
      const limit = asPositiveInt(req.query.limit, 40, 100);
      const offset = (page - 1) * limit;
      const search = String(req.query.search || "").trim().slice(0, 100);
      const where = [];
      const params = [];

      if (search) {
        where.push("(aal.action LIKE ? OR aal.target_type LIKE ? OR aal.target_id LIKE ? OR u.nama LIKE ?)");
        params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
      }

      const whereSql = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
      const countRows = await q(
        `SELECT COUNT(*) AS total
         FROM admin_audit_logs aal
         INNER JOIN users u ON u.id = aal.admin_user_id
         ${whereSql}`,
        params,
      );

      const logs = await q(
        `SELECT
           aal.id,
           aal.admin_user_id,
           aal.action,
           aal.target_type,
           aal.target_id,
           aal.old_data,
           aal.new_data,
           aal.ip_address,
           aal.created_at,
           u.nama AS admin_name,
           u.email AS admin_email
         FROM admin_audit_logs aal
         INNER JOIN users u ON u.id = aal.admin_user_id
         ${whereSql}
         ORDER BY aal.created_at DESC, aal.id DESC
         LIMIT ${limit} OFFSET ${offset}`,
        params,
      );

      return res.json({
        status: "ok",
        page,
        limit,
        total: Number(countRows[0]?.total || 0),
        logs: logs.map((item) => ({
          ...item,
          id: Number(item.id),
          admin_user_id: Number(item.admin_user_id),
        })),
      });
    } catch (error) {
      console.error("Audit logs error:", error);
      return res.status(500).json({ error: "Audit log gagal dimuat." });
    }
  });

  return router;
};