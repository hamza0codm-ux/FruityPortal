const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/*
|--------------------------------------------------------------------------
| DATABASE
|--------------------------------------------------------------------------
*/

let pool = null;

if (process.env.DATABASE_URL) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl:
      process.env.NODE_ENV === "production"
        ? { rejectUnauthorized: false }
        : false
  });
} else {
  console.log("DATABASE_URL not found. Running without PostgreSQL.");
}

/*
|--------------------------------------------------------------------------
| SESSION
|--------------------------------------------------------------------------
*/

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-this-secret-on-railway",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

/*
|--------------------------------------------------------------------------
| DATABASE SETUP
|--------------------------------------------------------------------------
*/

async function setupDatabase() {
  if (!pool) return;

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(32) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name VARCHAR(100),
      role VARCHAR(30) NOT NULL DEFAULT 'staff',
      department VARCHAR(100),
      status VARCHAR(30) NOT NULL DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS access_requests (
      id SERIAL PRIMARY KEY,
      username VARCHAR(32) NOT NULL,
      email VARCHAR(255) NOT NULL,
      display_name VARCHAR(100),
      department VARCHAR(100),
      requested_role VARCHAR(30) DEFAULT 'staff',
      reason TEXT,
      status VARCHAR(30) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS invitations (
      id SERIAL PRIMARY KEY,
      token VARCHAR(100) UNIQUE NOT NULL,
      email VARCHAR(255) NOT NULL,
      username VARCHAR(32),
      role VARCHAR(30) DEFAULT 'staff',
      department VARCHAR(100),
      expires_at TIMESTAMP NOT NULL,
      used BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS tasks (
      id SERIAL PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      description TEXT,
      assigned_to INTEGER REFERENCES users(id) ON DELETE SET NULL,
      priority VARCHAR(30) DEFAULT 'normal',
      status VARCHAR(30) DEFAULT 'pending',
      due_date DATE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS updates (
      id SERIAL PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      content TEXT NOT NULL,
      author_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS absences (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      start_date DATE NOT NULL,
      end_date DATE NOT NULL,
      reason TEXT,
      status VARCHAR(30) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS feedback (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      content TEXT NOT NULL,
      anonymous BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS polls (
      id SERIAL PRIMARY KEY,
      question TEXT NOT NULL,
      options JSONB NOT NULL,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS self_evaluations (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      answers JSONB NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  /*
   * Create the first owner account if it doesn't exist.
   *
   * IMPORTANT:
   * Change these credentials immediately after first login.
   */

  const existingOwner = await pool.query(
    "SELECT id FROM users WHERE username = $1",
    ["Owner"]
  );

  if (existingOwner.rows.length === 0) {
    const passwordHash = await bcrypt.hash(
      process.env.OWNER_PASSWORD || "ChangeMe123!",
      12
    );

    await pool.query(
      `
      INSERT INTO users
      (username, email, password_hash, display_name, role, department, status)
      VALUES ($1,$2,$3,$4,$5,$6,$7)
      `,
      [
        "Owner",
        process.env.OWNER_EMAIL || "owner@fruity.local",
        passwordHash,
        "Fruity Owner",
        "owner",
        "Management",
        "active"
      ]
    );

    console.log("Initial Owner account created.");
    console.log(
      "Username: Owner | Password: " +
        (process.env.OWNER_PASSWORD || "ChangeMe123!")
    );
  }
}

/*
|--------------------------------------------------------------------------
| HELPERS
|--------------------------------------------------------------------------
*/

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "You must be logged in."
    });
  }

  next();
}

function requireManagement(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "You must be logged in."
    });
  }

  if (
    !["owner", "admin", "manager"].includes(
      req.session.user.role
    )
  ) {
    return res.status(403).json({
      error: "Management access required."
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "You must be logged in."
    });
  }

  if (!["owner", "admin"].includes(req.session.user.role)) {
    return res.status(403).json({
      error: "Admin access required."
    });
  }

  next();
}

/*
|--------------------------------------------------------------------------
| AUTH
|--------------------------------------------------------------------------
*/

app.post("/api/login", async (req, res) => {
  try {
    if (!pool) {
      return res.status(500).json({
        error: "Database is not connected yet."
      });
    }

    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: "Username and password are required."
      });
    }

    const result = await pool.query(
      `
      SELECT *
      FROM users
      WHERE LOWER(username) = LOWER($1)
      `,
      [username.trim()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Invalid username or password."
      });
    }

    const user = result.rows[0];

    if (user.status !== "active") {
      return res.status(403).json({
        error:
          user.status === "pending"
            ? "Your account is still awaiting approval."
            : "Your account is not active."
      });
    }

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return res.status(401).json({
        error: "Invalid username or password."
      });
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      displayName: user.display_name,
      role: user.role,
      department: user.department
    };

    res.json({
      success: true,
      user: req.session.user
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Login failed."
    });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({
      success: true
    });
  });
});

app.get("/api/me", (req, res) => {
  res.json({
    user: req.session.user || null
  });
});

/*
|--------------------------------------------------------------------------
| REQUEST STAFF ACCESS
|--------------------------------------------------------------------------
*/

app.post("/api/request-access", async (req, res) => {
  try {
    if (!pool) {
      return res.status(500).json({
        error: "Database is not connected yet."
      });
    }

    const {
      username,
      email,
      displayName,
      department,
      requestedRole,
      reason,
      password
    } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({
        error: "Username, email and password are required."
      });
    }

    if (username.length < 3 || username.length > 32) {
      return res.status(400).json({
        error: "Username must be between 3 and 32 characters."
      });
    }

    const existing = await pool.query(
      `
      SELECT id
      FROM users
      WHERE LOWER(username) = LOWER($1)
         OR LOWER(email) = LOWER($2)
      `,
      [username.trim(), email.trim()]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: "That username or email is already registered."
      });
    }

    const requestExists = await pool.query(
      `
      SELECT id
      FROM access_requests
      WHERE LOWER(username) = LOWER($1)
      AND status = 'pending'
      `,
      [username.trim()]
    );

    if (requestExists.rows.length > 0) {
      return res.status(409).json({
        error: "You already have a pending request."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    /*
     * We store the password hash temporarily in the request.
     * It is never stored as plain text.
     */

    await pool.query(
      `
      INSERT INTO access_requests
      (username,email,display_name,department,requested_role,reason,status)
      VALUES ($1,$2,$3,$4,$5,$6,'pending')
      `,
      [
        username.trim(),
        email.trim(),
        displayName || username.trim(),
        department || "General",
        requestedRole || "staff",
        JSON.stringify({
          passwordHash,
          reason: reason || ""
        })
      ]
    );

    /*
     * The "reason" field above is intentionally handled below.
     * PostgreSQL doesn't need the password hash exposed to the frontend.
     */

    await pool.query(
      `
      UPDATE access_requests
      SET reason = $1
      WHERE username = $2
      AND status = 'pending'
      `,
      [
        reason
          ? `${reason}\n\n[SECURE_HASH:${passwordHash}]`
          : `[SECURE_HASH:${passwordHash}]`,
        username.trim()
      ]
    );

    res.json({
      success: true,
      message:
        "Your request has been sent to FRT management."
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not submit request."
    });
  }
});

/*
|--------------------------------------------------------------------------
| MANAGEMENT - ACCESS REQUESTS
|--------------------------------------------------------------------------
*/

app.get(
  "/api/management/access-requests",
  requireManagement,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          id,
          username,
          email,
          display_name,
          department,
          requested_role,
          reason,
          status,
          created_at
        FROM access_requests
        ORDER BY created_at DESC
      `);

      res.json(result.rows);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not load requests."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| MANAGEMENT - APPROVE ACCESS
|--------------------------------------------------------------------------
*/

app.post(
  "/api/management/access-requests/:id/approve",
  requireManagement,
  async (req, res) => {
    try {
      const requestId = req.params.id;

      const result = await pool.query(
        `
        SELECT *
        FROM access_requests
        WHERE id = $1
        `,
        [requestId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Request not found."
        });
      }

      const request = result.rows[0];

      if (request.status !== "pending") {
        return res.status(400).json({
          error: "This request has already been handled."
        });
      }

      const hashMatch = request.reason
        ? request.reason.match(/\[SECURE_HASH:(.*?)\]/)
        : null;

      if (!hashMatch) {
        return res.status(400).json({
          error: "Secure password data is missing."
        });
      }

      const passwordHash = hashMatch[1];

      const cleanReason = request.reason
        .replace(/\n?\[SECURE_HASH:.*?\]/, "")
        .trim();

      await pool.query(
        `
        INSERT INTO users
        (username,email,password_hash,display_name,role,department,status)
        VALUES ($1,$2,$3,$4,$5,$6,'active')
        `,
        [
          request.username,
          request.email,
          passwordHash,
          request.display_name || request.username,
          request.requested_role || "staff",
          request.department || "General"
        ]
      );

      await pool.query(
        `
        UPDATE access_requests
        SET status = 'approved',
            reason = $1
        WHERE id = $2
        `,
        [cleanReason, requestId]
      );

      res.json({
        success: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not approve request."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| MANAGEMENT - REJECT ACCESS
|--------------------------------------------------------------------------
*/

app.post(
  "/api/management/access-requests/:id/reject",
  requireManagement,
  async (req, res) => {
    try {
      await pool.query(
        `
        UPDATE access_requests
        SET status = 'rejected'
        WHERE id = $1
        `,
        [req.params.id]
      );

      res.json({
        success: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not reject request."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| STAFF DATA
|--------------------------------------------------------------------------
*/

app.get("/api/dashboard", requireLogin, async (req, res) => {
  try {
    const tasks = await pool.query(
      `
      SELECT *
      FROM tasks
      WHERE assigned_to = $1
      ORDER BY created_at DESC
      LIMIT 10
      `,
      [req.session.user.id]
    );

    const updates = await pool.query(`
      SELECT *
      FROM updates
      ORDER BY created_at DESC
      LIMIT 5
    `);

    const absences = await pool.query(
      `
      SELECT *
      FROM absences
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 5
      `,
      [req.session.user.id]
    );

    const feedback = await pool.query(
      `
      SELECT *
      FROM feedback
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 5
      `,
      [req.session.user.id]
    );

    res.json({
      tasks: tasks.rows,
      updates: updates.rows,
      absences: absences.rows,
      feedback: feedback.rows
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load dashboard."
    });
  }
});

/*
|--------------------------------------------------------------------------
| TASKS
|--------------------------------------------------------------------------
*/

app.get("/api/tasks", requireLogin, async (req, res) => {
  try {
    let result;

    if (
      ["owner", "admin", "manager"].includes(
        req.session.user.role
      )
    ) {
      result = await pool.query(`
        SELECT
          tasks.*,
          users.username AS assigned_username
        FROM tasks
        LEFT JOIN users
          ON users.id = tasks.assigned_to
        ORDER BY tasks.created_at DESC
      `);
    } else {
      result = await pool.query(
        `
        SELECT *
        FROM tasks
        WHERE assigned_to = $1
        ORDER BY created_at DESC
        `,
        [req.session.user.id]
      );
    }

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load tasks."
    });
  }
});

app.post(
  "/api/tasks",
  requireManagement,
  async (req, res) => {
    try {
      const {
        title,
        description,
        assignedTo,
        priority,
        dueDate
      } = req.body;

      if (!title) {
        return res.status(400).json({
          error: "Task title is required."
        });
      }

      await pool.query(
        `
        INSERT INTO tasks
        (title,description,assigned_to,priority,due_date)
        VALUES ($1,$2,$3,$4,$5)
        `,
        [
          title,
          description || "",
          assignedTo || null,
          priority || "normal",
          dueDate || null
        ]
      );

      res.json({
        success: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not create task."
      });
    }
  }
);

app.patch(
  "/api/tasks/:id",
  requireLogin,
  async (req, res) => {
    try {
      const { status } = req.body;

      if (!status) {
        return res.status(400).json({
          error: "Status is required."
        });
      }

      await pool.query(
        `
        UPDATE tasks
        SET status = $1
        WHERE id = $2
        AND (
          assigned_to = $3
          OR $4 = TRUE
        )
        `,
        [
          status,
          req.params.id,
          req.session.user.id,
          ["owner", "admin", "manager"].includes(
            req.session.user.role
          )
        ]
      );

      res.json({
        success: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not update task."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| UPDATES
|--------------------------------------------------------------------------
*/

app.get("/api/updates", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        updates.*,
        users.username AS author
      FROM updates
      LEFT JOIN users
        ON users.id = updates.author_id
      ORDER BY updates.created_at DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load updates."
    });
  }
});

app.post(
  "/api/updates",
  requireManagement,
  async (req, res) => {
    try {
      const { title, content } = req.body;

      if (!title || !content) {
        return res.status(400).json({
          error: "Title and content are required."
        });
      }

      await pool.query(
        `
        INSERT INTO updates
        (title,content,author_id)
        VALUES ($1,$2,$3)
        `,
        [
          title,
          content,
          req.session.user.id
        ]
      );

      res.json({
        success: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not create update."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| ABSENCES
|--------------------------------------------------------------------------
*/

app.post(
  "/api/absences",
  requireLogin,
  async (req, res) => {
    try {
      const {
        startDate,
        endDate,
        reason
      } = req.body;

      if (!startDate || !endDate) {
        return res.status(400).json({
          error: "Start and end dates are required."
        });
      }

      await pool.query(
        `
        INSERT INTO absences
        (user_id,start_date,end_date,reason)
        VALUES ($1,$2,$3,$4)
        `,
        [
          req.session.user.id,
          startDate,
          endDate,
          reason || ""
        ]
      );

      res.json({
        success: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not submit absence."
      });
    }
  }
);

app.get(
  "/api/management/absences",
  requireManagement,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          absences.*,
          users.username,
          users.display_name
        FROM absences
        JOIN users
          ON users.id = absences.user_id
        ORDER BY absences.created_at DESC
      `);

      res.json(result.rows);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not load absences."
      });
    }
  }
);

app.patch(
  "/api/management/absences/:id",
  requireManagement,
  async (req, res) => {
    try {
      const { status } = req.body;

      if (!["approved", "rejected"].includes(status)) {
        return res.status(400).json({
          error: "Invalid status."
        });
      }

      await pool.query(
        `
        UPDATE absences
        SET status = $1
        WHERE id = $2
        `,
        [status, req.params.id]
      );

      res.json({
        success: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not update absence."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| FEEDBACK
|--------------------------------------------------------------------------
*/

app.post(
  "/api/feedback",
  requireLogin,
  async (req, res) => {
    try {
      const { content, anonymous } = req.body;

      if (!content) {
        return res.status(400).json({
          error: "Feedback cannot be empty."
        });
      }

      await pool.query(
        `
        INSERT INTO feedback
        (user_id,content,anonymous)
        VALUES ($1,$2,$3)
        `,
        [
          req.session.user.id,
          content,
          Boolean(anonymous)
        ]
      );

      res.json({
        success: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not submit feedback."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| STAFF DIRECTORY
|--------------------------------------------------------------------------
*/

app.get(
  "/api/management/staff",
  requireManagement,
  async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT
          id,
          username,
          display_name,
          role,
          department,
          status,
          created_at
        FROM users
        ORDER BY username ASC
      `);

      res.json(result.rows);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Could not load staff."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| STATIC WEBSITE
|--------------------------------------------------------------------------
*/

app.get("*", (req, res) => {
  const file = path.join(__dirname, "index.html");

  if (!fs.existsSync(file)) {
    return res.status(404).send("index.html not found.");
  }

  res.sendFile(file);
});

/*
|--------------------------------------------------------------------------
| START
|--------------------------------------------------------------------------
*/

async function start() {
  try {
    await setupDatabase();

    app.listen(PORT, () => {
      console.log(`FRT Staff Portal running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Startup error:", error);
    process.exit(1);
  }
}

start();
