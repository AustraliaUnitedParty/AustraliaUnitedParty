require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStoreFactory = require("connect-sqlite3");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { z } = require("zod");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, "party.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','secretary','membership_officer','viewer')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  member_code TEXT UNIQUE NOT NULL,
  title TEXT DEFAULT '',
  given_names TEXT NOT NULL,
  surname TEXT NOT NULL,
  dob TEXT NOT NULL,
  address_line1 TEXT NOT NULL,
  address_line2 TEXT DEFAULT '',
  suburb TEXT NOT NULL,
  state TEXT NOT NULL,
  postcode TEXT NOT NULL,
  email TEXT DEFAULT '',
  phone TEXT DEFAULT '',
  enrolled_voter INTEGER NOT NULL DEFAULT 0,
  supports_registration INTEGER NOT NULL DEFAULT 0,
  not_counted_for_other_party INTEGER NOT NULL DEFAULT 0,
  consent_to_membership INTEGER NOT NULL DEFAULT 0,
  privacy_acknowledged INTEGER NOT NULL DEFAULT 0,
  declaration_name TEXT DEFAULT '',
  declaration_date TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending','active','incomplete','withdrawn','reserve','selected')),
  notes TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  entity TEXT NOT NULL,
  entity_id INTEGER,
  details TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS party_profile (
  id INTEGER PRIMARY KEY CHECK(id=1),
  party_name TEXT NOT NULL,
  party_abbreviation TEXT DEFAULT '',
  website TEXT DEFAULT '',
  email TEXT DEFAULT '',
  phone TEXT DEFAULT '',
  street_address TEXT DEFAULT '',
  postal_address TEXT DEFAULT '',
  registered_officer TEXT DEFAULT '',
  party_secretary TEXT DEFAULT '',
  updated_at TEXT NOT NULL
);
`);

const now = () => new Date().toISOString();
const adminName = process.env.ADMIN_USERNAME || "admin";
const adminPass = process.env.ADMIN_PASSWORD || "";
if (!db.prepare("SELECT id FROM users WHERE username=?").get(adminName) && adminPass) {
  const hash = bcrypt.hashSync(adminPass, 12);
  db.prepare("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)")
    .run(adminName, hash, "admin", now());
}
if (!db.prepare("SELECT id FROM party_profile WHERE id=1").get()) {
  db.prepare(`INSERT INTO party_profile(id,party_name,updated_at) VALUES(1,?,?)`)
    .run(process.env.PARTY_NAME || "Australia United Party", now());
}

const SQLiteStore = SQLiteStoreFactory(session);
app.disable("x-powered-by");
if (process.env.TRUST_PROXY === "true") app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: {
  directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"],
    imgSrc: ["'self'", "data:"], connectSrc: ["'self'"], objectSrc: ["'none'"],
    baseUri: ["'self'"], frameAncestors: ["'none'"], formAction: ["'self'"]
  }
}}));
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "100kb" }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: DATA_DIR }),
  name: "aup.sid",
  secret: process.env.SESSION_SECRET || "development-only-change-this-secret",
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "strict", secure: process.env.COOKIE_SECURE === "true",
    maxAge: 8 * 60 * 60 * 1000 }
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10,
  standardHeaders: "draft-7", legacyHeaders: false });
const roles = {
  admin: ["read","write","export","manage_users","manage_settings","audit"],
  secretary: ["read","write","export","audit"],
  membership_officer: ["read","write","export"],
  viewer: ["read"]
};
function hasPermission(user, permission) {
  return !!user && !!roles[user.role]?.includes(permission);
}
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Please sign in." });
  next();
}
function requirePermission(permission) {
  return (req, res, next) => hasPermission(req.session.user, permission)
    ? next() : res.status(403).json({ error: "You do not have permission to perform this action." });
}
function audit(req, action, entity, entityId, details="") {
  db.prepare(`INSERT INTO audit_log(user_id,action,entity,entity_id,details,created_at)
              VALUES(?,?,?,?,?,?)`)
    .run(req.session.user?.id || null, action, entity, entityId || null, details, now());
}
function csrf(req, res, next) {
  if (["GET","HEAD","OPTIONS"].includes(req.method)) return next();
  const token = req.get("x-csrf-token");
  if (!req.session.csrfToken || !token ||
      !crypto.timingSafeEqual(Buffer.from(req.session.csrfToken), Buffer.from(token))) {
    return res.status(403).json({ error: "Security token expired. Refresh and try again." });
  }
  next();
}
app.use("/api", csrf);

const memberSchema = z.object({
  title: z.string().max(20).optional().default(""),
  given_names: z.string().trim().min(1).max(100),
  surname: z.string().trim().min(1).max(100),
  dob: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  address_line1: z.string().trim().min(1).max(150),
  address_line2: z.string().max(150).optional().default(""),
  suburb: z.string().trim().min(1).max(100),
  state: z.enum(["ACT","NSW","NT","QLD","SA","TAS","VIC","WA"]),
  postcode: z.string().regex(/^\d{4}$/),
  email: z.string().email().max(254).or(z.literal("")).optional().default(""),
  phone: z.string().max(30).optional().default(""),
  enrolled_voter: z.boolean(),
  supports_registration: z.boolean(),
  not_counted_for_other_party: z.boolean(),
  consent_to_membership: z.boolean(),
  privacy_acknowledged: z.boolean(),
  declaration_name: z.string().trim().min(1).max(150),
  declaration_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  notes: z.string().max(1000).optional().default("")
});
function nextMemberCode() {
  const n = db.prepare("SELECT seq FROM sqlite_sequence WHERE name='members'").get()?.seq || 0;
  return `AUP-${String(n + 1).padStart(6, "0")}`;
}
function deriveStatus(m) {
  const required = m.given_names && m.surname && m.dob && m.address_line1 &&
    m.suburb && m.state && m.postcode && m.enrolled_voter &&
    m.supports_registration && m.not_counted_for_other_party &&
    m.consent_to_membership && m.privacy_acknowledged && m.declaration_name && m.declaration_date;
  return required ? "active" : "incomplete";
}
function duplicateMember(m, exceptId=null) {
  const q = `SELECT id FROM members WHERE lower(given_names)=lower(?) AND lower(surname)=lower(?)
    AND dob=? AND lower(address_line1)=lower(?) AND lower(suburb)=lower(?) ${exceptId ? "AND id<>?" : ""} LIMIT 1`;
  return exceptId
    ? db.prepare(q).get(m.given_names,m.surname,m.dob,m.address_line1,m.suburb,exceptId)
    : db.prepare(q).get(m.given_names,m.surname,m.dob,m.address_line1,m.suburb);
}

app.get("/api/csrf", (req,res) => {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  res.json({ token: req.session.csrfToken });
});
app.post("/api/login", loginLimiter, (req,res) => {
  const parsed = z.object({username:z.string().min(1).max(80),password:z.string().min(1).max(200)}).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({error:"Enter username and password."});
  const user = db.prepare("SELECT * FROM users WHERE username=? AND active=1").get(parsed.data.username);
  if (!user || !bcrypt.compareSync(parsed.data.password,user.password_hash))
    return res.status(401).json({error:"Invalid sign-in details."});
  req.session.regenerate(err => {
    if (err) return res.status(500).json({error:"Could not start secure session."});
    req.session.user = {id:user.id,username:user.username,role:user.role};
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
    res.json({user:req.session.user,csrfToken:req.session.csrfToken});
  });
});
app.post("/api/logout", requireAuth, (req,res) => req.session.destroy(() => res.json({ok:true})));
app.get("/api/me", (req,res) => res.json({user:req.session.user || null}));
app.get("/api/config", (req,res) => {
  const p = db.prepare("SELECT party_name,party_abbreviation,website,email,phone FROM party_profile WHERE id=1").get();
  res.json({party:p});
});
app.get("/api/dashboard", requireAuth, requirePermission("read"), (req,res) => {
  const counts = db.prepare(`SELECT
    COUNT(*) total,
    SUM(status='active') active,
    SUM(status='pending') pending,
    SUM(status='incomplete') incomplete,
    SUM(status='withdrawn') withdrawn,
    SUM(status='reserve') reserve,
    SUM(status='selected') selected
    FROM members`).get();
  res.json({counts, target:1500, selectionLimit:1650});
});
app.get("/api/members", requireAuth, requirePermission("read"), (req,res) => {
  const q = String(req.query.q || "").slice(0,100);
  const status = String(req.query.status || "");
  let rows;
  if (status && ["pending","active","incomplete","withdrawn","reserve","selected"].includes(status)) {
    rows = db.prepare(`SELECT id,member_code,given_names,surname,dob,suburb,state,email,phone,status,created_at
      FROM members WHERE status=? AND (given_names LIKE ? OR surname LIKE ? OR member_code LIKE ?)
      ORDER BY id DESC LIMIT 500`).all(status,`%${q}%`,`%${q}%`,`%${q}%`);
  } else {
    rows = db.prepare(`SELECT id,member_code,given_names,surname,dob,suburb,state,email,phone,status,created_at
      FROM members WHERE given_names LIKE ? OR surname LIKE ? OR member_code LIKE ?
      ORDER BY id DESC LIMIT 500`).all(`%${q}%`,`%${q}%`,`%${q}%`);
  }
  res.json({members:rows});
});
app.post("/api/members", requireAuth, requirePermission("write"), (req,res) => {
  const parsed = memberSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({error:"Please check required fields and formats.",details:parsed.error.flatten()});
  const m = parsed.data;
  if (duplicateMember(m)) return res.status(409).json({error:"Possible duplicate: matching name, date of birth and address already exists."});
  const status = deriveStatus(m);
  const code = nextMemberCode();
  const result = db.prepare(`INSERT INTO members(
    member_code,title,given_names,surname,dob,address_line1,address_line2,suburb,state,postcode,email,phone,
    enrolled_voter,supports_registration,not_counted_for_other_party,consent_to_membership,privacy_acknowledged,
    declaration_name,declaration_date,status,notes,created_at,updated_at)
    VALUES(@member_code,@title,@given_names,@surname,@dob,@address_line1,@address_line2,@suburb,@state,@postcode,
    @email,@phone,@enrolled_voter,@supports_registration,@not_counted_for_other_party,@consent_to_membership,
    @privacy_acknowledged,@declaration_name,@declaration_date,@status,@notes,@created_at,@updated_at)`)
    .run({...m,member_code:code,status,created_at:now(),updated_at:now()});
  audit(req,"CREATE","member",result.lastInsertRowid,`Created ${code}`);
  res.status(201).json({id:result.lastInsertRowid,member_code:code,status});
});
app.patch("/api/members/:id/status", requireAuth, requirePermission("write"), (req,res) => {
  const status = z.enum(["pending","active","incomplete","withdrawn","reserve","selected"]).safeParse(req.body.status);
  if (!status.success) return res.status(400).json({error:"Invalid status."});
  const id = Number(req.params.id);
  const member = db.prepare("SELECT id,member_code,status FROM members WHERE id=?").get(id);
  if (!member) return res.status(404).json({error:"Member not found."});
  if (["reserve","selected"].includes(status.data) && member.status !== "active")
    return res.status(400).json({error:"Only active records can be moved to reserve or selected."});
  db.prepare("UPDATE members SET status=?,updated_at=? WHERE id=?").run(status.data,now(),id);
  audit(req,"STATUS_CHANGE","member",id,`${member.status} -> ${status.data}`);
  res.json({ok:true});
});
app.delete("/api/members/:id", requireAuth, requirePermission("admin"), (req,res) => {
  const id = Number(req.params.id);
  const m = db.prepare("SELECT member_code FROM members WHERE id=?").get(id);
  if (!m) return res.status(404).json({error:"Member not found."});
  db.prepare("DELETE FROM members WHERE id=?").run(id);
  audit(req,"DELETE","member",id,`Deleted ${m.member_code}`);
  res.json({ok:true});
});
app.get("/api/export/aec.csv", requireAuth, requirePermission("export"), (req,res) => {
  const rows = db.prepare(`SELECT title,given_names,surname,dob,address_line1,address_line2,suburb,state,postcode,email,phone
    FROM members WHERE status IN ('active','selected') AND enrolled_voter=1 AND supports_registration=1
    AND not_counted_for_other_party=1 AND consent_to_membership=1 AND privacy_acknowledged=1
    ORDER BY id LIMIT 1650`).all();
  const headers = ["Title","Given names","Surname","Date of birth","Residential address line 1",
    "Residential address line 2","Suburb/Town","State","Postcode","Email","Phone"];
  const esc = v => `"${String(v ?? "").replace(/"/g,'""')}"`;
  const csv = [headers.map(esc).join(","),...rows.map(r=>[
    r.title,r.given_names,r.surname,r.dob,r.address_line1,r.address_line2,r.suburb,r.state,r.postcode,r.email,r.phone
  ].map(esc).join(","))].join("\r\n");
  audit(req,"EXPORT","members",null,`AEC-oriented CSV export: ${rows.length} rows`);
  res.setHeader("Content-Type","text/csv; charset=utf-8");
  res.setHeader("Content-Disposition",'attachment; filename="Australia_United_Party_AEC_members.csv"');
  res.send("\uFEFF"+csv);
});
app.get("/api/audit", requireAuth, requirePermission("audit"), (req,res) => {
  const rows = db.prepare(`SELECT a.id,a.action,a.entity,a.entity_id,a.details,a.created_at,u.username
    FROM audit_log a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 300`).all();
  res.json({logs:rows});
});
app.get("/api/settings", requireAuth, requirePermission("manage_settings"), (req,res) => {
  res.json({party:db.prepare("SELECT * FROM party_profile WHERE id=1").get()});
});
app.put("/api/settings", requireAuth, requirePermission("manage_settings"), (req,res) => {
  const p = z.object({
    party_name:z.string().trim().min(1).max(120),
    party_abbreviation:z.string().max(30).optional().default(""),
    website:z.string().max(200).optional().default(""),
    email:z.string().email().or(z.literal("")).optional().default(""),
    phone:z.string().max(40).optional().default(""),
    street_address:z.string().max(200).optional().default(""),
    postal_address:z.string().max(200).optional().default(""),
    registered_officer:z.string().max(120).optional().default(""),
    party_secretary:z.string().max(120).optional().default("")
  }).safeParse(req.body);
  if (!p.success) return res.status(400).json({error:"Please check the party details."});
  db.prepare(`UPDATE party_profile SET party_name=@party_name,party_abbreviation=@party_abbreviation,
    website=@website,email=@email,phone=@phone,street_address=@street_address,postal_address=@postal_address,
    registered_officer=@registered_officer,party_secretary=@party_secretary,updated_at=@updated_at WHERE id=1`)
    .run({...p.data,updated_at:now()});
  audit(req,"UPDATE","party_profile",1,"Updated party profile");
  res.json({ok:true});
});
app.post("/api/users", requireAuth, requirePermission("manage_users"), (req,res) => {
  const p = z.object({username:z.string().trim().min(3).max(80),password:z.string().min(14).max(200),
    role:z.enum(["admin","secretary","membership_officer","viewer"])}).safeParse(req.body);
  if (!p.success) return res.status(400).json({error:"Use a username and a password of at least 14 characters."});
  try {
    const hash = bcrypt.hashSync(p.data.password,12);
    const r = db.prepare("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)")
      .run(p.data.username,hash,p.data.role,now());
    audit(req,"CREATE","user",r.lastInsertRowid,`Created user ${p.data.username} (${p.data.role})`);
    res.status(201).json({ok:true});
  } catch { res.status(409).json({error:"That username already exists."}); }
});

app.use(express.static(path.join(__dirname,"public"), { etag:true, maxAge:"1h" }));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.use((err,req,res,next)=>{ console.error(err); res.status(500).json({error:"An unexpected server error occurred."}); });

app.listen(PORT,()=>console.log(`Australia United Party workspace listening on port ${PORT}`));
