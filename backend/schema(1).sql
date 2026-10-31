-- YARDLEY ESPORTS — SQLite Relational Database Schema
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE,
  email_or_phone TEXT NOT NULL UNIQUE,
  ff_uid TEXT NOT NULL UNIQUE,
  ff_ign TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'player' CHECK(role IN ('player', 'admin')),
  team_id TEXT,
  kills INTEGER NOT NULL DEFAULT 0,
  wins INTEGER NOT NULL DEFAULT 0,
  total_points INTEGER NOT NULL DEFAULT 0,
  earnings INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS teams (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  tag TEXT NOT NULL,
  captain_id TEXT NOT NULL,
  invite_code TEXT NOT NULL UNIQUE,
  members_json TEXT NOT NULL DEFAULT '[]',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (captain_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tournaments (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  mode TEXT NOT NULL CHECK(mode IN ('BR-Squad', 'BR-Duo', 'BR-Solo', 'Clash Squad', '2v2', '1v1')),
  status TEXT NOT NULL DEFAULT 'upcoming' CHECK(status IN ('upcoming', 'live', 'completed')),
  match_date TEXT NOT NULL,
  match_time TEXT NOT NULL,
  map_name TEXT NOT NULL DEFAULT 'Bermuda',
  entry_fee INTEGER NOT NULL DEFAULT 0 CHECK(entry_fee >= 0),
  prize_pool INTEGER NOT NULL DEFAULT 0 CHECK(prize_pool >= 0),
  first_prize INTEGER NOT NULL DEFAULT 0,
  per_kill_reward INTEGER NOT NULL DEFAULT 0,
  max_slots INTEGER NOT NULL CHECK(max_slots >= 2 AND max_slots <= 100),
  room_id TEXT DEFAULT '',
  room_password TEXT DEFAULT '',
  requires_approval INTEGER NOT NULL DEFAULT 0,
  rules TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS registrations (
  id TEXT PRIMARY KEY,
  tournament_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  player_name TEXT NOT NULL,
  ign TEXT NOT NULL,
  ff_uid TEXT NOT NULL,
  team_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'approved' CHECK(status IN ('approved', 'pending_approval', 'rejected')),
  payment_status TEXT NOT NULL DEFAULT 'pending' CHECK(payment_status IN ('pending', 'verified_sandbox_upi', 'verified_razorpay', 'failed')),
  upi_ref TEXT NOT NULL,
  amount_paid INTEGER NOT NULL DEFAULT 0,
  registered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(tournament_id, user_id),
  UNIQUE(tournament_id, ff_uid),
  FOREIGN KEY (tournament_id) REFERENCES tournaments(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS results (
  id TEXT PRIMARY KEY,
  tournament_id TEXT NOT NULL,
  tournament_title TEXT NOT NULL,
  mode TEXT NOT NULL,
  rank INTEGER NOT NULL,
  team_or_player TEXT NOT NULL,
  kills INTEGER NOT NULL DEFAULT 0,
  placement_points INTEGER NOT NULL DEFAULT 0,
  total_points INTEGER NOT NULL DEFAULT 0,
  prize_won INTEGER NOT NULL DEFAULT 0,
  payout_status TEXT NOT NULL DEFAULT 'PAID VIA UPI',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tournament_id) REFERENCES tournaments(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS announcements (
  id TEXT PRIMARY KEY,
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
