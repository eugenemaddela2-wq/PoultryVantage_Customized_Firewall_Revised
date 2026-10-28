import os
import shutil
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path

from config import DB_PATH, BACKUP_DIR

PST_TIMEZONE = timezone(timedelta(hours=8))

def utcnow():
    return datetime.now(timezone.utc).isoformat()

def ph_now_iso():
    return datetime.now(PST_TIMEZONE).isoformat()

@contextmanager
def connect():
    """Yield a SQLite connection and always close it after the transaction."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                received_at TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                forwarded_at TEXT,
                latency_ms REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS authorized_devices (
                device_id TEXT PRIMARY KEY,
                secret_key TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                approved_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS browser_access (
                session_token TEXT PRIMARY KEY,
                client_ip TEXT NOT NULL,
                user_agent TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                approved_at TEXT,
                last_active_at TEXT,
                revoked_at TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS banned_ips (
                ip_address TEXT PRIMARY KEY,
                banned_at TEXT NOT NULL,
                reason TEXT
            )
        """)

def get_browser_status(session_token):
    with connect() as conn:
        row = conn.execute("SELECT status FROM browser_access WHERE session_token = ?", (session_token,)).fetchone()
        return row["status"] if row else None

def request_browser_access(session_token, client_ip, user_agent):
    now = ph_now_iso()
    with connect() as conn:
        conn.execute("""
            INSERT INTO browser_access (session_token, client_ip, user_agent, status, created_at, last_active_at)
            VALUES (?, ?, ?, 'pending', ?, ?)
            ON CONFLICT(session_token) DO UPDATE SET
                client_ip = excluded.client_ip,
                user_agent = excluded.user_agent,
                last_active_at = excluded.last_active_at
        """, (session_token, client_ip, user_agent, now, now))

def grant_browser_access(session_token):
    now = ph_now_iso()
    with connect() as conn:
        conn.execute("""
            UPDATE browser_access 
            SET status = 'approved', approved_at = ?, last_active_at = ?
            WHERE session_token = ?
        """, (now, now, session_token))

def revoke_browser_access(session_token):
    now = ph_now_iso()
    with connect() as conn:
        conn.execute("""
            UPDATE browser_access 
            SET status = 'revoked', revoked_at = ?
            WHERE session_token = ?
        """, (now, session_token))

def update_browser_heartbeat(session_token):
    now = ph_now_iso()
    with connect() as conn:
        conn.execute("""
            UPDATE browser_access 
            SET last_active_at = ? 
            WHERE session_token = ? AND status = 'approved'
        """, (now, session_token))

# --- IP BAN FUNCTIONS ---
def ban_ip_address(ip_address, reason="Admin manually banned this client IP"):
    now = ph_now_iso()
    with connect() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO banned_ips (ip_address, banned_at, reason)
            VALUES (?, ?, ?)
        """, (ip_address, now, reason))
        # Revoke any active browser sessions associated with this IP
        conn.execute("""
            UPDATE browser_access
            SET status = 'banned', revoked_at = ?
            WHERE client_ip = ?
        """, (now, ip_address))

def is_ip_permanently_banned(ip_address):
    with connect() as conn:
        row = conn.execute("SELECT ip_address FROM banned_ips WHERE ip_address = ?", (ip_address,)).fetchone()
        return bool(row)

def unban_ip_address(ip_address):
    with connect() as conn:
        conn.execute("DELETE FROM banned_ips WHERE ip_address = ?", (ip_address,))

def list_browser_requests():
    with connect() as conn:
        rows = conn.execute("SELECT * FROM browser_access ORDER BY created_at DESC LIMIT 50").fetchall()
        now = datetime.now(PST_TIMEZONE)
        results = []

        for r in rows:
            item = dict(r)
            status = item.get("status", "pending")
            approved_at_str = item.get("approved_at")
            last_active_str = item.get("last_active_at")
            revoked_at_str = item.get("revoked_at")

            session_duration_sec = 0
            is_active_online = False

            if approved_at_str:
                try:
                    start_time = datetime.fromisoformat(approved_at_str)
                    if start_time.tzinfo is None:
                        start_time = start_time.replace(tzinfo=PST_TIMEZONE)

                    if status == "approved":
                        end_time = now
                        if last_active_str:
                            last_active = datetime.fromisoformat(last_active_str)
                            if last_active.tzinfo is None:
                                last_active = last_active.replace(tzinfo=PST_TIMEZONE)
                            if (now - last_active).total_seconds() <= 20:
                                is_active_online = True
                    elif status in ["revoked", "banned"] and revoked_at_str:
                        # Timer shuts off at the moment of revocation
                        end_time = datetime.fromisoformat(revoked_at_str)
                        if end_time.tzinfo is None:
                            end_time = end_time.replace(tzinfo=PST_TIMEZONE)
                    else:
                        end_time = now

                    session_duration_sec = max(0, int((end_time - start_time).total_seconds()))
                except Exception:
                    session_duration_sec = 0

            hrs = session_duration_sec // 3600
            mins = (session_duration_sec % 3600) // 60
            secs = session_duration_sec % 60
            if hrs > 0:
                item["live_duration"] = f"{hrs}h {mins}m"
            elif mins > 0:
                item["live_duration"] = f"{mins}m {secs}s"
            elif session_duration_sec > 0:
                item["live_duration"] = f"{secs}s"
            else:
                item["live_duration"] = "—"

            item["is_online"] = is_active_online
            results.append(item)

        return results

def get_device(device_id):
    with connect() as conn:
        row = conn.execute("SELECT * FROM authorized_devices WHERE device_id = ?", (device_id,)).fetchone()
        return dict(row) if row else None

def register_pending_device(device_id, secret_key=""):
    with connect() as conn:
        conn.execute("""
            INSERT OR IGNORE INTO authorized_devices (device_id, secret_key, status, created_at)
            VALUES (?, ?, 'pending', ?)
        """, (device_id, secret_key, utcnow()))

def set_device_status(device_id, status, secret_key=None):
    with connect() as conn:
        if secret_key:
            conn.execute("""
                UPDATE authorized_devices 
                SET status = ?, approved_at = ?, secret_key = ? 
                WHERE device_id = ?
            """, (status, utcnow(), secret_key, device_id))
        else:
            conn.execute("""
                UPDATE authorized_devices 
                SET status = ?, approved_at = ? 
                WHERE device_id = ?
            """, (status, utcnow(), device_id))

def list_devices():
    with connect() as conn:
        return [dict(r) for r in conn.execute("SELECT device_id, status, created_at, approved_at FROM authorized_devices").fetchall()]
        


def add_record(device_id, payload_text, status="buffered"):
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO records (device_id, payload, received_at, status) VALUES (?, ?, ?, ?)",
            (device_id, payload_text, utcnow(), status),
        )
        return cur.lastrowid


def mark_forwarded(record_id, latency_ms=None):
    with connect() as conn:
        conn.execute(
            "UPDATE records SET status='forwarded', forwarded_at=?, last_error=NULL, latency_ms=? WHERE id=?",
            (utcnow(), latency_ms, record_id),
        )


def mark_failed(record_id, error):
    with connect() as conn:
        conn.execute(
            "UPDATE records SET status='buffered', attempts=attempts+1, last_error=? WHERE id=?",
            (str(error)[:500], record_id),
        )


def get_pending(limit=100):
    with connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM records WHERE status='buffered' ORDER BY id ASC LIMIT ?", (limit,)
        ).fetchall()]


def get_recent_records(limit=50):
    with connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM records ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()]


def add_event(event_type, message):
    with connect() as conn:
        conn.execute(
            "INSERT INTO events (event_type, message, created_at) VALUES (?, ?, ?)",
            (event_type, message, utcnow()),
        )


def get_recent_events(limit=100):
    with connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()]


def counts():
    with connect() as conn:
        result = {"total": 0, "forwarded": 0, "buffered": 0}
        for row in conn.execute("SELECT status, COUNT(*) AS c FROM records GROUP BY status"):
            result[row["status"]] = row["c"]
            result["total"] += row["c"]
        return result
    

# In storage.py

def backup_database():
    """Single, clean automated/manual backup function."""
    db_file = Path(DB_PATH)
    if not db_file.exists():
        raise FileNotFoundError("Database file not found.")
    
    backup_path = Path(BACKUP_DIR)
    backup_path.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    dest_file = backup_path / f"gateway_backup_{timestamp}.db"
    
    # SQLite's online backup API avoids copying a database while a write is in progress.
    source = sqlite3.connect(str(db_file))
    destination = sqlite3.connect(str(dest_file))
    try:
        source.backup(destination)
    finally:
        destination.close()
        source.close()
    return str(dest_file)


def get_performance_stats():
    """Calculates transmission reliability metrics for Objective 3."""
    with connect() as conn:
        # Total, forwarded, and buffered counts
        summary = conn.execute("""
            SELECT 
                COUNT(*) as total_records,
                SUM(CASE WHEN status = 'forwarded' THEN 1 ELSE 0 END) as forwarded_count,
                SUM(CASE WHEN status = 'buffered' THEN 1 ELSE 0 END) as buffered_count,
                AVG(latency_ms) as avg_latency_ms,
                MAX(latency_ms) as max_latency_ms,
                AVG(attempts) as avg_retry_attempts
            FROM records
        """).fetchone()

        stats = dict(summary)
        
        # Calculate reliability percentage
        total = stats["total_records"] or 0
        forwarded = stats["forwarded_count"] or 0
        forwarded_record_rate = (forwarded / total * 100) if total > 0 else 0.0
        
        stats["forwarded_record_rate"] = round(forwarded_record_rate, 2)
        stats["avg_latency_ms"] = round(stats["avg_latency_ms"] or 0.0, 2)
        stats["max_latency_ms"] = round(stats["max_latency_ms"] or 0.0, 2)
        stats["avg_retry_attempts"] = round(stats["avg_retry_attempts"] or 0.0, 2)
        return stats