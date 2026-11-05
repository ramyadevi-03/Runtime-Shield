import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone


class LeaseRepository:
    def __init__(self, path, claim_ttl_seconds=30):
        if claim_ttl_seconds <= 0:
            raise ValueError("claim_ttl_seconds must be positive")
        self.path = path
        self.claim_ttl_seconds = claim_ttl_seconds
        self.lock = threading.RLock()
        with self.lock, self._db() as connection:
            connection.execute('BEGIN IMMEDIATE')
            connection.execute('''CREATE TABLE IF NOT EXISTS leases(
                id TEXT PRIMARY KEY, agent TEXT NOT NULL, workload TEXT NOT NULL,
                alias TEXT NOT NULL, tool TEXT NOT NULL, operation TEXT NOT NULL,
                resource TEXT NOT NULL, manifest_hash TEXT NOT NULL, delegation_id TEXT,
                decision_ref TEXT NOT NULL, created TEXT NOT NULL, expires TEXT NOT NULL,
                max_uses INTEGER NOT NULL, uses INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL, audience TEXT NOT NULL)''')
            claim_table = connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='lease_claims'").fetchone()
            if claim_table:
                columns = {row['name'] for row in connection.execute('PRAGMA table_info(lease_claims)')}
                if not {'claim_id', 'created_at', 'expires_at'}.issubset(columns):
                    # Old claims had no reliable expiry. Expire them during migration so
                    # an interrupted redemption cannot permanently consume capacity.
                    connection.execute('DROP INDEX IF EXISTS lease_claims_lease_id')
                    connection.execute('ALTER TABLE lease_claims RENAME TO lease_claims_legacy')
                    self._create_claim_table(connection)
                    now = self._now().isoformat()
                    old_id = 'token' if 'token' in columns else 'claim_id'
                    connection.execute(
                        f'INSERT INTO lease_claims(claim_id,lease_id,created_at,expires_at) '
                        f'SELECT {old_id},lease_id,?,? FROM lease_claims_legacy',
                        (now, now),
                    )
                    connection.execute('DROP TABLE lease_claims_legacy')
            else:
                self._create_claim_table(connection)
            connection.execute('CREATE INDEX IF NOT EXISTS lease_claims_lease_id ON lease_claims(lease_id)')
            connection.commit()

    @staticmethod
    def _create_claim_table(connection):
        connection.execute('''CREATE TABLE lease_claims(
            claim_id TEXT PRIMARY KEY, lease_id TEXT NOT NULL,
            created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
            FOREIGN KEY(lease_id) REFERENCES leases(id) ON DELETE CASCADE)''')

    @contextmanager
    def _db(self):
        connection = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        finally:
            connection.close()

    @staticmethod
    def _now():
        return datetime.now(timezone.utc)

    def create(self, row):
        columns = ["id", "agent", "workload", "alias", "tool", "operation", "resource", "manifest_hash", "delegation_id", "decision_ref", "created", "expires", "max_uses", "uses", "status", "audience"]
        placeholders = ",".join("?" for _ in columns)
        with self.lock, self._db() as connection:
            with connection:
                connection.execute(f'INSERT INTO leases ({",".join(columns)}) VALUES ({placeholders})', tuple(row[key] for key in columns))

    def get(self, lid):
        with self.lock, self._db() as connection:
            row = connection.execute('SELECT * FROM leases WHERE id=?', (lid,)).fetchone()
            return dict(row) if row else None

    def claim(self, lid, audience):
        """Reserve one use while the broker fetches the credential."""
        with self.lock, self._db() as connection:
            connection.execute('BEGIN IMMEDIATE')
            row = connection.execute('SELECT * FROM leases WHERE id=?', (lid,)).fetchone()
            if not row:
                connection.commit()
                return None, None, "missing"
            lease = dict(row)
            if lease['status'] != 'active':
                connection.commit()
                return lease, None, "inactive"
            if datetime.fromisoformat(lease['expires']) <= self._now():
                connection.execute("UPDATE leases SET status='expired' WHERE id=? AND status='active'", (lid,))
                connection.execute('DELETE FROM lease_claims WHERE lease_id=?', (lid,))
                connection.commit()
                return lease, None, "expired"
            if lease['audience'] != audience:
                connection.commit()
                return lease, None, "audience"
            now = self._now()
            connection.execute('DELETE FROM lease_claims WHERE lease_id=? AND expires_at<=?', (lid, now.isoformat()))
            pending = connection.execute('SELECT COUNT(*) FROM lease_claims WHERE lease_id=?', (lid,)).fetchone()[0]
            if lease['uses'] + pending >= lease['max_uses']:
                connection.commit()
                return lease, None, "used"
            claim_id = str(uuid.uuid4())
            created_at = now.isoformat()
            expires_at = (now + timedelta(seconds=self.claim_ttl_seconds)).isoformat()
            connection.execute(
                'INSERT INTO lease_claims(claim_id,lease_id,created_at,expires_at) VALUES(?,?,?,?)',
                (claim_id, lid, created_at, expires_at),
            )
            connection.commit()
            return lease, claim_id, "ok"

    def finalize(self, lid, claim_id):
        """Consume a reservation only if the lease is still redeemable."""
        with self.lock, self._db() as connection:
            connection.execute('BEGIN IMMEDIATE')
            row = connection.execute('SELECT * FROM leases WHERE id=?', (lid,)).fetchone()
            claim = connection.execute(
                'SELECT expires_at FROM lease_claims WHERE claim_id=? AND lease_id=?',
                (claim_id, lid),
            ).fetchone()
            if not row or not claim:
                connection.commit()
                return False
            lease = dict(row)
            if lease['status'] != 'active':
                connection.execute('DELETE FROM lease_claims WHERE claim_id=? AND lease_id=?', (claim_id, lid))
                connection.commit()
                return False
            if datetime.fromisoformat(lease['expires']) <= self._now():
                connection.execute("UPDATE leases SET status='expired' WHERE id=? AND status='active'", (lid,))
                connection.execute('DELETE FROM lease_claims WHERE lease_id=?', (lid,))
                connection.commit()
                return False
            if datetime.fromisoformat(claim['expires_at']) <= self._now():
                connection.execute('DELETE FROM lease_claims WHERE claim_id=? AND lease_id=?', (claim_id, lid))
                connection.commit()
                return False
            uses = lease['uses'] + 1
            status = 'redeemed' if uses >= lease['max_uses'] else 'active'
            connection.execute('UPDATE leases SET uses=?,status=? WHERE id=? AND status=\'active\'', (uses, status, lid))
            connection.execute('DELETE FROM lease_claims WHERE claim_id=? AND lease_id=?', (claim_id, lid))
            connection.commit()
            return True

    def release(self, lid, claim_id):
        """Release a failed fetch without reviving expired or revoked leases."""
        with self.lock, self._db() as connection:
            connection.execute('BEGIN IMMEDIATE')
            row = connection.execute('SELECT status,expires FROM leases WHERE id=?', (lid,)).fetchone()
            if row and row['status'] == 'active' and datetime.fromisoformat(row['expires']) <= self._now():
                connection.execute("UPDATE leases SET status='expired' WHERE id=? AND status='active'", (lid,))
                connection.execute('DELETE FROM lease_claims WHERE lease_id=?', (lid,))
            connection.execute('DELETE FROM lease_claims WHERE claim_id=? AND lease_id=?', (claim_id, lid))
            connection.commit()

    def redeem(self, lid, audience):
        """Compatibility helper for callers that do not need a vault round trip."""
        row, claim_id, reason = self.claim(lid, audience)
        if reason == 'ok' and not self.finalize(lid, claim_id):
            return row, 'inactive'
        return row, reason

    def revoke(self, lid):
        with self.lock, self._db() as connection:
            connection.execute('BEGIN IMMEDIATE')
            row = connection.execute('SELECT status FROM leases WHERE id=?', (lid,)).fetchone()
            if not row:
                connection.commit()
                return None
            new_status = 'revoked' if row['status'] == 'active' else row['status']
            connection.execute('UPDATE leases SET status=? WHERE id=?', (new_status, lid))
            if new_status == 'revoked':
                connection.execute('DELETE FROM lease_claims WHERE lease_id=?', (lid,))
            connection.commit()
            return new_status

    def cleanup(self):
        with self.lock, self._db() as connection:
            connection.execute('BEGIN IMMEDIATE')
            expired = connection.execute("UPDATE leases SET status='expired' WHERE status='active' AND expires<=?", (self._now().isoformat(),)).rowcount
            connection.execute("DELETE FROM lease_claims WHERE lease_id IN (SELECT id FROM leases WHERE status='expired')")
            connection.commit()
            return expired
