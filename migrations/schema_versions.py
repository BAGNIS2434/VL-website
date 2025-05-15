import sqlite3
from datetime import datetime

class Migration:
    def __init__(self, db_path):
        self.db_path = db_path
        
    def init_migrations(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS schema_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version INTEGER NOT NULL,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.commit()
        conn.close()
    
    def get_current_version(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT MAX(version) FROM schema_versions')
        version = c.fetchone()[0] or 0
        conn.close()
        return version

    def apply_migration(self, version, sql):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        try:
            c.executescript(sql)
            c.execute('INSERT INTO schema_versions (version) VALUES (?)', [version])
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
