import sqlite3

def test_sqlite_backup_restore_preserves_representative_state(tmp_path):
    source = tmp_path / "raven.db"; backup = tmp_path / "raven.backup.db"
    with sqlite3.connect(source) as db:
        db.execute("create table organizations (organization_id text primary key)")
        db.execute("insert into organizations values ('org-1')")
        db.commit()
        destination = sqlite3.connect(backup)
        db.backup(destination)
        destination.close()
    with sqlite3.connect(source) as db:
        db.execute("delete from organizations"); db.commit()
    with sqlite3.connect(backup) as db:
        assert db.execute("select organization_id from organizations").fetchone() == ("org-1",)
