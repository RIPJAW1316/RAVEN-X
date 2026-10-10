"""Start SQLite writes before reading state used for lifecycle decisions."""


def begin_serialized_write(session):
    """Acquire SQLite's reserved writer lock before a read-modify-write cycle.

    SQLite's deferred transactions allow two sessions to read the same state
    before either writes.  A later write can then overwrite a terminal state
    or fail with SQLITE_BUSY_SNAPSHOT.  BEGIN IMMEDIATE makes the second writer
    wait before its SELECT.  Other databases use row locks at the call sites.
    """
    connection = session.connection()
    if connection.dialect.name == "sqlite":
        connection.exec_driver_sql("BEGIN IMMEDIATE")
