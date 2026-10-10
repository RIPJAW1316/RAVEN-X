"""Thread-safe presence repository for deterministic tests."""

from copy import deepcopy
from threading import RLock


class InMemoryEndpointPresenceRepository:
    def __init__(self):
        self._items = {}
        self._lock = RLock()

    def get(self, endpoint_id):
        with self._lock:
            value = self._items.get(str(endpoint_id))
            return deepcopy(value) if value is not None else None

    def upsert(self, presence):
        with self._lock:
            self._items[str(presence.endpoint_id)] = deepcopy(presence)
            return deepcopy(presence)

    def list_for_organization(self, organization_id):
        with self._lock:
            return tuple(deepcopy(item) for item in self._items.values()
                         if item.organization_id == str(organization_id))

    def list_all(self):
        with self._lock:
            return tuple(deepcopy(item) for item in self._items.values())
