"""A dict-backed stand-in for redis.asyncio, enough for the sandbox slot / queue code
(src/scanner/behavioral/slots.py) and the router helpers around it. Shared by the
behavioral tests that run without a real Redis (``--noconftest`` safe). TTLs are
recorded in ``ttls`` (seconds) and never expire by themselves; tests expire a key by
deleting it; sorted-set scores are compared to ``time.time()`` by the code."""
from __future__ import annotations

import fnmatch


class SlotFakeRedis:
    def __init__(self):
        self.store: dict[str, object] = {}
        self.hashes: dict[str, dict[str, str]] = {}
        self.sets: dict[str, set[str]] = {}
        self.zsets: dict[str, dict[str, float]] = {}
        self.ttls: dict[str, int] = {}
        self.ttl_writes: list[str] = []  # every key a TTL was (re)set on, in order

    # strings
    async def get(self, key):
        return self.store.get(key)

    async def mget(self, keys):
        return [self.store.get(k) for k in keys]

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.store:
            return None
        self.store[key] = value
        if ex is not None:
            self.ttls[key] = int(ex)
            self.ttl_writes.append(key)
        return True

    async def delete(self, *keys):
        n = 0
        for k in keys:
            hit = False
            for d in (self.store, self.hashes, self.sets, self.zsets):
                if d.pop(k, None) is not None:
                    hit = True
            self.ttls.pop(k, None)
            n += int(hit)
        return n

    async def incr(self, key):
        self.store[key] = int(self.store.get(key, 0)) + 1
        return self.store[key]

    async def incrby(self, key, by):
        self.store[key] = int(self.store.get(key, 0)) + int(by)
        return self.store[key]

    async def decr(self, key):
        self.store[key] = int(self.store.get(key, 0)) - 1
        return self.store[key]

    async def expire(self, key, ttl):
        if key in self.store or key in self.hashes or key in self.zsets:
            self.ttls[key] = int(ttl)
            self.ttl_writes.append(key)
            return True
        return False

    async def scan(self, cursor=0, match=None, count=None):
        keys = [k for k in list(self.store) if match is None or fnmatch.fnmatchcase(k, match)]
        return 0, keys

    # hashes
    async def hset(self, key, field=None, value=None, mapping=None):
        h = self.hashes.setdefault(key, {})
        if mapping:
            h.update({str(k): str(v) for k, v in mapping.items()})
        if field is not None:
            h[str(field)] = str(value)
        return 1

    async def hget(self, key, field):
        return self.hashes.get(key, {}).get(field)

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    async def hdel(self, key, *fields):
        h = self.hashes.get(key, {})
        return sum(1 for f in fields if h.pop(f, None) is not None)

    # sets
    async def sadd(self, key, *members):
        self.sets.setdefault(key, set()).update(members)
        return len(members)

    async def scard(self, key):
        return len(self.sets.get(key, set()))

    # sorted sets
    def _sorted(self, key):
        return sorted(self.zsets.get(key, {}).items(), key=lambda kv: (kv[1], kv[0]))

    async def zadd(self, key, mapping, nx=False, xx=False, lt=False, gt=False):
        z = self.zsets.setdefault(key, {})
        added = 0
        for m, sc in mapping.items():
            if m not in z and xx:
                continue
            if m not in z:
                z[m] = float(sc)
                added += 1
            elif nx:
                continue
            elif lt and float(sc) < z[m]:
                z[m] = float(sc)
            elif gt and float(sc) > z[m]:
                z[m] = float(sc)
            elif not lt and not gt:
                z[m] = float(sc)
        return added

    async def zscore(self, key, member):
        return self.zsets.get(key, {}).get(member)

    async def zremrangebyscore(self, key, lo, hi):
        lo = float("-inf") if lo == "-inf" else float(lo)
        hi = float("inf") if hi == "+inf" else float(hi)
        z = self.zsets.get(key, {})
        gone = [m for m, sc in z.items() if lo <= sc <= hi]
        for m in gone:
            del z[m]
        return len(gone)

    async def zcard(self, key):
        return len(self.zsets.get(key, {}))

    async def zrank(self, key, member):
        for i, (m, _) in enumerate(self._sorted(key)):
            if m == member:
                return i
        return None

    async def zrange(self, key, start, end, withscores=False):
        items = self._sorted(key)
        n = len(items)
        s = start if start >= 0 else n + start
        e = end if end >= 0 else n + end
        out = items[max(0, s):e + 1]
        return [(m, sc) for m, sc in out] if withscores else [m for m, _ in out]

    async def zrangebyscore(self, key, lo, hi, start=None, num=None):
        lo = float("-inf") if lo == "-inf" else float(lo)
        hi = float("inf") if hi == "+inf" else float(hi)
        out = [m for m, sc in self._sorted(key) if lo <= sc <= hi]
        if start is not None and num is not None:
            out = out[start:start + num]
        return out

    async def zrem(self, key, *members):
        z = self.zsets.get(key, {})
        return sum(1 for m in members if z.pop(m, None) is not None)
