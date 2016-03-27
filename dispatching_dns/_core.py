from dnslib.server import BaseResolver
from dnslib.dns import DNSRecord, DNSQuestion, RR, QTYPE
from threading import RLock, Thread
from time import time
from recordclass import recordclass
from cachetools import LRUCache
from ipaddress import ip_address
import os


class CachingResolver(BaseResolver):
    _Record = recordclass('_Record', 'expire data')

    def __init__(self, cache_size, dest, port=53, tcp=False, timeout=None, ipv6=False):
        super().__init__()
        self._dest = dest
        self._port = port
        self._tcp = tcp
        self._timeout = timeout
        self._ipv6 = ipv6

        self._cache = LRUCache(cache_size)
        self._cache_lock = RLock()

    def _query_cache(self, key):
        with self._cache_lock:
            records = self._cache.get(key, None)
            if records is None:
                records = []
            else:
                records = [record for record in records if record.expire > time()]
                if len(records):
                    records = records[1:] + [records[0]]
                    self._cache[key] = records
                else:
                    del self._cache[key]
            return records

    def _add_to_cache(self, key, record):
        with self._cache_lock:
            records = self._cache.get(key, None)
            if records is None:
                self._cache[key] = [record]
            else:
                for erecord in records:
                    if erecord.data == record.data:
                        erecord.expire = record.expire
                        break
                else:
                    records.append(record)

    def _resolve_in_cache(self, questions, oq, oa, now):
        for q in questions:
            key = (q.qname, QTYPE.CNAME, q.qclass)
            cnames = self._query_cache(key)
            if len(cnames):
                recursive_questions = []
                for cname in cnames:
                    oa.add_answer(RR(ttl=max(cname.expire - now, 0), **cname.data))
                    recursive_questions.append(DNSQuestion(
                        qname=cname.data['rdata'].label,
                        qtype=q.qtype,
                        qclass=q.qclass
                    ))

                    self._resolve_in_cache(recursive_questions, oq, oa, now)
            else:
                if q.qtype != QTYPE.CNAME:
                    key = (q.qname, q.qtype, q.qclass)
                    record_list = self._query_cache(key)
                    if len(record_list):
                        for record in record_list:
                            oa.add_answer(RR(ttl=max(record.expire - now, 0), **record.data))
                    else:
                        oq.add_question(q)
                else:
                    oq.add_question(q)

    def resolve(self, request, handler):
        now = int(time())
        a = request.reply()

        uq = DNSRecord()
        self._resolve_in_cache(request.questions, uq, a, now)

        if len(uq.questions):
            ua_pkt = uq.send(self._dest, self._port, self._tcp, self._timeout, self._ipv6)
            ua = DNSRecord.parse(ua_pkt)

            for rr in ua.rr:
                key = (rr.rname, rr.rtype, rr.rclass)
                cr = self._Record(now + rr.ttl, {
                    'rname': rr.rname,
                    'rtype': rr.rtype,
                    'rclass': rr.rclass,
                    'rdata': rr.rdata,
                })
                self._add_to_cache(key, cr)

            a.add_answer(*ua.rr)

        return a


class DispatchingResolver(BaseResolver):
    def __init__(self, rules, targets):
        self._rules = rules
        self._targets = targets

    def resolve(self, request, handler):
        qll = [[] for _ in range(len(self._targets))]
        a = request.reply()
        for q in request.questions:
            for suffix, jump in self._rules:
                if q.qname.matchSuffix(suffix):
                    qll[jump].append(q)
                    break
            else:
                qll[0].append(q)
        for i, ql in enumerate(qll):
            if not len(ql):
                continue
            ur = DNSRecord(header=request.header)
            ur.add_question(*ql)
            a.add_answer(*self._targets[i].resolve(ur, handler).rr)
        return a


class LoggingResolver(BaseResolver):
    def __init__(self, resolver, logfn, write_interval=600):
        self._resolver = resolver
        self._logfn = logfn
        self._addresses = set()
        if os.path.exists(self._logfn):
            with open(self._logfn, 'r') as log:
                for entry in log:
                    entry = entry.strip()
                    if entry:
                        self._addresses.add(ip_address(entry))
        self._last_write_time = 0
        self._last_write_length = len(self._addresses)
        self._write_interval = write_interval
        self._writing = False
        self._lock = RLock()

    def _write_log(self):
        if self._last_write_length == len(self._addresses):
            return

        now = time()
        if now - self._last_write_time < self._write_interval:
            return

        with self._lock:
            if not self._writing:
                self._writing = True
                to_write = True
            else:
                to_write = False

        if not to_write:
            return

        def write_back():
            with open(self._logfn, 'w') as log:
                for entry in self._addresses:
                    print(str(entry), file=log)
            with self._lock:
                self._writing = False
        Thread(target=write_back).start()

    def resolve(self, request, handler):
        a = self._resolver.resolve(request, handler)
        for rr in a.rr:
            if rr.rtype in [QTYPE.A, QTYPE.AAAA]:
                self._addresses.add(ip_address(repr(rr.rdata)))
        self._write_log()
        return a
