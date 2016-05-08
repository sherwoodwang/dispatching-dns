from dnslib.server import BaseResolver
from dnslib.dns import DNSLabel, DNSRecord, DNSQuestion, RR, QTYPE, CLASS
import dnslib.dns as dns
from threading import RLock, Thread
from time import time
from recordclass import recordclass
from cachetools import LRUCache
from ipaddress import ip_address, IPv4Address, IPv6Address, ip_network
import os


class DNSService:
    def __init__(self, address, port=53, tcp=False, timeout=5):
        self.address = ip_address(address)
        self.port = port
        self.tcp = tcp
        self.timeout = timeout
        self.ipv6 = isinstance(self.address, IPv6Address)


class ProxyResolver(BaseResolver):
    _Record = recordclass('_Record', 'expire data')

    def __init__(self, upstreams, cache_size=None):
        super().__init__()
        self._upstreams = upstreams

        self._cache = LRUCache(cache_size) if cache_size else None
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
        if self._cache is None:
            return

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
            for upstream in self._upstreams:
                try:
                    ua_pkt = uq.send(
                        str(upstream.address),
                        upstream.port,
                        upstream.tcp,
                        upstream.timeout,
                        upstream.ipv6
                    )
                    ua = DNSRecord.parse(ua_pkt)
                except:
                    continue

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
                break
            else:
                raise IOError

        return a


class DispatchingResolver(BaseResolver):
    def __init__(self, rules, targets):
        self._rules = [
            (suffix, jump if isinstance(jump, int) else ip_address(jump))
            for suffix, jump in rules
            ]
        self._targets = targets

    def resolve(self, request, handler):
        qll = [[] for _ in range(len(self._targets))]
        a = request.reply()
        for q in request.questions:
            for suffix, jump in self._rules:
                if q.qname.matchSuffix(suffix):
                    if isinstance(jump, int):
                        qll[jump].append(q)
                        break
                    elif q.qclass == CLASS.IN and q.qtype == QTYPE.A and isinstance(jump, IPv4Address):
                        a.add_answer(RR(q.qname, QTYPE.A, CLASS.IN, 1, dns.A(str(jump))))
                        break
                    elif q.qclass == CLASS.IN and q.qtype == QTYPE.AAAA and isinstance(jump, IPv6Address):
                        a.add_answer(RR(q.qname, QTYPE.AAAA, CLASS.IN, 1, dns.AAAA(str(jump))))
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


class RecordingResolver(BaseResolver):
    def __init__(self, resolver, db, exceptions=None, write_interval=600):
        if exceptions is None:
            exceptions = []
        exceptions = [ip_network(exception) for exception in exceptions]

        self._resolver = resolver
        self._db = db
        self._exceptions = exceptions
        self._addresses = {}
        if os.path.exists(self._db):
            with open(self._db, 'r') as f_db:
                for entry in f_db:
                    if not entry.strip():
                        continue
                    address, hosts = entry.split(':', 1)
                    address = address.strip()
                    address = ip_address(address)
                    for exception in self._exceptions:
                        if address in exception:
                            break
                    else:
                        for host in hosts.split(','):
                            host = host.strip()
                            host = DNSLabel(host)
                            if address not in self._addresses:
                                self._addresses[address] = set()
                            self._addresses[address].add(host)
        self._last_write_time = 0
        self._write_interval = write_interval
        self._writing = False
        self._lock = RLock()

    def _write_db(self):
        now = time()
        if now - self._last_write_time < self._write_interval:
            return

        with self._lock:
            if not self._writing:
                self._writing = True
            else:
                return

        def write_back():
            with open(self._db, 'w') as f_db:
                addresses = list(self._addresses.keys())
                addresses.sort()
                for address in addresses:
                    print(
                        '{}: {}'.format(
                            str(address),
                            ', '.join(str(host) for host in self._addresses[address])),
                        file=f_db)
            with self._lock:
                self._writing = False
        Thread(target=write_back).start()

    def resolve(self, request, handler):
        a = self._resolver.resolve(request, handler)
        for rr in a.rr:
            if rr.rtype in [QTYPE.A, QTYPE.AAAA]:
                address = ip_address(repr(rr.rdata))
                for exception in self._exceptions:
                    if address in exception:
                        break
                else:
                    with self._lock:
                        if address not in self._addresses:
                            self._addresses[address] = set()
                        self._addresses[address].add(rr.rname)
        self._write_db()
        return a
