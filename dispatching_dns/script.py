from dnslib.server import DNSServer
from ._core import DNSService, CachingResolver, DispatchingResolver, LoggingResolver
from yaml import Loader
import sys
import signal
import os
import pwd, grp


def resolver_constructor(factory):
    def constructor(loader: Loader, node):
        args = loader.construct_mapping(node, True)
        return factory(**args)
    return constructor


def main(argv=None):
    if argv is None:
        argv = sys.argv
    config_path = argv[1]

    servers = []
    with open(config_path, 'r') as config:
        config_loader = Loader(config)
        config_loader.add_constructor('!cache', resolver_constructor(CachingResolver))
        config_loader.add_constructor('!dispatch', resolver_constructor(DispatchingResolver))
        config_loader.add_constructor('!log', resolver_constructor(LoggingResolver))
        config_loader.add_constructor('!service', resolver_constructor(DNSService))
        config_data = config_loader.get_data()

    servers.append(DNSServer(
        resolver=config_data['resolver'],
        address=config_data.get('address', ''),
        port=config_data.get('port', 53)
    ))

    servers.append(DNSServer(
        resolver=config_data['resolver'],
        address=config_data.get('address', ''),
        port=config_data.get('port', 53),
        tcp=True
    ))

    user = config_data.get('user', None)
    group = config_data.get('group', None)

    if group is not None:
        try:
            group = int(group)
        except ValueError:
            group = grp.getgrnam(group).gr_gid
        os.setgid(group)

    if user is not None:
        try:
            user = int(user)
        except ValueError:
            user = pwd.getpwnam(user).pw_uid
        os.setuid(user)

    for server in servers:
        server.start_thread()

    def shutdown(sig, frame):
        for server in servers:
            server.stop()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    for server in servers:
        if server.isAlive():
            while True:
                try:
                    server.thread.join()
                except KeyboardInterrupt:
                    pass
                else:
                    break

if __name__ == '__main__':
    main()

