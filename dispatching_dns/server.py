import grp
import os
import pwd
import signal
import sys

from dnslib.server import DNSServer
from yaml import Loader

from ._core import DNSService, ProxyResolver, DispatchingResolver, RecordingResolver


def resolver_constructor(factory):
    def constructor(loader: Loader, node):
        args = loader.construct_mapping(node, True)
        return factory(**args)
    return constructor


def main(argv=None):
    if argv is None:
        argv = sys.argv
    config_path = argv[1]

    with open(config_path, 'r') as config:
        config_loader = Loader(config)
        config_loader.add_constructor('!proxy', resolver_constructor(ProxyResolver))
        config_loader.add_constructor('!dispatch', resolver_constructor(DispatchingResolver))
        config_loader.add_constructor('!record', resolver_constructor(RecordingResolver))
        config_loader.add_constructor('!service', resolver_constructor(DNSService))
        config_data = config_loader.get_data()

    serve(config_data)


def serve(config):
    servers = []

    servers.append(DNSServer(
        resolver=config['resolver'],
        address=config.get('address', ''),
        port=config.get('port', 53)
    ))

    servers.append(DNSServer(
        resolver=config['resolver'],
        address=config.get('address', ''),
        port=config.get('port', 53),
        tcp=True
    ))

    user = config.get('user', None)
    group = config.get('group', None)

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

