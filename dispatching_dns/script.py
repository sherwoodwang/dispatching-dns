from dnslib.server import DNSServer
from ._core import DNSService, CachingResolver, DispatchingResolver, LoggingResolver
from yaml import Loader
import sys
import signal


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

    for server in servers:
        server.start_thread()

    def shutdown(sig, frame):
        for server in servers:
            server.stop()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while True:
        alive = False
        try:
            for server in servers:
                server.thread.join()
                if server.isAlive():
                    alive = True
        except KeyboardInterrupt:
            alive = True
        if not alive:
            break

if __name__ == '__main__':
    main()

