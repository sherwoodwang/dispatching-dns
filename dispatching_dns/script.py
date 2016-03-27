from dnslib.server import DNSServer
from ._core import CachingResolver, DispatchingResolver, LoggingResolver
from yaml import Loader
import sys


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
        config_loader.add_constructor('!cache', resolver_constructor(CachingResolver))
        config_loader.add_constructor('!dispatch', resolver_constructor(DispatchingResolver))
        config_loader.add_constructor('!log', resolver_constructor(LoggingResolver))
        resolver = config_loader.get_data()
        server = DNSServer(resolver=resolver)
    server.start()

if __name__ == '__main__':
    main()

