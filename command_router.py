import argparse

def get_command_parser():

    parser = argparse.ArgumentParser()
    command_subparsers = parser.add_subparsers(dest='command')

    command_subparsers.add_parser('help', help="Print help.")

    # Print Commands
    print_subparser = command_subparsers.add_parser('print', help="Print some information to the screen.")

    print_type_parser = print_subparser.add_subparsers(dest='print_type')

    print_register_parser = print_type_parser.add_parser('registers',
                                                         help="Print one or more registers. You can type 'all' to see all available "
                                                              "registers, or 'basic' to show just a basic, common set.")
    print_register_parser.add_argument('register_name', nargs="+", help="Print registers by name.")

    print_memory_parser = print_type_parser.add_parser('memory', help="Print the contents of some memory.")
    print_memory_parser.add_argument('address', help="Print memory.", type=str)
    print_memory_parser.add_argument('num_bytes', help="The number of bytes to print")

    # Memory actions
    memory_subparser = command_subparsers.add_parser('memory', help="Map some more memory into a memory space")
    memory_action_subparser = memory_subparser.add_subparsers(dest='memory_action')

    # Map Memory
    memory_map_subparser = memory_action_subparser.add_parser('map')
    memory_map_subparser.add_argument('base_address', help="The base address to map memory into")
    memory_map_subparser.add_argument('memory_size', help="The memory size to map.")

    # Show memory mappings
    memory_action_subparser.add_parser('show')


    return parser


