import argparse
import getpass
import hashlib
import os.path
import sys

from cryptography.hazmat.primitives import serialization

import key_factory as kf
from box_factory import BlackBox, encapsulate, decapsulate
from key_factory import RSAKey

parser = argparse.ArgumentParser(prog='PROG', description='BlackBox CLI')
subparsers = parser.add_subparsers(help='sub-command help')

keygen_subparsers = subparsers.add_parser('keygen', help='Generate asymmetric key')
keygen_subparsers.set_defaults(which='keygen')
keygen_subparsers.add_argument('output', metavar='', type=str, help='Path to key output')
keygen_subparsers.add_argument('-s', '--size', metavar='', type=int, required=False, default=4096, help='key size')

create_subparsers = subparsers.add_parser('create', help='Create a black box')
create_subparsers.set_defaults(which='create')
create_subparsers.add_argument('path', metavar='', type=str, help='Path to black box output')
create_subparsers.add_argument('-kp', '--key_path', metavar='', type=str, required=True, help='Public key path')
create_subparsers.add_argument('-sc', '--slot_count', metavar='', type=int, required=False, default=float('inf'), help='Slot count')
create_subparsers.add_argument('-sk', '--size_limitation', metavar='', type=int, required=False, default=float('inf'), help='Blackbox size threshold')
create_subparsers.add_argument('-c', '--compression', action='store_true', help='Enable compression')

describe_subparsers = subparsers.add_parser('describe', help='Description of a blackbox')
describe_subparsers.set_defaults(which='describe')
describe_subparsers.add_argument('path', metavar='', type=str, help='Path to blackbox')

put_subparsers = subparsers.add_parser('put', help='Put content into blackbox')
put_subparsers.set_defaults(which='put')
put_subparsers.add_argument('path', metavar='', type=str, help='Path to blackbox')
put_subparsers.add_argument('-f', '--file', metavar='', type=str, required=False, default=False, help='File path')
put_subparsers.add_argument('text_content', nargs='?', help='Textual input')

get_subparsers = subparsers.add_parser('get', help='Get content from blackbox')
get_subparsers.set_defaults(which='get')
get_subparsers.add_argument('path', metavar='', type=str, help='Path to blackbox')
get_subparsers.add_argument('index', metavar='', type=int, help='Item index')
get_subparsers.add_argument('-kf', '--key_file', metavar='', type=str, required=True, help='Private key file path')

delete_subparsers = subparsers.add_parser('delete', help='Delete content from blackbox')
delete_subparsers.set_defaults(which='delete')
delete_subparsers.add_argument('path', metavar='', type=str, help='Path to blackbox')
delete_subparsers.add_argument('index', metavar='', type=int, help='Item index')

def main():
    match args.which:
        case 'keygen':
            if os.path.exists(args.output):
                print(f"Operation aborted: file '{args.output}' already exists", file=sys.stderr)
                exit(1)

            if os.path.exists(f'{args.output}.pub'):
                print(f"Operation aborted: file '{args.output}.pub' already exists", file=sys.stderr)
                exit(1)

            if args.size < 3072:
                print("Generating key with size lower than 3072 may cause vulnerability to quantum attacks")
                input('Press `Enter` to processed anyway ...')

            pass_phrase = getpass.getpass('Enter passphrase for the key file (leave empty if there is none): \n', stream=None).encode('utf-8')
            pass_phrase = None if pass_phrase == b'' else pass_phrase

            kf.RSAKey.generate_rsa_keys(args.output, key_size=args.size, pass_phrase=pass_phrase)
        case 'create':
            key = RSAKey()
            key.public_key = RSAKey.load_public_key(args.key_path)

            black_box = BlackBox(
                key=key,
                slots_count_limit=args.slot_count,
                slots_size_limit=args.size_limitation,
                compression=args.compression
            )

            with open(args.path, 'wb') as file:
                file.write(encapsulate(black_box))

        case 'describe':
            with open(args.path, 'rb') as file:
                black_box = decapsulate(file.read())

            print('BlackBox description:')
            print('-' * 30)
            print()
            print('ID:\t\t\t', black_box.id)
            print('Key_Hash:\t\t', hashlib.sha256(black_box.key.public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).hexdigest())

            print('Slots_Limitation:\t', black_box.slots_count_limit)
            print('Size_Limitation:\t', black_box.slots_size_limit)
            print('Compression:\t\t', 'Enabled' if black_box.compression else 'Disabled')
            print('Slot_Count\t\t', len(black_box.slots))
        case 'put':
            with open(args.path, 'rb') as file:
                black_box = decapsulate(file.read())

            data = open(args.file, 'rb').read() if args.file else args.text_content.encode('utf-8')

            black_box.put(data)

            with open(args.path, 'wb') as file:
                file.write(encapsulate(black_box))

        case 'get':
            with open(args.path, 'rb') as file:
                black_box = decapsulate(file.read())
            pass_phrase = getpass.getpass('Enter passphrase for the key file (leave empty if there is none): \n', stream=None).encode('utf-8')
            pass_phrase = None if pass_phrase == b'' else pass_phrase

            key = RSAKey()
            key.private_key = RSAKey.load_private_key(args.key_file, pass_phrase)

            print(key.decrypt(black_box[args.index - 1]))

        case 'delete':
            with open(args.path, 'rb') as file:
                black_box = decapsulate(file.read())

            black_box.slots.pop(args.index - 1)

            with open(args.path, 'wb') as file:
                file.write(encapsulate(black_box))


if __name__ == '__main__':
    args = parser.parse_args()
    main()
