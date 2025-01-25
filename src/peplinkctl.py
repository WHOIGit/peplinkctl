#!/usr/bin/env python3
import argparse
import datetime
import getpass
import json
import os
import ssl
import urllib.request

from http.cookiejar import CookieJar


# Global opener object with cookie jar and SSL context
ctx = ssl.create_default_context()
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ctx),
    urllib.request.HTTPCookieProcessor(CookieJar())
)
urllib.request.install_opener(opener)


def set_ssl_verify(verify=True):
    global ctx
    ctx.check_hostname = verify
    ctx.verify_mode = ssl.CERT_NONE if not verify else ssl.CERT_REQUIRED


def assert_ok(response: dict):
    if not response.get('stat') == 'ok':
        raise Exception(f'API error: {response.get("code")} - '
                        f'{response.get("message")}')


def get_login_credentials():
    username = os.environ.get('PEPLINK_USER')
    password = os.environ.get('PEPLINK_PASSWORD')
    if not username:
        username = input('Username: ')
    if not password:
        password = getpass.getpass('Password: ')
    return username, password


def get_client_credentials():
    client_id = os.environ.get('CLIENT_ID')
    client_secret = os.environ.get('CLIENT_SECRET')
    if not client_id or not client_secret:
        raise Exception('CLIENT_ID and CLIENT_SECRET environment variables '
                        'must be set')
    return client_id, client_secret


def login(server: str, username: str, password: str):
    '''Log in with username and password'''

    req = urllib.request.Request(
        f'{server}/api/login',
        headers={'Content-Type': 'application/json'},
        data=json.dumps({
            'username': username,
            'password': password,
        }).encode(),
    )
    response = json.loads(urllib.request.urlopen(req).read())
    assert_ok(response)


def get_or_create_client(server: str, name: str, readwrite: bool):
    '''Get existing client credentials or create new ones'''

    # Query existing clients
    response = json.loads(
        urllib.request.urlopen(f'{server}/api/auth.client').read()
    )
    assert_ok(response)

    # Look for existing client
    for c in response['response']:
        if c['name'] == name:
            if (not readwrite) ^ (c['scope'] == 'api.read-only'):
                # TODO: Client exists with different scope
                raise NotImplementedError('Cannot recreate clients yet')
            return c['clientId'], c['clientSecret']

    # Create new client
    req = urllib.request.Request(
        f'{server}/api/auth.client',
        method='POST',
        headers={'Content-Type': 'application/json'},
        data=json.dumps({
            'action': 'add',
            'name': name,
            'scope': 'api' if readwrite else 'api.read-only'
        }).encode(),
    )
    response = json.loads(urllib.request.urlopen(req).read())
    assert_ok(response)

    return (
        response['response']['clientId'],
        response['response']['clientSecret']
    )


def get_token(server: str, client_id: str, client_secret: str):
    '''Get API token using client credentials'''
    req = urllib.request.Request(
        f'{server}/api/auth.token.grant',
        method='POST',
        headers={'Content-Type': 'application/json'},
        data=json.dumps({
            'clientId': client_id,
            'clientSecret': client_secret,
            'scope': 'api.read-only'
        }).encode()
    )
    response = json.loads(urllib.request.urlopen(req).read())
    assert_ok(response)

    token = response['response']['accessToken']
    expiry = (datetime.datetime.now(datetime.timezone.utc) +
              datetime.timedelta(seconds=response['response']['expiresIn']))
    return token, expiry


def get_status_wan_connection(server, token):
    response = json.loads(urllib.request.urlopen(
        f'{server}/api/status.wan.connection?accessToken={token}'
    ).read())
    assert_ok(response)
    return response['response']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server', required=True)
    parser.add_argument('-k', '--no-verify-ssl', action='store_true')
    parser.add_argument('-t', '--token')
    subparsers = parser.add_subparsers(dest='command', required=True)

    subparser = subparsers.add_parser('create-client')
    subparser.add_argument('-c', '--client', required=True)
    subparser.add_argument('--read-write', dest='rw', action='store_true')
    subparser.add_argument('--read-only', dest='rw', action='store_false')

    subparsers.add_parser('get-token')

    subparser = subparsers.add_parser('get-status-wan-connection')

    args = parser.parse_args()

    args.server = args.server.rstrip('/')

    if args.no_verify_ssl:
        set_ssl_verify(False)

    if args.command == 'create-client':
        username, password = get_login_credentials()
        login(args.server, username, password)
        client_id, client_secret = get_or_create_client(
            args.server, args.client, args.rw)
        print(f'CLIENT_ID="{client_id}"')
        print(f'CLIENT_SECRET="{client_secret}"')
        return

    # If a token isn't provided, create one
    if not args.token:
        client_id, client_secret = get_client_credentials()
        args.token, expiry = get_token(args.server, client_id, client_secret)

    if args.command == 'get-token':
        print(f'TOKEN="{args.token}"')
        print(f'EXPIRATION="{expiry}"')
        return

    if args.command == 'get-status-wan-connection':
        status = get_status_wan_connection(args.server, args.token)
        print(json.dumps(status, indent=2))


if __name__ == '__main__':
    main()
