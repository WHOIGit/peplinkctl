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


def assert_ok(response):
    if not response.get('stat') == 'ok':
        raise Exception(f'API error: {response.get("code")} - '
                        f'{response.get("message")}')


def get_credentials():
    username = os.environ.get('PEPLINK_USER')
    password = os.environ.get('PEPLINK_PASSWORD')
    if not username:
        username = input('Username: ')
    if not password:
        password = getpass.getpass('Password: ')
    return username, password


def login(server, username, password, client):
    # Log in with username and password; gives us a session cookie
    req = urllib.request.Request(
        f'{server}/api/login',
        headers={
            'Content-Type': 'application/json'
        },
        data=json.dumps({
            'username': username,
            'password': password
        }).encode(),
    )
    response = json.loads(urllib.request.urlopen(req).read())
    assert_ok(response)

    # Query the set of configured API clients
    response = json.loads(urllib.request.urlopen(f'{server}/api/auth.client').read())
    assert_ok(response)

    # Look for an existing client with credentials
    client_id, client_secret = None, None
    for c in response['response']:
        if c['name'] == client:
            client_id, client_secret = c['clientId'], c['clientSecret']
            break

    # If there is no existing client, create one
    if client_id is None:
        req = urllib.request.Request(
            f'{server}/api/auth.client',
            method='POST',
            headers={
                'Content-Type': 'application/json'
            },
            data=json.dumps({
                'action': 'add',
                'name': client,
                'scope': 'api.read-only'
            }).encode(),
        )
        response = json.loads(urllib.request.urlopen(req).read())
        assert_ok(response)

        client_id = response['response']['clientId']
        client_secret = response['response']['clientSecret']

    # Use the client credentials to request an API token
    req = urllib.request.Request(
        f'{server}/api/auth.token.grant',
        method='POST',
        headers={
            'Content-Type': 'application/json'
        },
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
    parser.add_argument('-c', '--client')
    parser.add_argument('-k', '--no-verify-ssl', action='store_true')
    parser.add_argument('-t', '--token')
    subparsers = parser.add_subparsers(dest='command', required=True)
    subparsers.add_parser('login')
    subparsers.add_parser('get-status-wan-connection')
    args = parser.parse_args()

    args.server = args.server.rstrip('/')

    if args.no_verify_ssl:
        set_ssl_verify(False)

    if args.command == 'login' and args.token:
        parser.error('Cannot use token with login command')

    if not args.token:
        if args.client is None:
            parser.error('Missing API client name (-c/--client)')
        username, password = get_credentials()
        args.token, expiry = login(args.server, username, password, args.client)

    if args.command == 'login':
        print(f'TOKEN="{args.token}"')
        print(f'EXPIRATION="{expiry}"')

    if args.command == 'get-status-wan-connection':
        status = get_status_wan_connection(args.server, args.token)
        print(json.dumps(status, indent=2))


if __name__ == '__main__':
    main()
