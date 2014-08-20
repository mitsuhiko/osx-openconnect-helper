import os
import re
import errno
import shutil
import tempfile

import toml
import click

from urlparse import urlparse
from subprocess import Popen, PIPE


CREATOR = 'OOCh'

devnull = open(os.path.devnull, 'w')


_token_re = re.compile(r'^token (.*?)$(?m)')


def _make_toml_group(**fields):
    return dict((k, v) for k, v in fields.iteritems()
                if v is not None)


class ProfileManager(object):

    def __init__(self):
        self.config_home = os.path.join(click.get_app_dir('OpenConnect Helper'))
        self.config_file = os.path.join(self.config_home, 'profiles.toml')

        fn = self.config_file
        try:
            with open(fn) as f:
                self.config = toml.load(f)
        except IOError as e:
            if e.errno != errno.ENOENT:
                raise click.UsageError('Could not open config file: %s' % e)
            self.config = {}

    def save(self):
        fn = self.config_file
        try:
            os.makedirs(self.config_home)
        except OSError:
            pass
        with open(fn, 'w') as f:
            return toml.dump(self.config, f)

    def profile_exists(self, name):
        return self.get_profile(name) is not None

    def get_profile(self, name):
        for profile in self.config.get('profiles') or ():
            if profile.get('name') == name:
                return profile

    def set_keychain_password(self, name, url, user, password,
                              kind='openconnect'):
        urlinfo = urlparse(url)
        if ':' in urlinfo.netloc:
            server, port = urlinfo.netloc.split(':', 1)
        else:
            server = urlinfo.netloc
            port = urlinfo.scheme == 'https' and '443' or '80'
        protocol = urlinfo.scheme == 'https' and 'htps' or 'http'
        path = urlinfo.path or '/'

        self.remove_keychain_password(name, kind=kind)
        Popen(['security', 'add-internet-password',
               '-c', CREATOR, '-s', server, '-P', port, '-D', kind,
               '-r', protocol, '-p', path, '-w', password, '-a', user,
               '-l', name, '-T', ''], stdout=devnull, stderr=devnull).wait()

    def remove_keychain_password(self, name, kind='openconnect'):
        Popen(['security', 'delete-internet-password',
               '-c', CREATOR, '-l', name, '-D', kind],
              stdout=devnull,
              stderr=devnull).wait()

    def get_keychain_password(self, name, kind='openconnect'):
        c = Popen(['security', 'find-internet-password',
               '-c', CREATOR, '-l', name, '-D', kind, '-w'],
              stdout=PIPE,
              stderr=devnull)
        password = c.communicate()[0].rstrip('\r\n')
        if c.returncode == 0:
            return password

    def import_rsa_token(self, name, url, token):
        folder = tempfile.mkdtemp()
        fn = os.path.join(folder, 'stokenrs')
        rv = Popen(['stoken', 'import', '--token=%s' % token,
                    '--rcfile', fn, '--new-password=']).wait()
        try:
            if rv != 0:
                raise click.UsageError('Could not import token')
            with open(fn) as f:
                token = _token_re.search(f.read()).group(1)
            self.set_keychain_password(name, url, '', token,
                                       kind='openconnect-rsa')
        finally:
            try:
                shutil.rmtree(folder)
            except Exception:
                pass

    def remove_rsa_token(self, name):
        return self.remove_keychain_password(name, kind='openconnect-rsa')

    def get_rsa_token(self, name):
        return self.get_keychain_password(name, kind='openconnect-rsa')

    def set_profile(self, name, url, user, group=None, fingerprint=None):
        profiles = self.config.setdefault('profiles', [])
        for idx, profile in enumerate(profiles):
            if profile.get('name') == name:
                break
        else:
            profiles.append(None)
            idx = -1
        profiles[idx] = _make_toml_group(name=name, url=url, user=user,
                                         group=group, fingerprint=fingerprint)

    def remove_profile(self, name):
        self.remove_keychain_password(name)
        self.remove_rsa_token(name)
        profiles = self.config.setdefault('profiles', [])
        profiles[:] = [x for x in profiles if x.get('name') != name]

    def iter_profiles(self):
        for profile in self.config.get('profiles') or ():
            if profile.get('name') is not None:
                yield profile

    def connect(self, name, cert_check=True):
        profile = self.get_profile(name)
        if profile is None:
            raise click.UsageError('The profile "%s" does not exist.' % name)

        kwargs = {}
        stdin = None
        password = self.get_keychain_password(name)
        rsa_token = self.get_rsa_token(name)

        args = ['sudo', 'openconnect']
        if not cert_check:
            args.append('--no-cert-check')

        user = profile.get('user')
        if user is not None:
            args.append('--user=%s' % user)
        group = profile.get('group')
        if group is not None:
            args.append('--authgroup=%s' % group)

        if password is not None:
            args.append('--passwd-on-stdin')
            stdin = password
            kwargs['stdin'] = PIPE
        elif rsa_token is not None:
            args.append('--token-mode=rsa')
            args.append('--token-secret=%s' % rsa_token)

        fingerprint = profile.get('fingerprint')
        if fingerprint is not None:
            args.append('--servercert=%s' % fingerprint)
        args.append(profile['url'])

        c = Popen(args, **kwargs)
        try:
            if stdin is not None:
                c.stdin.write(stdin)
                c.stdin.flush()
                c.stdin.close()
            c.wait()
        except KeyboardInterrupt:
            try:
                c.terminate()
            except Exception:
                pass


class Context(object):

    def __init__(self):
        self.profile_manager = ProfileManager()


pass_context = click.make_pass_decorator(Context, ensure=True)


def validate_url(ctx, param, value):
    if value is None:
        return
    info = urlparse(value)
    if info.scheme not in ('http', 'https'):
        raise click.BadParameter('Expected http or https url')
    if not info.path:
        value += '/'
    return value


def validate_fingerprint(ctx, param, value):
    if value is not None:
        fingerprint = value.replace(':', '').strip().upper()
        try:
            if len(fingerprint.decode('hex')) != 20:
                raise ValueError()
        except (TypeError, ValueError):
            raise click.BadParameter('Invalid SHA1 fingerprint provided.')
        return fingerprint


def common_profile_params(f):
    f = click.option('--url', help='The AnyConnect URL endpoint.',
                     callback=validate_url, required=True)(f)
    f = click.option('--user', help='The username to log in.', required=True)(f)
    f = click.option('--group', help='The group to log in through.')(f)
    f = click.option('--password', help='Sets the new password.')(f)
    f = click.option('--fingerprint', help='The fingerprint of the server.  '
                     'This is the SHA1 fingerprint of the certificate which '
                     'can be used to connect to untrusted servers.',
                     callback=validate_fingerprint)(f)
    f = click.option('--ask-password', is_flag=True,
                     help='Prompts for a password.')(f)
    f = click.option('--remove-password', is_flag=True,
                     help='Removes an already set password.')(f)
    f = click.option('--rsa-token', help='The RSA token to import.  This '
                     'requires stoken to be installed and compiled into '
                     'openconnect.')(f)
    f = click.option('--remove-rsa-token', help='Removes an old RSA token.',
                     is_flag=True)(f)
    return f


def update_profile(manager, name, fields):
    password = fields.pop('password')
    remove_password = fields.pop('remove_password')
    if fields.pop('ask_password'):
        password = click.prompt('Password', hide_input=True)
    rsa_token = fields.pop('rsa_token')
    remove_rsa_token = fields.pop('remove_rsa_token')
    manager.set_profile(name, **fields)
    manager.save()

    if password is not None:
        manager.set_keychain_password(name, url=fields['url'],
                                      user=fields['user'],
                                      password=password)
    elif remove_password:
        manager.remove_keychain_password(name)

    if rsa_token is not None:
        manager.import_rsa_token(name, fields['url'], rsa_token)
    elif remove_rsa_token:
        manager.remove_rsa_token(name)


@click.group()
def cli():
    """openconnect-helper is a simple command line application that
    can manage different openconnect profiles for you.
    """


@cli.command('add')
@common_profile_params
@click.argument('name', required=False)
@pass_context
def add_profile(ctx, name, **kwargs):
    """Adds a new profile to openconnect."""
    if name is None:
        name = urlparse(kwargs['url']).netloc.rsplit(':', 1)[0]

    if ctx.profile_manager.profile_exists(name):
        raise click.UsageError('The profile "%s" already exists.' % name)

    update_profile(ctx.profile_manager, name, kwargs)


@cli.command('edit')
@common_profile_params
@click.argument('name')
@pass_context
def edit_profile(ctx, name, **kwargs):
    """Updates a profile on openconnect."""
    if not ctx.profile_manager.profile_exists(name):
        raise click.UsageError('The profile "%s" does not exist.' % name)

    update_profile(ctx.profile_manager, name, kwargs)


@cli.command('remove')
@common_profile_params
@click.argument('name')
@pass_context
def remove_profile(ctx, name, **kwargs):
    """Removes a VPN profile."""
    if not ctx.profile_manager.profile_exists(name):
        raise click.UsageError('The profile "%s" does not exist.' % name)
    ctx.profile_manager.remove_profile(name)
    ctx.profile_manager.save()


@cli.command('list')
@pass_context
def list_profiles(ctx):
    """Lists all profiles."""
    for profile in ctx.profile_manager.iter_profiles():
        print profile['name']


@cli.command('connect')
@click.option('--cert-check/--no-cert-check', default=True,
              help='Enables or disables certificate checks.')
@click.argument('name')
@pass_context
def connect(ctx, name, cert_check):
    """Connects to a VPN profile."""
    ctx.profile_manager.connect(name, cert_check=cert_check)
