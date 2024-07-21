import secrets

from Crypto.Cipher import AES

from cryptopals.basics import padding


def key_value_parsing(cookie):
    """
    >>> key_value_parsing('foo=bar&baz=qux&zap=zazzle')
    {'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'}
    """
    return dict(kv.split("=") for kv in cookie.strip("\x00").split("&"))


def profile_for(email: str):
    """
    >>> profile_for('foo@bar.com')
    'email=foo@bar.com&uid=10&role=user'
    >>> profile_for('foo@bar.com&role=admin')
    'email=foo@bar.comroleadmin&uid=10&role=user'
    """
    return "email=%s&uid=10&role=user" % email.replace("&", "").replace("=", "")


def encrypt_profile(user_input, key):
    profile = profile_for(user_input).encode()
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(padding(profile))


def decrypt_profile(secret, key):
    aes = AES.new(key, AES.MODE_ECB)
    plain = aes.decrypt(secret).decode()
    return key_value_parsing(plain)


def make_admin_role():
    """
    >>> make_admin_role()
    {'email': 'fofoo@bar.com', 'uid': '10', 'role': 'admin'}
    """
    key = secrets.token_bytes(16)
    # 'email=fofoo@bar.com.....role='
    role_block = encrypt_profile("fofoo@bar.com", key)[:32]
    # 'admin...' with fake padding
    admin_block = encrypt_profile("1234567812admin" + "\x00" * 16, key)[16:32]
    return decrypt_profile(role_block + admin_block, key)


Aufzeichnen, wo sich die Blöcke trennen
stripPadding kann auch umgangen werden
