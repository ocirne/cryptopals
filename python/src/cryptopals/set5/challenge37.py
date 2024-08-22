from cryptopals.set5.challenge36 import Server, sha256, hmac_sha256, to_bytes, N


class BadClient:
    def __init__(self, server: Server):
        self.server = server

    def run(self, A):  # NOSONAR
        """ A = 0 = xN mod N for all x in N """
        salt, _ = self.server.request_key("any-email@example.com", A)
        K = sha256(to_bytes(0))
        return self.server.validate(hmac_sha256(K, salt))


def challenge37():
    """
    >>> challenge37()
    True
    True
    True
    """
    server = Server()
    bad_client = BadClient(server)

    print(bad_client.run(0))
    print(bad_client.run(N))
    print(bad_client.run(2 * N))


if __name__ == "__main__":
    challenge37()
