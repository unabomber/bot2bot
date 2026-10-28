import os
import tempfile
import unittest

from relay.auth import authenticate, bearer_token, hash_token
from relay.domain import Domain
from relay.store import Store


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(os.path.join(tempfile.mkdtemp(), 'a.db'))
        self.domain = Domain(self.store)
        self.addCleanup(self.store.close)

    def test_bearer_parsing(self):
        token = 'a' * 30
        self.assertEqual(bearer_token(f'Bearer {token}'), token)
        for bad in (None, '', 'Bearer', f'bearer {token}', f'Basic {token}', 'Bearer short',
                    f'Bearer {token} extra', f'Bearer {token}\n'):
            self.assertIsNone(bearer_token(bad), bad)

    def test_authenticate(self):
        token = self.domain.mint_agent('claude')
        self.assertEqual(authenticate(self.domain, f'Bearer {token}'), {'name': 'claude', 'role': 'agent'})
        self.assertIsNone(authenticate(self.domain, 'Bearer ' + 'x' * 43))
        self.assertIsNone(authenticate(self.domain, None))

    def test_revoked_token_rejected(self):
        token = self.domain.mint_agent('claude')
        self.domain.revoke('claude')
        self.assertIsNone(authenticate(self.domain, f'Bearer {token}'))

    def test_plaintext_not_stored(self):
        token = self.domain.mint_agent('claude')
        with self.store.transaction() as db:
            stored = db.execute('SELECT token_hash FROM agents').fetchone()[0]
        self.assertNotEqual(stored, token)
        self.assertEqual(stored, hash_token(token))


if __name__ == '__main__':
    unittest.main()
