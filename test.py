import unittest
from root_ca import *

class MyTestCase(unittest.TestCase):

    def test_gen_generate_rsa_keypair(self):
        generate_rsa_keypair('data/root')

    def test_generate_root_ca_certificate(self):
        generate_root_ca_certificate(path='data/root/root_ca.pem', private_pem_path='data/root/private.pem')


if __name__ == '__main__':
    unittest.main()
