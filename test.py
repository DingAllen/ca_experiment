import unittest
from root_ca import *
from utils import *

# class MyTestCase(unittest.TestCase):
#
#     def test_gen_generate_rsa_keypair(self):
#         generate_rsa_keypair('data/root')
#
#     def test_generate_root_ca_certificate(self):
#         generate_root_ca_certificate(path='data/root/root_ca.pem', private_pem_path='data/root/private.pem')


if __name__ == '__main__':
    generate_rsa_keypair('data/root')  # 生成根CA的公私钥
    generate_root_ca_certificate(path='data/root/root_ca.pem', private_pem_path='data/root/private.pem')  # 生成根CA证书
    generate_rsa_keypair('data/immediate')  # 生成中间CA的公私钥
    generate_csr(path='data/immediate/csr.pem', private_pem_path='data/immediate/private.pem')  # 生成CSR
    generate_intermediate_ca_certificate_from_csr(path='data/immediate/immediate_ca.pem',
                                                  csr_path='data/immediate/csr.pem',
                                                  root_ca_pem_path='data/root/root_ca.pem',
                                                  root_ca_private_pem_path='data/root/private.pem')  # 生成中间CA证书
