import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# 生成RSA密钥对，并保存到文件中
def generate_rsa_keypair(path='./', password=None, key_size=2048, public_exponent=65537):
    # 生成私钥对象
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )
    # 生成公钥对象
    public_key = private_key.public_key()
    # 将私钥对象序列化为PEM格式，并加密为PKCS8格式，使用密码
    encryption_algorithm = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )
    # 将公钥对象序列化为PEM格式，不加密，使用SubjectPublicKeyInfo格式
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # 将私钥和公钥分别写入文件中，文件名为"private.pem"和"public.pem"
    with open(os.path.join(path, "private.pem"), "wb") as f:
        f.write(private_pem)
    with open(os.path.join(path, "public.pem"), "wb") as f:
        f.write(public_pem)