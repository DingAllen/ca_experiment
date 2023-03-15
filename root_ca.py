import os
import datetime
import ssl
import cryptography.x509 as x509
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

class Root_CA_Attributes:
    country_name = u'CN'
    state_or_province_name = u'Jiangsu'
    locality_name = u'Zhenjiang'
    organization_name = u'Dingod'
    common_name = u'Dingod CA Root'


# 定义一个函数，用于生成自签名的根CA证书，并保存到文件中
def generate_root_ca_certificate(path, private_pem_path, password=None, sign_algorithm=hashes.SHA256()):
    # 从文件中读取私钥对象，并使用密码解密
    with open(private_pem_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            data=f.read(),
            password=password
        )

    # 创建一个X.509证书构建器对象，并设置一些基本信息，如版本号、序列号、有效期等
    builder = x509.CertificateBuilder()

    builder = builder.serial_number(x509.random_serial_number())  # 设置随机序列号

    builder = builder.not_valid_before(datetime.datetime.utcnow())  # 设置有效期开始时间为当前时间

    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # 设置有效期结束时间为一年后

    # 创建一个X.509名称对象，并设置根CA证书的主题信息，如国家、组织、通用名等
    subject_name = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u'CN'),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u'Jiangsu'),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u'Zhenjiang'),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u'Dingod'),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u'Dingod CA Root'),
    ])

    builder = builder.subject_name(subject_name)  # 设置主题名称

    builder = builder.issuer_name(subject_name)  # 设置颁发者名称（自签名时与主题名称相同）

    builder = builder.public_key(private_key.public_key())  # 设置公钥

    # 创建一个X.509扩展对象，并设置根CA证书的扩展信息，如基本约束、密钥用法、主体密钥标识符等

    basic_constraints_ext = x509.BasicConstraints(ca=True, path_length=None)  # 设置基本约束为CA证书，无路径长度限制

    key_usage_ext = x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False
    )  # 设置密钥用法为签发证书和撤销列表

    subject_key_identifier_ext = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())  # 从公钥生成主体密钥标识符

    builder = builder.add_extension(basic_constraints_ext, critical=True)  # 添加基本约束扩展，并设置为关键

    builder = builder.add_extension(key_usage_ext, critical=True)  # 添加密钥用法扩展，并设置为关键

    builder = builder.add_extension(subject_key_identifier_ext, critical=False)  # 添加主体密钥标识符扩展，并设置为非关键

    # 使用私钥对证书进行签名，并指定签名算法
    certificate = builder.sign(
        private_key=private_key,
        algorithm=sign_algorithm,
    )

    # 将证书对象序列化为PEM格式，并写入文件中
    with open(path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
