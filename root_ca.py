import datetime
import cryptography.x509 as x509
from cryptography.hazmat.primitives import hashes, serialization


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


# 定义一个函数，用于生成一个中间CA的证书，并保存到文件中
def generate_intermediate_ca_certificate(path, private_pem_path, root_ca_pem_path, root_ca_private_pem_path,
                                         password=None, sign_algorithm=hashes.SHA256()):
    # 从文件中读取私钥对象，并使用密码解密
    with open(private_pem_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            data=f.read(),
            password=password
        )

    # 从文件中读取根CA证书对象
    with open(root_ca_pem_path, "rb") as f:
        root_ca_certificate = x509.load_pem_x509_certificate(
            data=f.read()
        )

    # 从文件中读取根CA私钥对象，并使用密码解密
    with open(root_ca_private_pem_path, "rb") as f:
        root_ca_private_key = serialization.load_pem_private_key(
            data=f.read(),
            password=password
        )

    # 创建一个X.509证书构建器对象，并设置一些基本信息，如版本号、序列号、有效期等
    builder = x509.CertificateBuilder()

    builder = builder.serial_number(x509.random_serial_number())  # 设置随机序列号

    builder = builder.not_valid_before(datetime.datetime.utcnow())  # 设置有效期开始时间为当前时间

    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # 设置有效期结束时间为一年后

    # 创建一个X.509名称对象，并设置中间CA证书的主题信息，如国家、组织、通用名等
    subject_name = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u'CN'),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u'Jiangsu'),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u'Zhenjiang'),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u'Dingod'),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u'Dingod CA Intermediate'),
    ])

    builder = builder.subject_name(subject_name)  # 设置主题名称

    builder = builder.issuer_name(root_ca_certificate.subject)  # 设置颁发者名称（根CA证书的主题名称）

    builder = builder.public_key(private_key.public_key())  # 设置公钥

    # 创建一个X.509扩展对象，并设置中间CA证书的扩展信息，如基本约束、密钥用法、主体密钥标识符、授权密钥标识符等

    basic_constraints_ext = x509.BasicConstraints(ca=True, path_length=0)  # 设置基本约束为CA证书，路径长度限制为0（只能签发终端实体证书）

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

    authority_key_identifier_ext = x509.AuthorityKeyIdentifier.from_issuer_public_key(
        root_ca_private_key.public_key())  # 从根CA私钥生成授权密钥标识符

    builder = builder.add_extension(basic_constraints_ext, critical=True)  # 添加基本约束扩展，并设置为关键

    builder = builder.add_extension(key_usage_ext, critical=True)  # 添加密钥用法扩展，并设置为关键

    builder = builder.add_extension(subject_key_identifier_ext, critical=False)  # 添加主体密钥标识符扩展，并设置为非关键

    builder = builder.add_extension(authority_key_identifier_ext, critical=False)  # 添加授权密钥标识符扩展，并设置为非关键

    # 使用根CA私钥对证书进行签名，并指定签名算法
    certificate = builder.sign(
        private_key=root_ca_private_key,
        algorithm=sign_algorithm,
    )

    # 将证书对象序列化为PEM格式，并写入文件中
    with open(path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))


# 定义一个函数，用于生成一个CSR，并保存到文件中
def generate_csr(path, private_pem_path, password=None):
    # 从文件中读取私钥对象，并使用密码解密
    with open(private_pem_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            data=f.read(),
            password=password
        )

    # 创建一个X.509名称对象，并设置主题信息，如国家、组织、通用名等
    subject_name = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u'CN'),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u'Jiangsu'),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u'Zhenjiang'),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u'Dingod'),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u'Dingod CA Intermediate'),
    ])

    # 创建一个X.509扩展对象，并设置基本约束为CA证书
    basic_constraints_ext = x509.BasicConstraints(ca=True, path_length=0)

    # 创建一个X.509 CSR构建器对象，并设置公钥、主题名称和扩展信息
    builder = x509.CertificateSigningRequestBuilder()

    builder = builder.subject_name(subject_name)  # 设置主题名称

    builder = builder.add_extension(basic_constraints_ext, critical=True)  # 添加基本约束扩展，并设置为关键

    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                                    critical=False)  # 设置公钥并添加主题密钥标识符扩展

    # 使用私钥对CSR进行签名，并指定签名算法
    csr = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256()
    )

    # 将CSR对象序列化为PEM格式，并写入文件中
    with open(path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))


# 定义一个函数，用于从CSR生成一个中间CA的证书，并保存到文件中
def generate_intermediate_ca_certificate_from_csr(path, csr_path,
                                                  root_ca_pem_path,
                                                  root_ca_private_pem_path,
                                                  password=None,
                                                  sign_algorithm=hashes.SHA256()):
    # 从文件中读取根CA证书对象
    with open(root_ca_pem_path, "rb") as f:
        root_ca_certificate = x509.load_pem_x509_certificate(
            data=f.read()
        )

    # 从文件中读取根CA私钥对象，并使用密码解密
    with open(root_ca_private_pem_path, "rb") as f:
        root_ca_private_key = serialization.load_pem_private_key(
            data=f.read(),
            password=password
        )

    # 从文件中读取CSR对象
    with open(csr_path, "rb") as f:
        csr = x509.load_pem_x509_csr(
            data=f.read()
        )

    # 从CSR中获取公钥对象
    public_key = csr.public_key()

    # 从CSR中获取主题名称对象
    subject_name = csr.subject

    # 创建一个X.509名称对象，并设置颁发者信息，即根CA证书的主题名称
    issuer_name = root_ca_certificate.subject

    # 创建一个X.509序列号生成器对象，并设置随机数生成器和位数
    serial_number = x509.random_serial_number()

    not_valid_before = datetime.datetime.utcnow()  # 设置开始时间为当前时间

    not_valid_after = not_valid_before + datetime.timedelta(days=365)  # 设置结束时间为一年后

    # 创建一个X.509扩展对象，并设置基本约束为CA证书
    basic_constraints_ext = x509.BasicConstraints(ca=True, path_length=0)

    # 创建一个X.509证书构建器对象，并设置公钥、序列号、颁发者、主题、有效期和扩展信息
    builder = x509.CertificateBuilder()

    builder = builder.public_key(public_key)  # 设置公钥

    builder = builder.serial_number(serial_number)  # 设置序列号

    builder = builder.issuer_name(issuer_name)  # 设置颁发者

    builder = builder.subject_name(subject_name)  # 设置主题

    builder = builder.not_valid_before(not_valid_before)  # 设置开始时间

    builder = builder.not_valid_after(not_valid_after)  # 设置结束时间

    builder = builder.add_extension(basic_constraints_ext, critical=True)  # 添加基本约束扩展，并设置为关键

    # 使用根CA私钥对证书进行签名，并指定签名算法
    certificate = builder.sign(
        private_key=root_ca_private_key,
        algorithm=sign_algorithm,
    )

    # 将证书对象序列化为PEM格式，并写入文件中
    with open(path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
