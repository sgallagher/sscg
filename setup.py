from setuptools import setup, find_packages


setup(
    name="sscg",
    version="0.1",
    use_2to3=True,

    entry_points="""\
    [console_scripts]
    sscg = sscg.main:main
    """,

    # We're going to generate these certificates using OpenSSL
    install_requires=['pyOpenSSL', 'pyasn1'],

    packages=find_packages('src'),
    package_dir={'': 'src'},

    # metadata for upload to PyPI
    author="Stephen Gallagher",
    author_email="sgallagh@redhat.com",
    description="""
A package to simplify the creation of self-signed certificates for services.
Note: this tool will generate certificates that are not truly self-signed;
instead, it will create a short-lived Certificate Authority to sign the
service certificate and then destroy the signing key. This allows the
temporary CA certificate to be imported safely to a trust store so that client
applications can trust this certificate without skipping validation. 
""",
    license="PSF",
    keywords="certificates openssl x509",
    url="https://github.com/sgallagher/sscg",  # project home page, if any

    # could also include long_description, download_url, classifiers, etc.
)
