"""Make the custom certificate and private key files used by TLS tests.

Code heavily borrowed from Lib/tests/make_ssl_certs.py in CPython.
"""

from __future__ import annotations

import os
import subprocess
import tempfile

import trustme

req_template = """
    [req]
    distinguished_name     = req_distinguished_name
    x509_extensions        = req_x509_extensions
    prompt                 = no

    [req_distinguished_name]
    C                      = XY
    L                      = Dask-distributed
    O                      = Dask
    CN                     = {hostname}

    [req_x509_extensions]
    subjectAltName         = @san

    [san]
    DNS.1 = {hostname}

    [ca]
    default_ca      = CA_default

    [CA_default]
    dir = cadir
    database  = $dir/index.txt
    crlnumber = $dir/crl.txt
    default_md = sha256
    default_days = 360000
    default_crl_days = 360000
    certificate = tls-ca-cert.pem
    private_key = tls-ca-key.pem
    serial    = $dir/serial
    RANDFILE  = $dir/.rand

    policy          = policy_match

    [policy_match]
    countryName             = match
    stateOrProvinceName     = optional
    organizationName        = match
    organizationalUnitName  = optional
    commonName              = supplied
    emailAddress            = optional

    [policy_anything]
    countryName   = optional
    stateOrProvinceName = optional
    localityName    = optional
    organizationName  = optional
    organizationalUnitName  = optional
    commonName    = supplied
    emailAddress    = optional

    [v3_ca]
    subjectKeyIdentifier=hash
    authorityKeyIdentifier=keyid:always,issuer
    basicConstraints = CA:true
    """

here = os.path.abspath(os.path.dirname(__file__))


def make_cert_key(hostname, sign=False):
    print("creating cert for " + hostname)
    tempnames = []
    for _ in range(3):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            tempnames.append(f.name)
    req_file, cert_file, key_file = tempnames
    try:
        req = req_template.format(hostname=hostname)
        with open(req_file, "w") as f:
            f.write(req)
        args = [
            "req",
            "-new",
            "-days",
            "365242",
            "-nodes",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_file,
            "-config",
            req_file,
        ]
        if sign:
            with tempfile.NamedTemporaryFile(delete=False) as f:
                tempnames.append(f.name)
                reqfile = f.name
            args += ["-out", reqfile]

        else:
            args += ["-x509", "-out", cert_file]
        subprocess.check_call(["openssl"] + args)

        if sign:
            args = [
                "ca",
                "-config",
                req_file,
                "-out",
                cert_file,
                "-outdir",
                "cadir",
                "-policy",
                "policy_anything",
                "-batch",
                "-infiles",
                reqfile,
            ]
            subprocess.check_call(["openssl"] + args)

        with open(cert_file) as f:
            cert = f.read()
        with open(key_file) as f:
            key = f.read()
        return cert, key
    finally:
        for name in tempnames:
            os.remove(name)


def write_cert_text_and_blob(
    cert: trustme.Blob, path: str | os.PathLike[str], append: bool = False
) -> None:
    with open(path, "ab" if append else "wb") as f:
        subprocess.run(
            ["openssl", "x509", "-text"],
            input=cert.bytes(),
            stdout=f,
            check=True,
        )


if __name__ == "__main__":
    os.chdir(here)
    cert, key = make_cert_key("localhost")
    with open("tls-self-signed-cert.pem", "w") as f:
        f.write(cert)
    with open("tls-self-signed-key.pem", "w") as f:
        f.write(key)

    # For certificate matching tests
    ca = trustme.CA(organization_name="Dask CA")
    write_cert_text_and_blob(ca.cert_pem, "tls-ca-cert.pem")

    child_ca = ca.create_child_ca()
    cert = child_ca.issue_cert("localhost")
    write_cert_text_and_blob(cert.cert_chain_pems[0], "tls-cert.pem")
    write_cert_text_and_blob(cert.cert_chain_pems[0], "tls-cert-chain.pem")
    for blob in cert.cert_chain_pems[1:]:
        write_cert_text_and_blob(blob, "tls-cert-chain.pem", append=True)
    cert.private_key_pem.write_to_path("tls-key.pem")
    cert.private_key_pem.write_to_path("tls-key-cert.pem")
    write_cert_text_and_blob(cert.cert_chain_pems[0], "tls-key-cert.pem", append=True)
