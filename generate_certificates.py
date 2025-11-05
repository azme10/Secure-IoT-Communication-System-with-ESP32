#!/usr/bin/env python3
"""
Certificate Generator for ESP32 Mutual TLS Authentication
Generates CA, Server (Receiver), and Client (Sender) certificates
"""

import os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta

def generate_private_key():
    """Generate an EC private key (P-256 curve)"""
    return ec.generate_private_key(ec.SECP256R1())

def generate_ca_certificate():
    """Generate a self-signed CA certificate"""
    print("🔐 Generating CA certificate...")
    
    # Generate CA private key
    ca_key = generate_private_key()
    
    # Create CA certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ESP32 Test CA"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ESP32 Root CA"),
    ])
    
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(ca_key, hashes.SHA256())
    
    return ca_key, ca_cert

def generate_device_certificate(common_name, ca_key, ca_cert, is_server=False):
    """Generate a device certificate signed by CA"""
    print(f"🔐 Generating {common_name} certificate...")
    
    # Generate device private key
    device_key = generate_private_key()
    
    # Create device certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ESP32"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, common_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        device_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)  # 1 year
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    
    # Add key usage
    if is_server:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=True,
                content_commitment=False,
                data_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=True,
        )
    else:  # client
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_agreement=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=True,
        )
    
    device_cert = builder.sign(ca_key, hashes.SHA256())
    
    return device_key, device_cert

def save_pem(filename, data):
    """Save PEM data to file"""
    with open(filename, "wb") as f:
        f.write(data)
    print(f"✅ Saved: {filename}")

def main():
    print("=" * 70)
    print("ESP32 Mutual TLS Authentication - Certificate Generator")
    print("=" * 70)
    print()
    
    # Create output directory
    os.makedirs("certs", exist_ok=True)
    
    # Generate CA
    ca_key, ca_cert = generate_ca_certificate()
    
    # Save CA certificate and key
    save_pem("certs/ca_cert.pem", ca_cert.public_bytes(serialization.Encoding.PEM))
    save_pem("certs/ca_key.pem", ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    
    print()
    
    # Generate Server (Receiver) certificate
    server_key, server_cert = generate_device_certificate("ESP32-Receiver", ca_key, ca_cert, is_server=True)
    
    # Save Server certificate and key
    save_pem("certs/server_cert.pem", server_cert.public_bytes(serialization.Encoding.PEM))
    save_pem("certs/server_key.pem", server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    
    print()
    
    # Generate Client (Sender) certificate
    client_key, client_cert = generate_device_certificate("ESP32-Sender", ca_key, ca_cert, is_server=False)
    
    # Save Client certificate and key
    save_pem("certs/client_cert.pem", client_cert.public_bytes(serialization.Encoding.PEM))
    save_pem("certs/client_key.pem", client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    
    print()
    print("=" * 70)
    print("✅ All certificates generated successfully!")
    print("=" * 70)
    print()
    print("📋 Generated files in 'certs/' directory:")
    print("   - ca_cert.pem       : CA certificate (use in both devices)")
    print("   - ca_key.pem        : CA private key (keep secure)")
    print("   - server_cert.pem   : Receiver's certificate")
    print("   - server_key.pem    : Receiver's private key")
    print("   - client_cert.pem   : Sender's certificate")
    print("   - client_key.pem    : Sender's private key")
    print()
    print("📝 Next steps:")
    print("   1. Copy the contents of these files into your Arduino code")
    print("   2. Update sender_tls_mutual_auth.ino with:")
    print("      - client_cert.pem → client_cert")
    print("      - client_key.pem → client_key")
    print("      - ca_cert.pem → ca_cert")
    print("   3. Update receiver_tls_mutual_auth.ino with:")
    print("      - server_cert.pem → server_cert")
    print("      - server_key.pem → server_key")
    print("      - ca_cert.pem → ca_cert")
    print()

if __name__ == "__main__":
    main()
