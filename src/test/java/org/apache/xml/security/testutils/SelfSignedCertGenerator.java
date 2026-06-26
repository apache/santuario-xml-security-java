/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.testutils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Map;

/**
 * Generates minimal self-signed X.509 v3 certificates using only public JDK APIs.
 *
 * <p>The certificate’s DER structure is constructed directly from ASN.1/DER primitives
 * and then parsed using CertificateFactory. No BouncyCastle, no sun.security.* internals,
 * and no --add-opens flags are required.
 * This class is designed to eliminate the need for storing test certificates in a keystore
 * or truststore. Instead, the certificates are generated dynamically during test execution.
 * </p>
 * <h3>Supported signature algorithms</h3>
 * <ul>
 *   <li>RSA — {@code SHA256withRSA}, {@code SHA384withRSA}, {@code SHA512withRSA}</li>
 *   <li>ECDSA — {@code SHA256withECDSA}, {@code SHA384withECDSA}, {@code SHA512withECDSA}</li>
 *   <li>EdDSA — {@code Ed25519}, {@code Ed448} (requires Java 15+)</li>
 * </ul>
 *
 * <h3>Limitations</h3>
 * <ul>
 *   <li>Only the {@code CN} attribute is supported in the subject/issuer DN.</li>
 *   <li>No X.509 extensions are added (basic-constraints, key-usage, etc.).</li>
 *   <li>Validity dates use UTCTime, which covers years 2000–2049.</li>
 * </ul>
 *
 * <p>These are acceptable constraints for unit and integration tests.
 */
public final class SelfSignedCertGenerator {

    private SelfSignedCertGenerator() {
    }

    /**
     * Pre-encoded DER bytes for the {@code AlgorithmIdentifier} of each supported
     * signature algorithm.  Values are constant per the relevant RFCs; they do not
     * depend on the key size or curve, only on the algorithm name.
     *
     * <p>RSA algorithms include a trailing {@code NULL} parameters element (RFC 4055 §3.2).
     * ECDSA and EdDSA algorithms omit parameters entirely (RFC 5758, RFC 8410).
     */
    private static final Map<String, byte[]> ALG_IDS = Map.of(
            "SHA256withRSA",   encodeAlgorithmIdentifier("1.2.840.113549.1.1.11"),
            "SHA384withRSA",   encodeAlgorithmIdentifier("1.2.840.113549.1.1.12"),
            "SHA512withRSA",   encodeAlgorithmIdentifier("1.2.840.113549.1.1.13"),
            "SHA256withECDSA", encodeAlgorithmIdentifier("1.2.840.10045.4.3.2"),
            "SHA384withECDSA", encodeAlgorithmIdentifier("1.2.840.10045.4.3.3"),
            "SHA512withECDSA", encodeAlgorithmIdentifier("1.2.840.10045.4.3.4"),
            "Ed25519",         encodeAlgorithmIdentifier("1.3.101.112"),
            "Ed448",           encodeAlgorithmIdentifier("1.3.101.113"));

    /**
     * Generates a self-signed X.509 v3 certificate.
     *
     * @param keyPair            the key pair to certify; the private key signs the TBS structure
     *                           and the public key is embedded in SubjectPublicKeyInfo
     * @param signatureAlgorithm JCA algorithm name, e.g. {@code "SHA256withRSA"} or {@code "Ed25519"}
     * @param subjectDN          distinguished name — only the {@code CN} attribute is used,
     *                           e.g. {@code "CN=Test Certificate"}
     * @param validityDays       number of days the certificate is valid, starting from now
     * @return the signed X.509 certificate
     * @throws IllegalArgumentException if {@code signatureAlgorithm} is not in the supported set
     */
    public static X509Certificate generate(KeyPair keyPair,
                                           String signatureAlgorithm,
                                           String subjectDN,
                                           int validityDays) throws Exception {
        byte[] algId = ALG_IDS.get(signatureAlgorithm);
        if (algId == null) {
            throw new IllegalArgumentException(
                    "Unsupported signature algorithm: " + signatureAlgorithm
                            + ". Supported: " + ALG_IDS.keySet());
        }

        // publicKey.getEncoded() returns the SubjectPublicKeyInfo in X.509/DER format.
        byte[] spki = keyPair.getPublic().getEncoded();
        byte[] name = encodeName(subjectDN);
        byte[] tbs = buildTbs(algId, name, spki, validityDays);

        Signature signer = Signature.getInstance(signatureAlgorithm);
        signer.initSign(keyPair.getPrivate());
        signer.update(tbs);
        byte[] sigBytes = signer.sign();

        // Certificate ::= SEQUENCE { TBSCertificate, AlgorithmIdentifier, BIT STRING }
        byte[] certDer = sequence(cat(tbs, algId, bitString(sigBytes)));

        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certDer));
    }

    // -------------------------------------------------------------------------
    // TBSCertificate builder
    // -------------------------------------------------------------------------

    /**
     * Builds the DER-encoded TBSCertificate.
     *
     * <pre>
     * TBSCertificate ::= SEQUENCE {
     *   version         [0] EXPLICIT INTEGER DEFAULT v1,
     *   serialNumber    INTEGER,
     *   signature       AlgorithmIdentifier,
     *   issuer          Name,
     *   validity        Validity,
     *   subject         Name,
     *   subjectPublicKeyInfo SubjectPublicKeyInfo
     * }
     * </pre>
     */
    private static byte[] buildTbs(byte[] algId, byte[] name,
                                   byte[] spki, int validityDays) {
        // [0] EXPLICIT INTEGER 2  →  version v3
        byte[] version = new byte[]{(byte) 0xA0, 0x03, 0x02, 0x01, 0x02};
        // Serial: milliseconds since epoch — unique enough for test certs
        byte[] serial = integer(BigInteger.valueOf(System.currentTimeMillis()));
        byte[] validity = buildValidity(validityDays);
        // issuer == subject for self-signed
        return sequence(cat(version, serial, algId, name, validity, name, spki));
    }

    private static byte[] buildValidity(int validityDays) {
        Instant notBefore = Instant.now();
        Instant notAfter = notBefore.plusSeconds(validityDays * 86_400L);
        return sequence(cat(utcTime(notBefore), utcTime(notAfter)));
    }

    // -------------------------------------------------------------------------
    // DN encoding — only CN attribute (OID 2.5.4.3) supported
    // -------------------------------------------------------------------------

    /**
     * Encodes a Name containing a single CN attribute.
     *
     * <pre>
     * Name ::= SEQUENCE OF SET OF SEQUENCE { OID, value }
     * </pre>
     */
    private static byte[] encodeName(String dn) {
        // OID for commonName (2.5.4.3): 06 03 55 04 03
        byte[] cnOid = encodeOid("2.5.4.3");
        byte[] cnValue = tlv(0x0C, extractCN(dn).getBytes(StandardCharsets.UTF_8)); // UTF8String
        return sequence(set(sequence(cat(cnOid, cnValue))));
    }

    /**
     * Extracts the CN value from a DN string such as {@code "CN=My Test,O=Acme"}.
     */
    private static String extractCN(String dn) {
        for (String part : dn.split(",")) {
            String trimmed = part.strip();
            if (trimmed.regionMatches(true, 0, "CN=", 0, 3)) {
                return trimmed.substring(3).strip();
            }
        }
        return dn; // fallback: treat the whole string as the CN value
    }

    // -------------------------------------------------------------------------
    // DER / ASN.1 primitives
    // -------------------------------------------------------------------------

    /**
     * Encodes the provided content as an ASN.1 DER SEQUENCE.
     *
     * <p>A SEQUENCE in ASN.1 represents an ordered collection of elements
     * <p>The DER tag for a SEQUENCE is <b>0x30</b>.</p>
     *
     * <p><b>Use in X.509:</b><br>
     * Distinguished Names (DNs), RelativeDistinguishedNames (RDNs), and
     * AttributeTypeAndValue pairs are all encoded using SEQUENCE structures. For example,
     * an AttributeTypeAndValue is defined as:</p>
     *
     * <pre>
     * AttributeTypeAndValue ::= SEQUENCE {
     *   type   OBJECT IDENTIFIER,
     *   value  DirectoryString
     * }
     * </pre>
     *
     * <p>Thus, for the DN <code>CN=Test</code>, the inner attribute pair is encoded as:</p>
     *
     * <pre>
     * 30 ...                SEQUENCE (AttributeTypeAndValue)
     *   06 03 55 04 03      OID 2.5.4.3 (commonName)
     *   0C 04 54 65 73 74   UTF8String "Test"
     * </pre>
     *
     * @param content the already‑encoded DER content to wrap in a SEQUENCE
     * @return the DER‑encoded SEQUENCE (tag 0x30 + length + content)
     */
    private static byte[] sequence(byte[] content) {
        return tlv(0x30, content);
    }


    /**
     * Encodes the provided content as an ASN.1 DER SET value.
     *
     * <p>In ASN.1, a SET represents an unordered collection of elements. Although the
     * abstract syntax does not impose ordering, DER requires all elements inside a SET
     * to be sorted by their encoded byte values to ensure canonical form.</p>
     *
     * <p>The DER tag for a SET is <b>0x31</b>.</p>
     *
     * <p><b>Use in X.509:</b><br>
     * Within an X.509 Distinguished Name (DN), each RelativeDistinguishedName (RDN)
     * is encoded as a SET containing one or more AttributeTypeAndValue structures.
     * A DN therefore follows the structure:</p>
     *
     * <pre>
     * Name ::= SEQUENCE OF
     *            SET OF
     *              SEQUENCE {
     *                type   OBJECT IDENTIFIER,   -- e.g., 2.5.4.3 (commonName)
     *                value  DirectoryString      -- e.g., UTF8String "Test"
     *              }
     * </pre>
     * @param content the already‑encoded DER content to wrap in a SET
     * @return the DER-encoded SET (tag 0x31 + length + content)
     */
    private static byte[] set(byte[] content) {
        return tlv(0x31, content);
    }

    private static byte[] integer(BigInteger value) {
        // toByteArray() produces two's-complement big-endian; positive integers may
        // have a leading 0x00 byte if the MSB would otherwise be set — that is correct
        // DER INTEGER encoding for a non-negative number.
        return tlv(0x02, value.toByteArray());
    }

    private static byte[] bitString(byte[] value) {
        return tlv(0x03, cat(new byte[]{0x00}, value)); // 0x00 = zero unused bits
    }

    // UTCTime covers 2000–2049 (yy < 50 → 20yy).  Sufficient for short-lived test certs.
    private static final DateTimeFormatter UTC_TIME_FMT =
            DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);

    private static byte[] utcTime(Instant instant) {
        return tlv(0x17, UTC_TIME_FMT.format(instant).getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Encodes a DER TLV (Tag–Length–Value) triplet.
     * Lengths up to 65535 bytes are supported; that is sufficient for all key types
     * used in practice.
     */
    private static byte[] tlv(int tag, byte[] value) {
        int len = value.length;
        byte[] lenBytes;
        if (len < 128) {
            lenBytes = new byte[]{(byte) len};
        } else if (len < 256) {
            lenBytes = new byte[]{(byte) 0x81, (byte) len};
        } else {
            lenBytes = new byte[]{(byte) 0x82, (byte) (len >> 8), (byte) (len & 0xFF)};
        }
        byte[] out = new byte[1 + lenBytes.length + len];
        out[0] = (byte) tag;
        System.arraycopy(lenBytes, 0, out, 1, lenBytes.length);
        System.arraycopy(value, 0, out, 1 + lenBytes.length, len);
        return out;
    }

    /**
     * Concatenates byte arrays.
     */
    private static byte[] cat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) {
            total += p.length;
        }
        byte[] buf = new byte[total];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, buf, pos, p.length);
            pos += p.length;
        }
        return buf;
    }

    /**
     * Encode oid as certificate algorithm identifier.
     * @param oid
     * @return
     */
    public static byte[] encodeAlgorithmIdentifier(String oid) {
        // RFC 8410: EdDSA parameters MUST be absent; RSA/ECDSA require a NULL (RFC 4055/5758)
        byte[] nullParam = oid.startsWith("1.3.101.11") ? new byte[0] : new byte[]{0x05, 0x00};
        return sequence(cat(encodeOid(oid), nullParam));
    }

    /**
     * Endodes all number values to ASN.1/DER encoded bytearray
     * @param oid - the value
     * @return encoded byte array
     */
    public static byte[] encodeOid(String oid) {
        String[] parts = oid.split("\\.");
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(40 * Integer.parseInt(parts[0]) + Integer.parseInt(parts[1]));
        for (int i = 2; i < parts.length; i++) {
            byte[] arc = encodeBase128(Long.parseLong(parts[i]));
            body.write(arc, 0, arc.length);
        }
        return tlv(0x06, body.toByteArray());
    }

    /**
     *  It encodes a non-negative integer using base-128 (variable-length) encoding, which is the standard
     *  way ASN.1/DER encodes OID arc values
     * @param value the long value
     * @return ASN.1/DER encoded value
     */
    private static byte[] encodeBase128(long value) {
        byte[] stack = new byte[10];
        int count = 0;
        do {
            stack[count++] = (byte) (value & 0x7F);
            value >>= 7;
        } while (value > 0);
        byte[] result = new byte[count];
        for (int i = 0; i < count; i++) {
            result[i] = (byte) (stack[count - 1 - i] | (i < count - 1 ? 0x80 : 0x00));
        }
        return result;
    }
}
