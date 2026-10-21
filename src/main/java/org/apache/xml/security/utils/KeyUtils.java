/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.utils;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.implementations.ECDSAUtils;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.encryption.keys.content.derivedKey.ConcatKDF;
import org.apache.xml.security.encryption.keys.content.derivedKey.HKDF;
import org.apache.xml.security.encryption.params.ConcatKDFParams;
import org.apache.xml.security.encryption.params.HKDFParams;
import org.apache.xml.security.encryption.params.KeyAgreementParameters;
import org.apache.xml.security.encryption.params.KeyDerivationParameters;
import org.apache.xml.security.exceptions.DERDecodingException;
import org.apache.xml.security.exceptions.XMLSecurityException;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.lang.System.Logger.Level;
import java.lang.reflect.Method;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Set;

/**
 * A set of utility methods to handle keys.
 */
public class KeyUtils {

    /**
     * Enumeration of Supported key algorithm types.
     */
    public enum KeyAlgorithmType {
        EC("EC", "1.2.840.10045.2.1"),
        DSA("DSA", "1.2.840.10040.4.1"),
        RSA("RSA", "1.2.840.113549.1.1.1"),
        RSASSA_PSS("RSASSA-PSS", "1.2.840.113549.1.1.10"),
        DH("DiffieHellman", "1.2.840.113549.1.3.1"),
        XDH("XDH", null),
        EdDSA("EdDSA", null);
        private final String jceName;
        private final String oid;

        KeyAlgorithmType(String jceName, String oid) {
            this.jceName = jceName;
            this.oid = oid;
        }

        public String getJceName() {
            return jceName;
        }

        public String getOid() {
            return oid;
        }

    }

    /**
     * Enumeration of specific key types.
     */
    public enum KeyType {
        DSA("DSA", "RFC 8017", KeyAlgorithmType.DSA, "1.2.840.10040.4.1"),
        RSA("RSA", "RFC 8017", KeyAlgorithmType.RSA, "1.2.840.113549.1.1.1"),
        RSASSA_PSS("RSASSA-PSS", "RFC 3447", KeyAlgorithmType.RSASSA_PSS, "1.2.840.113549.1.1.10"),
        SECT163K1("sect163k1", "NIST K-163", KeyAlgorithmType.EC, "1.3.132.0.1"),
        SECT163R1("sect163r1", "", KeyAlgorithmType.EC, "1.3.132.0.2"),
        SECT163R2("sect163r2", "NIST B-163", KeyAlgorithmType.EC, "1.3.132.0.15"),
        SECT193R1("sect193r1", "", KeyAlgorithmType.EC, "1.3.132.0.24"),
        SECT193R2("sect193r2", "", KeyAlgorithmType.EC, "1.3.132.0.25"),
        SECT233K1("sect233k1", "NIST K-233", KeyAlgorithmType.EC, "1.3.132.0.26"),
        SECT233R1("sect233r1", "NIST B-233", KeyAlgorithmType.EC, "1.3.132.0.27"),
        SECT239K1("sect239k1", "", KeyAlgorithmType.EC, "1.3.132.0.3"),
        SECT283K1("sect283k1", "NIST K-283", KeyAlgorithmType.EC, "1.3.132.0.16"),
        SECT283R1("sect283r1", "", KeyAlgorithmType.EC, "1.3.132.0.17"),
        SECT409K1("sect409k1", "NIST K-409", KeyAlgorithmType.EC, "1.3.132.0.36"),
        SECT409R1("sect409r1", "NIST B-409", KeyAlgorithmType.EC, "1.3.132.0.37"),
        SECT571K1("sect571k1", "NIST K-571", KeyAlgorithmType.EC, "1.3.132.0.38"),
        SECT571R1("sect571r1", "NIST B-571", KeyAlgorithmType.EC, "1.3.132.0.39"),
        SECP160K1("secp160k1", "", KeyAlgorithmType.EC, "1.3.132.0.9"),
        SECP160R1("secp160r1", "", KeyAlgorithmType.EC, "1.3.132.0.8"),
        SECP160R2("secp160r2", "", KeyAlgorithmType.EC, "1.3.132.0.30"),
        SECP192K1("secp192k1", "", KeyAlgorithmType.EC, "1.3.132.0.31"),
        SECP192R1("secp192r1", "NIST P-192,X9.62 prime192v1", KeyAlgorithmType.EC, "1.2.840.10045.3.1.1"),
        SECP224K1("secp224k1", "", KeyAlgorithmType.EC, "1.3.132.0.32"),
        SECP224R1("secp224r1", "NIST P-224", KeyAlgorithmType.EC, "1.3.132.0.33"),
        SECP256K1("secp256k1", "", KeyAlgorithmType.EC, "1.3.132.0.10"),
        SECP256R1("secp256r1", "NIST P-256,X9.62 prime256v1", KeyAlgorithmType.EC, "1.2.840.10045.3.1.7"),
        SECP384R1("secp384r1", "NIST P-384", KeyAlgorithmType.EC, "1.3.132.0.34"),
        SECP521R1("secp521r1", "NIST P-521", KeyAlgorithmType.EC, "1.3.132.0.35"),
        BRAINPOOLP256R1("brainpoolP256r1", "RFC 5639", KeyAlgorithmType.EC, "1.3.36.3.3.2.8.1.1.7"),
        BRAINPOOLP384R1("brainpoolP384r1", "RFC 5639", KeyAlgorithmType.EC, "1.3.36.3.3.2.8.1.1.11"),
        BRAINPOOLP512R1("brainpoolP512r1", "RFC 5639", KeyAlgorithmType.EC, "1.3.36.3.3.2.8.1.1.13"),
        X25519("x25519", "RFC 7748", KeyAlgorithmType.XDH, "1.3.101.110"),
        X448("x448", "RFC 7748", KeyAlgorithmType.XDH, "1.3.101.111"),
        ED25519("ed25519", "RFC 8032", KeyAlgorithmType.EdDSA, "1.3.101.112"),
        ED448("ed448", "RFC 8032", KeyAlgorithmType.EdDSA, "1.3.101.113");

        private final String name;
        private final String origin;
        private final KeyAlgorithmType algorithm;
        private final String oid;

        KeyType(String name, String origin, KeyAlgorithmType algorithm, String oid) {
            this.name = name;
            this.origin = origin;
            this.algorithm = algorithm;
            this.oid = oid;
        }

        public String getName() {
            return name;
        }

        public KeyAlgorithmType getAlgorithm() {
            return algorithm;
        }

        public String getOid() {
            return oid;
        }

        public String getOrigin() {
            return origin;
        }

        public static KeyType getByOid(String oid) {
            return Arrays.stream(KeyType.values())
                    .filter(keyType -> keyType.getOid().equals(oid))
                    .findFirst().orElse(null);
        }
    }

    /**
     * Method generates DH keypair which match the type of given public key type.
     *
     * @param recipientPublicKey public key of recipient
     * @param provider provider to use for key generation
     * @return generated keypair
     * @throws XMLEncryptionException if the keys cannot be generated
     */
    public static KeyPair generateEphemeralDHKeyPair(PublicKey recipientPublicKey, Provider provider) throws XMLEncryptionException {
        String algorithm = recipientPublicKey.getAlgorithm();
        KeyPairGenerator keyPairGenerator;
        try {

            if (recipientPublicKey instanceof ECPublicKey) {
                keyPairGenerator = createKeyPairGenerator(algorithm, provider);
                ECPublicKey exchangePublicKey = (ECPublicKey) recipientPublicKey;
                String keyOId = ECDSAUtils.getOIDFromPublicKey(exchangePublicKey);
                if (keyOId == null) {
                    keyOId = DERDecoderUtils.getAlgorithmIdFromPublicKey(recipientPublicKey);
                }
                ECGenParameterSpec kpgparams = new ECGenParameterSpec(keyOId);
                keyPairGenerator.initialize(kpgparams);
            } else {
                String keyOId = DERDecoderUtils.getAlgorithmIdFromPublicKey(recipientPublicKey);
                KeyType keyType = KeyType.getByOid(keyOId);
                keyPairGenerator = createKeyPairGenerator(keyType == null ? keyOId : keyType.getName(), provider);
            }
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | DERDecodingException e) {
            throw new XMLEncryptionException(e);
        }
    }

    /**
     * Create a KeyPairGenerator for the given algorithm and provider.
     *
     * @param algorithm  the key JCE algorithm name
     * @param provider the provider to use or null if default JCE provider should be used
     * @return the KeyPairGenerator
     * @throws NoSuchAlgorithmException if the algorithm is not supported
     */
    public static KeyPairGenerator createKeyPairGenerator(String algorithm, Provider provider) throws NoSuchAlgorithmException {
        return provider == null ? KeyPairGenerator.getInstance(algorithm)
                : KeyPairGenerator.getInstance(algorithm, provider);
    }

    /**
     * Method generates a secret key for given KeyAgreementParameterSpec.
     *
     * @param parameterSpec KeyAgreementParameterSpec which defines algorithm to derive key
     * @return generated secret key
     * @throws XMLEncryptionException if the secret key cannot be generated as: Key agreement is not supported,
     * wrong key types, etc.
     */
    public static SecretKey aesWrapKeyWithDHGeneratedKey(KeyAgreementParameters parameterSpec)
            throws XMLEncryptionException {
        try {
            PublicKey publicKey = parameterSpec.getAgreementPublicKey();
            PrivateKey privateKey = parameterSpec.getAgreementPrivateKey();

            String keyAlgorithm = publicKey.getAlgorithm();
            String keyAgreementAlgorithm = keyAlgorithm + ("EC".equalsIgnoreCase(keyAlgorithm) ? "DH" : "");
            KeyAgreement keyAgreement = KeyAgreement.getInstance(keyAgreementAlgorithm);
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(publicKey, true);
            byte[] secret = keyAgreement.generateSecret();
            byte[] kek = deriveKeyEncryptionKey(secret, parameterSpec.getKeyDerivationParameter());
            return new SecretKeySpec(kek, "AES");
        } catch (XMLSecurityException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new XMLEncryptionException(e);
        }
    }

    /**
     * Defines the key size for the encrypting algorithm.
     *
     * @param keyWrapAlg the key wrap algorithm URI
     * @return the key size in bits
     * @throws XMLEncryptionException if the key wrap algorithm is not supported
     */
    public static int getAESKeyBitSizeForWrapAlgorithm(String keyWrapAlg) throws XMLEncryptionException {
        switch (keyWrapAlg) {
            case EncryptionConstants.ALGO_ID_KEYWRAP_AES128:
                return 128;
            case EncryptionConstants.ALGO_ID_KEYWRAP_AES192:
                return 192;
            case EncryptionConstants.ALGO_ID_KEYWRAP_AES256:
                return 256;
            default:
                throw new XMLEncryptionException("Unsupported KeyWrap Algorithm");
        }
    }

    /**
     * Derive a key encryption key from a shared secret and keyDerivationParameter.
     * Currently only the ConcatKDF and HMAC-base Extract-and-Expand Key Derivation
     * Function (HKDF) are supported.
     *
     * @param sharedSecret the shared secret
     * @param keyDerivationParameter the key derivation parameters
     * @return the derived key encryption key
     * @throws IllegalArgumentException if the keyDerivationParameter is null
     * @throws XMLSecurityException if the key derivation algorithm is not supported
     */
    public static byte[] deriveKeyEncryptionKey(byte[] sharedSecret, KeyDerivationParameters keyDerivationParameter)
            throws XMLSecurityException {

        if (keyDerivationParameter == null) {
            throw new IllegalArgumentException(I18n.translate("KeyDerivation.MissingParameters"));
        }

        String keyDerivationAlgorithm = keyDerivationParameter.getAlgorithm();
        if (keyDerivationParameter instanceof HKDFParams) {
            return deriveKeyWithHKDF(sharedSecret, (HKDFParams) keyDerivationParameter);
        } else if (keyDerivationParameter instanceof ConcatKDFParams) {
            return deriveKeyWithConcatKDF(sharedSecret, (ConcatKDFParams) keyDerivationParameter);
        }

        throw new XMLEncryptionException("KeyDerivation.UnsupportedAlgorithm", keyDerivationAlgorithm,
                keyDerivationParameter.getClass().getName());
    }

    /**
     * Derive a key using the HMAC-based Extract-and-Expand Key Derivation
     * Function (HKDF) with implementation instance {@link HKDFParams}.
     *
     * @param sharedSecret the shared secret
     * @param hkdfParameter the HKDF parameters
     * @return the derived key encryption key.
     * @throws XMLSecurityException if the key derivation parameters are invalid or
     *       the hmac algorithm is not supported.
     */
    public static byte[] deriveKeyWithHKDF(byte[] sharedSecret, HKDFParams hkdfParameter)
            throws XMLSecurityException {

        if (!EncryptionConstants.ALGO_ID_KEYDERIVATION_HKDF.equals(hkdfParameter.getAlgorithm())){
            throw new XMLEncryptionException("KeyDerivation.UnsupportedAlgorithm", hkdfParameter.getAlgorithm(),
                    HKDFParams.class.getName());
        }

        HKDF kdf = new HKDF();
        return kdf.deriveKey(sharedSecret, hkdfParameter);
    }

    /**
     * Derive a key using the Concatenation Key Derivation Function (ConcatKDF)
     * with implementation instance {@link ConcatKDFParams}.
     *
     * @param sharedSecret the shared secret/ input keying material
     * @param ckdfParameter the ConcatKDF parameters
     * @return the derived key
     * @throws XMLSecurityException if the key derivation parameters are invalid or
     *        the hash algorithm is not supported.
     */
    public static byte[] deriveKeyWithConcatKDF(byte[] sharedSecret, ConcatKDFParams ckdfParameter)
            throws XMLSecurityException {

        if (!EncryptionConstants.ALGO_ID_KEYDERIVATION_CONCATKDF.equals(ckdfParameter.getAlgorithm())){
            throw new XMLEncryptionException("KeyDerivation.UnsupportedAlgorithm", ckdfParameter.getAlgorithm(),
                    HKDFParams.class.getName());
        }

        ConcatKDF concatKDF = new ConcatKDF();
        return concatKDF.deriveKey(sharedSecret, ckdfParameter);
    }

    // The only Key Encapsulation Method algorithms this library registers (see JCEMapper /
    // security-config.xml). kemEncapsulate/kemDecapsulate are reachable with a KEM algorithm URI
    // taken directly from parsed XML (ghc:KeyEncapsulationMethod/@Algorithm), so this whitelist is
    // enforced explicitly rather than relying on javax.crypto.KEM#getInstance to reject anything
    // else JCEMapper might resolve the URI to.
    private static final Set<String> SUPPORTED_KEM_ALGORITHMS = Set.of(
            EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_512,
            EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_768,
            EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_1024);

    // Fully-qualified javax.crypto.KEM class names. This module targets Java 11
    // (see maven.compiler.release), but the KEM API (JEP 452) is only available since
    // Java 21, so it is accessed via reflection rather than a compile-time import - the
    // same reason the ML-DSA/ML-KEM JCA algorithm names are looked up dynamically rather
    // than depending on BouncyCastle at compile time.
    private static final String KEM_CLASS = "javax.crypto.KEM";
    private static final String KEM_ENCAPSULATOR_CLASS = "javax.crypto.KEM$Encapsulator";
    private static final String KEM_DECAPSULATOR_CLASS = "javax.crypto.KEM$Decapsulator";
    private static final String KEM_ENCAPSULATED_CLASS = "javax.crypto.KEM$Encapsulated";

    /**
     * The result of a KEM encapsulation: the encapsulation/ciphertext (traditionally called "C0")
     * to be sent to the recipient, and the AES key-wrap key derived from the KEM shared secret.
     */
    public static final class KemEncapsulation {
        private final byte[] encapsulation;
        private final SecretKey wrapKey;

        KemEncapsulation(byte[] encapsulation, SecretKey wrapKey) {
            this.encapsulation = encapsulation;
            this.wrapKey = wrapKey;
        }

        public byte[] getEncapsulation() {
            return encapsulation;
        }

        public SecretKey getWrapKey() {
            return wrapKey;
        }
    }

    /**
     * The result of a KEM decapsulation: the AES key-wrap key derived from the KEM shared secret,
     * and the remainder of the ciphertext (traditionally called "C1", the AES-wrapped CEK) once the
     * leading KEM encapsulation octets have been stripped off.
     */
    public static final class KemDecapsulation {
        private final SecretKey wrapKey;
        private final byte[] wrappedKey;

        KemDecapsulation(SecretKey wrapKey, byte[] wrappedKey) {
            this.wrapKey = wrapKey;
            this.wrappedKey = wrappedKey;
        }

        public SecretKey getWrapKey() {
            return wrapKey;
        }

        public byte[] getWrappedKey() {
            return wrappedKey;
        }
    }

    /**
     * Encapsulate a fresh shared secret to the recipient's KEM public key (e.g. ML-KEM, FIPS 203) and
     * derive an AES key-wrap key from it, per the W3C "XML Security: Generic Hybrid Cipher" note
     * (https://www.w3.org/TR/xmlsec-generic-hybrid/, section 5 "Using Key Encapsulation Algorithms for
     * Key Transport"). Uses the JDK's {@code javax.crypto.KEM} API via reflection - see {@link #KEM_CLASS}.
     *
     * @param recipientPublicKey the recipient's KEM public key
     * @param kemAlgorithmURI the KEM algorithm URI (e.g. {@code ALGO_ID_KEYTRANSPORT_MLKEM_512})
     * @param keyDerivationParameter the key derivation parameters used to derive the AES key-wrap key
     *                                from the KEM shared secret
     * @return the KEM encapsulation (C0) and the derived AES key-wrap key
     * @throws XMLEncryptionException if {@code kemAlgorithmURI} is not one of the registered ML-KEM
     *          algorithms, the KEM API is unavailable (requires Java 21+), the KEM algorithm is not
     *          supported by the configured JCE provider, or key derivation fails
     */
    public static KemEncapsulation kemEncapsulate(PublicKey recipientPublicKey, String kemAlgorithmURI,
                                                   KeyDerivationParameters keyDerivationParameter)
            throws XMLEncryptionException {
        validateKemAlgorithm(kemAlgorithmURI);
        try {
            String jceKemName = JCEMapper.translateURItoJCEID(kemAlgorithmURI);
            Object kem = kemGetInstance(jceKemName);
            Object encapsulator = invoke(kem, kem.getClass(), "newEncapsulator",
                    new Class<?>[]{PublicKey.class}, recipientPublicKey);
            Object encapsulated = invoke(encapsulator, Class.forName(KEM_ENCAPSULATOR_CLASS), "encapsulate",
                    new Class<?>[0]);
            Class<?> encapsulatedClass = Class.forName(KEM_ENCAPSULATED_CLASS);
            byte[] c0 = (byte[]) invoke(encapsulated, encapsulatedClass, "encapsulation", new Class<?>[0]);
            SecretKey sharedSecret = (SecretKey) invoke(encapsulated, encapsulatedClass, "key", new Class<?>[0]);
            byte[] kek = deriveKeyEncryptionKey(sharedSecret.getEncoded(), keyDerivationParameter);
            return new KemEncapsulation(c0, new SecretKeySpec(kek, "AES"));
        } catch (ReflectiveOperationException e) {
            throw new XMLEncryptionException(e);
        } catch (XMLSecurityException e) {
            throw new XMLEncryptionException(e);
        }
    }

    /**
     * Decapsulate a shared secret using the recipient's KEM private key and derive the AES key-wrap
     * key from it, splitting the leading KEM encapsulation octets (C0) off the combined ciphertext
     * first (its length is algorithm-specific and obtained from the KEM API itself, so no hardcoded
     * per-algorithm length table is required). See {@link #kemEncapsulate}.
     *
     * @param recipientPrivateKey the recipient's KEM private key
     * @param kemAlgorithmURI the KEM algorithm URI (e.g. {@code ALGO_ID_KEYTRANSPORT_MLKEM_512})
     * @param combinedCiphertext the concatenation of the KEM encapsulation (C0) and the AES-wrapped
     *                            CEK (C1), as read from {@code xenc:CipherValue}
     * @param keyDerivationParameter the key derivation parameters used to derive the AES key-wrap key
     *                                from the KEM shared secret
     * @return the derived AES key-wrap key, and the remaining AES-wrapped CEK bytes (C1)
     * @throws XMLEncryptionException if {@code kemAlgorithmURI} is not one of the registered ML-KEM
     *          algorithms (this method is reachable with an algorithm URI parsed directly from
     *          untrusted input XML, so it is validated explicitly rather than delegating entirely to
     *          the JCE provider), the KEM API is unavailable (requires Java 21+), the KEM algorithm is
     *          not supported by the configured JCE provider, the ciphertext is shorter than the
     *          algorithm's expected encapsulation size, or key derivation fails
     */
    public static KemDecapsulation kemDecapsulate(PrivateKey recipientPrivateKey, String kemAlgorithmURI,
                                                   byte[] combinedCiphertext, KeyDerivationParameters keyDerivationParameter)
            throws XMLEncryptionException {
        validateKemAlgorithm(kemAlgorithmURI);
        try {
            String jceKemName = JCEMapper.translateURItoJCEID(kemAlgorithmURI);
            Object kem = kemGetInstance(jceKemName);
            Object decapsulator = invoke(kem, kem.getClass(), "newDecapsulator",
                    new Class<?>[]{PrivateKey.class}, recipientPrivateKey);
            Class<?> decapsulatorClass = Class.forName(KEM_DECAPSULATOR_CLASS);
            int encapsulationSize = (int) invoke(decapsulator, decapsulatorClass, "encapsulationSize", new Class<?>[0]);
            if (combinedCiphertext.length < encapsulationSize) {
                throw new XMLEncryptionException("KeyDerivation.MissingParameters");
            }
            byte[] c0 = Arrays.copyOfRange(combinedCiphertext, 0, encapsulationSize);
            byte[] c1 = Arrays.copyOfRange(combinedCiphertext, encapsulationSize, combinedCiphertext.length);
            SecretKey sharedSecret = (SecretKey) invoke(decapsulator, decapsulatorClass, "decapsulate",
                    new Class<?>[]{byte[].class}, (Object) c0);
            byte[] kek = deriveKeyEncryptionKey(sharedSecret.getEncoded(), keyDerivationParameter);
            return new KemDecapsulation(new SecretKeySpec(kek, "AES"), c1);
        } catch (ReflectiveOperationException e) {
            throw new XMLEncryptionException(e);
        } catch (XMLSecurityException e) {
            throw new XMLEncryptionException(e);
        }
    }

    /**
     * Restricts a Key Encapsulation Method algorithm URI (e.g. parsed from
     * {@code ghc:KeyEncapsulationMethod/@Algorithm} of untrusted input XML) to the ML-KEM
     * algorithms this library actually registers, rather than accepting any URI JCEMapper
     * happens to resolve.
     *
     * @param kemAlgorithmURI the KEM algorithm URI to validate
     * @throws XMLEncryptionException if the URI is not one of the supported ML-KEM algorithms
     */
    private static void validateKemAlgorithm(String kemAlgorithmURI) throws XMLEncryptionException {
        if (!SUPPORTED_KEM_ALGORITHMS.contains(kemAlgorithmURI)) {
            throw new XMLEncryptionException("algorithms.NoSuchAlgorithm",
                    new Object[] { kemAlgorithmURI, "not a registered ML-KEM Key Encapsulation Method algorithm" });
        }
    }

    private static Object kemGetInstance(String jceKemName) throws ReflectiveOperationException {
        Class<?> kemClass = Class.forName(KEM_CLASS);
        Method getInstance = kemClass.getMethod("getInstance", String.class);
        return getInstance.invoke(null, jceKemName);
    }

    private static Object invoke(Object target, Class<?> declaringClass, String methodName, Class<?>[] paramTypes,
                                  Object... args) throws ReflectiveOperationException {
        Method method = declaringClass.getMethod(methodName, paramTypes);
        return method.invoke(target, args);
    }
}
