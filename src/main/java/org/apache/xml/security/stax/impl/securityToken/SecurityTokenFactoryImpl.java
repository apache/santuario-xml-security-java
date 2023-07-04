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
package org.apache.xml.security.stax.impl.securityToken;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;

import org.apache.xml.security.binding.xmldsig.DSAKeyValueType;
import org.apache.xml.security.binding.xmldsig.KeyInfoType;
import org.apache.xml.security.binding.xmldsig.KeyValueType;
import org.apache.xml.security.binding.xmldsig.RSAKeyValueType;
import org.apache.xml.security.binding.xmldsig.X509DataType;
import org.apache.xml.security.binding.xmldsig.X509IssuerSerialType;
import org.apache.xml.security.binding.xmldsig11.ECKeyValueType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.InboundSecurityContext;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants.TokenType;
import org.apache.xml.security.stax.securityToken.SecurityTokenFactory;
import org.apache.xml.security.utils.RFC2253Parser;
import org.apache.xml.security.utils.UnsyncByteArrayInputStream;

/**
 * Factory to create SecurityToken Objects from keys in XML
 *
 */
public class SecurityTokenFactoryImpl extends SecurityTokenFactory {

    public SecurityTokenFactoryImpl() {
    }

    @Override
    public InboundSecurityToken getSecurityToken(KeyInfoType keyInfoType,
                                          SecurityTokenConstants.KeyUsage keyUsage,
                                          XMLSecurityProperties securityProperties,
                                          InboundSecurityContext inboundSecurityContext) throws XMLSecurityException {
        if (keyInfoType != null) {
            // X509Data
            final X509DataType x509DataType =
                    XMLSecurityUtils.getQNameType(keyInfoType.getContent(), XMLSecurityConstants.TAG_dsig_X509Data);
            if (x509DataType != null) {
                return getSecurityToken(x509DataType, securityProperties, inboundSecurityContext, keyUsage);
            }

            // KeyValue
            final KeyValueType keyValueType
                    = XMLSecurityUtils.getQNameType(keyInfoType.getContent(), XMLSecurityConstants.TAG_dsig_KeyValue);
            if (keyValueType != null) {
                return getSecurityToken(keyValueType, securityProperties, inboundSecurityContext, keyUsage);
            }

            // KeyName
            final String keyName =
                    XMLSecurityUtils.getQNameType(keyInfoType.getContent(), XMLSecurityConstants.TAG_dsig_KeyName);
            if (keyName != null) {
                final KeyNameSecurityToken token = getSecurityToken(keyName, securityProperties, inboundSecurityContext, keyUsage);
                return token;
            }
        }

        // Use a default key if it exists
        if (SecurityTokenConstants.KeyUsage_Signature_Verification.equals(keyUsage)
                && securityProperties.getSignatureVerificationKey() != null) {
            return getDefaultSecurityToken(securityProperties, inboundSecurityContext, keyUsage);
        } else if (SecurityTokenConstants.KeyUsage_Decryption.equals(keyUsage)
                && securityProperties.getDecryptionKey() != null) {
            return getDefaultSecurityToken(securityProperties, inboundSecurityContext, keyUsage);
        }

        throw new XMLSecurityException("stax.noKey", new Object[] {keyUsage});
    }

    private InboundSecurityToken getDefaultSecurityToken(XMLSecurityProperties securityProperties, final InboundSecurityContext inboundSecurityContext, SecurityTokenConstants.KeyUsage keyUsage) {
        final AbstractInboundSecurityToken token =
                new AbstractInboundSecurityToken(inboundSecurityContext, IDGenerator.generateID(null),
                        SecurityTokenConstants.KeyIdentifier_NoKeyInfo, false) {
                    @Override
                    public TokenType getTokenType() {
                        return SecurityTokenConstants.DefaultToken;
                    }
                };
        setTokenKey(securityProperties, keyUsage, token);
        return token;
    }

    private KeyNameSecurityToken getSecurityToken(String keyName, XMLSecurityProperties securityProperties, InboundSecurityContext inboundSecurityContext,
            SecurityTokenConstants.KeyUsage keyUsage) throws XMLSecurityException {
        final KeyNameSecurityToken token =
                new KeyNameSecurityToken(keyName, inboundSecurityContext);

        // This if is here to preserve the current behaviour when the SignatureVerificationKey is set
        if (SecurityTokenConstants.KeyUsage_Signature_Verification.equals(keyUsage)
                && securityProperties.getSignatureVerificationKey() == null) {
            final Map<String, Key> keyNameMap = securityProperties.getKeyNameMap();
            final Key key = keyNameMap.get(keyName);
            if (key == null) {
                throw new XMLSecurityException("stax.keyNotFoundForName", new Object[] {keyName});
            }

            if (key instanceof PublicKey) {
                token.setPublicKey((PublicKey)key);
            } else {
                throw new XMLSecurityException("stax.keyTypeNotSupported", new Object[] {key.getClass().getSimpleName()});
            }
        }

        setTokenKey(securityProperties, keyUsage, token);
        return token;
    }

    private static InboundSecurityToken getSecurityToken(KeyValueType keyValueType,
            XMLSecurityProperties securityProperties,
            InboundSecurityContext inboundSecurityContext,
            SecurityTokenConstants.KeyUsage keyUsage)
            throws XMLSecurityException {

        final RSAKeyValueType rsaKeyValueType =
                XMLSecurityUtils.getQNameType(keyValueType.getContent(), XMLSecurityConstants.TAG_dsig_RSAKeyValue);
        if (rsaKeyValueType != null) {
            final RsaKeyValueSecurityToken token =
                new RsaKeyValueSecurityToken(rsaKeyValueType, inboundSecurityContext);
            setTokenKey(securityProperties, keyUsage, token);
            return token;
        }
        final DSAKeyValueType dsaKeyValueType =
                XMLSecurityUtils.getQNameType(keyValueType.getContent(), XMLSecurityConstants.TAG_dsig_DSAKeyValue);
        if (dsaKeyValueType != null) {
            final DsaKeyValueSecurityToken token =
                    new DsaKeyValueSecurityToken(dsaKeyValueType, inboundSecurityContext);
            setTokenKey(securityProperties, keyUsage, token);
            return token;
        }
        final ECKeyValueType ecKeyValueType =
                XMLSecurityUtils.getQNameType(keyValueType.getContent(), XMLSecurityConstants.TAG_dsig11_ECKeyValue);
        if (ecKeyValueType != null) {
            final ECKeyValueSecurityToken token =
                    new ECKeyValueSecurityToken(ecKeyValueType, inboundSecurityContext);
            setTokenKey(securityProperties, keyUsage, token);
            return token;
        }
        throw new XMLSecurityException("stax.unsupportedKeyValue");
    }

    private static InboundSecurityToken getSecurityToken(X509DataType x509DataType,
                                                  XMLSecurityProperties securityProperties,
                                                  InboundSecurityContext inboundSecurityContext,
                                                  SecurityTokenConstants.KeyUsage keyUsage)
            throws XMLSecurityException {
        // X509Certificate
        final byte[] certBytes =
                XMLSecurityUtils.getQNameType(
                        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName(),
                        XMLSecurityConstants.TAG_dsig_X509Certificate
                );
        if (certBytes != null) {
            final X509Certificate cert = getCertificateFromBytes(certBytes);
            TokenType tokenType = SecurityTokenConstants.X509V3Token;
            if (cert.getVersion() == 1) {
                tokenType = SecurityTokenConstants.X509V1Token;
            }
            final X509SecurityToken token =
                    new X509SecurityToken(tokenType, inboundSecurityContext,
                            IDGenerator.generateID(null), SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier, true);
            token.setX509Certificates(new X509Certificate[]{cert});

            setTokenKey(securityProperties, keyUsage, token);
            return token;
        }

        // Issuer Serial
        final X509IssuerSerialType issuerSerialType =
                XMLSecurityUtils.getQNameType(
                        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName(),
                        XMLSecurityConstants.TAG_dsig_X509IssuerSerial
                );
        if (issuerSerialType != null) {
            if (issuerSerialType.getX509IssuerName() == null
                    || issuerSerialType.getX509SerialNumber() == null
                    || SecurityTokenConstants.KeyUsage_Signature_Verification.equals(keyUsage)
                        && securityProperties.getSignatureVerificationKey() == null
                    || SecurityTokenConstants.KeyUsage_Decryption.equals(keyUsage)
                        && securityProperties.getDecryptionKey() == null) {
                throw new XMLSecurityException("stax.noKey", new Object[] {keyUsage});
            }
            final X509IssuerSerialSecurityToken token =
                    new X509IssuerSerialSecurityToken(
                            SecurityTokenConstants.X509V3Token, inboundSecurityContext, IDGenerator.generateID(null));
            token.setIssuerName(issuerSerialType.getX509IssuerName());
            token.setSerialNumber(issuerSerialType.getX509SerialNumber());

            setTokenKey(securityProperties, keyUsage, token);
            return token;
        }

        // Subject Key Identifier
        final byte[] skiBytes =
                XMLSecurityUtils.getQNameType(
                        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName(),
                        XMLSecurityConstants.TAG_dsig_X509SKI
                );
        if (skiBytes != null) {
            if (SecurityTokenConstants.KeyUsage_Signature_Verification.equals(keyUsage)
                && securityProperties.getSignatureVerificationKey() == null
                || SecurityTokenConstants.KeyUsage_Decryption.equals(keyUsage)
                && securityProperties.getDecryptionKey() == null) {
                throw new XMLSecurityException("stax.noKey", new Object[] {keyUsage});
            }
            final X509SKISecurityToken token =
                    new X509SKISecurityToken(
                            SecurityTokenConstants.X509V3Token, inboundSecurityContext, IDGenerator.generateID(null));
            token.setSkiBytes(skiBytes);

            setTokenKey(securityProperties, keyUsage, token);
            return token;
        }

        // Subject Name
        final String subjectName =
                XMLSecurityUtils.getQNameType(
                        x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName(),
                        XMLSecurityConstants.TAG_dsig_X509SubjectName
                );
        if (subjectName != null) {
            if (SecurityTokenConstants.KeyUsage_Signature_Verification.equals(keyUsage)
                && securityProperties.getSignatureVerificationKey() == null
                || SecurityTokenConstants.KeyUsage_Decryption.equals(keyUsage)
                && securityProperties.getDecryptionKey() == null) {
                throw new XMLSecurityException("stax.noKey", new Object[] {keyUsage});
            }
            final String normalizedSubjectName =
                    RFC2253Parser.normalize(subjectName);
            final X509SubjectNameSecurityToken token =
                    new X509SubjectNameSecurityToken(
                            SecurityTokenConstants.X509V3Token, inboundSecurityContext, IDGenerator.generateID(null));
            token.setSubjectName(normalizedSubjectName);

            setTokenKey(securityProperties, keyUsage, token);
            return token;
        }

        throw new XMLSecurityException("stax.noKey", new Object[] {keyUsage});
    }

    private static void setTokenKey(XMLSecurityProperties securityProperties, SecurityTokenConstants.KeyUsage keyUsage,
                                    AbstractInboundSecurityToken token) {
        Key key = null;
        if (SecurityTokenConstants.KeyUsage_Signature_Verification.equals(keyUsage)) {
            key = securityProperties.getSignatureVerificationKey();
        } else if (SecurityTokenConstants.KeyUsage_Decryption.equals(keyUsage)) {
            key = securityProperties.getDecryptionKey();
        }
        if (key instanceof PublicKey
            && !SecurityTokenConstants.KeyValueToken.equals(token.getTokenType())) {
            token.setPublicKey((PublicKey) key);
        } else {
            token.setSecretKey("", key);
        }
    }

    /**
     * Construct an X509Certificate'from the byte array.
     * <p></p>
     *
     * @param data The <code>byte</code> array containing the X509 data
     * @return An X509 certificate
     * @throws XMLSecurityException
     */
    private static X509Certificate getCertificateFromBytes(byte[] data)
            throws XMLSecurityException {
        try (InputStream in = new UnsyncByteArrayInputStream(data)) {
            final CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(in);
        } catch (CertificateException | IOException e) {
            throw new XMLSecurityException(e);
        }
    }
}
