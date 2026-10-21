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
package org.apache.xml.security.stax.impl.processor.output;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.encryption.params.HKDFParams;
import org.apache.xml.security.encryption.params.KeyDerivationParameters;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.EncryptionPartDef;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.KeyUtils;
import org.apache.xml.security.utils.XMLUtils;

/**
 * Processor to encrypt XML structures
 *
 */
public class XMLEncryptOutputProcessor extends AbstractEncryptOutputProcessor {

    private static final transient Logger LOG = System.getLogger(XMLEncryptOutputProcessor.class.getName());

    public XMLEncryptOutputProcessor() throws XMLSecurityException {
        super();
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
            XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();

            //avoid double encryption when child elements matches too
            if (getActiveInternalEncryptionOutputProcessor() == null) {
                SecurePart securePart = securePartMatches(xmlSecStartElement, outputProcessorChain, XMLSecurityConstants.ENCRYPTION_PARTS);
                if (securePart != null) {
                    LOG.log(Level.DEBUG, "Matched encryptionPart for encryption");
                    String tokenId = outputProcessorChain.getSecurityContext().get(
                            XMLSecurityConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION);
                    SecurityTokenProvider<OutboundSecurityToken> securityTokenProvider =
                            outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
                    final OutboundSecurityToken securityToken = securityTokenProvider.getSecurityToken();

                    EncryptionPartDef encryptionPartDef = new EncryptionPartDef();
                    encryptionPartDef.setSecurePart(securePart);
                    encryptionPartDef.setModifier(securePart.getModifier());
                    encryptionPartDef.setEncRefId(IDGenerator.generateID(null));
                    encryptionPartDef.setKeyId(securityTokenProvider.getId());
                    encryptionPartDef.setSymmetricKey(securityToken.getSecretKey(getSecurityProperties().getEncryptionSymAlgorithm()));
                    outputProcessorChain.getSecurityContext().putAsList(EncryptionPartDef.class, encryptionPartDef);

                    AbstractInternalEncryptionOutputProcessor internalEncryptionOutputProcessor =
                            createInternalEncryptionOutputProcessor(
                                    encryptionPartDef, xmlSecStartElement,
                                    outputProcessorChain.getDocumentContext().getEncoding(),
                                    (OutboundSecurityToken)securityToken.getKeyWrappingToken()
                            );
                    internalEncryptionOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                    internalEncryptionOutputProcessor.setAction(getAction(), getActionOrder());
                    internalEncryptionOutputProcessor.init(outputProcessorChain);

                    setActiveInternalEncryptionOutputProcessor(internalEncryptionOutputProcessor);
                }
            }
        }

        outputProcessorChain.processEvent(xmlSecEvent);
    }

    /**
     * Override this method to return a different AbstractInternalEncryptionOutputProcessor instance
     * which will write out the KeyInfo contents in the EncryptedData.
     */
    protected AbstractInternalEncryptionOutputProcessor createInternalEncryptionOutputProcessor(
            EncryptionPartDef encryptionPartDef,
            XMLSecStartElement startElement,
            String encoding,
            final OutboundSecurityToken keyWrappingToken
    ) throws XMLStreamException, XMLSecurityException {

        final AbstractInternalEncryptionOutputProcessor processor =
                new AbstractInternalEncryptionOutputProcessor(encryptionPartDef,
                        startElement,
                        encoding) {

                    @Override
                    protected void createKeyInfoStructure(OutputProcessorChain outputProcessorChain)
                            throws XMLStreamException, XMLSecurityException {
                        if (keyWrappingToken == null) {
                            // Do not write out a KeyInfo element
                            return;
                        }

                        final String encryptionKeyTransportAlgorithm = getSecurityProperties().getEncryptionKeyTransportAlgorithm();

                        PublicKey pubKey = keyWrappingToken.getPublicKey();
                        Key secretKey = keyWrappingToken.getSecretKey(encryptionKeyTransportAlgorithm);
                        if (pubKey == null && secretKey == null) {
                            // Do not write out a KeyInfo element
                            return;
                        }

                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_KeyInfo, true, null);

                        List<XMLSecAttribute> attributes = new ArrayList<>(1);
                        String keyId = IDGenerator.generateID("EK");
                        attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_Id, keyId));
                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_EncryptedKey, true, attributes);

                        if (EncryptionConstants.ALGO_ID_KEYTRANSPORT_GENERIC_HYBRID.equals(encryptionKeyTransportAlgorithm)) {
                            if (pubKey == null) {
                                throw new XMLSecurityException("stax.unsupportedKeyTransp");
                            }
                            createGenericHybridCipherKeyInfoStructure(outputProcessorChain, pubKey);
                        } else {
                            createFlatKeyTransportKeyInfoStructure(
                                    outputProcessorChain, encryptionKeyTransportAlgorithm, pubKey, secretKey);
                        }

                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_EncryptedKey);

                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_KeyInfo);
                    }

                    /**
                     * Writes the EncryptionMethod/KeyInfo/CipherData for a flat (RSA-OAEP-style) key
                     * transport algorithm, unchanged from before Generic Hybrid Cipher support was added.
                     */
                    private void createFlatKeyTransportKeyInfoStructure(
                            OutputProcessorChain outputProcessorChain, String encryptionKeyTransportAlgorithm,
                            PublicKey pubKey, Key secretKey) throws XMLStreamException, XMLSecurityException {

                        List<XMLSecAttribute> attributes = new ArrayList<>(1);
                        attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_Algorithm, encryptionKeyTransportAlgorithm));
                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_EncryptionMethod, false, attributes);

                        final String encryptionKeyTransportDigestAlgorithm = getSecurityProperties().getEncryptionKeyTransportDigestAlgorithm();
                        // Check for rsa-oaep-mgf1p then MGF1 is set by default and encryptionKeyTransportMGFAlgorithm must not be set!
                        final String encryptionKeyTransportMGFAlgorithm = XMLSecurityConstants.NS_XENC_RSAOAEPMGF1P.equals(encryptionKeyTransportAlgorithm)?
                                null : getSecurityProperties().getEncryptionKeyTransportMGFAlgorithm();

                        if (XMLSecurityConstants.NS_XENC11_RSAOAEP.equals(encryptionKeyTransportAlgorithm) ||
                                XMLSecurityConstants.NS_XENC_RSAOAEPMGF1P.equals(encryptionKeyTransportAlgorithm)) {

                            byte[] oaepParams = getSecurityProperties().getEncryptionKeyTransportOAEPParams();
                            if (oaepParams != null) {
                                createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_OAEPparams, false, null);
                                createCharactersAndOutputAsEvent(outputProcessorChain, XMLUtils.encodeToString(oaepParams));
                                createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_OAEPparams);
                            }

                            if (encryptionKeyTransportDigestAlgorithm != null) {
                                attributes = new ArrayList<>(1);
                                attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_Algorithm, encryptionKeyTransportDigestAlgorithm));
                                createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_DigestMethod, true, attributes);
                                createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_DigestMethod);
                            }

                            if (encryptionKeyTransportMGFAlgorithm != null) {
                                attributes = new ArrayList<>(1);
                                attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_Algorithm, encryptionKeyTransportMGFAlgorithm));
                                createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc11_MGF, true, attributes);
                                createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc11_MGF);
                            }
                        }

                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_EncryptionMethod);

                        createKeyInfoStructureForEncryptedKey(outputProcessorChain, keyWrappingToken);

                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_CipherData, false, null);
                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_CipherValue, false, null);

                        //encrypt the symmetric session key with the public key from the receiver:
                        String jceid = JCEMapper.translateURItoJCEID(encryptionKeyTransportAlgorithm);
                        if (jceid == null) {
                            throw new XMLSecurityException("algorithms.NoSuchMap",
                                                           new Object[] {encryptionKeyTransportAlgorithm});
                        }

                        try {
                            Cipher cipher = Cipher.getInstance(jceid);

                            AlgorithmParameterSpec algorithmParameterSpec = null;
                            if (XMLSecurityConstants.NS_XENC11_RSAOAEP.equals(encryptionKeyTransportAlgorithm) ||
                                    XMLSecurityConstants.NS_XENC_RSAOAEPMGF1P.equals(encryptionKeyTransportAlgorithm)) {

                                String jceDigestAlgorithm = "SHA-1";
                                if (encryptionKeyTransportDigestAlgorithm != null) {
                                    jceDigestAlgorithm = JCEMapper.translateURItoJCEID(encryptionKeyTransportDigestAlgorithm);
                                }

                                PSource.PSpecified pSource = PSource.PSpecified.DEFAULT;
                                byte[] oaepParams = getSecurityProperties().getEncryptionKeyTransportOAEPParams();
                                if (oaepParams != null) {
                                    pSource = new PSource.PSpecified(oaepParams);
                                }

                                MGF1ParameterSpec mgfParameterSpec = new MGF1ParameterSpec("SHA-1");
                                // Check for RSA-OAEP then MGF1 is set by default and value must not be set!
                                if (encryptionKeyTransportMGFAlgorithm != null
                                    && !XMLSecurityConstants.NS_XENC_RSAOAEPMGF1P.equals(encryptionKeyTransportAlgorithm)) {
                                    String jceMGFAlgorithm = JCEMapper.translateURItoJCEID(encryptionKeyTransportMGFAlgorithm);
                                    mgfParameterSpec = new MGF1ParameterSpec(jceMGFAlgorithm);
                                }
                                algorithmParameterSpec = new OAEPParameterSpec(jceDigestAlgorithm, "MGF1", mgfParameterSpec, pSource);
                            }

                            if (pubKey != null) {
                                cipher.init(Cipher.WRAP_MODE, pubKey, algorithmParameterSpec);
                            } else {
                                cipher.init(Cipher.WRAP_MODE, secretKey, algorithmParameterSpec);
                            }

                            String tokenId = outputProcessorChain.getSecurityContext().get(
                                    XMLSecurityConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION);
                            SecurityTokenProvider<OutboundSecurityToken> securityTokenProvider =
                                    outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);

                            final OutboundSecurityToken securityToken = securityTokenProvider.getSecurityToken();
                            Key sessionKey =
                                    securityToken.getSecretKey(getSecurityProperties().getEncryptionSymAlgorithm());
                            if (pubKey != null) {
                                int blockSize = cipher.getBlockSize();
                                if (blockSize > 0 && blockSize < sessionKey.getEncoded().length) {
                                    throw new XMLSecurityException(
                                            "stax.unsupportedKeyTransp"
                                    );
                                }
                            }
                            byte[] encryptedEphemeralKey = cipher.wrap(sessionKey);

                            createCharactersAndOutputAsEvent(outputProcessorChain, XMLUtils.encodeToString(encryptedEphemeralKey));

                        } catch (NoSuchPaddingException e) {
                            throw new XMLSecurityException(e);
                        } catch (NoSuchAlgorithmException e) {
                            throw new XMLSecurityException(e);
                        } catch (InvalidKeyException e) {
                            throw new XMLSecurityException(e);
                        } catch (IllegalBlockSizeException e) {
                            throw new XMLSecurityException(e);
                        } catch (InvalidAlgorithmParameterException e) {
                            throw new XMLSecurityException(e);
                        }

                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_CipherValue);
                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_CipherData);
                    }

                    /**
                     * Writes the EncryptionMethod/KeyInfo/CipherData for KEM-based (Generic Hybrid Cipher)
                     * key transport, per https://www.w3.org/TR/xmlsec-generic-hybrid/ section 6.1
                     * "Key Transport Example" (see SANTUARIO-633).
                     */
                    private void createGenericHybridCipherKeyInfoStructure(
                            OutputProcessorChain outputProcessorChain, PublicKey pubKey)
                            throws XMLStreamException, XMLSecurityException {

                        String kemAlgorithm = getSecurityProperties().getEncryptionKeyEncapsulationAlgorithm();
                        String dataEncapsulationAlgorithm = getSecurityProperties().getEncryptionDataEncapsulationAlgorithm();
                        if (kemAlgorithm == null || dataEncapsulationAlgorithm == null) {
                            throw new XMLSecurityException("stax.unsupportedKeyTransp");
                        }
                        String hmacAlgorithm = getSecurityProperties().getEncryptionKeyEncapsulationHmacAlgorithm();
                        if (hmacAlgorithm == null) {
                            hmacAlgorithm = XMLSecurityConstants.NS_XMLDSIG_HMACSHA256;
                        }

                        int wrapKeyBitLength = KeyUtils.getAESKeyBitSizeForWrapAlgorithm(dataEncapsulationAlgorithm);
                        KeyDerivationParameters kdfParams = HKDFParams.createBuilder(wrapKeyBitLength, hmacAlgorithm).build();

                        // EncryptionMethod/ghc:GenericHybridCipherMethod/ghc:KeyEncapsulationMethod/...
                        List<XMLSecAttribute> attributes = new ArrayList<>(1);
                        attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_Algorithm,
                                EncryptionConstants.ALGO_ID_KEYTRANSPORT_GENERIC_HYBRID));
                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_EncryptionMethod, false, attributes);

                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_ghc_GenericHybridCipherMethod, true, null);

                        attributes = new ArrayList<>(1);
                        attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_Algorithm, kemAlgorithm));
                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_ghc_KeyEncapsulationMethod, true, attributes);

                        attributes = new ArrayList<>(1);
                        attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_Algorithm, XMLSecurityConstants.NS_HKDF));
                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc11_KeyDerivationMethod, true, attributes);

                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_hkdf_HKDFParams, true, null);

                        attributes = new ArrayList<>(1);
                        attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_Algorithm, hmacAlgorithm));
                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_hkdf_PRF, true, attributes);
                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_hkdf_PRF);

                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_hkdf_KeyLength, false, null);
                        createCharactersAndOutputAsEvent(outputProcessorChain, String.valueOf(wrapKeyBitLength / 8));
                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_hkdf_KeyLength);

                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_hkdf_HKDFParams);

                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc11_KeyDerivationMethod);

                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_ghc_KeyLen, false, null);
                        createCharactersAndOutputAsEvent(outputProcessorChain, String.valueOf(wrapKeyBitLength / 8));
                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_ghc_KeyLen);

                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_ghc_KeyEncapsulationMethod);

                        attributes = new ArrayList<>(1);
                        attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_Algorithm, dataEncapsulationAlgorithm));
                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_ghc_DataEncapsulationMethod, true, attributes);
                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_ghc_DataEncapsulationMethod);

                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_ghc_GenericHybridCipherMethod);

                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_EncryptionMethod);

                        createKeyInfoStructureForEncryptedKey(outputProcessorChain, keyWrappingToken);

                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_CipherData, false, null);
                        createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_CipherValue, false, null);

                        String tokenId = outputProcessorChain.getSecurityContext().get(
                                XMLSecurityConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION);
                        SecurityTokenProvider<OutboundSecurityToken> securityTokenProvider =
                                outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
                        final OutboundSecurityToken securityToken = securityTokenProvider.getSecurityToken();
                        Key sessionKey = securityToken.getSecretKey(getSecurityProperties().getEncryptionSymAlgorithm());

                        // Encapsulate a shared secret to the recipient's KEM public key, derive the
                        // AES key-wrap key from it, and wrap the CEK with that key. CipherValue holds
                        // the concatenation of the KEM encapsulation (C0) and the wrapped CEK (C1).
                        KeyUtils.KemEncapsulation kemResult = KeyUtils.kemEncapsulate(pubKey, kemAlgorithm, kdfParams);
                        try {
                            String jceWrapId = JCEMapper.translateURItoJCEID(dataEncapsulationAlgorithm);
                            Cipher wrapCipher = Cipher.getInstance(jceWrapId);
                            wrapCipher.init(Cipher.WRAP_MODE, kemResult.getWrapKey());
                            byte[] wrappedKey = wrapCipher.wrap(sessionKey);

                            byte[] encapsulation = kemResult.getEncapsulation();
                            byte[] combined = new byte[encapsulation.length + wrappedKey.length];
                            System.arraycopy(encapsulation, 0, combined, 0, encapsulation.length);
                            System.arraycopy(wrappedKey, 0, combined, encapsulation.length, wrappedKey.length);

                            createCharactersAndOutputAsEvent(outputProcessorChain, XMLUtils.encodeToString(combined));
                        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException
                                | IllegalBlockSizeException e) {
                            throw new XMLSecurityException(e);
                        }

                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_CipherValue);
                        createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_CipherData);
                    }

                    protected void createKeyInfoStructureForEncryptedKey(
                        OutputProcessorChain outputProcessorChain,
                        OutboundSecurityToken securityToken
                    ) throws XMLStreamException, XMLSecurityException {
                        SecurityTokenConstants.KeyIdentifier keyIdentifier =
                            getSecurityProperties().getEncryptionKeyIdentifier();

                        X509Certificate[] x509Certificates = securityToken.getX509Certificates();
                        if (x509Certificates == null) {
                            if (securityToken.getPublicKey() != null
                                && SecurityTokenConstants.KeyIdentifier_KeyValue.equals(keyIdentifier)) {
                                createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_KeyInfo, true, null);

                                XMLSecurityUtils.createKeyValueTokenStructure(this, outputProcessorChain,
                                                                              securityToken.getPublicKey());
                                createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_KeyInfo);
                            }
                            return;
                        }

                        if (!SecurityTokenConstants.KeyIdentifier_NoKeyInfo.equals(keyIdentifier)) {
                            createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_KeyInfo, true, null);

                            if (keyIdentifier == null || SecurityTokenConstants.KeyIdentifier_IssuerSerial.equals(keyIdentifier)) {
                                XMLSecurityUtils.createX509IssuerSerialStructure(this, outputProcessorChain, x509Certificates);
                            } else if (SecurityTokenConstants.KeyIdentifier_KeyValue.equals(keyIdentifier)) {
                                XMLSecurityUtils.createKeyValueTokenStructure(this, outputProcessorChain, x509Certificates);
                            } else if (SecurityTokenConstants.KeyIdentifier_SkiKeyIdentifier.equals(keyIdentifier)) {
                                XMLSecurityUtils.createX509SubjectKeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
                            } else if (SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier.equals(keyIdentifier)) {
                                XMLSecurityUtils.createX509CertificateStructure(this, outputProcessorChain, x509Certificates);
                            } else if (SecurityTokenConstants.KeyIdentifier_X509SubjectName.equals(keyIdentifier)) {
                                XMLSecurityUtils.createX509SubjectNameStructure(this, outputProcessorChain, x509Certificates);
                            } else if (SecurityTokenConstants.KeyIdentifier_KeyName.equals(keyIdentifier)) {
                                String keyName = getSecurityProperties().getEncryptionKeyName();
                                XMLSecurityUtils.createKeyNameTokenStructure(this, outputProcessorChain, keyName);
                            } else {
                                throw new XMLSecurityException("stax.unsupportedToken",
                                                               new Object[] {keyIdentifier});
                            }

                            createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_KeyInfo);
                        }
                    }
                };
        processor.getAfterProcessors().add(XMLEncryptOutputProcessor.class);
        return processor;
    }
}
