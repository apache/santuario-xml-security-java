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
package org.apache.xml.security.test.stax.encryption;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.OutboundXMLSec;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.test.stax.utils.XMLSecEventAllocator;
import org.apache.xml.security.test.stax.utils.XmlReaderToWriter;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * StAX-path tests for ML-KEM key transport with AES-256-GCM content encryption, using the W3C
 * "XML Security: Generic Hybrid Cipher" key transport structure
 * (https://www.w3.org/TR/xmlsec-generic-hybrid/, see SANTUARIO-633) - the same structure exercised
 * by the DOM {@code XMLCipher} API in {@code XMLEncryptionMLKEMTest}.
 */
class StaxMLKEMEncryptionTest {

    private static boolean mlKemAvailable;
    private static boolean bcAddedForTheTest;
    private static final Map<String, KeyPair> keyPairs = new HashMap<>();
    private final XMLInputFactory xmlInputFactory;

    @BeforeAll
    static void setUp() {
        org.apache.xml.security.Init.init();
        if (Security.getProvider("BC") == null) {
            try {
                Class<?> cls = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                Provider bc = (Provider) cls.getConstructor().newInstance();
                Security.insertProviderAt(bc, 2);
                bcAddedForTheTest = true;
            } catch (ReflectiveOperationException e) {
                mlKemAvailable = false;
                return;
            }
        }
        try {
            for (String alg : new String[]{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, "BC");
                keyPairs.put(alg, kpg.generateKeyPair());
            }
            // javax.crypto.KEM (JEP 452) is only available since Java 21
            Class.forName("javax.crypto.KEM");
            mlKemAvailable = true;
        } catch (Exception | LinkageError e) {
            mlKemAvailable = false;
        }
    }

    @AfterAll
    static void cleanup() {
        if (bcAddedForTheTest) {
            Security.removeProvider("BC");
        }
    }

    public StaxMLKEMEncryptionTest() throws Exception {
        org.apache.xml.security.Init.init();
        xmlInputFactory = XMLInputFactory.newInstance();
        xmlInputFactory.setEventAllocator(new XMLSecEventAllocator());
    }

    @ParameterizedTest
    @CsvSource({
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_512  + ",ML-KEM-512",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_768  + ",ML-KEM-768",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_1024 + ",ML-KEM-1024"
    })
    void testMLKEMEncryptDecrypt(String keyEncapsulationUri, String jcaAlgorithm) throws Exception {
        Assumptions.assumeTrue(mlKemAvailable, "ML-KEM requires BouncyCastle 1.84+ and Java 21+ (javax.crypto.KEM)");

        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey cek = keygen.generateKey();
        properties.setEncryptionKey(cek);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2009/xmlenc11#aes256-gcm");

        KeyPair kp = keyPairs.get(jcaAlgorithm);
        properties.setEncryptionKeyTransportAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_GENERIC_HYBRID);
        properties.setEncryptionKeyEncapsulationAlgorithm(keyEncapsulationUri);
        properties.setEncryptionDataEncapsulationAlgorithm(EncryptionConstants.ALGO_ID_KEYWRAP_AES256);
        properties.setEncryptionTransportKey(kp.getPublic());

        SecurePart securePart = new SecurePart(
            new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        byte[] output = process("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml", properties);

        // Verify the produced XML carries the spec's element names, per
        // https://www.w3.org/TR/xmlsec-generic-hybrid/ section 6.1 "Key Transport Example"
        String serialized = new String(output, StandardCharsets.UTF_8);
        assertTrue(serialized.contains("GenericHybridCipherMethod"), "Missing GenericHybridCipherMethod element");
        assertTrue(serialized.contains("KeyEncapsulationMethod"), "Missing KeyEncapsulationMethod element");
        assertTrue(serialized.contains("DataEncapsulationMethod"), "Missing DataEncapsulationMethod element");
        assertTrue(serialized.contains("http://www.w3.org/2010/xmlsec-ghc#generic-hybrid"),
                "Missing Generic Hybrid Cipher EncryptionMethod algorithm");

        Document document;
        try (InputStream is = new ByteArrayInputStream(output)) {
            document = XMLUtils.read(is, false);
        }

        NodeList nodeList = document.getElementsByTagNameNS("urn:example:po", "PaymentInfo");
        assertEquals(0, nodeList.getLength());

        nodeList = document.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(0, nodeList.getLength());

        nodeList = document.getElementsByTagNameNS(
            XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
            XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
        );
        assertEquals(1, nodeList.getLength());

        Document decrypted = decryptUsingDOM(document, kp.getPrivate());

        nodeList = decrypted.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(1, nodeList.getLength());
    }

    @ParameterizedTest
    @CsvSource({
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_512  + ",ML-KEM-512",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_768  + ",ML-KEM-768",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_1024 + ",ML-KEM-1024"
    })
    void testMLKEMStaxEncryptStaxDecrypt(String keyEncapsulationUri, String jcaAlgorithm) throws Exception {
        Assumptions.assumeTrue(mlKemAvailable, "ML-KEM requires BouncyCastle 1.84+ and Java 21+ (javax.crypto.KEM)");

        XMLSecurityProperties encryptProperties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        encryptProperties.setActions(actions);

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey cek = keygen.generateKey();
        encryptProperties.setEncryptionKey(cek);
        encryptProperties.setEncryptionSymAlgorithm("http://www.w3.org/2009/xmlenc11#aes256-gcm");

        KeyPair kp = keyPairs.get(jcaAlgorithm);
        encryptProperties.setEncryptionKeyTransportAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_GENERIC_HYBRID);
        encryptProperties.setEncryptionKeyEncapsulationAlgorithm(keyEncapsulationUri);
        encryptProperties.setEncryptionDataEncapsulationAlgorithm(EncryptionConstants.ALGO_ID_KEYWRAP_AES256);
        encryptProperties.setEncryptionTransportKey(kp.getPublic());

        SecurePart securePart = new SecurePart(
            new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        encryptProperties.addEncryptionPart(securePart);

        byte[] encrypted = process("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml", encryptProperties);

        XMLSecurityProperties decryptProperties = new XMLSecurityProperties();
        decryptProperties.setDecryptionKey(kp.getPrivate());
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(decryptProperties);
        XMLStreamReader xmlStreamReader =
            xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(encrypted));
        XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(xmlStreamReader, null, null);

        Document decrypted = StAX2DOM.readDoc(securityStreamReader);

        NodeList nodeList = decrypted.getElementsByTagNameNS("urn:example:po", "CreditCard");
        assertEquals(1, nodeList.getLength());
    }

    private byte[] process(String inputXmlFile, XMLSecurityProperties properties) throws Exception {
        OutboundXMLSec outboundXMLSec = XMLSec.getOutboundXMLSec(properties);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLStreamWriter xmlStreamWriter = outboundXMLSec.processOutMessage(baos, StandardCharsets.UTF_8.name());
        try (InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream(inputXmlFile)) {
            XMLStreamReader xmlStreamReader = null;
            try {
                xmlStreamReader = xmlInputFactory.createXMLStreamReader(sourceDocument);
                XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
                return baos.toByteArray();
            } finally {
                if (xmlStreamReader != null) {
                    xmlStreamReader.close();
                }
            }
        } finally {
            xmlStreamWriter.close();
        }
    }

    private Document decryptUsingDOM(Document document, Key privateKey) throws Exception {
        NodeList nodeList = document.getElementsByTagNameNS(
            XMLSecurityConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
            XMLSecurityConstants.TAG_xenc_EncryptedData.getLocalPart()
        );
        Element ee = (Element) nodeList.item(0);

        XMLCipher cipher = XMLCipher.getInstance();
        cipher.init(XMLCipher.DECRYPT_MODE, null);
        EncryptedData encryptedData = cipher.loadEncryptedData(document, ee);

        XMLCipher kwCipher = XMLCipher.getInstance();
        kwCipher.init(XMLCipher.UNWRAP_MODE, privateKey);
        KeyInfo ki = encryptedData.getKeyInfo();
        EncryptedKey encryptedKey = ki.itemEncryptedKey(0);
        Key symmetricKey = kwCipher.decryptKey(
            encryptedKey, encryptedData.getEncryptionMethod().getAlgorithm()
        );

        cipher.init(XMLCipher.DECRYPT_MODE, symmetricKey);
        return cipher.doFinal(document, ee);
    }

    @ParameterizedTest
    @CsvSource({
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_512  + ",ML-KEM-512",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_768  + ",ML-KEM-768",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_1024 + ",ML-KEM-1024"
    })
    void testMLKEMStaxWrongRecipientPrivateKeyFailsCleanly(String keyEncapsulationUri, String jcaAlgorithm)
            throws Exception {
        Assumptions.assumeTrue(mlKemAvailable, "ML-KEM requires BouncyCastle 1.84+ and Java 21+ (javax.crypto.KEM)");

        KeyPair kp = keyPairs.get(jcaAlgorithm);
        Document document = encryptToRecipient(kp.getPublic(), keyEncapsulationUri);

        // A second, independent recipient - not the one the message was encrypted to.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(jcaAlgorithm, "BC");
        PrivateKey wrongPrivateKey = kpg.generateKeyPair().getPrivate();

        // See the equivalent DOM-path test (XMLEncryptionMLKEMTest) for why this must throw
        // rather than return a Key built from the wrong shared secret.
        assertThrows(XMLEncryptionException.class, () -> decryptUsingDOM(document, wrongPrivateKey));
    }

    @ParameterizedTest
    @CsvSource({
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_512  + ",ML-KEM-512",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_768  + ",ML-KEM-768",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_1024 + ",ML-KEM-1024"
    })
    void testMLKEMStaxTruncatedEncapsulationRejected(String keyEncapsulationUri, String jcaAlgorithm)
            throws Exception {
        Assumptions.assumeTrue(mlKemAvailable, "ML-KEM requires BouncyCastle 1.84+ and Java 21+ (javax.crypto.KEM)");

        KeyPair kp = keyPairs.get(jcaAlgorithm);
        Document document = encryptToRecipient(kp.getPublic(), keyEncapsulationUri);

        // Truncate the EncryptedKey's CipherValue to well under half its length - shorter than
        // any ML-KEM variant's encapsulationSize() - before it is parsed into an EncryptedKey
        // object, mirroring XMLEncryptionMLKEMTest#testMLKEMTruncatedEncapsulationRejected.
        NodeList encryptedKeyNodes = document.getElementsByTagNameNS(
            XMLSecurityConstants.TAG_xenc_EncryptedKey.getNamespaceURI(),
            XMLSecurityConstants.TAG_xenc_EncryptedKey.getLocalPart());
        Element encryptedKeyElem = (Element) encryptedKeyNodes.item(0);
        Element cipherValueElem = (Element) encryptedKeyElem.getElementsByTagNameNS(
            XMLSecurityConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), "CipherValue").item(0);
        byte[] combined = Base64.getMimeDecoder().decode(cipherValueElem.getTextContent());
        byte[] truncated = Arrays.copyOf(combined, combined.length / 2);

        NodeList children = cipherValueElem.getChildNodes();
        for (int i = children.getLength() - 1; i >= 0; i--) {
            cipherValueElem.removeChild(children.item(i));
        }
        Text newText = document.createTextNode(Base64.getEncoder().encodeToString(truncated));
        cipherValueElem.appendChild(newText);

        assertThrows(XMLEncryptionException.class, () -> decryptUsingDOM(document, kp.getPrivate()));
    }

    /**
     * Wrong-recipient rejection driven through the real StAX inbound path
     * ({@link InboundXMLSec#processInMessage}), not the DOM {@code XMLCipher} helper used by
     * {@link #testMLKEMStaxWrongRecipientPrivateKeyFailsCleanly}. This exercises
     * {@code XMLEncryptedKeyInputHandler}'s Generic Hybrid Cipher branch, which is otherwise only
     * covered on the happy path. ML-KEM's implicit rejection means decapsulation with the wrong
     * private key does not fail; the handler derives a wrong key-wrap key and substitutes a random
     * CEK (timing mitigation), so rejection surfaces late at the AES-256-GCM tag check and reaches
     * the caller as an {@link XMLStreamException}. The property under test is that the inbound path
     * rejects the message rather than yielding plaintext.
     */
    @ParameterizedTest
    @CsvSource({
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_512  + ",ML-KEM-512",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_768  + ",ML-KEM-768",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_1024 + ",ML-KEM-1024"
    })
    void testMLKEMStaxInboundWrongRecipientKeyRejected(String keyEncapsulationUri, String jcaAlgorithm)
            throws Exception {
        Assumptions.assumeTrue(mlKemAvailable, "ML-KEM requires BouncyCastle 1.84+ and Java 21+ (javax.crypto.KEM)");

        KeyPair kp = keyPairs.get(jcaAlgorithm);
        Document document = encryptToRecipient(kp.getPublic(), keyEncapsulationUri);

        // A second, independent recipient - not the one the message was encrypted to.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(jcaAlgorithm, "BC");
        PrivateKey wrongPrivateKey = kpg.generateKeyPair().getPrivate();

        assertThrows(XMLStreamException.class, () -> decryptUsingStax(document, wrongPrivateKey));
    }

    /**
     * Truncated-encapsulation rejection driven through the StAX inbound path, the streaming
     * counterpart of {@link #testMLKEMStaxTruncatedEncapsulationRejected} (which uses the DOM
     * helper). A {@code CipherValue} shorter than any ML-KEM variant's {@code encapsulationSize()}
     * fails the length check in {@code KeyUtils#kemDecapsulate}; the inbound handler catches that
     * and substitutes a random CEK, so here too rejection surfaces at the GCM tag check as an
     * {@link XMLStreamException}. The message must be rejected, not decrypted.
     */
    @ParameterizedTest
    @CsvSource({
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_512  + ",ML-KEM-512",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_768  + ",ML-KEM-768",
        EncryptionConstants.ALGO_ID_KEYTRANSPORT_MLKEM_1024 + ",ML-KEM-1024"
    })
    void testMLKEMStaxInboundTruncatedEncapsulationRejected(String keyEncapsulationUri, String jcaAlgorithm)
            throws Exception {
        Assumptions.assumeTrue(mlKemAvailable, "ML-KEM requires BouncyCastle 1.84+ and Java 21+ (javax.crypto.KEM)");

        KeyPair kp = keyPairs.get(jcaAlgorithm);
        Document document = encryptToRecipient(kp.getPublic(), keyEncapsulationUri);

        Element encryptedKeyElem = (Element) document.getElementsByTagNameNS(
            XMLSecurityConstants.TAG_xenc_EncryptedKey.getNamespaceURI(),
            XMLSecurityConstants.TAG_xenc_EncryptedKey.getLocalPart()).item(0);
        Element cipherValueElem = (Element) encryptedKeyElem.getElementsByTagNameNS(
            XMLSecurityConstants.TAG_xenc_EncryptedKey.getNamespaceURI(), "CipherValue").item(0);
        byte[] combined = Base64.getMimeDecoder().decode(cipherValueElem.getTextContent());
        byte[] truncated = Arrays.copyOf(combined, combined.length / 2);
        NodeList children = cipherValueElem.getChildNodes();
        for (int i = children.getLength() - 1; i >= 0; i--) {
            cipherValueElem.removeChild(children.item(i));
        }
        cipherValueElem.appendChild(document.createTextNode(Base64.getEncoder().encodeToString(truncated)));

        assertThrows(XMLStreamException.class, () -> decryptUsingStax(document, kp.getPrivate()));
    }

    /**
     * Decrypts a document through the real StAX inbound path ({@link InboundXMLSec#processInMessage}
     * + {@link StAX2DOM#readDoc}), the counterpart of {@link #decryptUsingDOM} for the tests that
     * need to exercise the inbound {@code XMLEncryptedKeyInputHandler} rather than the DOM cipher.
     */
    private Document decryptUsingStax(Document document, PrivateKey key) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        javax.xml.transform.TransformerFactory.newInstance().newTransformer().transform(
            new javax.xml.transform.dom.DOMSource(document),
            new javax.xml.transform.stream.StreamResult(bos));

        XMLSecurityProperties decryptProperties = new XMLSecurityProperties();
        decryptProperties.setDecryptionKey(key);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(decryptProperties);
        XMLStreamReader xmlStreamReader =
            xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(bos.toByteArray()));
        XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(xmlStreamReader, null, null);
        return StAX2DOM.readDoc(securityStreamReader);
    }

    /**
     * Runs the encrypt half of the round trip for the given key encapsulation algorithm (same
     * properties as {@link #testMLKEMEncryptDecrypt}) and returns the parsed resulting document,
     * for tests that want to corrupt or otherwise interfere with the decrypt half.
     */
    private Document encryptToRecipient(java.security.PublicKey pubKey, String keyEncapsulationUri)
            throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.ENCRYPTION);
        properties.setActions(actions);

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey cek = keygen.generateKey();
        properties.setEncryptionKey(cek);
        properties.setEncryptionSymAlgorithm("http://www.w3.org/2009/xmlenc11#aes256-gcm");

        properties.setEncryptionKeyTransportAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_GENERIC_HYBRID);
        properties.setEncryptionKeyEncapsulationAlgorithm(keyEncapsulationUri);
        properties.setEncryptionDataEncapsulationAlgorithm(EncryptionConstants.ALGO_ID_KEYWRAP_AES256);
        properties.setEncryptionTransportKey(pubKey);

        SecurePart securePart = new SecurePart(
            new QName("urn:example:po", "PaymentInfo"), SecurePart.Modifier.Element);
        properties.addEncryptionPart(securePart);

        byte[] output = process("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml", properties);

        try (InputStream is = new ByteArrayInputStream(output)) {
            return XMLUtils.read(is, false);
        }
    }
}
