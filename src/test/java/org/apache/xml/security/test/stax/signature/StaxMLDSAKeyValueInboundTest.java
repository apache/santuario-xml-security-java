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
package org.apache.xml.security.test.stax.signature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.securityEvent.KeyValueTokenSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.test.stax.utils.XMLSecEventAllocator;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

/**
 * StAX inbound verification of ML-DSA signatures whose KeyInfo carries the public key as a
 * {@code dsig11:DEREncodedKeyValue} (the KeyValue form emitted for key types without a
 * structured KeyValue element). No verification key is supplied out of band: the inbound
 * processor must resolve the key from the document itself, then verify with it.
 */
class StaxMLDSAKeyValueInboundTest extends AbstractSignatureCreationTest {

    private static final Map<String, KeyPair> keyPairs = new HashMap<>();

    @BeforeAll
    static void generateKeys() throws Exception {
        if (!isBcInstalled()) {
            return;
        }
        try {
            for (String alg : new String[]{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, "BC");
                keyPairs.put(alg, kpg.generateKeyPair());
            }
        } catch (Exception e) {
            // ML-DSA not available with this BC version
        }
    }

    @ParameterizedTest
    @CsvSource({
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-44,ML-DSA-44",
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-65,ML-DSA-65",
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-87,ML-DSA-87"
    })
    void testInboundVerifiesWithKeyFromDerEncodedKeyValue(String sigAlgorithm, String jcaAlgorithm) throws Exception {
        Assumptions.assumeTrue(isBcInstalled() && keyPairs.containsKey(jcaAlgorithm),
            "ML-DSA requires BouncyCastle 1.81+");

        KeyPair kp = keyPairs.get(jcaAlgorithm);
        byte[] signed = signWithKeyValue(sigAlgorithm, kp);

        List<SecurityEvent> events = new ArrayList<>();
        Document verified = verifyInbound(signed, events);
        Assertions.assertNotNull(verified.getDocumentElement(), "Inbound processing must yield a document");

        // The key the inbound processor verified with must be the signer's, recovered from the
        // document's DEREncodedKeyValue (no key was supplied out of band).
        PublicKey resolved = null;
        for (SecurityEvent event : events) {
            if (event instanceof KeyValueTokenSecurityEvent) {
                resolved = ((KeyValueTokenSecurityEvent) event).getSecurityToken().getPublicKey();
            }
        }
        Assertions.assertNotNull(resolved, "Expected a KeyValueTokenSecurityEvent carrying the resolved key");
        Assertions.assertArrayEquals(kp.getPublic().getEncoded(), resolved.getEncoded(),
            "Key resolved from DEREncodedKeyValue must be the signer's public key");
    }

    @ParameterizedTest
    @CsvSource({
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-44,ML-DSA-44",
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-65,ML-DSA-65",
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-87,ML-DSA-87"
    })
    void testInboundTamperedSignatureRejected(String sigAlgorithm, String jcaAlgorithm) throws Exception {
        Assumptions.assumeTrue(isBcInstalled() && keyPairs.containsKey(jcaAlgorithm),
            "ML-DSA requires BouncyCastle 1.81+");

        KeyPair kp = keyPairs.get(jcaAlgorithm);
        byte[] tampered = tamperSignatureValue(signWithKeyValue(sigAlgorithm, kp));

        // The key still resolves from the document; the rejection must come from signature
        // validation itself, not from a failure to resolve the key.
        XMLStreamException ex = Assertions.assertThrows(XMLStreamException.class,
            () -> verifyInbound(tampered, new ArrayList<>()));
        String chain = messageChain(ex);
        Assertions.assertTrue(chain.contains("INVALID signature"),
            "Expected a core-validation failure, got: " + chain);
    }

    private static String messageChain(Throwable t) {
        StringBuilder sb = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause()) {
            sb.append(c.getClass().getSimpleName()).append(": ").append(c.getMessage()).append(" | ");
        }
        return sb.toString();
    }

    /**
     * XML Signature 1.1 defines {@code dsig11:DEREncodedKeyValue} as a direct child of
     * {@code ds:KeyInfo}; the nested-in-KeyValue placement is what this library emits. A document
     * from another implementation may use the canonical placement, so the inbound side must
     * resolve the key from there as well.
     */
    @ParameterizedTest
    @CsvSource({
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-44,ML-DSA-44",
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-65,ML-DSA-65",
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-87,ML-DSA-87"
    })
    void testInboundVerifiesWithDerEncodedKeyValueAsKeyInfoChild(String sigAlgorithm, String jcaAlgorithm)
            throws Exception {
        Assumptions.assumeTrue(isBcInstalled() && keyPairs.containsKey(jcaAlgorithm),
            "ML-DSA requires BouncyCastle 1.81+");

        KeyPair kp = keyPairs.get(jcaAlgorithm);
        byte[] signed = moveDerEncodedKeyValueToKeyInfo(signWithKeyValue(sigAlgorithm, kp));

        List<SecurityEvent> events = new ArrayList<>();
        Document verified = verifyInbound(signed, events);
        Assertions.assertNotNull(verified.getDocumentElement(), "Inbound processing must yield a document");

        PublicKey resolved = null;
        for (SecurityEvent event : events) {
            if (event instanceof KeyValueTokenSecurityEvent) {
                resolved = ((KeyValueTokenSecurityEvent) event).getSecurityToken().getPublicKey();
            }
        }
        Assertions.assertNotNull(resolved, "Expected a KeyValueTokenSecurityEvent carrying the resolved key");
        Assertions.assertArrayEquals(kp.getPublic().getEncoded(), resolved.getEncoded(),
            "Key resolved from a KeyInfo-level DEREncodedKeyValue must be the signer's public key");
    }

    /**
     * Re-parents the emitted {@code dsig11:DEREncodedKeyValue} from inside {@code ds:KeyValue} to
     * be a direct child of {@code ds:KeyInfo} (removing the now-empty KeyValue), giving the
     * canonical XML Signature 1.1 layout. KeyInfo is outside the signed content, so the
     * signature stays valid.
     */
    private byte[] moveDerEncodedKeyValueToKeyInfo(byte[] signed) throws Exception {
        Document document;
        try (InputStream is = new ByteArrayInputStream(signed)) {
            document = XMLUtils.read(is, false);
        }
        Element keyInfo = (Element) document.getElementsByTagNameNS(Constants.SignatureSpecNS, "KeyInfo").item(0);
        Element keyValue = (Element) keyInfo.getElementsByTagNameNS(Constants.SignatureSpecNS, "KeyValue").item(0);
        Element der = (Element) keyValue.getElementsByTagNameNS(
            "http://www.w3.org/2009/xmldsig11#", "DEREncodedKeyValue").item(0);
        Assertions.assertNotNull(der, "Expected a DEREncodedKeyValue inside KeyValue to re-parent");
        keyValue.removeChild(der);
        keyInfo.replaceChild(der, keyValue);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        javax.xml.transform.TransformerFactory.newInstance().newTransformer().transform(
            new javax.xml.transform.dom.DOMSource(document),
            new javax.xml.transform.stream.StreamResult(bos));
        return bos.toByteArray();
    }

    /**
     * A DEREncodedKeyValue whose content is garbage (decodes to no valid SubjectPublicKeyInfo)
     * must be rejected cleanly at key resolution, not crash the pipeline with an uncaught
     * RuntimeException. Some providers throw an unchecked exception (e.g. BouncyCastle's
     * XDH/EdDSA KeyFactorySpi throws ArrayIndexOutOfBoundsException) for malformed input, and
     * inbound KeyInfo content is attacker-controlled.
     */
    @ParameterizedTest
    @CsvSource({
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-44,ML-DSA-44",
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-65,ML-DSA-65",
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-87,ML-DSA-87"
    })
    void testInboundGarbageDerContentRejectedCleanly(String sigAlgorithm, String jcaAlgorithm) throws Exception {
        Assumptions.assumeTrue(isBcInstalled() && keyPairs.containsKey(jcaAlgorithm),
            "ML-DSA requires BouncyCastle 1.81+");

        KeyPair kp = keyPairs.get(jcaAlgorithm);
        byte[] corrupted = corruptDerEncodedKeyValue(signWithKeyValue(sigAlgorithm, kp));

        XMLStreamException ex = Assertions.assertThrows(XMLStreamException.class,
            () -> verifyInbound(corrupted, new ArrayList<>()));
        String chain = messageChain(ex);
        Assertions.assertFalse(chain.contains("ArrayIndexOutOfBoundsException"),
            "Malformed DEREncodedKeyValue content must not surface as an uncaught RuntimeException: " + chain);
    }

    /** Replaces the DEREncodedKeyValue's base64 content with bytes that decode to no known SubjectPublicKeyInfo. */
    private byte[] corruptDerEncodedKeyValue(byte[] signed) throws Exception {
        Document document;
        try (InputStream is = new ByteArrayInputStream(signed)) {
            document = XMLUtils.read(is, false);
        }
        Element der = (Element) document.getElementsByTagNameNS(
            "http://www.w3.org/2009/xmldsig11#", "DEREncodedKeyValue").item(0);
        byte[] garbage = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        NodeList children = der.getChildNodes();
        for (int i = children.getLength() - 1; i >= 0; i--) {
            der.removeChild(children.item(i));
        }
        der.appendChild(document.createTextNode(Base64.getEncoder().encodeToString(garbage)));

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        javax.xml.transform.TransformerFactory.newInstance().newTransformer().transform(
            new javax.xml.transform.dom.DOMSource(document),
            new javax.xml.transform.stream.StreamResult(bos));
        return bos.toByteArray();
    }

    private Document verifyInbound(byte[] signed, List<SecurityEvent> events) throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        // deliberately no setSignatureVerificationKey(...)
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
        xmlInputFactory.setEventAllocator(new XMLSecEventAllocator());
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(signed));
        XMLStreamReader securityStreamReader =
            inboundXMLSec.processInMessage(xmlStreamReader, null, events::add);
        return StAX2DOM.readDoc(securityStreamReader);
    }

    private byte[] signWithKeyValue(String sigAlgorithm, KeyPair kp) throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_KeyValue);
        properties.setSignatureAlgorithm(sigAlgorithm);
        properties.setSignatureKey(kp.getPrivate());
        properties.setSignatureVerificationKey(kp.getPublic());

        SecurePart securePart = new SecurePart(
            new QName("urn:example:po", "PaymentInfo"),
            SecurePart.Modifier.Content,
            new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
            "http://www.w3.org/2001/04/xmlenc#sha256");
        properties.addSignaturePart(securePart);

        return process("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml", properties, null);
    }

    /** Flips one byte of the SignatureValue and re-serializes. */
    private byte[] tamperSignatureValue(byte[] signed) throws Exception {
        Document document;
        try (InputStream is = new ByteArrayInputStream(signed)) {
            document = XMLUtils.read(is, false);
        }
        NodeList sigValues = document.getElementsByTagNameNS(Constants.SignatureSpecNS, "SignatureValue");
        Assertions.assertEquals(1, sigValues.getLength(), "Expected exactly one SignatureValue element");
        Element sigValueElement = (Element) sigValues.item(0);

        byte[] sigBytes = Base64.getMimeDecoder().decode(sigValueElement.getTextContent());
        sigBytes[sigBytes.length / 2] ^= (byte) 0xFF;

        NodeList children = sigValueElement.getChildNodes();
        for (int i = children.getLength() - 1; i >= 0; i--) {
            sigValueElement.removeChild(children.item(i));
        }
        Text newText = document.createTextNode(Base64.getEncoder().encodeToString(sigBytes));
        sigValueElement.appendChild(newText);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        javax.xml.transform.TransformerFactory.newInstance().newTransformer().transform(
            new javax.xml.transform.dom.DOMSource(document),
            new javax.xml.transform.stream.StreamResult(bos));
        return bos.toByteArray();
    }
}
