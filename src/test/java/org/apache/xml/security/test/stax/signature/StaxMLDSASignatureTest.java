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

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.stax.ext.SecurePart;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
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
 * StAX-path tests for ML-DSA (FIPS 204) XML digital signatures.
 */
class StaxMLDSASignatureTest extends AbstractSignatureCreationTest {

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
    void testMLDSASign(String sigAlgorithm, String jcaAlgorithm) throws Exception {
        Assumptions.assumeTrue(isBcInstalled() && keyPairs.containsKey(jcaAlgorithm),
            "ML-DSA requires BouncyCastle 1.81+");

        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_KeyValue);
        properties.setSignatureAlgorithm(sigAlgorithm);

        KeyPair kp = keyPairs.get(jcaAlgorithm);
        properties.setSignatureKey(kp.getPrivate());
        properties.setSignatureVerificationKey(kp.getPublic());

        SecurePart securePart = new SecurePart(
            new QName("urn:example:po", "PaymentInfo"),
            SecurePart.Modifier.Content,
            new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
            "http://www.w3.org/2001/04/xmlenc#sha256");
        properties.addSignaturePart(securePart);

        byte[] output = process("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml", properties, null);

        Document document;
        try (InputStream is = new ByteArrayInputStream(output)) {
            document = XMLUtils.read(is, false);
        }

        verifyUsingDOM(document, kp.getPublic(), properties.getSignatureSecureParts());
    }

    @ParameterizedTest
    @CsvSource({
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-44,ML-DSA-44",
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-65,ML-DSA-65",
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-87,ML-DSA-87"
    })
    void testMLDSAStaxTamperedSignatureRejected(String sigAlgorithm, String jcaAlgorithm) throws Exception {
        Assumptions.assumeTrue(isBcInstalled() && keyPairs.containsKey(jcaAlgorithm),
            "ML-DSA requires BouncyCastle 1.81+");

        Document document = signWith(sigAlgorithm, jcaAlgorithm);
        Element sigElement = tamperSignatureValue(document);

        XMLSignature signature = new XMLSignature(sigElement, "");
        boolean coreValidity = signature.checkSignatureValue(keyPairs.get(jcaAlgorithm).getPublic());
        Assertions.assertFalse(coreValidity, "A tampered SignatureValue must not validate");
    }

    @ParameterizedTest
    @CsvSource({
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-44,ML-DSA-44",
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-65,ML-DSA-65",
        "http://www.w3.org/2026/08/xmldsig-more#ml-dsa-87,ML-DSA-87"
    })
    void testMLDSAStaxWrongPublicKeyRejected(String sigAlgorithm, String jcaAlgorithm) throws Exception {
        Assumptions.assumeTrue(isBcInstalled() && keyPairs.containsKey(jcaAlgorithm),
            "ML-DSA requires BouncyCastle 1.81+");

        Document document = signWith(sigAlgorithm, jcaAlgorithm);
        Element sigElement = (Element) document.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature").item(0);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(jcaAlgorithm, "BC");
        PublicKey wrongPublicKey = kpg.generateKeyPair().getPublic();

        XMLSignature signature = new XMLSignature(sigElement, "");
        boolean coreValidity = signature.checkSignatureValue(wrongPublicKey);
        Assertions.assertFalse(coreValidity, "Verification against the wrong public key must not validate");
    }

    private Document signWith(String sigAlgorithm, String jcaAlgorithm) throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);
        properties.setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier_KeyValue);
        properties.setSignatureAlgorithm(sigAlgorithm);

        KeyPair kp = keyPairs.get(jcaAlgorithm);
        properties.setSignatureKey(kp.getPrivate());
        properties.setSignatureVerificationKey(kp.getPublic());

        SecurePart securePart = new SecurePart(
            new QName("urn:example:po", "PaymentInfo"),
            SecurePart.Modifier.Content,
            new String[]{"http://www.w3.org/2001/10/xml-exc-c14n#"},
            "http://www.w3.org/2001/04/xmlenc#sha256");
        properties.addSignaturePart(securePart);

        byte[] output = process("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml", properties, null);

        try (InputStream is = new ByteArrayInputStream(output)) {
            return XMLUtils.read(is, false);
        }
    }

    /**
     * Decodes the &lt;SignatureValue&gt; text content, flips one byte, and writes it back -
     * simulates an attacker (or transport bug) corrupting the signature bytes while leaving
     * the rest of the document intact. Returns the enclosing &lt;Signature&gt; element.
     */
    private Element tamperSignatureValue(Document document) {
        NodeList sigValues = document.getElementsByTagNameNS(Constants.SignatureSpecNS, "SignatureValue");
        Assertions.assertEquals(1, sigValues.getLength(), "Expected exactly one SignatureValue element");
        Element sigValueElement = (Element) sigValues.item(0);

        byte[] sigBytes = Base64.getMimeDecoder().decode(sigValueElement.getTextContent());
        sigBytes[sigBytes.length / 2] ^= (byte) 0xFF;
        String tamperedBase64 = Base64.getEncoder().encodeToString(sigBytes);

        NodeList children = sigValueElement.getChildNodes();
        for (int i = children.getLength() - 1; i >= 0; i--) {
            sigValueElement.removeChild(children.item(i));
        }
        Text newText = document.createTextNode(tamperedBase64);
        sigValueElement.appendChild(newText);

        return (Element) sigValueElement.getParentNode();
    }
}
