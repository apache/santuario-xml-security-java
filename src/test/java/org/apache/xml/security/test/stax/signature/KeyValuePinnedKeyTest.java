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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.stax.ext.InboundXMLSec;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A signature verification key configured via XMLSecurityProperties.setSignatureVerificationKey
 * must be used for verification even when the document carries a ds:KeyValue.
 */
class KeyValuePinnedKeyTest extends AbstractSignatureVerificationTest {

    private final TransformerFactory transformerFactory = TransformerFactory.newInstance();

    private byte[] signWithKeyValue(KeyPair signingKeyPair) throws Exception {
        return sign(signingKeyPair, null);
    }

    private byte[] sign(KeyPair signingKeyPair, X509Certificate cert) throws Exception {
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        XMLSignature sig = signUsingDOM(
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", document, localNames, signingKeyPair.getPrivate());
        if (cert != null) {
            sig.addKeyInfo(cert);
        } else {
            sig.addKeyInfo(signingKeyPair.getPublic());
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        transformerFactory.newTransformer().transform(new DOMSource(document), new StreamResult(baos));
        return baos.toByteArray();
    }

    private void verify(byte[] signed, Key pinnedKey) throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setSignatureVerificationKey(pinnedKey);
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(signed));
        XMLStreamReader securityStreamReader = inboundXMLSec.processInMessage(xmlStreamReader, null, null);
        StAX2DOM.readDoc(securityStreamReader);
    }

    /**
     * The attacker signs with their own key and embeds it as KeyValue: verification against the
     * pinned key must fail.
     */
    @Test
    void testAttackerKeyValueRejectedWhenKeyPinned() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair attacker = kpg.generateKeyPair();

        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        PublicKey partnerKey = ((X509Certificate) keyStore.getCertificate("transmitter")).getPublicKey();

        byte[] signed = signWithKeyValue(attacker);
        assertThrows(XMLStreamException.class, () -> verify(signed, partnerKey));
    }

    /**
     * The caller pinned an HMAC key; an attacker RSA signature with KeyValue must not verify.
     */
    @Test
    void testAttackerKeyValueRejectedWhenHmacKeyPinned() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        byte[] signed = signWithKeyValue(kpg.generateKeyPair());
        Key hmacKey = new SecretKeySpec(new byte[32], "HmacSHA256");
        assertThrows(XMLStreamException.class, () -> verify(signed, hmacKey));
    }

    /**
     * The caller pinned an HMAC key; an RSA signature with an X509Data certificate must not verify.
     * (Uses the test keystore's certificate as a stand-in for an attacker's self-signed one.)
     */
    @Test
    void testX509DataRejectedWhenHmacKeyPinned() throws Exception {
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        X509Certificate cert = (X509Certificate) keyStore.getCertificate("transmitter");
        java.security.PrivateKey priv = (java.security.PrivateKey) keyStore.getKey("transmitter",
            XmlSecTestEnvironment.TRANSMITTER_KS_PASSWORD.toCharArray());
        byte[] signed = sign(new KeyPair(cert.getPublicKey(), priv), cert);
        Key hmacKey = new SecretKeySpec(new byte[32], "HmacSHA256");
        assertThrows(XMLStreamException.class, () -> verify(signed, hmacKey));
    }
}
