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
import java.security.KeyStore;
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
import org.apache.xml.security.test.stax.utils.StAX2DOM;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An HMAC signature must not be verified with a public key. Some JCE providers (e.g. BouncyCastle)
 * would accept a public key for HMAC and use its encoding as the HMAC key, so that anyone could
 * create an "HMAC signature" from the trusted public key alone.
 */
class HmacPublicKeyTest extends AbstractSignatureVerificationTest {

    private byte[] forge(PublicKey trustedKey, X509Certificate keyInfoCert) throws Exception {
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);
        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");
        XMLSignature sig = signUsingDOM("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", document, localNames,
            new SecretKeySpec(trustedKey.getEncoded(), "HmacSHA256"));
        if (keyInfoCert != null) {
            sig.addKeyInfo(keyInfoCert);
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        TransformerFactory.newInstance().newTransformer().transform(new DOMSource(document), new StreamResult(baos));
        return baos.toByteArray();
    }

    private void verify(byte[] signed, PublicKey pinned) throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        if (pinned != null) {
            properties.setSignatureVerificationKey(pinned);
        }
        InboundXMLSec inboundXMLSec = XMLSec.getInboundWSSec(properties);
        XMLStreamReader r = xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(signed));
        StAX2DOM.readDoc(inboundXMLSec.processInMessage(r, null, null));
    }

    private X509Certificate cert() throws Exception {
        KeyStore ks = KeyStore.getInstance("jks");
        ks.load(
                this.getClass().getClassLoader().getResource("transmitter.jks").openStream(),
                "default".toCharArray()
        );
        return (X509Certificate) ks.getCertificate("transmitter");
    }

    private static void assertWrongKeyType(Throwable ex) {
        // rejected because of the key type, not merely because a JCE provider refused the key
        assertTrue(ex.getMessage().contains("wrong key type"), ex.getMessage());
    }

    /** The caller pinned a public key; an HMAC keyed with its encoding must be rejected. */
    @Test
    void testPinnedPublicKeyAsHmacKey() throws Exception {
        PublicKey pub = cert().getPublicKey();
        byte[] signed = forge(pub, null);
        XMLStreamException ex = assertThrows(XMLStreamException.class, () -> verify(signed, pub));
        assertWrongKeyType(ex);
    }

    /** No key pinned, legitimate certificate in KeyInfo; an HMAC keyed with its public key must be rejected. */
    @Test
    void testCertificatePublicKeyAsHmacKey() throws Exception {
        X509Certificate cert = cert();
        byte[] signed = forge(cert.getPublicKey(), cert);
        XMLStreamException ex = assertThrows(XMLStreamException.class, () -> verify(signed, null));
        assertWrongKeyType(ex);
    }
}
