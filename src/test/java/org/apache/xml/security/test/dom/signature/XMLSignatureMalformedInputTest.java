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
package org.apache.xml.security.test.dom.signature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Malformed values in an (untrusted) ds:Signature must be reported as {@link XMLSignatureException},
 * the exception type declared by the XMLSignature verification API, rather than escaping as an
 * unchecked IllegalArgumentException, NumberFormatException or NullPointerException.
 * Secure validation is on (the default for {@code new XMLSignature(Element, String)}).
 */
class XMLSignatureMalformedInputTest {

    private static final String DS = Constants.SignatureSpecNS;
    /** Rejected by the MIME base64 decoder ("Last unit does not have enough valid bits"). */
    private static final String BAD_BASE64 = "A";
    private static final SecretKey HMAC_KEY =
        new SecretKeySpec("0123456789abcdef0123456789abcdef".getBytes(), "HmacSHA256");

    @BeforeAll
    static void setUp() {
        org.apache.xml.security.Init.init();
    }

    @Test
    void testWellFormedSignatureVerifies() throws Exception {
        assertTrue(verify(signedDocument(false)));
        assertTrue(verify(signedDocument(true)));
    }

    @Test
    void testMalformedSignatureValue() throws Exception {
        Document doc = signedDocument(false);
        setText(doc, DS, "SignatureValue", BAD_BASE64);
        assertThrows(XMLSignatureException.class, () -> verify(doc));
        assertThrows(XMLSignatureException.class, () -> newSignature(doc).getSignatureValue());
    }

    @Test
    void testMalformedDigestValue() throws Exception {
        // The SignedInfo is re-MACed, so the signature itself verifies and the DigestValue is decoded
        Document doc = signedDocument(false);
        setText(doc, DS, "DigestValue", BAD_BASE64);
        remac(doc);
        assertThrows(XMLSignatureException.class, () -> verify(doc));
    }

    @Test
    void testMalformedContentUnderBase64Transform() throws Exception {
        Document doc = signedDocument(true);
        doc.getElementsByTagName("data").item(0).setTextContent(BAD_BASE64);
        assertThrows(XMLSignatureException.class, () -> verify(doc));
    }

    @Test
    void testNonNumericHMACOutputLength() throws Exception {
        Document doc = signedDocument(false);
        Element signatureMethod = (Element) doc.getElementsByTagNameNS(DS, "SignatureMethod").item(0);
        Element hmacOutputLength = doc.createElementNS(DS, "ds:HMACOutputLength");
        hmacOutputLength.setTextContent("abc");
        signatureMethod.appendChild(hmacOutputLength);
        assertThrows(XMLSignatureException.class, () -> newSignature(doc));
    }

    @Test
    void testEmptyDigestMethodAlgorithm() throws Exception {
        Document doc = signedDocument(false);
        Element digestMethod = (Element) doc.getElementsByTagNameNS(DS, "DigestMethod").item(0);
        digestMethod.setAttributeNS(null, "Algorithm", "");
        remac(doc);
        assertThrows(XMLSignatureException.class, () -> verify(doc));
    }

    // ---------------------------------------------------------------- helpers

    /** HMAC-SHA256 signature over #d, through either exclusive c14n or the base64 transform. */
    private static Document signedDocument(boolean base64Transform) throws Exception {
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
        Element root = doc.createElement("root");
        doc.appendChild(root);
        Element data = doc.createElement("data");
        data.setAttributeNS(null, "Id", "d");
        data.setIdAttributeNS(null, "Id", true);
        data.setTextContent(base64Transform ? "QUJD" : "hello");
        root.appendChild(data);

        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_MAC_HMAC_SHA256,
            Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        root.appendChild(sig.getElement());
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(base64Transform
            ? Transforms.TRANSFORM_BASE64_DECODE : Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        sig.addDocument("#d", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
        sig.sign(HMAC_KEY);
        return reparse(doc);
    }

    /** Recompute the HMAC over the (mutated) SignedInfo so that the SignatureValue is valid again. */
    private static void remac(Document doc) throws Exception {
        Element signedInfo = (Element) doc.getElementsByTagNameNS(DS, "SignedInfo").item(0);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS).canonicalizeSubtree(signedInfo, bos);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(HMAC_KEY);
        setText(doc, DS, "SignatureValue", Base64.getEncoder().encodeToString(mac.doFinal(bos.toByteArray())));
    }

    private static XMLSignature newSignature(Document doc) throws Exception {
        Element data = (Element) doc.getElementsByTagName("data").item(0);
        data.setIdAttributeNS(null, "Id", true);
        return new XMLSignature((Element) doc.getElementsByTagNameNS(DS, "Signature").item(0), "");
    }

    private static boolean verify(Document doc) throws Exception {
        return newSignature(doc).checkSignatureValue(HMAC_KEY);
    }

    private static void setText(Document doc, String namespace, String localName, String value) {
        Element element = (Element) doc.getElementsByTagNameNS(namespace, localName).item(0);
        while (element.hasChildNodes()) {
            element.removeChild(element.getFirstChild());
        }
        element.appendChild(doc.createTextNode(value));
    }

    private static Document reparse(Document doc) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLUtils.outputDOM(doc, bos);
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(new ByteArrayInputStream(bos.toByteArray()));
    }
}
