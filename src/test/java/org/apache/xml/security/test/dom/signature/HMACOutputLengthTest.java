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


import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;

import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class HMACOutputLengthTest {

    public HMACOutputLengthTest() throws Exception {
        Init.init();
    }

    @org.junit.jupiter.api.Test
    public void test_signature_enveloping_hmac_sha1_trunclen_0() throws Exception {
        try {
            validate("signature-enveloping-hmac-sha1-trunclen-0-attack.xml");
            fail("Expected HMACOutputLength exception");
        } catch (XMLSignatureException xse) {
            // System.out.println(xse.getMessage());
            if (!"algorithms.HMACOutputLengthMin".equals(xse.getMsgID())) {
                fail(xse.getMessage());
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void test_signature_enveloping_hmac_sha1_trunclen_8() throws Exception {
        try {
            validate("signature-enveloping-hmac-sha1-trunclen-8-attack.xml");
        } catch (XMLSignatureException xse) {
            // System.out.println(xse.getMessage());
            if (!"algorithms.HMACOutputLengthMin".equals(xse.getMsgID())) {
                fail(xse.getMessage());
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void test_generate_hmac_sha1_40() throws Exception {
        Document doc = TestUtils.newDocument();
        try {
            new XMLSignature(
                doc, null, XMLSignature.ALGO_ID_MAC_HMAC_SHA1,
                 40, Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS
            );
            fail("Expected HMACOutputLength Exception");
        } catch (XMLSignatureException xse) {
            // System.out.println(xse.getMessage());
            if (!"algorithms.HMACOutputLengthMin".equals(xse.getMsgID())) {
                fail(xse.getMessage());
            }
        }
    }

    @org.junit.jupiter.api.Test
    public void testValidHMACOutputLength() throws Exception {
        Document doc = TestUtils.newDocument();

        doc.appendChild(doc.createComment(" Comment before "));
        Element root = doc.createElementNS("", "RootElement");

        doc.appendChild(root);
        root.appendChild(doc.createTextNode("Some simple text\n"));

        Element canonElem =
            XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttributeNS(
            null, Constants._ATT_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS
        );

        XMLSignature sig =
            new XMLSignature(doc, null, XMLSignature.ALGO_ID_MAC_HMAC_SHA1, 160);

        root.appendChild(sig.getElement());
        doc.appendChild(doc.createComment(" Comment after "));
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        sig.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);

        SecretKey sk = sig.createSecretKey("secret".getBytes(StandardCharsets.US_ASCII));
        sig.sign(sk);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        XMLUtils.outputDOMc14nWithComments(doc, bos);
        String signedContent = new String(bos.toByteArray());

        assertTrue(signedContent.contains("ds:HMACOutputLength>160</ds:HMACOutputLength>"));

        // Verify
        NodeList nl =
            doc.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("Couldn't find signature Element");
        }
        Element sigElement = (Element) nl.item(0);
        XMLSignature signature = new XMLSignature(sigElement, null);
        assertTrue(signature.checkSignatureValue(sk));
    }

    private boolean validate(String data) throws Exception {
        File file = resolveFile("src", "test", "resources", "org", "apache", "xml", "security", "test", "javax", "xml",
            "crypto", "dsig", data);
        Document doc = XMLUtils.read(file, false);
        NodeList nl = doc.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("Couldn't find signature Element");
        }
        Element sigElement = (Element) nl.item(0);
        XMLSignature signature = new XMLSignature(sigElement, file.toURI().toString());
        SecretKey sk = signature.createSecretKey("secret".getBytes(StandardCharsets.US_ASCII));
        return signature.checkSignatureValue(sk);
    }

}