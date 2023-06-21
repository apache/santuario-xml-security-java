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
package org.apache.xml.security.test.dom.encryption;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.transform.TransformerFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.encryption.DocumentSerializer;
import org.apache.xml.security.encryption.TransformSerializer;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 */
public class SignedEncryptedTest {

    private static final String SAMPLE_MSG = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<SOAP-ENV:Envelope "
            + "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
            + "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
            + "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
            + "<SOAP-ENV:Body xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
            + "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
            + "<value xmlns=\"http://blah.com\">15</value>"
            + "<o:other xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:o=\"http://other.com\" xmlns=\"\">0</o:other>"
            + "</add>"
            + "</SOAP-ENV:Body>"
            + "</SOAP-ENV:Envelope>";

    @BeforeEach
    public void setUp() throws Exception {
        org.apache.xml.security.Init.init();
    }

    /**
     * This test uses the xalan identity-transformer to insert the decrypted content into the original document.
     *
     * @throws Exception
     */
    @Test
    public void decryptUsingXalanTransformer() throws Exception {
        try {
            Class<?> tf = getClass().getClassLoader().loadClass(
                    "org.apache.xalan.processor.TransformerFactoryImpl");
            secureAndVerify((TransformerFactory) tf.newInstance(), false);
        } catch (ClassNotFoundException e) {
            System.out.println(
                    "org.apache.xalan.processor.TransformerFactoryImpl not found, skipping test");
        }
    }

    /**
     * This test does not use the IdentityTransformer but instead it uses the DocumentSerializer
     * which uses the DocumentBuilder to read in the decrypted content and then does a DOM2DOM copy.
     *
     * @throws Exception
     */
    @Test
    public void decryptUsingSunDOMSerializer() throws Exception {
        secureAndVerify(null, true);
    }

    public void secureAndVerify(TransformerFactory transformerFactory, boolean useDocumentSerializer) throws Exception {
        Document document = null;
        try (InputStream is = new ByteArrayInputStream(SAMPLE_MSG.getBytes(StandardCharsets.UTF_8))) {
            document = XMLUtils.read(is, false);
        }

        // Set up the Key
        KeyPairGenerator rsaKeygen = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = rsaKeygen.generateKeyPair();
        PrivateKey priv = kp.getPrivate();
        PublicKey pub = kp.getPublic();

        XMLSignature sig = new XMLSignature(document, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1,
                Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        Element sigElement = sig.getElement();
        document.getDocumentElement().appendChild(sigElement);

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        Element element =
                (Element) xpath.evaluate("//*[local-name()='Body']", document, XPathConstants.NODE);

        String id = UUID.randomUUID().toString();
        element.setAttributeNS(null, "Id", id);
        element.setIdAttributeNS(null, "Id", true);

        Transforms transforms = new Transforms(document);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        sig.addDocument("#" + id, transforms, Constants.ALGO_ID_DIGEST_SHA1);

        sig.addKeyInfo(pub);
        sig.sign(priv);

        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256);
        SecretKey secretKey = keygen.generateKey();

        XMLCipher cipher = XMLCipher.getInstance(XMLCipher.AES_128);
        cipher.init(XMLCipher.ENCRYPT_MODE, secretKey);

        document = cipher.doFinal(document, element, true);

        XMLCipher deCipher = null;
        if (useDocumentSerializer) {
            deCipher = XMLCipher.getInstance(new DocumentSerializer(true), XMLCipher.AES_128);
        } else {
            TransformSerializer serializer = new TransformSerializer(true);
            Field f = serializer.getClass().getDeclaredField("transformerFactory");
            f.setAccessible(true);
            f.set(serializer, transformerFactory);
            deCipher = XMLCipher.getInstance(serializer, XMLCipher.AES_128);
        }
        deCipher.init(XMLCipher.DECRYPT_MODE, secretKey);
        deCipher.doFinal(document, element, true);

        XMLSignature xmlSignatureVerifier = new XMLSignature(sigElement, "");
        assertTrue(xmlSignatureVerifier.checkSignatureValue(pub));
    }
}