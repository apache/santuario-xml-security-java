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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.encryption.CipherData;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.EncryptionMethod;
import org.apache.xml.security.encryption.EncryptionProperties;
import org.apache.xml.security.encryption.EncryptionProperty;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.parser.XMLParserException;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assumptions.assumeFalse;


/**
 *
 */
public class XMLCipherTest {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(XMLCipherTest.class);

    static {
        org.apache.xml.security.Init.init();
    }

    private final String documentName;
    private final String elementName;
    private final String elementIndex;
    private XMLCipher cipher;
    private final String basedir;
    private boolean haveISOPadding;
    private final boolean haveKeyWraps;
    private final String tstBase64EncodedString;
    private boolean bcInstalled;

    private final boolean isIBMJdK = System.getProperty("java.vendor").contains("IBM");

    public XMLCipherTest() throws Exception {
        basedir = System.getProperty("basedir",".");
        documentName = System.getProperty("org.apache.xml.enc.test.doc",
                                          basedir + "/pom.xml");
        elementName = System.getProperty("org.apache.xml.enc.test.elem", "project");
        elementIndex = System.getProperty("org.apache.xml.enc.test.idx", "0");

        tstBase64EncodedString =
            "YmNkZWZnaGlqa2xtbm9wcRrPXjQ1hvhDFT+EdesMAPE4F6vlT+y0HPXe0+nAGLQ8";

        // Determine if we have ISO 10126 Padding - needed for Bulk AES or
        // 3DES encryption

        haveISOPadding = false;
        final String algorithmId =
            JCEMapper.translateURItoJCEID(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

        if (algorithmId != null) {
            try {
                if (Cipher.getInstance(algorithmId) != null) {
                    haveISOPadding = true;
                }
            } catch (final NoSuchAlgorithmException nsae) {
                //
            } catch (final NoSuchPaddingException nspe) {
                //
            }
        }

        haveKeyWraps =
            JCEMapper.translateURItoJCEID(EncryptionConstants.ALGO_ID_KEYWRAP_AES128) != null;
    }

    /**
     * Test encryption using a generated AES 128 bit key that is
     * encrypted using a AES 192 bit key.  Then reverse using the KEK
     */
    @Test
    public void testAES128ElementAES192KWCipherUsingKEK() throws Exception {

        final Document d = document(); // source
        Document ed = null;
        Document dd = null;
        final Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding && haveKeyWraps) {
            source = toString(d);

            // Set up a Key Encryption Key
            final byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
            final Key kek = new SecretKeySpec(bits192, "AES");

            // Generate a traffic key
            final KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(128);
            Key key = keygen.generateKey();

            cipher = XMLCipher.getInstance(XMLCipher.AES_192_KeyWrap);
            cipher.init(XMLCipher.WRAP_MODE, kek);
            cipher.setSecureValidation(true);
            final EncryptedKey encryptedKey = cipher.encryptKey(d, key);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_128);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            final EncryptedData builder = cipher.getEncryptedData();

            KeyInfo builderKeyInfo = builder.getKeyInfo();
            if (builderKeyInfo == null) {
                builderKeyInfo = new KeyInfo(d);
                builder.setKeyInfo(builderKeyInfo);
            }

            builderKeyInfo.add(encryptedKey);

            ed = cipher.doFinal(d, e);

            //decrypt
            key = null;
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            cipher = XMLCipher.getInstance(XMLCipher.AES_128);
            cipher.init(XMLCipher.DECRYPT_MODE, null);
            cipher.setKEK(kek);
            cipher.setSecureValidation(true);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.warn(
                "Test testAES128ElementAES192KWCipherUsingKEK skipped as "
                + "necessary algorithms not available"
            );
        }
    }

    /**
     * Test encryption using a generated AES 256 bit key that is
     * encrypted using an RSA key.  Reverse using KEK
     */
    @Test
    public void testAES256ElementRSAKWCipherUsingKEK() throws Exception {

        final Document d = document(); // source
        Document ed = null;
        Document dd = null;
        final Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding) {
            source = toString(d);

            // Generate an RSA key
            final KeyPairGenerator rsaKeygen = KeyPairGenerator.getInstance("RSA");
            final KeyPair kp = rsaKeygen.generateKeyPair();
            final PrivateKey priv = kp.getPrivate();
            final PublicKey pub = kp.getPublic();

            // Generate a traffic key
            final KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(256);
            Key key = keygen.generateKey();


            cipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
            cipher.init(XMLCipher.WRAP_MODE, pub);
            cipher.setSecureValidation(true);
            final EncryptedKey encryptedKey = cipher.encryptKey(d, key);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_256);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            final EncryptedData builder = cipher.getEncryptedData();

            KeyInfo builderKeyInfo = builder.getKeyInfo();
            if (builderKeyInfo == null) {
                builderKeyInfo = new KeyInfo(d);
                builder.setKeyInfo(builderKeyInfo);
            }

            builderKeyInfo.add(encryptedKey);

            ed = cipher.doFinal(d, e);
            LOG.debug("Encrypted document");
            LOG.debug(toString(ed));


            //decrypt
            key = null;
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            cipher = XMLCipher.getInstance(XMLCipher.AES_256);
            cipher.init(XMLCipher.DECRYPT_MODE, null);
            cipher.setKEK(priv);
            cipher.setSecureValidation(true);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.warn(
                "Test testAES256ElementRSAKWCipherUsingKEK skipped as "
                + "necessary algorithms not available"
            );
        }
    }

    /**
     * Test encryption using a generated AES 192 bit key that is
     * encrypted using a 3DES key.  Then reverse by decrypting
     * EncryptedKey by hand
     */
    @Test
    public void testAES192Element3DESKWCipher() throws Exception {

        assumeFalse(isIBMJdK);

        final Document d = document(); // source
        Document ed = null;
        Document dd = null;
        final Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding && haveKeyWraps) {
            source = toString(d);

            // Set up a Key Encryption Key
            final byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
            final DESedeKeySpec keySpec = new DESedeKeySpec(bits192);
            final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            final Key kek = keyFactory.generateSecret(keySpec);

            // Generate a traffic key
            final KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(192);
            Key key = keygen.generateKey();

            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES_KeyWrap);
            cipher.init(XMLCipher.WRAP_MODE, kek);
            final EncryptedKey encryptedKey = cipher.encryptKey(d, key);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_192);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            final EncryptedData builder = cipher.getEncryptedData();

            KeyInfo builderKeyInfo = builder.getKeyInfo();
            if (builderKeyInfo == null) {
                builderKeyInfo = new KeyInfo(d);
                builder.setKeyInfo(builderKeyInfo);
            }

            builderKeyInfo.add(encryptedKey);

            ed = cipher.doFinal(d, e);

            //decrypt
            key = null;
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            cipher = XMLCipher.getInstance();
            cipher.init(XMLCipher.DECRYPT_MODE, null);

            final EncryptedData encryptedData = cipher.loadEncryptedData(ed, ee);

            if(encryptedData == null) {
                System.out.println("ed is null");
            }
            else if (encryptedData.getKeyInfo() == null) {
                System.out.println("ki is null");
            }
            final EncryptedKey ek = encryptedData.getKeyInfo().itemEncryptedKey(0);

            if (ek != null) {
                final XMLCipher keyCipher = XMLCipher.getInstance();
                keyCipher.init(XMLCipher.UNWRAP_MODE, kek);
                key = keyCipher.decryptKey(ek, encryptedData.getEncryptionMethod().getAlgorithm());
            }

            // Create a new cipher just to be paranoid
            final XMLCipher cipher3 = XMLCipher.getInstance();
            cipher3.init(XMLCipher.DECRYPT_MODE, key);
            dd = cipher3.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.warn(
                "Test testAES192Element3DESKWCipher skipped as "
                + "necessary algorithms not available"
            );
        }
    }

    @Test
    public void testTripleDesElementCipher() throws Exception {
        final Document d = document(); // source
        Document ed = null;      // target
        Document dd = null;      // target
        final Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding) {
            source = toString(d);

            // prepare for encryption
            final byte[] passPhrase = "24 Bytes per DESede key!".getBytes();
            final DESedeKeySpec keySpec = new DESedeKeySpec(passPhrase);
            final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            final SecretKey key = keyFactory.generateSecret(keySpec);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            ed = cipher.doFinal(d, e);

            //decrypt
            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            cipher.init(XMLCipher.DECRYPT_MODE, key);
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            final EncryptedData encryptedData = cipher.loadEncryptedData(ed, ee);
            final String algorithm = encryptedData.getEncryptionMethod().getAlgorithm();
            assertEquals(XMLCipher.TRIPLEDES, algorithm);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.warn(
                "Test testTripleDesElementCipher skipped as necessary algorithms not available"
            );
        }
    }

    @Test
    public void testAes128ElementCipher() throws Exception {
        final byte[] bits128 = {
                          (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                          (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
                          (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
                          (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
        final Key key = new SecretKeySpec(bits128, "AES");

        final Document d = document(); // source
        Document ed = null;      // target
        Document dd = null;      // target
        final Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding) {
            source = toString(d);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_128);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            ed = cipher.doFinal(d, e);

            //decrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_128);
            cipher.init(XMLCipher.DECRYPT_MODE, key);
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            final EncryptedData encryptedData = cipher.loadEncryptedData(ed, ee);
            final String algorithm = encryptedData.getEncryptionMethod().getAlgorithm();
            assertEquals(XMLCipher.AES_128, algorithm);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.warn(
                "Test testAes128ElementCipher skipped as necessary algorithms not available"
            );
        }
    }

    @Test
    public void testAes192ElementCipher() throws Exception {
        final byte[] bits192 = {
                          (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B,
                          (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
                          (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                          (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
                          (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
                          (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
        final Key key = new SecretKeySpec(bits192, "AES");

        final Document d = document(); // source
        Document ed = null;      // target
        Document dd = null;      // target
        final Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding) {
            source = toString(d);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_192);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            ed = cipher.doFinal(d, e);

            //decrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_192);
            cipher.init(XMLCipher.DECRYPT_MODE, key);
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            final EncryptedData encryptedData = cipher.loadEncryptedData(ed, ee);
            final String algorithm = encryptedData.getEncryptionMethod().getAlgorithm();
            assertEquals(XMLCipher.AES_192, algorithm);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.warn("Test testAes192ElementCipher skipped as necessary algorithms not available");
        }
    }

    @Test
    public void testAes265ElementCipher() throws Exception {
        final byte[] bits256 = {
                          (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03,
                          (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
                          (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B,
                          (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
                          (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                          (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
                          (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
                          (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
        final Key key = new SecretKeySpec(bits256, "AES");

        final Document d = document(); // source
        Document ed = null;      // target
        Document dd = null;      // target
        final Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding) {
            source = toString(d);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_256);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            ed = cipher.doFinal(d, e);

            //decrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_256);
            cipher.init(XMLCipher.DECRYPT_MODE, key);
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            final EncryptedData encryptedData = cipher.loadEncryptedData(ed, ee);
            final String algorithm = encryptedData.getEncryptionMethod().getAlgorithm();
            assertEquals(XMLCipher.AES_256, algorithm);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.warn("Test testAes265ElementCipher skipped as necessary algorithms not available");
        }
    }

    /*
     * Test case for when the entire document is encrypted and decrypted
     * In this case the EncryptedData becomes the root element of the document
     */
    @Test
    public void testTripleDesDocumentCipher() throws Exception {
        final Document d = document(); // source
        Document ed = null;      // target
        Document dd = null;      // target
        final Element e = d.getDocumentElement();
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding) {
            source = toString(d);

            // prepare for encryption
            final byte[] passPhrase = "24 Bytes per DESede key!".getBytes();
            final DESedeKeySpec keySpec = new DESedeKeySpec(passPhrase);
            final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            final SecretKey key = keyFactory.generateSecret(keySpec);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            ed = cipher.doFinal(d, e);

            //decrypt
            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            cipher.init(XMLCipher.DECRYPT_MODE, key);
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.warn(
                "Test testTripleDesDocumentCipher skipped as "
                + "necessary algorithms not available"
            );
        }
    }

    @Test
    public void testEncryptionProperties() throws Exception {
        final Document d = document(); // source
        Document ed = null;      // target
        Document dd = null;      // target
        final Element e = d.getDocumentElement();
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding) {
            source = toString(d);

            // prepare for encryption
            final byte[] passPhrase = "24 Bytes per DESede key!".getBytes();
            final DESedeKeySpec keySpec = new DESedeKeySpec(passPhrase);
            final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            final SecretKey key = keyFactory.generateSecret(keySpec);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);

            // Add EncryptionProperties
            final Element elem = d.createElement("CustomInformation");
            elem.setTextContent("Some text content");

            final EncryptionProperties eps = cipher.createEncryptionProperties();
            final EncryptionProperty ep = cipher.createEncryptionProperty();
            ep.addEncryptionInformation(elem);
            ep.setId("_124124");
            ep.setTarget("http://localhost/");
            ep.setAttribute("xml:lang", "en");
            eps.addEncryptionProperty(ep);

            final EncryptedData encData = cipher.getEncryptedData();
            encData.setEncryptionProperties(eps);

            ed = cipher.doFinal(d, e);
            // XMLUtils.outputDOM(ed, System.out);

            //decrypt
            cipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            cipher.init(XMLCipher.DECRYPT_MODE, key);
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.warn(
                "Test testTripleDesDocumentCipher skipped as "
                + "necessary algorithms not available"
            );
        }
    }

    /*
     * Test a Cipher Reference
     */
    @Test
    public void testSameDocumentCipherReference() throws Exception {

        if (haveISOPadding) {
            final Document d = TestUtils.newDocument();

            final Element docElement = d.createElement("EncryptedDoc");
            d.appendChild(docElement);

            // Create the XMLCipher object
            cipher = XMLCipher.getInstance();

            final EncryptedData ed =
                cipher.createEncryptedData(CipherData.REFERENCE_TYPE,
                                           "#CipherTextId");
            final EncryptionMethod em =
                cipher.createEncryptionMethod(XMLCipher.AES_128);

            ed.setEncryptionMethod(em);

            final org.apache.xml.security.encryption.Transforms xencTransforms =
                cipher.createTransforms(d);
            ed.getCipherData().getCipherReference().setTransforms(xencTransforms);
            final org.apache.xml.security.transforms.Transforms dsTransforms =
                xencTransforms.getDSTransforms();

            // An XPath transform
            final XPathContainer xpc = new XPathContainer(d);
            xpc.setXPath("self::text()[parent::CipherText[@Id=\"CipherTextId\"]]");
            dsTransforms.addTransform(
                org.apache.xml.security.transforms.Transforms.TRANSFORM_XPATH,
                xpc.getElementPlusReturns()
            );

            // Add a Base64 Transforms
            dsTransforms.addTransform(
                org.apache.xml.security.transforms.Transforms.TRANSFORM_BASE64_DECODE
            );

            final Element ee = cipher.martial(d, ed);

            docElement.appendChild(ee);

            // Add the cipher text
            final Element encryptedElement = d.createElement("CipherText");
            encryptedElement.setAttributeNS(null, "Id", "CipherTextId");
            encryptedElement.setIdAttributeNS(null, "Id", true);
            encryptedElement.appendChild(d.createTextNode(tstBase64EncodedString));
            docElement.appendChild(encryptedElement);
            // dump(d);

            // Now the decrypt, with a brand new cipher
            final XMLCipher cipherDecrypt = XMLCipher.getInstance();
            final Key key = new SecretKeySpec("abcdefghijklmnop".getBytes(StandardCharsets.US_ASCII), "AES");

            cipherDecrypt.init(XMLCipher.DECRYPT_MODE, key);
            final byte[] decryptBytes = cipherDecrypt.decryptToByteArray(ee);

            assertEquals("A test encrypted secret",
                        new String(decryptBytes, StandardCharsets.US_ASCII));
        } else {
            LOG.warn(
                "Test testSameDocumentCipherReference skipped as "
                + "necessary algorithms not available"
            );
        }
    }

    /*
     * Test physical representation of decrypted element, see SANTUARIO-309
     */
    @Test
    public void testPhysicalRepresentation() throws Exception {

        if (haveISOPadding) {
            final byte[] bits192 = "abcdefghijklmnopqrstuvwx".getBytes();
            final DESedeKeySpec keySpec = new DESedeKeySpec(bits192);
            final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            final SecretKey secretKey = keyFactory.generateSecret(keySpec);

            // Test inherited namespaces don't add extra attributes
            // Test unused namespaces are preserved
            final String DATA1 = "<ns:root xmlns:ns=\"ns.com\"><ns:elem xmlns:ns2=\"ns2.com\">11</ns:elem></ns:root>";
            Document doc = null;
            try (InputStream is = new ByteArrayInputStream(DATA1.getBytes(StandardCharsets.UTF_8))) {
                doc = XMLUtils.read(is, false);
            }
            Element elem = (Element)doc.getDocumentElement().getFirstChild();

            XMLCipher dataCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            dataCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);
            dataCipher.doFinal(doc, elem);

            Element encrElem = (Element)doc.getDocumentElement().getFirstChild();
            assertEquals("EncryptedData", encrElem.getLocalName());

            XMLCipher deCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            deCipher.init(XMLCipher.DECRYPT_MODE, secretKey);
            deCipher.doFinal(doc, encrElem);

            Element decrElem = (Element)doc.getDocumentElement().getFirstChild();
            assertEquals("ns:elem", decrElem.getNodeName());
            assertEquals("ns.com", decrElem.getNamespaceURI());
            assertEquals(1, decrElem.getAttributes().getLength());
            Attr attr = (Attr)decrElem.getAttributes().item(0);
            assertEquals("xmlns:ns2", attr.getName());
            assertEquals("ns2.com", attr.getValue());

            // Test default namespace undeclaration is preserved
            final String DATA2 = "<ns:root xmlns=\"defns.com\" xmlns:ns=\"ns.com\"><elem xmlns=\"\">11</elem></ns:root>";
            try (InputStream is = new ByteArrayInputStream(DATA2.getBytes(StandardCharsets.UTF_8))) {
                doc = XMLUtils.read(is, false);
            }
            elem = (Element)doc.getDocumentElement().getFirstChild();

            dataCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            dataCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);
            dataCipher.doFinal(doc, elem);

            encrElem = (Element)doc.getDocumentElement().getFirstChild();
            assertEquals("EncryptedData", encrElem.getLocalName());

            deCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            deCipher.init(XMLCipher.DECRYPT_MODE, secretKey);
            deCipher.doFinal(doc, encrElem);

            decrElem = (Element)doc.getDocumentElement().getFirstChild();
            assertEquals("elem", decrElem.getNodeName());
            assertNull(decrElem.getNamespaceURI());
            assertEquals(1, decrElem.getAttributes().getLength());
            attr = (Attr)decrElem.getAttributes().item(0);
            assertEquals("xmlns", attr.getName());
            assertEquals("", attr.getValue());

            // Test comments and PIs are not treated specially when serializing element content.
            // Other c14n algorithms add a newline after comments and PIs, when they are before or after the document element.
            final String DATA3 = "<root><!--comment1--><?pi1 target1?><elem/><!--comment2--><?pi2 target2?></root>";
            try (InputStream is = new ByteArrayInputStream(DATA3.getBytes(StandardCharsets.UTF_8))) {
                doc = XMLUtils.read(is, false);
            }
            elem = doc.getDocumentElement();

            dataCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            dataCipher.init(XMLCipher.ENCRYPT_MODE, secretKey);
            dataCipher.doFinal(doc, elem, true);

            encrElem = (Element)elem.getFirstChild();
            assertEquals("EncryptedData", encrElem.getLocalName());
            assertNull(encrElem.getNextSibling());

            deCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
            deCipher.init(XMLCipher.DECRYPT_MODE, secretKey);
            deCipher.doFinal(doc, encrElem);

            Node n = elem.getFirstChild();
            assertEquals(Node.COMMENT_NODE, n.getNodeType());
            n = n.getNextSibling();
            assertEquals(Node.PROCESSING_INSTRUCTION_NODE, n.getNodeType());
            n = n.getNextSibling();
            assertEquals(Node.ELEMENT_NODE, n.getNodeType());
            n = n.getNextSibling();
            assertEquals(Node.COMMENT_NODE, n.getNodeType());
            n = n.getNextSibling();
            assertEquals(Node.PROCESSING_INSTRUCTION_NODE, n.getNodeType());
            n = n.getNextSibling();
            assertNull(n);
        } else {
            LOG.warn(
                "Test testPhysicalRepresentation skipped as "
                + "necessary algorithms not available"
            );
        }
    }

    @Test
    public void testSerializedData() throws Exception {
        if (!haveISOPadding) {
            LOG.warn("Test testSerializedData skipped as necessary algorithms not available");
            return;
        }

        final byte[] bits128 = {
                          (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13,
                          (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
                          (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B,
                          (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F};
        final Key key = new SecretKeySpec(bits128, "AES");

        final Document d = document(); // source
        final Element e = (Element) d.getElementsByTagName(element()).item(index());

        // encrypt
        cipher = XMLCipher.getInstance(XMLCipher.AES_128);
        cipher.init(XMLCipher.ENCRYPT_MODE, key);

        // serialize element ...
        final Canonicalizer canon =
            Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        canon.canonicalizeSubtree(e, baos);
        baos.close();
        final String before = baos.toString(StandardCharsets.UTF_8.name());

        final byte[] serialized = baos.toByteArray();
        EncryptedData encryptedData = null;
        try (InputStream is = new ByteArrayInputStream(serialized)) {
            encryptedData = cipher.encryptData(d, EncryptionConstants.TYPE_ELEMENT, is);
        }

        //decrypt
        final XMLCipher dcipher = XMLCipher.getInstance(XMLCipher.AES_128);
        dcipher.init(XMLCipher.DECRYPT_MODE, key);
        final String algorithm = encryptedData.getEncryptionMethod().getAlgorithm();
        assertEquals(XMLCipher.AES_128, algorithm);
        final byte[] bytes = dcipher.decryptToByteArray(dcipher.martial(encryptedData));
        final String after = new String(bytes, StandardCharsets.UTF_8);
        assertEquals(before, after);

        // test with null type
        try (InputStream is = new ByteArrayInputStream(serialized)) {
            encryptedData = cipher.encryptData(d, null, is);
        }
    }

    @Test
    public void testEncryptedKeyWithRecipient() throws Exception {
        String filename =
            "src/test/resources/org/apache/xml/security/encryption/encryptedKey.xml";
        if (basedir != null && basedir.length() != 0) {
            filename = basedir + "/" + filename;
        }
        final File f = new File(filename);

        final Document document = XMLUtils.read(new FileInputStream(f), false);

        final XMLCipher keyCipher = XMLCipher.getInstance();
        keyCipher.init(XMLCipher.UNWRAP_MODE, null);

        final NodeList ekList =
            document.getElementsByTagNameNS(
                EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTEDKEY
            );
        for (int i = 0; i < ekList.getLength(); i++) {
            final EncryptedKey ek =
                keyCipher.loadEncryptedKey(document, (Element) ekList.item(i));
            assertNotNull(ek.getRecipient());
        }
    }

    @Test
    public void testEecryptToByteArray() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        final KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(128);
        final Key key = keygen.generateKey();

        final Document document = document();

        final XMLCipher cipher = XMLCipher.getInstance(XMLCipher.AES_128_GCM);
        cipher.init(XMLCipher.ENCRYPT_MODE, key);
        cipher.getEncryptedData();

        final Document encrypted = cipher.doFinal(document, document);

        final XMLCipher xmlCipher = XMLCipher.getInstance();
        xmlCipher.init(XMLCipher.DECRYPT_MODE, key);
        final Element encryptedData = (Element) encrypted.getElementsByTagNameNS(EncryptionConstants.EncryptionSpecNS, EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);

        xmlCipher.decryptToByteArray(encryptedData);
    }

    @Test
    public void testMultipleKEKs() throws Exception {

        final Document d = document(); // source
        Document ed = null;
        Document dd = null;
        final Element e = (Element) d.getElementsByTagName(element()).item(index());
        Element ee = null;

        String source = null;
        String target = null;

        if (haveISOPadding && haveKeyWraps) {
            source = toString(d);

            // Set up Key Encryption Key no. 1
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(192);
            final Key kek1 = keygen.generateKey();

            // Set up Key Encryption Key no. 2
            final Key kek2 = keygen.generateKey();

            // Generate a traffic key
            keygen = KeyGenerator.getInstance("AES");
            keygen.init(128);
            Key key = keygen.generateKey();

            cipher = XMLCipher.getInstance(XMLCipher.AES_192_KeyWrap);
            cipher.init(XMLCipher.WRAP_MODE, kek1);
            final EncryptedKey encryptedKey1 = cipher.encryptKey(d, key);

            cipher.init(XMLCipher.WRAP_MODE, kek2);
            final EncryptedKey encryptedKey2 = cipher.encryptKey(d, key);

            // encrypt
            cipher = XMLCipher.getInstance(XMLCipher.AES_128);
            cipher.init(XMLCipher.ENCRYPT_MODE, key);
            final EncryptedData builder = cipher.getEncryptedData();

            KeyInfo builderKeyInfo = builder.getKeyInfo();
            if (builderKeyInfo == null) {
                builderKeyInfo = new KeyInfo(d);
                builder.setKeyInfo(builderKeyInfo);
            }

            builderKeyInfo.add(encryptedKey1);
            builderKeyInfo.add(encryptedKey2);

            ed = cipher.doFinal(d, e);

            //decrypt
            key = null;
            ee = (Element) ed.getElementsByTagName("xenc:EncryptedData").item(0);
            cipher = XMLCipher.getInstance(XMLCipher.AES_128);
            cipher.init(XMLCipher.DECRYPT_MODE, null);
            cipher.setKEK(kek2);
            dd = cipher.doFinal(ed, ee);

            target = toString(dd);
            assertEquals(source, target);
        } else {
            LOG.warn(
                "Test testAES128ElementAES192KWCipherUsingKEK skipped as "
                + "necessary algorithms not available"
            );
        }
    }

    private String toString (Node n) throws Exception {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final Canonicalizer c14n = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);

        c14n.canonicalizeSubtree(n, baos);
        baos.flush();

        return baos.toString(StandardCharsets.UTF_8.name());
    }

    private Document document() throws XMLParserException, IOException {
        final File f = new File(documentName);
        return XMLUtils.read(new FileInputStream(f), false);
    }

    private String element() {
        return elementName;
    }

    private int index() {
        return Integer.parseInt(elementIndex);
    }

}