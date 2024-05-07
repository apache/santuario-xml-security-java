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

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.encryption.AgreementMethod;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.keys.KeyInfoEnc;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.parser.XMLParserException;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.BeforeEach;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This is abstract class for with common methods for to test vectors
 * associated with the W3C XML Encryption 1.1 specification:
 * <p>
 * <a href="http://www.w3.org/2008/xmlsec/Drafts/xmlenc-core-11/test-cases/">
 *     xmlenc-core-11 test-cases</a>
 * <p>
 * The abstract class method can also be used with newer cryptographic algorithms used in
 * the same XML manner as the older algorithms specified in the
 * "W3C XML Encryption 1.1" specification
 */
public abstract class XMLEncryption11TestAbstract {

    protected static final DocumentBuilderFactory DEFAULT_DOCUMENT_BUILDER_FACTORY;
    private static final System.Logger LOG = System.getLogger(XMLEncryption11TestAbstract.class.getName());
    private static final String RESOURCE_FOLDER = "/org/w3c/www/interop/xmlenc-core-11/";
    private static String cardNumber;
    private static int nodeCount = 0;

    static {
        DEFAULT_DOCUMENT_BUILDER_FACTORY = DocumentBuilderFactory.newInstance();
        DEFAULT_DOCUMENT_BUILDER_FACTORY.setNamespaceAware(true);
    }

    protected final boolean isIBMJdK = System.getProperty("java.vendor").contains("IBM");
    protected boolean haveISOPadding;


    @BeforeEach
    public void beforeEach() throws XMLParserException, IOException, XPathExpressionException, TransformerException {
        // Create the comparison strings
        File f = resolveFile("src/test/resources/org/w3c/www/interop/xmlenc-core-11/plaintext.xml");
        Document doc = XMLUtils.read(f, false);

        cardNumber = retrieveCCNumber(doc);

        // Count the nodes in the document as a secondary test
        nodeCount = countNodes(doc);

        // Initialise the library
        org.apache.xml.security.Init.init();

        // Check what algorithms are available

        haveISOPadding = false;
        String algorithmId = JCEMapper.translateURItoJCEID(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

        if (algorithmId != null) {
            try {
                if (Cipher.getInstance(algorithmId) != null) {
                    haveISOPadding = true;
                }
            } catch (NoSuchAlgorithmException nsae) {
                //
            } catch (NoSuchPaddingException nspe) {
                //
            }
        }
    }

    /**
     * Method countNodes
     * <p>
     * Recursively count the number of nodes in the document
     *
     * @param n Node to count beneath
     */
    protected static int countNodes(Node n) {

        if (n == null) {
            return 0;  // Paranoia
        }

        int count = 1;  // Always count myself
        Node c = n.getFirstChild();

        while (c != null) {
            count += XMLEncryption11TestAbstract.countNodes(c);
            c = c.getNextSibling();
        }

        return count;
    }

    /**
     * Method retrieveCCNumber
     * <p>
     * Retrieve the credit card number from the payment info document
     *
     * @param doc The document to retrieve the card number from
     * @return The retrieved credit card number
     * @throws XPathExpressionException
     */
    protected static String retrieveCCNumber(Document doc)
            throws XPathExpressionException {

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        Map<String, String> namespace = new HashMap<>();
        namespace.put("x", "urn:example:po");
        DSNamespaceContext context = new DSNamespaceContext(namespace);
        xpath.setNamespaceContext(context);

        String expression = "//x:Number/text()";
        Node ccnumElt =
                (Node) xpath.evaluate(expression, doc, XPathConstants.NODE);

        if (ccnumElt != null) {
            return ccnumElt.getNodeValue();
        }

        return null;
    }

    public static byte[] hexFileContentByteArray(String fileName) throws IOException {
        byte[] data;
        try (InputStream is = XMLEncryption11TestAbstract.getResourceInputStream(fileName)) {
            int l = is.available() / 2;
            data = new byte[l];
            byte[] charByte = new byte[2];
            for (int i = 0; i < l; i++) {
                is.read(charByte);
                data[i] = (byte) ((Character.digit(charByte[0], 16) << 4)
                        + Character.digit(charByte[1], 16));
            }
        }
        return data;
    }

    /**
     * Method returns  a resource input stream object from resources folder '/org/w3c/www/interop/xmlenc-core-11/'
     *
     * @param resourceName name of the resource file
     * @return InputStream object or null if resource not found
     */
    public static InputStream getResourceInputStream(String resourceName) {
        return XMLEncryption11TestAbstract.getResourceInputStream(RESOURCE_FOLDER, resourceName);
    }

    public static InputStream getResourceInputStream(String resourceFolder, String resourceName) {
        return XMLEncryption11Test.class.getResourceAsStream(resourceFolder + resourceName);
    }

    protected KeyStore loadKeyStore(File keystore)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance(getKeystoreTypeForFileName(keystore.getName()));
        try (FileInputStream inputStream = new FileInputStream(keystore)) {
            keyStore.load(inputStream, "passwd".toCharArray());
        }
        return keyStore;
    }

    protected KeyStore loadKeyStoreFromResource(String filename, String passwd, String keystoreType)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {

        return loadKeyStoreFromResource(RESOURCE_FOLDER, filename, passwd, keystoreType);
    }

    protected KeyStore loadKeyStoreFromResource(String resourceFolder, String filename, String passwd, String
            keystoreType)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {

        KeyStore keyStore = KeyStore.getInstance(keystoreType);
        try (InputStream keystoreIS = XMLEncryption11TestAbstract.getResourceInputStream(resourceFolder, filename)) {
            keyStore.load(keystoreIS, passwd != null ? passwd.toCharArray() : null);
        }
        return keyStore;
    }

    protected Document loadDocumentFromResource(String resourceName)
            throws IOException, XMLParserException {

        try (InputStream dataXMLInputStream = XMLEncryption11TestAbstract.getResourceInputStream(resourceName)) {
            return XMLUtils.read(dataXMLInputStream, false);
        }
    }

    private String getKeystoreTypeForFileName(String filename) {
        return filename.toLowerCase().endsWith(".p12") ? "PKCS12" : "JKS";
    }

    /**
     * Method decryptElement
     * <p>
     * Take a key, encryption type and a file, find an encrypted element
     * decrypt it and return the resulting document
     *
     * @param decKey  The Key to use for decryption
     * @param encCert The certificate used to encrypt the key
     */
    protected Document decryptElement(File file, Key decKey, X509Certificate encCert) throws Exception {
        // Parse the document in question
        Document doc;
        try (FileInputStream inputStream = new FileInputStream(file)) {
            doc = XMLUtils.read(inputStream, false);
        }
        return decryptElement(doc, decKey, encCert);
    }

    /**
     * Method decryptElement
     * <p>
     * Take a key, encryption type and a document, find an encrypted element
     * decrypt it and return the resulting document
     *
     * @param doc     the XML document wrrapping the encrypted data
     * @param decKey  The Key to use for decryption
     * @param encCert The certificate used to encrypt the key
     */
    protected Document decryptElement(Document doc, Key decKey, X509Certificate encCert) throws Exception {
        // Create the XMLCipher element
        XMLCipher cipher = XMLCipher.getInstance();

        // Need to pre-load the Encrypted Data so we can get the key info
        Element ee = (Element) doc.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedData").item(0);
        cipher.init(XMLCipher.DECRYPT_MODE, null);
        EncryptedData encryptedData = cipher.loadEncryptedData(doc, ee);

        KeyInfo ki = encryptedData.getKeyInfo();
        EncryptedKey encryptedKey = ki.itemEncryptedKey(0);
        KeyInfoEnc kiek = (KeyInfoEnc) encryptedKey.getKeyInfo();
        if (kiek.containsAgreementMethod()) {
            AgreementMethod agreementMethod = kiek.itemAgreementMethod(0);
            kiek = agreementMethod.getRecipientKeyInfo();
        }
        X509Data certData = kiek.itemX509Data(0);
        XMLX509Certificate xcert = certData.itemCertificate(0);
        X509Certificate cert = xcert.getX509Certificate();
        assertEquals(encCert, cert);

        XMLCipher cipher2 = XMLCipher.getInstance();
        cipher2.init(XMLCipher.UNWRAP_MODE, decKey);
        Key key = cipher2.decryptKey(encryptedKey, encryptedData.getEncryptionMethod().getAlgorithm());

        cipher.init(XMLCipher.DECRYPT_MODE, key);
        return  cipher.doFinal(doc, ee);
    }

    /**
     * Method decryptElement
     * <p>
     * Take a key, encryption type and a document, find an encrypted element
     * decrypt it and return the resulting document
     *
     * @param doc     the XML document wrrapping the encrypted data
     * @param decKey  The Key to use for decryption
     * @param rsaCert The certificate used to encrypt the key
     */
    protected byte[] decryptData(Document doc, Key decKey, X509Certificate rsaCert) throws Exception {
        // Create the XMLCipher element
        XMLCipher cipher = XMLCipher.getInstance();

        // Need to pre-load the Encrypted Data so we can get the key info
        Element ee = (Element) doc.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "EncryptedData").item(0);
        cipher.init(XMLCipher.DECRYPT_MODE, null);
        EncryptedData encryptedData = cipher.loadEncryptedData(doc, ee);

        KeyInfo ki = encryptedData.getKeyInfo();
        EncryptedKey encryptedKey = ki.itemEncryptedKey(0);
        KeyInfoEnc kiek = (KeyInfoEnc) encryptedKey.getKeyInfo();
        if (kiek.containsAgreementMethod()) {
            AgreementMethod agreementMethod = kiek.itemAgreementMethod(0);
            kiek = agreementMethod.getRecipientKeyInfo();
        }
        X509Data certData = kiek.itemX509Data(0);
        XMLX509Certificate xcert = certData.itemCertificate(0);
        X509Certificate cert = xcert.getX509Certificate();
        assertEquals(rsaCert, cert);

        XMLCipher cipher2 = XMLCipher.getInstance();
        cipher2.init(XMLCipher.UNWRAP_MODE, decKey);
        Key key = cipher2.decryptKey(encryptedKey, encryptedData.getEncryptionMethod().getAlgorithm());

        cipher.init(XMLCipher.DECRYPT_MODE, key);
        return cipher.decryptToByteArray(ee);
    }

    /**
     * Create an EncryptedKey object using the given parameters.
     */
    protected EncryptedKey createEncryptedKey(
            Document doc,
            X509Certificate rsaCert,
            Key sessionKey,
            String encryptionMethod,
            String digestMethod,
            String mgfAlgorithm,
            byte[] oaepParams
    ) throws Exception {
        return createEncryptedKey(doc, rsaCert, sessionKey, encryptionMethod,
                digestMethod, mgfAlgorithm, oaepParams, null);
    }

    protected EncryptedKey createEncryptedKey(
            Document doc,
            X509Certificate rsaCert,
            Key sessionKey,
            String encryptionMethod,
            String digestMethod,
            String mgfAlgorithm,
            byte[] oaepParams,
            SecureRandom random
    ) throws Exception {
        // Create the XMLCipher element
        XMLCipher cipher = XMLCipher.getInstance(encryptionMethod, null, digestMethod);

        cipher.init(XMLCipher.WRAP_MODE, rsaCert.getPublicKey());

        EncryptedKey encryptedKey = cipher.encryptKey(doc, sessionKey, mgfAlgorithm, oaepParams, random);

        KeyInfo builderKeyInfo = encryptedKey.getKeyInfo();
        if (builderKeyInfo == null) {
            builderKeyInfo = new KeyInfo(doc);
            encryptedKey.setKeyInfo(builderKeyInfo);
        }

        X509Data x509Data = new X509Data(doc);
        x509Data.addCertificate(rsaCert);
        builderKeyInfo.add(x509Data);

        return encryptedKey;
    }

    protected EncryptedKey createEncryptedKey(
            Document doc,
            X509Certificate cert,
            Key sessionKey,
            String encryptionMethod,
            AlgorithmParameterSpec params,
            SecureRandom random
    ) throws Exception {
        // Create the XMLCipher element
        XMLCipher cipher = XMLCipher.getInstance(encryptionMethod, null, null);

        cipher.init(XMLCipher.WRAP_MODE, cert.getPublicKey());

        EncryptedKey encryptedKey = cipher.encryptKey(doc, sessionKey, params, random);

        KeyInfo builderKeyInfo = encryptedKey.getKeyInfo();
        if (builderKeyInfo == null) {
            builderKeyInfo = new KeyInfoEnc(doc);
            encryptedKey.setKeyInfo(builderKeyInfo);
        }

        X509Data x509Data = new X509Data(doc);
        x509Data.addCertificate(cert);
        if (builderKeyInfo instanceof KeyInfoEnc
                && ((KeyInfoEnc) builderKeyInfo).lengthAgreementMethod() > 0) {
            AgreementMethod agreementMethod = ((KeyInfoEnc) builderKeyInfo).itemAgreementMethod(0);
            agreementMethod.getRecipientKeyInfo().add(x509Data);
        } else {
            builderKeyInfo.add(x509Data);
        }
        return encryptedKey;
    }

    /**
     * Generate a session key using the given algorithm
     */
    protected Key getSessionKey(String encryptionMethod) throws Exception {
        // Generate a session key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        if (encryptionMethod.contains("128")) {
            keyGen.init(128);
        } else if (encryptionMethod.contains("192")) {
            keyGen.init(192);
        } else if (encryptionMethod.contains("256")) {
            keyGen.init(256);
        }
        return keyGen.generateKey();
    }

    /**
     * Encrypt a Document using the given parameters.
     */
    protected Document encryptDocument(
            Document doc,
            EncryptedKey encryptedKey,
            Key sessionKey,
            String encryptionMethod
    ) throws Exception {
        // Create the XMLCipher element
        XMLCipher cipher = XMLCipher.getInstance(encryptionMethod);

        cipher.init(XMLCipher.ENCRYPT_MODE, sessionKey);
        EncryptedData builder = cipher.getEncryptedData();

        KeyInfo builderKeyInfo = builder.getKeyInfo();
        if (builderKeyInfo == null) {
            builderKeyInfo = new KeyInfo(doc);
            builder.setKeyInfo(builderKeyInfo);
        }

        builderKeyInfo.add(encryptedKey);

        return cipher.doFinal(doc, doc.getDocumentElement());
    }

    /**
     * Encrypt a Document using the given parameters.
     */
    protected Document encryptData(
            Document doc,
            EncryptedKey encryptedKey,
            Key sessionKey,
            String encryptionMethod,
            InputStream dataToEncrypt
    ) throws Exception {
        // Create the XMLCipher element
        XMLCipher cipher = XMLCipher.getInstance(encryptionMethod);

        cipher.init(XMLCipher.ENCRYPT_MODE, sessionKey);
        EncryptedData builder = cipher.getEncryptedData();

        KeyInfo builderKeyInfo = builder.getKeyInfo();
        if (builderKeyInfo == null) {
            builderKeyInfo = new KeyInfo(doc);
            builder.setKeyInfo(builderKeyInfo);
        }

        builderKeyInfo.add(encryptedKey);

        EncryptedData endData = cipher.encryptData(doc, null, dataToEncrypt);
        Element encDataElement = cipher.martial(endData);
        doc.appendChild(encDataElement);
        return doc;
    }

    /*
     * Check we have retrieved a Credit Card number and that it is OK
     * Check that the document has the correct number of nodes
     */
    protected void checkDecryptedDoc(Document d, boolean doNodeCheck) throws Exception {

        String cc = XMLEncryption11TestAbstract.retrieveCCNumber(d);
        LOG.log(System.Logger.Level.DEBUG, "Retrieved Credit Card : " + cc);
        assertEquals(cardNumber, cc);

        // Test cc numbers
        if (doNodeCheck) {
            int myNodeCount = XMLEncryption11TestAbstract.countNodes(d);

            assertTrue(
                    myNodeCount > 0 && myNodeCount == nodeCount, "Node count mismatches"
            );
        }
    }

    protected String toString(Node n) throws Exception {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            Canonicalizer c14n = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);

            c14n.canonicalizeSubtree(n, baos);
            baos.flush();

            return baos.toString(StandardCharsets.UTF_8);
        }
    }
}
