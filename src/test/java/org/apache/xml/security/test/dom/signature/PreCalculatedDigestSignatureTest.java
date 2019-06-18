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

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class PreCalculatedDigestSignatureTest {

    private static final Logger LOG = LoggerFactory.getLogger(PreCalculatedDigestSignatureTest.class);

    /**
     * External resource name to be signed
     */
    private static final String EXTERNAL_DOCUMENT_URI = "test.txt";

    /**
     * External resource pre-calculated digest value in base64
     */
    private static final String PRE_CALCULATED_DIGEST = "tYpuWTmktpzSwRM8cxRlZfY4aw4wqr4vkXKPs9lwxP4=";

    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final String ALIAS = "mullan";
    private String signatureFilePath;

    @TempDir
    public Path testFolder;
    private PrivateKey privateKey;
    private X509Certificate signingCert;

    @BeforeEach
    public void setUp() throws Exception {
        org.apache.xml.security.Init.init();
        signatureFilePath = getAbsolutePath("src/test/resources/org/apache/xml/security/samples/input/signatureWithExternalReference.xml");
        KeyStore keyStore = openKeyStore();
        privateKey = (PrivateKey) keyStore.getKey(ALIAS, PASSWORD);
        signingCert = (X509Certificate) keyStore.getCertificate(ALIAS);
    }

    @Test
    public void validateSignatureWithCorrectDigestShouldBeValid() throws Exception {
        XMLSignature signature = openSignature(signatureFilePath);
        //Add resource resolver for the external document (test.txt) with the pre-calculated digest (valid for this test)
        ExternalResourceResolver resolver = new ExternalResourceResolver(EXTERNAL_DOCUMENT_URI, PRE_CALCULATED_DIGEST);
        signature.addResourceResolver(resolver);
        boolean validSignature = validateSignature(signature);
        assertTrue(validSignature);
    }

    @Test
    public void validateSignatureWithWrongDigestShouldBeInvalid() throws Exception {
        XMLSignature signature = openSignature(signatureFilePath);
        //Add resource resolver for the external document (test.txt) with the pre-calculated digest (invalid for this test)
        ExternalResourceResolver resolver = new ExternalResourceResolver(EXTERNAL_DOCUMENT_URI, "BjVs1oFu54LZwQuUA+kHgZApH0pIc8PGOoo0YrLrNUI=");
        signature.addResourceResolver(resolver);
        boolean validSignature = validateSignature(signature);
        assertFalse(validSignature);
    }

    @Test
    public void createSignatureWithPreCalculatedDigestShouldBeValid() throws Exception {
        XMLSignature signature = createXmlSignature();

        //Add external URI. This is a detached Reference.
        signature.addDocument(EXTERNAL_DOCUMENT_URI, null, "http://www.w3.org/2001/04/xmlenc#sha256");
        //Add resource resolver for the external document with pre-calculated digest
        signature.addResourceResolver(new ExternalResourceResolver(EXTERNAL_DOCUMENT_URI, PRE_CALCULATED_DIGEST));

        signature.addKeyInfo(signingCert);
        signature.sign(privateKey);

        writeSignature(signature.getDocument());
        assertTrue(signature.checkSignatureValue(signingCert));
    }

    private XMLSignature openSignature(String signatureFile) throws Exception {
        Document document = XMLUtils.read(new FileInputStream(new File(signatureFile)), false);
        Element root = document.getDocumentElement();
        Element signatureDocument = (Element) root.getFirstChild();
        String baseURI = "";
        XMLSignature signature = new XMLSignature(signatureDocument, baseURI);
        return signature;
    }

    private boolean validateSignature(XMLSignature signature) throws XMLSecurityException {
        PublicKey publicKey = signature.getKeyInfo().getPublicKey();
        boolean validSignature = signature.checkSignatureValue(publicKey);
        LOG.debug("Is signature valid: " + validSignature);
        return validSignature;
    }

    private XMLSignature createXmlSignature() throws ParserConfigurationException, XMLSecurityException {
        Document signatureDocument = XMLUtils.newDocument();
        Element root = createSignatureRoot(signatureDocument);

        String baseURI = "";
        XMLSignature signature = new XMLSignature(signatureDocument, baseURI, XMLSignature.ALGO_ID_SIGNATURE_DSA);
        root.appendChild(signature.getElement());

        Transforms transforms = createTransformsForSignature(signatureDocument);
        signature.addDocument("", transforms, "http://www.w3.org/2001/04/xmlenc#sha256");
        return signature;
    }

    private Transforms createTransformsForSignature(Document signatureDocument) throws TransformationException {
        Transforms transforms = new Transforms(signatureDocument);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
        return transforms;
    }

    private Element createSignatureRoot(Document signatureDocument) {
        Element root = signatureDocument.createElementNS("http://www.apache.org/ns/#app1", "apache:RootElement");
        root.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:apache", "http://www.apache.org/ns/#app1");
        signatureDocument.appendChild(root);
        return root;
    }

    private void writeSignature(Document doc) throws IOException {
        String signatureFilePath = Files.createFile(testFolder.resolve("signature.xml")).toString();
        FileOutputStream fileOutputStream = null;
        try {
            fileOutputStream = new FileOutputStream(signatureFilePath);
            XMLUtils.outputDOMc14nWithComments(doc, fileOutputStream);
            LOG.debug("Wrote signature to " + signatureFilePath);
        } finally {
            fileOutputStream.close();
        }
    }

    private KeyStore openKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        FileInputStream fileInputStream = null;
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            fileInputStream = new FileInputStream(getAbsolutePath("src/test/resources/test.jks"));
            keyStore.load(fileInputStream, PASSWORD);
            return keyStore;
        } finally {
            fileInputStream.close();
        }
    }

    private String getAbsolutePath(String path) {
        String basedir = System.getProperty("basedir");
        if (basedir != null && !"".equals(basedir)) {
            path = basedir + "/" + path;
        }
        return path;
    }

    /**
     * Resolves external resources with pre-calculated digest.
     */
    public static class ExternalResourceResolver extends ResourceResolverSpi {

        private final String externalDocumentUri;
        private String preCalculatedDigest;

        /**
         * Constructor for resolving external resources with pre-calculated digest.
         *
         * @param externalDocumentUri external resource uri.
         * @param preCalculatedDigest pre-calculated digest of the external resource.
         */
        public ExternalResourceResolver(String externalDocumentUri, String preCalculatedDigest) {
            this.preCalculatedDigest = preCalculatedDigest;
            this.externalDocumentUri = externalDocumentUri;
        }

        @Override
        public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException {
            String documentUri = extractDocumentUri(context);
            XMLSignatureInput result = new XMLSignatureInput(preCalculatedDigest);
            result.setSourceURI(documentUri);
            result.setMIMEType("text/plain");
            return result;
        }

        @Override
        public boolean engineCanResolveURI(ResourceResolverContext context) {
            String documentUri = extractDocumentUri(context);
            return documentUri.equals(externalDocumentUri);
        }

        private String extractDocumentUri(ResourceResolverContext context) {
            Attr uriAttr = context.attr;
            return uriAttr.getNodeValue();
        }
    }
}