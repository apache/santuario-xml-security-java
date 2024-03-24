/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.test.dom.signature;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.extension.xades.XAdESSignatureProcessor;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.testutils.JDKTestUtils;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Element;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;

import static org.apache.jcp.xml.dsig.internal.dom.DOMUtils.setIdFlagToIdAttributes;


class XAdESSignatureTest {

    static {
        if (!org.apache.xml.security.Init.isInitialized()) {
            org.apache.xml.security.Init.init();
        }
    }

    private static final String ECDSA_KS =
            "src/test/resources/org/apache/xml/security/samples/input/keystore-chain.p12";
    private static final String ECDSA_KS_PASSWORD = "security";
    public static final String ECDSA_KS_TYPE = "PKCS12";


    @BeforeAll
    public static void beforeAll() {
        Security.insertProviderAt
                (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
        // Since JDK 15, the ECDSA algorithms are supported in the default java JCA provider.
        // Add BouncyCastleProvider only for java versions before JDK 15.
        boolean isNotJDK15up;
        try {
            int javaVersion = Integer.getInteger("java.specification.version", 0);
            isNotJDK15up = javaVersion < 15;
        } catch (NumberFormatException ex) {
            isNotJDK15up = true;
        }

        if (isNotJDK15up && Security.getProvider("BC") == null) {
            // Use reflection to add new BouncyCastleProvider
            try {
                Class<?> bouncyCastleProviderClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                Provider bouncyCastleProvider = (Provider) bouncyCastleProviderClass.getConstructor().newInstance();
                Security.addProvider(bouncyCastleProvider);
            } catch (ReflectiveOperationException e) {
                // BouncyCastle not installed, ignore
                System.out.println("BouncyCastle not installed!");
            }
        }
    }

    @ParameterizedTest
    @CsvSource({"rsa2048, http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "ed25519, http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519",
            "ed448, http://www.w3.org/2021/04/xmldsig-more#eddsa-ed448",
            "secp256r1, http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            "secp384r1, http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
            "secp521r1, http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"})
    void testXAdESSignatuire(String alias,String signatureAlgorithm) throws Exception {
        String jceAlgorithm = JCEMapper.translateURItoJCEID(signatureAlgorithm);
        Assumptions.assumeTrue(JDKTestUtils.isAlgorithmSupportedByJDK(jceAlgorithm));

        KeyStore keyStore = KeyStore.getInstance(ECDSA_KS_TYPE);
        keyStore.load(Files.newInputStream(Paths.get(ECDSA_KS)), ECDSA_KS_PASSWORD.toCharArray());

        PrivateKey privateKey =
                (PrivateKey) keyStore.getKey(alias, ECDSA_KS_PASSWORD.toCharArray());

        doVerify(doSign(privateKey, (X509Certificate) keyStore.getCertificate(alias),
                null, signatureAlgorithm, alias));
    }


    private byte[] doSign(PrivateKey privateKey, X509Certificate x509, PublicKey publicKey,
                          String sigAlgURI, String alias) throws Exception {

        // generate test document for signing element
        org.w3c.dom.Document doc = TestUtils.newDocument();
        doc.appendChild(doc.createComment(" Comment before "));
        Element root = doc.createElementNS("", "RootElement");
        doc.appendChild(root);
        root.appendChild(doc.createTextNode("Some simple text\n"));

        Element canonElem =
                XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttributeNS(
                null, Constants._ATT_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS
        );

        SignatureAlgorithm signatureAlgorithm =
                new SignatureAlgorithm(doc, sigAlgURI);
        XMLSignature sig =
                new XMLSignature(doc, null, signatureAlgorithm.getElement(), canonElem);
        root.appendChild(sig.getElement());
        doc.appendChild(doc.createComment(" Comment after "));


        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        sig.addDocument("", transforms, XMLCipher.SHA256);

        if (x509 != null) {
            sig.addKeyInfo(x509);
        } else {
            sig.addKeyInfo(publicKey);
        }
        // create XAdES processor
        XAdESSignatureProcessor xadesProcessor = new XAdESSignatureProcessor(x509);
        xadesProcessor.addReferenceTransformAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        sig.addPreProcessor(xadesProcessor);

        sig.sign(privateKey);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        //XMLUtils.outputDOMc14nWithComments(doc, bos);
        XMLUtils.outputDOM(doc.getDocumentElement(), bos);

        Files.write(Paths.get("target/XAdES-" + alias + ".xml"), bos.toByteArray());
        return bos.toByteArray();
    }

    private void doVerify(byte[] signedXml) throws Exception {
        try (InputStream is = new ByteArrayInputStream(signedXml)) {
            doVerify(is);
        }
    }

    private void doVerify(InputStream is) throws Exception {
        org.w3c.dom.Document doc = XMLUtils.read(is, false);
        setIdFlagToIdAttributes(doc.getDocumentElement());

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        String expression = "//ds:Signature[1]";
        Element sigElement =
                (Element) xpath.evaluate(expression, doc, XPathConstants.NODE);
        XMLSignature signature = new XMLSignature(sigElement, "");

        signature.addResourceResolver(new XPointerResourceResolver(sigElement));

        KeyInfo ki = signature.getKeyInfo();
        if (ki == null) {
            throw new RuntimeException("No keyinfo");
        }
        X509Certificate cert = signature.getKeyInfo().getX509Certificate();
        if (cert != null) {
            Assertions.assertTrue(signature.checkSignatureValue(cert));
        } else {
            Assertions.assertTrue(signature.checkSignatureValue(signature.getKeyInfo().getPublicKey()));
        }
    }
}
