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
package org.apache.xml.security.test.javax.xml.crypto.dsig;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.apache.xml.security.testutils.JDKTestUtils;
import org.apache.xml.security.testutils.SelfSignedCertGenerator;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.AfterAll;
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
 * Tests for ML-DSA (FIPS 204) XML digital signatures via the
 * {@code javax.xml.crypto.dsig.XMLSignatureFactory} DOM API.
 *
 * <p>Key pairs and self-signed certificates are generated on the fly for each of
 * ML-DSA-44/65/87 via {@link SelfSignedCertGenerator}, rather than loading a
 * pre-generated keystore committed as a binary test resource (see SANTUARIO-634).
 * The ML-DSA JCA provider is the JDK's own from Java 24 on (JEP 497); on older
 * JDKs the tests fall back to BouncyCastle via the shared test auxiliary provider,
 * and are skipped if neither is available. Compile-time BC classes are deliberately
 * avoided so the default build (without {@code -P bouncycastle}) still compiles cleanly.
 *
 * <p>On a pre-24 JDK, run with the Maven {@code bouncycastle} profile:
 * <pre>mvn test -Dtest=XMLSignatureMLDSATest -P bouncycastle</pre>
 */
class XMLSignatureMLDSATest extends XMLSignatureAbstract {

    static final char[] KEY_PASSWORD = "security".toCharArray();

    private static boolean mlDsaAvailable;
    private static boolean auxProviderRegistered;
    private static KeyStore keyStore;

    @BeforeAll
    static void setUp() {
        Security.insertProviderAt(
                new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);

        // The JDK ships ML-DSA (JEP 497) from Java 24 on; before that it needs BouncyCastle.
        // Prefer whatever provider the platform already offers, and only pull in the shared
        // test auxiliary provider (BouncyCastle) when running on a pre-24 JDK without it,
        // so the tests exercise the JDK implementation where one is available.
        if (JDKTestUtils.getJDKVersion() < 24 && Security.getProvider("BC") == null) {
            if (JDKTestUtils.getAuxiliaryProvider() == null) {
                mlDsaAvailable = false;
                return;
            }
            JDKTestUtils.registerAuxiliaryProvider();
            auxProviderRegistered = true;
        }

        try {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            for (String alias : new String[]{"ml-dsa-44", "ml-dsa-65", "ml-dsa-87"}) {
                String jcaAlgorithm = alias.toUpperCase();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(jcaAlgorithm);
                KeyPair keyPair = kpg.generateKeyPair();
                X509Certificate cert = SelfSignedCertGenerator.generate(
                        keyPair, jcaAlgorithm, "CN=Test " + jcaAlgorithm + ",O=Apache Santuario,C=US", 365);
                keyStore.setKeyEntry(alias, keyPair.getPrivate(), KEY_PASSWORD, new Certificate[]{cert});
            }
            mlDsaAvailable = true;
        } catch (Exception e) {
            mlDsaAvailable = false;
        }
    }

    @AfterAll
    static void tearDown() {
        if (auxProviderRegistered) {
            JDKTestUtils.unregisterAuxiliaryProvider();
        }
    }

    @ParameterizedTest
    @CsvSource({
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_44 + ",ml-dsa-44",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_65 + ",ml-dsa-65",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_87 + ",ml-dsa-87",
    })
    void testMLDSASignAndVerify(String signatureAlgorithmURI, String alias) throws Exception {
        Assumptions.assumeTrue(mlDsaAvailable, "ML-DSA requires JDK 24+ or BouncyCastle 1.81+");
        byte[] signedXml = doSignWithJcpApi(signatureAlgorithmURI, alias, false);
        Assertions.assertNotNull(signedXml);
        assertValidSignatureWithJcpApi(signedXml, false);
    }

    @ParameterizedTest
    @CsvSource({
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_44 + ",ml-dsa-44",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_65 + ",ml-dsa-65",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_87 + ",ml-dsa-87",
    })
    void testMLDSATamperedSignatureRejected(String signatureAlgorithmURI, String alias) throws Exception {
        Assumptions.assumeTrue(mlDsaAvailable, "ML-DSA requires JDK 24+ or BouncyCastle 1.81+");
        byte[] signedXml = doSignWithJcpApi(signatureAlgorithmURI, alias, false);

        byte[] tamperedXml = flipByteInSignatureValue(signedXml);

        boolean coreValidity = validateSignatureWithJcpApi(tamperedXml, new KeySelectors.RawX509KeySelector());
        Assertions.assertFalse(coreValidity, "A tampered SignatureValue must not validate");
    }

    @ParameterizedTest
    @CsvSource({
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_44 + ",ml-dsa-44",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_65 + ",ml-dsa-65",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_87 + ",ml-dsa-87",
    })
    void testMLDSAWrongPublicKeyRejected(String signatureAlgorithmURI, String alias) throws Exception {
        Assumptions.assumeTrue(mlDsaAvailable, "ML-DSA requires JDK 24+ or BouncyCastle 1.81+");
        byte[] signedXml = doSignWithJcpApi(signatureAlgorithmURI, alias, false);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alias.toUpperCase());
        PublicKey wrongPublicKey = kpg.generateKeyPair().getPublic();

        KeySelector wrongKeySelector = new KeySelector() {
            @Override
            public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method,
                                             XMLCryptoContext context) throws KeySelectorException {
                return () -> wrongPublicKey;
            }
        };

        boolean coreValidity = validateSignatureWithJcpApi(signedXml, wrongKeySelector);
        Assertions.assertFalse(coreValidity, "Verification against the wrong public key must not validate");
    }

    /**
     * Decodes the &lt;SignatureValue&gt; text content, flips one byte, and re-serializes -
     * simulates an attacker (or transport bug) corrupting the signature bytes while leaving
     * the rest of the document, including the embedded certificate, intact.
     */
    private byte[] flipByteInSignatureValue(byte[] signedXml) throws Exception {
        Document doc;
        try (ByteArrayInputStream is = new ByteArrayInputStream(signedXml)) {
            doc = XMLUtils.read(is, false);
        }
        NodeList sigValues = doc.getElementsByTagNameNS(Constants.SignatureSpecNS, "SignatureValue");
        Assertions.assertEquals(1, sigValues.getLength(), "Expected exactly one SignatureValue element");
        Element sigValueElement = (Element) sigValues.item(0);

        byte[] sigBytes = Base64.getMimeDecoder().decode(sigValueElement.getTextContent());
        sigBytes[sigBytes.length / 2] ^= (byte) 0xFF;
        String tamperedBase64 = Base64.getEncoder().encodeToString(sigBytes);

        // Replace the SignatureValue element's text content in place
        NodeList children = sigValueElement.getChildNodes();
        for (int i = children.getLength() - 1; i >= 0; i--) {
            sigValueElement.removeChild(children.item(i));
        }
        Text newText = doc.createTextNode(tamperedBase64);
        sigValueElement.appendChild(newText);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(doc, bos);
        return bos.toByteArray();
    }

    // ===== ML-DSA SignatureContext rejection =====
    // draft-eastlake-rfc9231bis-xmlsec-uris-09 section 3.3.15 defines an optional
    // dsig-more:SignatureContext element (carried in a ds:Object). java.security.Signature
    // cannot pass a context to ML-DSA (JEP 497 non-goal), so the library must refuse to
    // create or verify such a signature rather than silently ignoring the context.

    private static final String SIGNATURE_CONTEXT_NS = "http://www.w3.org/2026/08/xmldsig-more#";

    @ParameterizedTest
    @CsvSource({
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_44 + ",ml-dsa-44",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_65 + ",ml-dsa-65",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_87 + ",ml-dsa-87",
    })
    void testMLDSAJcpSignRejectsSignatureContext(String signatureAlgorithmURI, String alias) throws Exception {
        Assumptions.assumeTrue(mlDsaAvailable, "ML-DSA requires JDK 24+ or BouncyCastle 1.81+");

        Document doc = TestUtils.newDocument();
        Element root = doc.createElement("RootElement");
        doc.appendChild(root);
        Element signed = doc.createElement("SignedElement");
        signed.setAttribute("id", "e1");
        signed.appendChild(doc.createTextNode("Some data to sign"));
        root.appendChild(signed);

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, KEY_PASSWORD);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        Reference ref = fac.newReference("#e1", fac.newDigestMethod(DigestMethod.SHA256, null),
            Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
            null, null);
        SignedInfo si = fac.newSignedInfo(
            fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
            fac.newSignatureMethod(signatureAlgorithmURI, null),
            Collections.singletonList(ref));

        Element ctx = doc.createElementNS(SIGNATURE_CONTEXT_NS, "dsig-more:SignatureContext");
        ctx.setTextContent(Base64.getEncoder().encodeToString("email-signature".getBytes(StandardCharsets.UTF_8)));
        XMLObject obj = fac.newXMLObject(
            Collections.singletonList(new DOMStructure(ctx)), null, null, null);

        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(
            kif.newX509Data(Collections.singletonList(cert))));

        javax.xml.crypto.dsig.XMLSignature sig =
            fac.newXMLSignature(si, ki, Collections.singletonList(obj), null, null);
        DOMSignContext sc = new DOMSignContext(privateKey, doc.getDocumentElement());
        sc.setIdAttributeNS(signed, null, "id");

        javax.xml.crypto.dsig.XMLSignatureException ex = Assertions.assertThrows(
            javax.xml.crypto.dsig.XMLSignatureException.class, () -> sig.sign(sc));
        Assertions.assertTrue(ex.getMessage().contains("SignatureContext"), ex.getMessage());
    }

    @ParameterizedTest
    @CsvSource({
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_44 + ",ml-dsa-44",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_65 + ",ml-dsa-65",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_87 + ",ml-dsa-87",
    })
    void testMLDSAJcpVerifyRejectsSignatureContext(String signatureAlgorithmURI, String alias) throws Exception {
        Assumptions.assumeTrue(mlDsaAvailable, "ML-DSA requires JDK 24+ or BouncyCastle 1.81+");
        byte[] signedXml = doSignWithJcpApi(signatureAlgorithmURI, alias, false);
        byte[] withContext = injectSignatureContext(signedXml);

        Assertions.assertThrows(javax.xml.crypto.dsig.XMLSignatureException.class,
            () -> validateSignatureWithJcpApi(withContext, new KeySelectors.RawX509KeySelector()));
    }

    @ParameterizedTest
    @CsvSource({
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_44 + ",ml-dsa-44",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_65 + ",ml-dsa-65",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_87 + ",ml-dsa-87",
    })
    void testMLDSANativeSignRejectsSignatureContext(String signatureAlgorithmURI, String alias) throws Exception {
        Assumptions.assumeTrue(mlDsaAvailable, "ML-DSA requires JDK 24+ or BouncyCastle 1.81+");

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, KEY_PASSWORD);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("", "RootElement");
        doc.appendChild(root);
        root.appendChild(doc.createTextNode("Some simple text"));

        Element canon = XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canon.setAttributeNS(null, Constants._ATT_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        SignatureAlgorithm sigAlg = new SignatureAlgorithm(doc, signatureAlgorithmURI);
        XMLSignature sig = new XMLSignature(doc, null, sigAlg.getElement(), canon);
        root.appendChild(sig.getElement());

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        sig.addDocument("", transforms, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
        sig.addKeyInfo(cert);

        ObjectContainer obj = new ObjectContainer(doc);
        Element ctx = doc.createElementNS(SIGNATURE_CONTEXT_NS, "dsig-more:SignatureContext");
        ctx.setTextContent(Base64.getEncoder().encodeToString("email-signature".getBytes(StandardCharsets.UTF_8)));
        obj.appendChild(ctx);
        sig.appendObject(obj);

        org.apache.xml.security.signature.XMLSignatureException ex = Assertions.assertThrows(
            org.apache.xml.security.signature.XMLSignatureException.class, () -> sig.sign(privateKey));
        Assertions.assertTrue(ex.getMessage().contains("SignatureContext"), ex.getMessage());
    }

    @ParameterizedTest
    @CsvSource({
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_44 + ",ml-dsa-44",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_65 + ",ml-dsa-65",
        XMLSignature.ALGO_ID_SIGNATURE_MLDSA_87 + ",ml-dsa-87",
    })
    void testMLDSANativeVerifyRejectsSignatureContext(String signatureAlgorithmURI, String alias) throws Exception {
        Assumptions.assumeTrue(mlDsaAvailable, "ML-DSA requires JDK 24+ or BouncyCastle 1.81+");
        byte[] signedXml = doSignWithJcpApi(signatureAlgorithmURI, alias, false);
        byte[] withContext = injectSignatureContext(signedXml);

        Document doc;
        try (ByteArrayInputStream is = new ByteArrayInputStream(withContext)) {
            doc = XMLUtils.read(is, false);
        }
        Element sigElement = (Element) doc.getElementsByTagNameNS(
            Constants.SignatureSpecNS, "Signature").item(0);
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
        XMLSignature signature = new XMLSignature(sigElement, "");

        org.apache.xml.security.signature.XMLSignatureException ex = Assertions.assertThrows(
            org.apache.xml.security.signature.XMLSignatureException.class,
            () -> signature.checkSignatureValue(cert));
        Assertions.assertTrue(ex.getMessage().contains("SignatureContext"), ex.getMessage());
    }

    /**
     * Inserts a {@code <ds:Object><dsig-more:SignatureContext>...</dsig-more:SignatureContext></ds:Object>}
     * as the last child of the {@code ds:Signature} element, simulating a signature that carries an
     * ML-DSA signature context.
     */
    private byte[] injectSignatureContext(byte[] signedXml) throws Exception {
        Document doc;
        try (ByteArrayInputStream is = new ByteArrayInputStream(signedXml)) {
            doc = XMLUtils.read(is, false);
        }
        Element sig = (Element) doc.getElementsByTagNameNS(
            Constants.SignatureSpecNS, "Signature").item(0);
        Assertions.assertNotNull(sig, "Expected a ds:Signature element");

        String sigPrefix = sig.getPrefix();
        String objectQName = sigPrefix == null ? "Object" : sigPrefix + ":Object";
        Element object = doc.createElementNS(Constants.SignatureSpecNS, objectQName);
        Element ctx = doc.createElementNS(SIGNATURE_CONTEXT_NS, "dsig-more:SignatureContext");
        ctx.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:dsig-more", SIGNATURE_CONTEXT_NS);
        ctx.setTextContent(Base64.getEncoder().encodeToString("email-signature".getBytes(StandardCharsets.UTF_8)));
        object.appendChild(ctx);
        sig.appendChild(object);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(doc, bos);
        return bos.toByteArray();
    }

    @Override
    KeyStore getKeyStore() {
        return keyStore;
    }

    @Override
    char[] getKeyPassword() {
        return KEY_PASSWORD;
    }
}
