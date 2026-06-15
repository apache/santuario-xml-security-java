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
package org.apache.xml.security.extension.xades;


import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.test.dom.signature.XPointerResourceResolver;
import org.apache.xml.security.testutils.JDKTestUtils;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.SelfSignedCertGenerator;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.apache.jcp.xml.dsig.internal.dom.DOMUtils.setIdFlagToIdAttributes;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests XAdES-B-B signing and structural validation using {@link XAdESSignatureProcessor}.
 * Certificates are generated programmatically; no external keystore files are required.
 */
class XAdESSignatureTest {

    static {
        if (!org.apache.xml.security.Init.isInitialized()) {
            org.apache.xml.security.Init.init();
        }
    }

    @BeforeAll
    static void setup() {
        Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    // -----------------------------------------------------------------
    // Parametrised sign + verify tests
    // -----------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @CsvSource({
            "RSA-2048,      SHA256withRSA,    http://www.w3.org/2001/04/xmldsig-more#rsa-sha256,     RSA,  2048",
            "ECDSA-256,     SHA256withECDSA,  http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256,   EC,   secp256r1",
            "ECDSA-384,     SHA384withECDSA,  http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384,   EC,   secp384r1",
            "ECDSA-521,     SHA512withECDSA,  http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512,   EC,   secp521r1",
            "EdDSA-Ed25519, Ed25519,          http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519,  EdDSA, Ed25519",
            "EdDSA-Ed448,   Ed448,            http://www.w3.org/2021/04/xmldsig-more#eddsa-ed448,    EdDSA, Ed448"
    })
    void signAndVerify(String label,
                       String certSigAlgorithm,
                       String xmlSigAlgorithmURI,
                       String keyAlgorithm,
                       String keyParam) throws Exception {
        String jceAlgorithm = JCEMapper.translateURItoJCEID(xmlSigAlgorithmURI);
        Assumptions.assumeTrue(JDKTestUtils.isAlgorithmSupportedByJDK(jceAlgorithm),
                label + " not supported by this JDK");

        KeyPair keyPair = generateKeyPair(keyAlgorithm, keyParam);
        X509Certificate cert = generateSelfSignedCert(keyPair, certSigAlgorithm, "CN=" + label);

        byte[] signed = sign(keyPair.getPrivate(), cert, xmlSigAlgorithmURI);
        verify(signed);
    }

    // -----------------------------------------------------------------
    // Structural assertions
    // -----------------------------------------------------------------

    @Test
    void signedDocumentHasCorrectXAdESStructure() throws Exception {
        KeyPair kp = generateRsaKeyPair();
        X509Certificate cert = generateSelfSignedCert(kp, "SHA256withRSA", "CN=StructureTest");

        byte[] signed = sign(kp.getPrivate(), cert, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        Document doc = parseDocument(signed);
        setIdFlagToIdAttributes(doc.getDocumentElement());

        XPath xpath = newXPath();

        // 1. One QualifyingProperties element is present
        NodeList qpNodes = (NodeList) xpath.evaluate(
                "//xades132:QualifyingProperties", doc, XPathConstants.NODESET);
        assertEquals(1, qpNodes.getLength(), "Expected exactly one QualifyingProperties");

        // 2. QualifyingProperties/@Target == "#" + signature Id
        Element sigEl = findSignatureElement(doc, xpath);
        String sigId = sigEl.getAttribute("Id");
        assertFalse(sigId.isEmpty(), "Signature must have an Id attribute");
        String target = ((Element) qpNodes.item(0)).getAttribute("Target");
        assertEquals("#" + sigId, target, "QualifyingProperties/@Target must reference the signature Id");

        // 3. ds:Reference with @Type=SignedProperties exists and points to SignedProperties
        String spRef = (String) xpath.evaluate(
                "//ds:Reference[@Type='" + XAdESConstants.REFERENCE_TYPE_SIGNEDPROPERTIES + "']/@URI",
                doc, XPathConstants.STRING);
        assertFalse(spRef.isEmpty(), "No ds:Reference with SignedProperties type found");
        String spId = spRef.substring(1); // strip leading '#'
        Element spEl = doc.getElementById(spId);
        assertNotNull(spEl, "SignedProperties element not found for id=" + spId);
        assertEquals("SignedProperties", spEl.getLocalName());

        // 4. SigningTime is present and parseable
        String signingTimeText = (String) xpath.evaluate(
                "//xades132:SigningTime", doc, XPathConstants.STRING);
        assertFalse(signingTimeText.isBlank(), "SigningTime must be present");
        OffsetDateTime signingTime = OffsetDateTime.parse(signingTimeText);
        assertNotNull(signingTime);

        // 5. CertDigest matches SHA-256 of the certificate
        String certDigestB64 = (String) xpath.evaluate(
                "//xades132:SigningCertificate/xades132:Cert/xades132:CertDigest/ds:DigestValue",
                doc, XPathConstants.STRING);
        assertFalse(certDigestB64.isBlank(), "CertDigest/DigestValue must be present");
        byte[] actualDigest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
        byte[] reportedDigest = Base64.getDecoder().decode(certDigestB64.trim());
        assertTrue(Arrays.equals(actualDigest, reportedDigest),
                "CertDigest must match SHA-256 of the signing certificate");
    }

    // -----------------------------------------------------------------
    // XAdES-B-B validator tests
    // -----------------------------------------------------------------

    @Test
    void xadesBBValidatorReportsValidResult() throws Exception {
        KeyPair kp = generateRsaKeyPair();
        X509Certificate cert = generateSelfSignedCert(kp, "SHA256withRSA", "CN=ValidatorTest");

        byte[] signed = sign(kp.getPrivate(), cert, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        Document doc = parseDocument(signed);
        setIdFlagToIdAttributes(doc.getDocumentElement());

        XPath xpath = newXPath();
        Element sigEl = findSignatureElement(doc, xpath);

        XMLSignature sig = new XMLSignature(sigEl, "");
        XAdESValidationResult result = new XAdESBBValidator().validate(sig, cert);

        assertTrue(result.isXAdESPresent(), "XAdES properties must be present");
        assertTrue(result.isValid(),
                "XAdES-B-B validation must pass; violations: " + result.getViolations());
        assertTrue(result.getViolations().isEmpty());
    }

    @Test
    void xadesBBValidatorDetectsWrongCertDigest() throws Exception {
        KeyPair kp = generateRsaKeyPair();
        X509Certificate cert = generateSelfSignedCert(kp, "SHA256withRSA", "CN=WrongDigestTest");

        byte[] signed = sign(kp.getPrivate(), cert, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        Document doc = parseDocument(signed);
        setIdFlagToIdAttributes(doc.getDocumentElement());

        // Use a different certificate for validation to trigger digest mismatch
        KeyPair otherKp = generateRsaKeyPair();
        X509Certificate otherCert = generateSelfSignedCert(otherKp, "SHA256withRSA", "CN=Other");

        XPath xpath = newXPath();
        Element sigEl = findSignatureElement(doc, xpath);
        XMLSignature sig = new XMLSignature(sigEl, "");

        XAdESValidationResult result = new XAdESBBValidator().validate(sig, otherCert);

        assertTrue(result.isXAdESPresent(), "XAdES properties must be present");
        assertFalse(result.isValid(), "Validation must fail when wrong certificate is provided");
        assertTrue(result.getViolations().stream()
                        .anyMatch(v -> v.contains("CertDigest")),
                "Violation must mention CertDigest; actual: " + result.getViolations());
    }

    @Test
    void xadesBBValidatorReportsNotPresentForPlainXmldsig() throws Exception {
        // Sign without XAdES processor — no QualifyingProperties
        KeyPair kp = generateRsaKeyPair();
        X509Certificate cert = generateSelfSignedCert(kp, "SHA256withRSA", "CN=NoXAdES");

        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("", "Root");
        doc.appendChild(root);

        XMLSignature sig = new XMLSignature(doc, null,
                XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        root.appendChild(sig.getElement());
        sig.addDocument("", null, XMLCipher.SHA256);
        sig.addKeyInfo(cert);
        sig.sign(kp.getPrivate());

        XAdESValidationResult result = new XAdESBBValidator().validate(sig, cert);

        assertFalse(result.isXAdESPresent(), "No XAdES should be reported for plain XMLDSig");
        assertFalse(result.isValid());
    }

    // -----------------------------------------------------------------
    // Negative test — tampered SignedProperties must fail verification
    // -----------------------------------------------------------------

    @Test
    void tamperedSignedPropertiesCausesVerificationFailure() throws Exception {
        KeyPair kp = generateRsaKeyPair();
        X509Certificate cert = generateSelfSignedCert(kp, "SHA256withRSA", "CN=TamperTest");

        byte[] signed = sign(kp.getPrivate(), cert, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        Document doc = parseDocument(signed);
        setIdFlagToIdAttributes(doc.getDocumentElement());

        // Tamper: change the SigningTime text
        XPath xpath = newXPath();
        Element signingTimeEl = (Element) xpath.evaluate(
                "//xades132:SigningTime", doc, XPathConstants.NODE);
        assertNotNull(signingTimeEl, "Need a SigningTime element to tamper");
        signingTimeEl.setTextContent("1970-01-01T00:00:00Z");

        // Serialise the tampered document
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLUtils.outputDOM(doc.getDocumentElement(), bos);

        // Verification must fail
        boolean valid = tryVerify(bos.toByteArray());
        assertFalse(valid, "Tampered SignedProperties must cause verification failure");
    }

    // -----------------------------------------------------------------
    // Helpers — signing
    // -----------------------------------------------------------------

    private byte[] sign(PrivateKey privateKey, X509Certificate cert,
                        String xmlSigAlgorithmURI) throws Exception {
        Document doc = TestUtils.newDocument();
        Element root = doc.createElementNS("", "RootElement");
        doc.appendChild(root);
        root.appendChild(doc.createTextNode("Content to sign"));

        Element c14nEl = XMLUtils.createElementInSignatureSpace(
                doc, Constants._TAG_CANONICALIZATIONMETHOD);
        c14nEl.setAttributeNS(null, Constants._ATT_ALGORITHM,
                Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        SignatureAlgorithm sigAlg = new SignatureAlgorithm(doc, xmlSigAlgorithmURI);
        XMLSignature sig = new XMLSignature(doc, null, sigAlg.getElement(), c14nEl);
        root.appendChild(sig.getElement());

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        sig.addDocument("", transforms, XMLCipher.SHA256);
        sig.addKeyInfo(cert);

        XAdESSignatureProcessor xades = XAdESSignatureProcessor.builder(cert)
                .addReferenceTransformAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
                .build();
        sig.addPreProcessor(xades);

        sig.sign(privateKey);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLUtils.outputDOM(doc.getDocumentElement(), bos);
        return bos.toByteArray();
    }

    // -----------------------------------------------------------------
    // Helpers — verification
    // -----------------------------------------------------------------

    private void verify(byte[] signedXml) throws Exception {
        assertTrue(tryVerify(signedXml), "Signature verification must succeed");
    }

    private boolean tryVerify(byte[] signedXml) throws Exception {
        Document doc = parseDocument(signedXml);
        setIdFlagToIdAttributes(doc.getDocumentElement());

        XPath xpath = newXPath();
        Element sigEl = findSignatureElement(doc, xpath);

        XMLSignature signature = new XMLSignature(sigEl, "");
        signature.addResourceResolver(new XPointerResourceResolver(sigEl));

        KeyInfo ki = signature.getKeyInfo();
        if (ki == null) {
            throw new IllegalStateException("No KeyInfo in signature");
        }

        X509Certificate cert = ki.getX509Certificate();
        boolean coreValid = cert != null
                ? signature.checkSignatureValue(cert)
                : signature.checkSignatureValue(ki.getPublicKey());

        if (!coreValid) {
            return false;
        }

        // Validate XAdES-B-B properties if present
        XAdESValidationResult xadesResult = new XAdESBBValidator().validate(signature, cert);
        if (xadesResult.isXAdESPresent() && !xadesResult.isValid()) {
            throw new AssertionError("XAdES-B-B validation failed: " + xadesResult.getViolations());
        }

        return true;
    }

    private Element findSignatureElement(Document doc, XPath xpath) throws Exception {
        return (Element) xpath.evaluate("//ds:Signature[1]", doc, XPathConstants.NODE);
    }

    // -----------------------------------------------------------------
    // Helpers — XPath
    // -----------------------------------------------------------------

    private XPath newXPath() {
        XPath xpath = XPathFactory.newInstance().newXPath();
        Map<String, String> ns = new HashMap<>();
        ns.put("ds", "http://www.w3.org/2000/09/xmldsig#");
        ns.put("xades132", XAdESConstants.XADES_V132_NS);
        xpath.setNamespaceContext(new DSNamespaceContext(ns));
        return xpath;
    }

    // -----------------------------------------------------------------
    // Helpers — document parsing
    // -----------------------------------------------------------------

    private Document parseDocument(byte[] xml) throws Exception {
        try (InputStream is = new ByteArrayInputStream(xml)) {
            return XMLUtils.read(is, false);
        }
    }

    // -----------------------------------------------------------------
    // Helpers — key & certificate generation
    // -----------------------------------------------------------------

    private KeyPair generateRsaKeyPair() throws Exception {
        return generateKeyPair("RSA", "2048");
    }

    private KeyPair generateKeyPair(String algorithm, String param) throws Exception {
        switch (algorithm) {
            case "RSA": {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(Integer.parseInt(param));
                return kpg.generateKeyPair();
            }
            case "EC": {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(new ECGenParameterSpec(param));
                return kpg.generateKeyPair();
            }
            case "EdDSA": {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(param);
                return kpg.generateKeyPair();
            }
            default:
                throw new IllegalArgumentException("Unknown key algorithm: " + algorithm);
        }
    }

    private X509Certificate generateSelfSignedCert(KeyPair keyPair,
                                                   String sigAlgorithm,
                                                   String subjectDN) throws Exception {
        return SelfSignedCertGenerator.generate(keyPair, sigAlgorithm, subjectDN, 365);
    }
}
