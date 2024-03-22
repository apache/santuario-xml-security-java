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

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.apache.xml.security.testutils.JDKTestUtils;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * Unit test for brainpool javax.xml.crypto.dsig.XMLSignature creation. The tests require BouncyCastle provider to be
 * activated. Please note also the setting of the system property "org.jcp.xml.dsig.internal.dom.SignatureProvider" to
 * provide signature provider for the XMLSignature creation. SunJCE provider does not support brainpool curves signatures
 * from JDK 15+
 * <p />
 * To execute just this tests class run the following command:
 * <code>mvn test -Dtest=XMLSignatureBrainpoolTest -P bouncycastle</code>
 * or to test it during the build start the project with the profile "bouncycastle"
 * <code>mvn clean install -P bouncycastle</code>
 */
class XMLSignatureBrainpoolTest {
    protected static final System.Logger LOG = System.getLogger(XMLSignatureBrainpoolTest.class.getName());
    private static final String DOM_SIGNATURE_PROVIDER = "org.jcp.xml.dsig.internal.dom.SignatureProvider";

    private static final String ECDSA_JKS =
            "src/test/resources/org/apache/xml/security/samples/input/ecbrainpool.p12";
    private static final String ECDSA_KS_PASSWORD = "security";
    public static final String ECDSA_KS_TYPE = "PKCS12";

    private final SignatureValidator testInstance = new SignatureValidator();

    @BeforeAll
    static void initProvider() {
        Assumptions.assumeTrue(JDKTestUtils.getAuxiliaryProvider() != null, "BouncyCastle is required for this test");
        Assumptions.assumeFalse("IBM Corporation".equals(System.getProperty("java.vendor")), "Skip for IBM JDK" );

        Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    @AfterAll
    static void removeProvider() {
        Security.removeProvider(org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI.class.getName());
    }

    @ParameterizedTest
    @CsvSource({"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256, brainpoolP256r1",
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256, brainpoolP384r1",
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256, brainpoolP512r1"
    })
    void createEdDSASignatureTest(String signatureAlgorithm, String alias) throws Exception {
        byte[] buff = doSign(signatureAlgorithm, alias);
        if (LOG.isLoggable(System.Logger.Level.DEBUG)) {
            Files.write(Paths.get("target","test-sign-"+alias+".xml"), buff);
        }
        Assertions.assertNotNull(buff);
        assertValidSignature(buff);
    }

    private byte[] doSign(String signatureMethod, String alias) throws Exception {

        // create test xml document to sign
        String signedElementId = "element-id-01";
        String signedElementName = "SignedElement";
        org.w3c.dom.Document doc = TestUtils.newDocument();
        Element root = doc.createElement("RootElement");
        Element signedElement = doc.createElement(signedElementName);
        signedElement.setAttribute("id", signedElementId);
        signedElement.appendChild(doc.createTextNode("Some data to sign"));
        doc.appendChild(root);
        root.appendChild(signedElement);

        // get private key and the certificate from the truststore
        KeyStore keyStore = KeyStore.getInstance(ECDSA_KS_TYPE);
        keyStore.load(Files.newInputStream(Paths.get(ECDSA_JKS)), ECDSA_KS_PASSWORD.toCharArray());
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, ECDSA_KS_PASSWORD.toCharArray());

        // prepare xml signature data
        Element canonElem = XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttributeNS(null, Constants._ATT_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        //Create XML Signature Factory
        XMLSignatureFactory xmlSigFactory = XMLSignatureFactory.getInstance("DOM");
        DOMSignContext domSignCtx = new DOMSignContext(privateKey, doc.getDocumentElement());
        // set the signature provider for the ECDSA with brainpool curves
        domSignCtx.setProperty(DOM_SIGNATURE_PROVIDER, JDKTestUtils.getAuxiliaryProvider());

        domSignCtx.setIdAttributeNS(signedElement, null, "id");
        // reference(s), SignedInfo and KeyInfo
        Reference ref = xmlSigFactory.newReference(
            "#" + signedElementId,
            xmlSigFactory.newDigestMethod(DigestMethod.SHA256, null),
            Collections.singletonList(xmlSigFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
            null,
            null
        );
        SignedInfo signedInfo = xmlSigFactory.newSignedInfo(
            xmlSigFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
            xmlSigFactory.newSignatureMethod(signatureMethod, null),
            Collections.singletonList(ref)
        );
        KeyInfo keyInfo = createKeyInfo(xmlSigFactory, certificate);
        //Create the XML Signature
        XMLSignature xmlSignature = xmlSigFactory.newXMLSignature(signedInfo, keyInfo);
        //Sign the document
        xmlSignature.sign(domSignCtx);
        // serialize the xml to byte array
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLUtils.outputDOMc14nWithComments(doc, bos);
        return bos.toByteArray();
    }

    private KeyInfo createKeyInfo(XMLSignatureFactory fac, X509Certificate cert) {
        // Create the KeyInfo containing the X509Data.
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List<Object> x509Content = new ArrayList<>();
        x509Content.add(cert.getSubjectX500Principal().getName());
        x509Content.add(cert);
        X509Data xd = kif.newX509Data(x509Content);
        return kif.newKeyInfo(Collections.singletonList(xd));
    }

    private void assertValidSignature(byte[] signedXml) throws Exception {
        try (InputStream is = new ByteArrayInputStream(signedXml)) {
            DOMValidateContext vc = testInstance.getValidateContext(is, new KeySelectors.RawX509KeySelector(), false);
            // set the signature provider for the ECDSA for brainpool curves
            vc.setProperty(DOM_SIGNATURE_PROVIDER, JDKTestUtils.getAuxiliaryProvider());
            updateIdReferences(vc, "SignedElement", "id");

            boolean coreValidity = testInstance.validate(vc);
            // assert expected result
            assertTrue(coreValidity);
        }
    }

    public void updateIdReferences(DOMValidateContext vc, String elementName, String idAttributeName) {
        Document doc = vc.getNode().getOwnerDocument();
        NodeList nl = doc.getElementsByTagName(elementName);
        vc.setIdAttributeNS((Element) nl.item(0), null, idAttributeName);
    }
}
