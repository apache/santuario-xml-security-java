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
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.apache.xml.security.testutils.JDKTestUtils;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertTrue;

abstract class XMLSignatureAbstract {

    static {
        org.apache.xml.security.Init.init();
    }

    protected static final String DOM_SIGNATURE_PROVIDER = "org.jcp.xml.dsig.internal.dom.SignatureProvider";
    private final SignatureValidator testInstance = new SignatureValidator();

    /**
     * Test method for XML signing with javax.xml.crypto.dsig.XMLSignature API
     *
     * @param signatureAlgorithmURI the signature algorithm URI
     * @param alias the alias of the key entry in the keystore
     * @param registerSignatureProvider register the auxiliary signature provider
     *        using DOMSignContext property "org.jcp.xml.dsig.internal.dom.SignatureProvider"
     *
     * @return signed document
     * @throws Exception any exception that occurs during the test
     */
    protected byte[] doSignWithJcpApi(String signatureAlgorithmURI, String alias, boolean registerSignatureProvider) throws Exception {

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
        KeyStore keyStore = getKeyStore();
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, getKeyPassword());

        // prepare xml signature data
        Element canonElem = XMLUtils.createElementInSignatureSpace(doc, Constants._TAG_CANONICALIZATIONMETHOD);
        canonElem.setAttributeNS(null, Constants._ATT_ALGORITHM, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        //Create XML Signature Factory
        XMLSignatureFactory xmlSigFactory = XMLSignatureFactory.getInstance("DOM");
        DOMSignContext domSignCtx = new DOMSignContext(privateKey, doc.getDocumentElement());
        // set the signature provider to handle the signature algorithm processing
        if (registerSignatureProvider) {
            domSignCtx.setProperty(DOM_SIGNATURE_PROVIDER, JDKTestUtils.getAuxiliaryProvider());
        }

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
                xmlSigFactory.newSignatureMethod(signatureAlgorithmURI, null),
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

    protected void assertValidSignatureWithJcpApi(byte[] signedXml, boolean registerSignatureProvider) throws Exception {
        try (InputStream is = new ByteArrayInputStream(signedXml)) {
            DOMValidateContext vc = testInstance.getValidateContext(is, new KeySelectors.RawX509KeySelector(), false);
            // set the signature provider for the ECDSA for brainpool curves
            if (registerSignatureProvider) {
                vc.setProperty(DOM_SIGNATURE_PROVIDER, JDKTestUtils.getAuxiliaryProvider());
            }
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

    abstract KeyStore getKeyStore() throws Exception;
    abstract char[] getKeyPassword();
}
