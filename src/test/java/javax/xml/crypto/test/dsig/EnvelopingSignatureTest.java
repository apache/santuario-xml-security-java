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
package javax.xml.crypto.test.dsig;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Collections;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * A test for Enveloping XML Signature
 */
// TODO
@org.junit.Ignore
public class EnvelopingSignatureTest {

    private KeyPair rsaKeyPair;

    static {
        Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public EnvelopingSignatureTest() throws NoSuchAlgorithmException {
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(2048);
        rsaKeyPair = rsaKpg.genKeyPair();
    }

    @Test
    public void enveloping() throws Exception {
        // Read in plaintext document
        InputStream sourceDocument =
            this.getClass().getClassLoader().getResourceAsStream(
                "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        DocumentBuilderFactory DBF = DocumentBuilderFactory.newInstance();
        DBF.setNamespaceAware(true);
        Document document = DBF.newDocumentBuilder().parse(sourceDocument);

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        DigestMethod digestMethod = fac.newDigestMethod(DigestMethod.SHA1, null);
        Reference reference = fac.newReference("#data", digestMethod);

        // Create a KeyInfo and add the KeyValue to it
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(rsaKeyPair.getPublic());
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

        CanonicalizationMethod canonicalizationMethod =
            fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null);
        SignatureMethod signatureMethod = fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null);
        SignedInfo si = fac.newSignedInfo(canonicalizationMethod, signatureMethod,
                                          Collections.singletonList(reference));

        // Add the document element as the Object to sign.
        XMLStructure structure = new DOMStructure(document.getDocumentElement());
        XMLObject object = fac.newXMLObject(Collections.singletonList(structure), "data", null, "UTF-8");

        // Perform the signature
        XMLSignature signature = fac.newXMLSignature(si,
                                                     ki,
                                                     Collections.singletonList(object),
                                                     null, null);

        DOMSignContext signContext = new DOMSignContext(rsaKeyPair.getPrivate(), document);
        signature.sign(signContext);

        assertEquals("Signature", document.getDocumentElement().getLocalName());

        // Check that the PurchaseOrder is now under Object
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        String expression = "//*[local-name()='PurchaseOrder']";
        Element signedElement =
            (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        assertNotNull(signedElement);
        assertEquals("Object", signedElement.getParentNode().getLocalName());
    }

}
