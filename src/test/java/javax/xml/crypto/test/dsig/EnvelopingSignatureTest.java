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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * A test for Enveloping XML Signature
 */
public class EnvelopingSignatureTest {

    private KeyPair rsaKeyPair;
    private XMLSignatureFactory fac;
    private KeyInfoFactory kif;
    private DocumentBuilderFactory dbf;

    static {
        Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public EnvelopingSignatureTest() throws NoSuchAlgorithmException {
        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(2048);
        rsaKeyPair = rsaKpg.genKeyPair();
        fac = XMLSignatureFactory.getInstance("DOM",
            new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
        dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        kif = fac.getKeyInfoFactory();
    }

    @Test
    public void enveloping() throws Exception {
        // Read in plaintext document
        InputStream sourceDocument =
            this.getClass().getClassLoader().getResourceAsStream(
                "ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml");
        Document document = dbf.newDocumentBuilder().parse(sourceDocument);

        DigestMethod digestMethod = fac.newDigestMethod(DigestMethod.SHA1, null);
        Reference reference = fac.newReference("#data", digestMethod);

        // Create a KeyInfo and add the KeyValue to it
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

        // validate signature
        DOMValidateContext dvc = new DOMValidateContext
            (rsaKeyPair.getPublic(), document.getDocumentElement());
        XMLSignature sig2 = fac.unmarshalXMLSignature(dvc);

        if (!signature.equals(sig2)) {
            throw new Exception
                ("Unmarshalled signature is not equal to generated signature");
        }
        if (!sig2.validate(dvc)) {
            throw new Exception("Validation of generated signature failed");
        }
    }

    @Test
    public void enveloping_dom_level1() throws Exception {
        // create reference
        DigestMethod sha256 = fac.newDigestMethod(DigestMethod.SHA256, null);
        Reference ref = fac.newReference("#object", sha256);

        // create SignedInfo
        CanonicalizationMethod withoutComments =
            fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                (C14NMethodParameterSpec) null);
        SignatureMethod rsaSha256 =
            fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null);
        SignedInfo si = fac.newSignedInfo(withoutComments, rsaSha256,
            Collections.singletonList(ref));

        // create object using DOM Level 1 methods
        Document doc = dbf.newDocumentBuilder().newDocument();
        Element child = doc.createElement("Child");
        child.setAttribute("Version", "1.0");
        child.setAttribute("Id", "child");
        child.setIdAttribute("Id", true);
        child.appendChild(doc.createComment("Comment"));
        XMLObject obj = fac.newXMLObject(
            Collections.singletonList(new DOMStructure(child)),
            "object", null, "UTF-8");

        // Create a KeyInfo and add the KeyValue to it
        KeyValue kv = kif.newKeyValue(rsaKeyPair.getPublic());
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));
        // Perform the signature
        XMLSignature sig = fac.newXMLSignature(si, ki,
                                               Collections.singletonList(obj),
                                               "signature", null);
        DOMSignContext dsc = new DOMSignContext(rsaKeyPair.getPrivate(), doc);
        sig.sign(dsc);

        // validate signature
        DOMValidateContext dvc = new DOMValidateContext
            (rsaKeyPair.getPublic(), doc.getDocumentElement());
        XMLSignature sig2 = fac.unmarshalXMLSignature(dvc);

        if (!sig.equals(sig2)) {
            throw new Exception
                ("Unmarshalled signature is not equal to generated signature");
        }
        if (!sig2.validate(dvc)) {
            throw new Exception("Validation of generated signature failed");
        }
    }
}
