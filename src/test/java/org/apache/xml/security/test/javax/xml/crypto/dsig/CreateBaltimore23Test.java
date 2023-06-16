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
/*
 * Copyright 2005 Sun Microsystems, Inc. All rights reserved.
 */
package org.apache.xml.security.test.javax.xml.crypto.dsig;


import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.KeySelector;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Manifest;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.RetrievalMethod;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.HMACParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;
import javax.xml.crypto.dsig.spec.XSLTTransformParameterSpec;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.parser.XMLParserException;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Test that recreates merlin-xmldsig-twenty-three test vectors but with
 * different keys and X.509 data.
 *
 */
public class CreateBaltimore23Test {

    private final XMLSignatureFactory fac;
    private final KeyInfoFactory kifac;
    private final CanonicalizationMethod withoutComments;
    private final Transform withComments;
    private final SignatureMethod dsaSha1, rsaSha1;
    private final DigestMethod sha1;
    private final KeyInfo dsa, rsa;
    private final KeySelector kvks = new KeySelectors.KeyValueKeySelector();
    private final KeySelector sks;
    private final Key signingKey;
    private final PublicKey validatingKey;
    private final Certificate signingCert;
    private final KeyStore ks;
    private final URIDereferencer ud;

    static {
        System.setProperty("org.apache.xml.security.allowUnsafeResourceResolving", "true");
        Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
        ResourceResolver.register(new ResolverLocalFilesystem(), false);
    }

    public CreateBaltimore23Test() throws Exception {
        fac = XMLSignatureFactory.getInstance("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
        kifac = fac.getKeyInfoFactory();

        ks = XmlSecTestEnvironment.getTestKeyStore();
        signingKey = ks.getKey("mullan", "changeit".toCharArray());
        signingCert = ks.getCertificate("mullan");
        validatingKey = signingCert.getPublicKey();

        // create common objects
        withoutComments = fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);
        withComments = fac.newTransform(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (TransformParameterSpec) null);
        dsaSha1 = fac.newSignatureMethod(SignatureMethod.DSA_SHA1, null);
        sha1 = fac.newDigestMethod(DigestMethod.SHA1, null);
        dsa = kifac.newKeyInfo(Collections.singletonList(kifac.newKeyValue(validatingKey)));
        rsa = kifac.newKeyInfo(Collections.singletonList(kifac.newKeyValue(TestUtils.getPublicKey("RSA"))));
        rsaSha1 = fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null);
        sks = new KeySelectors.SecretKeySelector("secret".getBytes(StandardCharsets.US_ASCII));

        ud = new LocalHttpCacheURIDereferencer();
    }

    @Test
    public void test_create_signature_enveloped_dsa() throws Exception {
        // create SignedInfo
        SignedInfo si = fac.newSignedInfo
            (withoutComments, dsaSha1, Collections.singletonList
                (fac.newReference
                    ("", sha1, Collections.singletonList
                        (fac.newTransform(Transform.ENVELOPED,
                         (TransformParameterSpec) null)),
                 null, null)));

        // create XMLSignature
        XMLSignature sig = fac.newXMLSignature(si, dsa);

        Document doc = TestUtils.newDocument();
        Element envelope = doc.createElementNS
            ("http://example.org/envelope", "Envelope");
        envelope.setAttributeNS
            (Constants.NamespaceSpecNS, "xmlns", "http://example.org/envelope");
        doc.appendChild(envelope);

        DOMSignContext dsc = new DOMSignContext(signingKey, envelope);

        sig.sign(dsc);

        DOMValidateContext dvc = new DOMValidateContext
            (kvks, envelope.getFirstChild());
        XMLSignature sig2 = fac.unmarshalXMLSignature(dvc);

        assertEquals(sig, sig2);

        assertTrue(sig2.validate(dvc));
    }

    @Test
    public void test_create_signature_enveloping_b64_dsa() throws Exception {
        test_create_signature_enveloping(dsaSha1, dsa, signingKey, kvks, true);
    }

    @Test
    public void test_create_signature_enveloping_dsa() throws Exception {
        test_create_signature_enveloping(dsaSha1, dsa, signingKey, kvks, false);
    }

    @Test
    public void test_create_signature_enveloping_hmac_sha1_40()
        throws Exception {
        SignatureMethod hmacSha1 = fac.newSignatureMethod
            (SignatureMethod.HMAC_SHA1, new HMACParameterSpec(40));
        try {
            test_create_signature_enveloping(hmacSha1, null,
                TestUtils.getSecretKey("secret".getBytes(StandardCharsets.US_ASCII)), sks, false);
            fail("Expected HMACOutputLength Exception");
        } catch (XMLSignatureException xse) {
            System.out.println(xse.getMessage());
            // pass
        }
    }

    @Test
    public void test_create_signature_enveloping_hmac_sha1()
        throws Exception {
        SignatureMethod hmacSha1 = fac.newSignatureMethod
            (SignatureMethod.HMAC_SHA1, null);
        test_create_signature_enveloping(hmacSha1, null,
            TestUtils.getSecretKey("secret".getBytes(StandardCharsets.US_ASCII)), sks, false);
    }

    @Test
    public void test_create_signature_enveloping_rsa() throws Exception {
        test_create_signature_enveloping(rsaSha1, rsa,
            TestUtils.getPrivateKey("RSA"), kvks, false);
    }

    @Test
    public void test_create_signature_external_b64_dsa() throws Exception {
        test_create_signature_external(dsaSha1, dsa, signingKey, kvks, true);
    }

    @Test
    public void test_create_signature_external_dsa() throws Exception {
        test_create_signature_external(dsaSha1, dsa, signingKey, kvks, false);
    }

    @Test
    public void test_create_signature_keyname() throws Exception {
        KeyInfo kn = kifac.newKeyInfo(Collections.singletonList
            (kifac.newKeyName("mullan")));
        test_create_signature_external(dsaSha1, kn, signingKey,
            new X509KeySelector(ks), false);
    }

    @Test
    public void test_create_signature_retrievalmethod_rawx509crt()
        throws Exception {
        KeyInfo rm = kifac.newKeyInfo(Collections.singletonList
            (kifac.newRetrievalMethod
            ("certs/mullan.crt", X509Data.RAW_X509_CERTIFICATE_TYPE, null)));
        test_create_signature_external(dsaSha1, rm, signingKey,
            new X509KeySelector(ks), false);
    }

    @Test
    public void test_create_signature_x509_crt_crl() throws Exception {

        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        List<Object> xds = new ArrayList<>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        xds.add(signingCert);
        X509CRL crl;
        try (FileInputStream fis = new FileInputStream(resolveFile("src", "test", "resources", "ie", "baltimore",
            "merlin-examples", "merlin-xmldsig-twenty-three", "certs", "crl"))) {
            crl = (X509CRL) cf.generateCRL(fis);
        }
        xds.add(crl);
        KeyInfo crt_crl = kifac.newKeyInfo(Collections.singletonList(kifac.newX509Data(xds)));

        test_create_signature_external(dsaSha1, crt_crl, signingKey, new X509KeySelector(ks), false);
    }

    @Test
    public void test_create_signature_x509_crt() throws Exception {
        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        KeyInfo crt = kifac.newKeyInfo(Collections.singletonList
            (kifac.newX509Data(Collections.singletonList(signingCert))));

        test_create_signature_external(dsaSha1, crt, signingKey,
            new X509KeySelector(ks), false);
    }

    @Test
    public void test_create_signature_x509_is() throws Exception {
        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        KeyInfo is = kifac.newKeyInfo(Collections.singletonList
            (kifac.newX509Data(Collections.singletonList
            (kifac.newX509IssuerSerial
            ("CN=Sean Mullan,DC=sun,DC=com",
            new BigInteger("47cdb772", 16))))));
        test_create_signature_external(dsaSha1, is, signingKey,
            new X509KeySelector(ks), false);
    }

    @Test
    public void test_create_signature_x509_ski() throws Exception {
        KeyInfo ski = kifac.newKeyInfo(Collections.singletonList
            (kifac.newX509Data(Collections.singletonList
            ("keyid".getBytes(StandardCharsets.US_ASCII)))));

        test_create_signature_external(dsaSha1, ski, signingKey,
            KeySelector.singletonKeySelector(validatingKey), false);
    }

    @Test
    public void test_create_signature_x509_sn() throws Exception {
        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        KeyInfo sn = kifac.newKeyInfo(Collections.singletonList
            (kifac.newX509Data(Collections.singletonList
            ("CN=Sean Mullan,DC=sun,DC=com"))));

        test_create_signature_external(dsaSha1, sn, signingKey,
            new X509KeySelector(ks), false);
    }

    @Test
    public void test_create_signature() throws Exception {

        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        // set up reusable objects
        Transform env = fac.newTransform(Transform.ENVELOPED,
            (TransformParameterSpec) null);

        // create references
        List<Reference> refs = new ArrayList<>();

        // Reference 1
        refs.add(fac.newReference("http://www.w3.org/TR/xml-stylesheet", sha1));

        // Reference 2
        refs.add(fac.newReference
            ("http://www.w3.org/Signature/2002/04/xml-stylesheet.b64",
            sha1, Collections.singletonList
            (fac.newTransform(Transform.BASE64,
             (TransformParameterSpec) null)), null, null));

        // Reference 3
        refs.add(fac.newReference("#object-1", sha1, Collections.singletonList
            (fac.newTransform(Transform.XPATH,
            new XPathFilterParameterSpec("self::text()"))),
            XMLObject.TYPE, null));

        // Reference 4
        String expr = "\n"
          + " ancestor-or-self::dsig:SignedInfo			 " + "\n"
          + "  and                                               " + "\n"
          + " count(ancestor-or-self::dsig:Reference |		 " + "\n"
          + "	   here()/ancestor::dsig:Reference[1]) >	 " + "\n"
          + " count(ancestor-or-self::dsig:Reference)		 " + "\n"
          + "  or                                                " + "\n"
          + " count(ancestor-or-self::node() |			 " + "\n"
          + "	   id('notaries')) =				 " + "\n"
          + " count(ancestor-or-self::node())			 " + "\n";

        new XPathFilterParameterSpec(expr,
            Collections.singletonMap("dsig", XMLSignature.XMLNS));
//        refs.add(fac.newReference("", sha1, Collections.singletonList
//	    (fac.newTransform(Transform.XPATH, xfp)),
//	    XMLObject.TYPE, null));

        // Reference 5
        refs.add(fac.newReference("#object-2", sha1, Collections.singletonList
            (fac.newTransform(Transform.BASE64, (TransformParameterSpec) null)),
            XMLObject.TYPE, null));

        // Reference 6
        refs.add(fac.newReference
            ("#manifest-1", sha1, null, Manifest.TYPE, null));

        // Reference 7
        refs.add(fac.newReference("#signature-properties-1", sha1, null,
            SignatureProperties.TYPE, null));

        // Reference 8
        List<Transform> transforms = new ArrayList<>();
        transforms.add(env);
        refs.add(fac.newReference("", sha1, transforms, null, null));

        // Reference 9
        transforms.add(withComments);
        refs.add(fac.newReference("", sha1, transforms, null, null));

        // Reference 10
        refs.add(fac.newReference("#xpointer(/)",
            sha1, Collections.singletonList(env), null, null));

        // Reference 11
        refs.add(fac.newReference("#xpointer(/)", sha1, transforms,
            null, null));

        // Reference 12
        refs.add
            (fac.newReference("#object-3", sha1, null, XMLObject.TYPE, null));

        // Reference 13
        refs.add(fac.newReference("#object-3", sha1,
            Collections.singletonList(withComments), XMLObject.TYPE, null));

        // Reference 14
        refs.add(fac.newReference("#xpointer(id('object-3'))", sha1, null,
            XMLObject.TYPE, null));

        // Reference 15
        refs.add(fac.newReference("#xpointer(id('object-3'))", sha1,
            Collections.singletonList(withComments), XMLObject.TYPE, null));

        // Reference 16
        refs.add(fac.newReference("#reference-2", sha1));

        // Reference 17
        refs.add(fac.newReference("#manifest-reference-1", sha1, null,
            null, "reference-1"));

        // Reference 18
        refs.add(fac.newReference("#reference-1", sha1, null, null,
            "reference-2"));

        // create SignedInfo
        SignedInfo si = fac.newSignedInfo(withoutComments, dsaSha1, refs);

        // create keyinfo
        XPathFilterParameterSpec xpf = new XPathFilterParameterSpec(
            "ancestor-or-self::dsig:X509Data",
            Collections.singletonMap("dsig", XMLSignature.XMLNS));
        RetrievalMethod rm = kifac.newRetrievalMethod("#object-4",
            X509Data.TYPE, Collections.singletonList(fac.newTransform
            (Transform.XPATH, xpf)));
        KeyInfo ki = kifac.newKeyInfo(Collections.singletonList(rm), null);

        Document doc = TestUtils.newDocument();

        // create objects
        List<XMLObject> objs = new ArrayList<>();

        // Object 1
        objs.add(fac.newXMLObject(Collections.singletonList
            (new DOMStructure(doc.createTextNode("I am the text."))),
            "object-1", "text/plain", null));

        // Object 2
        objs.add(fac.newXMLObject(Collections.singletonList
            (new DOMStructure(doc.createTextNode("SSBhbSB0aGUgdGV4dC4="))),
            "object-2", "text/plain", Transform.BASE64));

        // Object 3
        Element nc = doc.createElementNS(null, "NonCommentandus");
        nc.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns", "");
        nc.appendChild(doc.createComment(" Commentandum "));
        objs.add(fac.newXMLObject(Collections.singletonList
            (new DOMStructure(nc)), "object-3", null, null));

        // Manifest
        List<Reference> manRefs = new ArrayList<>();

        // Manifest Reference 1
        manRefs.add(fac.newReference("http://www.w3.org/TR/xml-stylesheet",
            sha1, null, null, "manifest-reference-1"));

        // Manifest Reference 2
        manRefs.add(fac.newReference("#reference-1", sha1));

        // Manifest Reference 3
        List<Transform> manTrans = new ArrayList<>();
        String xslt = ""
          + "<xsl:stylesheet xmlns:xsl='http://www.w3.org/1999/XSL/Transform'\n"
          + "		 xmlns='http://www.w3.org/TR/xhtml1/strict' \n"
          + "		 exclude-result-prefixes='foo' \n"
          + "		 version='1.0'>\n"
          + "  <xsl:output encoding='UTF-8' \n"
          + "		indent='no' \n"
          + "		method='xml' />\n"
          + "  <xsl:template match='/'>\n"
          + "    <html>\n"
          + "	<head>\n"
          + "	 <title>Notaries</title>\n"
          + "	</head>\n"
          + "	<body>\n"
          + "	 <table>\n"
          + "	   <xsl:for-each select='Notaries/Notary'>\n"
          + "		<tr>\n"
          + "		<th>\n"
          + "		 <xsl:value-of select='@name' />\n"
          + "		</th>\n"
          + "		</tr>\n"
          + "	   </xsl:for-each>\n"
          + "	 </table>\n"
          + "	</body>\n"
          + "    </html>\n"
          + "  </xsl:template>\n"
          + "</xsl:stylesheet>\n";
        Document docxslt = null;
        try (InputStream is = new ByteArrayInputStream(xslt.getBytes())) {
            docxslt = XMLUtils.read(is, false);
        }
        Node xslElem = docxslt.getDocumentElement();

        manTrans.add(fac.newTransform(Transform.XSLT,
            new XSLTTransformParameterSpec(new DOMStructure(xslElem))));
        manTrans.add(fac.newTransform(CanonicalizationMethod.INCLUSIVE,
            (TransformParameterSpec) null));
        // Comment out Manifest Reference 3, for some reason xalan is throwing NPE
        // when Transform is processed.
        //	manRefs.add(fac.newReference("#notaries", sha1, manTrans, null, null));

        objs.add(fac.newXMLObject(Collections.singletonList
            (fac.newManifest(manRefs, "manifest-1")), null, null, null));

        // SignatureProperties
        Element sa = doc.createElementNS("urn:demo", "SignerAddress");
        sa.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns", "urn:demo");
        Element ip = doc.createElementNS("urn:demo", "IP");
        ip.appendChild(doc.createTextNode("192.168.21.138"));
        sa.appendChild(ip);
        SignatureProperty sp = fac.newSignatureProperty
            (Collections.singletonList(new DOMStructure(sa)),
            "#signature", null);
        SignatureProperties sps = fac.newSignatureProperties
            (Collections.singletonList(sp), "signature-properties-1");
        objs.add(fac.newXMLObject(Collections.singletonList(sps), null,
            null, null));

        // Object 4
        List<Object> xds = new ArrayList<>();
        xds.add("CN=Sean Mullan,DC=sun,DC=com");
        xds.add(kifac.newX509IssuerSerial
            ("CN=Sean Mullan,DC=sun,DC=com",
            new BigInteger("47cdb772", 16)));
        xds.add(signingCert);
        objs.add(fac.newXMLObject(Collections.singletonList
            (kifac.newX509Data(xds)), "object-4", null, null));

        // create XMLSignature
        XMLSignature sig = fac.newXMLSignature(si, ki, objs, "signature", null);

        // create envelope header
        Element envelope = doc.createElementNS
            ("http://example.org/usps", "Envelope");
        envelope.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns",
            "http://example.org/usps");
        envelope.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:foo",
            "http://example.org/foo");
        doc.appendChild(envelope);
        Element dearSir = doc.createElementNS
            ("http://example.org/usps", "DearSir");
        dearSir.appendChild(doc.createTextNode("foo"));
        envelope.appendChild(dearSir);
        Element body = doc.createElementNS("http://example.org/usps", "Body");
        body.appendChild(doc.createTextNode("bar"));
        envelope.appendChild(body);
        Element ys = doc.createElementNS
            ("http://example.org/usps", "YoursSincerely");
        envelope.appendChild(ys);

        // create envelope footer
        Element ps = doc.createElementNS
            ("http://example.org/usps", "PostScript");
        ps.appendChild(doc.createTextNode("bar"));
        envelope.appendChild(ps);
        Element notaries = doc.createElementNS(null, "Notaries");
        notaries.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns", "");
        notaries.setAttributeNS(null, "Id", "notaries");
        Element notary1 = doc.createElementNS(null, "Notary");
        notary1.setAttributeNS(null, "name", "Great, A. T.");
        Element notary2 = doc.createElementNS(null, "Notary");
        notary2.setAttributeNS(null, "name", "Hun, A. T.");
        notaries.appendChild(notary1);
        notaries.appendChild(notary2);
        envelope.appendChild(notaries);
        envelope.appendChild(doc.createComment(" Commentary "));

        DOMSignContext dsc = new DOMSignContext(signingKey, ys);
        dsc.setIdAttributeNS(notaries, null, "Id");
        dsc.setURIDereferencer(ud);

        sig.sign(dsc);

        // DOM L2 does not support the creation of DOCTYPEs, so instead
        // we insert it before the document using a StringWriter
        //	String docType =
        //	    "<!DOCTYPE Envelope [\n"
        //  	  + "<!ENTITY dsig 'http://www.w3.org/2000/09/xmldsig#'>\n"
        //          + "<!ENTITY c14n 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'>\n"
        //          + "<!ENTITY xpath 'http://www.w3.org/TR/1999/REC-xpath-19991116'>\n"
        //          + "<!ENTITY xslt 'http://www.w3.org/TR/1999/REC-xslt-19991116'>\n"
        //          + "<!ATTLIST Notaries Id ID #IMPLIED>\n"
        //          + "]>\n";
                StringWriter sw = new StringWriter();
        //	sw.write(docType);

        dumpDocument(doc, sw);

        // read document back into DOM tree
        try {
            doc = XMLUtils.read(new ByteArrayInputStream(sw.toString().getBytes(StandardCharsets.UTF_8)), false);
        } catch (XMLParserException spe) {
            System.err.println("xml:" + sw.toString());
        }
        Element sigElement = SignatureValidator.getSignatureElement(doc);
        if (sigElement == null) {
            throw new Exception("Couldn't find signature Element");
        }

        DOMValidateContext dvc = new DOMValidateContext
            (new X509KeySelector(ks), sigElement);
        File f = new File(
        System.getProperty("dir.test.vector.baltimore") +
        FileSystems.getDefault().getSeparator() +
        "merlin-xmldsig-twenty-three" +
        FileSystems.getDefault().getSeparator());
        dvc.setBaseURI(f.toURI().toString());
        dvc.setURIDereferencer(ud);

        // register Notaries ID
        //	Element notariesElem =
        //	    (Element) doc.getElementsByTagName("Notaries").item(0);
        //	dvc.setIdAttributeNS(notariesElem, "", "Id");
        //	notariesElem.setIdAttributeNS("", "Id", true);

        XMLSignature sig2 = fac.unmarshalXMLSignature(dvc);

        assertEquals(sig, sig2);
        assertTrue(sig2.validate(dvc));
    }

    private void dumpDocument(Document doc, Writer w) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        // trans.setOutputProperty(OutputKeys.INDENT, "yes");
        trans.transform(new DOMSource(doc), new StreamResult(w));
    }

    private void test_create_signature_external
        (SignatureMethod sm, KeyInfo ki, Key signingKey, KeySelector ks,
        boolean b64) throws Exception {

        // create reference
        Reference ref;
        if (b64) {
            ref = fac.newReference
                ("http://www.w3.org/Signature/2002/04/xml-stylesheet.b64",
                sha1, Collections.singletonList
                (fac.newTransform(Transform.BASE64,
                 (TransformParameterSpec) null)), null, null);
        } else {
            ref = fac.newReference
                ("http://www.w3.org/Signature/2002/04/xml-stylesheet.b64",sha1);
        }

        // create SignedInfo
        SignedInfo si = fac.newSignedInfo(withoutComments, sm,
            Collections.singletonList(ref));

        Document doc = TestUtils.newDocument();

        // create XMLSignature
        XMLSignature sig = fac.newXMLSignature(si, ki);

        DOMSignContext dsc = new DOMSignContext(signingKey, doc);
        dsc.setURIDereferencer(ud);

        sig.sign(dsc);

        /*
        System.out.println("doc is:");
        StringWriter sw = new StringWriter();
        dumpDocument(doc, sw);
        System.out.println(sw.toString());
        */

        DOMValidateContext dvc = new DOMValidateContext(ks, doc.getDocumentElement());
        File f = resolveFile("src", "test", "resources", "ie", "baltimore", "merlin-examples", "merlin-xmldsig-twenty-three");
        dvc.setBaseURI(f.toURI().toString());
        dvc.setURIDereferencer(ud);

        XMLSignature sig2 = fac.unmarshalXMLSignature(dvc);

        assertEquals(sig, sig2);
        assertTrue(sig2.validate(dvc));
    }

    private void test_create_signature_enveloping
        (SignatureMethod sm, KeyInfo ki, Key signingKey, KeySelector ks,
        boolean b64) throws Exception {

        // create reference
        Reference ref;
        if (b64) {
            ref = fac.newReference("#object", sha1, Collections.singletonList
                (fac.newTransform(Transform.BASE64,
                 (TransformParameterSpec) null)), null, null);
        } else {
            ref = fac.newReference("#object", sha1);
        }

        // create SignedInfo
        SignedInfo si = fac.newSignedInfo(withoutComments, sm,
            Collections.singletonList(ref));

        Document doc = TestUtils.newDocument();
        // create Objects
        XMLObject obj = fac.newXMLObject(Collections.singletonList
            (new DOMStructure(doc.createTextNode("some text"))),
            "object", null, null);

        // create XMLSignature
        XMLSignature sig = fac.newXMLSignature
            (si, ki, Collections.singletonList(obj), null, null);

        DOMSignContext dsc = new DOMSignContext(signingKey, doc);

        sig.sign(dsc);

        DOMValidateContext dvc = new DOMValidateContext
            (ks, doc.getDocumentElement());
        XMLSignature sig2 = fac.unmarshalXMLSignature(dvc);

        assertEquals(sig, sig2);
        assertTrue(sig2.validate(dvc));
    }

}