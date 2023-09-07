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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.dom.TestUtils;
import org.apache.xml.security.test.javax.xml.crypto.dsig.EdDSATestAbstract;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;


/**
 * Tests of the EDDSA Ed25519 and Ed448 signatures.
 * @since 2.3.3.
 */
class EDDSASignatureTest extends EdDSATestAbstract {
    static {
        if (!org.apache.xml.security.Init.isInitialized()) {
            org.apache.xml.security.Init.init();
        }
    }

    @Test
    void testEd22519() throws Exception {
        Assumptions.assumeTrue(isEdDSASupported());
        KeyStore keyStore = KeyStore.getInstance(EDDSA_KS_TYPE);
        keyStore.load(Files.newInputStream(Paths.get(EDDSA_KS)), EDDSA_KS_PASSWORD.toCharArray());

        PrivateKey privateKey =
                (PrivateKey) keyStore.getKey("Ed25519", EDDSA_KS_PASSWORD.toCharArray());

        doVerify(doSign(privateKey, (X509Certificate) keyStore.getCertificate("Ed25519"), null, XMLSignature.ALGO_ID_SIGNATURE_EDDSA_ED25519));
    }

    @Test
    void testEd22519VerifyXML() throws Exception {
        Assumptions.assumeTrue(isEdDSASupported());
        try (InputStream xmlSignatureExample
                     = EDDSASignatureTest.class.getResourceAsStream("/org/apache/xml/security/samples/input/eddsaEd25519Signature.xml")) {
            doVerify(xmlSignatureExample);
        }
    }

    @Test
    void testEd448VerifyXML() throws Exception {
        Assumptions.assumeTrue(isEdDSASupported());
        try (InputStream xmlSignatureExample
                     = EDDSASignatureTest.class.getResourceAsStream("/org/apache/xml/security/samples/input/eddsaEd448Signature.xml")) {
            doVerify(xmlSignatureExample);
        }
    }

    @Test
    void testEd448() throws Exception {
        Assumptions.assumeTrue(isEdDSASupported());
        KeyStore keyStore = KeyStore.getInstance(EDDSA_KS_TYPE);
        keyStore.load(Files.newInputStream(Paths.get(EDDSA_KS)), EDDSA_KS_PASSWORD.toCharArray());

        PrivateKey privateKey =
                (PrivateKey) keyStore.getKey("Ed448", EDDSA_KS_PASSWORD.toCharArray());

        doVerify(doSign(privateKey, (X509Certificate) keyStore.getCertificate("Ed448"), null, XMLSignature.ALGO_ID_SIGNATURE_EDDSA_ED448));
    }


    private byte[] doSign(PrivateKey privateKey, X509Certificate x509, PublicKey publicKey, String signAlgorithm) throws Exception {
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
                new SignatureAlgorithm(doc, signAlgorithm);
        XMLSignature sig =
                new XMLSignature(doc, null, signatureAlgorithm.getElement(), canonElem);

        root.appendChild(sig.getElement());
        doc.appendChild(doc.createComment(" Comment after "));
        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        if (x509 != null) {
            sig.addKeyInfo(x509);
        } else {
            sig.addKeyInfo(publicKey);
        }
        sig.sign(privateKey);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        XMLUtils.outputDOMc14nWithComments(doc, bos);
        return bos.toByteArray();
    }

    private void doVerify(byte[] signedXml) throws Exception {
        try (InputStream is = new ByteArrayInputStream(signedXml)) {
            doVerify(is);
        }
    }

    private void doVerify(InputStream is) throws Exception {
        org.w3c.dom.Document doc = XMLUtils.read(is, false);

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

/**
 * DO NOT DELETE THIS COMMENTED OUT METHOD!
 *
 * The reason this method is commented out is to avoid introducing explicit
 * BouncyCastle dependencies.
 *
 * Create an X.509 Certificate and associated private key using the Edwards-Curve Digital Signature Algorithm
 * DSA algorithm, and store in a KeyStore. This method was used to generate the
 * keystore used for this test
 * ("src/test/resources/org/apache/xml/security/samples/input/eddsa.p12").
 * To generate certificte add the:  org.bouncycastle::bcpkix-jdk18on

 private static void setUpKeyAndCertificate() throws Exception {
 String[] algorithms = new String []{"Ed25519","Ed448"};
 KeyStore keyStore = KeyStore.getInstance("PKCS12");
 keyStore.load(null, EDDSA_KS_PASSWORD.toCharArray());
 for (String parameterName:algorithms) {


 String signatureAlgName = parameterName;

 java.security.KeyPairGenerator kpg =
 java.security.KeyPairGenerator.getInstance(parameterName, org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME);
 org.bouncycastle.jcajce.spec.EdDSAParameterSpec keySpec = new org.bouncycastle.jcajce.spec.EdDSAParameterSpec(parameterName);
 kpg.initialize(keySpec, new java.security.SecureRandom());

 // Cert data
 java.security.KeyPair keyPair = kpg.generateKeyPair();
 long now = System.currentTimeMillis();
 java.util.Date from_date = new java.util.Date(now);
 java.util.Calendar cal = new java.util.GregorianCalendar();
 cal.setTime(from_date);
 cal.add(java.util.Calendar.YEAR, 4);
 java.util.Date to_date = cal.getTime();

 org.bouncycastle.asn1.x500.X500Name subject = new org.bouncycastle.asn1.x500.X500Name("CN=XML "+parameterName+" Signature Test,DC=apache,DC=org");
 org.bouncycastle.cert.X509v3CertificateBuilder certBuilder = new org.bouncycastle.cert.X509v3CertificateBuilder(subject,
 java.math.BigInteger.valueOf(now), from_date, to_date, subject,
 SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

 certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new org.bouncycastle.asn1.x509.BasicConstraints(true));
 certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, new org.bouncycastle.asn1.x509.KeyUsage(org.bouncycastle.asn1.x509.KeyUsage.digitalSignature |
 org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment |
 org.bouncycastle.asn1.x509.KeyUsage.keyCertSign |
 org.bouncycastle.asn1.x509.KeyUsage.cRLSign));

 ContentSigner sigGen = new JcaContentSignerBuilder(signatureAlgName)
 .build(keyPair.getPrivate());

 X509Certificate x509 = new JcaX509CertificateConverter().getCertificate(certBuilder.build(sigGen));


 keyStore.setKeyEntry(
 parameterName, keyPair.getPrivate(),
 EDDSA_KS_PASSWORD.toCharArray(), new java.security.cert.Certificate[]{x509}
 );
 }
 keyStore.store(
 new java.io.FileOutputStream(EDDSA_KS), EDDSA_KS_PASSWORD.toCharArray()
 );
 }
 */
}
