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

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
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
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.KeyUtils;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Element;


/**
 * Tests that creates and verifies EC signatures with brainpool curves.
 *
 */
class ECBrainpoolSignatureTest {

    private static final String ECDSA_JKS =
        "src/test/resources/org/apache/xml/security/samples/input/ecbrainpool.jks";
    private static final String ECDSA_JKS_PASSWORD = "security";
    private static boolean bcInstalled;

    public ECBrainpoolSignatureTest() throws Exception {
        org.apache.xml.security.Init.init();

        //
        // If the BouncyCastle provider is not installed, then try to load it
        // via reflection.
        //
        if (Security.getProvider("BC") == null) {
            Constructor<?> cons = null;
            try {
                Class<?> c = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                cons = c.getConstructor(new Class[] {});
            } catch (Exception e) {
                //ignore
            }
            if (cons != null) {
                Provider provider = (Provider)cons.newInstance();
                Security.insertProviderAt(provider, 2);
                bcInstalled = true;
            }
        }
    }

    @AfterAll
    public static void cleanup() throws Exception {
        Security.removeProvider("BC");
    }

    @Test
    void testOne() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(ECDSA_JKS), ECDSA_JKS_PASSWORD.toCharArray());

        PrivateKey privateKey =
            (PrivateKey)keyStore.getKey("ECDSA", ECDSA_JKS_PASSWORD.toCharArray());

        doVerify(doSign(privateKey, (X509Certificate)keyStore.getCertificate("ECDSA"), null));
        doVerify(doSign(privateKey, (X509Certificate)keyStore.getCertificate("ECDSA"), null));
    }

    @ParameterizedTest
    @CsvSource({"BRAINPOOLP256R1,ECDH", "BRAINPOOLP384R1,ECDH", "BRAINPOOLP512R1,ECDH",
            "BRAINPOOLP256R1,ECDSA", "BRAINPOOLP384R1,ECDSA", "BRAINPOOLP512R1,ECDSA"
    })
    void testKeyValue(KeyUtils.KeyType keyType, String algorithm) throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        java.security.spec.ECGenParameterSpec bSpec =
                new java.security.spec.ECGenParameterSpec(keyType.getName());

        final SecureRandom secureRandom = new SecureRandom ();
        final KeyPairGenerator bGenerator = KeyPairGenerator.getInstance (algorithm, "BC");
        bGenerator.initialize (bSpec, secureRandom);

        final KeyPair keyPair = bGenerator.genKeyPair ();

        doVerify(doSign(keyPair.getPrivate(), null, keyPair.getPublic()));
    }

    private byte[] doSign(PrivateKey privateKey, X509Certificate x509, PublicKey publicKey) throws Exception {
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
            new SignatureAlgorithm(doc, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA1);
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
            assertTrue(signature.checkSignatureValue(cert));
        } else {
            assertTrue(signature.checkSignatureValue(signature.getKeyInfo().getPublicKey()));
        }
    }


    /**
     * DO NOT DELETE THIS COMMENTED OUT METHOD!
     *
     * The reason this method is commented out is to avoid introducing explicit
     * BouncyCastle dependencies.
     *
     * Create an X.509 Certificate and associated private key using the Elliptic Curve
     * DSA algorithm, and store in a KeyStore. This method was used to generate the
     * keystore used for this test
     * ("src/test/resources/org/apache/xml/security/samples/input/ecbrainpool.jks").
     *
    private static void setUpKeyAndCertificate() throws Exception {
        final ECNamedCurveParameterSpec ecGenParameterSpec = ECNamedCurveTable.getParameterSpec (KeyType.BRAINPOOLP256R1.getName());

        java.security.KeyPairGenerator kpg =
            java.security.KeyPairGenerator.getInstance("ECDH", "BC");

        kpg.initialize(ecGenParameterSpec, new java.security.SecureRandom());

        java.security.KeyPair kp = kpg.generateKeyPair();

        org.bouncycastle.x509.X509V3CertificateGenerator certGen =
            new org.bouncycastle.x509.X509V3CertificateGenerator();

        long now = System.currentTimeMillis();
        certGen.setSerialNumber(java.math.BigInteger.valueOf(now));

        org.bouncycastle.jce.X509Principal subject =
            new org.bouncycastle.jce.X509Principal(
                "CN=XML ECDSA Signature Test,DC=apache,DC=org"
            );
        certGen.setIssuerDN(subject);
        certGen.setSubjectDN(subject);

        java.util.Date from_date = new java.util.Date(now);
        certGen.setNotBefore(from_date);
        java.util.Calendar cal = new java.util.GregorianCalendar();
        cal.setTime(from_date);
        cal.add(java.util.Calendar.YEAR, 4);
        java.util.Date to_date = cal.getTime();
        certGen.setNotAfter(to_date);

        certGen.setPublicKey(kp.getPublic());
        certGen.setSignatureAlgorithm("SHA1withECDSA");
        certGen.addExtension(
            org.bouncycastle.asn1.x509.X509Extensions.BasicConstraints,
            true,
            new org.bouncycastle.asn1.x509.BasicConstraints(false)
        );
        certGen.addExtension(
            org.bouncycastle.asn1.x509.X509Extensions.KeyUsage,
            true,
            new org.bouncycastle.asn1.x509.KeyUsage(
                org.bouncycastle.asn1.x509.KeyUsage.digitalSignature |
                org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment |
                org.bouncycastle.asn1.x509.KeyUsage.keyCertSign |
                org.bouncycastle.asn1.x509.KeyUsage.cRLSign
            )
        );

        X509Certificate x509 = certGen.generateX509Certificate(kp.getPrivate());

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, ECDSA_JKS_PASSWORD.toCharArray());
        keyStore.setKeyEntry(
            "ECDSA", kp.getPrivate(),
            ECDSA_JKS_PASSWORD.toCharArray(), new java.security.cert.Certificate[]{x509}
        );
        keyStore.store(
            new java.io.FileOutputStream(ECDSA_JKS), ECDSA_JKS_PASSWORD.toCharArray()
        );

    }
*/

}
