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
package org.apache.xml.security.test.dom.algorithms;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.dom.providers.TestCustomSignatureSpi;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * A test to make sure that the various Public Key Signature algorithms are working
 */
class PKSignatureAlgorithmTest {
    private static final System.Logger LOG = System.getLogger(PKSignatureAlgorithmTest.class.getName());
    private static KeyPair rsaKeyPair, ecKeyPair;
    private static boolean bcInstalled;
    private static int javaVersion;

    static {
        org.apache.xml.security.Init.init();
    }

    @BeforeAll
    public static void setup() throws Exception {
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
        try {
            javaVersion = Integer.getInteger("java.specification.version", 0);
        } catch (NumberFormatException ex) {
            // ignore
        }

        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(2048);
        rsaKeyPair = rsaKpg.genKeyPair();

        ecKeyPair = KeyPairGenerator.getInstance("EC").genKeyPair();
    }

    @AfterAll
    public static void cleanup() throws Exception {
        Security.removeProvider("BC");
    }

    @Test
    void testRSA_MD5() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_NOT_RECOMMENDED_RSA_MD5, document, localNames, rsaKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames, false);
    }

    @Test
    void testRSA_SHA1() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1, document, localNames, rsaKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames);
    }

    @Test
    void testRSA_SHA_224() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA224, document, localNames, rsaKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames);
    }

    @Test
    void testRSA_SHA_256() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, document, localNames, rsaKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames);
    }

    @Test
    void testRSA_SHA_384() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384, document, localNames, rsaKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames);
    }

    @Test
    void testRSA_SHA_512() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512, document, localNames, rsaKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames);
    }

    @Test
    void testRSA_RIPEMD160() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_RIPEMD160, document, localNames, rsaKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames);
    }

    @Test
    void testRSA_SHA1_MGF1() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1_MGF1, document, localNames, rsaKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames);
    }

    @Test
    void testRSA_SHA224_MGF1() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA224_MGF1, document, localNames, rsaKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames);
    }

    @Test
    void testRSA_SHA256_MGF1() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1, document, localNames, rsaKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames);
    }

    @Test
    void testRSA_SHA384_MGF1() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1, document, localNames, rsaKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames);
    }

    @Test
    void testRSA_SHA512_MGF1() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1, document, localNames, rsaKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames);
    }

    @Test
    void testRSA_SHA3_224_MGF1() throws Exception {
        Assumptions.assumeTrue(bcInstalled || javaVersion >=16);

        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_224_MGF1, document, localNames, rsaKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames);
    }

    @Test
    void testRSA_SHA3_256_MGF1() throws Exception {
        Assumptions.assumeTrue(bcInstalled || javaVersion >=16);

        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_256_MGF1, document, localNames, rsaKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames);
    }

    @Test
    void testRSA_SHA3_384_MGF1() throws Exception {
        Assumptions.assumeTrue(bcInstalled || javaVersion >=16);

        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_384_MGF1, document, localNames, rsaKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames);
    }

    @Test
    void testRSA_SHA3_512_MGF1() throws Exception {
        Assumptions.assumeTrue(bcInstalled || javaVersion >=16);

        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA3_512_MGF1, document, localNames, rsaKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames);
    }

    @Test
    void testRSA_PSS() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_PSS, document, localNames, rsaKeyPair.getPrivate(),
             new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        // XMLUtils.outputDOM(document, System.out);
        verify(document, rsaKeyPair.getPublic(), localNames);
    }

    @Test
    void testECDSA_SHA1() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA1, document, localNames, ecKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, ecKeyPair.getPublic(), localNames);
    }

    @Test
    void testECDSA_SHA_224() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA224, document, localNames, ecKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, ecKeyPair.getPublic(), localNames);
    }

    @Test
    void testECDSA_SHA_256() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, document, localNames, ecKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, ecKeyPair.getPublic(), localNames);
    }

    @Test
    void testECDSA_SHA_384() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA384, document, localNames, ecKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, ecKeyPair.getPublic(), localNames);
    }

    @Test
    void testECDSA_SHA_512() throws Exception {
        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA512, document, localNames, ecKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, ecKeyPair.getPublic(), localNames);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA3_224,
        XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA3_256,
        XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA3_384,
        XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA3_512
    })
    void testECDSA_SHA3(String algorithm) throws Exception {
        // support added in JDK16 see:
        // https://seanjmullan.org/blog/2021/03/18/jdk16
        // https://www.oracle.com/java/technologies/javase/16all-relnotes.html
        Assumptions.assumeTrue(bcInstalled || javaVersion >=16);

        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(algorithm, document, localNames, ecKeyPair.getPrivate());
        if (LOG.isLoggable(System.Logger.Level.DEBUG)) {
            XMLUtils.outputDOM(document, System.out);
        }
        // XMLUtils.outputDOM(document, System.out);
        verify(document, ecKeyPair.getPublic(), localNames);
    }

    @Test
    void testECDSA_RIPEMD160() throws Exception {
        Assumptions.assumeTrue(bcInstalled);

        // Read in plaintext document
        Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
            getClass().getClassLoader(), false);

        List<String> localNames = new ArrayList<>();
        localNames.add("PaymentInfo");

        sign(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_RIPEMD160, document, localNames, ecKeyPair.getPrivate());
        // XMLUtils.outputDOM(document, System.out);
        verify(document, ecKeyPair.getPublic(), localNames);
    }

    @Test
    void testRSA_SHA1WithCustomSecurityProvider() throws Exception {
        TestCustomSignatureSpi.reset();
        CustomFakeProvider.register();
        try {
            // Read in plaintext document
            Document document = XMLUtils.readResource("ie/baltimore/merlin-examples/merlin-xmlenc-five/plaintext.xml",
                getClass().getClassLoader(), false);

            List<String> localNames = new ArrayList<>();
            localNames.add("PaymentInfo");

            sign(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1, document, localNames, new CustomFakePrivateKey());
            verify(document, new CustomFakePublicKey(), localNames);
            TestCustomSignatureSpi.verifyCalls();
        } finally {
            CustomFakeProvider.deRegister();
        }
    }

    private static class CustomFakeProvider extends Provider {

        public static final String PROVIDER_NAME = "TestCustomProvider";

        protected CustomFakeProvider() {
            super(PROVIDER_NAME, "1.0", "Custom security provider for unit tests");
            put("Signature.SHA1withRSA", TestCustomSignatureSpi.class.getName());
        }

        private static void register() {
            Security.addProvider(new CustomFakeProvider());
        }

        private static void deRegister() {
            final Provider provider = Security.getProvider(PROVIDER_NAME);
            if (provider instanceof CustomFakeProvider) {
                Security.removeProvider(PROVIDER_NAME);
            }
        }
    }

    private static class CustomFakePublicKey implements PublicKey {

        @Override
        public String getAlgorithm() {
            return "Custom-ALG"; //return an algorithm that will not be supported by other providers
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }
    }

    private static class CustomFakePrivateKey implements PrivateKey {

        @Override
        public String getAlgorithm() {
            return "Custom-ALG"; //return an algorithm that will not be supported by other providers
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }
    }

    private XMLSignature sign(
        String algorithm,
        Document document,
        List<String> localNames,
        Key signingKey
    ) throws Exception {
        return sign(algorithm, document, localNames, signingKey, null);
    }

    private XMLSignature sign(
        String algorithm,
        Document document,
        List<String> localNames,
        Key signingKey,
        AlgorithmParameterSpec parameterSpec
    ) throws Exception {
        String c14nMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
        XMLSignature sig = new XMLSignature(document, "", algorithm, 0, c14nMethod, null, parameterSpec);

        Element root = document.getDocumentElement();
        root.appendChild(sig.getElement());

        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        for (String localName : localNames) {
            String expression = "//*[local-name()='" + localName + "']";
            NodeList elementsToSign =
                    (NodeList) xpath.evaluate(expression, document, XPathConstants.NODESET);
            for (int i = 0; i < elementsToSign.getLength(); i++) {
                Element elementToSign = (Element)elementsToSign.item(i);
                assertNotNull(elementToSign);
                String id = UUID.randomUUID().toString();
                elementToSign.setAttributeNS(null, "Id", id);
                elementToSign.setIdAttributeNS(null, "Id", true);

                Transforms transforms = new Transforms(document);
                transforms.addTransform(c14nMethod);
                String digestMethod = "http://www.w3.org/2000/09/xmldsig#sha1";
                sig.addDocument("#" + id, transforms, digestMethod);
            }
        }

        sig.sign(signingKey);

        String expression = "//ds:Signature[1]";
        Element sigElement =
                (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        assertNotNull(sigElement);

        return sig;
    }

    private void verify(
        Document document,
        Key key,
        List<String> localNames
    ) throws Exception {
        verify(document, key, localNames, true);
    }

    private void verify(
        Document document,
        Key key,
        List<String> localNames,
        boolean secureValidation
    ) throws Exception {
        XPathFactory xpf = XPathFactory.newInstance();
        XPath xpath = xpf.newXPath();
        xpath.setNamespaceContext(new DSNamespaceContext());

        String expression = "//dsig:Signature[1]";
        Element sigElement =
            (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        assertNotNull(sigElement);

        for (String name : localNames) {
            expression = "//*[local-name()='" + name + "']";
            Element signedElement =
                (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
            assertNotNull(signedElement);
            signedElement.setIdAttributeNS(null, "Id", true);
        }

        XMLSignature signature = new XMLSignature(sigElement, "", secureValidation);

        assertTrue(signature.checkSignatureValue(key));
    }

}
