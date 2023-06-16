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
package org.apache.xml.security.test.stax.signature;

import java.lang.reflect.Constructor;
import java.security.Key;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;
import java.util.UUID;

import javax.xml.stream.XMLInputFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.impl.securityToken.KeyNameSecurityToken;
import org.apache.xml.security.stax.impl.securityToken.X509IssuerSerialSecurityToken;
import org.apache.xml.security.stax.impl.securityToken.X509SecurityToken;
import org.apache.xml.security.stax.impl.securityToken.X509SubjectNameSecurityToken;
import org.apache.xml.security.stax.securityEvent.AlgorithmSuiteSecurityEvent;
import org.apache.xml.security.stax.securityEvent.DefaultTokenSecurityEvent;
import org.apache.xml.security.stax.securityEvent.KeyNameTokenSecurityEvent;
import org.apache.xml.security.stax.securityEvent.KeyValueTokenSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.SignatureValueSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SignedElementSecurityEvent;
import org.apache.xml.security.stax.securityEvent.X509TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
import org.apache.xml.security.test.dom.DSNamespaceContext;
import org.apache.xml.security.test.stax.utils.XMLSecEventAllocator;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 */
public class AbstractSignatureVerificationTest {

    protected static boolean bcInstalled;

    protected XMLInputFactory xmlInputFactory;
    protected TransformerFactory transformerFactory = TransformerFactory.newInstance();

    @BeforeAll
    public static void setup() throws Exception {
        Init.init(AbstractSignatureVerificationTest.class.getClassLoader().getResource("security-config.xml").toURI(),
                AbstractSignatureVerificationTest.class);
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

    @BeforeEach
    public void createXMLInputFactory() throws Exception {
        xmlInputFactory = XMLInputFactory.newInstance();
        xmlInputFactory.setEventAllocator(new XMLSecEventAllocator());
    }

    /**
     * Sign the document using DOM
     */
    protected XMLSignature signUsingDOM(
            String algorithm,
            Document document,
            List<String> localNames,
            Key signingKey
    ) throws Exception {
        String c14nMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
        return signUsingDOM(algorithm, document, localNames, signingKey, c14nMethod, (List<ReferenceInfo>)null);
    }

    /**
     * Sign the document using DOM
     */
    protected XMLSignature signUsingDOM(
            String algorithm,
            Document document,
            List<String> localNames,
            String referenceC14Nmethod,
            Key signingKey
    ) throws Exception {
        String c14nMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
        return signUsingDOM(algorithm, document, localNames, signingKey, c14nMethod, (List<ReferenceInfo>)null);
    }


    /**
     * Sign the document using DOM
     */
    protected XMLSignature signUsingDOM(
            String algorithm,
            Document document,
            List<String> localNames,
            Key signingKey,
            List<ReferenceInfo> additionalReferences,
            ResourceResolverSpi resourceResolverSpi
    ) throws Exception {
        String c14nMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
        return signUsingDOM(algorithm, document, localNames, signingKey, c14nMethod,
                additionalReferences, resourceResolverSpi);
    }

    /**
     * Sign the document using DOM
     */
    protected XMLSignature signUsingDOM(
            String algorithm,
            Document document,
            List<String> localNames,
            Key signingKey,
            List<ReferenceInfo> additionalReferences
    ) throws Exception {
        String c14nMethod = "http://www.w3.org/2001/10/xml-exc-c14n#";
        return signUsingDOM(algorithm, document, localNames, signingKey, c14nMethod, additionalReferences);
    }

    /**
     * Sign the document using DOM
     */
    protected XMLSignature signUsingDOM(
            String algorithm,
            Document document,
            List<String> localNames,
            Key signingKey,
            String c14nMethod
    ) throws Exception {
        String digestMethod = "http://www.w3.org/2000/09/xmldsig#sha1";
        return signUsingDOM(algorithm, document, localNames, signingKey, c14nMethod, digestMethod, null, null, null);
    }

    /**
     * Sign the document using DOM
     */
    protected XMLSignature signUsingDOM(
            String algorithm,
            Document document,
            List<String> localNames,
            Key signingKey,
            String c14nMethod,
            List<ReferenceInfo> additionalReferences,
            ResourceResolverSpi resourceResolverSpi
    ) throws Exception {
        String digestMethod = "http://www.w3.org/2000/09/xmldsig#sha1";
        return signUsingDOM(algorithm, document, localNames, signingKey,
                c14nMethod, digestMethod, additionalReferences, resourceResolverSpi, null);
    }

    /**
     * Sign the document using DOM
     */
    protected XMLSignature signUsingDOM(
            String algorithm,
            Document document,
            List<String> localNames,
            Key signingKey,
            String c14nMethod,
            List<ReferenceInfo> additionalReferences
    ) throws Exception {
        String digestMethod = "http://www.w3.org/2000/09/xmldsig#sha1";
        return signUsingDOM(algorithm, document, localNames, signingKey,
                c14nMethod, digestMethod, additionalReferences, null, null);
    }

    /**
     * Sign the document using DOM
     */
    protected XMLSignature signUsingDOM(
            String algorithm,
            Document document,
            List<String> localNames,
            Key signingKey,
            String c14nMethod,
            String digestMethod
    ) throws Exception {
        return signUsingDOM(algorithm, document, localNames, signingKey, c14nMethod, digestMethod, null, null, null);
    }

    /**
     * Sign the document using DOM
     */
    protected XMLSignature signUsingDOM(
            String algorithm,
            Document document,
            List<String> localNames,
            Key signingKey,
            String c14nMethod,
            String digestMethod,
            List<ReferenceInfo> additionalReferences,
            ResourceResolverSpi resourceResolverSpi,
            AlgorithmParameterSpec spec
    ) throws Exception {
        XMLSignature sig = new XMLSignature(document, "", algorithm, 0, c14nMethod, null, spec);
        if (resourceResolverSpi != null) {
            sig.addResourceResolver(resourceResolverSpi);
        }
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
                sig.addDocument("#" + id, transforms, digestMethod);
            }
        }

        if (additionalReferences != null) {
            for (ReferenceInfo referenceInfo : additionalReferences) {
                if (referenceInfo.isBinary()) {
                    sig.addDocument(referenceInfo.getResource(), null, referenceInfo.getDigestMethod());
                } else {
                    Transforms transforms = new Transforms(document);
                    for (int j = 0; j < referenceInfo.getC14NMethod().length; j++) {
                        String transform = referenceInfo.getC14NMethod()[j];
                        transforms.addTransform(transform);
                    }
                    sig.addDocument(referenceInfo.getResource(), transforms, referenceInfo.getDigestMethod());
                }
            }
        }

        sig.sign(signingKey);

        String expression = "//ds:Signature[1]";
        Element sigElement =
                (Element) xpath.evaluate(expression, document, XPathConstants.NODE);
        assertNotNull(sigElement);

        return sig;
    }

    protected void checkSecurityEvents(TestSecurityEventListener securityEventListener) {
        String c14nAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
        String digestAlgorithm = "http://www.w3.org/2000/09/xmldsig#sha1";
        String signatureMethod = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
        checkSecurityEvents(securityEventListener, c14nAlgorithm, digestAlgorithm, signatureMethod);
    }

    protected void checkSecurityEvents(
            TestSecurityEventListener securityEventListener,
            String c14nAlgorithm,
            String digestAlgorithm,
            String signatureMethod
    ) {
        SignatureValueSecurityEvent sigValueEvent =
                (SignatureValueSecurityEvent) securityEventListener.getSecurityEvent(SecurityEventConstants.SignatureValue);
        assertNotNull(sigValueEvent);
        assertNotNull(sigValueEvent.getSignatureValue());

        List<SecurityEvent> algorithmEvents =
                securityEventListener.getSecurityEvents(SecurityEventConstants.AlgorithmSuite);
        assertFalse(algorithmEvents.isEmpty());

        // C14n algorithm
        for (SecurityEvent event : algorithmEvents) {
            AlgorithmSuiteSecurityEvent algorithmEvent = (AlgorithmSuiteSecurityEvent) event;
            if (XMLSecurityConstants.SigC14n.equals(algorithmEvent.getAlgorithmUsage())
                || XMLSecurityConstants.SigTransform.equals(algorithmEvent.getAlgorithmUsage())) {
                assertEquals(c14nAlgorithm, algorithmEvent.getAlgorithmURI());
            }
        }

        // Digest algorithm
        for (SecurityEvent event : algorithmEvents) {
            AlgorithmSuiteSecurityEvent algorithmEvent = (AlgorithmSuiteSecurityEvent) event;
            if (XMLSecurityConstants.SigDig.equals(algorithmEvent.getAlgorithmUsage())) {
                assertEquals(digestAlgorithm, algorithmEvent.getAlgorithmURI());
            }
        }

        // Signature method
        for (SecurityEvent event : algorithmEvents) {
            AlgorithmSuiteSecurityEvent algorithmEvent = (AlgorithmSuiteSecurityEvent) event;
            if (XMLSecurityConstants.Asym_Sig.equals(algorithmEvent.getAlgorithmUsage())
                    || XMLSecurityConstants.Sym_Sig.equals(algorithmEvent.getAlgorithmUsage())) {
                assertEquals(signatureMethod, algorithmEvent.getAlgorithmURI());
            }
        }
    }

    protected void checkSignedElementSecurityEvents(TestSecurityEventListener securityEventListener) {
        SignedElementSecurityEvent signedElementEvent =
                (SignedElementSecurityEvent) securityEventListener.getSecurityEvent(SecurityEventConstants.SignedElement);
        assertNotNull(signedElementEvent);
        assertEquals(signedElementEvent.getElementPath().size(), 2);
        assertEquals("{urn:example:po}PurchaseOrder", signedElementEvent.getElementPath().get(0).toString());
        assertEquals("{urn:example:po}PaymentInfo", signedElementEvent.getElementPath().get(1).toString());
        assertTrue(signedElementEvent.isSigned());
    }

    protected void checkSignedElementMultipleSecurityEvents(
            TestSecurityEventListener securityEventListener
    ) {
        List<SecurityEvent> signedElements =
                securityEventListener.getSecurityEvents(SecurityEventConstants.SignedElement);
        assertTrue(signedElements.size() == 2);
        SignedElementSecurityEvent signedElementEvent =
                (SignedElementSecurityEvent) signedElements.get(0);
        assertNotNull(signedElementEvent);
        assertEquals(signedElementEvent.getElementPath().size(), 2);
        assertEquals("{urn:example:po}PurchaseOrder", signedElementEvent.getElementPath().get(0).toString());
        assertEquals("{urn:example:po}ShippingAddress", signedElementEvent.getElementPath().get(1).toString());

        assertTrue(signedElementEvent.isSigned());

        signedElementEvent =
                (SignedElementSecurityEvent) signedElements.get(1);
        assertNotNull(signedElementEvent);
        assertEquals(signedElementEvent.getElementPath().size(), 2);
        assertEquals("{urn:example:po}PurchaseOrder", signedElementEvent.getElementPath().get(0).toString());
        assertEquals("{urn:example:po}PaymentInfo", signedElementEvent.getElementPath().get(1).toString());
        assertTrue(signedElementEvent.isSigned());
    }

    protected void checkSignatureToken(
            TestSecurityEventListener securityEventListener,
            X509Certificate cert,
            Key key,
            SecurityTokenConstants.KeyIdentifier keyIdentifier
    ) throws XMLSecurityException {
        if (SecurityTokenConstants.KeyIdentifier_KeyValue.equals(keyIdentifier)) {
            KeyValueTokenSecurityEvent tokenEvent =
                    (KeyValueTokenSecurityEvent) securityEventListener.getSecurityEvent(SecurityEventConstants.KeyValueToken);
            assertNotNull(tokenEvent);
        } else if (SecurityTokenConstants.KeyIdentifier_NoKeyInfo.equals(keyIdentifier)) {
            DefaultTokenSecurityEvent tokenEvent =
                    (DefaultTokenSecurityEvent) securityEventListener.getSecurityEvent(SecurityEventConstants.DefaultToken);
            assertNotNull(tokenEvent);
            Key processedKey = tokenEvent.getSecurityToken().getSecretKey().values().iterator().next();
            assertEquals(processedKey, key);
        } else if (SecurityTokenConstants.KeyIdentifier_KeyName.equals(keyIdentifier)) {
            KeyNameTokenSecurityEvent tokenEvent =
                    (KeyNameTokenSecurityEvent) securityEventListener.getSecurityEvent(SecurityEventConstants.KeyNameToken);
            assertNotNull(tokenEvent);
            Key processedKey = tokenEvent.getSecurityToken().getSecretKey().values().iterator().next();
            assertEquals(processedKey, key);
            assertNotNull(((KeyNameSecurityToken) tokenEvent.getSecurityToken()).getKeyName());
        } else {
            X509TokenSecurityEvent tokenEvent =
                    (X509TokenSecurityEvent) securityEventListener.getSecurityEvent(SecurityEventConstants.X509Token);
            assertNotNull(tokenEvent);
            X509SecurityToken x509SecurityToken =
                    (X509SecurityToken) tokenEvent.getSecurityToken();
            assertNotNull(x509SecurityToken);
            if (SecurityTokenConstants.KeyIdentifier_X509KeyIdentifier.equals(keyIdentifier)) {
                assertEquals(cert, x509SecurityToken.getX509Certificates()[0]);
            } else if (SecurityTokenConstants.KeyIdentifier_X509SubjectName.equals(keyIdentifier)) {
                Key processedKey = x509SecurityToken.getPublicKey();
                assertEquals(processedKey, cert.getPublicKey());
                assertNotNull(((X509SubjectNameSecurityToken) x509SecurityToken).getSubjectName());
            } else if (SecurityTokenConstants.KeyIdentifier_IssuerSerial.equals(keyIdentifier)) {
                Key processedKey = x509SecurityToken.getPublicKey();
                assertEquals(processedKey, cert.getPublicKey());
                assertNotNull(((X509IssuerSerialSecurityToken) x509SecurityToken).getIssuerName());
                assertNotNull(((X509IssuerSerialSecurityToken) x509SecurityToken).getSerialNumber());
            }
        }
    }

    class ReferenceInfo {
        private String resource;
        private String[] c14NMethod;
        private String digestMethod;
        private boolean binary;

        ReferenceInfo(String resource, String[] c14NMethod, String digestMethod, boolean binary) {
            this.resource = resource;
            this.c14NMethod = c14NMethod;
            this.digestMethod = digestMethod;
            this.binary = binary;
        }

        public String getResource() {
            return resource;
        }

        public void setResource(String resource) {
            this.resource = resource;
        }

        public String[] getC14NMethod() {
            return c14NMethod;
        }

        public void setC14NMethod(String[] c14NMethod) {
            this.c14NMethod = c14NMethod;
        }

        public String getDigestMethod() {
            return digestMethod;
        }

        public void setDigestMethod(String digestMethod) {
            this.digestMethod = digestMethod;
        }

        public boolean isBinary() {
            return binary;
        }

        public void setBinary(boolean binary) {
            this.binary = binary;
        }
    }
}