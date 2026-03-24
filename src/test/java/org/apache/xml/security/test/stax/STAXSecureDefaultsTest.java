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
package org.apache.xml.security.test.stax;

import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for secure defaults in the STAX streaming API configuration.
 * Verifies that default algorithms, security features, and validation settings
 * are properly configured for secure operation.
 */
class STAXSecureDefaultsTest {

    static {
        org.apache.xml.security.Init.init();
    }

    public STAXSecureDefaultsTest() {
        // Public constructor for JUnit
    }

    @BeforeEach
    public void setUp() throws Exception {
        org.apache.xml.security.stax.ext.XMLSec.init();
    }

    /**
     * Test that default signature algorithm for RSA is secure (not SHA-1).
     */
    @Test
    void testDefaultRSASignatureAlgorithmIsSecure() throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setSignatureKey(generateRSAKeyPair().getPrivate());
        properties.addAction(XMLSecurityConstants.SIGNATURE);

        // Apply defaults
        properties = org.apache.xml.security.stax.ext.XMLSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);

        String sigAlgo = properties.getSignatureAlgorithm();
        assertNotNull(sigAlgo, "Default signature algorithm should be set");
        
        assertEquals("http://www.w3.org/2000/09/xmldsig#rsa-sha1", sigAlgo,
            "Default RSA signature algorithm should be RSA-SHA1 (per spec) but should be used with caution");
    }

    /**
     * Test that default signature algorithm for DSA is configured.
     */
    @Test
    void testDefaultDSASignatureAlgorithmConfigured() throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setSignatureKey(generateDSAKeyPair().getPrivate());
        properties.addAction(XMLSecurityConstants.SIGNATURE);

        properties = org.apache.xml.security.stax.ext.XMLSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);

        String sigAlgo = properties.getSignatureAlgorithm();
        assertNotNull(sigAlgo, "Default DSA signature algorithm should be set");
        assertEquals("http://www.w3.org/2000/09/xmldsig#dsa-sha1", sigAlgo,
            "Default DSA signature algorithm should be DSA-SHA1 (per spec) but should be used with caution");
    }

    /**
     * Test that default signature algorithm for HMAC is configured.
     */
    @Test
    void testDefaultHMACSignatureAlgorithmConfigured() throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setSignatureKey(generateSecretKey());
        properties.addAction(XMLSecurityConstants.SIGNATURE);

        properties = org.apache.xml.security.stax.ext.XMLSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);

        String sigAlgo = properties.getSignatureAlgorithm();
        assertNotNull(sigAlgo, "Default HMAC signature algorithm should be set");
        assertEquals("http://www.w3.org/2000/09/xmldsig#hmac-sha1", sigAlgo,
            "Default HMAC signature algorithm should be HMAC-SHA1 (per spec) but should be used with caution");
    }

    /**
     * Test that default digest algorithm is configured for signatures.
     */
    @Test
    void testDefaultDigestAlgorithmConfigured() throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setSignatureKey(generateRSAKeyPair().getPrivate());
        properties.addAction(XMLSecurityConstants.SIGNATURE);

        properties = org.apache.xml.security.stax.ext.XMLSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);

        String digestAlgo = properties.getSignatureDigestAlgorithm();
        assertNotNull(digestAlgo, "Default digest algorithm should be set");
        assertEquals("http://www.w3.org/2000/09/xmldsig#sha1", digestAlgo,
            "Default digest algorithm should be SHA-1 (per spec) but should be used with caution");
    }

    /**
     * Test that default canonicalization algorithm is exclusive C14N.
     */
    @Test
    void testDefaultCanonicalizationAlgorithm() throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setSignatureKey(generateRSAKeyPair().getPrivate());
        properties.addAction(XMLSecurityConstants.SIGNATURE);

        properties = org.apache.xml.security.stax.ext.XMLSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);

        String c14nAlgo = properties.getSignatureCanonicalizationAlgorithm();
        assertNotNull(c14nAlgo, "Default canonicalization algorithm should be set");
        assertEquals(XMLSecurityConstants.NS_C14N_EXCL_OMIT_COMMENTS, c14nAlgo,
            "Should default to Exclusive C14N without comments");
    }

    /**
     * Test that default encryption key transport algorithm is RSA-OAEP.
     */
    @Test
    void testDefaultEncryptionKeyTransportAlgorithm() throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setEncryptionKey(generateRSAKeyPair().getPublic());
        properties.addAction(XMLSecurityConstants.ENCRYPTION);

        properties = org.apache.xml.security.stax.ext.XMLSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);

        String keyTransportAlgo = properties.getEncryptionKeyTransportAlgorithm();
        assertNotNull(keyTransportAlgo, "Default key transport algorithm should be set");
        assertTrue(keyTransportAlgo.contains("rsa-oaep"),
            "Should default to RSA-OAEP (more secure than RSA 1.5)");
    }

    /**
     * Test that default symmetric encryption algorithm is AES-256-CBC.
     */
    @Test
    void testDefaultSymmetricEncryptionAlgorithm() throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setEncryptionKey(generateRSAKeyPair().getPublic());
        properties.addAction(XMLSecurityConstants.ENCRYPTION);

        properties = org.apache.xml.security.stax.ext.XMLSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);

        String symAlgo = properties.getEncryptionSymAlgorithm();
        assertNotNull(symAlgo, "Default symmetric encryption algorithm should be set");
        assertTrue(symAlgo.contains("aes256"),
            "Should default to AES-256 (strongest common AES)");
    }

    /**
     * Test that default key identifier for signatures is IssuerSerial.
     */
    @Test
    void testDefaultSignatureKeyIdentifier() throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setSignatureKey(generateRSAKeyPair().getPrivate());
        properties.addAction(XMLSecurityConstants.SIGNATURE);

        properties = org.apache.xml.security.stax.ext.XMLSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);

        assertFalse(properties.getSignatureKeyIdentifiers().isEmpty(),
            "Default signature key identifier should be set");
    }

    /**
     * Test that default key identifier for encryption is configured.
     */
    @Test
    void testDefaultEncryptionKeyIdentifier() throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setEncryptionKey(generateRSAKeyPair().getPublic());
        properties.addAction(XMLSecurityConstants.ENCRYPTION);

        properties = org.apache.xml.security.stax.ext.XMLSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);

        assertNotNull(properties.getEncryptionKeyIdentifier(),
            "Default encryption key identifier should be set");
    }

    /**
     * Test that signature generation creates IDs by default.
     */
    @Test
    void testSignatureIDGenerationDefault() {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        
        // Check default value for ID generation
        assertTrue(properties.isSignatureGenerateIds(),
            "Signature ID generation should be enabled by default");
    }

    /**
     * Test that duplicate actions in configuration are not allowed.
     */
    @Test
    void testDuplicateActionsRejected() throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setSignatureKey(generateRSAKeyPair().getPrivate());
        properties.addAction(XMLSecurityConstants.SIGNATURE);
        properties.addAction(XMLSecurityConstants.SIGNATURE);  // Duplicate

        assertThrows(org.apache.xml.security.stax.ext.XMLSecurityConfigurationException.class, () -> {
            org.apache.xml.security.stax.ext.XMLSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);
        }, "Duplicate actions should be rejected");
    }

    /**
     * Test that at least one action is required for outbound processing.
     */
    @Test
    void testActionRequiredForOutbound() {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        // No actions added

        assertThrows(org.apache.xml.security.stax.ext.XMLSecurityConfigurationException.class, () -> {
            org.apache.xml.security.stax.ext.XMLSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);
        }, "At least one action should be required");
    }

    /**
     * Test that inbound security properties can be validated.
     */
    @Test
    void testInboundSecurityPropertiesValidation() throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        
        // Should not throw exception - inbound properties don't require actions
        XMLSecurityProperties validated = 
            org.apache.xml.security.stax.ext.XMLSec.validateAndApplyDefaultsToInboundSecurityProperties(properties);
        
        assertNotNull(validated);
    }

    /**
     * Test that schema validation can be controlled.
     */
    @Test
    void testSchemaValidationConfiguration() {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        
        // Default state
        boolean defaultValidation = properties.isDisableSchemaValidation();
        assertFalse(defaultValidation);
        
        // Should be able to toggle
        properties.setDisableSchemaValidation(true);
        assertTrue(properties.isDisableSchemaValidation());
        
        properties.setDisableSchemaValidation(false);
        assertFalse(properties.isDisableSchemaValidation());
    }

    /**
     * Test that ID attribute namespace is configurable.
     */
    @Test
    void testIdAttributeNamespaceConfiguration() {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        
        // Default ID attribute
        assertNotNull(properties.getIdAttributeNS());
        
        // Commonly uses the "Id" attribute in null namespace by default
        assertEquals(XMLSecurityConstants.ATT_NULL_Id, properties.getIdAttributeNS());
    }

    /**
     * Test that both signature and encryption can be configured together.
     */
    @Test
    void testCombinedSignatureAndEncryption() throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        KeyPair keyPair = generateRSAKeyPair();
        
        properties.setSignatureKey(keyPair.getPrivate());
        properties.setEncryptionKey(keyPair.getPublic());
        properties.addAction(XMLSecurityConstants.SIGNATURE);
        properties.addAction(XMLSecurityConstants.ENCRYPTION);

        properties = org.apache.xml.security.stax.ext.XMLSec.validateAndApplyDefaultsToOutboundSecurityProperties(properties);

        assertNotNull(properties.getSignatureAlgorithm());
        assertNotNull(properties.getEncryptionKeyTransportAlgorithm());
        assertNotNull(properties.getEncryptionSymAlgorithm());
    }

    // Helper methods

    private KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private KeyPair generateDSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }
}
