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
package org.apache.xml.security.stax.impl.securityToken;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.xml.bind.JAXBElement;

import org.apache.xml.security.binding.xmldsig.KeyInfoType;
import org.apache.xml.security.binding.xmldsig.ObjectFactory;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.ext.InboundSecurityContext;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.impl.InboundSecurityContextImpl;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;
import org.apache.xml.security.stax.securityToken.SecurityTokenFactory;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.apache.xml.security.stax.securityToken.SecurityTokenConstants.KeyIdentifier_KeyName;
import static org.apache.xml.security.test.stax.utils.KeyLoader.loadPublicKey;
import static org.junit.Assert.*;

public class SecurityTokenFactoryImplTest {
    private KeyInfoType keyInfoType;
    private XMLSecurityProperties xmlSecurityProperties;
    private InboundSecurityContext inboundSecurityContext;

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
        Init.init(null, this.getClass());

        ObjectFactory of = new ObjectFactory();

        JAXBElement<String> keyname = of.createKeyName("mykey");
        keyInfoType = new KeyInfoType();
        keyInfoType.setId("KeyName");
        keyInfoType.getContent().add(keyname);

        xmlSecurityProperties = new XMLSecurityProperties();

        inboundSecurityContext = new InboundSecurityContextImpl();

    }

    @Test
    public void testKeyNameToken() throws Exception {
        SecurityTokenFactory factory = new SecurityTokenFactoryImpl();

        SecurityTokenConstants.KeyUsage keyUsage = SecurityTokenConstants.KeyUsage_Signature_Verification;

        xmlSecurityProperties.addKeyNameMapping("mykey", loadPublicKey("dsa.key", "DSA"));

        InboundSecurityToken token =
                factory.getSecurityToken(keyInfoType, keyUsage, xmlSecurityProperties, inboundSecurityContext);

        assertEquals(KeyIdentifier_KeyName, token.getKeyIdentifier());
        assertNotNull(token.getPublicKey());
        assertEquals("DSA", token.getPublicKey().getAlgorithm());
    }

    @Test
    public void testKeyNameTokenWithSignatureVerificationKeySet() throws Exception {
        SecurityTokenFactory factory = new SecurityTokenFactoryImpl();

        SecurityTokenConstants.KeyUsage keyUsage = SecurityTokenConstants.KeyUsage_Signature_Verification;

        xmlSecurityProperties.addKeyNameMapping("mykey", loadPublicKey("dsa.key", "DSA"));
        xmlSecurityProperties.setSignatureVerificationKey(loadPublicKey("rsa.key", "RSA"));

        InboundSecurityContext inboundSecurityContext = new InboundSecurityContextImpl();

        InboundSecurityToken token =
                factory.getSecurityToken(keyInfoType, keyUsage, xmlSecurityProperties, inboundSecurityContext);

        assertEquals(KeyIdentifier_KeyName, token.getKeyIdentifier());
        assertNotNull(token.getPublicKey());
        assertEquals("RSA", token.getPublicKey().getAlgorithm());
    }

    @Test
    public void testKeyNameTokenWithoutKeyInMap() throws Exception {
        expectedException.expect(XMLSecurityException.class);
        expectedException.expectMessage("No key configured for KeyName: mykey");

        SecurityTokenFactory factory = new SecurityTokenFactoryImpl();

        SecurityTokenConstants.KeyUsage keyUsage = SecurityTokenConstants.KeyUsage_Signature_Verification;


        InboundSecurityContext inboundSecurityContext = new InboundSecurityContextImpl();

        factory.getSecurityToken(keyInfoType, keyUsage, xmlSecurityProperties, inboundSecurityContext);
    }

    @Test
    public void testKeyNameTokenWithWrongKeyInMap() throws Exception {
        expectedException.expect(XMLSecurityException.class);
        expectedException.expectMessage("Key of type DSAPrivateKey not supported for a KeyName lookup");

        SecurityTokenFactory factory = new SecurityTokenFactoryImpl();

        SecurityTokenConstants.KeyUsage keyUsage = SecurityTokenConstants.KeyUsage_Signature_Verification;

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
        KeyPair keyPair = keyGen.generateKeyPair();
        Key privateKey = keyPair.getPrivate();

        xmlSecurityProperties.addKeyNameMapping("mykey", privateKey);

        InboundSecurityContext inboundSecurityContext = new InboundSecurityContextImpl();

        factory.getSecurityToken(keyInfoType, keyUsage, xmlSecurityProperties, inboundSecurityContext);
    }

}
