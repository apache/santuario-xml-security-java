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
package org.apache.xml.security.test.stax.encryption;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;

import org.apache.xml.security.binding.xmlenc.CipherDataType;
import org.apache.xml.security.binding.xmlenc.CipherValueType;
import org.apache.xml.security.binding.xmlenc.EncryptedKeyType;
import org.apache.xml.security.binding.xmlenc.EncryptionMethodType;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.stax.XMLSecEventFactory;
import org.apache.xml.security.stax.impl.InboundSecurityContextImpl;
import org.apache.xml.security.stax.impl.InputProcessorChainImpl;
import org.apache.xml.security.stax.impl.processor.input.XMLEncryptedKeyInputHandler;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * When an EncryptedKey cannot be unwrapped, a random key is used in its place. That key must be
 * usable with an algorithm that does not define a key length, such as HMAC, so that a failed
 * unwrap is not distinguishable from a key that simply does not verify.
 */
class EncryptedKeyFakeKeyTest {

    private static final String RSA_OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
    private static final String HMAC_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";

    @BeforeEach
    public void setUp() throws Exception {
        XMLSec.init();
    }

    @Test
    void testFakeKeyForHmac() throws Exception {
        KeyStore keyStore = XmlSecTestEnvironment.getTransmitterKeyStore();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("transmitter",
            XmlSecTestEnvironment.TRANSMITTER_KS_PASSWORD.toCharArray());
        XMLSecurityProperties properties = new XMLSecurityProperties();
        properties.setDecryptionKey(privateKey);

        // An EncryptedKey whose CipherValue does not decrypt under the private key
        byte[] garbage = new byte[256];
        new SecureRandom().nextBytes(garbage);
        CipherValueType cipherValue = new CipherValueType();
        cipherValue.getContent().add(Base64.getEncoder().encodeToString(garbage));
        CipherDataType cipherData = new CipherDataType();
        cipherData.setCipherValue(cipherValue);
        EncryptionMethodType encryptionMethod = new EncryptionMethodType();
        encryptionMethod.setAlgorithm(RSA_OAEP);
        EncryptedKeyType encryptedKey = new EncryptedKeyType();
        encryptedKey.setEncryptionMethod(encryptionMethod);
        encryptedKey.setCipherData(cipherData);
        encryptedKey.setId("EK-1");

        InboundSecurityContextImpl securityContext = new InboundSecurityContextImpl();
        InputProcessorChainImpl inputProcessorChain = new InputProcessorChainImpl(securityContext);
        new XMLEncryptedKeyInputHandler().handle(inputProcessorChain, encryptedKey,
            XMLSecEventFactory.createXmlSecStartElement(XMLSecurityConstants.TAG_xenc_EncryptedKey,
                Collections.emptyList(), Collections.emptyList()),
            properties);

        InboundSecurityToken token = securityContext.getSecurityTokenProvider("EK-1").getSecurityToken();
        Key key = token.getSecretKey(HMAC_SHA256, XMLSecurityConstants.Sym_Sig, "EK-1");
        assertEquals(32, key.getEncoded().length);
    }
}
