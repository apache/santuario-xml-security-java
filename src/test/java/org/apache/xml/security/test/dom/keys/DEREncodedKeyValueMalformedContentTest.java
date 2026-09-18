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
package org.apache.xml.security.test.dom.keys;

import java.security.Provider;
import java.security.Security;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.content.DEREncodedKeyValue;
import org.apache.xml.security.test.dom.TestUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * {@link DEREncodedKeyValue#getPublicKey()} resolves the key by trying each supported key type's
 * {@code KeyFactory}. Some providers throw an unchecked exception for malformed or short input
 * instead of {@code InvalidKeySpecException} - notably BouncyCastle 1.85's XDH/EdDSA
 * KeyFactorySpi throws {@code ArrayIndexOutOfBoundsException}. Since a DEREncodedKeyValue read
 * from an inbound document (via {@code DEREncodedKeyValueResolver}, a default KeyResolver) is
 * untrusted, attacker-controlled content, such an exception must not propagate out of key
 * resolution.
 *
 * <p>The unchecked exception is only observed when BouncyCastle is the provider selected for
 * XDH/EdDSA, i.e. registered ahead of the JDK's own providers (a common BouncyCastle-primary
 * deployment). With the JDK providers taking precedence they reject the same input cleanly with
 * {@code InvalidKeySpecException}, so this test inserts BouncyCastle at the first position (as
 * {@code XMLCipherTest} does for its BouncyCastle-specific case) and is skipped when BouncyCastle
 * is unavailable.
 */
class DEREncodedKeyValueMalformedContentTest {

    @Test
    void testMalformedDerContentRejectedCleanly() throws Exception {
        boolean bcAtFirstPosition = false;
        if (Security.getProvider("BC") == null) {
            try {
                Class<?> bcClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                Provider bc = (Provider) bcClass.getConstructor().newInstance();
                Security.insertProviderAt(bc, 1);
                bcAtFirstPosition = true;
            } catch (ReflectiveOperationException e) {
                // BouncyCastle not installed, ignore
            }
        }
        assumeTrue(bcAtFirstPosition, "requires BouncyCastle at first provider position");

        try {
            Document doc = TestUtils.newDocument();
            // Bytes that decode to no valid SubjectPublicKeyInfo; short enough that BouncyCastle
            // 1.85's XDH/EdDSA KeyFactory reads past the end (ArrayIndexOutOfBoundsException).
            DEREncodedKeyValue derEncodedKeyValue =
                    new DEREncodedKeyValue(doc, new byte[]{0, 1, 2, 3, 4, 5, 6, 7});

            // Must fail cleanly with the declared XMLSecurityException, not an uncaught
            // RuntimeException such as ArrayIndexOutOfBoundsException.
            assertThrows(XMLSecurityException.class, derEncodedKeyValue::getPublicKey);
        } finally {
            Security.removeProvider("BC");
        }
    }
}
