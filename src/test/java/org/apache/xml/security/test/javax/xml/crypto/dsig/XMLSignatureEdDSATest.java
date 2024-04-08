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
package org.apache.xml.security.test.javax.xml.crypto.dsig;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;


/**
 * Unit test for EdDSA javax.xml.crypto.dsig.XMLSignature creation, the test
 * uses the EdDSA signature algorithm with Ed25519 and Ed448 curves. For JDK versions
 * before 15, the BouncyCastle provider is needed to support the EdDSA algorithms.
 *
 * To execute just this tests class run the following command
 * (for JDK16+ you can skip the profile "bouncycastle"
 * <code>mvn test -Dtest=XMLSignatureEdDSATest -P bouncycastle</code>
 *
 */
class XMLSignatureEdDSATest extends EdDSATestAbstract {


    @ParameterizedTest
    @CsvSource({"http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519,ed25519",
            "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed448,ed448",
    })
    void createEdDSASignatureTest(String signatureAlgorithm, String alias) throws Exception {
        Assumptions.assumeTrue(isEdDSASupported());
        byte[] buff = doSignWithJcpApi(signatureAlgorithm, alias, false);
        Assertions.assertNotNull(buff);
        assertValidSignatureWithJcpApi(buff, false);
    }
}
