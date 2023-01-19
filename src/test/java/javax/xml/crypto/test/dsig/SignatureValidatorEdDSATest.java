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
package javax.xml.crypto.test.dsig;


import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.test.KeySelectors;
import java.nio.file.Paths;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;


/**
 * This is a testcase validates various EdDSA XML signatures
 */
public class SignatureValidatorEdDSATest {

    private SignatureValidator testInstance;

    private static boolean bcAddedForTheTest = false;

    @org.junit.jupiter.api.BeforeAll
    public static void beforeTest() {
        Security.insertProviderAt
                (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
        // Since JDK 15, the EdDSA algorithms are supported in the default java JCA provider.
        // Add BouncyCastleProvider only for java versions before JDK 15.
        boolean isNotJDK15up;
        try {
            int javaVersion = Integer.parseInt(System.getProperty("java.specification.version"));
            isNotJDK15up = javaVersion < 15;
        } catch (NumberFormatException ex) {
            isNotJDK15up = true;
        }
        if (isNotJDK15up && Security.getProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            bcAddedForTheTest = true;
        }
    }

    @org.junit.jupiter.api.AfterAll
    public static void afterAll() {
        if (bcAddedForTheTest) {
            Security.removeProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME);
        }
    }

    @org.junit.jupiter.api.BeforeEach
    public void before() {
        String base = System.getProperty("basedir", "./");
        testInstance = new SignatureValidator(Paths.get(base, "src", "test", "resources", "javax", "xml", "crypto", "dsig", "eddsa").toFile());
    }

    /**
     * Validates a signature that references an element with an ID attribute.
     * The element's ID needs to be registered so that it can be found.
     */
    @ParameterizedTest
    @CsvSource({"envelopingSignatureEd25519.xml,true,Signature failed core validation",
            "envelopingSignatureEd448.xml,true,Signature failed core validation",
            "envelopingInvalidSignatureEd25519.xml,false,Invalid signature should fail!",
            "envelopingInvalidSignatureEd448.xml,false,Invalid signature should fail!"})
    public void test_enveloping_signature_with_ID(String filename, String result, String message) throws Exception {
        DOMValidateContext vc = testInstance.getValidateContext
                (filename, new KeySelectors.RawX509KeySelector());
        updateIdReferences(vc);

        boolean coreValidity = testInstance.validate(vc);
        // assert expected result
        assertEquals(Boolean.valueOf(result), coreValidity, message);
    }

    protected void updateIdReferences(DOMValidateContext vc) {
        Document doc = vc.getNode().getOwnerDocument();
        NodeList nl = doc.getElementsByTagName("Assertion");
        vc.setIdAttributeNS((Element) nl.item(0), null, "AssertionID");
    }
}
