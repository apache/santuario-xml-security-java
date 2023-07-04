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


import java.lang.reflect.Constructor;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.test.dom.TestUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;


/**
 * A test to make sure that the various digest algorithms are working
 */
public class DigestAlgorithmTest {

    private static boolean bcInstalled;

    static {
        org.apache.xml.security.Init.init();
    }

    public DigestAlgorithmTest() throws Exception {
        //
        // If the BouncyCastle provider is not installed, then try to load it
        // via reflection.
        //
        if (Security.getProvider("BC") == null) {
            Constructor<?> cons = null;
            try {
                final Class<?> c = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                cons = c.getConstructor(new Class[] {});
            } catch (final Exception e) {
                //ignore
            }
            if (cons != null) {
                final Provider provider = (Provider)cons.newInstance();
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
    public void testSHA1() throws Exception {
        final Document doc = TestUtils.newDocument();

        final MessageDigestAlgorithm digestAlgorithm =
            MessageDigestAlgorithm.getInstance(doc, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1);
        assertEquals(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1, digestAlgorithm.getAlgorithmURI());

        final byte[] digest = digestAlgorithm.digest("test-string".getBytes());
        assertNotNull(digest);
        assertTrue(digest.length > 0);

        // Now compare against a JDK MessageDigest Object
        final MessageDigest md = MessageDigest.getInstance("SHA-1");
        final byte[] digest2 = md.digest("test-string".getBytes());
        assertArrayEquals(digest, digest2);
    }

    @Test
    public void testSHA224() throws Exception {
        final Document doc = TestUtils.newDocument();

        final MessageDigestAlgorithm digestAlgorithm =
            MessageDigestAlgorithm.getInstance(doc, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA224);
        assertEquals(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA224, digestAlgorithm.getAlgorithmURI());

        final byte[] digest = digestAlgorithm.digest("test-string".getBytes());
        assertNotNull(digest);
        assertTrue(digest.length > 0);

        // Now compare against a JDK MessageDigest Object
        final MessageDigest md = MessageDigest.getInstance("SHA-224");
        final byte[] digest2 = md.digest("test-string".getBytes());
        assertArrayEquals(digest, digest2);
    }

    @Test
    public void testSHA256() throws Exception {
        final Document doc = TestUtils.newDocument();

        final MessageDigestAlgorithm digestAlgorithm =
            MessageDigestAlgorithm.getInstance(doc, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
        assertEquals(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256, digestAlgorithm.getAlgorithmURI());

        final byte[] digest = digestAlgorithm.digest("test-string".getBytes());
        assertNotNull(digest);
        assertTrue(digest.length > 0);

        // Now compare against a JDK MessageDigest Object
        final MessageDigest md = MessageDigest.getInstance("SHA-256");
        final byte[] digest2 = md.digest("test-string".getBytes());
        assertArrayEquals(digest, digest2);
    }

    @Test
    public void testSHA384() throws Exception {
        final Document doc = TestUtils.newDocument();

        final MessageDigestAlgorithm digestAlgorithm =
            MessageDigestAlgorithm.getInstance(doc, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384);
        assertEquals(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA384, digestAlgorithm.getAlgorithmURI());

        final byte[] digest = digestAlgorithm.digest("test-string".getBytes());
        assertNotNull(digest);
        assertTrue(digest.length > 0);

        // Now compare against a JDK MessageDigest Object
        final MessageDigest md = MessageDigest.getInstance("SHA-384");
        final byte[] digest2 = md.digest("test-string".getBytes());
        assertArrayEquals(digest, digest2);
    }

    @Test
    public void testSHA512() throws Exception {
        final Document doc = TestUtils.newDocument();

        final MessageDigestAlgorithm digestAlgorithm =
            MessageDigestAlgorithm.getInstance(doc, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512);
        assertEquals(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512, digestAlgorithm.getAlgorithmURI());

        final byte[] digest = digestAlgorithm.digest("test-string".getBytes());
        assertNotNull(digest);
        assertTrue(digest.length > 0);

        // Now compare against a JDK MessageDigest Object
        final MessageDigest md = MessageDigest.getInstance("SHA-512");
        final byte[] digest2 = md.digest("test-string".getBytes());
        assertArrayEquals(digest, digest2);
    }

    @Test
    public void testMD5() throws Exception {
        final Document doc = TestUtils.newDocument();

        final MessageDigestAlgorithm digestAlgorithm =
            MessageDigestAlgorithm.getInstance(doc, MessageDigestAlgorithm.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5);
        assertEquals(MessageDigestAlgorithm.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5, digestAlgorithm.getAlgorithmURI());

        final byte[] digest = digestAlgorithm.digest("test-string".getBytes());
        assertNotNull(digest);
        assertTrue(digest.length > 0);

        // Now compare against a JDK MessageDigest Object
        final MessageDigest md = MessageDigest.getInstance("MD5");
        final byte[] digest2 = md.digest("test-string".getBytes());
        assertArrayEquals(digest, digest2);
    }

    @Test
    public void testRIPEMD160() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        final Document doc = TestUtils.newDocument();

        final MessageDigestAlgorithm digestAlgorithm =
            MessageDigestAlgorithm.getInstance(doc, MessageDigestAlgorithm.ALGO_ID_DIGEST_RIPEMD160);
        assertEquals(MessageDigestAlgorithm.ALGO_ID_DIGEST_RIPEMD160, digestAlgorithm.getAlgorithmURI());

        final byte[] digest = digestAlgorithm.digest("test-string".getBytes());
        assertNotNull(digest);
        assertTrue(digest.length > 0);

        // Now compare against a JDK MessageDigest Object
        final MessageDigest md = MessageDigest.getInstance("RIPEMD160");
        final byte[] digest2 = md.digest("test-string".getBytes());
        assertArrayEquals(digest, digest2);
    }

    @Test
    public void testWhirlpool() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        final Document doc = TestUtils.newDocument();

        final MessageDigestAlgorithm digestAlgorithm =
            MessageDigestAlgorithm.getInstance(doc, MessageDigestAlgorithm.ALGO_ID_DIGEST_WHIRLPOOL);
        assertEquals(MessageDigestAlgorithm.ALGO_ID_DIGEST_WHIRLPOOL, digestAlgorithm.getAlgorithmURI());

        final byte[] digest = digestAlgorithm.digest("test-string".getBytes());
        assertNotNull(digest);
        assertTrue(digest.length > 0);

        // Now compare against a JDK MessageDigest Object
        final MessageDigest md = MessageDigest.getInstance("WHIRLPOOL");
        final byte[] digest2 = md.digest("test-string".getBytes());
        assertArrayEquals(digest, digest2);
    }

    @Test
    public void testSHA3_224() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        final Document doc = TestUtils.newDocument();

        final MessageDigestAlgorithm digestAlgorithm =
            MessageDigestAlgorithm.getInstance(doc, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_224);
        assertEquals(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_224, digestAlgorithm.getAlgorithmURI());

        final byte[] digest = digestAlgorithm.digest("test-string".getBytes());
        assertNotNull(digest);
        assertTrue(digest.length > 0);

        // Now compare against a JDK MessageDigest Object
        final MessageDigest md = MessageDigest.getInstance("SHA3-224");
        final byte[] digest2 = md.digest("test-string".getBytes());
        assertArrayEquals(digest, digest2);
    }

    @Test
    public void testSHA3_256() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        final Document doc = TestUtils.newDocument();

        final MessageDigestAlgorithm digestAlgorithm =
            MessageDigestAlgorithm.getInstance(doc, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_256);
        assertEquals(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_256, digestAlgorithm.getAlgorithmURI());

        final byte[] digest = digestAlgorithm.digest("test-string".getBytes());
        assertNotNull(digest);
        assertTrue(digest.length > 0);

        // Now compare against a JDK MessageDigest Object
        final MessageDigest md = MessageDigest.getInstance("SHA3-256");
        final byte[] digest2 = md.digest("test-string".getBytes());
        assertArrayEquals(digest, digest2);
    }

    @Test
    public void testSHA3_384() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        final Document doc = TestUtils.newDocument();

        final MessageDigestAlgorithm digestAlgorithm =
            MessageDigestAlgorithm.getInstance(doc, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_384);
        assertEquals(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_384, digestAlgorithm.getAlgorithmURI());

        final byte[] digest = digestAlgorithm.digest("test-string".getBytes());
        assertNotNull(digest);
        assertTrue(digest.length > 0);

        // Now compare against a JDK MessageDigest Object
        final MessageDigest md = MessageDigest.getInstance("SHA3-384");
        final byte[] digest2 = md.digest("test-string".getBytes());
        assertArrayEquals(digest, digest2);
    }

    @Test
    public void testSHA3_512() throws Exception {
        Assumptions.assumeTrue(bcInstalled);
        final Document doc = TestUtils.newDocument();

        final MessageDigestAlgorithm digestAlgorithm =
            MessageDigestAlgorithm.getInstance(doc, MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_512);
        assertEquals(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_512, digestAlgorithm.getAlgorithmURI());

        final byte[] digest = digestAlgorithm.digest("test-string".getBytes());
        assertNotNull(digest);
        assertTrue(digest.length > 0);

        // Now compare against a JDK MessageDigest Object
        final MessageDigest md = MessageDigest.getInstance("SHA3-512");
        final byte[] digest2 = md.digest("test-string".getBytes());
        assertArrayEquals(digest, digest2);
    }

    @Test
    public void testNullAlgorithm() throws Exception {
        assertThrows(XMLSignatureException.class, () ->
                MessageDigestAlgorithm.getInstance(TestUtils.newDocument(), null));
    }

    @Test
    public void testNoSuchAlgorithm() throws Exception {
        assertThrows(XMLSignatureException.class, () ->
                MessageDigestAlgorithm.getInstance(TestUtils.newDocument(), "xyz"));
    }
}
