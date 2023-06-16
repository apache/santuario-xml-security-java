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
package org.apache.xml.security.test.dom.keys.storage;


import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.NoSuchElementException;

import org.apache.xml.security.keys.storage.implementations.KeyStoreResolver;
import org.junit.jupiter.api.Test;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * KeyStore StorageResolver test.
 */
class KeyStoreResolverTest {

    @Test
    void testKeyStoreResolver() throws Exception {

        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        KeyStore ks = KeyStore.getInstance("JCEKS");
        try (FileInputStream f = new FileInputStream(resolveFile("src", "test", "resources", "org", "apache", "xml",
            "security", "samples", "input", "keystore2.jks"))) {
            ks.load(f, "xmlsecurity".toCharArray());
        }

        KeyStoreResolver ksResolver = new KeyStoreResolver(ks);
        Iterator<?> iter = ksResolver.getIterator();
        checkIterator(iter);

        // check new iterator starts from the beginning
        Iterator<?> iter2 = ksResolver.getIterator();
        checkIterator(iter2);

        // check the iterators are independent
        // check calling next() without calling hasNext()
        iter = ksResolver.getIterator();
        iter2 = ksResolver.getIterator();

        while (iter.hasNext()) {
            X509Certificate cert = (X509Certificate) iter.next();
            X509Certificate cert2 = (X509Certificate) iter2.next();
            if (!cert.equals(cert2)) {
                fail("KeyStoreResolver iterators are not independent");
            }
        }
        assertFalse(iter2.hasNext());
    }

    private void checkIterator(Iterator<?> iter) {
        int count = 0;
        iter.hasNext(); // hasNext() is idempotent

        while (iter.hasNext()) {
            X509Certificate cert = (X509Certificate) iter.next();
            cert.getSubjectX500Principal().getName();
            count++;
        }

        // The iterator skipped over symmetric keys
        assertEquals(3, count);

        // Cannot go beyond last element
        try {
            iter.next();
            fail("Expecting NoSuchElementException");
        } catch (NoSuchElementException e) {
            //
        }
    }

}