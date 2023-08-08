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


import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.NoSuchElementException;

import org.apache.xml.security.keys.storage.StorageResolver;
import org.junit.jupiter.api.Test;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * KeyStore StorageResolver test.
 */
class StorageResolverTest {

    @Test
    void testStorageResolver() throws Exception {

        //
        // This test fails with the IBM JDK
        //
        if ("IBM Corporation".equals(System.getProperty("java.vendor"))) {
            return;
        }

        File inputDir = resolveFile("src", "test", "resources", "org", "apache", "xml", "security", "samples", "input");
        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream inStream = new FileInputStream(new File(inputDir, "keystore.jks"))) {
            ks.load(inStream, "xmlsecurity".toCharArray());
        }

        KeyStore ks2 = KeyStore.getInstance("JCEKS");
        try (FileInputStream inStream2 = new FileInputStream(new File(inputDir, "keystore2.jks"))) {
            ks2.load(inStream2, "xmlsecurity".toCharArray());
        }

        StorageResolver storage = new StorageResolver(ks);
        storage.add(ks2);

        Iterator<?> iter = storage.getIterator();
        checkIterator(iter);

        // check new iterator starts from the beginning
        Iterator<?> iter2 = storage.getIterator();
        checkIterator(iter2);

        // check the iterators are independent
        // check calling next() without calling hasNext()
        iter = storage.getIterator();
        iter2 = storage.getIterator();

        while (iter.hasNext()) {
            X509Certificate cert = (X509Certificate) iter.next();
            X509Certificate cert2 = (X509Certificate) iter2.next();
            if (!cert.equals(cert2)) {
                fail("StorageResolver iterators are not independent");
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
        assertEquals(4, count);

        // Cannot go beyond last element
        try {
            iter.next();
            fail("Expecting NoSuchElementException");
        } catch (NoSuchElementException e) {
            //
        }
    }
}