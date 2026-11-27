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

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;

import org.apache.xml.security.stax.ext.stax.XMLSecNamespace;
import org.apache.xml.security.stax.impl.stax.XMLSecNamespaceImpl;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class XMLSecNamespaceImplTest {

    @Test
    void testValuesAndEquality() {
        XMLSecNamespace defaultNs = XMLSecNamespaceImpl.getInstance(null, null);
        assertEquals("", defaultNs.getPrefix());
        assertEquals("", defaultNs.getNamespaceURI());

        XMLSecNamespace ns1 = XMLSecNamespaceImpl.getInstance("p", "urn:a");
        XMLSecNamespace ns2 = XMLSecNamespaceImpl.getInstance("p", "urn:a");
        assertEquals("p", ns1.getPrefix());
        assertEquals("urn:a", ns1.getNamespaceURI());
        assertEquals(ns1, ns2);
        assertEquals(ns1.hashCode(), ns2.hashCode());
        // namespaces are compared by prefix, as namespace nodes are in canonicalization
        assertNotEquals(ns1, XMLSecNamespaceImpl.getInstance("q", "urn:a"));
    }

    /**
     * Namespaces taken from processed documents must not be kept in memory by the library once
     * they are no longer used, or documents declaring ever new namespaces exhaust the memory.
     */
    @Test
    void testInstancesAreNotRetained() throws Exception {
        WeakReference<XMLSecNamespace> ref = createUnreferencedNamespace();
        for (int i = 0; i < 50 && ref.get() != null; i++) {
            // create some garbage so that the collector runs
            List<byte[]> garbage = new ArrayList<>();
            for (int j = 0; j < 100; j++) {
                garbage.add(new byte[10_000]);
            }
            garbage.clear();
            System.gc();
            Thread.sleep(20);
        }
        assertNull(ref.get(), "the namespace instance is still referenced after garbage collection");
    }

    private static WeakReference<XMLSecNamespace> createUnreferencedNamespace() {
        return new WeakReference<>(
            XMLSecNamespaceImpl.getInstance("p", "urn:unique:" + System.nanoTime()));
    }
}
