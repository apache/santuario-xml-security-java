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
package org.apache.xml.security.test.dom.utils;

import org.apache.xml.security.utils.WeakObjectPool;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.Test;

import javax.xml.parsers.DocumentBuilder;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;
import java.util.Iterator;
import java.util.concurrent.*;

import static org.junit.Assert.*;

public class DocumentBuilderPoolingTest {

    private static final String DOCUMENTBUILDERPROXY_CLASSNAME =
            "org.apache.xml.security.utils.XMLUtils$DocumentBuilderProxy";

    @Test
    public void testEquals() throws Exception {
        DocumentBuilder documentBuilder = XMLUtils.createDocumentBuilder(true);
        assertEquals(documentBuilder, documentBuilder);
        assertSame(documentBuilder, documentBuilder);
    }

    @Test
    public void testGetValidatingDocumentBuilder() throws Exception {
        DocumentBuilder documentBuilder = XMLUtils.createDocumentBuilder(true);
        assertTrue(documentBuilder.isValidating());
    }

    @Test
    public void testGetNonValidatingDocumentBuilder() throws Exception {
        DocumentBuilder documentBuilder = XMLUtils.createDocumentBuilder(false);
        assertFalse(documentBuilder.isValidating());
    }

    @Test
    public void testGetValidatingAndAllowDocTypeDeclarationsDocumentBuilder() throws Exception {
        DocumentBuilder documentBuilder = XMLUtils.createDocumentBuilder(true, false);
        assertTrue(documentBuilder.isValidating());
        assertEquals(documentBuilder.getClass().getName(), DOCUMENTBUILDERPROXY_CLASSNAME);
        assertAllowDocTypeDeclarations(documentBuilder, false);
    }

    @Test
    public void testGetValidatingAndDisAllowDocTypeDeclarationsDocumentBuilder() throws Exception {
        DocumentBuilder documentBuilder = XMLUtils.createDocumentBuilder(true, true);
        assertTrue(documentBuilder.isValidating());
        assertEquals(documentBuilder.getClass().getName(), DOCUMENTBUILDERPROXY_CLASSNAME);
        assertAllowDocTypeDeclarations(documentBuilder, true);
    }

    private void assertAllowDocTypeDeclarations(DocumentBuilder documentBuilder, boolean allow) throws Exception {
        Field field = documentBuilder.getClass().getDeclaredField("disAllowDocTypeDeclarations");
        field.setAccessible(true);
        assertEquals(allow, field.get(documentBuilder));
    }

    @Test
    public void testNewDocumentBuilderInstances() throws Exception {
        int count = 4;

        // get all possible combinations of DocumentBuilders:
        DocumentBuilder[] documentBuilders = new DocumentBuilder[count];
        for (int i = 0; i < count; i++) {
            documentBuilders[i] = XMLUtils.createDocumentBuilder(i / 2 > 0, i % 2 == 1);
        }

        //test that we got always a new instance:
        for (int i = 0; i < count; i++) {
            for (int j = i + 1; j < count; j++) {
                assertNotEquals(documentBuilders[i], documentBuilders[j]);
                assertNotSame(documentBuilders[i], documentBuilders[j]);
            }
        }
    }

    @Test
    public void testRepoolingTwice() throws Exception {
        DocumentBuilder documentBuilder = XMLUtils.createDocumentBuilder(true);
        assertTrue(XMLUtils.repoolDocumentBuilder(documentBuilder));
        assertFalse("can't repool the same object twice!", XMLUtils.repoolDocumentBuilder(documentBuilder));
    }

    @Test(timeout = 30000)
    public void testPooling() throws Exception {
        int nThreads = 8;
        ExecutorService exec = Executors.newFixedThreadPool(nThreads);
        Future<?>[] results = new Future[nThreads];
        for (int i = 0; i < nThreads - 1; i++) {
            results[i] = exec.submit(new Runnable() {
                @Override
                public void run() {
                    try {
                        while (true) {
                            // retrieve some DocumentBuilders...
                            DocumentBuilder documentBuilders[] = new DocumentBuilder[10];
                            for (int i = 0; i < documentBuilders.length; i++) {
                                documentBuilders[i] = XMLUtils.createDocumentBuilder(false);
                                assertNotNull(documentBuilders[i]);
                            }
                            // ...then repool them so that another thread may pickup them again
                            for (int i = 0; i < documentBuilders.length; i++) {
                                assertTrue(XMLUtils.repoolDocumentBuilder(documentBuilders[i]));
                            }
                        }
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            });
        }
        // more or less mimic gc
        results[nThreads - 1] = exec.submit(new Runnable() {
            @Override
            public void run() {
                try {
                    final Field poolField = XMLUtils.class.getDeclaredField("pools");
                    poolField.setAccessible(true);
                    final WeakObjectPool[] weakObjectPools = (WeakObjectPool[]) poolField.get(null);

                    final Field availableField = WeakObjectPool.class.getDeclaredField("available");
                    availableField.setAccessible(true);

                    while (true) {
                        final BlockingDeque blockingDeque = (BlockingDeque) availableField.get(weakObjectPools[1]);
                        Iterator iterator = blockingDeque.iterator();
                        while (iterator.hasNext()) {
                            ((WeakReference) iterator.next()).clear();
                        }
                        Thread.sleep(200);
                    }
                } catch (InterruptedException e) {
                    return;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });

        exec.shutdown();
        exec.awaitTermination(5, TimeUnit.SECONDS);
        for (Future<?> f : results) {
            if (!f.isDone()) {
                f.cancel(false);
            }
            try {
                assertNull(f.get(1000, TimeUnit.MILLISECONDS));
            } catch (CancellationException ce) {
                ;//expected since we did cancel it
            } catch (TimeoutException e) {
                fail(f + "didn't cancel after timeout?");
            }
        }
    }
}
