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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Random;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.utils.XMLUtils;
import org.junit.Test;

public class PoolingTest {
    
    @Test
    public void testPooling() throws ParserConfigurationException, InterruptedException, ExecutionException {
        //assert parameters
        DocumentBuilder db = XMLUtils.createDocumentBuilder(true);
        assertTrue(db.isValidating());
        DocumentBuilder db2 = XMLUtils.createDocumentBuilder(false);
        assertFalse(db2.isValidating());
        assertNotEquals(db2, db);
        DocumentBuilder db3 = XMLUtils.createDocumentBuilder(true, false);
        assertTrue(db3.isValidating());
        DocumentBuilder db4 = XMLUtils.createDocumentBuilder(false, false);
        assertFalse(db4.isValidating());
        
        //assert get
        DocumentBuilder db_ = XMLUtils.createDocumentBuilder(true);
        assertNotSame("db wasn't returned", db, db_);
        DocumentBuilder db2_ = XMLUtils.createDocumentBuilder(false);
        assertNotSame(db2, db2_);
        DocumentBuilder db3_ = XMLUtils.createDocumentBuilder(true, false);
        assertNotSame(db3, db3_);
        DocumentBuilder db4_ = XMLUtils.createDocumentBuilder(false, false);
        assertNotSame(db4, db4_);
        
        //assert get after return
        assertTrue(XMLUtils.repoolDocumentBuilder(db_));
        assertFalse("can't repool the same object twice!", XMLUtils.repoolDocumentBuilder(db_));
        DocumentBuilder db_1 = XMLUtils.createDocumentBuilder(true);
        assertSame(db_, db_1);
        
        assertTrue(XMLUtils.repoolDocumentBuilder(db2_));
        assertFalse("can't repool the same object twice!", XMLUtils.repoolDocumentBuilder(db2_));
        DocumentBuilder db_2 = XMLUtils.createDocumentBuilder(false);
        assertSame(db2_, db_2);
        
        assertTrue(XMLUtils.repoolDocumentBuilder(db3_));
        assertFalse("can't repool the same object twice!", XMLUtils.repoolDocumentBuilder(db3_));
        DocumentBuilder db_3 = XMLUtils.createDocumentBuilder(true, false);
        assertSame(db3_, db_3);
        
        assertTrue(XMLUtils.repoolDocumentBuilder(db4_));
        assertFalse("can't repool the same object twice!", XMLUtils.repoolDocumentBuilder(db4_));
        DocumentBuilder db_4 = XMLUtils.createDocumentBuilder(false, false);
        assertSame(db4_, db_4);
        
//        final byte[] largeArrays[] = new byte[1024][];
//        final DocumentBuilder[] dbLargeArrays = new DocumentBuilder[largeArrays.length];

        int nThreads = Runtime.getRuntime().availableProcessors();
        ExecutorService exec = Executors.newFixedThreadPool(nThreads);
        Future<?>[] results = new Future[nThreads]; 
        for(int i = 0; i < nThreads-1; i++) {
            results[i] = exec.submit(new Runnable() {
                @Override
                public void run() {
                    for(;;) {
                        DocumentBuilder dbA[] = new DocumentBuilder[10];
                        for (int i = 0; i < dbA.length; i++) {
                            try {
                                dbA[i] = XMLUtils.createDocumentBuilder(false);
                                assertNotNull(dbA[i]);
                            } catch (ParserConfigurationException e) {
                                e.printStackTrace();
                                fail(e.toString());
                            }
                            assertNotNull(dbA[i]);
                        }
                        for(int i = 0; i < new Random().nextInt(dbA.length); i++) {
                            assertTrue(XMLUtils.repoolDocumentBuilder(dbA[i]));
                        }
                    }
                }
            });
        }
        results[nThreads-1] = exec.submit(new Runnable() {
            @Override
            public void run() {
                for(;;) {
                    byte[] largeArrays[] = new byte[1024][];
                    for (int i = 0; i < largeArrays.length; i++)
                        try {
                            largeArrays[i] = new byte[1024*1024];
                        } catch (OutOfMemoryError e) {
                            System.out.println("OOM from largeArray");
                            break;
                        }
                }
            }
        });
        exec.shutdown();
        exec.awaitTermination(5, TimeUnit.SECONDS);
        for(Future<?> f : results) {
            if (!f.isDone())
                f.cancel(false);
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
