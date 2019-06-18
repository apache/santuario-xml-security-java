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
/*
 * Copyright 2005 Sun Microsystems, Inc. All rights reserved.
 */
package javax.xml.crypto.test;


import java.io.*;
import java.util.*;
import javax.xml.crypto.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * Unit test for javax.xml.crypto.OctetStreamData
 *
 */
public class OctetStreamDataTest {

    @org.junit.jupiter.api.Test
    public void testConstructor() throws Exception {
        // test OctetStreamData(InputStream) and
        // OctetStreamData(InputStream, String, String)
        OctetStreamData osdata;
        try {
            osdata = new OctetStreamData(null);
            fail("Should raise a NPE for null input stream");
        } catch (NullPointerException npe) {}
        try {
            osdata = new OctetStreamData(null, "uri", "mimeType");
            fail("Should raise a NPE for null input stream");
        } catch (NullPointerException npe) {}

        int len = 300;
        byte[] in = new byte[len];
        new Random().nextBytes(in);

        try (ByteArrayInputStream bais = new ByteArrayInputStream(in)) {
            osdata = new OctetStreamData(bais);
            assertNotNull(osdata);
            assertEquals(osdata.getOctetStream(), bais);
            assertNull(osdata.getURI());
            assertNull(osdata.getMimeType());

            osdata = new OctetStreamData(bais, null, null);
            assertNotNull(osdata);
            assertEquals(osdata.getOctetStream(), bais);
            assertNull(osdata.getURI());
            assertNull(osdata.getMimeType());

            String uri="testUri";
            String mimeType="test";
            osdata = new OctetStreamData(bais, uri, mimeType);
            assertNotNull(osdata);
            assertEquals(osdata.getOctetStream(), bais);
            assertEquals(osdata.getURI(), uri);
            assertEquals(osdata.getMimeType(), mimeType);
        }
    }
}