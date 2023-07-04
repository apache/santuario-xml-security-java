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
package org.apache.xml.security.stax.impl.util;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.apache.xml.security.utils.UnsyncByteArrayOutputStream;

public class FullyBufferedOutputStream extends FilterOutputStream {

    private final UnsyncByteArrayOutputStream buf = new UnsyncByteArrayOutputStream();

    public FullyBufferedOutputStream(OutputStream out) {
        super(out);
    }

    @Override
    public void write(int b) throws IOException {
        buf.write(b);
    }

    @Override
    public void write(byte[] b) throws IOException {
        buf.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        buf.write(b, off, len);
    }

    @Override
    public void close() throws IOException {
        buf.writeTo(out);
        out.close();
        buf.close();
    }

    @Override
    public void flush() throws IOException {
        //nothing to do here
    }
}
