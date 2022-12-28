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
package org.apache.xml.security.utils;

import java.io.ByteArrayOutputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;

/**
 *
 */
public class DigesterOutputStream extends ByteArrayOutputStream {
    private static final Logger LOG = System.getLogger(DigesterOutputStream.class.getName());

    final MessageDigestAlgorithm mda;

    /**
     * @param mda
     */
    public DigesterOutputStream(MessageDigestAlgorithm mda) {
        this.mda = mda;
    }

    /** {@inheritDoc} */
    @Override
    public void write(byte[] arg0) {
        write(arg0, 0, arg0.length);
    }

    /** {@inheritDoc} */
    @Override
    public synchronized void write(int arg0) {
        mda.update((byte)arg0);
    }

    /** {@inheritDoc} */
    @Override
    public void write(byte[] arg0, int arg1, int arg2) {
        if (LOG.isLoggable(Level.DEBUG)) {
            LOG.log(Level.DEBUG, "Pre-digested input:");
            StringBuilder sb = new StringBuilder(arg2);
            for (int i = arg1; i < (arg1 + arg2); i++) {
                sb.append((char)arg0[i]);
            }
            LOG.log(Level.DEBUG, sb.toString());
        }
        mda.update(arg0, arg1, arg2);
    }

    /**
     * @return the digest value
     */
    public byte[] getDigestValue() {
        return mda.digest();
    }
}
