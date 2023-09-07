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

import java.io.OutputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.security.MessageDigest;

/**
 * A Streaming based message-digest implementation
 *
 */
public class DigestOutputStream extends OutputStream {

    private static final Logger LOG = System.getLogger(DigestOutputStream.class.getName());
    protected static final transient boolean isDebugEnabled = LOG.isLoggable(Level.DEBUG);

    private final MessageDigest messageDigest;
    private StringBuilder stringBuilder; //NOPMD

    public DigestOutputStream(MessageDigest messageDigest) {
        this.messageDigest = messageDigest;
        if (isDebugEnabled) {
            stringBuilder = new StringBuilder();
        }
    }

    @Override
    public void write(byte[] arg0) {
        write(arg0, 0, arg0.length);
    }

    @Override
    public void write(int arg0) {
        byte asByte = (byte) arg0;
        messageDigest.update(asByte);
        if (isDebugEnabled) {
            stringBuilder.append((char)asByte);
        }
    }

    @Override
    public void write(byte[] arg0, int arg1, int arg2) {
        messageDigest.update(arg0, arg1, arg2);
        if (isDebugEnabled) {
            stringBuilder.append(new String(arg0, arg1, arg2, java.nio.charset.StandardCharsets.UTF_8));
        }
    }

    public byte[] getDigestValue() {
        if (isDebugEnabled) {
            LOG.log(Level.DEBUG, "Pre Digest: ");
            LOG.log(Level.DEBUG, stringBuilder.toString());
            LOG.log(Level.DEBUG, "End pre Digest ");
            stringBuilder = new StringBuilder();
        }
        return messageDigest.digest();
    }
}
