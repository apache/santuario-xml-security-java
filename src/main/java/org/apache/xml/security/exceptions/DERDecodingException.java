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
package org.apache.xml.security.exceptions;

/**
 * This Exception is thrown if decoding of ANS1 (DER) data fails.
 *
 */
public class DERDecodingException extends XMLSecurityException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructor DERDecodingException
     *
     * @param msgID
     */
    public DERDecodingException(String msgID) {
        super(msgID);
    }

    /**
     * Constructor DERDecodingException
     *
     * @param msgID
     * @param exArgs
     */
    public DERDecodingException(String msgID, Object[] exArgs) {
        super(msgID, exArgs);
    }

    /**
     * Constructor DERDecodingException
     *
     * @param originalException
     * @param msgID
     */
    public DERDecodingException(Exception originalException, String msgID) {
        super(originalException, msgID);
    }


    /**
     * Constructor DERDecodingException
     *
     * @param originalException
     * @param msgID
     * @param exArgs
     */
    public DERDecodingException(Exception originalException, String msgID, Object[] exArgs) {
        super(originalException, msgID, exArgs);
    }
}
