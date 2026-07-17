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
package org.apache.xml.security.extension;

import org.apache.xml.security.signature.XMLSignatureException;

/**
 * Thrown by a {@link SignatureProcessor} when it cannot complete its processing
 * and the signing operation must be aborted.
 *
 * <p>Extends {@link XMLSignatureException} so callers that already handle the
 * standard library exception hierarchy will catch this automatically.
 */
public class SignatureExtensionException extends XMLSignatureException {

    private static final long serialVersionUID = 1L;

    private final String detailMessage;

    /**
     * @param message human-readable description of the failure
     */
    public SignatureExtensionException(String message) {
        super(message);
        this.detailMessage = message;
    }

    /**
     * @param message human-readable description of the failure
     * @param cause   the underlying exception that triggered this failure
     */
    public SignatureExtensionException(String message, Throwable cause) {
        super(message);
        this.detailMessage = message;
        if (cause != null) {
            initCause(cause);
        }
    }

    @Override
    public String getMessage() {
        return detailMessage;
    }
}
