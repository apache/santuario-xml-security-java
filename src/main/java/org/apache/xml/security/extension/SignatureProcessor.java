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

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;

/**
 * This interface is responsible for processing signature. The implementation of
 * this interface can be uses as pre-processors to add to the signature and
 * additional data such as XAdES QualifyingProperties for the XAdES basic
 * signatures profile.
 * The implementation can be used as post-processors to add update the signatures
 * after the signature has been generated. An example the Timestamp (TSA) of the
 * signature, or automatic registration of the signature hast to blockchain ledger.
 */
public interface SignatureProcessor {

    /**
     * Process the signature.
     *
     * @param signature the XMLSignature instance to be processed
     * @throws XMLSignatureException if an error occurs while processing the signature
     */
    void processSignature(XMLSignature signature) throws XMLSignatureException;
}
