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
 * Extension point for pluggable pre- and post-signature processing hooks in
 * the DOM-based XML Signature implementation.
 *
 * <p>Instances are registered on an {@link XMLSignature} via
 * {@link XMLSignature#addPreProcessor(SignatureProcessor)} or
 * {@link XMLSignature#addPostProcessor(SignatureProcessor)}.
 *
 * <ul>
 *   <li><b>Pre-processors</b> are invoked before digest values are computed on
 *       the {@code ds:SignedInfo} references. A pre-processor may therefore add
 *       XML content (e.g., XAdES {@code QualifyingProperties}) that will be
 *       covered by the signature digest.</li>
 *   <li><b>Post-processors</b> are invoked after the {@code ds:SignatureValue}
 *       element has been populated with the completed signature bytes. A
 *       post-processor may read the final signature value, for example to
 *       request a signature-timestamp token for XAdES-T.</li>
 * </ul>
 *
 * <p>If a processor throws {@link XMLSignatureException} the signing operation
 * is aborted and the exception is propagated to the caller of
 * {@link XMLSignature#sign(java.security.Key)}.
 *
 */
public interface SignatureProcessor {

    /**
     * Called during the {@link XMLSignature#sign(java.security.Key)} lifecycle.
     *
     * @param signature the signature being created; never {@code null}
     * @throws XMLSignatureException if processing fails and signing must be aborted
     */
    void processSignature(XMLSignature signature) throws XMLSignatureException;
}
