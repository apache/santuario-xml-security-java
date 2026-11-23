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
package org.apache.xml.security.stax.impl.transformer;

import java.io.InputStream;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;

import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;

/**
 */
public class TransformEnvelopedSignature extends TransformIdentity {

    // depth within a ds:Signature element being removed; 0 when outside one
    private int depthInSignature;

    @Override
    public XMLSecurityConstants.TransformMethod getPreferredTransformMethod(XMLSecurityConstants.TransformMethod forInput) {
        switch (forInput) {
            case XMLSecEvent:
                return XMLSecurityConstants.TransformMethod.XMLSecEvent;
            case InputStream:
                return XMLSecurityConstants.TransformMethod.XMLSecEvent;
            default:
                throw new IllegalArgumentException("Unsupported class " + forInput.name());
        }
    }

    @Override
    public void transform(XMLSecEvent xmlSecEvent) throws XMLStreamException {
        int eventType = xmlSecEvent.getEventType();
        if (depthInSignature > 0) {
            // inside a removed Signature: drop everything, including any nested elements
            // (and nested Signature elements) until its own end tag
            if (XMLStreamConstants.START_ELEMENT == eventType) {
                depthInSignature++;
            } else if (XMLStreamConstants.END_ELEMENT == eventType) {
                depthInSignature--;
            }
            return;
        }
        if (XMLStreamConstants.START_ELEMENT == eventType
            && XMLSecurityConstants.TAG_dsig_Signature.equals(xmlSecEvent.asStartElement().getName())) {
            depthInSignature = 1;
            return;
        }
        super.transform(xmlSecEvent);
    }

    @Override
    public void transform(InputStream inputStream) throws XMLStreamException {
        //there is no use case at the moment but can be implemented if needed
        throw new UnsupportedOperationException("transform(InputStream) not supported");
    }
}
