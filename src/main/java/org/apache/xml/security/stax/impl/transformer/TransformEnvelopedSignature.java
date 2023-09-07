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
import org.apache.xml.security.stax.ext.stax.XMLSecEndElement;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

/**
 */
public class TransformEnvelopedSignature extends TransformIdentity {

    private int curLevel;
    private int sigElementLevel = -1;

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
        if (XMLStreamConstants.START_ELEMENT == xmlSecEvent.getEventType()) {
            curLevel++;
            XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
            if (XMLSecurityConstants.TAG_dsig_Signature.equals(xmlSecStartElement.getName())) {
                sigElementLevel = curLevel;
                return;
            }
        } else if (XMLStreamConstants.END_ELEMENT == xmlSecEvent.getEventType()) {
            XMLSecEndElement xmlSecEndElement = xmlSecEvent.asEndElement();
            if (sigElementLevel == curLevel && XMLSecurityConstants.TAG_dsig_Signature.equals(xmlSecEndElement.getName())) {
                sigElementLevel = -1;
                return;
            }
            curLevel--;
        }
        if (sigElementLevel == -1) {
            super.transform(xmlSecEvent);
        }
    }

    @Override
    public void transform(InputStream inputStream) throws XMLStreamException {
        //there is no use case at the moment but can be implemented if needed
        throw new UnsupportedOperationException("transform(InputStream) not supported");
    }
}
