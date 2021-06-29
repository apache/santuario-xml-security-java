/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.xml.security.stax.impl.stax;

import java.util.Objects;

import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecSignaturePosition;

/**
 * Custom event used by the collective XML signature output processors to mark the position of the XML signature in the
 * document.
 */
public class XMLSecSignaturePositionImpl extends XMLSecEventBaseImpl implements XMLSecSignaturePosition {

    private final XMLSecEvent context;

    public XMLSecSignaturePositionImpl(XMLSecEvent context) {
        Objects.requireNonNull(context, "Context is null");
        this.context = context;
    }

    @Override
    public int getEventType() {
        return XMLSecurityConstants.SIGNATURE_POSITION;
    }

    /**
     * The context of this event, which is the start-element or end-element event to insert the signature after.
     */
    @Override
    public XMLSecEvent getContext() {
        return context;
    }
}
