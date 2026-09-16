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
package org.apache.xml.security.extension.xades;

import org.w3c.dom.Document;

/**
 * Proxy for the {@code xades132:SignedProperties} element.
 *
 * <p>Carries an {@code Id} attribute (registered as an XML ID so that
 * {@link org.w3c.dom.Document#getElementById} resolves it) that is referenced
 * from the {@code ds:Reference} added by the XAdES pre-processor.
 *
 * <pre>{@code
 * <xades132:SignedProperties Id="sig-prop-xxx">
 *   ...
 * </xades132:SignedProperties>
 * }</pre>
 */
public class SignedProperties extends XAdESElementProxy {

    public SignedProperties(Document doc, String id) {
        super(doc);
        setLocalIdAttribute("Id", id);
    }

    @Override
    public String getBaseLocalName() {
        return "SignedProperties";
    }

    public void setSignedSignatureProperties(SignedSignatureProperties ssp) {
        appendSelf(ssp);
    }
}
