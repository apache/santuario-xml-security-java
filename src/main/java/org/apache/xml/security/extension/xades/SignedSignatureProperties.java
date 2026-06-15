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
import org.w3c.dom.Element;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Proxy for the {@code xades132:SignedSignatureProperties} element.
 *
 * <p>Orchestrates the mandatory and optional children for XAdES-B-B:
 * <ul>
 *   <li>{@code SigningTime} — mandatory, set via {@link #setSigningTime}</li>
 *   <li>{@code SigningCertificate} — mandatory, set via {@link #setSigningCertificate}</li>
 *   <li>{@code SignaturePolicyIdentifier/SignaturePolicyImplied} — optional, via {@link #setSignaturePolicyImplied}</li>
 *   <li>{@code SignatureProductionPlace} — optional, via {@link #setSignatureProductionPlace}</li>
 * </ul>
 */
public class SignedSignatureProperties extends XAdESElementProxy {

    public SignedSignatureProperties(Document doc) {
        super(doc);
    }

    @Override
    public String getBaseLocalName() {
        return "SignedSignatureProperties";
    }

    /** Appends a {@code <xades132:SigningTime>} child with an ISO-8601 timestamp. */
    public void setSigningTime(OffsetDateTime dateTime) {
        Element e = createXAdESChild("SigningTime");
        e.setTextContent(DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(dateTime));
        appendSelf(e);
    }

    public void setSigningCertificate(SigningCertificate sc) {
        appendSelf(sc);
    }

    /**
     * Appends an empty {@code <SignaturePolicyImplied/>} wrapped in
     * {@code <SignaturePolicyIdentifier>}, indicating that the signature
     * policy is implied by the signing context.
     */
    public void setSignaturePolicyImplied() {
        Element policyId = createXAdESChild("SignaturePolicyIdentifier");
        policyId.appendChild(createXAdESChild(XAdESConstants.TAG_SIGNATURE_POLICY_IMPLIED));
        appendSelf(policyId);
    }

    /**
     * Appends a {@code <SignatureProductionPlace>} child.
     * At least one of {@code city} or {@code countryName} must be non-null.
     */
    public void setSignatureProductionPlace(String city, String countryName) {
        Element place = createXAdESChild("SignatureProductionPlace");
        if (city != null) {
            Element cityEl = createXAdESChild("City");
            cityEl.setTextContent(city);
            place.appendChild(cityEl);
        }
        if (countryName != null) {
            Element countryEl = createXAdESChild("CountryName");
            countryEl.setTextContent(countryName);
            place.appendChild(countryEl);
        }
        appendSelf(place);
    }
}
