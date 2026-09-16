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

import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.math.BigInteger;

/**
 * Proxy for the {@code xades132:Cert} element.
 *
 * <p>Holds certificate identification data:
 * <ul>
 *   <li>{@code CertDigest} — digest of the DER-encoded certificate,
 *       using {@code ds:DigestMethod} and {@code ds:DigestValue}</li>
 *   <li>{@code IssuerSerial} — issuer distinguished name and serial number,
 *       using {@code ds:X509IssuerName} and {@code ds:X509SerialNumber}</li>
 * </ul>
 *
 * <pre>{@code
 * <xades132:Cert>
 *   <xades132:CertDigest>
 *     <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
 *     <ds:DigestValue>base64...</ds:DigestValue>
 *   </xades132:CertDigest>
 *   <xades132:IssuerSerial>
 *     <ds:X509IssuerName>CN=...</ds:X509IssuerName>
 *     <ds:X509SerialNumber>12345</ds:X509SerialNumber>
 *   </xades132:IssuerSerial>
 * </xades132:Cert>
 * }</pre>
 */
public class Cert extends XAdESElementProxy {

    public Cert(Document doc) {
        super(doc);
    }

    @Override
    public String getBaseLocalName() {
        return "Cert";
    }

    /**
     * Appends a {@code <xades132:CertDigest>} child containing the digest algorithm
     * and the base64-encoded digest value of the DER-encoded certificate.
     *
     * @param digestAlgorithmURI W3C URI of the digest algorithm (e.g. {@code XMLCipher.SHA256})
     * @param digestValue        the raw digest bytes
     */
    public void setCertDigest(String digestAlgorithmURI, byte[] digestValue) {
        Element certDigest = createXAdESChild("CertDigest");

        Element digestMethod = createDsChild("DigestMethod");
        digestMethod.setAttributeNS(null, "Algorithm", digestAlgorithmURI);
        certDigest.appendChild(digestMethod);

        Element digestValueEl = createDsChild("DigestValue");
        digestValueEl.setTextContent(XMLUtils.encodeToString(digestValue));
        certDigest.appendChild(digestValueEl);

        appendSelf(certDigest);
    }

    /**
     * Appends a {@code <xades132:IssuerSerial>} child containing the certificate's
     * issuer distinguished name and serial number.
     *
     * @param issuerName   RFC 2253 issuer distinguished name
     * @param serialNumber certificate serial number
     */
    public void setIssuerSerial(String issuerName, BigInteger serialNumber) {
        Element issuerSerial = createXAdESChild("IssuerSerial");

        Element issuerNameEl = createDsChild("X509IssuerName");
        issuerNameEl.setTextContent(issuerName);
        issuerSerial.appendChild(issuerNameEl);

        Element serialEl = createDsChild("X509SerialNumber");
        serialEl.setTextContent(serialNumber.toString());
        issuerSerial.appendChild(serialEl);

        appendSelf(issuerSerial);
    }
}
