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
package org.apache.xml.security.keys.content.x509;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.RFC2253Parser;
import org.apache.xml.security.utils.SignatureElementProxy;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class XMLX509IssuerSerial extends SignatureElementProxy implements XMLX509DataContent {

    private static final Logger LOG = System.getLogger(XMLX509IssuerSerial.class.getName());

    /**
     * Constructor XMLX509IssuerSerial
     *
     * @param element
     * @param baseURI
     * @throws XMLSecurityException
     */
    public XMLX509IssuerSerial(Element element, String baseURI) throws XMLSecurityException {
        super(element, baseURI);
    }

    /**
     * Constructor XMLX509IssuerSerial
     *
     * @param doc
     * @param x509IssuerName
     * @param x509SerialNumber
     */
    public XMLX509IssuerSerial(Document doc, String x509IssuerName, BigInteger x509SerialNumber) {
        super(doc);
        addReturnToSelf();
        addTextElement(x509IssuerName, Constants._TAG_X509ISSUERNAME);
        addTextElement(x509SerialNumber.toString(), Constants._TAG_X509SERIALNUMBER);
    }

    /**
     * Constructor XMLX509IssuerSerial
     *
     * @param doc
     * @param x509IssuerName
     * @param x509SerialNumber
     */
    public XMLX509IssuerSerial(Document doc, String x509IssuerName, String x509SerialNumber) {
        this(doc, x509IssuerName, new BigInteger(x509SerialNumber));
    }

    /**
     * Constructor XMLX509IssuerSerial
     *
     * @param doc
     * @param x509IssuerName
     * @param x509SerialNumber
     */
    public XMLX509IssuerSerial(Document doc, String x509IssuerName, int x509SerialNumber) {
        this(doc, x509IssuerName, new BigInteger(Integer.toString(x509SerialNumber)));
    }

    /**
     * Constructor XMLX509IssuerSerial
     *
     * @param doc
     * @param x509certificate
     */
    public XMLX509IssuerSerial(Document doc, X509Certificate x509certificate) {
        this(
            doc,
            x509certificate.getIssuerX500Principal().getName(),
            x509certificate.getSerialNumber()
        );
    }

    /**
     * Method getSerialNumber
     *
     * @return the serial number
     */
    public BigInteger getSerialNumber() {
        String text =
            this.getTextFromChildElement(Constants._TAG_X509SERIALNUMBER, Constants.SignatureSpecNS);
        LOG.log(Level.DEBUG, "X509SerialNumber text: {0}", text);

        return new BigInteger(text);
    }

    /**
     * Method getSerialNumberInteger
     *
     * @return the serial number as plain int
     */
    public int getSerialNumberInteger() {
        return this.getSerialNumber().intValue();
    }

    /**
     * Method getIssuerName
     *
     * @return the issuer name
     */
    public String getIssuerName()  {
        return RFC2253Parser.normalize(
            this.getTextFromChildElement(Constants._TAG_X509ISSUERNAME, Constants.SignatureSpecNS)
        );
    }

    /** {@inheritDoc} */
    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof XMLX509IssuerSerial)) {
            return false;
        }

        XMLX509IssuerSerial other = (XMLX509IssuerSerial) obj;

        return this.getSerialNumber().equals(other.getSerialNumber())
            && this.getIssuerName().equals(other.getIssuerName());
    }

    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + getSerialNumber().hashCode();
        result = 31 * result + getIssuerName().hashCode();
        return result;
    }

    /** {@inheritDoc} */
    @Override
    public String getBaseLocalName() {
        return Constants._TAG_X509ISSUERSERIAL;
    }
}
