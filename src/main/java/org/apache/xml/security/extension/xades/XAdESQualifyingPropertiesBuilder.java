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

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.binding.xmldsig.DigestMethodType;
import org.apache.xml.security.binding.xmldsig.X509IssuerSerialType;
import org.apache.xml.security.binding.xmldsig.xades.v132.*;
import org.apache.xml.security.extension.exceptions.ExtensionException;

import javax.xml.datatype.DatatypeConfigurationException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;


/**
 * This class is used to build XAdES QualifyingProperties with compliance to
 * XAdES-B-B (Basic Electronic Signature) structure. The lowest and simplest
 * version just containing the SignedInfo, SignatureValue, KeyInfo and
 * SignedProperties. This form extends the definition of an electronic signature
 * to conform to the identified signature policy.
 * <p>
 * The XAdESQualifyingPropertiesBuilder adds the following elements to [XMLDSIG]:
 *<pre>
 * QualifyingProperties
 *     SignedProperties
 *         SignedSignatureProperties
 *             SigningTime
 *             SigningCertificate
 *             SignaturePolicyIdentifier
 *             SignatureProductionPlace?
 * </pre>
 * <p>
 * @see <a href="https://www.w3.org/TR/XAdES/">XAdES</a>
 * @see <a href="https://etsi.org/deliver/etsi_en/319100_319199/31913201/01.01.01_60/en_31913201v010101p.pdf">
 *     ETSI TS 101 903 V1.4.2</a>
 */
public class XAdESQualifyingPropertiesBuilder {

    String signatureId;
    String xadesSignaturePropertiesId;
    X509Certificate signingCertificate;
    String certificateDigestMethodURI;
    String signaturePolicy;
    String signatureCity;
    String signatureCountryName;

    protected XAdESQualifyingPropertiesBuilder() {
    }

    /**
     * Create a new instance of XAdESQualifyingPropertiesBuilder
     *
     * @return XAdESQualifyingPropertiesBuilder
     */
    public static XAdESQualifyingPropertiesBuilder create() {
        return new XAdESQualifyingPropertiesBuilder();
    }

    /**
     * Set the signature identifier to be targeted from element
     * QualifyingProperties/@Target
     *
     * @param signatureId - signature identifier
     * @return XAdESQualifyingPropertiesBuilder for continued configuration
     */
    public XAdESQualifyingPropertiesBuilder withSignatureId(String signatureId) {
        this.signatureId = signatureId;
        return this;
    }


    /**
     * Set the identifier for the XAdES SignatureProperties element
     *
     * @param xadesSignaturePropertiesId - XAdES SignatureProperties identifier
     * @return XAdESQualifyingPropertiesBuilder for continued configuration
     */
    public XAdESQualifyingPropertiesBuilder withXAdESSignaturePropertiesId(String xadesSignaturePropertiesId) {
        this.xadesSignaturePropertiesId = xadesSignaturePropertiesId;
        return this;
    }

    /**
     * Set the signing certificate
     *
     * @param signingCertificate - signing certificate to be included in the
     *                           XAdES QualifyingProperties
     * @return XAdESQualifyingPropertiesBuilder for continued configuration
     */
    public XAdESQualifyingPropertiesBuilder withSigningCertificate(X509Certificate signingCertificate) {
        this.signingCertificate = signingCertificate;
        return this;
    }

    /**
     * Set the digest method URI for the certificate
     *
     * @param digestURI - digest method URI for calculating the certificate digest
     * @return XAdESQualifyingPropertiesBuilder for continued configuration
     */
    public XAdESQualifyingPropertiesBuilder withCertificateDigestMethodURI(String digestURI) {
        this.certificateDigestMethodURI = digestURI;
        return this;
    }

   /**
     * Set the signature policy
     *
     * @param signaturePolicy - signature policy to be included in the
    *                        XAdES QualifyingProperties
     * @return XAdESQualifyingPropertiesBuilder for continued configuration
     */
    public XAdESQualifyingPropertiesBuilder withSignaturePolicy(String signaturePolicy) {
        this.signaturePolicy = signaturePolicy;
        return this;
    }

    /**
     * Set the city where the signature was created (Optional)
     *
     * @param signatureCity - city where the signature was created
     * @return XAdESQualifyingPropertiesBuilder for continued configuration
     */
    public XAdESQualifyingPropertiesBuilder withSignatureCity(String signatureCity) {
        this.signatureCity = signatureCity;
        return this;
    }

    /**
     * Set the country name where the signature was created (Optional)
     *
     * @param signatureCountryName - country name where the signature was created
     * @return XAdESQualifyingPropertiesBuilder for continued configuration
     */
    public XAdESQualifyingPropertiesBuilder withSignatureCountryName(String signatureCountryName) {
        this.signatureCountryName = signatureCountryName;
        return this;
    }

    /**
     * Build the XAdES QualifyingProperties
     *
     * @return QualifyingPropertiesType
     * @throws CertificateEncodingException
     * @throws NoSuchAlgorithmException
     * @throws DatatypeConfigurationException
     */
    public QualifyingPropertiesType build() throws ExtensionException {
        return createXAdESQualifyingProperties(signatureId,
                xadesSignaturePropertiesId,
                signingCertificate,
                certificateDigestMethodURI,
                signaturePolicy,
                signatureCity,
                signatureCountryName);
    }


    /**
     * Method creates Signature/Object/QualifyingProperties/*SignedProperties* for signed certificate
     *
     * @param strSigPropId    signed properties id
     * @param cert,           signing certificate
     * @param digestUri       digest method code (JCA provider code and W3c - URI)
     * @param signatureReason value for: SignaturePolicyIdentifier/SignaturePolicyImplied - The
     *                        signature policy is a set of rules for the creation and validation of an electronic signature,
     *                        under which the signature can be determined to be valid. A given legal/contractual context may
     *                        recognize a particular signature policy as meeting its requirements.
     * @param sigCity         city where signature was created
     * @param sigCountryName  country name where signature was created
     * @return XAdES data structure: SignedProperties
     */
    private SignedPropertiesType createSignedProperties(String strSigPropId,
                                                       X509Certificate cert,
                                                       String digestUri,
                                                       String signatureReason,
                                                       String sigCity,
                                                       String sigCountryName) throws ExtensionException {
        SignedPropertiesType sp = new SignedPropertiesType();

        sp.setId(strSigPropId);
        CertIDListType scert = new CertIDListType();
        CertIDType sit = new CertIDType();
        DigestAlgAndValueType dt = new DigestAlgAndValueType();

        MessageDigest md;
        try {
            md = MessageDigest.getInstance(JCEMapper.translateURItoJCEID(digestUri));
        } catch (NoSuchAlgorithmException ex) {
            throw new ExtensionException("Message digest ["+digestUri+"] is not supported!", ex);
        }

        byte[] der;
        try {
            der = cert.getEncoded();
        } catch (CertificateEncodingException ex) {
            throw new ExtensionException("Certificate encoding error!", ex);
        }
        md.update(der);
        dt.setDigestValue(md.digest());
        dt.setDigestMethod(new DigestMethodType());
        dt.getDigestMethod().setAlgorithm(digestUri);
        sit.setCertDigest(dt);
        sit.setIssuerSerial(new X509IssuerSerialType());
        sit.getIssuerSerial().setX509IssuerName(cert.getIssuerDN().getName());
        sit.getIssuerSerial().setX509SerialNumber(cert.getSerialNumber());
        SignedSignaturePropertiesType ssp = new SignedSignaturePropertiesType();
        ssp.setSigningTime(OffsetDateTime.now());
        ssp.setSigningCertificate(scert);
        if (signatureReason != null){
            ssp.setSignaturePolicyIdentifier(new SignaturePolicyIdentifierType());
            ssp.getSignaturePolicyIdentifier().setSignaturePolicyImplied(signatureReason);
        }

        if (sigCity != null || sigCountryName != null) {
            ssp.setSignatureProductionPlace(new SignatureProductionPlaceType());
            ssp.getSignatureProductionPlace().setCity(sigCity);
            ssp.getSignatureProductionPlace().setCountryName(sigCountryName);
        }

        scert.getCert().add(sit);
        sp.setSignedSignatureProperties(ssp);
        return sp;
    }


    /**
     * Method creates XAdESQualifyingProperties. Object QualifyingProperties must be stored into
     * XMLdSIg Signature/Object element.
     *
     * @param sigId           - signature id to which QualifyingProperties targets
     * @param strSigPropId    - id for created SignedProperties (part of QualifyingProperties) which must
     *                        be signed
     * @param cert,           signing certificate
     * @param digestURI       digest method code (JCA provider code and W3c - URI)
     * @param signaturePolicy - value for: SignaturePolicyIdentifier/SignaturePolicyImplied - The
     *                        signature policy is a set of rules for the creation and validation ofan electronic signature,
     *                        under which the signature can be determined to be valid. A given legal/contractual context may
     *                        recognize a particular signature policy as meeting its requirements.
     * @param signatureCity         - city where signature was created
     * @param signatureCountryName  - country name where signature was created
     * @return
     * @throws CertificateEncodingException
     * @throws NoSuchAlgorithmException
     */
    public QualifyingPropertiesType createXAdESQualifyingProperties(String sigId,  String strSigPropId,
                                                                    X509Certificate cert, String digestURI,
                                                                    String signaturePolicy,
                                                                    String signatureCity,
                                                                    String signatureCountryName)
            throws ExtensionException {

        QualifyingPropertiesType qt = new QualifyingPropertiesType();
        qt.setTarget("#" + sigId);
        qt.setSignedProperties(createSignedProperties(strSigPropId, cert, digestURI, signaturePolicy,
                signatureCity, signatureCountryName));

        return qt;
    }
}
