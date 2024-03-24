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
package org.apache.xml.security.extension.xades;

import jakarta.xml.bind.JAXBException;
import org.apache.xml.security.binding.xmldsig.xades.v132.QualifyingPropertiesType;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.extension.SignatureProcessor;
import org.apache.xml.security.extension.exceptions.ExtensionException;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;

import javax.xml.namespace.QName;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.apache.jcp.xml.dsig.internal.dom.DOMUtils.objectToXMLStructure;
import static org.apache.xml.security.extension.xades.XAdESConstants.*;
import static org.apache.xml.security.extension.xades.XAdESQualifyingPropertiesBuilder.create;

/**
 * This class is responsible for pre-processing XAdES signature.
 * It adds XAdES QualifyingProperties to the signature to be signed.
 */
public class XAdESSignatureProcessor implements SignatureProcessor {
    private static final String ID_PREFIX_SIG = "sig-";
    private static final String ID_PREFIX_SIG_VAL = "sig-val-";
    private static final String ID_PREFIX_SIG_PROP = "sig-prop-";

    // XAdES data
    private X509Certificate signatureCertificate;
    private String certificateDigestMethodURI;
    private String signaturePolicy;
    private String signatureCity;
    private String signatureCountryName;
    // List of transformations to be done before digesting
    List<String> referenceTransformAlgorithms = new ArrayList<>();

    public XAdESSignatureProcessor(X509Certificate x509) {
        this(x509, XMLCipher.SHA256, null, null, null);
    }

    public XAdESSignatureProcessor(X509Certificate x509, String certificateDigestMethodURI, String signaturePolicy, String signatureCity, String signatureCountryName) {
        this.signatureCertificate = x509;
        this.certificateDigestMethodURI = certificateDigestMethodURI;
        this.signaturePolicy = signaturePolicy;
        this.signatureCity = signatureCity;
        this.signatureCountryName = signatureCountryName;
    }

    public void processSignature(XMLSignature signature) throws XMLSignatureException {

        if (isEmptyString(signature.getId())) {
            signature.setId(IDGenerator.generateID(ID_PREFIX_SIG));
        }
        // set signature value id to be ready for XAdES-T extension
        if (isEmptyString(signature.getSignatureValueId())) {
            signature.setSignatureValueId(IDGenerator.generateID(ID_PREFIX_SIG_VAL));
        }

        String strSigId = signature.getId();
        String strXAdESSigPropId = IDGenerator.generateID(ID_PREFIX_SIG_PROP);
        Document doc = signature.getElement().getOwnerDocument();
        // set xades data
        QualifyingPropertiesType qualifyingProperties;

        try {
            // create XAdES QualifyingProperties
            qualifyingProperties = create()
                    .withSignatureId(strSigId)
                    .withXAdESSignaturePropertiesId(strXAdESSigPropId)
                    .withSigningCertificate(signatureCertificate)
                    .withCertificateDigestMethodURI(certificateDigestMethodURI)
                    .withSignaturePolicy(signaturePolicy)
                    .withSignatureCity(signatureCity)
                    .withSignatureCountryName(signatureCountryName)
                    .build();
        } catch (ExtensionException e) {
            throw new XMLSignatureException(e);
        }

        // add XAdES QualifyingProperties to the signature
        ObjectContainer objectContainer = new ObjectContainer(doc);
        try {
            objectContainer.appendChild(objectToXMLStructure(objectContainer.getElement(),
                    qualifyingProperties,
                    new QName(XADES_V132_NS, _TAG_QUALIFYINGPROPERTIES, XADES_V132_PREFIX)));
        } catch (JAXBException e) {
            throw new XMLSignatureException(e);
        }

        signature.appendObject(objectContainer);
        // add reference to the signed properties
        Transforms transforms = getReferenceTransform(doc);
        signature.addDocument("#" + strXAdESSigPropId, transforms, XMLCipher.SHA256,
                null, REFERENCE_TYPE_SIGNEDPROPERTIES);
    }

    private static boolean isEmptyString(String str) {
        return str == null || str.isEmpty();
    }

    /**
     * This method returns the reference transform algorithm.
     * Optional list of transformations to be done before digesting
     *
     * @return the reference transform algorithm
     */
    public List<String> getReferenceTransformsAlgorithm() {
        return referenceTransformAlgorithms;
    }

    public void addReferenceTransformAlgorithm(String referenceTransformAlgorithm) {
        this.referenceTransformAlgorithms.add(referenceTransformAlgorithm);
    }

    public void removeReferenceTransformAlgorithm(String referenceTransformAlgorithm) {
        this.referenceTransformAlgorithms.remove(referenceTransformAlgorithm);
    }

    /**
     * This method returns the Transforms object with the reference transform
     * algorithm set.
     *
     * @param doc the document in which the Transforms object is created
     * @return the Transforms object with the transform algorithm set or
     *          null if no transform algorithm is not set
     * @throws XMLSignatureException if an error occurs during the creation of the Transforms object
     */
    private Transforms getReferenceTransform(Document doc) throws XMLSignatureException {
        if (referenceTransformAlgorithms.isEmpty()) {
            return null;
        }
        Transforms transforms = new Transforms(doc);
        try {
            for (String referenceTransformAlgorithm : referenceTransformAlgorithms) {
                transforms.addTransform(referenceTransformAlgorithm);
            }
        } catch (TransformationException e) {
            throw new XMLSignatureException(e);
        }
        return transforms;
    }
}
