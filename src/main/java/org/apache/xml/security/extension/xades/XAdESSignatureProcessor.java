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

import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.extension.SignatureExtensionException;
import org.apache.xml.security.extension.SignatureProcessor;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Pre-processor that adds XAdES-B-B (Basic Electronic Signature) qualifying properties
 * to an XML signature before digests are computed.
 *
 * <p>The processor:
 * <ol>
 *   <li>Assigns an {@code Id} to the {@code ds:Signature} element if one is not already set.</li>
 *   <li>Assigns an {@code Id} to the {@code ds:SignatureValue} element (enables XAdES-T extension).</li>
 *   <li>Builds an XAdES {@code QualifyingProperties} structure containing {@code SignedProperties}
 *       using DOM-based {@link XAdESElementProxy} classes — no JAXB dependency.</li>
 *   <li>Wraps it in a {@code ds:Object} and appends it to the signature.</li>
 *   <li>Adds a {@code ds:Reference} with type {@code SignedProperties} so that
 *       {@code SignedProperties} is covered by the signature digest.</li>
 * </ol>
 *
 * <p>Create an instance using the {@link Builder}:
 * <pre>{@code
 * XAdESSignatureProcessor xades = XAdESSignatureProcessor.builder(certificate)
 *         .withSignaturePolicyImplied(true)
 *         .withSignatureCity("Brussels")
 *         .build();
 * sig.addPreProcessor(xades);
 * }</pre>
 *
 * @see <a href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
 *      ETSI EN 319 132-1 (XAdES)</a>
 */
public final class XAdESSignatureProcessor implements SignatureProcessor {

    private static final String ID_PREFIX_SIG = "sig-";
    private static final String ID_PREFIX_SIG_VAL = "sig-val-";
    private static final String ID_PREFIX_SIG_PROP = "sig-prop-";

    private final X509Certificate certificate;
    private final String certificateDigestAlgorithmURI;
    private final boolean signaturePolicyImplied;
    private final String signatureCity;
    private final String signatureCountryName;
    private final List<String> referenceTransformAlgorithms;

    private XAdESSignatureProcessor(Builder builder) {
        this.certificate = builder.certificate;
        this.certificateDigestAlgorithmURI = builder.certificateDigestAlgorithmURI;
        this.signaturePolicyImplied = builder.signaturePolicyImplied;
        this.signatureCity = builder.signatureCity;
        this.signatureCountryName = builder.signatureCountryName;
        this.referenceTransformAlgorithms = new ArrayList<>(builder.referenceTransformAlgorithms);
    }

    /**
     * Creates a builder for configuring an {@link XAdESSignatureProcessor}.
     *
     * @param certificate the signing certificate; must not be {@code null}
     */
    public static Builder builder(X509Certificate certificate) {
        return new Builder(certificate);
    }

    @Override
    public void processSignature(XMLSignature signature) throws XMLSignatureException {
        ensureSignatureId(signature);
        ensureSignatureValueId(signature);

        String signatureId = signature.getId();
        String signedPropertiesId = IDGenerator.generateID(ID_PREFIX_SIG_PROP);
        Document doc = signature.getElement().getOwnerDocument();

        SignedSignatureProperties ssp = buildSignedSignatureProperties(doc);

        SignedProperties sp = new SignedProperties(doc, signedPropertiesId);
        sp.setSignedSignatureProperties(ssp);

        QualifyingProperties qp = new QualifyingProperties(doc, "#" + signatureId);
        qp.setSignedProperties(sp);

        ObjectContainer objectContainer = new ObjectContainer(doc);
        objectContainer.appendChild(qp.getElement());
        signature.appendObject(objectContainer);

        Transforms transforms = buildReferenceTransforms(doc);
        signature.addDocument(
                "#" + signedPropertiesId,
                transforms,
                XMLCipher.SHA256,
                null,
                XAdESConstants.REFERENCE_TYPE_SIGNEDPROPERTIES);
    }

    private SignedSignatureProperties buildSignedSignatureProperties(Document doc)
            throws XMLSignatureException {
        SignedSignatureProperties ssp = new SignedSignatureProperties(doc);
        ssp.setSigningTime(OffsetDateTime.now());
        ssp.setSigningCertificate(buildSigningCertificate(doc));
        if (signaturePolicyImplied) {
            ssp.setSignaturePolicyImplied();
        }
        if (signatureCity != null || signatureCountryName != null) {
            ssp.setSignatureProductionPlace(signatureCity, signatureCountryName);
        }
        return ssp;
    }

    private SigningCertificate buildSigningCertificate(Document doc) throws XMLSignatureException {
        byte[] certDer;
        try {
            certDer = certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new SignatureExtensionException("Cannot encode signing certificate", e);
        }

        byte[] digest;
        try {
            digest = MessageDigestAlgorithm.getDigestInstance(certificateDigestAlgorithmURI).digest(certDer);
        } catch (XMLSecurityException e) {
            throw new SignatureExtensionException(
                    "Digest algorithm not available: " + certificateDigestAlgorithmURI, e);
        }

        Cert cert = new Cert(doc);
        cert.setCertDigest(certificateDigestAlgorithmURI, digest);
        cert.setIssuerSerial(
                certificate.getIssuerX500Principal().getName(),
                certificate.getSerialNumber());

        SigningCertificate sc = new SigningCertificate(doc);
        sc.addCert(cert);
        return sc;
    }

    private void ensureSignatureId(XMLSignature signature) {
        if (isBlank(signature.getId())) {
            signature.setId(IDGenerator.generateID(ID_PREFIX_SIG));
        }
    }

    private void ensureSignatureValueId(XMLSignature signature){
        if (isBlank(signature.getSignatureValueId())) {
            signature.setSignatureValueId(IDGenerator.generateID(ID_PREFIX_SIG_VAL));
        }
    }

    private Transforms buildReferenceTransforms(Document doc) throws XMLSignatureException {
        if (referenceTransformAlgorithms.isEmpty()) {
            return null;
        }
        Transforms transforms = new Transforms(doc);
        try {
            for (String algorithm : referenceTransformAlgorithms) {
                transforms.addTransform(algorithm);
            }
        } catch (TransformationException e) {
            throw new XMLSignatureException(e);
        }
        return transforms;
    }

    /** Returns an unmodifiable view of the currently configured reference transform algorithms. */
    public List<String> getReferenceTransformAlgorithms() {
        return Collections.unmodifiableList(referenceTransformAlgorithms);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    // -------------------------------------------------------------------------
    // Builder
    // -------------------------------------------------------------------------

    /**
     * Fluent builder for {@link XAdESSignatureProcessor}.
     */
    public static final class Builder {

        private boolean allowWeakAlgorithms = false;
        private final X509Certificate certificate;
        private String certificateDigestAlgorithmURI = XMLCipher.SHA256;
        private boolean signaturePolicyImplied = false;
        private String signatureCity;
        private String signatureCountryName;
        private final List<String> referenceTransformAlgorithms = new ArrayList<>();

        private Builder(X509Certificate certificate) {
            this.certificate = Objects.requireNonNull(certificate, "certificate");
        }

        /**
         * Digest algorithm URI used to hash the signing certificate.
         * Defaults to {@code XMLCipher.SHA256} if not set.
         */
        public Builder withCertificateDigestAlgorithmURI(String uri) {
            this.certificateDigestAlgorithmURI = Objects.requireNonNull(uri, "uri");
            return this;
        }

        /**
         * When {@code true}, includes an empty {@code <SignaturePolicyImplied/>} element
         * indicating the policy is implied by the signing context.
         */
        public Builder withSignaturePolicyImplied(boolean signaturePolicyImplied) {
            this.signaturePolicyImplied = signaturePolicyImplied;
            return this;
        }

        /** Optional city to include in {@code SignatureProductionPlace}. */
        public Builder withSignatureCity(String city) {
            this.signatureCity = city;
            return this;
        }

        /** Optional country name to include in {@code SignatureProductionPlace}. */
        public Builder withSignatureCountryName(String countryName) {
            this.signatureCountryName = countryName;
            return this;
        }

        /** When {@code true}, allows weak digest algorithms (e.g. SHA-1) to be used for certificate digest. */
        public Builder withAllowWeakAlgorithms(boolean allowWeakAlgorithms) {
            this.allowWeakAlgorithms = allowWeakAlgorithms;
            return this;
        }

        /**
         * Adds a canonicalization or transform algorithm URI to apply to the
         * {@code SignedProperties} reference before digesting. Algorithms are applied in
         * the order they are added.
         */
        public Builder addReferenceTransformAlgorithm(String algorithm) {
            this.referenceTransformAlgorithms.add(Objects.requireNonNull(algorithm, "algorithm"));
            return this;
        }

        public XAdESSignatureProcessor build() {
            Objects.requireNonNull(certificateDigestAlgorithmURI, "certificateDigestAlgorithmURI");
            if (!this.allowWeakAlgorithms && !XAdESConstants.APPROVED_CERT_DIGEST_ALGORITHM_URIS.contains(certificateDigestAlgorithmURI)) {
                throw new IllegalArgumentException(
                        "certificateDigestAlgorithmURI uses a weak or disallowed digest algorithm: "
                                + certificateDigestAlgorithmURI);
            }
            return new XAdESSignatureProcessor(this);
        }
    }
}
