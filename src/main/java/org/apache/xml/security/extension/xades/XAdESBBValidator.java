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
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.ClassLoaderUtils;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Element;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Validates XAdES-B-B (Basic Electronic Signature) qualifying properties embedded in an
 * {@link XMLSignature}.
 *
 * <h3>Validation performed</h3>
 * <ol>
 *   <li><b>Presence check</b> — XAdES is present if {@code ds:SignedInfo} contains a
 *       {@code ds:Reference} with {@code @Type} {@link XAdESConstants#REFERENCE_TYPE_SIGNEDPROPERTIES}
 *       or if {@code xades132:QualifyingProperties} is a direct child of a {@code ds:Object} that is
 *       itself a direct child of the {@code ds:Signature}.  If neither holds the result is reported
 *       as {@link XAdESValidationResult#isXAdESPresent()} == {@code false}.  A SignedProperties
 *       reference without {@code QualifyingProperties} at that location, or more than one
 *       {@code QualifyingProperties}, is a violation.</li>
 *   <li><b>SignedProperties binding</b> — the {@code QualifyingProperties} must have exactly one
 *       direct child {@code xades132:SignedProperties} with an {@code Id}, and {@code ds:SignedInfo}
 *       must contain exactly one {@code ds:Reference} whose {@code @Type} equals
 *       {@link XAdESConstants#REFERENCE_TYPE_SIGNEDPROPERTIES}. That reference's {@code @URI}
 *       must name the {@code Id}, dereference to that very element, use only canonicalization
 *       transforms ({@link XAdESConstants#ALLOWED_SIGNED_PROPERTIES_TRANSFORMS}), and its digest
 *       must verify. If the binding fails, the remaining checks are skipped: properties that
 *       are not covered by the signature are never reported as validated.</li>
 *   <li><b>XSD structural validation</b> — validates the {@code QualifyingProperties} subtree
 *       against the bundled XAdES v1.3.2 schema ({@code XAdES01903v132-201601.xsd}).</li>
 *   <li><b>Target attribute</b> — {@code QualifyingProperties/@Target} must equal
 *       {@code "#"} + the signature element {@code Id}.</li>
 *   <li><b>Signing certificate digest</b> — the {@code CertDigest} value at
 *       {@code SignedProperties/SignedSignatureProperties/SigningCertificateV2/Cert[1]} (or
 *       {@code SigningCertificate/Cert[1]}) must match the SHA-256 (or configured algorithm) digest
 *       of the provided signing certificate. Having both elements is a violation.</li>
 * </ol>
 *
 * <p>The validator re-verifies the digest of the {@code SignedProperties} reference only.
 * The caller must still perform core {@link XMLSignature} verification
 * ({@code SignatureValue} and all other references) and decide whether the signing certificate
 * is trusted.
 *
 * <h3>What is and isn't covered</h3>
 * <p>Only {@code xades132:SignedProperties} is bound to the signature.
 * {@code QualifyingProperties/@Target}, {@code UnsignedProperties} and anything else outside
 * {@code SignedProperties} are only checked for structure. A valid result does not make them
 * trustworthy: callers must verify such content (for example timestamp tokens) independently.
 *
 * <h3>Usage</h3>
 * <pre>{@code
 * XAdESBBValidator validator = new XAdESBBValidator();
 * XAdESValidationResult result = validator.validate(signature, signingCertificate);
 * if (!result.isValid()) {
 *     // reject: either XAdES is absent or a check failed
 *     result.getViolations().forEach(System.out::println);
 * }
 * }</pre>
 *
 * <p>{@link XAdESValidationResult#isXAdESPresent()} is informational. Callers that require XAdES
 * must check {@link XAdESValidationResult#isValid()}.
 *
 * <p>The schema is loaded once at class-load time and reused across instances.
 *
 * @see <a href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
 *      ETSI EN 319 132-1 (XAdES)</a>
 */
public final class XAdESBBValidator {

    private static final String XADES_SCHEMA_RESOURCE =
            "bindings/schemas/XAdES01903v132-201601.xsd";


    /**
     * Schema is thread-safe once constructed; load once and share.
     * Null if schema loading failed at class init time.
     */
    private static final Schema XADES_SCHEMA = loadSchema();

    private static Schema loadSchema() {
        try {
            SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            sf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            sf.setResourceResolver(new SchemeResourceResolver());
            // load all schema resources from classpath and combine into a single schema
            String xadesUri = resourceUri(XADES_SCHEMA_RESOURCE);
            try (InputStream xadesIs = ClassLoaderUtils.getResourceAsStream(
                    XADES_SCHEMA_RESOURCE, XAdESBBValidator.class)) {
                return sf.newSchema(new StreamSource(xadesIs, xadesUri));
            }
        } catch (SAXException | IOException e) {
            // Logged here; validate() reports the violation rather than crashing callers
            System.getLogger(XAdESBBValidator.class.getName())
                    .log(System.Logger.Level.ERROR,
                            "Failed to load XAdES schema — XSD validation will be skipped", e);
            return null;
        }
    }

    private static String resourceUri(String path) {
        java.net.URL url = ClassLoaderUtils.getResource(path, XAdESBBValidator.class);
        if (url == null) {
            throw new IllegalStateException("XAdES schema not found on classpath: " + path);
        }
        return url.toExternalForm();
    }


    /** Maximum length of an attacker-influenced value embedded in a violation message. */
    private static final int MAX_MESSAGE_VALUE_LENGTH = 256;

    private final boolean secureValidation;

    public XAdESBBValidator() {
        this(true);
    }

    /**
     * @param secureValidation if {@code true}, the digest algorithms of the SignedProperties
     *                         {@code ds:Reference} and of {@code CertDigest} must be in
     *                         {@link XAdESConstants#APPROVED_CERT_DIGEST_ALGORITHM_URIS}. For untrusted
     *                         input the {@link XMLSignature} must also be created with secure validation on.
     */
    public XAdESBBValidator(boolean secureValidation) {
        this.secureValidation = secureValidation;
    }

    /**
     * Validates XAdES-B-B properties in {@code signature}.
     *
     * @param signature          the {@link XMLSignature} to check. The validator does not verify
     *                           {@code SignatureValue}: {@link XAdESValidationResult#isValid()} never
     *                           implies core validity, callers must call
     *                           {@link XMLSignature#checkSignatureValue} separately
     * @param signingCertificate the certificate used to create the signature;
     *                           used to check the {@code CertDigest} value; must not be
     *                           {@code null}, a {@code null} value makes the result invalid
     * @return validation result; never {@code null}
     */
    public XAdESValidationResult validate(XMLSignature signature,
                                          X509Certificate signingCertificate) {
        List<String> violations = new ArrayList<>();

        // Presence is decided from SignedInfo too: it is covered by SignatureValue, so an attacker
        // cannot hide XAdES by moving the unsigned ds:Object
        List<Reference> spRefs;
        try {
            spRefs = findSignedPropertiesReferences(signature.getSignedInfo());
        } catch (XMLSecurityException e) {
            violations.add("Cannot read ds:SignedInfo references: " + sanitize(e.getMessage()));
            return new XAdESValidationResult(true, violations);
        }

        List<Element> qualifyingPropsList = findQualifyingProperties(signature);
        if (qualifyingPropsList.isEmpty()) {
            if (spRefs.isEmpty()) {
                return XAdESValidationResult.notPresent();
            }
            violations.add("SignedProperties reference present but no xades132:QualifyingProperties "
                    + "found directly under ds:Signature/ds:Object");
            return new XAdESValidationResult(true, violations);
        }
        if (qualifyingPropsList.size() > 1) {
            violations.add("Multiple xades132:QualifyingProperties elements found in ds:Signature ("
                    + qualifyingPropsList.size() + "); exactly one is allowed");
            return new XAdESValidationResult(true, violations);
        }
        Element qualifyingProps = qualifyingPropsList.get(0);

        Element signedProps = findSignedProperties(qualifyingProps, violations);
        if (signedProps == null
                || !validateSignedPropertiesBinding(spRefs, signedProps, violations)) {
            // Unbound properties are attacker-controlled: do not validate their content
            return new XAdESValidationResult(true, violations);
        }

        validateSchema(qualifyingProps, violations);
        validateTarget(qualifyingProps, signature, violations);
        if (signingCertificate == null) {
            violations.add("No signing certificate provided — SigningCertificate binding cannot be verified");
        } else {
            validateCertDigest(signedProps, signingCertificate, violations);
        }

        return new XAdESValidationResult(true, violations);
    }

    /**
     * Returns all {@code xades132:QualifyingProperties} that are direct children of a
     * {@code ds:Object} that is a direct child of the signature element. Elements nested
     * deeper (e.g. inside a counter-signature or a {@code ds:Manifest}) belong to other
     * structures and are ignored.
     */
    private List<Element> findQualifyingProperties(XMLSignature signature) {
        List<Element> result = new ArrayList<>();
        for (Element object : XMLUtils.selectDsNodes(signature.getElement().getFirstChild(),
                Constants._TAG_OBJECT)) {
            result.addAll(Arrays.asList(XMLUtils.selectNodes(object.getFirstChild(),
                    XAdESConstants.XADES_V132_NS, XAdESConstants.TAG_QUALIFYING_PROPERTIES)));
        }
        return result;
    }

    private static List<Reference> findSignedPropertiesReferences(SignedInfo signedInfo)
            throws XMLSecurityException {
        List<Reference> result = new ArrayList<>();
        for (int i = 0; i < signedInfo.getLength(); i++) {
            Reference ref = signedInfo.item(i);
            if (XAdESConstants.REFERENCE_TYPE_SIGNEDPROPERTIES.equals(ref.getType())) {
                result.add(ref);
            }
        }
        return result;
    }

    private Element findSignedProperties(Element qualifyingProps, List<String> violations) {
        Element[] signedPropsList = XMLUtils.selectNodes(qualifyingProps.getFirstChild(),
                XAdESConstants.XADES_V132_NS, XAdESConstants.TAG_SIGNED_PROPERTIES);
        if (signedPropsList.length == 0) {
            violations.add("No xades132:SignedProperties element found in QualifyingProperties");
            return null;
        }
        if (signedPropsList.length > 1) {
            violations.add("Multiple xades132:SignedProperties elements found in QualifyingProperties");
            return null;
        }
        Element signedProps = signedPropsList[0];
        String id = signedProps.getAttributeNS(null, "Id");
        if (id.isBlank()) {
            violations.add("xades132:SignedProperties has no Id attribute and cannot be referenced");
            return null;
        }
        return signedProps;
    }

    // -------------------------------------------------------------------------
    // XSD validation
    // -------------------------------------------------------------------------

    private void validateSchema(Element qualifyingProps, List<String> violations) {
        if (XADES_SCHEMA == null) {
            violations.add("XAdES schema not available — XSD validation skipped");
            return;
        }
        try {
            Validator validator = XADES_SCHEMA.newValidator();
            validator.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            // Collect all schema violations rather than stopping at first error
            List<String> schemaViolations = new ArrayList<>();
            validator.setErrorHandler(new SchemaErrorCollector(schemaViolations));
            validator.validate(new DOMSource(qualifyingProps));
            violations.addAll(schemaViolations);
        } catch (SAXException | IOException e) {
            violations.add("XSD validation error: " + sanitize(e.getMessage()));
        }
    }

    // -------------------------------------------------------------------------
    // Semantic checks
    // -------------------------------------------------------------------------

    private void validateTarget(Element qualifyingProps,
                                XMLSignature signature,
                                List<String> violations) {
        String target = qualifyingProps.getAttribute("Target");
        String signatureId = signature.getId();
        if (signatureId == null || signatureId.isBlank()) {
            violations.add("QualifyingProperties/@Target validation skipped: " +
                    "ds:Signature has no Id attribute");
            return;
        }
        String expected = "#" + signatureId;
        if (!expected.equals(target)) {
            violations.add("QualifyingProperties/@Target '" + sanitize(target) +
                    "' does not match expected '" + expected + "'");
        }
    }

    /**
     * Verifies that {@code signedProps} is the element covered by the signature: exactly one
     * {@code SignedProperties}-typed reference exists, it points at and dereferences to this
     * element, it only uses canonicalization transforms and its digest verifies.
     *
     * @return {@code true} if the binding holds; otherwise a violation has been added
     */
    private boolean validateSignedPropertiesBinding(List<Reference> spRefs,
                                                    Element signedProps,
                                                    List<String> violations) {
        try {
            if (spRefs.size() > 1) {
                violations.add("Multiple ds:Reference elements with @Type='" +
                        XAdESConstants.REFERENCE_TYPE_SIGNEDPROPERTIES + "' found");
                return false;
            }
            if (spRefs.isEmpty()) {
                violations.add("No ds:Reference with @Type='" +
                        XAdESConstants.REFERENCE_TYPE_SIGNEDPROPERTIES +
                        "' found — SignedProperties is not covered by the signature");
                return false;
            }
            Reference spRef = spRefs.get(0);

            String id = signedProps.getAttributeNS(null, "Id");
            String uri = spRef.getURI();
            if (!("#" + id).equals(uri) && !("#xpointer(id('" + id + "'))").equals(uri)
                    && !("#xpointer(id(\"" + id + "\"))").equals(uri)) {
                violations.add("SignedProperties reference URI '" + sanitize(uri) +
                        "' does not point to SignedProperties Id '" + sanitize(id) + "'");
                return false;
            }

            // The dereferenced node must be exactly the validated element; this also defeats
            // duplicate-Id wrapping when secure validation is disabled in the resolver
            XMLSignatureInput input = spRef.getContentsBeforeTransformation();
            if (input == null || input.getSubNode() != signedProps) {
                violations.add("SignedProperties reference '" + sanitize(uri) +
                        "' does not resolve to the validated xades132:SignedProperties element");
                return false;
            }

            Transforms transforms = spRef.getTransforms();
            if (transforms != null) {
                for (int i = 0; i < transforms.getLength(); i++) {
                    String algorithm = transforms.item(i).getURI();
                    if (!XAdESConstants.ALLOWED_SIGNED_PROPERTIES_TRANSFORMS.contains(algorithm)) {
                        violations.add("Disallowed transform on SignedProperties reference: " + sanitize(algorithm));
                        return false;
                    }
                }
            }

            MessageDigestAlgorithm mda = spRef.getMessageDigestAlgorithm();
            if (mda == null) {
                violations.add("SignedProperties reference has no ds:DigestMethod/@Algorithm");
                return false;
            }
            String digestUri = mda.getAlgorithmURI();
            if (secureValidation && !XAdESConstants.APPROVED_CERT_DIGEST_ALGORITHM_URIS.contains(digestUri)) {
                violations.add("SignedProperties reference uses a weak or disallowed digest algorithm: "
                        + sanitize(digestUri));
                return false;
            }

            if (!spRef.verify()) {
                violations.add("SignedProperties reference digest does not verify — " +
                        "SignedProperties has been modified");
                return false;
            }
            return true;
        } catch (XMLSecurityException e) {
            violations.add("Cannot verify SignedProperties reference: " + sanitize(e.getMessage()));
            return false;
        }
    }

    private void validateCertDigest(Element signedProps,
                                    X509Certificate signingCertificate,
                                    List<String> violations) {
        // SignedProperties/SignedSignatureProperties/SigningCertificate[V2]/Cert[1]/CertDigest
        Element ssp = firstChildElement(signedProps, XAdESConstants.TAG_SIGNED_SIGNATURE_PROPERTIES);
        Element signingCert = firstChildElement(ssp, XAdESConstants.TAG_SIGNING_CERTIFICATE);
        Element signingCertV2 = firstChildElement(ssp, XAdESConstants.TAG_SIGNING_CERTIFICATE_V2);
        if (signingCert != null && signingCertV2 != null) {
            violations.add("Both SigningCertificate and SigningCertificateV2 present; exactly one is allowed");
            return;
        }
        Element certDigest = firstChildElement(signingCertV2 != null ? signingCertV2 : signingCert,
                XAdESConstants.TAG_CERT);
        certDigest = firstChildElement(certDigest, XAdESConstants.TAG_CERT_DIGEST);
        if (certDigest == null) {
            violations.add("No xades132:CertDigest element found in " +
                    "SignedProperties/SignedSignatureProperties/SigningCertificate[V2]/Cert");
            return;
        }

        String algorithmURI = getChildTextContent(certDigest,
                Constants.SignatureSpecNS, "DigestMethod", "Algorithm");
        String digestValueB64 = getChildTextContent(certDigest,
                Constants.SignatureSpecNS, "DigestValue", null);

        if (algorithmURI == null || algorithmURI.isBlank()) {
            violations.add("CertDigest/ds:DigestMethod/@Algorithm is missing or empty");
            return;
        }
        if (digestValueB64 == null || digestValueB64.isBlank()) {
            violations.add("CertDigest/ds:DigestValue is missing or empty");
            return;
        }

        if (secureValidation && !XAdESConstants.APPROVED_CERT_DIGEST_ALGORITHM_URIS.contains(algorithmURI)) {
            violations.add("CertDigest uses a weak or disallowed digest algorithm: " + sanitize(algorithmURI));
            return;
        }

        byte[] reportedDigest;
        try {
            // xs:base64Binary allows XML whitespace; any other non-alphabet character is rejected
            reportedDigest = Base64.getDecoder().decode(digestValueB64.replaceAll("[ \\t\\r\\n]", ""));
        } catch (IllegalArgumentException e) {
            violations.add("CertDigest/ds:DigestValue is not valid Base64: " + sanitize(e.getMessage()));
            return;
        }

        byte[] actualDigest;
        try {
            byte[] certDer = signingCertificate.getEncoded();
            actualDigest = MessageDigestAlgorithm.getDigestInstance(algorithmURI).digest(certDer);
        } catch (CertificateEncodingException | XMLSecurityException e) {
            violations.add("Cannot compute signing certificate digest: " + sanitize(e.getMessage()));
            return;
        }

        if (!Arrays.equals(actualDigest, reportedDigest)) {
            violations.add("CertDigest does not match the digest of the signing certificate " +
                    "(algorithm=" + sanitize(algorithmURI) + ")");
        }
    }

    /**
     * Makes an attacker-influenced value safe to embed in a violation message: control
     * characters (including CR/LF) are replaced with {@code '?'} and the value is truncated.
     */
    private static String sanitize(String value) {
        if (value == null) {
            return "null";
        }
        boolean truncated = value.length() > MAX_MESSAGE_VALUE_LENGTH;
        StringBuilder sb = new StringBuilder(truncated ? value.substring(0, MAX_MESSAGE_VALUE_LENGTH) : value);
        for (int i = 0; i < sb.length(); i++) {
            char c = sb.charAt(i);
            if (Character.isISOControl(c) || c == ' ' || c == ' ') {
                sb.setCharAt(i, '?');
            }
        }
        return truncated ? sb.append("...").toString() : sb.toString();
    }

    // -------------------------------------------------------------------------
    // DOM helpers
    // -------------------------------------------------------------------------

    /** Returns the first direct XAdES v1.3.2 child element, or {@code null} if absent or parent is {@code null}. */
    private static Element firstChildElement(Element parent, String localName) {
        if (parent == null) {
            return null;
        }
        return XMLUtils.selectNode(parent.getFirstChild(), XAdESConstants.XADES_V132_NS, localName, 0);
    }

    /**
     * Returns the text content of a direct child element, or the value of {@code attributeName}
     * on that child if {@code attributeName} is non-null.
     */
    private String getChildTextContent(Element parent, String ns, String localName,
                                       String attributeName) {
        Element child = XMLUtils.selectNode(parent.getFirstChild(), ns, localName, 0);
        if (child == null) {
            return null;
        }
        if (attributeName != null) {
            return child.getAttribute(attributeName);
        }
        return child.getTextContent();
    }

    /**
     * The Schema Error Collector
     */
    private static final class SchemaErrorCollector implements org.xml.sax.ErrorHandler {

        private final List<String> violations;

        SchemaErrorCollector(List<String> violations) {
            this.violations = violations;
        }

        @Override
        public void warning(org.xml.sax.SAXParseException e) {
            violations.add("XSD warning: " + sanitize(e.getMessage()));
        }

        @Override
        public void error(org.xml.sax.SAXParseException e) {
            violations.add("XSD error: " + sanitize(e.getMessage()));
        }

        @Override
        public void fatalError(org.xml.sax.SAXParseException e) throws org.xml.sax.SAXException {
            violations.add("XSD fatal error: " + sanitize(e.getMessage()));
            throw e;
        }
    }

    /**
     * LSResourceResolver that loads schema resources from the classpath. Used to resolve the XAdES schema and its
     * dependencies (e.g. xmldsig-core-schema.xsd) during XSD validation. The schema files must be located in the
     * "bindings/schemas/" directory on the classpath.
     */
    private static final class SchemeResourceResolver implements LSResourceResolver {
        private static final String resourcePath = "bindings/schemas/";
        @Override
        public LSInput resolveResource(
                String type,
                String namespaceURI,
                String publicId,
                String systemId,
                String baseURI) {

            // systemId is e.g. "xmldsig-core-schema.xsd"
            String resource = resourcePath + systemId;
            InputStream is =  ClassLoaderUtils.getResourceAsStream(resource, XAdESBBValidator.class);

            if (is == null) {
                throw new IllegalStateException("Cannot resolve schema: " + systemId);
            }

            return new LSInput() {
                @Override public Reader getCharacterStream() { return null; }
                @Override public void setCharacterStream(Reader characterStream) {}
                @Override public InputStream getByteStream() { return is; }
                @Override public void setByteStream(InputStream byteStream) {}
                @Override public String getStringData() { return null; }
                @Override public void setStringData(String stringData) {}
                @Override public String getSystemId() { return systemId; }
                @Override public void setSystemId(String systemId) {}
                @Override public String getPublicId() { return publicId; }
                @Override public void setPublicId(String publicId) {}
                @Override public String getBaseURI() { return baseURI; }
                @Override public void setBaseURI(String baseURI) {}
                @Override public String getEncoding() { return "UTF-8"; }
                @Override public void setEncoding(String encoding) {}
                @Override public boolean getCertifiedText() { return false; }
                @Override public void setCertifiedText(boolean certifiedText) {}
            };
        }
    }
}
