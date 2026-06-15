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
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.ClassLoaderUtils;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
 *   <li><b>Presence check</b> — determines whether {@code xades132:QualifyingProperties}
 *       is present in the signature's {@code ds:Object} elements.  If not present the
 *       result is reported as {@link XAdESValidationResult#isXAdESPresent()} == {@code false}
 *       and no further checks are run.</li>
 *   <li><b>XSD structural validation</b> — validates the {@code QualifyingProperties} subtree
 *       against the bundled XAdES v1.3.2 schema ({@code XAdES01903v132-201601.xsd}).</li>
 *   <li><b>Target attribute</b> — {@code QualifyingProperties/@Target} must equal
 *       {@code "#"} + the signature element {@code Id}.</li>
 *   <li><b>SignedProperties reference</b> — the signature must contain a
 *       {@code ds:Reference} whose {@code @Type} equals
 *       {@link XAdESConstants#REFERENCE_TYPE_SIGNEDPROPERTIES}.</li>
 *   <li><b>Signing certificate digest</b> — the {@code CertDigest} value inside
 *       {@code SigningCertificate/Cert} must match the SHA-256 (or configured algorithm)
 *       digest of the provided signing certificate.</li>
 * </ol>
 *
 * <h3>Usage</h3>
 * <pre>{@code
 * XAdESBBValidator validator = new XAdESBBValidator();
 * XAdESValidationResult result = validator.validate(signature, signingCertificate);
 * if (result.isXAdESPresent() && !result.isValid()) {
 *     result.getViolations().forEach(System.out::println);
 * }
 * }</pre>
 *
 * <p>The schema is loaded once at class-load time and reused across instances.
 *
 * @see <a href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
 *      ETSI EN 319 132-1 (XAdES)</a>
 */
public final class XAdESBBValidator {

    private static final String XADES_SCHEMA_RESOURCE ="bindings/schemas/XAdES01903v141-202107.xsd";

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
        } catch (SAXException | IOException  e) {
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

    /**
     * Validates XAdES-B-B properties in {@code signature}.
     *
     * @param signature          the cryptographically verified {@link XMLSignature}
     *                           (core verification must have already succeeded)
     * @param signingCertificate the certificate used to create the signature;
     *                           used to check the {@code CertDigest} value
     * @return validation result; never {@code null}
     */
    public XAdESValidationResult validate(XMLSignature signature,
                                          X509Certificate signingCertificate) {
        List<String> violations = new ArrayList<>();

        Element qualifyingProps = findQualifyingProperties(signature);
        if (qualifyingProps == null) {
            return XAdESValidationResult.notPresent();
        }

        validateSchema(qualifyingProps, violations);
        validateTarget(qualifyingProps, signature, violations);
        validateSignedPropertiesReference(signature, violations);
        if (signingCertificate != null) {
            validateCertDigest(qualifyingProps, signingCertificate, violations);
        }

        return new XAdESValidationResult(true, violations);
    }

    // -------------------------------------------------------------------------
    // XAdES element discovery
    // -------------------------------------------------------------------------

    private Element findQualifyingProperties(XMLSignature signature) {
        Element sigElement = signature.getElement();
        NodeList objects = sigElement.getElementsByTagNameNS(
                Constants.SignatureSpecNS, "Object");
        for (int i = 0; i < objects.getLength(); i++) {
            Element object = (Element) objects.item(i);
            NodeList qpList = object.getElementsByTagNameNS(
                    XAdESConstants.XADES_V132_NS,
                    XAdESConstants.TAG_QUALIFYING_PROPERTIES);
            if (qpList.getLength() > 0) {
                return (Element) qpList.item(0);
            }
        }
        return null;
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
            violations.add("XSD validation error: " + e.getMessage());
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
            violations.add("QualifyingProperties/@Target '" + target +
                    "' does not match expected '" + expected + "'");
        }
    }

    private void validateSignedPropertiesReference(XMLSignature signature,
                                                   List<String> violations) {
        try {
            SignedInfo si = signature.getSignedInfo();
            for (int i = 0; i < si.getLength(); i++) {
                Reference ref = si.item(i);
                if (XAdESConstants.REFERENCE_TYPE_SIGNEDPROPERTIES.equals(ref.getType())) {
                    return; // found
                }
            }
        } catch (XMLSecurityException e) {
            violations.add("Cannot read ds:SignedInfo references: " + e.getMessage());
            return;
        }
        violations.add("No ds:Reference with @Type='" +
                XAdESConstants.REFERENCE_TYPE_SIGNEDPROPERTIES +
                "' found — SignedProperties is not covered by the signature");
    }

    private void validateCertDigest(Element qualifyingProps,
                                    X509Certificate signingCertificate,
                                    List<String> violations) {
        // Find the first CertDigest inside SigningCertificate/Cert
        NodeList certDigestNodes = qualifyingProps.getElementsByTagNameNS(
                XAdESConstants.XADES_V132_NS, "CertDigest");
        if (certDigestNodes.getLength() == 0) {
            violations.add("No xades132:CertDigest element found in QualifyingProperties");
            return;
        }
        Element certDigest = (Element) certDigestNodes.item(0);

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

        String jceAlgorithm = JCEMapper.translateURItoJCEID(algorithmURI);
        if (jceAlgorithm == null) {
            violations.add("Unknown digest algorithm URI in CertDigest: " + algorithmURI);
            return;
        }

        byte[] reportedDigest;
        try {
            reportedDigest = Base64.getDecoder().decode(digestValueB64.trim());
        } catch (IllegalArgumentException e) {
            violations.add("CertDigest/ds:DigestValue is not valid Base64: " + e.getMessage());
            return;
        }

        byte[] actualDigest;
        try {
            byte[] certDer = signingCertificate.getEncoded();
            actualDigest = MessageDigest.getInstance(jceAlgorithm).digest(certDer);
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            violations.add("Cannot compute signing certificate digest: " + e.getMessage());
            return;
        }

        if (!Arrays.equals(actualDigest, reportedDigest)) {
            violations.add("CertDigest does not match the digest of the signing certificate " +
                    "(algorithm=" + algorithmURI + ")");
        }
    }

    // -------------------------------------------------------------------------
    // DOM helpers
    // -------------------------------------------------------------------------

    /**
     * Returns the text content of a child element, or the value of {@code attributeName}
     * on that child if {@code attributeName} is non-null.
     */
    private String getChildTextContent(Element parent, String ns, String localName,
                                       String attributeName) {
        NodeList children = parent.getElementsByTagNameNS(ns, localName);
        if (children.getLength() == 0) {
            return null;
        }
        Element child = (Element) children.item(0);
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
            violations.add("XSD warning: " + e.getMessage());
        }

        @Override
        public void error(org.xml.sax.SAXParseException e) {
            violations.add("XSD error: " + e.getMessage());
        }

        @Override
        public void fatalError(org.xml.sax.SAXParseException e) throws org.xml.sax.SAXException {
            violations.add("XSD fatal error: " + e.getMessage());
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
