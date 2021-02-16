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
package org.apache.xml.security.stax.ext;

import java.security.Key;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants;

import static java.util.Objects.requireNonNull;

/**
 * Main configuration class to supply keys etc.
 * This class is subject to change in the future.
 *
 */
public class XMLSecurityProperties {

    private final List<InputProcessor> inputProcessorList = new ArrayList<>();
    private boolean skipDocumentEvents = false;
    private boolean disableSchemaValidation = false;

    private List<XMLSecurityConstants.Action> actions = new ArrayList<>();

    private X509Certificate encryptionUseThisCertificate;
    private String encryptionSymAlgorithm;
    private String encryptionKeyTransportAlgorithm;
    private String encryptionKeyTransportDigestAlgorithm;
    private String encryptionKeyTransportMGFAlgorithm;
    private byte[] encryptionKeyTransportOAEPParams;
    private final List<SecurePartSelector> encryptionPartSelectors = new LinkedList<>();
    private Key encryptionKey;
    private Key encryptionTransportKey;
    private SecurityTokenConstants.KeyIdentifier encryptionKeyIdentifier;
    private String encryptionKeyName;

    private Key decryptionKey;

    private final List<SecurePartSelector> signaturePartSelectors = new LinkedList<>();
    private String signatureAlgorithm;
    private String signatureDigestAlgorithm;
    private String signatureCanonicalizationAlgorithm;
    private Key signatureKey;
    private X509Certificate[] signatureCerts;
    private boolean addExcC14NInclusivePrefixes = false;
    private List<SecurityTokenConstants.KeyIdentifier> signatureKeyIdentifiers = new ArrayList<>();
    private String signatureKeyName;
    private boolean useSingleCert = true;

    private Key signatureVerificationKey;

    private int signaturePosition;

    private QName idAttributeNS = XMLSecurityConstants.ATT_NULL_Id;

    private final Map<String, Key> keyNameMap = new HashMap<>();

    private boolean signatureGenerateIds = true;
    private boolean signatureIncludeDigestTransform = true;

    private QName signaturePositionQName;
    private boolean signaturePositionStart = false;
    private AlgorithmParameterSpec algorithmParameterSpec;

    public XMLSecurityProperties() {
    }

    protected XMLSecurityProperties(XMLSecurityProperties xmlSecurityProperties) {
        this.inputProcessorList.addAll(xmlSecurityProperties.inputProcessorList);
        this.skipDocumentEvents = xmlSecurityProperties.skipDocumentEvents;
        this.disableSchemaValidation = xmlSecurityProperties.disableSchemaValidation;
        this.actions = xmlSecurityProperties.actions;
        this.encryptionUseThisCertificate = xmlSecurityProperties.encryptionUseThisCertificate;
        this.encryptionSymAlgorithm = xmlSecurityProperties.encryptionSymAlgorithm;
        this.encryptionKeyTransportAlgorithm = xmlSecurityProperties.encryptionKeyTransportAlgorithm;
        this.encryptionKeyTransportDigestAlgorithm = xmlSecurityProperties.encryptionKeyTransportDigestAlgorithm;
        this.encryptionKeyTransportMGFAlgorithm = xmlSecurityProperties.encryptionKeyTransportMGFAlgorithm;
        this.encryptionKeyTransportOAEPParams = xmlSecurityProperties.encryptionKeyTransportOAEPParams;
        this.encryptionPartSelectors.addAll(xmlSecurityProperties.encryptionPartSelectors);
        this.encryptionKey = xmlSecurityProperties.encryptionKey;
        this.encryptionTransportKey = xmlSecurityProperties.encryptionTransportKey;
        this.encryptionKeyIdentifier = xmlSecurityProperties.encryptionKeyIdentifier;
        this.decryptionKey = xmlSecurityProperties.decryptionKey;
        this.signaturePartSelectors.addAll(xmlSecurityProperties.signaturePartSelectors);
        this.signatureAlgorithm = xmlSecurityProperties.signatureAlgorithm;
        this.signatureDigestAlgorithm = xmlSecurityProperties.signatureDigestAlgorithm;
        this.signatureCanonicalizationAlgorithm = xmlSecurityProperties.signatureCanonicalizationAlgorithm;
        this.signatureKey = xmlSecurityProperties.signatureKey;
        this.signatureCerts = xmlSecurityProperties.signatureCerts;
        this.addExcC14NInclusivePrefixes = xmlSecurityProperties.addExcC14NInclusivePrefixes;
        this.signatureKeyIdentifiers.addAll(xmlSecurityProperties.signatureKeyIdentifiers);
        this.useSingleCert = xmlSecurityProperties.useSingleCert;
        this.signatureVerificationKey = xmlSecurityProperties.signatureVerificationKey;
        this.signaturePosition = xmlSecurityProperties.signaturePosition;
        this.idAttributeNS = xmlSecurityProperties.idAttributeNS;
        this.signatureKeyName = xmlSecurityProperties.signatureKeyName;
        this.encryptionKeyName = xmlSecurityProperties.encryptionKeyName;
        this.keyNameMap.putAll(xmlSecurityProperties.keyNameMap);
        this.signatureGenerateIds = xmlSecurityProperties.signatureGenerateIds;
        this.signatureIncludeDigestTransform = xmlSecurityProperties.signatureIncludeDigestTransform;
        this.signaturePositionQName = xmlSecurityProperties.signaturePositionQName;
        this.signaturePositionStart = xmlSecurityProperties.signaturePositionStart;
        this.algorithmParameterSpec = xmlSecurityProperties.algorithmParameterSpec;
    }

    public boolean isSignaturePositionStart() {
        return signaturePositionStart;
    }

    public void setSignaturePositionStart(boolean signaturePositionStart) {
        this.signaturePositionStart = signaturePositionStart;
    }

    @Deprecated
    public SecurityTokenConstants.KeyIdentifier getSignatureKeyIdentifier() {
        if (signatureKeyIdentifiers.isEmpty()) {
            return null;
        }
        return signatureKeyIdentifiers.get(0);
    }

    public List<SecurityTokenConstants.KeyIdentifier> getSignatureKeyIdentifiers() {
        return new ArrayList<>(signatureKeyIdentifiers);
    }

    public void setSignatureKeyIdentifier(SecurityTokenConstants.KeyIdentifier signatureKeyIdentifier) {
        signatureKeyIdentifiers.clear();
        signatureKeyIdentifiers.add(signatureKeyIdentifier);
    }

    public void setSignatureKeyIdentifiers(List<SecurityTokenConstants.KeyIdentifier> signatureKeyIdentifiers) {
        this.signatureKeyIdentifiers.clear();
        this.signatureKeyIdentifiers.addAll(signatureKeyIdentifiers);
    }

    /**
     * returns the position of the signature. By default, the signature
     * is located at the first child of the root element
     *
     * @return The signature position
     */
    public int getSignaturePosition() {
        return signaturePosition;
    }

    /**
     * Specifies the position of the signature
     *
     * @param signaturePosition Position of the signature (by default: 0)
     */
    public void setSignaturePosition(int signaturePosition) {
        this.signaturePosition = signaturePosition;
    }

    /**
     * Return the qualified name of the ID attribute used to sign the document.
     * By default, ID is used.
     *
     * @return the qualified name of the ID attribute
     */
    public QName getIdAttributeNS() {
        return idAttributeNS;
    }

    /**
     * Sets the qualified name of the ID attribute used to sign the document.
     * @param idAttributeNS Qualified Name of the ID attribute to use
     */
    public void setIdAttributeNS(QName idAttributeNS) {
        this.idAttributeNS = idAttributeNS;
    }

    /**
     * returns the KeyIdentifierType which will be used in the secured document
     *
     * @return The KeyIdentifierType
     */
    public SecurityTokenConstants.KeyIdentifier getEncryptionKeyIdentifier() {
        return encryptionKeyIdentifier;
    }

    /**
     * Specifies the KeyIdentifierType to use in the secured document
     *
     * @param encryptionKeyIdentifier
     */
    public void setEncryptionKeyIdentifier(SecurityTokenConstants.KeyIdentifier encryptionKeyIdentifier) {
        this.encryptionKeyIdentifier = encryptionKeyIdentifier;
    }

    /**
     * Add an additional, non standard, InputProcessor to the chain
     *
     * @param inputProcessor The InputProcessor to add
     */
    public void addInputProcessor(InputProcessor inputProcessor) {
        this.inputProcessorList.add(inputProcessor);
    }

    /**
     * Returns the currently registered additional InputProcessors
     *
     * @return the List with the InputProcessors
     */
    public List<InputProcessor> getInputProcessorList() {
        return inputProcessorList;
    }

    public void setDecryptionKey(Key decryptionKey) {
        this.decryptionKey = decryptionKey;
    }

    public Key getDecryptionKey() {
        return decryptionKey;
    }

    public void setEncryptionTransportKey(Key encryptionTransportKey) {
        this.encryptionTransportKey = encryptionTransportKey;
    }

    public Key getEncryptionTransportKey() {
        return encryptionTransportKey;
    }

    public void setEncryptionKey(Key encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    public Key getEncryptionKey() {
        return encryptionKey;
    }

    /**
     * Adds a part which must be encrypted by the framework.
     * Consider using {@link #addEncryptionPartSelector(ElementSelector, SecurePartFactory, int)} instead.
     *
     * @see #addEncryptionPartSelector(ElementSelector, SecurePartFactory, int)
     */
    @SuppressWarnings("PMD.AccessorClassGeneration")
    public void addEncryptionPart(SecurePart securePart) {
        encryptionPartSelectors.add(createSecurePartSelector(securePart));
    }

    /**
     * Adds a part to be signed by the framework using given element selector, secure part factory and required number
     * of occurrences.
     * The element selector defines <i>what</i> to secure.
     * The secure part factory defines <i>how</i> to secure the element.
     * The required number of occurrences defines <i>how many</i> elements must be signed, and is verified after having
     * processed the entire document.
     * Processing will fail when the number of occurrences mismatches the required number.
     * Use {@code -1} to disable verification.
     * Use {@code 0} to verify that a secure part <i>never</i> occurs.
     *
     * @param elementSelector An element selector, which must not be {@code null}.
     * @param securePartFactory A secure part factory, which must not be {@code null}.
     * @param requiredNumOccurrences A required number of occurrences, or {@code -1} for no such requirement.
     */
    @SuppressWarnings("PMD.AccessorClassGeneration")
    public void addEncryptionPartSelector(ElementSelector elementSelector, SecurePartFactory securePartFactory, int requiredNumOccurrences) {
        encryptionPartSelectors.add(new SecurePartSelector(elementSelector, securePartFactory, requiredNumOccurrences));
    }

    /**
     * Returns the encryption parts which are actually set
     *
     * @return A List of SecurePart's
     */
    public List<SecurePartSelector> getEncryptionPartSelectors() {
        return encryptionPartSelectors;
    }

    private ElementSelector createElementSelector(SecurePart securePart) {
        if (securePart.getExternalReference() != null) {
            return DocumentElementSelector.getInstance();
        } else if (securePart.getIdToSecure() != null) {
            return new ByAttributeElementSelector(() -> getIdAttributeNS(), securePart.getIdToSecure());
        } else if (securePart.getName() != null) {
            return new ByNameElementSelector(securePart.getName());
        } else if (securePart.isSecureEntireRequest()) {
            return (element, context) -> {
                boolean selected = RootElementSelector.getInstance().select(element, context);
                if (selected) {
                    // Preserve legacy behavior for backward compatibility.
                    securePart.setName(element.getName());
                }
                return selected;
            };
        } else {
            return NoElementSelector.getInstance();
        }
    }

    private SecurePartSelector createSecurePartSelector(SecurePart securePart) {
        requireNonNull(securePart, "secure part is null");
        ElementSelector elementSelector = new ElementSelector() {

            private final ElementSelector delegate = createElementSelector(securePart);

            @Override
            public boolean select(XMLSecStartElement element, OutputProcessorChain outputProcessorChain) {
                boolean selected = delegate.select(element, outputProcessorChain);
                outputProcessorChain.getSecurityContext().put(this, selected);
                return selected;
            }

            @Override
            public String toString() {
                return delegate.toString();
            }
        };
        SecurePartFactory securePartFactory = new SecurePartFactory() {

            @Override
            public SecurePart createSecurePart(XMLSecStartElement element, OutputProcessorChain outputProcessorChain) {
                Boolean selected = outputProcessorChain.getSecurityContext().get(elementSelector);
                return Boolean.TRUE.equals(selected) ? securePart : null;
            }

            @Override
            public String toString() {
                return securePart.toString();
            }
        };
        int requiredNumOccurrences = securePart.isRequired() ? 1 : -1;
        return new SecurePartSelector(elementSelector, securePartFactory, requiredNumOccurrences);
    }

    /**
     * Returns the Encryption-Algo
     *
     * @return the Encryption-Algo as String
     */
    public String getEncryptionSymAlgorithm() {
        return encryptionSymAlgorithm;
    }

    /**
     * Specifies the encryption algorithm
     *
     * @param encryptionSymAlgorithm The algo to use for encryption
     */
    public void setEncryptionSymAlgorithm(String encryptionSymAlgorithm) {
        this.encryptionSymAlgorithm = encryptionSymAlgorithm;
    }

    /**
     * Returns the encryption key transport algorithm
     *
     * @return the key transport algorithm as string
     */
    public String getEncryptionKeyTransportAlgorithm() {
        return encryptionKeyTransportAlgorithm;
    }

    /**
     * Specifies the encryption key transport algorithm
     *
     * @param encryptionKeyTransportAlgorithm
     *         the encryption key transport algorithm as string
     */
    public void setEncryptionKeyTransportAlgorithm(String encryptionKeyTransportAlgorithm) {
        this.encryptionKeyTransportAlgorithm = encryptionKeyTransportAlgorithm;
    }

    public String getEncryptionKeyTransportDigestAlgorithm() {
        return encryptionKeyTransportDigestAlgorithm;
    }

    public void setEncryptionKeyTransportDigestAlgorithm(String encryptionKeyTransportDigestAlgorithm) {
        this.encryptionKeyTransportDigestAlgorithm = encryptionKeyTransportDigestAlgorithm;
    }

    public String getEncryptionKeyTransportMGFAlgorithm() {
        return encryptionKeyTransportMGFAlgorithm;
    }

    public void setEncryptionKeyTransportMGFAlgorithm(String encryptionKeyTransportMGFAlgorithm) {
        this.encryptionKeyTransportMGFAlgorithm = encryptionKeyTransportMGFAlgorithm;
    }

    public byte[] getEncryptionKeyTransportOAEPParams() {
        return encryptionKeyTransportOAEPParams;
    }

    public void setEncryptionKeyTransportOAEPParams(byte[] encryptionKeyTransportOAEPParams) {
        this.encryptionKeyTransportOAEPParams = encryptionKeyTransportOAEPParams;
    }

    public X509Certificate getEncryptionUseThisCertificate() {
        return encryptionUseThisCertificate;
    }

    public void setEncryptionUseThisCertificate(X509Certificate encryptionUseThisCertificate) {
        this.encryptionUseThisCertificate = encryptionUseThisCertificate;
    }

    public X509Certificate[] getSignatureCerts() {
        return signatureCerts;
    }

    public void setSignatureCerts(X509Certificate[] signatureCerts) {
        this.signatureCerts = signatureCerts;
    }

    /**
     * Adds a part to be signed by the framework.
     * Consider using {@link #addSignaturePartSelector(ElementSelector, SecurePartFactory, int)} instead.
     *
     * @see #addSignaturePartSelector(ElementSelector, SecurePartFactory, int)
     */
    @SuppressWarnings("PMD.AccessorClassGeneration")
    public void addSignaturePart(SecurePart securePart) {
        signaturePartSelectors.add(createSecurePartSelector(securePart));
    }

    /**
     * Adds a part to be signed by the framework using given element selector, secure part factory and required number
     * of occurrences.
     * The element selector defines <i>what</i> to secure.
     * The secure part factory defines <i>how</i> to secure the element.
     * The required number of occurrences defines <i>how many</i> elements must be signed, and is verified after having
     * processed the entire document.
     * Processing will fail when the number of occurrences mismatches the required number.
     * Use {@code -1} to disable verification.
     * Use {@code 0} to verify that a secure part <i>never</i> occurs.
     *
     * @param elementSelector An element selector, which must not be {@code null}.
     * @param securePartFactory A secure part factory, which must not be {@code null}.
     * @param requiredNumOccurrences A required number of occurrences, or {@code -1} for no such requirement.
     */
    public void addSignaturePartSelector(ElementSelector elementSelector, SecurePartFactory securePartFactory, int requiredNumOccurrences) {
        signaturePartSelectors.add(new SecurePartSelector(elementSelector, securePartFactory, requiredNumOccurrences));
    }

    public List<SecurePartSelector> getSignaturePartSelectors() {
        return signaturePartSelectors;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public String getSignatureDigestAlgorithm() {
        return signatureDigestAlgorithm;
    }

    public void setSignatureDigestAlgorithm(String signatureDigestAlgorithm) {
        this.signatureDigestAlgorithm = signatureDigestAlgorithm;
    }

    public void setSignatureKey(Key signatureKey) {
        this.signatureKey = signatureKey;
    }

    public Key getSignatureKey() {
        return signatureKey;
    }

    public boolean isUseSingleCert() {
        return useSingleCert;
    }

    public void setUseSingleCert(boolean useSingleCert) {
        this.useSingleCert = useSingleCert;
    }

    public boolean isAddExcC14NInclusivePrefixes() {
        return addExcC14NInclusivePrefixes;
    }

    public void setAddExcC14NInclusivePrefixes(boolean addExcC14NInclusivePrefixes) {
        this.addExcC14NInclusivePrefixes = addExcC14NInclusivePrefixes;
    }

    /**
     * Returns the actual set actions
     *
     * @return The Actions in applied order
     */
    public List<XMLSecurityConstants.Action> getActions() {
        return actions;
    }

    /**
     * Specifies how to secure the document eg. Timestamp, Signature, Encrypt
     *
     * @param actions
     */
    public void setActions(List<XMLSecurityConstants.Action> actions) {
        this.actions = actions;
    }

    public void addAction(XMLSecurityConstants.Action action) {
        if (actions == null) {
            actions = new ArrayList<>();
        }
        actions.add(action);
    }

    public String getSignatureCanonicalizationAlgorithm() {
        return signatureCanonicalizationAlgorithm;
    }

    public void setSignatureCanonicalizationAlgorithm(String signatureCanonicalizationAlgorithm) {
        this.signatureCanonicalizationAlgorithm = signatureCanonicalizationAlgorithm;
    }

    public Key getSignatureVerificationKey() {
        return signatureVerificationKey;
    }

    public void setSignatureVerificationKey(Key signatureVerificationKey) {
        this.signatureVerificationKey = signatureVerificationKey;
    }

    /**
     * Returns if the framework is skipping document-events
     *
     * @return true if document-events will be skipped, false otherwise
     */
    public boolean isSkipDocumentEvents() {
        return skipDocumentEvents;
    }

    /**
     * specifies if the framework should forward Document-Events or not
     *
     * @param skipDocumentEvents set to true when document events should be discarded, false otherwise
     */
    public void setSkipDocumentEvents(boolean skipDocumentEvents) {
        this.skipDocumentEvents = skipDocumentEvents;
    }

    public boolean isDisableSchemaValidation() {
        return disableSchemaValidation;
    }

    public void setDisableSchemaValidation(boolean disableSchemaValidation) {
        this.disableSchemaValidation = disableSchemaValidation;
    }

    public String getSignatureKeyName() {
        return signatureKeyName;
    }

    /**
     * specifies the contents of the KeyInfo/KeyName element for signing
     *
     * @param signatureKeyName set to a String that will be passed as contents of the KeyName element
     */
    public void setSignatureKeyName(String signatureKeyName) {
        this.signatureKeyName = signatureKeyName;
    }

    public String getEncryptionKeyName() {
        return encryptionKeyName;
    }

    /**
     * specifies the contents of the KeyInfo/KeyName element for encryption
     *
     * @param encryptionKeyName set to a String that will be passed as contents of the KeyName element
     */
    public void setEncryptionKeyName(String encryptionKeyName) {
        this.encryptionKeyName = encryptionKeyName;
    }

    /**
     * returns an immutable instance of the map that links KeyName values to actual keys
     *
     * @return keyNameMap set to the map containing KeyNames and Keys
     */
    public Map<String, Key> getKeyNameMap() {
        return Collections.unmodifiableMap(keyNameMap);
    }

    public void addKeyNameMapping(String keyname, Key key) {
        keyNameMap.put(keyname, key);
    }

    public boolean isSignatureGenerateIds() {
        return signatureGenerateIds;
    }

    /**
     * specifies if Id attributes should be generated for the document element, the Signature element and KeyInfo structures
     *
     * @param signatureGenerateIds set to true (default) to generate Id attributes
     */
    public void setSignatureGenerateIds(boolean signatureGenerateIds) {
        this.signatureGenerateIds = signatureGenerateIds;
    }

    public boolean isSignatureIncludeDigestTransform() {
        return signatureIncludeDigestTransform;
    }

    /**
     * specifies if the transform set with signatureDigestAlgorithm should be included in the Reference/Transforms
     * list
     * @param signatureIncludeDigestTransform set to true (default) to include the transform in the list
     */
    public void setSignatureIncludeDigestTransform(boolean signatureIncludeDigestTransform) {
        this.signatureIncludeDigestTransform = signatureIncludeDigestTransform;
    }

    public QName getSignaturePositionQName() {
        return signaturePositionQName;
    }

    public void setSignaturePositionQName(QName signaturePositionQName) {
        this.signaturePositionQName = signaturePositionQName;
    }

    public AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return algorithmParameterSpec;
    }

    public void setAlgorithmParameterSpec(AlgorithmParameterSpec algorithmParameterSpec) {
        this.algorithmParameterSpec = algorithmParameterSpec;
    }
}
