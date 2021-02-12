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

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import javax.xml.namespace.QName;

/**
 * Class to describe which and how an element must be secured.
 * The "which" is deprecated in favor of a dedicated and more flexible {@link ElementSelector}, and is only supported
 * for backward compatibility.
 * The "how" is the sole and dedicated purpose of this class.
 */
public class SecurePart {

    public enum Modifier {
        Element("http://www.w3.org/2001/04/xmlenc#Element"),
        Content("http://www.w3.org/2001/04/xmlenc#Content");

        private final String modifier;

        Modifier(String modifier) {
            this.modifier = modifier;
        }

        public String getModifier() {
            return this.modifier;
        }

        private static final Map<String, Modifier> modifierMap = new HashMap<>();

        static {
            for (Modifier modifier : EnumSet.allOf(Modifier.class)) {
                modifierMap.put(modifier.getModifier(), modifier);
            }
        }

        public static Modifier getModifier(String modifier) {
            return modifierMap.get(modifier);
        }
    }

    private QName name;
    private boolean generateXPointer;
    private Modifier modifier;
    private String idToSecure;
    private String externalReference;
    private String[] transforms;
    private String digestMethod;
    private boolean required = true;
    private boolean secureEntireRequest;

    public SecurePart(Modifier modifier) {
        this(null, false, modifier);
    }

    public SecurePart(QName name, Modifier modifier) {
        this(name, false, modifier);
    }

    public SecurePart(QName name, Modifier modifier, String[] transforms, String digestMethod) {
        this(name, false, modifier, transforms, digestMethod);
    }

    public SecurePart(QName name, boolean generateXPointer, Modifier modifier) {
        this.name = name;
        this.generateXPointer = generateXPointer;
        this.modifier = modifier;
    }

    public SecurePart(QName name, boolean generateXPointer, Modifier modifier, String[] transforms, String digestMethod) {
        this.name = name;
        this.generateXPointer = generateXPointer;
        this.modifier = modifier;
        this.transforms = transforms;
        this.digestMethod = digestMethod;
    }

    public SecurePart(String externalReference) {
        this.externalReference = externalReference;
    }

    public SecurePart(String externalReference, Modifier modifier) {
        this.externalReference = externalReference;
        this.modifier = modifier;
    }

    public SecurePart(String externalReference, String[] transforms, String digestMethod) {
        this.externalReference = externalReference;
        this.transforms = transforms;
        this.digestMethod = digestMethod;
    }

    /**
     * The name of the element to be secured.
     *
     * @return The Element-Local-Name
     */
    public QName getName() {
        return name;
    }

    /**
     * Sets which element to secure based on a given qualified name.
     * Consider using {@link ByNameElementSelector} instead.
     */
    public void setName(QName name) {
        this.name = name;
    }

    public Modifier getModifier() {
        return modifier;
    }

    /**
     * Sets the modifier of the part to secure, either the whole element or only its content.
     * Consider using a lambda expression for a secure part factory instead:
     * <pre>
     * {@code
     * SecurePartFactory securePartFactory = (element, context) -> new SecurePart(element.getName(), modifier);
     * }
     * </pre>
     *
     * @param modifier The modifier, which may be {@code null}.
     */
    public void setModifier(Modifier modifier) {
        this.modifier = modifier;
    }

    /**
     * The ID of the element to secure (encrypt or sign), possibly {@code null}.
     * This matches the attribute value of an element that has an attribute with a name given by
     * {@link XMLSecurityProperties#getIdAttributeNS()}.
     *
     * @return The ID of the element to secure, possibly {@code null}.
     */
    public String getIdToSecure() {
        return idToSecure;
    }

    /**
     * Sets which element to secure based on a given attribute value.
     * Consider using {@link ByAttributeElementSelector} instead.
     */
    public void setIdToSecure(String idToSecure) {
        this.idToSecure = idToSecure;
    }

    /**
     * Use {@link #getIdToSecure()} instead.
     */
    @Deprecated
    public String getIdToSign() {
        return getIdToSecure();
    }

    /**
     * Use {@link #setIdToSecure(String)} instead.
     * @param idToSign
     */
    @Deprecated
    public void setIdToSign(String idToSign) {
        setIdToSecure(idToSign);
    }

    public boolean isGenerateXPointer() {
        return generateXPointer;
    }

    public void setGenerateXPointer(boolean generateXPointer) {
        this.generateXPointer = generateXPointer;
    }

    public String getExternalReference() {
        return externalReference;
    }

    public void setExternalReference(String externalReference) {
        this.externalReference = externalReference;
    }

    public String[] getTransforms() {
        return transforms;
    }

    public void setTransforms(String[] transforms) {
        this.transforms = transforms;
    }

    public String getDigestMethod() {
        return digestMethod;
    }

    public void setDigestMethod(String digestMethod) {
        this.digestMethod = digestMethod;
    }

    /**
     * If this secure part is required or not.
     */
    public boolean isRequired() {
        return required;
    }

    /**
     * Sets if this element is required, which is {@code true} by default.
     * Consider using {@link XMLSecurityProperties#addEncryptionPartSelector(ElementSelector, SecurePartFactory, int)}
     * instead, with a required number of occurrences of {@code 1} (required) or {@code -1} (not required).
     */
    public void setRequired(boolean required) {
        this.required = required;
    }

    /**
     * If the entire request is to be secured.
     */
    public boolean isSecureEntireRequest() {
        return secureEntireRequest;
    }

    /**
     * Sets if the entire request is to be secured.
     * Setting this to {@code true} is equivalent to selecting the root element.
     * Consider using {@link RootElementSelector} instead.
     */
    public void setSecureEntireRequest(boolean secureEntireRequest) {
        this.secureEntireRequest = secureEntireRequest;
    }

    @Override
    public String toString() {
        if (idToSecure != null) {
            return idToSecure;
        } else if (name != null) {
            return name.toString();
        } else if (externalReference != null) {
            return externalReference;
        }
        return super.toString();
    }
}
