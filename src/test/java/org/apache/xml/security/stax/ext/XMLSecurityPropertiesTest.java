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

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.xml.security.stax.ext.SecurePart.Modifier;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.OutboundSecurityContextImpl;
import org.apache.xml.security.stax.impl.OutputProcessorChainImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecAttributeImpl;
import org.apache.xml.security.stax.impl.stax.XMLSecStartElementImpl;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;

public class XMLSecurityPropertiesTest {

    @Test
    public void testDefaultValues() {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        assertThat(properties.getEncryptionPartSelectors(), is(empty()));
        assertThat(properties.getSignaturePartSelectors(), is(empty()));
    }

    @Test
    public void testAddEncryptionPart() {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        QName name = new QName("tag");
        SecurePart encryptionPart = new SecurePart(name, Modifier.Element);
        properties.addEncryptionPart(encryptionPart);
        List<SecurePartSelector> selectors = properties.getEncryptionPartSelectors();
        assertThat(selectors, hasSize(1));
        SecurePartSelector selector = selectors.get(0);
        XMLSecStartElement element = new XMLSecStartElementImpl(name, null, null);
        OutboundSecurityContext securityContext = new OutboundSecurityContextImpl(properties);
        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(securityContext);
        assertThat(selector.select(element, outputProcessorChain), is(sameInstance(encryptionPart)));
    }

    @Test
    public void testAddSignaturePart() {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        QName name = new QName("tag");
        SecurePart signaturePart = new SecurePart(name, Modifier.Element);
        properties.addSignaturePart(signaturePart);
        List<SecurePartSelector> selectors = properties.getSignaturePartSelectors();
        assertThat(selectors, hasSize(1));
        SecurePartSelector selector = selectors.get(0);
        XMLSecStartElement element = new XMLSecStartElementImpl(name, null, null);
        OutboundSecurityContext securityContext = new OutboundSecurityContextImpl(properties);
        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(securityContext);
        assertThat(selector.select(element, outputProcessorChain), is(sameInstance(signaturePart)));
    }

    @Test
    public void testElementSelectionBasedOnAttributeIdThatIsSetAfterwards() {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        SecurePart encryptionPart = new SecurePart(Modifier.Element);
        String idAttributeValue = "myIdAttributeValue";
        encryptionPart.setIdToSecure(idAttributeValue);
        properties.addEncryptionPart(encryptionPart);
        QName idAttributeName = new QName("myIdAttributeName");
        properties.setIdAttributeNS(idAttributeName);
        SecurePartSelector securePartSelector = properties.getEncryptionPartSelectors().get(0);
        Collection<XMLSecAttribute> attributes = Collections.singletonList(new XMLSecAttributeImpl(idAttributeName, idAttributeValue));
        XMLSecStartElement element = new XMLSecStartElementImpl(new QName("myElement"), attributes, null);
        OutboundSecurityContext securityContext = new OutboundSecurityContextImpl(properties);
        OutputProcessorChain outputProcessorChain = new OutputProcessorChainImpl(securityContext);
        assertThat(securePartSelector.select(element, outputProcessorChain), is(equalTo(encryptionPart)));
    }
}