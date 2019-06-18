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
package org.apache.xml.security.test.stax;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.junit.jupiter.api.Test;
import org.apache.xml.security.stax.config.Init;
import org.apache.xml.security.stax.ext.XMLSec;
import org.apache.xml.security.stax.ext.XMLSecurityConfigurationException;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 */
public class UncategorizedTest {

    @Test
    public void testConfigurationLoadFromUrl() throws Exception {
        URL url =
            this.getClass().getClassLoader().getResource(
                "org/apache/xml/security/c14n/in/32_input.xml");
        try {
            Init.init(url.toURI(), this.getClass());
            fail();
        } catch (XMLSecurityException e) {
            assertTrue(e.getMessage().contains("Cannot find the declaration of element 'doc'."));
        }
    }

    @Test
    public void testDuplicateActions() throws Exception {
        XMLSecurityProperties properties = new XMLSecurityProperties();
        List<XMLSecurityConstants.Action> actions = new ArrayList<>();
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        // Should work
        XMLSec.getOutboundXMLSec(properties);

        // Should throw an error on a duplicate Action
        actions.add(XMLSecurityConstants.SIGNATURE);
        properties.setActions(actions);

        try {
            XMLSec.getOutboundXMLSec(properties);
            fail();
        } catch (XMLSecurityConfigurationException ex) {
            assertTrue(ex.getMessage().contains("Duplicate Actions are not allowed"));
        }
    }
}
