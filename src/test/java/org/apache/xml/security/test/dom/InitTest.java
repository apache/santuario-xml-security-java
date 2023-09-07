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
package org.apache.xml.security.test.dom;


import java.io.InputStream;

import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.algorithms.SignatureAlgorithmSpi;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.CanonicalizerSpi;
import org.apache.xml.security.keys.keyresolver.KeyResolver;
import org.apache.xml.security.keys.keyresolver.KeyResolverSpi;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.TransformSpi;
import org.apache.xml.security.utils.ClassLoaderUtils;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InitTest {

    private static final String CONFIG_FILE = "org/apache/xml/security/resource/config.xml";

    @BeforeAll
    public static void setup() {
        System.setProperty("org.apache.xml.security.resource.config", CONFIG_FILE);
    }

    @AfterAll
    public static void cleanup() {
        System.clearProperty("org.apache.xml.security.resource.config");
    }

    @Test
    void testFileInit() throws Exception {
        assertFalse(Init.isInitialized());
        Init.init();
        assertTrue(Init.isInitialized());

        // Test that initialization seems to have happened OK
        new SignatureAlgorithm(TestUtils.newDocument(), XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        assertEquals("MessageDigest", JCEMapper.getAlgorithmClassFromURI(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256));
    }

    @Test
    void checkConfigFileImplementationsExist() throws Exception {
        Document doc;
        try (InputStream is = ClassLoaderUtils.getResourceAsStream(CONFIG_FILE, InitTest.class)) {
            /* read library configuration file */
            doc = XMLUtils.read(is, true);
        }

        Node config = doc.getFirstChild();
        for (; config != null; config = config.getNextSibling()) {
            if ("Configuration".equals(config.getLocalName())) {
                break;
            }
        }

        for (Node el = config.getFirstChild(); el != null; el = el.getNextSibling()) {
            if (Node.ELEMENT_NODE != el.getNodeType()) {
                continue;
            }
            String tag = el.getLocalName();

            if ("CanonicalizationMethods".equals(tag)) {
                Element[] list =
                    XMLUtils.selectNodes(el.getFirstChild(), Init.CONF_NS, "CanonicalizationMethod");

                for (Element element : list) {
                    String javaClass =
                        element.getAttributeNS(null, "JAVACLASS");

                    Class<? extends CanonicalizerSpi> clazz =
                        (Class<? extends CanonicalizerSpi>)
                        ClassLoaderUtils.loadClass(javaClass, Canonicalizer.class);
                    assertNotNull(clazz);
                }
            }

            if ("TransformAlgorithms".equals(tag)) {
                Element[] tranElem =
                    XMLUtils.selectNodes(el.getFirstChild(), Init.CONF_NS, "TransformAlgorithm");

                for (Element element : tranElem) {
                    String javaClass =
                        element.getAttributeNS(null, "JAVACLASS");

                    Class<? extends TransformSpi> transformSpiClass =
                        (Class<? extends TransformSpi>)
                        ClassLoaderUtils.loadClass(javaClass, Transform.class);
                    assertNotNull(transformSpiClass);
                }
            }

            if ("SignatureAlgorithms".equals(tag)) {
                Element[] sigElems =
                    XMLUtils.selectNodes(el.getFirstChild(), Init.CONF_NS, "SignatureAlgorithm");

                for (Element sigElem : sigElems) {
                    String javaClass =
                        sigElem.getAttributeNS(null, "JAVACLASS");

                    Class<? extends SignatureAlgorithmSpi> clazz =
                        (Class<? extends SignatureAlgorithmSpi>)
                        ClassLoaderUtils.loadClass(javaClass, SignatureAlgorithm.class);
                    assertNotNull(clazz);
                }
            }

            if ("ResourceResolvers".equals(tag)) {
                Element[] resolverElem =
                    XMLUtils.selectNodes(el.getFirstChild(), Init.CONF_NS, "Resolver");
                for (Element element : resolverElem) {
                    String javaClass =
                        element.getAttributeNS(null, "JAVACLASS");
                    ResourceResolverSpi resourceResolverSpi = (ResourceResolverSpi) ClassLoaderUtils
                        .loadClass(javaClass, ResourceResolver.class).getDeclaredConstructor().newInstance();
                    assertNotNull(resourceResolverSpi);
                }
            }

            if ("KeyResolver".equals(tag)){
                Element[] resolverElem =
                    XMLUtils.selectNodes(el.getFirstChild(), Init.CONF_NS, "Resolver");
                for (Element element : resolverElem) {
                    String javaClass =
                        element.getAttributeNS(null, "JAVACLASS");
                    KeyResolverSpi keyResolverSpi = (KeyResolverSpi) ClassLoaderUtils
                        .loadClass(javaClass, KeyResolver.class).getDeclaredConstructor().newInstance();
                    assertNotNull(keyResolverSpi);
                }
            }
        }
    }
}
