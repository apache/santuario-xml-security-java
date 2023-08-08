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
package org.apache.xml.security.test.dom.keys.keyresolver;

import java.security.Security;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;


/**
 * Some tests on attacks against the RetrievalMethodResolver.
 */
class RetrievalMethodResolverTest {

    public RetrievalMethodResolverTest() {
        org.apache.xml.security.Init.init();
        Security.insertProviderAt(new XMLDSigRI(), 1);
    }

    @Test
    void testReferenceToSameRetrievalMethod() throws Exception {
        String filename = "src/test/resources/org/apache/xml/security/keyresolver/retrievalmethod1.xml";
        Document doc = XMLUtils.read(resolveFile(filename), false);
        KeyInfo keyInfo = new KeyInfo(doc.getDocumentElement(), null);

        // Check neither of these give a StackOverflowError.
        keyInfo.getPublicKey();
        keyInfo.getX509Certificate();
    }

    @Test
    void testLoopBetweenRetrievalMethods() throws Exception {
        String filename = "src/test/resources/org/apache/xml/security/keyresolver/retrievalmethod2.xml";
        Document doc = XMLUtils.read(resolveFile(filename), false);
        KeyInfo keyInfo = new KeyInfo(doc.getDocumentElement(), null);

        // Check neither of these give a StackOverflowError.
        keyInfo.getPublicKey();
        keyInfo.getX509Certificate();
    }

}
