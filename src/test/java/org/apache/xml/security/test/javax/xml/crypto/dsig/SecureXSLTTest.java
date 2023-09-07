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
package org.apache.xml.security.test.javax.xml.crypto.dsig;

import java.io.File;
import java.security.Security;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertFalse;


class SecureXSLTTest {

    private static final File BASEDIR = resolveFile("src", "test", "resources", "org", "apache", "xml", "security",
        "test", "javax", "xml", "crypto", "dsig");

    static {
        Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    @Test
    void testSignature1() throws Exception {
        testSignature(new File(BASEDIR, "signature1.xml"));
    }

    @Test
    void testSignature2() throws Exception {
        testSignature(new File(BASEDIR, "signature2.xml"));
    }

    @Test
    void testSignature3() throws Exception {
        testSignature(new File(BASEDIR, "signature3.xml"));
    }

    private void testSignature(File signatureFile) throws Exception {

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
        Document doc = XMLUtils.read(signatureFile, false);

        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("Cannot find Signature element");
        }

        DOMValidateContext valContext = new DOMValidateContext(new KeySelectors.KeyValueKeySelector(), nl.item(0));
        // enable reference caching in your validation context
        valContext.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);

        XMLSignature sig = fac.unmarshalXMLSignature(valContext);
        assertFalse(sig.validate(valContext));
        sig.getSignedInfo().getReferences().get(0);
    }
}