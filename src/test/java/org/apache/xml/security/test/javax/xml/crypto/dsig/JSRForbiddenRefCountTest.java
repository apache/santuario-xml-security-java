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

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMCryptoContext;

import org.apache.jcp.xml.dsig.internal.dom.DOMSignedInfo;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This is a test for a forbidden number of references when secure validation is enabled.
 */
class JSRForbiddenRefCountTest {

    static {
        Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    @Test
    void testReferenceCount() throws Exception {
        Element signedInfoElement =
            getSignedInfoElement("src/test/resources/interop/c14n/Y4", "signature-manifest.xml");

        InternalDOMCryptoContext context = new InternalDOMCryptoContext();

        try {
            new DOMSignedInfo(signedInfoElement, context, null);
        } catch (MarshalException ex) {
            String error =
                "A maximum of 30 references per Manifest are allowed with secure validation";
            assertTrue(ex.getMessage().contains(error));
        }

        context.setProperty("org.apache.jcp.xml.dsig.secureValidation", Boolean.FALSE);
        new DOMSignedInfo(signedInfoElement, context, null);
    }

    private static class InternalDOMCryptoContext extends DOMCryptoContext {
        //
    }

    private Element getSignedInfoElement(String directory, String file) throws Exception {
        File f = new File(XmlSecTestEnvironment.resolveFile(directory), file);
        org.w3c.dom.Document doc = XMLUtils.read(f, false);
        return (Element) doc.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNEDINFO).item(0);
    }

}
