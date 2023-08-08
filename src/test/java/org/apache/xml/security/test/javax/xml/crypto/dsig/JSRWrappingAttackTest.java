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

import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;


/**
 * This is a test for a wrapping attack.
 */
class JSRWrappingAttackTest {

    private final SignatureValidator validator;
    private final File dir;

    static {
        Security.insertProviderAt(new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    public JSRWrappingAttackTest() {
        dir = resolveFile("src", "test", "resources", "at", "iaik", "ixsil", "coreFeatures", "signatures");
        validator = new SignatureValidator(dir);
    }


    @Test
    void testWrappingAttack() throws Exception {
        String file = "manifestSignatureWrapping.xml";
        Document doc = XMLUtils.read(new File(dir, file), false);
        Element sigElement = SignatureValidator.getSignatureElement(doc);
        if (sigElement == null) {
            throw new Exception("Couldn't find signature Element");
        }
        DOMValidateContext vc =
            new DOMValidateContext(new KeySelectors.KeyValueKeySelector(), sigElement);
        vc.setBaseURI(dir.toURI().toString());

        vc.setProperty("org.apache.jcp.xml.dsig.secureValidation", Boolean.FALSE);
        boolean coreValidity = validator.validate(vc);
        assertTrue(coreValidity, "Signature failed core validation");

        vc.setProperty("org.apache.jcp.xml.dsig.secureValidation", Boolean.TRUE);

        Element manifestElement =
            (Element) doc.getElementsByTagName("Manifest").item(0);
        vc.setIdAttributeNS(manifestElement, null, "Id");

        try {
            boolean valid = validator.validate(vc);
            System.out.println("Valid: " + valid);
            fail("Failure expected when secure validation is enabled");
        } catch (XMLSignatureException ex) {
            assertTrue(ex.getMessage().contains("URIReferenceException"));
        }
    }

}