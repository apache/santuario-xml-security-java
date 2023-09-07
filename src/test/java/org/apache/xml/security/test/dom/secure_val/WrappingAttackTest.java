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
package org.apache.xml.security.test.dom.secure_val;


import java.io.File;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.test.dom.interop.InteropTestBase;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;



/**
 * This is a test for a wrapping attack.
 */
class WrappingAttackTest extends InteropTestBase {

    static {
        org.apache.xml.security.Init.init();
    }

    @Test
    void testWrappingAttack() throws Exception {
        boolean success = readAndVerifySignature("manifestSignatureWrapping.xml");
        assertTrue(success);
        try {
            readAndVerifySignatureAndSetManifest("manifestSignatureWrapping.xml");
            fail("Failure expected when secure validation is enabled");
        } catch (XMLSignatureException ex) {
            assertTrue(ex.getMessage().contains("no XMLSignatureInput"));
        }
    }


    private boolean readAndVerifySignature(String file) throws Exception {
        File f = resolveFile("src", "test", "resources", "at", "iaik", "ixsil", "coreFeatures", "signatures", file);
        org.w3c.dom.Document doc = XMLUtils.read(f, false);

        Element sigElement = (Element) doc.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATURE)
            .item(0);
        XMLSignature signature = new XMLSignature(sigElement, f.toURI().toURL().toString());
        return signature.checkSignatureValue(signature.getKeyInfo().getPublicKey());
    }


    private boolean readAndVerifySignatureAndSetManifest(String file) throws Exception {
        File f = resolveFile("src", "test", "resources", "at", "iaik", "ixsil", "coreFeatures", "signatures", file);

        org.w3c.dom.Document doc = XMLUtils.read(f, false);

        Element sigElement = (Element) doc.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATURE)
            .item(0);

        Element manifestElement = (Element) doc.getElementsByTagName("Manifest").item(0);
        manifestElement.setIdAttribute("Id", true);

        XMLSignature signature = new XMLSignature(sigElement, f.toURI().toURL().toString(), true);
        return signature.checkSignatureValue(signature.getKeyInfo().getPublicKey());
    }

}