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
package org.apache.xml.security.test.dom.c14n.implementations;

import java.io.File;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;

import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.dom.interop.InteropTestBase;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertNull;


/**
 * Interop test for exclusive canonical XML.
 */
class ExclusiveC14NInteropTest extends InteropTestBase {

    private static final Logger LOG = System.getLogger(ExclusiveC14NInteropTest.class.getName());

    static {
        org.apache.xml.security.Init.init();
        ResourceResolver.register(new ResolverLocalFilesystem(), false);
    }

    /**
     *  Constructor ExclusiveC14NInteropTest
     */
    public ExclusiveC14NInteropTest() {
        super();
    }

    /**
     * Method test_Y1
     *
     * @throws Exception
     */
    @Test
    void test_Y1() throws Exception {

        String success = t("src/test/resources/interop/c14n/Y1", "exc-signature.xml", true);

        assertNull(success);
    }

    /**
     * Method test_Y2
     *
     * @throws Exception
     */
    @Test
    void test_Y2() throws Exception {

        String success = t("src/test/resources/interop/c14n/Y2", "signature-joseph-exc.xml", false);

        assertNull(success);
    }

    /**
     * Method test_Y3
     *
     * @throws Exception
     */
    @Test
    void test_Y3() throws Exception {

        String success = t("src/test/resources/interop/c14n/Y3", "signature.xml", false);

        assertNull(success);
    }

    /**
     * Method test_Y4
     *
     * @throws Exception
     */
    @Test
    void test_Y4() throws Exception {

        String success = t("src/test/resources/interop/c14n/Y4", "signature.xml", true);

        assertNull(success);
    }

    @Test
    void test_xfilter2() throws Exception {

        String success = t("src/test/resources/interop/xfilter2/merlin-xpath-filter2-three", "sign-spec.xml", true);

        assertNull(success);
    }

    private String t(String directory, String file, boolean secureValidation) throws Exception {
        File f = XmlSecTestEnvironment.resolveFile(directory, file);
        org.w3c.dom.Document doc = XMLUtils.read(f, false);

        Element sigElement = (Element) doc.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATURE)
            .item(0);
        XMLSignature signature = new XMLSignature(sigElement, f.toURI().toURL().toString(), secureValidation);
        boolean verify = signature.checkSignatureValue(signature.getKeyInfo().getPublicKey());

        LOG.log(Level.DEBUG, "   signature.checkSignatureValue finished: {0}", verify);

        // if (!verify) {
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < signature.getSignedInfo().getLength(); i++) {
            boolean refVerify =
                signature.getSignedInfo().getVerificationResult(i);
            //JavaUtils.writeBytesToFilename(directory + "/c14n-" + i + ".apache.html", signature.getSignedInfo().item(i).getHTMLRepresentation().getBytes());

            if (refVerify) {
                LOG.log(Level.DEBUG, "Reference " + i + " was OK");
            } else {
                sb.append(i);
                sb.append(' ');

                //JavaUtils.writeBytesToFilename(directory + "/c14n-" + i + ".apache.txt", signature.getSignedInfo().item(i).getContentsAfterTransformation().getBytes());
                //JavaUtils.writeBytesToFilename(directory + "/c14n-" + i + ".apache.html", signature.getSignedInfo().item(i).getHTMLRepresentation().getBytes());

                Reference reference = signature.getSignedInfo().item(i);
                int length = reference.getTransforms().getLength();
                String algo = reference.getTransforms().item(length - 1).getURI();

                LOG.log(Level.DEBUG, "Reference " + i + " failed: " + algo);
            }
        }

        String r = sb.toString().trim();
        return r.isEmpty() ? null : r;
    }

}