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
package javax.xml.crypto.test.dsig;

import java.io.*;
import java.security.Security;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.*;

import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.*;

import javax.xml.crypto.test.KeySelectors;

public class SecureXSLTTest extends org.junit.Assert {

    static {
        Security.insertProviderAt
            (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
    }

    @org.junit.Test
    public void testSignature1() throws Exception {

        String fs = System.getProperty("file.separator");
        String base = System.getProperty("basedir") == null ? "./": System.getProperty("basedir");

        File baseDir = new File(base + fs + "src/test/resources"
            + fs + "javax" + fs + "xml" + fs + "crypto", "dsig");

        testSignature(new File(baseDir, "signature1.xml"));
    }

    public void testSignature2() throws Exception {

        String fs = System.getProperty("file.separator");
        String base = System.getProperty("basedir") == null ? "./": System.getProperty("basedir");

        File baseDir = new File(base + fs + "src/test/resources"
            + fs + "javax" + fs + "xml" + fs + "crypto", "dsig");

        testSignature(new File(baseDir, "signature2.xml"));
    }

    public void testSignature3() throws Exception {

        String fs = System.getProperty("file.separator");
        String base = System.getProperty("basedir") == null ? "./": System.getProperty("basedir");

        File baseDir = new File(base + fs + "src/test/resources"
            + fs + "javax" + fs + "xml" + fs + "crypto", "dsig");

        testSignature(new File(baseDir, "signature3.xml"));
    }

    private void testSignature(File signatureFile) throws Exception {

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        File f = new File("doc.xml");

        Document doc =
            XMLUtils.createDocumentBuilder(false).parse(new FileInputStream(signatureFile));

        NodeList nl =
            doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("Cannot find Signature element");
        }

        DOMValidateContext valContext = new DOMValidateContext
            (new KeySelectors.KeyValueKeySelector(), nl.item(0));
        // enable reference caching in your validation context
        valContext.setProperty("javax.xml.crypto.dsig.cacheReference", Boolean.TRUE);

        try {
            XMLSignature sig = fac.unmarshalXMLSignature(valContext);
            assertFalse(sig.validate(valContext));
            sig.getSignedInfo().getReferences().get(0);
        } finally {
            if (f.exists()) {
                f.delete(); // cleanup file. comment out when debugging
                throw new Exception("Test FAILED: doc.xml was successfully created");
            }
        }
    }
}
