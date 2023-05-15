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
import java.io.FileInputStream;
import java.util.HashMap;
import java.util.Map;

import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;

/**
 * This URIDereferencer implementation retrieves http references used in
 * test signatures from local disk in order to avoid network requests.
 */
public class LocalHttpCacheURIDereferencer implements URIDereferencer {

    private static final File DIR = resolveFile("src", "test", "resources", "org", "apache", "xml", "security", "test",
        "javax", "xml", "crypto", "dsig");

    private final URIDereferencer ud;
    private final Map<String, File> uriMap;

    public LocalHttpCacheURIDereferencer() {
        XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM",
            new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI());
        ud = xmlSignatureFactory.getURIDereferencer();
        uriMap = new HashMap<>();
        uriMap.put("http://www.w3.org/TR/xml-stylesheet", getExistingFile("xml-stylesheet"));
        uriMap.put("http://www.w3.org/Signature/2002/04/xml-stylesheet.b64", getExistingFile("xml-stylesheet.b64"));
        uriMap.put("http://www.ietf.org/rfc/rfc3161.txt", getExistingFile("rfc3161.txt"));
    }

    @Override
    public Data dereference(URIReference uriReference, XMLCryptoContext context)
        throws URIReferenceException {
        String uri = uriReference.getURI();
        if (uriMap.containsKey(uri)) {
            try {
                return new OctetStreamData(new FileInputStream(uriMap.get(uri)), uriReference.getURI(),
                    uriReference.getType());
            } catch (Exception e) {
                throw new URIReferenceException(e);
            }
        }

        // fallback on builtin deref
        return ud.dereference(uriReference, context);
    }


    private File getExistingFile(String fileName) {
        File file = new File(DIR, fileName);
        if (file.canRead()) {
            return file;
        }
        throw new IllegalArgumentException("The file cannot be read: " + file);
    }
}
