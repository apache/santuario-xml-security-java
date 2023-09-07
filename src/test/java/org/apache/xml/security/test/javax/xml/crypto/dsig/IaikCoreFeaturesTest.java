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
/*
 * Copyright 2005 Sun Microsystems, Inc. All rights reserved.
 */
package org.apache.xml.security.test.javax.xml.crypto.dsig;


import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.security.Security;

import javax.xml.crypto.Data;
import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignatureFactory;

import org.apache.xml.security.test.XmlSecTestEnvironment;
import org.apache.xml.security.test.javax.xml.crypto.KeySelectors;
import org.apache.xml.security.utils.resolver.ResourceResolver;
import org.apache.xml.security.utils.resolver.implementations.ResolverLocalFilesystem;
import org.junit.jupiter.api.Test;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.apache.xml.security.test.XmlSecTestEnvironment.resolvePath;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This is a testcase to validate all "coreFeatures"
 * testcases from IAIK
 *
 */
class IaikCoreFeaturesTest {

    private final SignatureValidator validator;
    private final Path base;

    static {
        Security.insertProviderAt
            (new org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI(), 1);
        ResourceResolver.register(new ResolverLocalFilesystem(), false);
    }

    public IaikCoreFeaturesTest() {
        base = resolvePath("src", "test", "resources", "at", "iaik", "ixsil");
        validator = new SignatureValidator(resolvePath(base, "coreFeatures", "signatures").toFile());
    }

    @Test
    void test_anonymousReferenceSignature() throws Exception {
        String file = "anonymousReferenceSignature.xml";

        boolean coreValidity = validator.validate(file, new KeySelectors.KeyValueKeySelector(),
            new NullURIDereferencer(base));
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_manifestSignature() throws Exception {
        String file = "manifestSignature.xml";

        boolean coreValidity = validator.validate
            (file, new KeySelectors.KeyValueKeySelector());
        assertTrue(coreValidity, "Signature failed core validation");
    }

    @Test
    void test_signatureTypesSignature() throws Exception {
        String file = "signatureTypesSignature.xml";

        boolean coreValidity = validator.validate
            (file, new KeySelectors.KeyValueKeySelector(),
                    new OfflineDereferencer(), false);
        assertTrue(coreValidity, "Signature failed core validation");
    }

    private static class NullURIDereferencer implements URIDereferencer {

        private final OctetStreamData osd;

        NullURIDereferencer(Path base) throws Exception {
            File content = resolveFile(base, "coreFeatures", "samples", "anonymousReferenceContent.xml");
            osd = new OctetStreamData(new FileInputStream(content));
        }

        @Override
        public Data dereference(URIReference uriReference,
            XMLCryptoContext context) throws URIReferenceException {

            if (uriReference.getURI() != null) {
                throw new URIReferenceException("must be a null URI");
            }

            return osd;
        }
    }

    private static class OfflineDereferencer implements URIDereferencer {
        private final File w3cRec;
        private final URIDereferencer defaultDereferencer;

        OfflineDereferencer() throws Exception {
            w3cRec = XmlSecTestEnvironment.resolveFile("src", "test", "resources", "org", "w3c", "www", "TR", "2000");
            defaultDereferencer = XMLSignatureFactory.getInstance().getURIDereferencer();
        }

        @Override
        public Data dereference(URIReference uriReference, XMLCryptoContext context) throws URIReferenceException {
            try {
                if ("http://www.w3.org/TR/2000/REC-xml-20001006".equals(uriReference.getURI())) {
                    File content = new File(w3cRec, "REC-xml-20001006");
                    return new OctetStreamData(new FileInputStream(content));
                }
                return defaultDereferencer.dereference(uriReference, context);
            } catch (java.io.FileNotFoundException ex) {
                throw new URIReferenceException(ex.getMessage(), ex);
            }
        }
    }

}