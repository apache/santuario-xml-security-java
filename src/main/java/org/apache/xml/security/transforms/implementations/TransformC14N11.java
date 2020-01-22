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
package org.apache.xml.security.transforms.implementations;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.implementations.Canonicalizer11_OmitComments;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.TransformSpi;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Element;

/**
 * Implements the <CODE>http://www.w3.org/2006/12/xml-c14n11</CODE>
 * (C14N 1.1) transform.
 *
 */
public class TransformC14N11 extends TransformSpi {

    /**
     * {@inheritDoc}
     */
    @Override
    protected String engineGetURI() {
        return Transforms.TRANSFORM_C14N11_OMIT_COMMENTS;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected XMLSignatureInput enginePerformTransform(
        XMLSignatureInput input, OutputStream os, Element transformElement,
        String baseURI, boolean secureValidation
    ) throws CanonicalizationException {

        Canonicalizer11_OmitComments c14n = new Canonicalizer11_OmitComments();
        c14n.setSecureValidation(secureValidation);

        if (os == null) {
            try (ByteArrayOutputStream writer = new ByteArrayOutputStream()) {
                c14n.engineCanonicalize(input, writer);
                writer.flush();
                XMLSignatureInput output = new XMLSignatureInput(writer.toByteArray());
                output.setSecureValidation(secureValidation);
                return output;
            } catch (IOException ex) {
                throw new CanonicalizationException("empty", new Object[] {ex.getMessage()});
            }
        } else {
            c14n.engineCanonicalize(input, os);
            XMLSignatureInput output = new XMLSignatureInput((byte[])null);
            output.setSecureValidation(secureValidation);
            output.setOutputStream(os);
            return output;
        }
    }
}
