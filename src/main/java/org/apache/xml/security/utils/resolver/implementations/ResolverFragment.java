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
package org.apache.xml.security.utils.resolver.implementations;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;

import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.signature.XMLSignatureNodeInput;
import org.apache.xml.security.utils.XMLUtils;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * This resolver is used for resolving same-document URIs like URI="" of URI="#id".
 *
 * @see <A HREF="http://www.w3.org/TR/xmldsig-core/#sec-ReferenceProcessingModel">The Reference processing model in the XML Signature spec</A>
 * @see <A HREF="http://www.w3.org/TR/xmldsig-core/#sec-Same-Document">Same-Document URI-References in the XML Signature spec</A>
 * @see <A HREF="http://www.ietf.org/rfc/rfc2396.txt">Section 4.2 of RFC 2396</A>
 */
public class ResolverFragment extends ResourceResolverSpi {

    private static final Logger LOG = System.getLogger(ResolverFragment.class.getName());

    /**
     * {@inheritDoc}
     */
    @Override
    public XMLSignatureInput engineResolveURI(ResourceResolverContext context)
        throws ResourceResolverException {

        Document doc = context.attr.getOwnerElement().getOwnerDocument();

        Node selectedElem = null;
        if (context.uriToResolve.isEmpty()) {
            /*
             * Identifies the node-set (minus any comment nodes) of the XML
             * resource containing the signature
             */
            LOG.log(Level.DEBUG, "ResolverFragment with empty URI (means complete document)");
            selectedElem = doc;
        } else {
            /*
             * URI="#chapter1"
             * Identifies a node-set containing the element with ID attribute
             * value 'chapter1' of the XML resource containing the signature.
             * XML Signature (and its applications) modify this node-set to
             * include the element plus all descendants including namespaces and
             * attributes -- but not comments.
             */
            String id = context.uriToResolve.substring(1);

            selectedElem = doc.getElementById(id);
            if (selectedElem == null) {
                Object[] exArgs = { id };
                throw new ResourceResolverException(
                    "signature.Verification.MissingID", exArgs, context.uriToResolve, context.baseUri
                );
            }
            if (context.secureValidation) {
                Element start = context.attr.getOwnerDocument().getDocumentElement();
                if (!XMLUtils.protectAgainstWrappingAttack(start, id)) {
                    Object[] exArgs = { id };
                    throw new ResourceResolverException(
                        "signature.Verification.MultipleIDs", exArgs, context.uriToResolve, context.baseUri
                    );
                }
            }
            LOG.log(Level.DEBUG,
                "Try to catch an Element with ID {0} and Element was {1}", id, selectedElem
            );
        }

        XMLSignatureInput result = new XMLSignatureNodeInput(selectedElem);
        result.setSecureValidation(context.secureValidation);
        result.setExcludeComments(true);
        result.setMIMEType("text/xml");
        if (context.baseUri != null && context.baseUri.length() > 0) {
            result.setSourceURI(context.baseUri.concat(context.uriToResolve));
        } else {
            result.setSourceURI(context.uriToResolve);
        }
        return result;
    }

    /**
     * Method engineCanResolve
     * {@inheritDoc}
     * @param context
     */
    @Override
    public boolean engineCanResolveURI(ResourceResolverContext context) {
        if (context.uriToResolve == null) {
            LOG.log(Level.DEBUG, "Quick fail for null uri");
            return false;
        }

        if (context.uriToResolve.isEmpty() ||
            context.uriToResolve.charAt(0) == '#' && !context.uriToResolve.startsWith("#xpointer(")
        ) {
            LOG.log(Level.DEBUG, "State I can resolve reference: \"{0}\"", context.uriToResolve);
            return true;
        }
        LOG.log(Level.DEBUG, "Do not seem to be able to resolve reference: \"{0}\"", context.uriToResolve);
        return false;
    }

}
