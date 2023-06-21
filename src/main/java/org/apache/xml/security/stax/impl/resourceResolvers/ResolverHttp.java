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
package org.apache.xml.security.stax.impl.resourceResolvers;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.regex.Pattern;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.ResourceResolver;
import org.apache.xml.security.stax.ext.ResourceResolverLookup;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

/**
 * Resolver for external http[s] resources.
 *
 */
public class ResolverHttp implements ResourceResolver, ResourceResolverLookup {

    private static Proxy proxy;

    private String uri;
    private String baseURI;
    private Pattern pattern = Pattern.compile("^http[s]?://.*");

    public ResolverHttp() {
    }

    public ResolverHttp(String uri, String baseURI) {
        this.uri = uri;
        this.baseURI = baseURI;
    }

    public static void setProxy(Proxy proxy) {
        ResolverHttp.proxy = proxy;
    }

    @Override
    public ResourceResolverLookup canResolve(String uri, String baseURI) {
        if (uri == null) {
            return null;
        }
        if (pattern.matcher(uri).matches() || baseURI != null && pattern.matcher(baseURI).matches()) {
            return this;
        }
        return null;
    }

    @Override
    public ResourceResolver newInstance(String uri, String baseURI) {
        return new ResolverHttp(uri, baseURI);
    }

    @Override
    public boolean isSameDocumentReference() {
        return false;
    }

    @Override
    public boolean matches(XMLSecStartElement xmlSecStartElement) {
        return false;
    }

    @Override
    public InputStream getInputStreamFromExternalReference() throws XMLSecurityException {
        try {
            URI tmp;
            if (baseURI == null || baseURI.length() == 0) {
                tmp = new URI(uri);
            } else {
                tmp = new URI(baseURI).resolve(uri);
            }

            if (tmp.getFragment() != null) {
                tmp = new URI(tmp.getScheme(), tmp.getSchemeSpecificPart(), null);
            }
            URL url = tmp.toURL();
            HttpURLConnection urlConnection;
            if (proxy != null) {
                urlConnection = (HttpURLConnection)url.openConnection(proxy);
            } else {
                urlConnection = (HttpURLConnection)url.openConnection();
            }
            return urlConnection.getInputStream();
        } catch (URISyntaxException | IOException e) {
            throw new XMLSecurityException(e);
        }
    }
}
