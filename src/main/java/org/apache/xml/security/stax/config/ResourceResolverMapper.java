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
package org.apache.xml.security.stax.config;

import java.util.ArrayList;
import java.util.List;

import org.apache.xml.security.configuration.ResolverType;
import org.apache.xml.security.configuration.ResourceResolversType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.ResourceResolver;
import org.apache.xml.security.stax.ext.ResourceResolverLookup;
import org.apache.xml.security.utils.ClassLoaderUtils;
import org.apache.xml.security.utils.JavaUtils;

/**
 */
public final class ResourceResolverMapper {

    private static List<ResourceResolverLookup> resourceResolvers;

    private ResourceResolverMapper() {
    }

    protected static synchronized void init(ResourceResolversType resourceResolversType,
            Class<?> callingClass) throws Exception {
        List<ResolverType> handlerList = resourceResolversType.getResolver();
        resourceResolvers = new ArrayList<>(handlerList.size() + 1);
        for (int i = 0; i < handlerList.size(); i++) {
            ResolverType uriResolverType = handlerList.get(i);
            resourceResolvers.add((ResourceResolverLookup)
                    JavaUtils.newInstanceWithEmptyConstructor(ClassLoaderUtils.loadClass(uriResolverType.getJAVACLASS(), callingClass)));
        }
    }

    public static ResourceResolver getResourceResolver(String uri, String baseURI) throws XMLSecurityException {
        for (ResourceResolverLookup resourceResolver : resourceResolvers) {
            ResourceResolverLookup rr = resourceResolver.canResolve(uri, baseURI);
            if (rr != null) {
                return rr.newInstance(uri, baseURI);
            }
        }
        throw new XMLSecurityException("utils.resolver.noClass", new Object[]{uri, baseURI});
    }
}
