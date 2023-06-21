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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.xml.security.configuration.TransformAlgorithmType;
import org.apache.xml.security.configuration.TransformAlgorithmsType;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.utils.ClassLoaderUtils;

/**
 * Mapping between JCE id and xmlsec uri's for algorithms
 *
 */
public final class TransformerAlgorithmMapper {

    private static Map<String, Class<?>> algorithmsClassMapInOut;
    private static Map<String, Class<?>> algorithmsClassMapIn;
    private static Map<String, Class<?>> algorithmsClassMapOut;

    private TransformerAlgorithmMapper() {
    }

    protected static synchronized void init(TransformAlgorithmsType transformAlgorithms,
            Class<?> callingClass) throws Exception {
        List<TransformAlgorithmType> algorithms = transformAlgorithms.getTransformAlgorithm();
        algorithmsClassMapInOut = new HashMap<>();
        algorithmsClassMapIn = new HashMap<>();
        algorithmsClassMapOut = new HashMap<>();

        for (int i = 0; i < algorithms.size(); i++) {
            TransformAlgorithmType algorithmType = algorithms.get(i);
            if (algorithmType.getINOUT() == null) {
                algorithmsClassMapInOut.put(algorithmType.getURI(),
                        ClassLoaderUtils.loadClass(algorithmType.getJAVACLASS(), callingClass));
            } else if ("IN".equals(algorithmType.getINOUT().value())) {
                algorithmsClassMapIn.put(algorithmType.getURI(),
                        ClassLoaderUtils.loadClass(algorithmType.getJAVACLASS(), callingClass));
            } else if ("OUT".equals(algorithmType.getINOUT().value())) {
                algorithmsClassMapOut.put(algorithmType.getURI(),
                        ClassLoaderUtils.loadClass(algorithmType.getJAVACLASS(), callingClass));
            } else {
                throw new IllegalArgumentException("INOUT parameter " + algorithmType.getINOUT().value() + " unsupported");
            }
        }
    }

    public static Class<?> getTransformerClass(String algoURI, XMLSecurityConstants.DIRECTION direction) throws XMLSecurityException {
        Class<?> clazz = null;

        if (XMLSecurityConstants.DIRECTION.IN == direction) {
            clazz = algorithmsClassMapIn.get(algoURI);
        } else if (XMLSecurityConstants.DIRECTION.OUT == direction) {
            clazz = algorithmsClassMapOut.get(algoURI);
        }

        if (clazz == null) {
            clazz = algorithmsClassMapInOut.get(algoURI);
        }
        if (clazz == null) {
            throw new XMLSecurityException("signature.Transform.UnknownTransform",
                                           new Object[] {algoURI});
        }
        return clazz;
    }
}
