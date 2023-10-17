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
package org.apache.xml.security.testutils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;


/**
 * The class provides testing utility methods to test XMLSEC functionality with various JDK version. Where possible
 * we use JDK provided algorithm implementations. However, some algorithms are not supported in lower JDK versions. For example
 * XDH keys were supported from JDK 11, EdDSA keys from JDK 16, etc. To ensure tests are executed for various JDK versions,
 * we need to know which algorithms are supported from particular JDK version.
 *
 * If the JDK security providers do not support algorithm, the class provides auxiliary security provider (BouncyCastle) to the test
 * xmlsec functionality ...
 *
 */
public class JDKTestUtils {


    private static final Provider auxiliaryProvider = new BouncyCastleProvider();

    private static Map<String, Integer> javaAlgSupportFrom = Stream.of(
                    new AbstractMap.SimpleImmutableEntry<>("eddsa", 16),
                    new AbstractMap.SimpleImmutableEntry<>("ed25519", 16),
                    new AbstractMap.SimpleImmutableEntry<>("ed448", 16),
                    new AbstractMap.SimpleImmutableEntry<>("xdh", 11),
                    new AbstractMap.SimpleImmutableEntry<>("x25519", 11),
                    new AbstractMap.SimpleImmutableEntry<>("x448", 11))
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

    private static  Set<String>  SUPPORTED_ALGORITHMS = Stream.of(Security.getProviders()).flatMap(provider -> provider.getServices().stream())
            .filter(s -> "Cipher".equals(s.getType()))
            .map(Provider.Service::getAlgorithm)
            .map(String::toLowerCase)
            .collect(Collectors.toSet());


    public static int getJDKVersion() {
        try {
            return Integer.getInteger("java.specification.version", 0);
        } catch (NumberFormatException ex) {
            // ignore
        }
        return 0;
    }

    public static Provider getAuxiliaryProvider() {
        return auxiliaryProvider;
    }

    public static void registerAuxiliaryProvider() {
        Security.addProvider(auxiliaryProvider);
    }

    public static void unregisterAuxiliaryProvider() {
        Security.removeProvider(auxiliaryProvider.getName());
    }

    public static boolean isAuxiliaryProviderRegistered() {
        return Security.getProvider(auxiliaryProvider.getName())!=null ;
    }


    public static boolean isAlgorithmSupported(String algorithm) {
        String alg = algorithm.toLowerCase();
        if (!javaAlgSupportFrom.containsKey(alg) || javaAlgSupportFrom.get(alg) > getJDKVersion()) {
            return false;
        }
        // double check in all supported algorithms ...
        return SUPPORTED_ALGORITHMS.contains(alg);
    }
}
