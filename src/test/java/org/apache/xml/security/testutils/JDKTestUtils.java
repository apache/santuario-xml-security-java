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

import java.lang.System.Logger.Level;
import java.lang.reflect.Constructor;
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


    // Purpose of auxiliary security provider is to enable testing of algorithms not supported by default JDK security providers.
    private static final String TEST_PROVIDER_CLASSNAME_PROPERTY = "test.auxiliary.jce.provider.classname";
    private static final String TEST_PROVIDER_CLASSNAME_DEFAULT = "org.bouncycastle.jce.provider.BouncyCastleProvider";
    private static final System.Logger LOG = System.getLogger(JDKTestUtils.class.getName());

    private static Provider auxiliaryProvider;
    private static boolean auxiliaryProviderInitialized = false;
    private static  Set<String> supportedAuxiliaryProviderAlgorithms = null;

    private static final Map<String, Integer> javaAlgSupportFrom = Stream.of(
                    new AbstractMap.SimpleImmutableEntry<>("eddsa", 16),
                    new AbstractMap.SimpleImmutableEntry<>("ed25519", 16),
                    new AbstractMap.SimpleImmutableEntry<>("ed448", 16),
                    new AbstractMap.SimpleImmutableEntry<>("xdh", 11),
                    new AbstractMap.SimpleImmutableEntry<>("x25519", 11),
                    new AbstractMap.SimpleImmutableEntry<>("x448", 11))
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

    private static final Set<String> SUPPORTED_ALGORITHMS = Stream.of(Security.getProviders())
            .flatMap(provider -> provider.getServices().stream())
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

    public static synchronized Provider getAuxiliaryProvider() {
        if (auxiliaryProviderInitialized) {
            return auxiliaryProvider;
        }
        try {
            String providerClassName = System.getProperty(TEST_PROVIDER_CLASSNAME_PROPERTY, TEST_PROVIDER_CLASSNAME_DEFAULT);
            LOG.log(Level.INFO, "Initialize the auxiliary security provider: [{0}]",  providerClassName);
            Class<?> c = Class.forName(providerClassName);
            Constructor<?> cons = c.getConstructor();
            auxiliaryProvider = (Provider)cons.newInstance();
            supportedAuxiliaryProviderAlgorithms = auxiliaryProvider.getServices().stream()
                    .map(Provider.Service::getAlgorithm)
                    .map(String::toLowerCase)
                    .collect(Collectors.toSet());
        } catch (Exception e) {
            LOG.log(Level.WARNING, "Failed to initialize the auxiliary security provider: [{0}]",  e.getMessage());
        }
        auxiliaryProviderInitialized = true;
        return auxiliaryProvider;
    }

    public static void registerAuxiliaryProvider() {
        // init provider if needed
        Provider provider = getAuxiliaryProvider();
        if (provider == null) {
           LOG.log(Level.WARNING, "Auxiliary security provider is not initialized. Cannot register it.");
           return;
        }
        Security.addProvider(provider);
    }

    public static void unregisterAuxiliaryProvider() {
        if (auxiliaryProvider == null) {
            LOG.log(Level.DEBUG, "Auxiliary security provider is not initialized. Cannot unregister it.");
            return;
        }
        LOG.log(Level.DEBUG, "Unregister auxiliary security provider [{0}]", auxiliaryProvider.getName());
        Security.removeProvider(auxiliaryProvider.getName());
    }

    public static boolean isAuxiliaryProviderRegistered() {
        return auxiliaryProvider!=null && Security.getProvider(auxiliaryProvider.getName())!=null ;
    }


    public static boolean isAlgorithmSupported(String algorithm, boolean useAuxiliaryProvider) {
        String alg = algorithm.toLowerCase();
        int iJDKVersion = getJDKVersion();
        if (javaAlgSupportFrom.containsKey(alg)
                && javaAlgSupportFrom.get(alg) <= iJDKVersion
                || SUPPORTED_ALGORITHMS.contains(alg)) {
            LOG.log(Level.DEBUG, "Algorithm [{0}] is supported by JDK version [{1}]", alg, iJDKVersion);
            return true;
        }
        Provider provider = getAuxiliaryProvider();
        if (useAuxiliaryProvider
                && provider!=null
                && supportedAuxiliaryProviderAlgorithms.contains(alg)){
            LOG.log(Level.DEBUG, "Algorithm [{0}] is supported by auxiliary Provider [{1}].",
                    alg, provider.getName());
            return true;
        }
        // double check in all supported algorithms ...
        LOG.log(Level.INFO, "Algorithm [{0}] is NOT supported!", alg);
        return false;
    }

    public static boolean isAlgorithmSupportedByJDK(String algorithm) {
        return isAlgorithmSupported(algorithm, false);
    }
}
