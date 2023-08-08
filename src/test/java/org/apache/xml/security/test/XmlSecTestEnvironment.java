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
package org.apache.xml.security.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

/**
 * This class keeps order in files used by tests.
 * Its purpose is to locate files by specifying relative paths to maven basedir.
 */
public final class XmlSecTestEnvironment {

    /** Password to the {@link KeyStore} returned by {@link #getTestKeyStore()} */
    public static final String TEST_KS_PASSWORD = "changeit";
    /** Password to the {@link KeyStore} returned by {@link #getTransmitterKeyStore()} */
    public static final String TRANSMITTER_KS_PASSWORD = "default";

    private static final Path BASEDIR = Path.of(System.getProperty("basedir", ".")).toAbsolutePath();

    private XmlSecTestEnvironment() {
        // hidden
    }


    /**
     * @return {@link KeyStore} loaded from test.jks
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static KeyStore getTestKeyStore() throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(resolveFile("src/test/resources/test.jks"))) {
            ks.load(fis, TEST_KS_PASSWORD.toCharArray());
        }
        return ks;
    }


    /**
     * @return {@link KeyStore} loaded from transmitter.jks
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public static KeyStore getTransmitterKeyStore() throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("jks");
        try (InputStream is = XmlSecTestEnvironment.class.getClassLoader().getResourceAsStream("transmitter.jks")) {
            ks.load(is, TRANSMITTER_KS_PASSWORD.toCharArray());
        }
        return ks;
    }


    /**
     * Resolves the absolute path and returns the {@link File}.
     * The file may not exist.
     *
     * @param relativePath
     * @return absolute {@link File} path
     */
    public static File resolveFile(Path relativePath) {
        return BASEDIR.resolve(relativePath).toFile();
    }


    /**
     * Resolves the absolute path and returns the {@link File}.
     * The file may not exist.
     *
     * @param first first element relative to the base dir
     * @param more other path elements
     * @return absolute {@link File} path
     */
    public static File resolveFile(String first, String... more) {
        return resolveFile(BASEDIR, first, more);
    }


    /**
     * Resolves the absolute path and returns the {@link File}.
     * The file may not exist.
     *
     * @param base orientation point to be used for resolving the path
     * @param first first element relative to the base dir
     * @param more other path elements
     * @return absolute {@link File} path
     */
    public static File resolveFile(Path base, String first, String... more) {
        return resolvePath(base, first, more).toFile();
    }


    /**
     * Resolves the absolute path and returns the {@link File}.
     * The file may not exist.
     *
     * @param first first element relative to the base dir
     * @param more other path elements
     * @return absolute {@link Path}
     */
    public static Path resolvePath(String first, String... more) {
        return resolvePath(BASEDIR, first, more);
    }


    /**
     * Resolves the absolute path and returns the {@link File}.
     * The file may not exist.
     *
     * @param base orientation point to be used for resolving the path
     * @param first first element relative to the base dir
     * @param more other path elements
     * @return absolute {@link Path}
     */
    public static Path resolvePath(Path base, String first, String... more) {
        return base.resolve(Path.of(first, more)).toAbsolutePath();
    }
}
