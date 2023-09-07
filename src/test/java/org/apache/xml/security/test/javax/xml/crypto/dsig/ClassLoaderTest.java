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
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.AccessController;
import java.security.Provider;
import java.security.Security;

import javax.xml.crypto.dsig.CanonicalizationMethod;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.junit.jupiter.api.Test;

import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;

/**
 * This test uses more than one classloader to load a class (Driver) that
 * invokes the XMLSignature API. It tests that there are not provider class
 * loading issues with more than one classloader (see 6380953).
 */
class ClassLoaderTest {

    private static final Logger LOG = System.getLogger(ClassLoaderTest.class.getName());

    @Test
    void testMultipleLoaders() throws Exception {
        File file0 = resolveFile("build", "classes");
        File file1 = resolveFile("build", "test");
        URL[] urls = new URL[2];
        urls[0] = file0.toURI().toURL();
        urls[1] = file1.toURI().toURL();
        try (URLClassLoader uc1 = new URLClassLoader(urls, Thread.currentThread().getContextClassLoader());
            URLClassLoader uc2 = new URLClassLoader(urls, Thread.currentThread().getContextClassLoader())) {
            Class<?> c1 = uc1.loadClass("org.apache.xml.security.test.javax.xml.crypto.dsig.Driver");
            Class<?> c2 = uc2.loadClass("org.apache.xml.security.test.javax.xml.crypto.dsig.Driver");
            Object o1 = c1.getDeclaredConstructor().newInstance();
            Object o2 = c2.getDeclaredConstructor().newInstance();
            Method m1 = c1.getMethod("dsig", (Class[]) null);
            Method m2 = c2.getMethod("dsig", (Class[]) null);
            m1.invoke(o1, (Object[]) null);
            m2.invoke(o2, (Object[]) null);
        }
    }

    @Test
    void testProviderMultipleLoaders() throws Exception {
        File file0 = resolveFile("build", "classes");
        File file1 = resolveFile("build", "test");
        URL[] urls = new URL[2];
        urls[0] = file0.toURI().toURL();
        urls[1] = file1.toURI().toURL();

        try (URLClassLoader uc1 = new URLClassLoader(urls, Thread.currentThread().getContextClassLoader())) {
            //load security provider using current class loader
            final Provider provider = new XMLDSigRI();
            AccessController.doPrivileged((java.security.PrivilegedAction<Object>)
                () -> Security.addProvider(provider));
            // get the provider from java.security.Security using URLClassLoader.
            // Need to use introspection to invoke methods to avoid using the
            // current class loader
            String factoryName = "javax.xml.crypto.dsig.XMLSignatureFactory";
            Class<?> factoryClass = uc1.loadClass(factoryName);
            Method factoryMethod = factoryClass.getDeclaredMethod("getInstance", new Class[] {String.class});
            Class<?> methodParameterClass = uc1.loadClass("javax.xml.crypto.dsig.spec.C14NMethodParameterSpec");
            Method canonicalizationMethod = factoryClass.getDeclaredMethod("newCanonicalizationMethod",
                new Class[] {String.class, methodParameterClass});
            Object factory = factoryMethod.invoke(null, "DOM");
            long start = System.currentTimeMillis();
            for (int i = 0; i < 100; i++) {
                canonicalizationMethod.invoke(factory, new Object[] {CanonicalizationMethod.EXCLUSIVE, null});
            }
            long end = System.currentTimeMillis();
            long elapsed = end-start;
            LOG.log(Level.DEBUG, "Elapsed: {0}", elapsed);
        }
    }

    @Test
    void testProviderMultipleLoadersTwo() throws Exception {
        File file0 = resolveFile("build", "classes");
        File file1 = resolveFile("build", "test");
        URL[] urls = new URL[2];
        urls[0] = file0.toURI().toURL();
        urls[1] = file1.toURI().toURL();
        try (URLClassLoader uc1 = new URLClassLoader(urls, Thread.currentThread().getContextClassLoader());
            URLClassLoader uc2 = new URLClassLoader(urls, Thread.currentThread().getContextClassLoader())) {
            Class<?> c1 = uc1.loadClass("org.apache.xml.security.test.javax.xml.crypto.dsig.AppA");
            Class<?> c2 = uc2.loadClass("org.apache.xml.security.test.javax.xml.crypto.dsig.AppB");
            Object o1 = c1.getDeclaredConstructor().newInstance();
            Object o2 = c2.getDeclaredConstructor().newInstance();
            Method m1 = c1.getMethod("dsig", (Class[]) null);
            Method m2 = c2.getMethod("dsig", (Class[]) null);
            m1.invoke(o1, (Object[]) null);
            m2.invoke(o2, (Object[]) null);
        }
    }

}
