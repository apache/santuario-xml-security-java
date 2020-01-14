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
package org.apache.xml.security.keys.storage.implementations;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import org.apache.xml.security.keys.storage.StorageResolverException;
import org.apache.xml.security.keys.storage.StorageResolverSpi;

/**
 * This {@link StorageResolverSpi} makes all raw (binary) {@link X509Certificate}s
 * which reside as files in a single directory available to the
 * {@link org.apache.xml.security.keys.storage.StorageResolver}.
 */
public class CertsInFilesystemDirectoryResolver extends StorageResolverSpi {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(
            CertsInFilesystemDirectoryResolver.class
        );

    /** Field certs */
    private final List<X509Certificate> certs;

    /**
     * @param directoryName
     * @throws StorageResolverException
     */
    public CertsInFilesystemDirectoryResolver(String directoryName)
        throws StorageResolverException {

        File certDir = new File(directoryName);
        List<String> al = new ArrayList<>();
        String[] names = certDir.list();

        if (names != null) {
            for (int i = 0; i < names.length; i++) {
                String currentFileName = names[i];

                if (currentFileName.endsWith(".crt")) {
                    al.add(names[i]);
                }
            }
        }

        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (CertificateException ex) {
            throw new StorageResolverException(ex);
        }

        List<X509Certificate> tmpCerts = new ArrayList<>();
        for (int i = 0; i < al.size(); i++) {
            String filename = certDir.getAbsolutePath() + File.separator + al.get(i);
            boolean added = false;
            String dn = null;

            try (InputStream inputStream = Files.newInputStream(Paths.get(filename))) {
                X509Certificate cert =
                    (X509Certificate) cf.generateCertificate(inputStream);

                //add to ArrayList
                cert.checkValidity();
                tmpCerts.add(cert);

                dn = cert.getSubjectX500Principal().getName();
                added = true;
            } catch (FileNotFoundException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Could not add certificate from file " + filename, ex);
                }
            } catch (CertificateNotYetValidException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Could not add certificate from file " + filename, ex);
                }
            } catch (CertificateExpiredException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Could not add certificate from file " + filename, ex);
                }
            } catch (CertificateException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Could not add certificate from file " + filename, ex);
                }
            } catch (IOException ex) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Could not add certificate from file " + filename, ex);
                }
            }

            if (added) {
                LOG.debug("Added certificate: {}", dn);
            }
        }

        certs = Collections.unmodifiableList(tmpCerts);
    }

    /** {@inheritDoc} */
    public Iterator<Certificate> getIterator() {
        return new FilesystemIterator(this.certs);
    }

    /**
     * Class FilesystemIterator
     */
    private static class FilesystemIterator implements Iterator<Certificate> {

        /** Field certs */
        private final List<X509Certificate> certs;

        /** Field i */
        private int i;

        /**
         * Constructor FilesystemIterator
         *
         * @param certs
         */
        public FilesystemIterator(List<X509Certificate> certs) {
            this.certs = certs;
            this.i = 0;
        }

        /** {@inheritDoc} */
        public boolean hasNext() {
            return this.i < this.certs.size();
        }

        /** {@inheritDoc} */
        public Certificate next() {
            if (hasNext()) {
                return this.certs.get(this.i++);
            }

            throw new NoSuchElementException();
        }

        /**
         * Method remove
         *
         */
        public void remove() {
            throw new UnsupportedOperationException("Can't remove keys from KeyStore");
        }
    }

}
