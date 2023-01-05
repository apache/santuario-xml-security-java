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
package org.apache.xml.security.test.stax.performance;

import java.io.File;

import org.apache.xml.security.test.JmhUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.profile.StackProfiler;
import org.openjdk.jmh.runner.options.ChainedOptionsBuilder;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import static org.apache.xml.security.test.JmhUtils.getSystemOptArg;
import static org.apache.xml.security.test.stax.performance.BenchmarkXmlFileFactory.DIR_TMP;
import static org.apache.xml.security.test.stax.performance.BenchmarkXmlFileFactory.FILE_INPUT_XML;
import static org.hamcrest.Matchers.lessThanOrEqualTo;

@Tag("benchmark")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class PerformanceIT {

    private static final File signedDomFile = new File(DIR_TMP, "signature-dom.xml");
    private static final File signedStreamFile = new File(DIR_TMP, "signature-stax.xml");
    private static final File encryptedDOMFile = new File(DIR_TMP, "encryption-dom.xml");
    private static final File encryptedStreamFile = new File(DIR_TMP, "encryption-stax.xml");

    private ChainedOptionsBuilder optionsBuilder;


    @BeforeAll
    static void initClass() throws Exception {
        BenchmarkXmlFileFactory.initFiles();
    }


    @BeforeEach
    void initTest() throws Exception {
        optionsBuilder = new OptionsBuilder().shouldFailOnError(true).shouldDoGC(true)
            .addProfiler(StackProfiler.class).addProfiler(GCProfiler.class).addProfiler(MemoryProfiler.class)
            .param("tmpDir", DIR_TMP.getAbsolutePath())
            .param("originalFileName", FILE_INPUT_XML.getName())
            .jvmArgsPrepend(
                "-Xms1g", "-Xmx1g", "-Xss512k", "-XX:+UseShenandoahGC", "-XX:+UseStringDeduplication",
                getSystemOptArg("org.apache.xml.security.securerandom.algorithm"),
                getSystemOptArg("javax.xml.accessExternalDTD")
            );
    }


    @Order(10)
    @Test
    void testSignAsStreams() throws Exception {
        Options options = optionsBuilder
            .include(Benchmarks.class.getCanonicalName() + ".signAsStreams.*")
            .param("processedFileName", signedStreamFile.getName())
            .build();
        JmhUtils.runAndVerify(options, lessThanOrEqualTo(10_000d), lessThanOrEqualTo(500d));
    }


    @Order(11)
    @Test
    void testReadSignedAsStream() throws Exception {
        Options options = optionsBuilder
            .include(Benchmarks.class.getCanonicalName() + ".readSignedAsStream.*")
            .param("processedFileName", signedStreamFile.getName())
            .build();
        JmhUtils.runAndVerify(options, lessThanOrEqualTo(10_000d), lessThanOrEqualTo(500d));
    }


    @Order(20)
    @Test
    void testSignAsDOM() throws Exception {
        Options options = optionsBuilder
            .include(Benchmarks.class.getCanonicalName() + ".signAsDOM.*")
            .param("processedFileName", signedDomFile.getName())
            .build();
        JmhUtils.runAndVerify(options, lessThanOrEqualTo(15_000d), lessThanOrEqualTo(500d));
    }


    @Order(21)
    @Test
    void testReadSignedAsDOM() throws Exception {
        Options options = optionsBuilder
            .include(Benchmarks.class.getCanonicalName() + ".readSignedAsDOM.*")
            .param("processedFileName", signedDomFile.getName())
            .build();
        JmhUtils.runAndVerify(options, lessThanOrEqualTo(10_000d), lessThanOrEqualTo(500d));
    }

    @Order(30)
    @Test
    void testEncryptStream() throws Exception {
        Options options = optionsBuilder
            .include(Benchmarks.class.getCanonicalName() + ".encryptStream.*")
            .param("processedFileName", encryptedStreamFile.getName())
            .build();
        JmhUtils.runAndVerify(options, lessThanOrEqualTo(10_000d), lessThanOrEqualTo(500d));
    }


    @Order(31)
    @Test
    void testDecryptStream() throws Exception {
        Options options = optionsBuilder
            .include(Benchmarks.class.getCanonicalName() + ".decryptStream.*")
            .param("processedFileName", encryptedStreamFile.getName())
            .build();
        JmhUtils.runAndVerify(options, lessThanOrEqualTo(10_000d), lessThanOrEqualTo(500d));
    }


    @Order(40)
    @Test
    void testEncryptDOM() throws Exception {
        Options options = optionsBuilder
            .include(Benchmarks.class.getCanonicalName() + ".encryptDOM.*")
            .param("processedFileName", encryptedDOMFile.getName())
            .build();
        JmhUtils.runAndVerify(options, lessThanOrEqualTo(25_000d), lessThanOrEqualTo(1500d));
    }


    @Order(41)
    @Test
    void testDecryptDOM() throws Exception {
        Options options = optionsBuilder
            .include(Benchmarks.class.getCanonicalName() + ".decryptDOM.*")
            .param("processedFileName", encryptedDOMFile.getName())
            .build();
        JmhUtils.runAndVerify(options, lessThanOrEqualTo(15_000d), lessThanOrEqualTo(1000d));
    }

    @FunctionalInterface
    interface Action {
        void run() throws Exception;
    }
}
