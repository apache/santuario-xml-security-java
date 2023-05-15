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
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

import org.apache.xml.security.test.JmhUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Timeout;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.profile.StackProfiler;
import org.openjdk.jmh.runner.options.ChainedOptionsBuilder;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import static org.apache.xml.security.test.JmhUtils.getSystemOptArg;
import static org.apache.xml.security.test.XmlSecTestEnvironment.resolveFile;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.lessThan;
import static org.hamcrest.Matchers.lessThanOrEqualTo;

@Tag("benchmark")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class PerformanceIT {

    private static final Logger LOG = System.getLogger(PerformanceIT.class.getName());

    private static final File DIR_TMP = resolveFile("target/performanceIT");
    private static final File FILE_SYMMETRIC_KEY = new File(DIR_TMP, "symkey.pcks12");

    private static final File FILE_INPUT_XML = new File(DIR_TMP, "input.xml");
    private static final File signedDomFile = new File(DIR_TMP, "signature-dom.xml");
    private static final File signedStreamFile = new File(DIR_TMP, "signature-stax.xml");
    private static final File encryptedDOMFile = new File(DIR_TMP, "encryption-dom.xml");
    private static final File encryptedStreamFile = new File(DIR_TMP, "encryption-stax.xml");

    private ChainedOptionsBuilder optionsBuilder;


    @BeforeAll
    public static void initClass() throws Exception {
        BenchmarkXmlFileFactory.initFiles(DIR_TMP, FILE_INPUT_XML, FILE_SYMMETRIC_KEY);
    }


    @BeforeEach
    public void initTest() throws Exception {
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
    public void testSignAsStreams() throws Exception {
        Options options = optionsBuilder
            .include(Benchmarks.class.getCanonicalName() + ".signAsStreams.*")
            .param("processedFileName", signedStreamFile.getName())
            .build();
        JmhUtils.runAndVerify(options, lessThanOrEqualTo(10_000d), lessThanOrEqualTo(500d));
    }


    @Order(11)
    @Test
    public void testReadSignedAsStream() throws Exception {
        Options options = optionsBuilder
            .include(Benchmarks.class.getCanonicalName() + ".readSignedAsStream.*")
            .param("processedFileName", signedStreamFile.getName())
            .build();
        JmhUtils.runAndVerify(options, lessThanOrEqualTo(8_000d), lessThanOrEqualTo(500d));
    }


    @Order(20)
    @Test
    public void testSignAsDOM() throws Exception {
        Options options = optionsBuilder
            .include(Benchmarks.class.getCanonicalName() + ".signAsDOM.*")
            .param("processedFileName", signedDomFile.getName())
            .build();
        JmhUtils.runAndVerify(options, lessThanOrEqualTo(180_000d), lessThanOrEqualTo(10_000d));
    }


    @Order(21)
    @Test
    public void testReadSignedAsDOM() throws Exception {
        Options options = optionsBuilder
            .include(Benchmarks.class.getCanonicalName() + ".readSignedAsDOM.*")
            .param("processedFileName", signedDomFile.getName())
            .build();
        JmhUtils.runAndVerify(options, lessThanOrEqualTo(8_000d), lessThanOrEqualTo(500d));
    }

    @Order(30)
    @Test
    public void testEncryptStream() throws Exception {
        Options options = optionsBuilder
            .include(Benchmarks.class.getCanonicalName() + ".encryptStream.*")
            .param("processedFileName", encryptedStreamFile.getName())
            .build();
        JmhUtils.runAndVerify(options, lessThanOrEqualTo(8_000d), lessThanOrEqualTo(500d));
    }


    @Order(31)
    @Test
    public void testDecryptStream() throws Exception {
        Options options = optionsBuilder
            .include(Benchmarks.class.getCanonicalName() + ".decryptStream.*")
            .param("processedFileName", encryptedStreamFile.getName())
            .build();
        JmhUtils.runAndVerify(options, lessThanOrEqualTo(8_000d), lessThanOrEqualTo(500d));
    }


    @Order(40)
    @Test
    public void testEncryptDOM() throws Exception {
        Options options = optionsBuilder
            .include(Benchmarks.class.getCanonicalName() + ".encryptDOM.*")
            .param("processedFileName", encryptedDOMFile.getName())
            .build();
        JmhUtils.runAndVerify(options, lessThanOrEqualTo(300_000d), lessThanOrEqualTo(10_000d));
    }


    @Order(41)
    @Test
    public void testDecryptDOM() throws Exception {
        Options options = optionsBuilder
            .include(Benchmarks.class.getCanonicalName() + ".decryptDOM.*")
            .param("processedFileName", encryptedDOMFile.getName())
            .build();
        JmhUtils.runAndVerify(options, lessThanOrEqualTo(10_000d), lessThanOrEqualTo(500d));
    }

    /**
     * This class is used as a base to generate JMH benchmark classes.
     * They will be used in own JVM.
     */
    @BenchmarkMode(Mode.SampleTime)
    @Warmup(batchSize = 1, iterations = 1)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Fork(1)
    @Timeout(time = 5, timeUnit = TimeUnit.MINUTES)
    // We work with files, don't add more
    @Threads(1)
    public static class Benchmarks {

        private static final BenchmarkXmlFileFactory XML_FACTORY = new BenchmarkXmlFileFactory(FILE_SYMMETRIC_KEY);

        @Measurement(batchSize = 4, iterations = 3)
        @Benchmark
        public void signAsStreams(final BenchmarkFiles files) throws Exception {
            Action action = () -> XML_FACTORY.signAsStream(files.getOriginalFile(), files.getProcessedFile());
            runAndCheckStability(action, files);
        }


        @Measurement(batchSize = 4, iterations = 3)
        @Benchmark
        public void readSignedAsStream(final BenchmarkFiles files) throws Exception {
            Action action = () -> XML_FACTORY.readSignedAsStream(files.getProcessedFile());
            runAndCheckStability(action, files);
        }


        @Measurement(batchSize = 4, iterations = 3)
        @Benchmark
        public void signAsDOM(final BenchmarkFiles files) throws Exception {
            Action action = () -> XML_FACTORY.signAsDOM(files.getOriginalFile(), files.getProcessedFile());
            runAndCheckStability(action, files);
        }


        @Measurement(batchSize = 4, iterations = 3)
        @Benchmark
        public void readSignedAsDOM(final BenchmarkFiles files) throws Exception {
            Action action = () -> XML_FACTORY.readSignedAsDOM(files.getProcessedFile());
            runAndCheckStability(action, files);
        }


        @Measurement(batchSize = 4, iterations = 3)
        @Benchmark
        public void encryptStream(final BenchmarkFiles files) throws Exception {
            Action action = () -> XML_FACTORY.encryptAsStream(files.getOriginalFile(), files.getProcessedFile());
            runAndCheckStability(action, files);
        }


        @Measurement(batchSize = 4, iterations = 3)
        @Benchmark
        public void decryptStream(final BenchmarkFiles files) throws Exception {
            Action action = () -> XML_FACTORY.decryptAsStream(files.getProcessedFile());
            runAndCheckStability(action, files);
        }


        @Measurement(batchSize = 4, iterations = 3)
        @Benchmark
        public void encryptDOM(final BenchmarkFiles files) throws Exception {
            Action action = () -> XML_FACTORY.encryptAsDOM(files.getOriginalFile(), files.getProcessedFile());
            runAndCheckStability(action, files);
        }


        @Measurement(batchSize = 4, iterations = 3)
        @Benchmark
        public void decryptDOM(final BenchmarkFiles files) throws Exception {
            Action action = () -> XML_FACTORY.decryptAsDOM(files.getProcessedFile());
            runAndCheckStability(action, files);
        }

        private void runAndCheckStability(Action action, BenchmarkFiles files) throws Exception {
            Instant start = Instant.now();
            action.run();
            Duration duration = Duration.between(start, Instant.now());
            if (files.maxAcceptableDuration == null) {
                files.maxAcceptableDuration = duration.plusMillis(duration.toMillis() / 10);
                LOG.log(Level.INFO, "Max tolerated duration of the action based on the warmup + 10%: {0} ms",
                    files.maxAcceptableDuration.toMillis());
                return;
            }
            assertThat("Duration of the action", duration, lessThan(files.maxAcceptableDuration));
        }
    }

    @FunctionalInterface
    interface Action {
        void run() throws Exception;
    }


    @State(Scope.Benchmark)
    public static class BenchmarkFiles {

        public Duration maxAcceptableDuration;

        // Values must be simple strings.
        // Affects also JMH output which is more simple.
        @Param("")
        private String tmpDir;
        @Param("")
        private String originalFileName;
        @Param("")
        private String processedFileName;

        /**
         * @return input unsigned and unencrypted xml file
         */
        public File getOriginalFile() {
            return originalFileName.isEmpty() ? null : new File(tmpDir, originalFileName);
        }

        /**
         * @return signed or encrypted file
         */
        public File getProcessedFile() {
            return processedFileName.isEmpty() ? null : new File(tmpDir, processedFileName);
        }

        @Override
        public String toString() {
            return "[originalFile=" + originalFileName + "|signedFile=" + processedFileName + "]";
        }
    }
}
