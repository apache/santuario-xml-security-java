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

import java.lang.System.Logger;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

import org.apache.xml.security.test.stax.performance.PerformanceIT.Action;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Timeout;
import org.openjdk.jmh.annotations.Warmup;

import static java.lang.System.Logger.Level.INFO;
import static java.lang.System.Logger.Level.WARNING;
import static org.apache.xml.security.test.stax.performance.BenchmarkXmlFileFactory.FILE_SYMMETRIC_KEY;

/**
 * This class is used as a base to generate JMH benchmark classes.
 * They will be used in own JVM.
 */
@BenchmarkMode(Mode.SampleTime)
@Warmup(batchSize = 1, iterations = 1)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(1)
@Timeout(time = 5, timeUnit = TimeUnit.MINUTES)
// We work with files, don't add more threads
@Threads(1)
public class Benchmarks {

    private static final Logger LOG = System.getLogger(Benchmarks.class.getName());

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
        if (files.warmupDuration == null) {
            files.warmupDuration = duration;
            LOG.log(INFO, "Duration of the warmup action: {0} ms", files.warmupDuration.toMillis());
            return;
        }
        if (duration.compareTo(files.warmupDuration) > 0) {
            LOG.log(WARNING, "The action was slower than warmup by {0}%", percent(files.warmupDuration, duration));
        } else {
            LOG.log(INFO, "The action was faster than warmup by {0}%", percent(files.warmupDuration, duration));
        }
    }

    private static double percent(Duration base, Duration now) {
        long baseDuration = base.toNanos();
        long nowDuration = now.toNanos();
        return Math.round(100 * Math.abs((baseDuration - nowDuration) / (double) baseDuration));
    }
}