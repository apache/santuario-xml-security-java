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
package org.apache.xml.security.utils.jaxb;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import static java.time.format.DateTimeFormatter.ISO_DATE;
import static java.time.format.DateTimeFormatter.ISO_DATE_TIME;

/**
 * Utility class for converting date and time values to and from string. The utility is used by JAXB adapters.
 */
public class DatatypeConverter {
    @FunctionalInterface
    private interface ConvertToOffsetDateTime {
        OffsetDateTime method(String string);
    }

    private static final System.Logger LOG = System.getLogger(DatatypeConverter.class.getName());

    private static final List<ConvertToOffsetDateTime> PARSER_FORMATS = Arrays.asList(
            value -> OffsetDateTime.parse(value, ISO_DATE_TIME),
            value -> {
                LocalDateTime ldt = LocalDateTime.parse(value, ISO_DATE_TIME);
                return ldt.atZone(ZoneId.systemDefault()).toOffsetDateTime();
            },
            value -> OffsetDateTime.parse(value, ISO_DATE),
            value -> {
                LocalDate ldt = LocalDate.parse(value, ISO_DATE);
                return ldt.atStartOfDay(ZoneId.systemDefault()).toOffsetDateTime();
            });

    protected DatatypeConverter() {
    }

    public static OffsetDateTime parseDateTime(String dateTimeValue) {
        String trimmedValue = trimToNull(dateTimeValue);
        if (trimmedValue == null) {
            return null;
        }

        OffsetDateTime dateTime = PARSER_FORMATS.stream()
                .map(parser -> parseDateTime(trimmedValue, parser))
                .filter(Objects::nonNull)
                .findFirst().orElse(null);

        if (dateTime == null) {
            LOG.log(System.Logger.Level.WARNING, "Can not parse date value [{}]. Value ingored!",
                    trimmedValue);
        }
        return dateTime;
    }

    private static OffsetDateTime parseDateTime(String value, ConvertToOffsetDateTime parser) {
        // first try to pase offset
        try {
            return parser.method(value);
        } catch (DateTimeParseException ex) {
            LOG.log(System.Logger.Level.WARNING, "Can not parse date [{}], Error: [{}]!",
                    value, ex.getMessage());
        }
        return null;
    }

    public static String printDateTime(OffsetDateTime value) {
        return value.format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
    }

    public static String printDate(OffsetDateTime value) {
        return value.format(DateTimeFormatter.ISO_OFFSET_DATE);
    }


    /**
     * Returns a none empty string whose value is this string, with all leading
     * and trailing space removed, otherwise returns null.
     *
     * @param value the string to be trimmed
     * @return the trimmed (not empty) string or null
     */
    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String result = value.trim();
        return result.isEmpty() ? null : result;
    }
}
