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

import java.util.List;
import java.util.Properties;

import org.apache.xml.security.configuration.PropertiesType;
import org.apache.xml.security.configuration.PropertyType;

/**
 * Configuration Properties
 *
 */
public final class ConfigurationProperties {

    private static Properties properties;
    private static Class<?> callingClass;

    private ConfigurationProperties() {
        super();
    }

    protected static synchronized void init(PropertiesType propertiesType,
            Class<?> callingClass) throws Exception {
        properties = new Properties();
        List<PropertyType> handlerList = propertiesType.getProperty();
        for (PropertyType propertyType : handlerList) {
            properties.setProperty(propertyType.getNAME(), propertyType.getVAL());
        }
        ConfigurationProperties.callingClass = callingClass;
    }

    public static String getProperty(String key) {
        return properties.getProperty(key);
    }

    public static Class<?> getCallingClass() {
        return callingClass;
    }
}
