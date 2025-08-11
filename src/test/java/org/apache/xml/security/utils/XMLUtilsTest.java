package org.apache.xml.security.utils;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

public class XMLUtilsTest {
    private static final byte[] data = new byte[60]; // long enough for a line break in MIME encoding

    private Properties backup;
    private ClassLoader classLoader;

    @BeforeEach
    public void createClassLoader() {
        /* create custom classloader to reload class in each test */
        ClassLoader parent = getClass().getClassLoader();
        Collection<Class<?>> classesToReload = List.of(
                XMLUtils.class,
                XMLUtils.Base64FormattingOptions.class,
                XMLUtils.Base64LineSeparator.class
        );
        classLoader = new ReloadingClassLoader(parent, classesToReload);
        ModuleLayer.boot().findModule("org.apache.santuario.xmlsec").orElseThrow()
                .addOpens("org.apache.xml.security.parser", classLoader.getUnnamedModule());
    }

    @BeforeEach
    public void backupProperties() {
        backup = new Properties();
        backup.putAll(System.getProperties());
    }

    @AfterEach
    public void restoreProperties() {
        System.setProperties(backup);
    }

    @Test
    public void testAllPropertiesUnset() throws ReflectiveOperationException, IOException {
        System.clearProperty("org.apache.xml.security.ignoreLineBreaks");
        System.clearProperty("org.apache.xml.security.base64.ignoreLineBreaks");
        System.clearProperty("org.apache.xml.security.base64.lineSeparator");
        System.clearProperty("org.apache.xml.security.base64.lineLength");

        Class<?> xmlUtilsClass = classLoader.loadClass(XMLUtils.class.getName());
        String encoded = encodeToString(xmlUtilsClass, data);
        String elementValue = encodeElementValue(xmlUtilsClass, data);
        String encodedWithStream = encodeUsingStream(xmlUtilsClass, data);

        assertThat(encoded, containsString("\r\n"));
        OptionalInt maxLineLength = Arrays.stream(encoded.split("\r\n")).mapToInt(String::length).max();
        assertTrue(maxLineLength.isPresent());
        assertEquals(76, maxLineLength.getAsInt());

        assertThat(elementValue, containsString(encoded));
        assertThat(elementValue, startsWith("\n"));
        assertThat(elementValue, endsWith("\n"));

        assertEquals(encoded, encodedWithStream);
    }

    @Test
    public void testIgnoreLineBreaksSet() throws ReflectiveOperationException, IOException {
        System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
        System.clearProperty("org.apache.xml.security.base64.ignoreLineBreaks");
        System.clearProperty("org.apache.xml.security.base64.lineSeparator");
        System.clearProperty("org.apache.xml.security.base64.lineLength");

        Class<?> xmlUtilsClass = classLoader.loadClass(XMLUtils.class.getName());
        String encoded = encodeToString(xmlUtilsClass, data);
        String elementValue = encodeElementValue(xmlUtilsClass, data);
        String encodedWithStream = encodeUsingStream(xmlUtilsClass, data);

        assertThat(encoded, not(containsString("\r\n")));
        assertThat(encoded, not(containsString("\n")));
        assertThat(elementValue, not(containsString("\r\n")));
        assertThat(elementValue, not(containsString("\n")));

        assertEquals(encoded, encodedWithStream);
    }

    @Test
    public void testIgnoreLineBreaksTakesPrecedence() throws ReflectiveOperationException, IOException {
        System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
        System.setProperty("org.apache.xml.security.base64.ignoreLineBreaks", "false");
        System.setProperty("org.apache.xml.security.base64.lineSeparator", "crlf");
        System.setProperty("org.apache.xml.security.base64.lineLength", "40");

        Class<?> xmlUtilsClass = classLoader.loadClass(XMLUtils.class.getName());
        String encoded = encodeToString(xmlUtilsClass, data);
        String elementValue = encodeElementValue(xmlUtilsClass, data);
        String encodedWithStream = encodeUsingStream(xmlUtilsClass, data);

        assertThat(encoded, not(containsString("\r\n")));
        assertThat(encoded, not(containsString("\n")));
        assertThat(elementValue, not(containsString("\r\n")));
        assertThat(elementValue, not(containsString("\n")));

        assertEquals(encoded, encodedWithStream);
    }

    @Test
    public void testBase64IgnoreLineBreaksSet() throws ReflectiveOperationException, IOException {
        System.clearProperty("org.apache.xml.security.ignoreLineBreaks");
        System.setProperty("org.apache.xml.security.base64.ignoreLineBreaks", "true");
        System.clearProperty("org.apache.xml.security.base64.lineSeparator");
        System.clearProperty("org.apache.xml.security.base64.lineLength");

        Class<?> xmlUtilsClass = classLoader.loadClass(XMLUtils.class.getName());
        String encoded = encodeToString(xmlUtilsClass, data);
        String elementValue = encodeElementValue(xmlUtilsClass, data);
        String encodedWithStream = encodeUsingStream(xmlUtilsClass, data);

        assertThat(encoded, not(containsString("\r\n")));
        assertThat(encoded, not(containsString("\n")));
        assertThat(elementValue, not(containsString("\r\n")));
        assertThat(elementValue, not(containsString("\n")));

        assertEquals(encoded, encodedWithStream);
    }

    @Test
    public void testBase64IgnoreLineBreaksTakesPrecedence() throws ReflectiveOperationException, IOException {
        System.clearProperty("org.apache.xml.security.ignoreLineBreaks");
        System.setProperty("org.apache.xml.security.base64.ignoreLineBreaks", "true");
        System.setProperty("org.apache.xml.security.base64.lineSeparator", "crlf");
        System.setProperty("org.apache.xml.security.base64.lineLength", "40");

        Class<?> xmlUtilsClass = classLoader.loadClass(XMLUtils.class.getName());
        String encoded = encodeToString(xmlUtilsClass, data);
        String elementValue = encodeElementValue(xmlUtilsClass, data);
        String encodedWithStream = encodeUsingStream(xmlUtilsClass, data);

        assertThat(encoded, not(containsString("\r\n")));
        assertThat(encoded, not(containsString("\n")));
        assertThat(elementValue, not(containsString("\r\n")));
        assertThat(elementValue, not(containsString("\n")));

        assertEquals(encoded, encodedWithStream);
    }

    @Test
    public void testBase64CustomFormatting() throws ReflectiveOperationException, IOException {
        System.clearProperty("org.apache.xml.security.ignoreLineBreaks");
        System.clearProperty("org.apache.xml.security.base64.ignoreLineBreaks");
        System.setProperty("org.apache.xml.security.base64.lineSeparator", "lf");
        System.setProperty("org.apache.xml.security.base64.lineLength", "40");

        Class<?> xmlUtilsClass = classLoader.loadClass(XMLUtils.class.getName());
        String encoded = encodeToString(xmlUtilsClass, data);
        String elementValue = encodeElementValue(xmlUtilsClass, data);
        String encodedWithStream = encodeUsingStream(xmlUtilsClass, data);

        assertThat(encoded, not(containsString("\r\n")));
        assertThat(encoded, containsString("\n"));
        OptionalInt maxLineLength = Arrays.stream(encoded.split("\n")).mapToInt(String::length).max();
        assertTrue(maxLineLength.isPresent());
        assertEquals(40, maxLineLength.getAsInt());

        assertThat(elementValue, containsString(encoded));
        assertThat(elementValue, startsWith("\n"));
        assertThat(elementValue, endsWith("\n"));

        assertEquals(encoded, encodedWithStream);
    }

    @Test
    public void testIllegalPropertiesAreIgnored() throws ReflectiveOperationException, IOException {
        System.setProperty("org.apache.xml.security.ignoreLineBreaks", "illegal");
        System.setProperty("org.apache.xml.security.base64.ignoreLineBreaks", "illegal");
        System.setProperty("org.apache.xml.security.base64.lineSeparator", "illegal");
        System.setProperty("org.apache.xml.security.base64.lineLength", "illegal");

        Class<?> xmlUtilsClass = classLoader.loadClass(XMLUtils.class.getName());
        String encoded = encodeToString(xmlUtilsClass, data);
        String elementValue = encodeElementValue(xmlUtilsClass, data);
        String encodedWithStream = encodeUsingStream(xmlUtilsClass, data);

        assertThat(encoded, containsString("\r\n"));
        OptionalInt maxLineLength = Arrays.stream(encoded.split("\r\n")).mapToInt(String::length).max();
        assertTrue(maxLineLength.isPresent());
        assertEquals(76, maxLineLength.getAsInt());

        assertThat(elementValue, containsString(encoded));
        assertThat(elementValue, startsWith("\n"));
        assertThat(elementValue, endsWith("\n"));

        assertEquals(encoded, encodedWithStream);
    }

    private String encodeToString(Class<?> xmlUtilsClass, byte[] bytes) throws ReflectiveOperationException {
        return (String) xmlUtilsClass.getMethod("encodeToString", byte[].class).invoke(null, (Object) bytes);
    }

    private String encodeElementValue(Class<?> xmlUtilsClass, byte[] bytes) throws ReflectiveOperationException {
        return (String) xmlUtilsClass.getMethod("encodeElementValue", byte[].class).invoke(null, (Object) bytes);
    }

    private OutputStream encodeStream(Class<?> xmlUtilsClass, OutputStream stream) throws ReflectiveOperationException {
        return (OutputStream) xmlUtilsClass.getMethod("encodeStream", OutputStream.class).invoke(null, stream);
    }

    private String encodeUsingStream(Class<?> xmlUtilsClass, byte[] bytes) throws ReflectiveOperationException, IOException {
        try (ByteArrayOutputStream encoded = new ByteArrayOutputStream();
             OutputStream raw = encodeStream(xmlUtilsClass, encoded)) {
            raw.write(bytes);
            raw.flush();
            return encoded.toString(StandardCharsets.US_ASCII);
        }
    }

    private static class ReloadingClassLoader extends ClassLoader {
        private Collection<String> classNames;

        public ReloadingClassLoader(ClassLoader parent, Collection<Class<?>> classes) {
            super("TestClassLoader", parent);
            this.classNames = classes.stream().map(Class::getName).collect(Collectors.toSet());
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (classNames.contains(name)) {
                Class<?> clazz = findClass(name);
                if (resolve) {
                    resolveClass(clazz);
                }
                return clazz;
            }
            return super.loadClass(name, resolve);
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            if (classNames.contains(name)) {
                Class<?> parentLoadedClass = getParent().loadClass(name);
                String resourceName = synthesizeClassName(parentLoadedClass) + ".class";
                byte[] classData;
                try (InputStream in = parentLoadedClass.getResourceAsStream(resourceName)) {
                    if (in == null) {
                        throw new ClassNotFoundException("Could not load class " + name);
                    }
                    classData = in.readAllBytes();
                } catch (IOException e) {
                    throw new ClassNotFoundException("Could not load class " + name, e);
                }

                return defineClass(name, classData, 0, classData.length);
            }
            throw new ClassNotFoundException("Class not found: " + name);
        }

        private String synthesizeClassName(Class<?> clazz) {
            String name = clazz.getSimpleName();
            if (clazz.isMemberClass()) name = synthesizeClassName(clazz.getEnclosingClass()) + "$" + name;
            return name;
        }
    }
}
