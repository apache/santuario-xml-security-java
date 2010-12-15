package com.r_bg.stax.c14n;

import junit.framework.TestCase;

import java.io.ByteArrayInputStream;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;



public class C14nUnknown extends TestCase {
		public void testStandard() throws Exception {
			String in="<doc xmlns:a=\"http://a\">\n" + 
					" <a:a xmlns=\"http://a\">\n" + 
					"  <b/>\n" + 
					" </a:a>\n" + 
					"</doc>";
			String out="<doc>\n" + 
					" <a:a xmlns:a=\"http://a\">\n" + 
					"  <b xmlns=\"http://a\"></b>\n" + 
					" </a:a>\n" + 
					"</doc>";
			XMLInputFactory im=XMLInputFactory.newInstance();		
			im.setProperty("javax.xml.stream.supportDTD", new Boolean(false));		
			XMLStreamReader reader=im.createXMLStreamReader(new ByteArrayInputStream(in.getBytes()));
			assertEquals("mismath",out,
					C14n.cannoicalizeWithoutComments(reader,new AttributeHandleExclusive()));
		}
}

