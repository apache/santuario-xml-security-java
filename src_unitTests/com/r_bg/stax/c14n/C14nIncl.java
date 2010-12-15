package com.r_bg.stax.c14n;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import junit.framework.TestCase;

public class C14nIncl extends TestCase {

	public static void main(String[] args) {
	}
	public static void testRfc3_1() throws Exception {
		String in="<?xml version=\"1.0\"?>\n" + 
				"\n" + 
				"<?xml-stylesheet   href=\"doc.xsl\"\n" + 
				"   type=\"text/xsl\"   ?>\n" + 
				"\n" + 
				"<!DOCTYPE doc SYSTEM \"doc.dtd\">\n" + 
				"\n" + 
				"<doc>Hello, world!<!-- Comment 1 --></doc>\n" + 
				"\n" + 
				"<?pi-without-data     ?>\n" + 
				"\n" + 
				"<!-- Comment 2 -->\n" + 
				"\n" + 
				"<!-- Comment 3 -->";
		String outWithoutComments="<?xml-stylesheet href=\"doc.xsl\"\n" + 
				"   type=\"text/xsl\"   ?>\n" + 
				"<doc>Hello, world!</doc>\n" + 
				"<?pi-without-data?>";
		String outWithComments="<?xml-stylesheet href=\"doc.xsl\"\n" + 
				"   type=\"text/xsl\"   ?>\n" + 
				"<doc>Hello, world!<!-- Comment 1 --></doc>\n" + 
				"<?pi-without-data?>\n" + 
				"<!-- Comment 2 -->\n" + 
				"<!-- Comment 3 -->";
		XMLInputFactory im=XMLInputFactory.newInstance();
		im.setProperty("javax.xml.stream.supportDTD", new Boolean(false));
		XMLStreamReader reader=im.createXMLStreamReader(new ByteArrayInputStream(in.getBytes()));		
		assertEquals("Output not like stated in 3.1 rfc",outWithoutComments,
				C14n.cannoicalizeWithoutComments(reader,new C14nInclusive()));
		
	}
	public static void testRfc3_2() throws Exception {
		String in="<doc>\n" + 
				"   <clean>   </clean>\n" + 
				"   <dirty>   A   B   </dirty>\n" + 
				"   <mixed>\n" + 
				"      A\n" + 
				"      <clean>   </clean>\n" + 
				"      B\n" + 
				"      <dirty>   A   B   </dirty>\n" + 
				"      C\n" + 
				"   </mixed>\n" + 
				"</doc>";
		String outWithoutComments="<doc>\n" + 
				"   <clean>   </clean>\n" + 
				"   <dirty>   A   B   </dirty>\n" + 
				"   <mixed>\n" + 
				"      A\n" + 
				"      <clean>   </clean>\n" + 
				"      B\n" + 
				"      <dirty>   A   B   </dirty>\n" + 
				"      C\n" + 
				"   </mixed>\n" + 
				"</doc>";
		XMLInputFactory im=XMLInputFactory.newInstance();
		im.setProperty("javax.xml.stream.supportDTD", new Boolean(false));
		XMLStreamReader reader=im.createXMLStreamReader(new ByteArrayInputStream(in.getBytes()));		
		assertEquals("Output not like stated in 3.1 rfc",outWithoutComments,
				C14n.cannoicalizeWithoutComments(reader,new C14nInclusive()));
		
	}
	public static void testOrderInAttributes() throws Exception {
		String in="<!DOCTYPE doc [<!ATTLIST e9 attr CDATA \"default\">]>\n" + 
				"<doc xmlns:b=\"http://www.ietf.org\">" + 
				"     <doc2 xmlns:a=\"http://www.w3.org\">" + 
				"      <doc3 xmlns=\"http://example.org\">\n" + 
				"   <e3   name = \"elem3\"   id=\"elem3\"   />\n" + 
				"   <e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I\'m\"\n" + 
				"      />\n" + 								
				"</doc3></doc2></doc>";
		String outWithoutComments="<doc xmlns:b=\"http://www.ietf.org\">     <doc2 xmlns:a=\"http://www.w3.org\">      <doc3 xmlns=\"http://example.org\">\n" + 
				"   <e3 id=\"elem3\" name=\"elem3\"></e3>\n" + 
				"   <e5 attr=\"I\'m\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>\n" + 
				"</doc3></doc2></doc>";
		XMLInputFactory im=XMLInputFactory.newInstance();
		im.setProperty("javax.xml.stream.supportDTD", new Boolean(false));
		XMLStreamReader reader=im.createXMLStreamReader(new ByteArrayInputStream(in.getBytes()));		
		assertEquals("Output not like stated in 3.1 rfc",outWithoutComments,
				C14n.cannoicalizeWithoutComments(reader,new C14nInclusive()));		
		
	}
	public static void testOrderBetwenAttributesAndNss() throws Exception {
		String in="<!DOCTYPE doc [<!ATTLIST e9 attr CDATA \"default\">]>\n" + 
				"<doc>\n"+
				"   <e3   name = \"elem3\" xmlns=\"http://a.com/\"  id=\"elem3\"   />\n" + 
				"</doc>";
		String outWithoutComments="<doc>\n"+
			"   <e3 xmlns=\"http://a.com/\" id=\"elem3\" name=\"elem3\"></e3>\n" + 
			"</doc>";
		XMLInputFactory im=XMLInputFactory.newInstance();
		im.setProperty("javax.xml.stream.supportDTD", new Boolean(false));
		XMLStreamReader reader=im.createXMLStreamReader(new ByteArrayInputStream(in.getBytes()));
		
		assertEquals("Output not like stated in 3.1 rfc",outWithoutComments,
				C14n.cannoicalizeWithoutComments(reader,new C14nInclusive()));
		
	}
	public static void testRfc3_3() throws Exception {
		String in="<!DOCTYPE doc [<!ATTLIST e9 attr CDATA \"default\">]>\n" + 
				"<doc>\n" + 
				"   <e1   />\n" + 
				"   <e2   ></e2>\n" + 
				"   <e3   name = \"elem3\"   id=\"elem3\"   />\n" + 
				"   <e4   name=\"elem4\"   id=\"elem4\"   ></e4>\n" + 
				"   <e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I\'m\"\n" + 
				"      xmlns:b=\"http://www.ietf.org\"\n" + 
				"      xmlns:a=\"http://www.w3.org\"\n" + 
				"      xmlns=\"http://example.org\"/>\n" + 
				"   <e6 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n" + 
				"      <e7 xmlns=\"http://www.ietf.org\">\n" + 
				"         <e8 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n" + 
				"            <e9 xmlns=\"\" xmlns:a=\"http://www.ietf.org\"/>\n" + 
				"         </e8>\n" + 
				"      </e7>\n" + 
				"   </e6>\n" + 
				"</doc>";
		String outWithoutComments="<doc>\n" + 
				"   <e1></e1>\n" + 
				"   <e2></e2>\n" + 
				"   <e3 id=\"elem3\" name=\"elem3\"></e3>\n" + 
				"   <e4 id=\"elem4\" name=\"elem4\"></e4>\n" + 
				"   <e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" attr=\"I\'m\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>\n" + 
				"   <e6 xmlns:a=\"http://www.w3.org\">\n" + 
				"      <e7 xmlns=\"http://www.ietf.org\">\n" + 
				"         <e8 xmlns=\"\">\n" + 
				"            <e9 xmlns:a=\"http://www.ietf.org\" attr=\"default\"></e9>\n" + 
				"         </e8>\n" + 
				"      </e7>\n" + 
				"   </e6>\n" + 
				"</doc>";
		XMLInputFactory im=XMLInputFactory.newInstance();
		//im.setProperty("javax.xml.stream.supportDTD", new Boolean(false));
		XMLStreamReader reader=im.createXMLStreamReader(new ByteArrayInputStream(in.getBytes()));		
		assertEquals("Output not like stated in 3.1 rfc",outWithoutComments,
				C14n.cannoicalizeWithoutComments(reader,new C14nInclusive()));
		ByteArrayOutputStream os=new ByteArrayOutputStream();
		C14n c=new C14n(new C14nInclusive(),os);
		reader=im.createXMLStreamReader(new ByteArrayInputStream(in.getBytes()));
		reader=im.createFilteredReader(reader,c);
		while ((reader.getEventType())!=XMLStreamReader.END_DOCUMENT) {
			reader.next();
		}
		assertEquals("Output not like stated in 3.1 rfc",outWithoutComments,
				new String(os.toByteArray()));
		
		
		
	}

	
	protected void setUp() throws Exception {
		super.setUp();
	}

}
