package com.r_bg.stax;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.XMLValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import sun.security.rsa.RSAKeyFactory;
import sun.security.rsa.RSAPrivateKeyImpl;

import junit.framework.TestCase;

public class XMLSignatureTest extends TestCase {
	static Key getKey() throws Exception {
		byte[] modulus=Base64.decode("skqbW7oBwM1lCWNwC1obkgj4VV58G1AX7ERMWEIrQQlZ8uFdQ3FNkgMdtmx/XUjNF+zXTDmxe+K/\n" + 
		         "lne+0KDwLWskqhS6gnkQmxZoR4FUovqRngoqU6bnnn0pM9gF/AI/vcdu7aowbF9S7TVlSw7IpxIQ\n" + 
		         "VjevEfohDpn/+oxljm0=\n");
		byte[] exponent=Base64.decode("AQAB");
		RSAPublicKeySpec spec=new RSAPublicKeySpec(new BigInteger(1,modulus),new BigInteger(1,exponent));
		return KeyFactory.getInstance("rsa").generatePublic(spec);
	}
	static PrivateKey obtainPrivateKey() throws Exception {
		KeyStore ks = KeyStore.getInstance("JKS");
	      FileInputStream fis = new FileInputStream("keystore.jks");

	      ks.load(fis, "secret".toCharArray());
	      return (PrivateKey) ks.getKey("tfc",
	                                 "secret".toCharArray());
	}
	static PublicKey obtainPublicKey() throws Exception {
		KeyStore ks = KeyStore.getInstance("JKS");
	      FileInputStream fis = new FileInputStream("keystore.jks");

	      ks.load(fis, "secret".toCharArray());
	       return ks.getCertificate("tfc").getPublicKey();	      
	      
	}
	
	static String generateSignature(int size,String name) throws Exception{
		DocumentBuilderFactory fact=DocumentBuilderFactory.newInstance();
		fact.setNamespaceAware(true);
		Document doc=fact.newDocumentBuilder().newDocument();
		org.apache.xml.security.signature.XMLSignature sig=new org.apache.xml.security.signature.XMLSignature(doc,"", 
				org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1,
				Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		Transforms trs=new Transforms(doc);
		trs.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
		sig.addDocument("#1",trs);
		doc.appendChild(sig.getElement());		
		ObjectContainer ob=new ObjectContainer(doc);
		ob.setId("1");		
		sig.appendObject(ob);
		sig.addKeyInfo(obtainPublicKey());
		for (int i=0;i<size;i++) {
			Element el=doc.createElement("Prueba");
			Element el2=doc.createElement("SubPrueba");
			el2.appendChild(doc.createTextNode("Prueba de firmas gordas"));
			el.appendChild(el2);
			Element el3=doc.createElement("SubPrueba");
			el3.appendChild(doc.createElement("SubSubPrueba"));
			el3.appendChild(doc.createTextNode("Otro textillo por aqui"));
			el2.appendChild(el3);
			el.appendChild(doc.createTextNode("\n"));
			ob.appendChild(el);
		}
		
		sig.sign(obtainPrivateKey());
		FileOutputStream bos=new FileOutputStream(name); 
		XMLUtils.outputDOM(doc, bos);
		//System.out.println(bos.toByteArray().length);		
		return "";
	}
	static Key checkSignature(String sig) throws Exception {
		DocumentBuilderFactory fact=DocumentBuilderFactory.newInstance();
		fact.setNamespaceAware(true);
		Document doc=fact.newDocumentBuilder().parse(new ByteArrayInputStream(sig.getBytes()));
		org.apache.xml.security.signature.XMLSignature signature = new org.apache.xml.security.signature.XMLSignature((Element)doc.getDocumentElement().getFirstChild(),"");
		System.out.println("Her:"+signature.checkSignatureValue(signature.getKeyInfo().getPublicKey()));
		System.out.println("Her2:"+(getKey().equals(signature.getKeyInfo().getPublicKey()))) ;
		return signature.getKeyInfo().getPublicKey();
	}
	public void testEnvelopedSignature() throws Exception {
		String in="<RootObject><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
         "<ds:SignedInfo>\n" + 
         "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" + 
         "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" + 
         "<ds:Reference URI=\"#1\">\n" + 
         "<ds:Transforms>\n" + 
         "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:Transform>\n" + 
         "</ds:Transforms>\n" + 
         "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></ds:DigestMethod>\n" + 
         "<ds:DigestValue>oMQoFufPA7Un6cfz0GaEOJpE4Z8=</ds:DigestValue>\n" + 
         "</ds:Reference>\n" + 
         "</ds:SignedInfo>\n" + 
         "<ds:SignatureValue>\n" + 
         "AhyiFQ6hucykYJOJDBV3wbPBe2TAURXXfCUD7BmSAecT+izT9fHFsxRVez3s+6hYSgtaVhmeVgbd\n" + 
         "ZEOMPFihBGldi1NV73Z/tpXxqNvY+/NwQmmasQp9gzFHxYF2cqi8m7sAHM03BIC1YoBctxVw/jxV\n" + 
         "ClhLJuTSHoKwlzKH24g=\n" + 
         "</ds:SignatureValue>\n" + 
         "<ds:KeyInfo>\n" + 
         "<ds:KeyValue>\n" + 
         "<ds:RSAKeyValue>\n" + 
         "<ds:Modulus>\n" + 
         "skqbW7oBwM1lCWNwC1obkgj4VV58G1AX7ERMWEIrQQlZ8uFdQ3FNkgMdtmx/XUjNF+zXTDmxe+K/\n" + 
         "lne+0KDwLWskqhS6gnkQmxZoR4FUovqRngoqU6bnnn0pM9gF/AI/vcdu7aowbF9S7TVlSw7IpxIQ\n" + 
         "VjevEfohDpn/+oxljm0=\n" + 
         "</ds:Modulus>\n" + 
         "<ds:Exponent>AQAB</ds:Exponent>\n" + 
         "</ds:RSAKeyValue>\n" + 
         "</ds:KeyValue>\n" + 
         "</ds:KeyInfo>\n" + 
         "<ds:Object Id=\"1\"><UnderObject>A text in a box<OtherObject><OtherObject2></OtherObject2><OtherObject6></OtherObject6><OtherObject></OtherObject></OtherObject></UnderObject></ds:Object>\n" + 
         "</ds:Signature></RootObject>";			
		XMLInputFactory im=XMLInputFactory.newInstance();		
		im.setProperty("javax.xml.stream.supportDTD", new Boolean(false));		
		XMLStreamReader reader=im.createXMLStreamReader(new ByteArrayInputStream(in.getBytes()));
		StaxValidateContext stx = StaxValidateContext.createEnvolopedValidator(getKey(),reader);		
		reader=im.createFilteredReader(reader, stx.getStreamFilter());
		while ((reader.getEventType())!=XMLStreamReader.END_DOCUMENT) {
			reader.next();
		}		
		XMLSignatureFactory fac=XMLSignatureFactory.getInstance("Stax", new com.r_bg.stax.StaxProvider());
		stx.setSignatureNumber(0);
		XMLSignature sig=fac.unmarshalXMLSignature(stx);	
		if (!((Reference)sig.getSignedInfo().getReferences().get(0)).validate(stx)) {
			//Firma invalida.
		}
		//generateSignature(262144/34,"Enveloped1MB.xml");
		assertTrue("Signature References must be right",
				((Reference)sig.getSignedInfo().getReferences().get(0)).validate(stx));
		assertTrue("Signature must be right",
				sig.validate(stx));
	}
	public void testTamperedEnvelopedSignature() throws Exception {
		String in="<RootObject><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
         "<ds:SignedInfo>\n" + 
         "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" + 
         "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n" + 
         "<ds:Reference URI=\"#1\">\n" + 
         "<ds:Transforms>\n" + 
         "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:Transform>\n" + 
         "</ds:Transforms>\n" + 
         "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></ds:DigestMethod>\n" + 
         "<ds:DigestValue>oMQoFufPA7Un6cfz0GaEOJpE4Z8=</ds:DigestValue>\n" + 
         "</ds:Reference>\n" + 
         "</ds:SignedInfo>\n" + 
         "<ds:SignatureValue>\n" + 
         "AhyiFQ6hucykYJOJDBV3wbPBe2TAURXXfCUD7BmSAecT+izT9fHFsxRVez3s+6hYSgtaVhmeVgbd\n" + 
         "ZEOMPFihBGldi1NV73Z/tpXxqNvY+/NwQmmasQp9gzFHxYF2cqi8m7sAHM03BIC1YoBctxVw/jxV\n" + 
         "ClhLJuTSHoKwlzKH24g=\n" + 
         "</ds:SignatureValue>\n" + 
         "<ds:KeyInfo>\n" + 
         "<ds:KeyValue>\n" + 
         "<ds:RSAKeyValue>\n" + 
         "<ds:Modulus>\n" + 
         "skqbW7oBwM1lCWNwC1obkgj4VV58G1AX7ERMWEIrQQlZ8uFdQ3FNkgMdtmx/XUjNF+zXTDmxe+K/\n" + 
         "lne+0KDwLWskqhS6gnkQmxZoR4FUovqRngoqU6bnnn0pM9gF/AI/vcdu7aowbF9S7TVlSw7IpxIQ\n" + 
         "VjevEfohDpn/+oxljm0=\n" + 
         "</ds:Modulus>\n" + 
         "<ds:Exponent>AQAB</ds:Exponent>\n" + 
         "</ds:RSAKeyValue>\n" + 
         "</ds:KeyValue>\n" + 
         "</ds:KeyInfo>\n" + 
         "<ds:Object Id=\"1\"><UnderObject>a text in a box<OtherObject><OtherObject2></OtherObject2><OtherObject6></OtherObject6><OtherObject></OtherObject></OtherObject></UnderObject></ds:Object>\n" + 
         "</ds:Signature></RootObject>";
		XMLInputFactory im=XMLInputFactory.newInstance();		
		im.setProperty("javax.xml.stream.supportDTD", new Boolean(false));		
		XMLStreamReader reader=im.createXMLStreamReader(new ByteArrayInputStream(in.getBytes()));
		StaxValidateContext stx = StaxValidateContext.createEnvolopedValidator(getKey(),reader);		
		reader=im.createFilteredReader(reader, stx.getStreamFilter());
		while ((reader.getEventType())!=XMLStreamReader.END_DOCUMENT) {
			reader.next();
		}		
		XMLSignatureFactory fac=XMLSignatureFactory.getInstance("Stax", new com.r_bg.stax.StaxProvider() );
		stx.setSignatureNumber(0);
		XMLSignature sig=fac.unmarshalXMLSignature(stx);
		assertFalse("Signature must be wrong",
				((Reference)sig.getSignedInfo().getReferences().get(0)).validate(stx));
		assertFalse("Signature must be false",
				sig.validate(stx));
	}
	final static String ALUMNO_NS="http://fi.upm.es/alumnos/1/0";
	public void atestParsing() throws Exception {		
		XMLInputFactory im=XMLInputFactory.newInstance();		
		im.setProperty("javax.xml.stream.supportDTD", new Boolean(false));		
		XMLStreamReader reader=im.createXMLStreamReader(new FileInputStream("alumnoEnveloped.xml"));
		StaxValidateContext stx = StaxValidateContext.createEnvolopedValidator(getKey(),reader);		
		reader=im.createFilteredReader(reader, stx.getStreamFilter());		
		String nombre=null;
	    String apellidos=null;
 	    do {
			if (reader.getEventType()==XMLStreamReader.START_ELEMENT) {
				if (!ALUMNO_NS.equals(reader.getNamespaceURI()))
					continue;
				if ("Nombre".equals(reader.getLocalName())) {
					reader.next();
					nombre=reader.getText();
					continue;
				}
				if ("Apellidos".equals(reader.getLocalName())) {
					reader.next();
					apellidos=reader.getText();
					continue;
				}
			}
			reader.next();
		} while ((reader.getEventType())!=XMLStreamReader.END_DOCUMENT);
		System.out.println("Nombre: "+nombre+" Apellidos:"+apellidos);
		XMLSignatureFactory fac=XMLSignatureFactory.getInstance("Stax", new com.r_bg.stax.StaxProvider());
		stx.setSignatureNumber(0);
		XMLSignature sig=fac.unmarshalXMLSignature(stx);	
		if (!sig.validate(stx)) {
			//Firma invalida.
			System.out.println("Firma Invalida");
		}
	}
	
	
	static {		
		Init.init();
		
		StaxXMLSignatureFactory.getInstance("Stax", new StaxProvider());

	};

}
