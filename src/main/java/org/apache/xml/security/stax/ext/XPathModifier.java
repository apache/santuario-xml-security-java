package org.apache.xml.security.stax.ext;

import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

/**
 * The XPath modifier defines the structure of the skeleton DOM elements which are passed to
 * {@link ElementSelector#select(XMLSecStartElement, OutputProcessorChain)}.
 * The parameter is passed in the security context and can be accessed by the element selector using {@code
 * outputProcessorChain.getSecurityContext().get(Element.class)}.
 * </pre>
 *
 * <table>
 *     <tr>
 *         <th>{@code XPathModifier}</th>
 *         <th>Properties</th>
 *     </tr>
 *     <tr>
 *         <td>{@code Node}</td>
 *         <td>
 *             The skeleton element has basic DOM element properties and is never {@code null}.
 *             It does not preserve any ancestors.
 *             Its parent is always the document element, making it a root element.
 *         </td>
 *     </tr>
 *     <tr>
 *         <td><b>{@code Path} (default)</b></td>
 *         <td>
 *             The skeleton element has basic DOM element properties and is never {@code null}.
 *             It preserves all ancestors up till the current element, all the way up to the document element,
 *             but no siblings.
 *             It is the default because it preserves the most information while still uses bounded memory for
 *             infinitely large XML streams (which is why you want to use streaming XML in the first place).
 *         </td>
 *     </tr>
 *     <tr>
 *         <td>{@code Tree}</td>
 *         <td>
 *             The skeleton element has basic DOM element properties and is never {@code null}.
 *             It preserves all ancestors and siblings up till the current element.
 *             It should be used with care because it uses unbounded memory for infinitely large XML streams.
 *         </td>
 *     </tr>
 * </table>
 */
public enum XPathModifier {

    Node, Path, Tree
}
