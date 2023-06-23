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
package org.apache.xml.security.test.stax.utils;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.InputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;

import org.apache.xml.security.stax.ext.XMLSecurityUtils;
import org.eclipse.jetty.http.MimeTypes;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

/**
 */
public class HttpRequestRedirectorProxy {
    private static final Logger LOG = System.getLogger(HttpRequestRedirectorProxy.class.getName());

    private static final int startPort = 31280;
    private static Server httpServer;

    public static Proxy startHttpEngine() throws Exception {

        int port = startPort;

        while (true) {
            try (ServerSocket ss = new ServerSocket(port)) {
                ss.setReuseAddress(true);
                //ok no exception so the port must be free
                break;
            } catch (IOException e) {
                port++;
            }
        }

        httpServer = new Server(port);
        /*ResourceHandler resourceHandler = new ResourceHandler();
        resourceHandler.setDirectoriesListed(true);
        resourceHandler.setResourceBase(".");
        httpServer.setHandler(resourceHandler);*/

        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.NO_SESSIONS);
        context.setContextPath("/");
        httpServer.setHandler(context);
        context.addServlet(new ServletHolder(new TestingHttpProxyServlet()), "/*");
        httpServer.start();

        return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port));
    }

    public static void stopHttpEngine() throws Exception {
        httpServer.stop();
    }

    static class TestingHttpProxyServlet extends HttpServlet {

        private static final long serialVersionUID = -6720321975901047227L;
        private static MimeTypes mimeTypes = new MimeTypes();
        private static List<String> paths = new ArrayList<>();

        static {
            paths.add("ie/baltimore/merlin-examples/merlin-xmldsig-twenty-three");
            paths.add("com/pothole/xmldsig");
            paths.add("org/apache/xml/security/test/javax/xml/crypto/dsig");
        }

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            String requestLine = req.getRequestURL().toString();
            String file = requestLine.substring(requestLine.lastIndexOf('/'));
            for (String path : paths) {
                String filePath = path + file;
                try (InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream(filePath)) {
                    if (inputStream == null) {
                        continue;
                    }
                    LOG.log(Level.DEBUG, "Providing resource {0}", filePath);
                    String mime = mimeTypes.getMimeByExtension(req.getPathInfo());
                    if (mime != null) {
                        resp.setContentType(mime);
                    }
                    XMLSecurityUtils.copy(inputStream, resp.getOutputStream());
                    return;
                }
            }
            LOG.log(Level.INFO, "Unable to serve request line {0}, the file name was not found.", requestLine);
            resp.sendError(HttpServletResponse.SC_NOT_FOUND);
        }
    }
}
