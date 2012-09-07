/**
 * 
 */
package com.justnudge.test;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Michael Ransley
 *
 */
public class KeystoreServlet extends HttpServlet {

	private static final long serialVersionUID = 8566487082363078798L;
	private Logger logger = Logger.getLogger(KeystoreServlet.class.getName());

	/**
	 * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		try {
			String configRoot = System.getenv("CONFIG_ROOT");
			String cellName = System.getenv("WAS_CELL");
			String keyStorePath = configRoot + "/cells/" + cellName + "/trust.p12";
			KeyStore keystore = KeyStore.getInstance("PKCS12");
			FileInputStream stream = new FileInputStream(keyStorePath);
			keystore.load(stream, "WebAS".toCharArray());
			StringBuilder message = new StringBuilder("<html><head><title>Certificates</title></head><body><ul>");
			Enumeration<String> aliases = keystore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				Certificate cert = keystore.getCertificate(alias);
				message.append("<li>").append(alias).append("=").append(cert.toString()).append("</li>");
			}
			message.append("</ul></body></html>");
			resp.getWriter().write(message.toString());
		} catch (Exception e) {
			logger.log(Level.SEVERE, "Problem opening keystore", e);
		}
	}
}
