package pl.com.marcing.tools;

import java.io.IOException;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.openssl.PEMParser;

/**
 *
 * @author MarcinG-dev
 */
public class CertGrabber {

	/**
	 * TODO: add different algorithms SSL Supports some version of SSL; may
	 * support other versions SSLv2 Supports SSL version 2 or later; may support
	 * other versions SSLv3 Supports SSL version 3; may support other versions
	 * TLS Supports some version of TLS; may support other versions TLSv1
	 * Supports RFC 2246: TLS version 1.0 ; may support other versions TLSv1.1
	 * Supports RFC 4346: TLS version 1.1 ; may support other versions TLSv1.2
	 */
	public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
	public static final String END_CERT = "-----END CERTIFICATE-----";
	private static final Logger log = Logger.getLogger(CertGrabber.class.getName());
	private static X509Certificate serverCert;

	private static final Options options = new Options();

	static {
		Option help = new Option("h", "help", false, "print this message");
		options.addOption(help);
		Option optDebug = new Option("d", "debug", false, "debug mode");
		options.addOption(optDebug);
		Option optTarget = OptionBuilder.withLongOpt("target").withArgName("hostname").hasArg().withDescription("target hostname/ip").create("t");
		options.addOption(optTarget);
		Option optPort = OptionBuilder.withLongOpt("port").withArgName("port").hasArg().withDescription("target port").create("p");
		options.addOption(optPort);
		Option optTimeout = OptionBuilder.withLongOpt("timeout").withArgName("seconds").hasArg().withDescription("connection timeout in seconds (default 5)").create("w");
		options.addOption(optTimeout);
	}

	private static final TrustManager[] trustAllCerts = new TrustManager[]{
		new X509TrustManager() {

			@Override
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			@Override
			public void checkClientTrusted(
					java.security.cert.X509Certificate[] certs, String authType) {
			}

			@Override
			public void checkServerTrusted(
					java.security.cert.X509Certificate[] serverCerts, String authType) {
				if (serverCerts.length > 0) {
					if (serverCerts[0] instanceof X509Certificate) {
						serverCert = (X509Certificate) serverCerts[0];
					}
				}
			}
		}
	};

	public static void main(String[] args) throws KeyManagementException, NoSuchAlgorithmException, IOException, CertificateEncodingException, CertificateParsingException {
		Security.addProvider(new BouncyCastleProvider());
		CommandLineParser parser = new BasicParser();
		CommandLine cmdLine = null;

		int portNumber = -1;
		String hostname;
		int timeout = 5;
		boolean debug;

		try {
			cmdLine = parser.parse(options, args);
		} catch (ParseException exp) {
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp(200, "java -jar jCertGrabber.jar", null, options, null);
			return;
		}
		if (cmdLine.hasOption("h") || (!cmdLine.hasOption("t") && !cmdLine.hasOption("p"))) {
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp(200, "java -jar jCertGrabber.jar", null, options, null);
			return;
		}
		if (cmdLine.hasOption("p")) {
			portNumber = Integer.parseInt(cmdLine.getOptionValue("p"));
		}
		if (cmdLine.hasOption("w")) {
			timeout = Integer.parseInt(cmdLine.getOptionValue("w"));
		}
		debug = cmdLine.hasOption("d");
		hostname = cmdLine.getOptionValue("t");

		SSLContext sc = SSLContext.getInstance("SSL");
		sc.init(null, trustAllCerts, new java.security.SecureRandom());
		SSLSocketFactory socketFactory = sc.getSocketFactory();
		Socket tmpSocket = new Socket();
		SocketAddress address = new InetSocketAddress(hostname, portNumber);
		tmpSocket.connect(address, timeout * 1000);
		SSLSocket socket = (SSLSocket) socketFactory.createSocket(tmpSocket, hostname, portNumber, true);
		socket.setSoTimeout(10000);
		try {
			socket.startHandshake();
		} catch (Exception e) {
		}
		try {
			socket.close();
			tmpSocket.close();
		} catch (IOException e) {
		}
		System.out.println("[+] got server cert");
		PEMParser pemParser = new PEMParser(new StringReader(BEGIN_CERT+"\n"+Base64.encodeBase64String(serverCert.getEncoded())+"\n"+END_CERT));
		X509CertificateHolder certHolder = (X509CertificateHolder) pemParser.readObject();
		X509CertificateObject testCert = new X509CertificateObject(certHolder.toASN1Structure());
		System.out.println(testCert);
        System.out.println(BEGIN_CERT);
		System.out.println(Base64.encodeBase64String(serverCert.getEncoded()));
        System.out.println(END_CERT);
	}

}
