package org.cesecore.util;

import java.io.ByteArrayInputStream;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;

public class CertTools {

	private static final Logger log = Logger.getLogger(CertTools.class);


	/**
	 * Creates Certificate from byte[], can be either an X509 certificate or a CVCCertificate
	 * 
	 * @param cert byte array containing certificate in binary (DER) format, or PEM encoded X.509 certificate
	 * @param provider provider for example "SUN" or "BC", use null for the default provider (BC)
	 * @param returnType the type of Certificate to be returned. Certificate can be used if certificate type is unknown.
	 * 
	 * @return a Certificate 
	 * @throws CertificateParsingException if certificate couldn't be parsed from cert, or if the incorrect return type was specified.
	 * 
	 */
	@SuppressWarnings("unchecked")
	public static <T extends Certificate> T getCertfromByteArray(byte[] cert, String provider, Class<T> returnType) throws CertificateParsingException {
		T ret = null;
		String prov = provider;
		if (prov == null) {
			prov = BouncyCastleProvider.PROVIDER_NAME;
		}

		if (returnType.equals(X509Certificate.class)) {
			ret = (T) parseX509Certificate(prov, cert);
		} else if (returnType.equals(CardVerifiableCertificate.class)) {
			ret = (T) parseCardVerifiableCertificate(prov, cert);
		} else {
			// Let's guess
			try {
				ret = (T) parseX509Certificate(prov, cert);
			} catch (CertificateParsingException e) {
				try {
					ret = (T) parseCardVerifiableCertificate(prov, cert);
				} catch (CertificateParsingException e1) {
					throw new CertificateParsingException("No certificate could be parsed from byte array. See debug logs for details.");
				}
			}
		}

		return ret;
	}

	/**
	 * 
	 * @param provider a provider name 
	 * @param cert a byte array containing an encoded certificate
	 * @return a decoded X509Certificate
	 * @throws CertificateParsingException if the byte array wasn't valid, or contained a certificate other than an X509 Certificate. 
	 */
	private static X509Certificate parseX509Certificate(String provider, byte[] cert) throws CertificateParsingException {
		final CertificateFactory cf = CertTools.getCertificateFactory(provider);
		X509Certificate result;
		try {  
			result = (X509Certificate) cf.generateCertificate(new SecurityFilterInputStream(new ByteArrayInputStream(cert))); 
		} catch (CertificateException e) {
			throw new CertificateParsingException("Could not parse byte array as X509Certificate." + e.getCause().getMessage(), e);
		}
		if(result != null) {
			return result;
		} else {
			throw new CertificateParsingException("Could not parse byte array as X509Certificate.");
		}
	}



	private static CardVerifiableCertificate parseCardVerifiableCertificate(String provider, byte[] cert) throws CertificateParsingException {
		// We could not create an X509Certificate, see if it is a CVC certificate instead
		try {
			final CVCertificate parsedObject = CertificateParser.parseCertificate(cert);
			return new CardVerifiableCertificate(parsedObject);
		} catch (ParseException e) {
			throw new CertificateParsingException("ParseException trying to read CVCCertificate.", e);
		} catch (ConstructionException e) {
			throw new CertificateParsingException("ConstructionException trying to read CVCCertificate.", e);
		} 
	}

	/**
	 * @param returnType the type of Certificate to be returned, for example X509Certificate.class. Certificate.class can be used if certificate type is unknown.
	 * 
	 * @throws CertificateParsingException if the byte array does not contain a proper certificate.
	 */
	public static <T extends Certificate> T getCertfromByteArray(byte[] cert, Class<T> returnType) throws CertificateParsingException {
		return getCertfromByteArray(cert, BouncyCastleProvider.PROVIDER_NAME, returnType);
	}

	private static CertificateFactory getCertificateFactory( final String provider) {
		final String prov;
		if (provider == null) {
			prov = BouncyCastleProvider.PROVIDER_NAME;
		} else {
			prov = provider;
		}
		if (BouncyCastleProvider.PROVIDER_NAME.equals(prov)) {
			CryptoProviderTools.installBCProviderIfNotAvailable();
		}
		try {
			return CertificateFactory.getInstance("X.509", prov);
		} catch (NoSuchProviderException nspe) {
			log.error("NoSuchProvider: ", nspe);
		} catch (CertificateException ce) {
			log.error("CertificateException: ", ce);
		}
		return null;
	}

}
