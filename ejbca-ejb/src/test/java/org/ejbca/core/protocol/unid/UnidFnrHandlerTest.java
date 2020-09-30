/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.unid;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.util.CeSecoreNameStyle;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.protocol.ExtendedUserDataHandler.HandlerException;
import org.ejbca.core.protocol.cmp.ICrmfRequestMessage;
import org.ejbca.core.protocol.unid.UnidFnrHandler.Storage;
import org.junit.Test;

/**
 * Testing of {@link UnidFnrHandler} .
 *
 * @version $Id: UnidFnrHandlerTest.java 28616 2018-04-03 11:51:50Z samuellb $
 */
public class UnidFnrHandlerTest {
	
    CmpConfiguration cmpConfiguration = new CmpConfiguration();
    String configAlias = "UnidFnrHandlerTestCmpConfigAlias";
    
    @Test
    public void test01() throws Exception {
        
        
        cmpConfiguration.addAlias(configAlias);
        
    	final String unidPrefix = "1234-5678-";
    	final String fnr = "90123456789";
    	final String lra = "01234";
    	final MyStorage storage = new MyStorage(unidPrefix, fnr, lra);
    	final RequestMessage reqIn = new MyIRequestMessage(fnr+'-'+lra);
    	final UnidFnrHandler handler = new UnidFnrHandler(storage);
    	final RequestMessage reqOut = handler.processRequestMessage(reqIn, unidPrefix+"_a_profile_name");
    	assertEquals(storage.unid, (reqOut.getRequestX500Name().getRDNs(CeSecoreNameStyle.SN)[0].getFirst().getValue()).toString());
    	
    	cmpConfiguration.removeAlias(configAlias);
    }
    
    @Test
    public void test02() throws Exception {
        
        cmpConfiguration.addAlias(configAlias);
        cmpConfiguration.setCertReqHandlerClass(configAlias, "org.ejbca.core.protocol.unid.UnidFnrHandler");
        
        final String unidPrefix = "1234-5678-";
        final String fnr = "90123456789";
        final String lra = "01234";
        final MyStorage storage = new MyStorage(unidPrefix, fnr, lra);
        final RequestMessage reqIn = new MyIRequestMessage(fnr+'-'+lra);
        final UnidFnrHandler handler = new UnidFnrHandler(storage);
        final RequestMessage reqOut = handler.processRequestMessage(reqIn, unidPrefix+"_a_profile_name");
        assertEquals(storage.unid, (reqOut.getRequestX500Name().getRDNs(CeSecoreNameStyle.SN)[0].getFirst().getValue()).toString());
        
        cmpConfiguration.removeAlias(configAlias);
    }
    
	private static class MyStorage implements Storage {
		final private String unidPrefix;
		final private String fnr;
		final private String lra;
		String unid;
		MyStorage( String _unidPrefix, String _fnr, String _lra) {
			this.unidPrefix = _unidPrefix;
			this.fnr = _fnr;
			this.lra = _lra;
		}
		@Override
		public void storeIt(String _unid, String _fnr) throws HandlerException {
			assertEquals(this.fnr, _fnr);
			assertEquals(this.unidPrefix, _unid.substring(0, 10));
			assertEquals(this.lra, _unid.substring(10, 15));
			this.unid = _unid;
		}
	}
	private static class MyIRequestMessage implements ICrmfRequestMessage {
		private static final long serialVersionUID = -2303591921932083436L;
        final X500Name dn;
        List<Certificate> additionalCaCertificates = new ArrayList<>();
        List<Certificate> additionalExtraCertsCertificates = new ArrayList<>();
        
		MyIRequestMessage(String serialNumber) {
		    X500NameBuilder nameBuilder = new X500NameBuilder(new CeSecoreNameStyle());
			nameBuilder.addRDN(CeSecoreNameStyle.SN, serialNumber);
			this.dn = nameBuilder.build();
		}
		@Override
		public String getUsername() {
			return null;
		}
		@Override
		public String getPassword() {
			return null;
		}
		@Override
		public String getIssuerDN() {
			return null;
		}
		@Override
		public BigInteger getSerialNo() {
			return null;
		}
		@Override
		public String getRequestDN() {
			return null;
		}
		@Override
		public X500Name getRequestX500Name() {
			return this.dn;
		}

		@Override
		public String getRequestAltNames() {
			return null;
		}
		@Override
		public Date getRequestValidityNotBefore() {
			return null;
		}
		@Override
		public Date getRequestValidityNotAfter() {
			return null;
		}
		@Override
		public Extensions getRequestExtensions() {
			return null;
		}
		@Override
		public String getCRLIssuerDN() {
			return null;
		}
		@Override
		public BigInteger getCRLSerialNo() {
			return null;
		}
		@Override
		public PublicKey getRequestPublicKey() throws InvalidKeyException,
				NoSuchAlgorithmException, NoSuchProviderException {
			return null;
		}
		@Override
		public boolean verify() throws InvalidKeyException,
				NoSuchAlgorithmException, NoSuchProviderException {
			return false;
		}
		@Override
		public boolean requireKeyInfo() {
			return false;
		}
		@Override
		public void setKeyInfo(Certificate cert, PrivateKey key, String provider) {
			// do nothing
		}
		@Override
		public int getErrorNo() {
			return 0;
		}
		@Override
		public String getErrorText() {
			return null;
		}
		@Override
		public String getSenderNonce() {
			return null;
		}
		@Override
		public String getTransactionId() {
			return null;
		}
		@Override
		public byte[] getRequestKeyInfo() {
			return null;
		}
		@Override
		public String getPreferredDigestAlg() {
			return null;
		}
		@Override
		public boolean includeCACert() {
			return false;
		}
		@Override
		public int getRequestType() {
			return 0;
		}
		@Override
		public int getRequestId() {
			return 0;
		}

	    @Override
	    public void setResponseKeyInfo(PrivateKey key, String provider) {
	    }

		@Override
		public int getPbeIterationCount() {
			return 0;
		}
		@Override
		public String getPbeDigestAlg() {
			return null;
		}
		@Override
		public String getPbeMacAlg() {
			return null;
		}
		@Override
		public String getPbeKeyId() {
			return null;
		}
		@Override
		public String getPbeKey() {
			return null;
		}
        @Override
        public boolean isImplicitConfirm() {
            return false;
        }
        @Override
        public PublicKey getProtocolEncrKey() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
            return null;
        }
        @Override
        public SubjectPublicKeyInfo getRequestSubjectPublicKeyInfo() {
            return null;
        }
        @Override
        public void setServerGenKeyPair(KeyPair serverGenKeyPair) {
        }
        @Override
        public KeyPair getServerGenKeyPair() {
            return null;
        }
        
        @Override
        public List<Certificate> getAdditionalCaCertificates() {
            return additionalCaCertificates;
        }
        @Override
        public void setAdditionalCaCertificates(final List<Certificate> certificates) {
            this.additionalCaCertificates = certificates;
        }
        @Override
        public List<Certificate> getAdditionalExtraCertsCertificates() {
            return this.additionalExtraCertsCertificates;
        }
        @Override
        public void setAdditionalExtraCertsCertificates(List<Certificate> certificates) {
            this.additionalExtraCertsCertificates = certificates;
        }
	}
}
