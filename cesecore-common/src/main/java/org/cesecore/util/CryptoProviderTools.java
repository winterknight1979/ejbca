package org.cesecore.util;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptoProviderTools {
	
	 public static synchronized void installBCProviderIfNotAvailable() {
	    	if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
	    		installBCProvider();
	    	}
	    }

	private static void installBCProvider() {
		// TODO Auto-generated method stub
		
	}

}
