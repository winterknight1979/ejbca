package org.cesecore.authorization.user.matchvalues;

import java.util.List;

import org.cesecore.authorization.user.AccessMatchType;

public enum X500PrincipalAccessMatchValue implements AccessMatchValue {
	WITH_SERIALNUMBER, WITH_FULLDN, WITH_COUNTRY, WITH_DOMAINCOMPONENT, WITH_STATEORPROVINCE, WITH_LOCALITY, WITH_ORGANIZATION, WITH_ORGANIZATIONALUNIT, WITH_TITLE, WITH_DNSERIALNUMBER, WITH_COMMONNAME, WITH_UID, WITH_DNEMAILADDRESS, WITH_RFC822NAME, WITH_UPN
	;

	@Override
	public int getNumericValue() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public String getTokenType() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isIssuedByCa() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isDefaultValue() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public List<AccessMatchType> getAvailableAccessMatchTypes() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String normalizeMatchValue(String value) {
		// TODO Auto-generated method stub
		return null;
	}

}
