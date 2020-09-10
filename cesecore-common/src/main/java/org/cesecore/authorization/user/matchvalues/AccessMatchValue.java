package org.cesecore.authorization.user.matchvalues;

import java.util.List;

import org.cesecore.authorization.user.AccessMatchType;

public interface AccessMatchValue {

	int getNumericValue();

	String getTokenType();

	boolean isIssuedByCa();

	boolean isDefaultValue();

	List<AccessMatchType> getAvailableAccessMatchTypes();

	String normalizeMatchValue(String value);

	String name();

}
