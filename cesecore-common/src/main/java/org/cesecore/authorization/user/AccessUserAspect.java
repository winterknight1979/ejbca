package org.cesecore.authorization.user;

public interface AccessUserAspect {

	public String getTokenType() ;

	public Integer getMatchWith() ;

	public int getCaId() ;

	public String getMatchValue();

	public AccessMatchType getMatchTypeAsType() ;

}
