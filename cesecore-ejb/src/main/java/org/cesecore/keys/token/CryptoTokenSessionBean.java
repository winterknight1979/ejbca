/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import javax.annotation.PostConstruct;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfigurationHelper;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.util.CryptoProviderUtil;
import org.cesecore.util.QueryResultWrapper;

/**
 * Basic CRUD and activation caching of CryptoTokens is provided through this
 * local access SSB.
 *
 * @version $Id: CryptoTokenSessionBean.java 28332 2018-02-20 14:40:52Z anatom $
 */
@Stateless(
    mappedName = JndiConstants.APP_JNDI_PREFIX + "CryptoTokenSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CryptoTokenSessionBean
    implements CryptoTokenSessionLocal, CryptoTokenSessionRemote {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(CryptoTokenSessionBean.class);
  /** Resource. */
  private static final InternalResources INTRES =
      InternalResources.getInstance();

  /** EM. */
  @PersistenceContext(unitName = CesecoreConfigurationHelper.PERSISTENCE_UNIT)
  private EntityManager entityManager;

  /** Setup. */
  @PostConstruct
  public void postConstruct() {
    CryptoProviderUtil.installBCProviderIfNotAvailable();
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public void flushCache() {
    CryptoTokenCache.INSTANCE.flush();
    if (LOG.isDebugEnabled()) {
      LOG.debug("Flushed CryptoToken cache.");
    }
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public void flushExcludingIDs(final List<Integer> ids) {
    CryptoTokenCache.INSTANCE.replaceCacheWith(ids);
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Flushed CryptoToken cache except for "
              + ids.size()
              + " specific entries.");
    }
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public CryptoToken getCryptoToken(final int cryptoTokenId) {
    // 1. Check (new) CryptoTokenCache if it is time to sync-up with database
    if (CryptoTokenCache.INSTANCE.shouldCheckForUpdates(cryptoTokenId)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "CryptoToken with ID "
                + cryptoTokenId
                + " will be checked for updates.");
      }
      // 2. If cache is expired or missing, first thread to discover this
      // reloads item from database and sends it to the cache
      final CryptoTokenData cryptoTokenData =
          readCryptoTokenData(cryptoTokenId);
      if (cryptoTokenData == null) {
        if (LOG.isDebugEnabled()) {
          LOG.debug(
              "Requested cryptoTokenId did not exist in database and will be"
                  + " purged from cache if present: "
                  + cryptoTokenId);
        }
        // Ensure that it is removed from cache
        CryptoTokenCache.INSTANCE.removeEntry(cryptoTokenId);
      } else {
        final int digest = cryptoTokenData.getProtectString(0).hashCode();
        // 3. The cache compares the database data with what is in the cache
        if (CryptoTokenCache.INSTANCE.willUpdate(cryptoTokenId, digest)) {
          final String tokenType = cryptoTokenData.getTokenType();
          final Properties properties = cryptoTokenData.getTokenProperties();
          final byte[] data = cryptoTokenData.getTokenDataAsBytes();
          final String tokenName = cryptoTokenData.getTokenName();
          // Create new token and store it in the cache.
          String inClassname = getClassNameForType(tokenType);
          CryptoToken cryptoToken;
          // 4. If database is different from cache, create the crypto token and
          // replace it in the cache (while trying to keep activation)
          //    (Invokes
          // org.cesecore.keys.token.CryptoTokenFactory.createCryptoToken)
          try {
            cryptoToken =
                CryptoTokenFactory.createCryptoToken(
                    inClassname,
                    properties,
                    data,
                    cryptoTokenId,
                    tokenName,
                    true);
          } catch (NoSuchSlotException e) {
            // This should never happen now, since the specify
            // allowNonExistingSlot in the createCryptoToken call
            throw new IllegalStateException(
                "Attempted to find a slot for a PKCS#11 crypto token, but it"
                    + " did not exists. Perhaps the token was removed?");
          }
          CryptoTokenCache.INSTANCE.updateWith(
              cryptoTokenId, digest, tokenName, cryptoToken);
        }
      }
    }
    // 5. Get CryptoToken from cache (or null) and be merry
    return CryptoTokenCache.INSTANCE.getEntry(cryptoTokenId);
  }

  @Override
  public String getClassNameForType(final String tokenType) {
    String inClassname = null;
    for (final AvailableCryptoToken act
        : CryptoTokenFactory.instance().getAvailableCryptoTokens()) {
      if (act.getClassPath().endsWith(tokenType)) {
        // We found a available token with the same Class.getSimpleName() as the
        // CryptoToken's type, so use it!
        // (By only storing the "simple" classname we can switch implementation
        // package without care)
        inClassname = act.getClassPath();
      }
    }
    return inClassname;
  }

  @Override
  public int mergeCryptoToken(final CryptoToken cryptoToken)
      throws CryptoTokenNameInUseException {
    if (LOG.isTraceEnabled()) {
      LOG.trace(
          ">addCryptoToken "
              + cryptoToken.getTokenName()
              + " "
              + cryptoToken.getClass().getName());
    }
    final int cryptoTokenId = cryptoToken.getId();
    final String tokenName = cryptoToken.getTokenName();
    String tokenType = "null";
    for (final AvailableCryptoToken act
        : CryptoTokenFactory.instance().getAvailableCryptoTokens()) {
      if (cryptoToken.getClass().getName().equals(act.getClassPath())) {
        tokenType = cryptoToken.getClass().getSimpleName();
        break;
      }
    }
    final long lastUpdate = System.currentTimeMillis();
    final Properties tokenProperties = cryptoToken.getProperties();
    final byte[] tokenDataAsBytes = cryptoToken.getTokenData();
    CryptoTokenData cryptoTokenData =
        entityManager.find(CryptoTokenData.class, cryptoTokenId);
    if (cryptoTokenData == null) {
      // The cryptoToken does not exist in the database, before we add it we
      // want to check that the name is not in use
      if (isCryptoTokenNameUsed(tokenName)) {
        throw new CryptoTokenNameInUseException(
            INTRES.getLocalizedMessage("token.nameisinuse", tokenName));
      }
      cryptoTokenData =
          new CryptoTokenData(
              cryptoTokenId,
              tokenName,
              tokenType,
              lastUpdate,
              tokenProperties,
              tokenDataAsBytes);
    } else {
      if (!isCryptoTokenNameUsedByIdOnly(tokenName, cryptoTokenId)) {
        throw new CryptoTokenNameInUseException(
            INTRES.getLocalizedMessage("token.nameisinuse", tokenName));
      }
      // It might be the case that the calling transaction has already loaded a
      // reference to this token
      // and hence we need to get the same one and perform updates on this
      // object instead of trying to
      // merge a new object.
      cryptoTokenData.setTokenName(tokenName);
      cryptoTokenData.setTokenType(tokenType);
      cryptoTokenData.setLastUpdate(lastUpdate);
      cryptoTokenData.setTokenProperties(tokenProperties);
      cryptoTokenData.setTokenDataAsBytes(tokenDataAsBytes);
    }
    cryptoTokenData = createOrUpdateCryptoTokenData(cryptoTokenData);
    // Update cache with provided token (it might be active and we like keeping
    // things active)
    CryptoTokenCache.INSTANCE.updateWith(
        cryptoTokenId,
        cryptoTokenData.getProtectString(0).hashCode(),
        tokenName,
        cryptoToken);
    if (LOG.isTraceEnabled()) {
      LOG.trace("<addCryptoToken " + cryptoToken.getTokenName());
    }
    return cryptoTokenId; // tokenId
  }

  @Override
  public boolean removeCryptoToken(final int cryptoTokenId) {
    final boolean ret = deleteCryptoTokenData(cryptoTokenId);
    CryptoTokenCache.INSTANCE.updateWith(cryptoTokenId, 0, null, null);
    return ret;
  }

  @Override
  public Map<String, Integer> getCachedNameToIdMap() {
    return CryptoTokenCache.INSTANCE.getNameToIdMap();
  }

  @Override
  public String getCryptoTokenName(final int cryptoTokenId) {
    return CryptoTokenCache.INSTANCE.getName(cryptoTokenId);
  }

  @Override
  public boolean isCryptoTokenNameUsed(final String cryptoTokenName) {
    final Query query =
        entityManager.createQuery(
            "SELECT a FROM CryptoTokenData a WHERE a.tokenName=:tokenName");
    query.setParameter("tokenName", cryptoTokenName);
    return !query.getResultList().isEmpty();
  }

  @Override
  public boolean isCryptoTokenNameUsedByIdOnly(
      final String cryptoTokenName, final int cryptoTokenId) {
    final Query query =
        entityManager.createQuery(
            "SELECT a FROM CryptoTokenData a WHERE a.tokenName=:tokenName");
    query.setParameter("tokenName", cryptoTokenName);
    @SuppressWarnings("unchecked")
    final List<CryptoTokenData> cryptoTokenDatas = query.getResultList();
    for (final CryptoTokenData cryptoTokenData : cryptoTokenDatas) {
      if (cryptoTokenData.getId() != cryptoTokenId) {
        return false;
      }
    }
    return true;
  }

  //
  // Create Read Update Delete (CRUD) methods
  //

  private CryptoTokenData readCryptoTokenData(final int cryptoTokenId) {
    final Query query =
        entityManager.createQuery(
            "SELECT a FROM CryptoTokenData a WHERE a.id=:id");
    query.setParameter("id", cryptoTokenId);
    return QueryResultWrapper.getSingleResult(query);
  }

  private CryptoTokenData createOrUpdateCryptoTokenData(
      final CryptoTokenData data) {
    return entityManager.merge(data);
  }

  private boolean deleteCryptoTokenData(final int cryptoTokenId) {
    final Query query =
        entityManager.createQuery(
            "DELETE FROM CryptoTokenData a WHERE a.id=:id");
    query.setParameter("id", cryptoTokenId);
    return query.executeUpdate() == 1;
  }

  @SuppressWarnings("unchecked")
  @Override
  public List<Integer> getCryptoTokenIds() {
    return entityManager
        .createQuery("SELECT a.id FROM CryptoTokenData a")
        .getResultList();
  }

  @TransactionAttribute(TransactionAttributeType.SUPPORTS)
  @Override
  public Map<Integer, String> getCryptoTokenIdToNameMap() {
    final Map<Integer, String> ret = new HashMap<>();
    for (final CryptoTokenData cryptoTokenData
        : entityManager
            .createQuery(
                "SELECT a FROM CryptoTokenData a", CryptoTokenData.class)
            .getResultList()) {
      ret.put(cryptoTokenData.getId(), cryptoTokenData.getTokenName());
    }
    return ret;
  }
}
