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

package org.ejbca.database;

import static org.junit.Assert.assertTrue;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.LinkedHashMap;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.EntityTransaction;
import javax.persistence.Persistence;
import org.apache.log4j.Logger;
import org.bouncycastle.util.Arrays;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificateprofile.CertificateProfileData;
import org.cesecore.certificates.crl.CRLData;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.configuration.GlobalConfigurationData;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.keybind.InternalKeyBindingData;
import org.cesecore.keys.token.CryptoTokenData;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.member.RoleMemberData;
import org.ejbca.core.ejb.approval.ApprovalData;
import org.ejbca.core.ejb.ca.publisher.PublisherData;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueData;
import org.ejbca.core.ejb.ca.store.CertReqHistoryData;
import org.ejbca.core.ejb.hardtoken.HardTokenCertificateMap;
import org.ejbca.core.ejb.hardtoken.HardTokenData;
import org.ejbca.core.ejb.hardtoken.HardTokenIssuerData;
import org.ejbca.core.ejb.hardtoken.HardTokenProfileData;
import org.ejbca.core.ejb.hardtoken.HardTokenPropertyData;
import org.ejbca.core.ejb.hardtoken.HardTokenPropertyDataPK;
import org.ejbca.core.ejb.keyrecovery.KeyRecoveryData;
import org.ejbca.core.ejb.keyrecovery.KeyRecoveryDataPK;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferencesData;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileData;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceData;
import org.ejbca.core.ejb.services.ServiceData;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * Simple class to trigger Hibernate's JPA schema validation.
 *
 * <p>run with "ant test:dbschema"
 *
 * <p>We also validate that all fields can hold the values that we assume they
 * can.
 *
 * <p>Must have 'max_allowed_packet' size set to a large value, &gt;2MB
 *
 * @version $Id: DatabaseSchemaTest.java 26474 2017-08-30 18:21:20Z anatom $
 */
@SuppressWarnings("deprecation")
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DatabaseSchemaTest {

    /** Logger. */
  private static final Logger LOG = Logger.getLogger(DatabaseSchemaTest.class);

  /** Param. */
  private static String varchar80B;
  /** Param. */
  private static String varchar250B;
  /** Param. */
  private static String varchar400B;
  /** Param. */
  private static String varchar2000B;
  /** Param. */
  private static String clob10KiB;
  /** Param. */
  private static String clob100KiB;
  /** Param. */
  private static String clob1MiB;
  /** Param. */
  private static final LinkedHashMap<String, Object> HASHMAP_200K =
      new LinkedHashMap<String, Object>();
  /** Param. */
  private static final LinkedHashMap<String, Object> HASHMAP_1M =
      new LinkedHashMap<String, Object>();
  /** Param. */
  private static final int BOGUS_INT = -32; // Very random..
  /** Param. */
  private static final Integer BOGUS_INTEGER = Integer.valueOf(BOGUS_INT);
  /** EMF. */
  private static EntityManagerFactory entityManagerFactory;
  /** EM. */
  private EntityManager entityManager;
  /**
   * Test.
   * @throws Exception  fail
   */
  @BeforeClass
  public static void beforeClass() throws Exception {
    LOG.trace(">setup");
    if (entityManagerFactory == null) {
      entityManagerFactory = Persistence.createEntityManagerFactory("ejbca-pu");
    }
    LOG.trace("<setup");
  }
  /**
   * Test.
   */
  @Before
  public void before() {
    entityManager = entityManagerFactory.createEntityManager();
  }
  /**
   * Test.
   * @throws Exception  fail
   */
  @After
  public void tearDown() throws Exception {
    LOG.trace(">tearDown");
    entityManager.close();
    LOG.trace("<tearDown");
  }
  /**
   * Test.
   * @throws Exception  fail
   */
  @AfterClass
  public static void afterClass() throws Exception {
    if (entityManagerFactory != null) {
      if (entityManagerFactory.isOpen()) {
        entityManagerFactory.close();
      }
    }
    logMemStats();
  }
  /**
   * Test.
   * @throws Exception  fail
   */
  @Test
  public void test000Setup() throws Exception {
    LOG.trace(">test000Setup");
    logMemStats();
    LOG.debug("Allocating memory..");
    varchar80B = getClob(80);
    varchar250B = getClob(250);
    varchar400B = getClob(400);
    varchar2000B = getClob(2000);
    clob10KiB = getClob(10 * 1024);
    clob100KiB = getClob(100 * 1024);
    clob1MiB = getClob(1024 * 1024);
    LOG.debug(
        "VARCHAR_80B   is      "
            + varchar80B.length()
            + " chars and     "
            + varchar80B.getBytes().length
            + " bytes.");
    LOG.debug(
        "VARCHAR_250B  is     "
            + varchar250B.length()
            + " chars and     "
            + varchar250B.getBytes().length
            + " bytes.");
    LOG.debug(
        "VARCHAR_400B  is     "
            + varchar400B.length()
            + " chars and     "
            + varchar400B.getBytes().length
            + " bytes.");
    LOG.debug(
        "VARCHAR_2000B is    "
            + varchar2000B.length()
            + " chars and    "
            + varchar2000B.getBytes().length
            + " bytes.");
    LOG.debug(
        "CLOB_10KiB    is   "
            + clob10KiB.length()
            + " chars and   "
            + clob10KiB.getBytes().length
            + " bytes.");
    LOG.debug(
        "CLOB_100KiB   is  "
            + clob100KiB.length()
            + " chars and  "
            + clob100KiB.getBytes().length
            + " bytes.");
    LOG.debug(
        "CLOB_1MiB     is "
            + clob1MiB.length()
            + " chars and "
            + clob1MiB.getBytes().length
            + " bytes.");
    LOG.debug("Filling HashMaps..");
    // Make them mimic "real" UpgradeablaHashMap's, because that's what is
    // usaully stored
    Float f =
        Float.valueOf(
            "9999"); // high number so not to trigger any
                     // UpgradeableHashMap.upgrade()'s
    HASHMAP_200K.put(
        "object",
        new String(
            getLob(
                196
                    * 1024))); // It need to be less than 200KiB in Serialized
                               // format..
    HASHMAP_200K.put(UpgradeableDataHashMap.VERSION, f);
    // make it look also like a UserData.ExtendedInformation
    HASHMAP_200K.put(
        ExtendedInformation.TYPE,
        Integer.valueOf(ExtendedInformation.TYPE_BASIC));
    HASHMAP_1M.put(
        "object",
        new String(
            getLob(
                996
                    * 1024))); // It need to be less than 1MiB in Serialized
                               // format..
    HASHMAP_1M.put(UpgradeableDataHashMap.VERSION, f);
    HASHMAP_1M.put(
        ExtendedInformation.TYPE,
        Integer.valueOf(ExtendedInformation.TYPE_BASIC));
    logMemStats();
    LOG.trace("<test000Setup");
  }

  private byte[] getLob(final int size) {
    byte[] ret = new byte[size];
    Arrays.fill(ret, (byte) '0');
    return ret;
  }

  private String getClob(final int size) {
    return new String(getLob(size));
  }
  /**
   * Test.
   */
  @Test
  public void testApprovalData() {
    LOG.trace(">testApprovalData");
    logMemStats();
    ApprovalData entity = new ApprovalData();
    entity.setApprovalid(0);
    entity.setApprovaldata(clob1MiB);
    entity.setApprovaltype(0);
    entity.setCaid(0);
    entity.setEndentityprofileid(0);
    entity.setExpiredate(0);
    entity.setId(Integer.valueOf(0));
    entity.setRemainingapprovals(0);
    entity.setReqadmincertissuerdn(varchar250B);
    entity.setReqadmincertsn(varchar250B);
    entity.setRequestdata(clob1MiB);
    entity.setRequestdate(0);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    entity.setStatus(0);
    storeAndRemoveEntity(entity);
    LOG.trace("<testApprovalData");
  }
  /**
   * Test.
   */
  @Test
  public void testAccessRulesData() {
    LOG.trace(">testAccessRulesData");
    logMemStats();
    AccessRuleData entity =
        new AccessRuleData(
            BOGUS_INTEGER.intValue(),
            varchar250B,
            AccessRuleState.RULE_ACCEPT,
            false);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    storeAndRemoveEntity(entity);
    LOG.trace("<testAccessRulesData");
  }
  /**
   * Test.
   */
  @Test
  public void testAdminEntityData() {
    LOG.trace(">testAdminEntityData");
    logMemStats();
    AccessUserAspectData entity =
        new AccessUserAspectData(
            varchar250B,
            BOGUS_INTEGER,
            X500PrincipalAccessMatchValue.WITH_SERIALNUMBER,
            AccessMatchType.TYPE_EQUALCASE,
            varchar250B);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    storeAndRemoveEntity(entity);
    LOG.trace("<testAdminEntityData");
  }
  /**
   * Test.
   */
  @Test
  public void testRoleMemberData() {
    LOG.trace(">testAdminEntityData");
    logMemStats();
    RoleMemberData entity =
        new RoleMemberData(
            BOGUS_INT,
            varchar250B,
            BOGUS_INT,
            BOGUS_INT,
            BOGUS_INT,
            varchar2000B,
            BOGUS_INT,
            varchar250B);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    storeAndRemoveEntity(entity);
    LOG.trace("<testAdminEntityData");
  }
  /**
   * Test.
   */
  @Test
  public void testAdminGroupData() {
    LOG.trace(">testAdminGroupData");
    logMemStats();
    AdminGroupData entity = new AdminGroupData(BOGUS_INTEGER, varchar250B);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    storeAndRemoveEntity(entity);
    LOG.trace("<testAdminGroupData");
  }
  /**
   * Test.
   */
  @Test
  public void testRoleData() {
    LOG.trace(">testRoleData");
    logMemStats();
    RoleData entity = new RoleData();
    entity.setId(123);
    entity.setNameSpace(varchar250B);
    entity.setRoleName(varchar250B);
    entity.setRawData(clob1MiB);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    storeAndRemoveEntity(entity);
    LOG.trace("<testRoleData");
  }
  /**
   * Test.
   */
  @Test
  public void testCAData() {
    LOG.trace(">testCAData");
    logMemStats();
    CAData entity = new CAData();
    entity.setCaId(BOGUS_INTEGER);
    entity.setData(clob100KiB);
    entity.setExpireTime(0);
    entity.setName(varchar250B);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    entity.setStatus(0);
    entity.setSubjectDN(varchar250B);
    entity.setUpdateTime(0);
    storeAndRemoveEntity(entity);
    LOG.trace("<testCAData");
  }
  /**
   * Test.
   */
  @Test
  public void testCertificateProfileData() {
    LOG.trace(">testCertificateProfileData");
    logMemStats();
    CertificateProfileData entity = new CertificateProfileData();
    entity.setCertificateProfileName(varchar250B);
    entity.setDataUnsafe(HASHMAP_1M);
    entity.setId(BOGUS_INTEGER);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    storeAndRemoveEntity(entity);
    LOG.trace("<testCertificateProfileData");
  }
  /**
   * Test.
   */
  @Test
  public void testPublisherData() {
    LOG.trace(">testPublisherData");
    logMemStats();
    PublisherData entity = new PublisherData();
    entity.setData(clob100KiB);
    entity.setId(BOGUS_INTEGER);
    entity.setName(varchar250B);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    entity.setUpdateCounter(0);
    storeAndRemoveEntity(entity);
    LOG.trace("<testPublisherData");
  }
  /**
   * Test.
   */
  @Test
  public void testPublisherQueueData() {
    LOG.trace(">testPublisherQueueData");
    logMemStats();
    PublisherQueueData entity = new PublisherQueueData();
    entity.setFingerprint(varchar250B);
    entity.setLastUpdate(0);
    entity.setPk(varchar250B);
    entity.setPublisherId(0);
    entity.setPublishStatus(0);
    entity.setPublishType(0);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    entity.setTimeCreated(0);
    entity.setTryCounter(0);
    entity.setVolatileData(clob100KiB);
    storeAndRemoveEntity(entity);
    LOG.trace("<testPublisherQueueData");
  }
  /**
   * Test.
   */
  @Test
  public void testCertificateData() {
    LOG.trace(">testCertificateData");
    logMemStats();
    CertificateData entity = new CertificateData();
    entity.setBase64Cert(clob1MiB);
    entity.setCaFingerprint(varchar250B);
    entity.setCertificateProfileId(BOGUS_INTEGER);
    entity.setExpireDate(0L);
    entity.setFingerprint(varchar250B);
    entity.setIssuerDN(varchar250B);
    // setPrivateField(entity, "issuerDN", VARCHAR_250B);
    entity.setRevocationDate(0L);
    entity.setRevocationReason(0);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    entity.setSerialNumber(varchar250B);
    entity.setStatus(0);
    entity.setSubjectDN(varchar400B);
    entity.setSubjectAltName(varchar2000B);
    entity.setSubjectKeyId(varchar250B);
    entity.setTag(varchar250B);
    entity.setType(0);
    entity.setUpdateTime(Long.valueOf(0L));
    entity.setUsername(varchar250B);
    storeAndRemoveEntity(entity);
    LOG.trace("<testCertificateData");
  }
  /**
   * Test.
   */
  @Test
  public void testCertReqHistoryData() {
    LOG.trace(">testCertReqHistoryData");
    logMemStats();
    CertReqHistoryData entity = new CertReqHistoryData();
    entity.setIssuerDN(varchar250B);
    entity.setFingerprint(varchar250B);
    // setPrivateField(entity, "issuerDN", VARCHAR_250B);
    // setPrivateField(entity, "fingerprint", VARCHAR_250B);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    entity.setSerialNumber(varchar250B);
    // setPrivateField(entity, "serialNumber", VARCHAR_250B);
    entity.setTimestamp(0L);
    entity.setUserDataVO(clob1MiB);
    entity.setUsername(varchar250B);
    // setPrivateField(entity, "username", VARCHAR_250B);
    storeAndRemoveEntity(entity);
    LOG.trace("<testCertReqHistoryData");
  }
  /**
   * Test.
   */
  @Test
  public void testCryptoTokenData() {
    LOG.trace(">testCryptoTokenData");
    logMemStats();
    CryptoTokenData entity = new CryptoTokenData();
    entity.setId(BOGUS_INT);
    entity.setLastUpdate(0L);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    entity.setTokenData(clob1MiB);
    entity.setTokenName(varchar250B);
    entity.setTokenProps(clob10KiB);
    entity.setTokenType(varchar250B);
    storeAndRemoveEntity(entity);
    LOG.trace("<testCryptoTokenData");
  }
  /**
   * Test.
   */
  // ZZ to run this test last, since we often run out of memory here and mess up
  // the database connection.
  @Test
  public void testZZCRLData() {
    LOG.trace(">testCRLData");
    logMemStats();
    String clob10MiB = getClob(10 * 1024 * 1024);
    CRLData entity = new CRLData();
    entity.setBase64Crl(clob10MiB);
    clob10MiB = null;
    System.gc();
    entity.setCaFingerprint(varchar250B);
    entity.setCrlNumber(0);
    entity.setDeltaCRLIndicator(0);
    entity.setFingerprint(varchar250B);
    entity.setIssuerDN(varchar250B);
    // setPrivateField(entity, "issuerDN", VARCHAR_250B);
    entity.setNextUpdate(0L);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    entity.setThisUpdate(0L);
    storeAndRemoveEntity(entity);
    LOG.trace("<testCRLData");
  }
  /**
   * Test.
   */
  @Test
  public void testHardTokenCertificateMap() {
    LOG.trace(">testHardTokenCertificateMap");
    logMemStats();
    HardTokenCertificateMap entity = new HardTokenCertificateMap();
    entity.setCertificateFingerprint(varchar250B);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    entity.setTokenSN(varchar250B);
    storeAndRemoveEntity(entity);
    LOG.trace("<testHardTokenCertificateMap");
  }
  /**
   * Test.
   */
  @Test
  public void testHardTokenData() {
    LOG.trace(">testHardTokenData");
    logMemStats();
    HardTokenData entity = new HardTokenData();
    entity.setCtime(0L);
    entity.setData(HASHMAP_200K);
    entity.setMtime(0L);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    entity.setSignificantIssuerDN(varchar250B);
    entity.setTokenSN(varchar250B);
    entity.setTokenType(0);
    entity.setUsername(varchar250B);
    storeAndRemoveEntity(entity);
    LOG.trace("<testHardTokenData");
  }
  /**
   * Test.
   */
  @Test
  public void testHardTokenIssuerData() {
    LOG.trace(">testHardTokenIssuerData");
    logMemStats();
    HardTokenIssuerData entity = new HardTokenIssuerData();
    entity.setAdminGroupId(0);
    entity.setAlias(varchar250B);
    entity.setDataUnsafe(HASHMAP_200K);
    entity.setId(BOGUS_INTEGER);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    storeAndRemoveEntity(entity);
    LOG.trace("<testHardTokenIssuerData");
  }
  /**
   * Test.
   */
  @Test
  public void testHardTokenProfileData() {
    LOG.trace(">testHardTokenProfileData");
    logMemStats();
    HardTokenProfileData entity = new HardTokenProfileData();
    entity.setData(clob1MiB);
    entity.setId(BOGUS_INTEGER);
    entity.setName(varchar250B);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    entity.setUpdateCounter(0);
    storeAndRemoveEntity(entity);
    LOG.trace("<testHardTokenProfileData");
  }
  /**
   * Test.
   */
  @Test
  public void testHardTokenPropertyData() {
    LOG.trace(">testHardTokenPropertyData");
    logMemStats();
    HardTokenPropertyData entity = new HardTokenPropertyData();
    // Combined primary key id+property has to be less than 1000 bytes on MyISAM
    // (UTF8: 3*(80+250) < 1000 bytes)
    entity.setHardTokenPropertyDataPK(
        new HardTokenPropertyDataPK(varchar80B, varchar250B));
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    entity.setValue(varchar250B);
    storeAndRemoveEntity(entity);
    LOG.trace("<testHardTokenPropertyData");
  }
  /**
   * Test.
   */
  @Test
  public void testInternalKeyBindingData() {
    LOG.trace(">testInternalKeyBindingData");
    logMemStats();
    InternalKeyBindingData entity = new InternalKeyBindingData();
    entity.setCertificateId(varchar250B);
    entity.setCryptoTokenId(BOGUS_INT);
    entity.setId(BOGUS_INT);
    entity.setKeyBindingType(varchar250B);
    entity.setKeyPairAlias(varchar250B);
    entity.setLastUpdate(0L);
    entity.setName(varchar250B);
    entity.setRawData(clob1MiB);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    entity.setStatus(varchar250B);
    storeAndRemoveEntity(entity);
    LOG.trace("<testInternalKeyBindingData");
  }
  /**
   * Test.
   */
  @Test
  public void testKeyRecoveryData() {
    LOG.trace(">testKeyRecoveryData");
    logMemStats();
    KeyRecoveryData entity = new KeyRecoveryData();
    entity.setKeyRecoveryDataPK(
        new KeyRecoveryDataPK(varchar80B, varchar250B));
    entity.setKeyData(clob1MiB);
    entity.setMarkedAsRecoverable(false);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    entity.setUsername(varchar250B);
    storeAndRemoveEntity(entity);
    LOG.trace("<testKeyRecoveryData");
  }
  /**
   * Test.
   */
  @Test
  public void testUserData() {
    LOG.trace(">testUserData");
    logMemStats();
    UserData entity = new UserData();
    entity.setCaId(0);
    entity.setCardNumber(varchar250B);
    entity.setCertificateProfileId(0);
    entity.setClearPassword(varchar250B);
    entity.setEndEntityProfileId(0);
    // Create a very large extendedInformation, that is still valid XML
    ExtendedInformation ei = new ExtendedInformation();
    ei.loadData(HASHMAP_1M);
    String eiString = EndEntityInformation.extendedInformationToStringData(ei);
    assertTrue(eiString.length() > 900000);
    entity.setExtendedInformationData(eiString);
    entity.setHardTokenIssuerId(0);
    entity.setKeyStorePassword(varchar250B);
    entity.setPasswordHash(varchar250B);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    entity.setStatus(0);
    entity.setSubjectAltName(varchar2000B);
    entity.setSubjectDN(varchar400B);
    entity.setSubjectEmail(varchar250B);
    entity.setTimeCreated(0L);
    entity.setTimeModified(0L);
    entity.setTokenType(0);
    entity.setType(0);
    entity.setUsername(varchar250B);
    storeAndRemoveEntity(entity);
    LOG.trace("<testUserData");
  }
  /**
   * Test.
   */
  @Test
  public void testAdminPreferencesData() {
    LOG.trace(">testAdminPreferencesData");
    logMemStats();
    AdminPreferencesData entity = new AdminPreferencesData();
    entity.setDataUnsafe(HASHMAP_200K);
    entity.setId(varchar250B);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    storeAndRemoveEntity(entity);
    LOG.trace("<testAdminPreferencesData");
  }
  /**
   * Test.
   */
  @Test
  public void testEndEntityProfileData() {
    LOG.trace(">testEndEntityProfileData");
    logMemStats();
    EndEntityProfileData entity = new EndEntityProfileData();
    entity.setDataUnsafe(HASHMAP_200K);
    entity.setId(BOGUS_INTEGER);
    entity.setProfileName(varchar250B);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    storeAndRemoveEntity(entity);
    LOG.trace("<testEndEntityProfileData");
  }
  /**
   * Test.
   */
  @Test
  public void testGlobalConfigurationData() {
    LOG.trace(">testGlobalConfigurationData");
    logMemStats();
    GlobalConfigurationData entity = new GlobalConfigurationData();
    entity.setConfigurationId(varchar250B);
    entity.setObjectUnsafe(HASHMAP_200K);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    storeAndRemoveEntity(entity);
    LOG.trace("<testGlobalConfigurationData");
  }
  /**
   * Test.
   */
  @Test
  public void testUserDataSourceData() {
    LOG.trace(">testUserDataSourceData");
    logMemStats();
    UserDataSourceData entity = new UserDataSourceData();
    entity.setData(clob100KiB);
    entity.setId(BOGUS_INTEGER);
    entity.setName(varchar250B);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    entity.setUpdateCounter(0);
    storeAndRemoveEntity(entity);
    LOG.trace("<testUserDataSourceData");
  }

  /**
   * Test.
   */
  @Test
  public void testServiceData() {
    LOG.trace(">testServiceData");
    logMemStats();
    ServiceData entity = new ServiceData();
    entity.setData(clob100KiB);
    entity.setId(BOGUS_INTEGER);
    entity.setName(varchar250B);
    entity.setNextRunTimeStamp(0L);
    entity.setRowProtection(clob10KiB);
    entity.setRowVersion(0);
    entity.setRunTimeStamp(0L);
    storeAndRemoveEntity(entity);
    LOG.trace("<testServiceData");
  }

  /**
   * Outputs which method it is run from. Validates that all getters on the
   * entity that is annotated with @javax.persistence.Column is set. Commits the
   * entity in one transaction and then removes it in another transaction.
   *
   * @param entity Entity
   */
  private void storeAndRemoveEntity(final Object entity) {
    LOG.trace(">storeAndRemoveEntity");
    logMemStats();
    try {
      Class<?> entityClass = entity.getClass();
      LOG.info(
          "  - verifying that all getter has an assigned value for "
              + entityClass.getName());
      boolean allOk = true;
      for (Method m : entityClass.getDeclaredMethods()) {
        for (Annotation a : m.getAnnotations()) {
          if (a.annotationType().equals(javax.persistence.Column.class)
              && m.getName().startsWith("get")) {
            try {
              m.setAccessible(true);
              if (m.invoke(entity) == null) {
                LOG.warn(
                    m.getName()
                        + " was annotated with @Column, but value was null."
                        + " Test should be updated!");
                allOk = false;
              }
            } catch (Exception e) {
              LOG.error(
                  m.getName()
                      + " was annotated with @Column and could not be read. "
                      + e.getMessage());
              allOk = false;
            }
          }
        }
      }
      assertTrue(
          "There is a problem with a @Column annotated getter. Please refer to"
              + " log output for further info.",
          allOk);
      LOG.info("  - adding entity.");
      EntityTransaction transaction = entityManager.getTransaction();
      transaction.begin();
      entityManager.persist(entity);
      transaction.commit();
      LOG.info("  - removing entity.");
      transaction = entityManager.getTransaction();
      transaction.begin();
      entityManager.remove(entity);
      transaction.commit();
    } finally {
      if (entityManager.getTransaction().isActive()) {
        entityManager.getTransaction().rollback();
      }
      logMemStats();
    }
    LOG.trace("<storeAndRemoveEntity");
  }

  private static void logMemStats() {
    System.gc();
    final long maxMemory = Runtime.getRuntime().maxMemory() / 1024 / 1024;
    final long freeMemory = Runtime.getRuntime().freeMemory() / 1024 / 1024;
    LOG.info(
        "JVM Runtime reports: freeMemory="
            + freeMemory
            + "MiB, maxMemory="
            + maxMemory
            + "MiB, ("
            + (maxMemory - freeMemory) * 100 / maxMemory
            + "% used)");
  }

  /* * Used in order to bypass validity check of different
   * private fields that are access via transient setters. * /
  private void setPrivateField(Object entity, String fieldName, Object value) {
      LOG.trace(">setPrivateField");
      try {
          Field field = entity.getClass().getDeclaredField(fieldName);
          field.setAccessible(true);
          field.set(entity, value);
      } catch (Exception e) {
          LOG.error("", e);
          assertTrue("Could not set " + fieldName + " to " + value + ": "
           + e.getMessage(), false);
      }
      LOG.trace("<setPrivateField");
  }
  */
}
