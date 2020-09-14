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
package org.cesecore.certificates.certificate;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import javax.ejb.Local;

import org.cesecore.certificates.crl.RevokedCertInfo;

/**
 * Local interface for CertificateDataSession.
 * 
 * @version $Id: CertificateDataSessionLocal.java 28981 2018-05-21 14:10:49Z jekaterina_b_helmes $
 */
@Local
public interface CertificateDataSessionLocal extends CertificateDataSession {

    /** @param fingerprint FP
     * @return the found entity instance or null if the entity does not exist */
    CertificateData findByFingerprint(String fingerprint);

    /** @param subjectDN Subject DN
     * @param issuerDN Issuer DN
     * @return return the query results as a Set. */
    Set<String> findUsernamesBySubjectDNAndIssuerDN(String subjectDN, String issuerDN);
    
    /** @param subjectDN Subject DN
     * @return return the query results as a List. */
    List<CertificateData> findBySubjectDN(String subjectDN);

    /** @param serialNumber Serial
     * @return return the query results as a List. */
    List<CertificateData> findBySerialNumber(String serialNumber);

    /** @param issuerDN Issuer DN
     * @param serialNumber Serial
     * @return return the query results as a List. */
    List<CertificateData> findByIssuerDNSerialNumber(String issuerDN, String serialNumber);

    /** @param issuerDN Issuer DN
     * @param serialNumber Serial
     * @return return the query results as a List. */
    CertificateInfo findFirstCertificateInfo(String issuerDN, String serialNumber);
    
    /** @param issuerDN Issuer DN
     * @param serialNumber Serial
     * @return the last found username or null if none was found */
    String findLastUsernameByIssuerDNSerialNumber(String issuerDN, String serialNumber);

    /** @param username username
     * @return return the query results as a List. */
    List<CertificateData> findByUsernameOrdered(String username);
    
    /** @param username username
     * @param status status
     * @return return the query results as a List. */
    List<CertificateData> findByUsernameAndStatus(String username, int status);

    /** @param username user name
     * @param status status
     * @param afterExpireDate date 
     * @return return the query results as a List. */
    List<CertificateData> findByUsernameAndStatusAfterExpireDate(String username, int status, long afterExpireDate);
    
    /** @param issuerDN Issuer DN
     * @param subjectKeyId Key
     * @return return the query results as a List. */
    Set<String> findUsernamesByIssuerDNAndSubjectKeyId(String issuerDN, String subjectKeyId);

    String findUsernameByIssuerDnAndSerialNumber(String issuerDn, String serialNumber);
    
    /** @param issuerDN Issuer DN
     * @param subjectKeyId Key
     * @param subjectDN Subject DN
     * @return return the query results as a List. */
    Set<String> findUsernamesBySubjectKeyIdOrDnAndIssuer(String issuerDN, String subjectKeyId, String subjectDN);
    
    /** @param issuerDN Issuer DN
     * @return return the query results as a List<String>. */
    List<String> findFingerprintsByIssuerDN(String issuerDN);
    
    /** @param issuerDN Issuer DN
     * @param lastbasecrldate CRL date
     * @return return the query results as a Collection<RevokedCertInfo>. */
    Collection<RevokedCertInfo> getRevokedCertInfos(String issuerDN, long lastbasecrldate);
    
    /** @param expireDate Date
     * @param maxNumberOfResults max 
     * @return return the query results as a List. */
    List<CertificateData> findByExpireDateWithLimit(long expireDate, int maxNumberOfResults);

    /** @param expireDate Date
     * @param maxNumberOfResults Max 
     * @param offset  Offset
     * @return return the query results as a List. */
    List<CertificateData> findByExpireDateWithLimitAndOffset(long expireDate, int maxNumberOfResults, int offset);

    /** @param expireDate Date
     * @return return count of query results. */
    int countByExpireDate(long expireDate);
    
    /** @param expireDate Date
     * @param issuerDN Issuer DN
     * @param maxNumberOfResults max
     * @return return the query results as a List. */
    List<CertificateData> findByExpireDateAndIssuerWithLimit(long expireDate, String issuerDN, int maxNumberOfResults);
    
    /** @param expireDate Date
     * @param certificateType Type
     * @param maxNumberOfResults max
     * @return return the query results as a List. */
    List<CertificateData> findByExpireDateAndTypeWithLimit(long expireDate, int certificateType, int maxNumberOfResults);
    
    List<String> findUsernamesByExpireTimeWithLimit(long minExpireTime, long maxExpireTime, int maxResults);
    
    /**
     * Get a list of {@link Certificate} from a list of list of {@link CertificateData}.
     * @param cdl data
     * @return The resulting list.
     */
    List<Certificate> getCertificateList(final List<CertificateData> cdl);
    
    List<Certificate> findCertificatesByIssuerDnAndSerialNumbers(final String issuerDN, final Collection<BigInteger> serialNumbers);
    
    /** @param fingerprint FP
     * @return the CertificateInfo representation (all fields except the actual cert) or null if no such fingerprint exists. */
    CertificateInfo getCertificateInfo(String fingerprint);
    
    /** @param certificateTypes Types
     * @return a List<Certificate> of SecConst.CERT_ACTIVE and CERT_NOTIFIEDABOUTEXPIRATION certs that have one of the specified types. */
    List<Certificate> findActiveCertificatesByType(Collection<Integer> certificateTypes);
    
    
    /**
     * @param certificateTypes Types
     * @param issuerDN Issuer DN 
     * @return a List<Certificate> of SecConst.CERT_ACTIVE and CERT_NOTIFIEDABOUTEXPIRATION certs that have one of the specified types for the given
     *         issuer.
     */
    List<Certificate> findActiveCertificatesByTypeAndIssuer(Collection<Integer> certificateTypes, String issuerDN);
    

    /**
     * Fetch a List of all certificate fingerprints and corresponding username
     *
     * We want to accomplish two things:
     *
     * 1. Notify for expirations within the service window
     * 2. Notify _once_ for expirations that occurred before the service window like flagging certificates that have a shorter
     * life-span than the threshold (pathologic test-case...)
     *
     * The first is checked by:
     *
     * notify = currRunTimestamp + thresHold <= ExpireDate < nextRunTimestamp + thresHold
     *          AND (status = ACTIVE OR status = NOTIFIEDABOUTEXPIRATION)
     *
     * The second can be checked by:
     *
     * notify = currRunTimestamp + thresHold > ExpireDate AND status = ACTIVE
     *
     * @param cas A list of CAs that the sought certificates should be issued from
     * @param certificateProfiles A list if certificateprofiles to sort from. Will be ignored if left empty.
     * @param activeNotifiedExpireDateMin The minimal date for expiration notification
     * @param activeNotifiedExpireDateMax The maxmimal date for expiration notification
     * @param activeExpireDateMin the current rune timestamp + the threshold
     *
     * @return [0] = (String) fingerprint, [1] = (String) username
     */
    List<Object[]> findExpirationInfo(Collection<String> cas, Collection<Integer> certificateProfiles,
            long activeNotifiedExpireDateMin, long activeNotifiedExpireDateMax, long activeExpireDateMin);
    
}
