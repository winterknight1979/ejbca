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
package org.cesecore.certificates.certificate.certextensions;

import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.cesecore.certificates.certificate.certextensions.standard.AuthorityInformationAccess;
import org.cesecore.certificates.certificate.certextensions.standard.AuthorityKeyIdentifier;
import org.cesecore.certificates.certificate.certextensions.standard.BasicConstraint;
import org.cesecore.certificates.certificate.certextensions.standard.CertificatePolicies;
import org.cesecore.certificates.certificate.certextensions.standard.CrlDistributionPoints;
import org.cesecore.certificates.certificate.certextensions.standard.DocumentTypeList;
import org.cesecore.certificates.certificate.certextensions.standard.ExtendedKeyUsage;
import org.cesecore.certificates.certificate.certextensions.standard.FreshestCrl;
import org.cesecore.certificates.certificate.certextensions.standard.IssuerAltNames;
import org.cesecore.certificates.certificate.certextensions.standard.KeyUsage;
import org.cesecore.certificates.certificate.certextensions.standard.MsTemplate;
import org.cesecore.certificates.certificate.certextensions.standard.NameConstraint;
import org.cesecore.certificates.certificate.certextensions.standard.OcspNoCheck;
import org.cesecore.certificates.certificate.certextensions.standard.PrivateKeyUsagePeriod;
import org.cesecore.certificates.certificate.certextensions.standard.QcStatement;
import org.cesecore.certificates.certificate.certextensions.standard.SeisCardNumber;
import org.cesecore.certificates.certificate.certextensions.standard.StandardCertificateExtension;
import org.cesecore.certificates.certificate.certextensions.standard.SubjectAltNames;
import org.cesecore.certificates.certificate.certextensions.standard.SubjectDirectoryAttributes;
import org.cesecore.certificates.certificate.certextensions.standard.SubjectKeyIdentifier;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.internal.InternalResources;
import org.cesecore.util.CertTools;

/**
 * Class parsing the modules/ejbca-common/src/certextensions.properties file and
 * maintains a set of available custom extensions to the system.
 *
 * <p>It is also responsible for creating the actual CertificateExtensions used
 * in certificate generation.
 *
 * <p>It also keep a list of standard (not custom) built in extensions.
 *
 * @version $Id: CertificateExtensionFactory.java 22142 2015-11-03 14:15:51Z
 *     mikekushner $
 */
public final class CertificateExtensionFactory {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(CertificateExtensionFactory.class);
  /** Internal resources. */
  private static final InternalResources INTRES =
      InternalResources.getInstance();

  /** Singleton instance. */
  private static CertificateExtensionFactory instance = null;

  /** Standard extensions. */
  private HashMap<String, String> standardCertificateExtensions =
      new HashMap<String, String>();

  private CertificateExtensionFactory() {
    standardCertificateExtensions.put(
        Extension.basicConstraints.getId(), BasicConstraint.class.getName());
    standardCertificateExtensions.put(
        Extension.subjectKeyIdentifier.getId(),
        SubjectKeyIdentifier.class.getName());
    standardCertificateExtensions.put(
        Extension.authorityKeyIdentifier.getId(),
        AuthorityKeyIdentifier.class.getName());
    standardCertificateExtensions.put(
        Extension.keyUsage.getId(), KeyUsage.class.getName());
    standardCertificateExtensions.put(
        Extension.extendedKeyUsage.getId(), ExtendedKeyUsage.class.getName());
    standardCertificateExtensions.put(
        Extension.subjectAlternativeName.getId(),
        SubjectAltNames.class.getName());
    standardCertificateExtensions.put(
        Extension.issuerAlternativeName.getId(),
        IssuerAltNames.class.getName());
    standardCertificateExtensions.put(
        "2.23.136.1.1.6.2", DocumentTypeList.class.getName());
    standardCertificateExtensions.put(
        Extension.cRLDistributionPoints.getId(),
        CrlDistributionPoints.class.getName());
    standardCertificateExtensions.put(
        Extension.freshestCRL.getId(), FreshestCrl.class.getName());
    standardCertificateExtensions.put(
        Extension.certificatePolicies.getId(),
        CertificatePolicies.class.getName());
    standardCertificateExtensions.put(
        Extension.subjectDirectoryAttributes.getId(),
        SubjectDirectoryAttributes.class.getName());
    standardCertificateExtensions.put(
        Extension.authorityInfoAccess.getId(),
        AuthorityInformationAccess.class.getName());
    standardCertificateExtensions.put(
        Extension.qCStatements.getId(), QcStatement.class.getName());
    standardCertificateExtensions.put(
        Extension.nameConstraints.getId(), NameConstraint.class.getName());
    standardCertificateExtensions.put(
        OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId(),
        OcspNoCheck.class.getName());
    standardCertificateExtensions.put(
        CertTools.OID_MSTEMPLATE, MsTemplate.class.getName());
    standardCertificateExtensions.put(
        SeisCardNumber.OID_CARDNUMBER, SeisCardNumber.class.getName());
    standardCertificateExtensions.put(
        Extension.privateKeyUsagePeriod.getId(),
        PrivateKeyUsagePeriod.class.getName());
   }

  /**
   * Method used to get the instance of the factory. If it is the first time the
   * method is called will the configuration file be parsed.
   *
   * @return The factory instance
   */
  public static CertificateExtensionFactory getInstance() {
    if (instance == null) {
      instance = new CertificateExtensionFactory();
    }

    return instance;
  }

  /**
   * Method returning the instance of the standard CertificateExtension given
   * its object identifier.
   *
   * @param oid OID
   * @param certProf Profile
   * @return null if the CertificateExtension doesn't exist
   */
  public CertificateExtension getStandardCertificateExtension(
      final String oid, final CertificateProfile certProf) {
    StandardCertificateExtension ret = null;
    final String classPath = (String) standardCertificateExtensions.get(oid);
    if (classPath != null) {
      try {
        final Class<?> implClass = Class.forName(classPath);
        ret =
            (StandardCertificateExtension)
                implClass.getConstructor().newInstance();
        ret.init(certProf);
      } catch (ClassNotFoundException e) {
        LOG.error(
            INTRES.getLocalizedMessage("certext.noextensionforid", oid), e);
      } catch (InstantiationException e) {
        LOG.error(
            INTRES.getLocalizedMessage("certext.noextensionforid", oid), e);
      } catch (IllegalAccessException e) {
        LOG.error(
            INTRES.getLocalizedMessage("certext.noextensionforid", oid), e);
      } catch (InvocationTargetException e) {
        LOG.error(
            INTRES.getLocalizedMessage("certext.noextensionforid", oid), e);
      } catch (NoSuchMethodException e) {
        LOG.error(
            INTRES.getLocalizedMessage("certext.noextensionforid", oid), e);
      }
    }
    if (ret == null) {
      LOG.error(INTRES.getLocalizedMessage("certext.noextensionforid", oid));
    }
    return ret;
  }

  /** Method used for testing to be able to reset class between tests. */
  protected static void resetExtensions() {
    instance = null;
  }
}
