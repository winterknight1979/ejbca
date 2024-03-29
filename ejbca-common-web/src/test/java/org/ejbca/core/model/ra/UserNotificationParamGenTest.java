package org.ejbca.core.model.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.util.Date;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.util.ValidityDateUtil;
import org.ejbca.core.model.SecConst;
import org.junit.Test;

/**
 * Tests some substitution variables for user notifications.
 *
 * @version $Id: UserNotificationParamGenTest.java 27422 2017-12-05 14:05:42Z
 *     bastianf $
 */
public class UserNotificationParamGenTest {
     /**
       * Test.
       */
  @Test
  public void testInterpolate() {
    Date now = new Date();
    int caid = 123;
    String approvalAdminDN = "CN=approvaluser,O=Org,C=SE";
    EndEntityInformation userdata =
        new EndEntityInformation(
            "foo",
            "CN=foome,O=Org,C=SE",
            caid,
            "rfc822Name=fooalt@foo.se",
            "fooee@foo.se",
            EndEntityConstants.STATUS_GENERATED,
            new EndEntityType(EndEntityTypes.ENDUSER),
            EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
            CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
            now,
            null,
            SecConst.TOKEN_SOFT_P12,
            SecConst.NO_HARDTOKENISSUER,
            null);
    userdata.setPassword("foo$123\\bar");
    EndEntityInformation admindata =
        new EndEntityInformation(
            "admin",
            "CN=Test Admin,C=NO",
            caid,
            "rfc822Name=adminalt@foo.se",
            "adminee@foo.se",
            EndEntityConstants.STATUS_GENERATED,
            new EndEntityType(EndEntityTypes.ENDUSER),
            EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
            CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
            now,
            null,
            SecConst.TOKEN_SOFT_P12,
            SecConst.NO_HARDTOKENISSUER,
            null);
    final String certificateSerialNumber = "1234567890";
    final CertificateData certificateData = new CertificateData();
    certificateData.setSerialNumber(certificateSerialNumber);
    certificateData.setExpireDate(now);
    certificateData.setSubjectDN("CN=foo,O=Org,C=SE");
    certificateData.setIssuerDN("CN=The CA,O=Org,C=NO");
    certificateData.setStatus(CertificateConstants.CERT_REVOKED);
    certificateData.setRevocationReason(
        RevocationReasons.CERTIFICATEHOLD.getDatabaseValue());
    final CertificateDataWrapper cdw =
        new CertificateDataWrapper(certificateData, null);
    final UserNotificationParamGen paramGen =
        new UserNotificationParamGen(
            userdata, approvalAdminDN, admindata, 123, cdw);
    assertNotNull("paramGen is null", paramGen);

    String msg =
        paramGen.interpolate(
            "${USERNAME} ${user.USERNAME} ${PASSWORD} ${user.PASSWORD} ${CN}"
                + " ${user.CN} ${C} ${approvalAdmin.CN} ${approvalAdmin.C}"
                + " ${approvalAdmin.O} ${user.EE.EMAIL} ${user.SAN.EMAIL}"
                + " ${requestAdmin.EE.EMAIL} ${requestAdmin.CN}"
                + " ${requestAdmin.SAN.EMAIL} ${revokedCertificate.CERTSERIAL}"
                + " ${revokedCertificate.EXPIREDATE}"
                + " ${revokedCertificate.CERTSUBJECTDN} "
                + " ${revokedCertificate.CERTISSUERDN}"
                + " ${revokedCertificate.REVOCATIONSTATUS}"
                + " ${revokedCertificate.REVOCATIONREASON}"
                + " ${approvalRequestID}");
    assertFalse(
        "Interpolating message failed", (msg == null || msg.length() == 0));
    assertEquals(
        "foo foo foo$123\\bar foo$123\\bar foome foome SE approvaluser SE Org"
            + " fooee@foo.se fooalt@foo.se adminee@foo.se Test Admin"
            + " adminalt@foo.se "
            + new BigInteger(certificateSerialNumber).toString(16).toUpperCase()
            + " "
       + ValidityDateUtil.formatAsISO8601(now, ValidityDateUtil.TIMEZONE_SERVER)
            + " CN=foo,O=Org,C=SE "
            + " CN=The CA,O=Org,C=NO Revoked certificateHold 123",
        msg);
  }
}
