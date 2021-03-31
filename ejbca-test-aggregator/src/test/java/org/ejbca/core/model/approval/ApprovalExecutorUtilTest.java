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

package org.ejbca.core.model.approval;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.util.ui.PropertyValidationException;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ChangeStatusEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id: ApprovalExecutorUtilTest.java 24958 2016-12-28 17:07:58Z
 *     mikekushner $
 */
public class ApprovalExecutorUtilTest {

    /** Partam.
     */
  private static final AuthenticationToken ADMIN =
      new AlwaysAllowLocalAuthenticationToken(
          new UsernamePrincipal("ApprovalExecutorUtilTest"));

  /**
   * @throws Exception fail
   */
  @Before
  public void setUp() throws Exception { }

  /**
   * @throws PropertyValidationException fail
   */
  @Test
  public void testNoOfApprovals() throws PropertyValidationException {
    int numOfApprovalsRequired = 1;
    AccumulativeApprovalProfile nrOfApprovalsApprovalProfile =
        new AccumulativeApprovalProfile("nrOfApprovalApprovalProfile");
    nrOfApprovalsApprovalProfile.initialize();
    nrOfApprovalsApprovalProfile.setNumberOfApprovalsRequired(
        numOfApprovalsRequired);
    ChangeStatusEndEntityApprovalRequest ar =
        new ChangeStatusEndEntityApprovalRequest(
            "foo",
            EndEntityConstants.STATUS_GENERATED,
            EndEntityConstants.STATUS_NEW,
            ADMIN,
            null,
            1,
            1,
            nrOfApprovalsApprovalProfile);
    boolean approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);
    assertTrue(approvalRequired);
    numOfApprovalsRequired = 0;
    nrOfApprovalsApprovalProfile.setNumberOfApprovalsRequired(
        numOfApprovalsRequired);
    ar =
        new ChangeStatusEndEntityApprovalRequest(
            "foo",
            EndEntityConstants.STATUS_GENERATED,
            EndEntityConstants.STATUS_NEW,
            ADMIN,
            null,
            1,
            1,
            nrOfApprovalsApprovalProfile);
    approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);
    assertFalse(approvalRequired);
  }

  /**
   * @throws PropertyValidationException fail
   */
  @Test
  public void testGloballyExcludedClasses() throws PropertyValidationException {
    int numOfApprovalsRequired = 1;
    AccumulativeApprovalProfile nrOfApprovalsApprovalProfile =
        new AccumulativeApprovalProfile("testGloballyExcludedClasses");
    nrOfApprovalsApprovalProfile.initialize();
    nrOfApprovalsApprovalProfile.setNumberOfApprovalsRequired(
        numOfApprovalsRequired);
    ChangeStatusEndEntityApprovalRequest ar =
        new ChangeStatusEndEntityApprovalRequest(
            "foo",
            EndEntityConstants.STATUS_GENERATED,
            EndEntityConstants.STATUS_NEW,
            ADMIN,
            null,
            1,
            1,
            nrOfApprovalsApprovalProfile);
    boolean approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);
    assertTrue(approvalRequired);
    ApprovalJunitHelper.JunitApprovalExecutorUtil1.init();
    approvalRequired =
        ApprovalJunitHelper.JunitApprovalExecutorUtil1.requireApproval(
            ar, null);
    assertFalse(approvalRequired);
    ApprovalJunitHelper.JunitApprovalExecutorUtil2.init();
    approvalRequired =
        ApprovalJunitHelper.JunitApprovalExecutorUtil2.requireApproval(
            ar, null);
    assertFalse(approvalRequired);
    ApprovalJunitHelper.JunitApprovalExecutorUtil3.init();
    approvalRequired =
        ApprovalJunitHelper.JunitApprovalExecutorUtil3.requireApproval(
            ar, null);
    assertTrue(approvalRequired);
  }

  /**
   * @throws PropertyValidationException fail
   */
  @Test
  public void testOverridableClassNames() throws PropertyValidationException {
    ApprovalOveradableClassName[] nonApprovableClassNamesSetUserStatus = {
      new ApprovalOveradableClassName(
          "org.ejbca.core.ejb.ra.EndEntityManagementSessionBean", "revokeUser"),
      new ApprovalOveradableClassName(
          "org.ejbca.core.ejb.ra.EndEntityManagementSessionBean", "revokeCert"),
      new ApprovalOveradableClassName(
          "org.ejbca.ui.web.admin.rainterface.RAInterfaceBean", "unrevokeCert"),
      new ApprovalOveradableClassName(
          "org.ejbca.ui.web.admin.rainterface.RAInterfaceBean",
          "markForRecovery"),
      new ApprovalOveradableClassName(
          "org.ejbca.extra.caservice.ExtRACAProcess",
          "processExtRARevocationRequest"),
      new ApprovalOveradableClassName(
          "se.primeKey.cardPersonalization.ra.connection.ejbca.EjbcaConnection",
          null)
    };

    int numOfApprovalsRequired = 1;
    AccumulativeApprovalProfile nrOfApprovalsApprovalProfile =
        new AccumulativeApprovalProfile("nrOfApprovalApprovalProfile");
    nrOfApprovalsApprovalProfile.initialize();
    nrOfApprovalsApprovalProfile.setNumberOfApprovalsRequired(
        numOfApprovalsRequired);
    ChangeStatusEndEntityApprovalRequest ar =
        new ChangeStatusEndEntityApprovalRequest(
            "foo",
            EndEntityConstants.STATUS_GENERATED,
            EndEntityConstants.STATUS_NEW,
            ADMIN,
            null,
            1,
            1,
            nrOfApprovalsApprovalProfile);
    boolean approvalRequired =
        ApprovalExecutorUtil.requireApproval(
            ar, nonApprovableClassNamesSetUserStatus);
    assertTrue(approvalRequired);
    ApprovalOveradableClassName[] nonApprovableClassNamesSetUserStatus1 = {
      new ApprovalOveradableClassName(
          "org.ejbca.core.ejb.ra.EndEntityManagementSessionBean", "revokeUser"),
      new ApprovalOveradableClassName(
          "org.ejbca.core.ejb.ra.EndEntityManagementSessionBean", "revokeCert"),
      new ApprovalOveradableClassName(
          "org.ejbca.core.model.approval.ApprovalExecutorUtilTest", "foo"),
      new ApprovalOveradableClassName(
          "org.ejbca.ui.web.admin.rainterface.RAInterfaceBean",
          "markForRecovery"),
      new ApprovalOveradableClassName(
          "org.ejbca.extra.caservice.ExtRACAProcess",
          "processExtRARevocationRequest"),
      new ApprovalOveradableClassName(
          "se.primeKey.cardPersonalization.ra.connection.ejbca.EjbcaConnection",
          null)
    };
    ar =
        new ChangeStatusEndEntityApprovalRequest(
            "foo",
            EndEntityConstants.STATUS_GENERATED,
            EndEntityConstants.STATUS_NEW,
            ADMIN,
            null,
            1,
            1,
            nrOfApprovalsApprovalProfile);
    approvalRequired =
        ApprovalExecutorUtil.requireApproval(
            ar, nonApprovableClassNamesSetUserStatus1);
    assertTrue(approvalRequired);
    ApprovalOveradableClassName[] nonApprovableClassNamesSetUserStatus2 = {
      new ApprovalOveradableClassName(
          "org.ejbca.core.ejb.ra.EndEntityManagementSessionBean", "revokeUser"),
      new ApprovalOveradableClassName(
          "org.ejbca.core.ejb.ra.EndEntityManagementSessionBean", "revokeCert"),
      new ApprovalOveradableClassName(
          "org.ejbca.core.model.approval.ApprovalExecutorUtilTest", null),
      new ApprovalOveradableClassName(
          "org.ejbca.ui.web.admin.rainterface.RAInterfaceBean",
          "markForRecovery"),
      new ApprovalOveradableClassName(
          "org.ejbca.extra.caservice.ExtRACAProcess",
          "processExtRARevocationRequest"),
      new ApprovalOveradableClassName(
          "se.primeKey.cardPersonalization.ra.connection.ejbca.EjbcaConnection",
          null)
    };
    ar =
        new ChangeStatusEndEntityApprovalRequest(
            "foo",
            EndEntityConstants.STATUS_GENERATED,
            EndEntityConstants.STATUS_NEW,
            ADMIN,
            null,
            1,
            1,
            nrOfApprovalsApprovalProfile);
    approvalRequired =
        ApprovalExecutorUtil.requireApproval(
            ar, nonApprovableClassNamesSetUserStatus2);
    assertFalse(approvalRequired);
    ApprovalOveradableClassName[] nonApprovableClassNamesSetUserStatus3 = {
      new ApprovalOveradableClassName(
          "org.ejbca.core.ejb.ra.EndEntityManagementSessionBean", "revokeUser"),
      new ApprovalOveradableClassName(
          "org.ejbca.core.ejb.ra.EndEntityManagementSessionBean", "revokeCert"),
      new ApprovalOveradableClassName(
          "org.ejbca.core.model.approval.ApprovalExecutorUtilTest",
          "testOverridableClassNames"),
      new ApprovalOveradableClassName(
          "org.ejbca.ui.web.admin.rainterface.RAInterfaceBean",
          "markForRecovery"),
      new ApprovalOveradableClassName(
          "org.ejbca.extra.caservice.ExtRACAProcess",
          "processExtRARevocationRequest"),
      new ApprovalOveradableClassName(
          "se.primeKey.cardPersonalization.ra.connection.ejbca.EjbcaConnection",
          null)
    };
    ar =
        new ChangeStatusEndEntityApprovalRequest(
            "foo",
            EndEntityConstants.STATUS_GENERATED,
            EndEntityConstants.STATUS_NEW,
            ADMIN,
            null,
            1,
            1,
            nrOfApprovalsApprovalProfile);
    approvalRequired =
        ApprovalExecutorUtil.requireApproval(
            ar, nonApprovableClassNamesSetUserStatus3);
    assertFalse(approvalRequired);
  }


  /**
   * @throws PropertyValidationException fail
   */
  @Test
  public void testAllowedTransitions() throws PropertyValidationException {
    int numOfApprovalsRequired = 1;
    AccumulativeApprovalProfile nrOfApprovalsApprovalProfile =
        new AccumulativeApprovalProfile("nrOfApprovalApprovalProfile");
    nrOfApprovalsApprovalProfile.initialize();
    nrOfApprovalsApprovalProfile.setNumberOfApprovalsRequired(
        numOfApprovalsRequired);
    ChangeStatusEndEntityApprovalRequest ar =
        new ChangeStatusEndEntityApprovalRequest(
            "foo",
            EndEntityConstants.STATUS_NEW,
            EndEntityConstants.STATUS_INPROCESS,
            ADMIN,
            null,
            1,
            1,
            nrOfApprovalsApprovalProfile);
    boolean approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);
    assertFalse(approvalRequired);
    ar =
        new ChangeStatusEndEntityApprovalRequest(
            "foo",
            EndEntityConstants.STATUS_GENERATED,
            EndEntityConstants.STATUS_NEW,
            ADMIN,
            null,
            1,
            1,
            nrOfApprovalsApprovalProfile);
    approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);
    assertTrue(approvalRequired);
    ar =
        new ChangeStatusEndEntityApprovalRequest(
            "foo",
            EndEntityConstants.STATUS_INPROCESS,
            EndEntityConstants.STATUS_GENERATED,
            ADMIN,
            null,
            1,
            1,
            nrOfApprovalsApprovalProfile);
    approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);
    assertFalse(approvalRequired);
    ar =
        new ChangeStatusEndEntityApprovalRequest(
            "foo",
            EndEntityConstants.STATUS_INPROCESS,
            EndEntityConstants.STATUS_FAILED,
            ADMIN,
            null,
            1,
            1,
            nrOfApprovalsApprovalProfile);
    approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);
    assertFalse(approvalRequired);
    ar =
        new ChangeStatusEndEntityApprovalRequest(
            "foo",
            EndEntityConstants.STATUS_REVOKED,
            EndEntityConstants.STATUS_NEW,
            ADMIN,
            null,
            1,
            1,
            nrOfApprovalsApprovalProfile);
    approvalRequired = ApprovalExecutorUtil.requireApproval(ar, null);
    assertTrue(approvalRequired);
  }

  /**
   * @throws Exception fail
   */
  @Test
  public void testAccumulativeApprovalProfile() throws Exception {
    final String approvalProfileName = "testAccumulativeApprovalProfile";
    final AccumulativeApprovalProfile approvalProfile =
        new AccumulativeApprovalProfile(approvalProfileName);
    approvalProfile.initialize();
    approvalProfile.setNumberOfApprovalsRequired(0);
    assertEquals(0, approvalProfile.getNumberOfApprovalsRequired());

    RevocationApprovalRequest revReq =
        new RevocationApprovalRequest(
            null, "", "", 0, null, 0, 0, approvalProfile);
    assertFalse(ApprovalExecutorUtil.requireApproval(revReq, null));
    AddEndEntityApprovalRequest addReq =
        new AddEndEntityApprovalRequest(
            null, false, null, "", 0, 0, approvalProfile);
    assertFalse(ApprovalExecutorUtil.requireApproval(addReq, null));

    approvalProfile.setNumberOfApprovalsRequired(1);
    assertEquals(1, approvalProfile.getNumberOfApprovalsRequired());
    revReq =
        new RevocationApprovalRequest(
            null, "", "", 0, null, 0, 0, approvalProfile);
    assertTrue(ApprovalExecutorUtil.requireApproval(revReq, null));
  }
}
