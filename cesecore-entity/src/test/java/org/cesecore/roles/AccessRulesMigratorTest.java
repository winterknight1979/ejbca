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
package org.cesecore.roles;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import org.apache.log4j.Logger;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.junit.Test;

/**
 * Test of the AccessRulesMigrator that is used to migrate AccessRuleData to the
 * new format used from EJBCA 6.8.0.
 *
 * @version $Id: AccessRulesMigratorTest.java 25830 2017-05-10 13:36:45Z
 *     mikekushner $
 */
@SuppressWarnings("deprecation")
public class AccessRulesMigratorTest {

    /** Logger. */
  private static final Logger LOG =
      Logger.getLogger(AccessRulesMigratorTest.class);

  /** Config. */
  private static final String ERRMSG_ALLOWED_TO_DENIED =
      "Access granted that should have been denied.";
  /** Config. */
  private static final String ERRMSG_DENIED_TO_ALLOWED =
      "Access denied that should have been granted.";

  /** Config. */
  private static final Boolean STATE_ALLOW = Role.STATE_ALLOW;
  /** Config. */
  private static final Boolean STATE_DENY = Role.STATE_DENY;

  /** Migrators. */
  private final AccessRulesMigrator accessRulesMigratorSystemA =
      new AccessRulesMigrator(
          Arrays.asList(
              "/",
              "/administrator",
              "/ca",
              "/ca/-1011",
              "/ca/12345",
              "/ca/67890",
              "/ca_functionality",
              "/ca_functionality/approve_caaction",
              "/ca_functionality/basic_functions",
              "/ca_functionality/basic_functions/activate_ca",
              "/ca_functionality/create_certificate",
              "/ca_functionality/create_crl",
              "/ca_functionality/edit_approval_profiles",
              "/ca_functionality/edit_ca",
              "/ca_functionality/edit_certificate_profiles",
              "/ca_functionality/edit_publisher",
              "/ca_functionality/renew_ca",
              "/ca_functionality/view_approval_profiles",
              "/ca_functionality/view_ca",
              "/ca_functionality/view_certificate",
              "/ca_functionality/view_certificate_profiles",
              "/ca_functionality/view_publisher",
              "/cryptotoken",
              "/cryptotoken/activate",
              "/cryptotoken/activate/12345",
              "/cryptotoken/activate/67890",
              "/cryptotoken/deactivate",
              "/cryptotoken/deactivate/12345",
              "/cryptotoken/deactivate/67890",
              "/cryptotoken/delete",
              // "/cryptotoken/keys",
              "/cryptotoken/keys/generate",
              "/cryptotoken/keys/generate/12345",
              "/cryptotoken/keys/generate/67890",
              "/cryptotoken/keys/remove",
              "/cryptotoken/keys/remove/12345",
              "/cryptotoken/keys/remove/67890",
              "/cryptotoken/keys/test",
              "/cryptotoken/keys/test/12345",
              "/cryptotoken/keys/test/67890",
              "/cryptotoken/modify",
              "/cryptotoken/use",
              "/cryptotoken/use/12345",
              "/cryptotoken/use/67890",
              "/cryptotoken/view",
              "/cryptotoken/view/12345",
              "/cryptotoken/view/67890",
              "/endentityprofilesrules",
              "/endentityprofilesrules/1",
              "/endentityprofilesrules/1/approve_end_entity",
              "/endentityprofilesrules/1/create_end_entity",
              "/endentityprofilesrules/1/delete_end_entity",
              "/endentityprofilesrules/1/edit_end_entity",
              "/endentityprofilesrules/1/keyrecovery",
              "/endentityprofilesrules/1/revoke_end_entity",
              "/endentityprofilesrules/1/view_end_entity",
              "/endentityprofilesrules/1/view_end_entity_history",
              "/endentityprofilesrules/1/view_hardtoken",
              "/endentityprofilesrules/1/view_hardtoken/puk_data",
              "/endentityprofilesrules/2345",
              "/endentityprofilesrules/2345/approve_end_entity",
              "/endentityprofilesrules/2345/create_end_entity",
              "/endentityprofilesrules/2345/delete_end_entity",
              "/endentityprofilesrules/2345/edit_end_entity",
              "/endentityprofilesrules/2345/keyrecovery",
              "/endentityprofilesrules/2345/revoke_end_entity",
              "/endentityprofilesrules/2345/view_end_entity",
              "/endentityprofilesrules/2345/view_end_entity_history",
              "/endentityprofilesrules/2345/view_hardtoken",
              "/endentityprofilesrules/2345/view_hardtoken/puk_data",
              "/hardtoken_functionality",
              "/hardtoken_functionality/edit_hardtoken_issuers",
              "/hardtoken_functionality/edit_hardtoken_profiles",
              "/hardtoken_functionality/issue_hardtoken_administrators",
              "/hardtoken_functionality/issue_hardtokens",
              "/internalkeybinding",
              "/internalkeybinding/delete",
              "/internalkeybinding/delete/-12345",
              "/internalkeybinding/delete/67890",
              "/internalkeybinding/modify",
              "/internalkeybinding/modify/-12345",
              "/internalkeybinding/modify/67890",
              "/internalkeybinding/view",
              "/internalkeybinding/view/-12345",
              "/internalkeybinding/view/67890",
              "/peer",
              "/peer/manage",
              "/peer/modify",
              "/peer/view",
              "/peerincoming",
              "/peerpublish",
              "/peerpublish/readcert",
              "/peerpublish/writecert",
              "/peerpublish/writecrl",
              "/public_web_user",
              "/ra_functionality",
              "/ra_functionality/approve_end_entity",
              "/ra_functionality/create_end_entity",
              "/ra_functionality/delete_end_entity",
              "/ra_functionality/edit_end_entity",
              "/ra_functionality/edit_end_entity_profiles",
              "/ra_functionality/edit_user_data_sources",
              "/ra_functionality/keyrecovery",
              "/ra_functionality/revoke_end_entity",
              "/ra_functionality/view_end_entity",
              "/ra_functionality/view_end_entity_history",
              "/ra_functionality/view_end_entity_profiles",
              "/ra_functionality/view_hardtoken",
              "/ra_functionality/view_hardtoken/puk_data",
              "/ra_master/invoke_api",
              "/ra_slave/manage",
              "/secureaudit",
              "/secureaudit/auditor/export",
              "/secureaudit/auditor/select",
              "/secureaudit/auditor/verify",
              "/secureaudit/log",
              "/secureaudit/log_custom_events",
              "/secureaudit/management/manage",
              "/services/edit",
              "/services/view",
              "/system_functionality",
              "/system_functionality/edit_administrator_privileges",
              "/system_functionality/"
              + "edit_available_custom_certificate_extensions",
              "/system_functionality/edit_available_extended_key_usages",
              "/system_functionality/edit_systemconfiguration",
              "/system_functionality/view_administrator_privileges",
              "/system_functionality/"
              + "view_available_custom_certificate_extensions",
              "/system_functionality/view_available_extended_key_usages",
              "/system_functionality/view_systemconfiguration",
              "/userdatasourcesrules",
              // "/userdatasourcesrules/123",
              "/userdatasourcesrules/123/fetch_userdata",
              "/userdatasourcesrules/123/remove_userdata",
              // "/userdatasourcesrules/456",
              "/userdatasourcesrules/456/fetch_userdata",
              "/userdatasourcesrules/456/remove_userdata",
              "/xcustomrule1",
              "/xcustomrule2"));
  /**
   * Test.
   */
  @Test
  public void testMigrationEmptyRole() {
    LOG.trace(">testMigrationEmptyRole()");
    final List<AccessRuleData> oldAccessRules = Arrays.asList();
    final List<ExpectedResourceState> expectedNewAccessRules = Arrays.asList();
    final List<ExpectedResourceState> expectedResourceAccesses =
        Arrays.asList(
            new ExpectedResourceState(STATE_DENY, "/"),
            new ExpectedResourceState(STATE_DENY, "/administrator"),
            new ExpectedResourceState(STATE_DENY, "/ca"),
            new ExpectedResourceState(STATE_DENY, "/ca/-1011"),
            new ExpectedResourceState(STATE_DENY, "/ca/12345"),
            new ExpectedResourceState(STATE_DENY, "/ca/67890"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/approve_caaction"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/basic_functions"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/basic_functions/activate_ca"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/create_certificate"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/create_crl"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_approval_profiles"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality/edit_ca"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_certificate_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_publisher"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality/renew_ca"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/view_approval_profiles"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality/view_ca"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/view_certificate"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/view_certificate_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/view_publisher"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/activate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/activate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/activate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/deactivate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/deactivate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/deactivate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/delete"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/generate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/generate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/generate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/remove"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/remove/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/remove/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/test"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/test/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/test/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/modify"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use/12345"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/view"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/view/12345"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/view/67890"),
            new ExpectedResourceState(STATE_DENY, "/endentityprofilesrules"),
            new ExpectedResourceState(STATE_DENY, "/endentityprofilesrules/1"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/approve_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/create_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/delete_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/edit_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/keyrecovery"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/view_end_entity"),
            new ExpectedResourceState(
                STATE_DENY,
                "/endentityprofilesrules/1/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/view_hardtoken"),
            new ExpectedResourceState(
                STATE_DENY,
                "/endentityprofilesrules/1/view_hardtoken/puk_data"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/approve_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/create_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/delete_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/edit_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/keyrecovery"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/view_end_entity"),
            new ExpectedResourceState(
                STATE_DENY,
                "/endentityprofilesrules/2345/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/view_hardtoken"),
            new ExpectedResourceState(
                STATE_DENY,
                "/endentityprofilesrules/2345/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_DENY, "/hardtoken_functionality"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/edit_hardtoken_issuers"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/edit_hardtoken_profiles"),
            new ExpectedResourceState(
                STATE_DENY,
                "/hardtoken_functionality/issue_hardtoken_administrators"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/issue_hardtokens"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding/delete"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/delete/-12345"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/delete/67890"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding/modify"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/modify/-12345"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/modify/67890"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding/view"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/view/-12345"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/view/67890"),
            new ExpectedResourceState(STATE_DENY, "/peer"),
            new ExpectedResourceState(STATE_DENY, "/peer/manage"),
            new ExpectedResourceState(STATE_DENY, "/peer/modify"),
            new ExpectedResourceState(STATE_DENY, "/peer/view"),
            new ExpectedResourceState(STATE_DENY, "/peerincoming"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/readcert"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/writecert"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/writecrl"),
            new ExpectedResourceState(STATE_DENY, "/public_web_user"),
            new ExpectedResourceState(STATE_DENY, "/ra_functionality"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/approve_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/create_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/delete_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/edit_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/edit_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/edit_user_data_sources"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/keyrecovery"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_hardtoken"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_DENY, "/ra_master/invoke_api"),
            new ExpectedResourceState(STATE_DENY, "/ra_slave/manage"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit/auditor"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/export"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/select"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/verify"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit/log"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/log_custom_events"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/management/manage"),
            new ExpectedResourceState(STATE_DENY, "/services/edit"),
            new ExpectedResourceState(STATE_DENY, "/services/view"),
            new ExpectedResourceState(STATE_DENY, "/system_functionality"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/edit_administrator_privileges"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/"
                + "edit_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/edit_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_DENY, "/system_functionality/edit_systemconfiguration"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/view_administrator_privileges"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/"
                + "view_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/view_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_DENY, "/system_functionality/view_systemconfiguration"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules/123"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/123/fetch_userdata"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/123/remove_userdata"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules/456"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/456/fetch_userdata"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/456/remove_userdata"),
            new ExpectedResourceState(STATE_DENY, "/xcustomrule1"),
            new ExpectedResourceState(STATE_DENY, "/xcustomrule2"));
    testMigrationInternal(
        accessRulesMigratorSystemA,
        "EmptyRole",
        oldAccessRules,
        expectedNewAccessRules,
        expectedResourceAccesses);
    LOG.trace("<testMigrationEmptyRole()");
  }
  /**
   * Test.
   */
  @Test
  public void testMigrationSuperAdmin() {
    LOG.trace(">testMigrationSuperAdmin()");
    final List<AccessRuleData> oldAccessRules =
        Arrays.asList(
            new AccessRuleData("", "/", AccessRuleState.RULE_ACCEPT, true));
    final List<ExpectedResourceState> expectedNewAccessRules =
        Arrays.asList(new ExpectedResourceState(STATE_ALLOW, "/"));
    final List<ExpectedResourceState> expectedResourceAccesses =
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/"),
            new ExpectedResourceState(STATE_ALLOW, "/administrator"),
            new ExpectedResourceState(STATE_ALLOW, "/ca"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/-1011"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/12345"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/ca_functionality"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/approve_caaction"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/basic_functions"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/basic_functions/activate_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/create_certificate"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/create_crl"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/edit_approval_profiles"),
            new ExpectedResourceState(STATE_ALLOW, "/ca_functionality/edit_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/edit_certificate_profiles"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/edit_publisher"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/renew_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_approval_profiles"),
            new ExpectedResourceState(STATE_ALLOW, "/ca_functionality/view_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_certificate"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_certificate_profiles"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_publisher"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/activate"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/activate/12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/activate/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/deactivate"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/deactivate/12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/deactivate/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/delete"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/keys"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/keys/generate"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/keys/generate/12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/keys/generate/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/keys/remove"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/keys/remove/12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/keys/remove/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/keys/test"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/keys/test/12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/keys/test/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/modify"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/use"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/use/12345"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/use/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/view"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/view/12345"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/view/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/endentityprofilesrules"),
            new ExpectedResourceState(STATE_ALLOW, "/endentityprofilesrules/1"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/approve_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/create_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/delete_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/edit_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/keyrecovery"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/1/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/view_hardtoken"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/1/view_hardtoken/puk_data"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/approve_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/create_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/delete_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/edit_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/keyrecovery"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/2345/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/view_hardtoken"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/2345/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_ALLOW, "/hardtoken_functionality"),
            new ExpectedResourceState(
                STATE_ALLOW, "/hardtoken_functionality/edit_hardtoken_issuers"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/hardtoken_functionality/edit_hardtoken_profiles"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/hardtoken_functionality/issue_hardtoken_administrators"),
            new ExpectedResourceState(
                STATE_ALLOW, "/hardtoken_functionality/issue_hardtokens"),
            new ExpectedResourceState(STATE_ALLOW, "/internalkeybinding"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/delete"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/delete/-12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/delete/67890"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/modify"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/modify/-12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/modify/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/internalkeybinding/view"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/view/-12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/view/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/peer"),
            new ExpectedResourceState(STATE_ALLOW, "/peer/manage"),
            new ExpectedResourceState(STATE_ALLOW, "/peer/modify"),
            new ExpectedResourceState(STATE_ALLOW, "/peer/view"),
            new ExpectedResourceState(STATE_ALLOW, "/peerincoming"),
            new ExpectedResourceState(STATE_ALLOW, "/peerpublish"),
            new ExpectedResourceState(STATE_ALLOW, "/peerpublish/readcert"),
            new ExpectedResourceState(STATE_ALLOW, "/peerpublish/writecert"),
            new ExpectedResourceState(STATE_ALLOW, "/peerpublish/writecrl"),
            new ExpectedResourceState(STATE_ALLOW, "/public_web_user"),
            new ExpectedResourceState(STATE_ALLOW, "/ra_functionality"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/approve_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/create_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/delete_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/edit_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/edit_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/edit_user_data_sources"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/keyrecovery"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_hardtoken"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_ALLOW, "/ra_master/invoke_api"),
            new ExpectedResourceState(STATE_ALLOW, "/ra_slave/manage"),
            new ExpectedResourceState(STATE_ALLOW, "/secureaudit"),
            new ExpectedResourceState(STATE_ALLOW, "/secureaudit/auditor"),
            new ExpectedResourceState(
                STATE_ALLOW, "/secureaudit/auditor/export"),
            new ExpectedResourceState(
                STATE_ALLOW, "/secureaudit/auditor/select"),
            new ExpectedResourceState(
                STATE_ALLOW, "/secureaudit/auditor/verify"),
            new ExpectedResourceState(STATE_ALLOW, "/secureaudit/log"),
            new ExpectedResourceState(
                STATE_ALLOW, "/secureaudit/log_custom_events"),
            new ExpectedResourceState(
                STATE_ALLOW, "/secureaudit/management/manage"),
            new ExpectedResourceState(STATE_ALLOW, "/services/edit"),
            new ExpectedResourceState(STATE_ALLOW, "/services/view"),
            new ExpectedResourceState(STATE_ALLOW, "/system_functionality"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/edit_administrator_privileges"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/"
                + "edit_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/edit_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_ALLOW, "/system_functionality/edit_systemconfiguration"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/view_administrator_privileges"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/"
                + "view_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/view_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_ALLOW, "/system_functionality/view_systemconfiguration"),
            new ExpectedResourceState(STATE_ALLOW, "/userdatasourcesrules"),
            new ExpectedResourceState(STATE_ALLOW, "/userdatasourcesrules/123"),
            new ExpectedResourceState(
                STATE_ALLOW, "/userdatasourcesrules/123/fetch_userdata"),
            new ExpectedResourceState(
                STATE_ALLOW, "/userdatasourcesrules/123/remove_userdata"),
            new ExpectedResourceState(STATE_ALLOW, "/userdatasourcesrules/456"),
            new ExpectedResourceState(
                STATE_ALLOW, "/userdatasourcesrules/456/fetch_userdata"),
            new ExpectedResourceState(
                STATE_ALLOW, "/userdatasourcesrules/456/remove_userdata"),
            new ExpectedResourceState(STATE_ALLOW, "/xcustomrule1"),
            new ExpectedResourceState(STATE_ALLOW, "/xcustomrule2"));
    testMigrationInternal(
        accessRulesMigratorSystemA,
        "SuperAdmin",
        oldAccessRules,
        expectedNewAccessRules,
        expectedResourceAccesses);
    LOG.trace("<testMigrationSuperAdmin()");
  }
  /**
   * Test.
   */
  @Test
  public void testMigrationSecurityOfficer() {
    LOG.trace(">testMigrationSecurityOfficer()");
    final List<AccessRuleData> oldAccessRules =
        Arrays.asList(
            new AccessRuleData("", "/", AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleData(
                "", "/secureaudit", AccessRuleState.RULE_DECLINE, false));
    final List<ExpectedResourceState> expectedNewAccessRules =
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit/"));
    final List<ExpectedResourceState> expectedResourceAccesses =
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/"),
            new ExpectedResourceState(STATE_ALLOW, "/administrator"),
            new ExpectedResourceState(STATE_ALLOW, "/ca"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/-1011"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/12345"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/ca_functionality"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/approve_caaction"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/basic_functions"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/basic_functions/activate_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/create_certificate"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/create_crl"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/edit_approval_profiles"),
            new ExpectedResourceState(STATE_ALLOW, "/ca_functionality/edit_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/edit_certificate_profiles"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/edit_publisher"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/renew_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_approval_profiles"),
            new ExpectedResourceState(STATE_ALLOW, "/ca_functionality/view_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_certificate"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_certificate_profiles"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_publisher"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/activate"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/activate/12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/activate/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/deactivate"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/deactivate/12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/deactivate/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/delete"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/keys"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/keys/generate"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/keys/generate/12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/keys/generate/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/keys/remove"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/keys/remove/12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/keys/remove/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/keys/test"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/keys/test/12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/keys/test/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/modify"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/use"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/use/12345"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/use/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/view"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/view/12345"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/view/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/endentityprofilesrules"),
            new ExpectedResourceState(STATE_ALLOW, "/endentityprofilesrules/1"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/approve_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/create_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/delete_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/edit_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/keyrecovery"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/1/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/view_hardtoken"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/1/view_hardtoken/puk_data"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/approve_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/create_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/delete_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/edit_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/keyrecovery"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/2345/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/view_hardtoken"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/2345/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_ALLOW, "/hardtoken_functionality"),
            new ExpectedResourceState(
                STATE_ALLOW, "/hardtoken_functionality/edit_hardtoken_issuers"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/hardtoken_functionality/edit_hardtoken_profiles"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/hardtoken_functionality/issue_hardtoken_administrators"),
            new ExpectedResourceState(
                STATE_ALLOW, "/hardtoken_functionality/issue_hardtokens"),
            new ExpectedResourceState(STATE_ALLOW, "/internalkeybinding"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/delete"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/delete/-12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/delete/67890"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/modify"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/modify/-12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/modify/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/internalkeybinding/view"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/view/-12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/view/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/peer"),
            new ExpectedResourceState(STATE_ALLOW, "/peer/manage"),
            new ExpectedResourceState(STATE_ALLOW, "/peer/modify"),
            new ExpectedResourceState(STATE_ALLOW, "/peer/view"),
            new ExpectedResourceState(STATE_ALLOW, "/peerincoming"),
            new ExpectedResourceState(STATE_ALLOW, "/peerpublish"),
            new ExpectedResourceState(STATE_ALLOW, "/peerpublish/readcert"),
            new ExpectedResourceState(STATE_ALLOW, "/peerpublish/writecert"),
            new ExpectedResourceState(STATE_ALLOW, "/peerpublish/writecrl"),
            new ExpectedResourceState(STATE_ALLOW, "/public_web_user"),
            new ExpectedResourceState(STATE_ALLOW, "/ra_functionality"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/approve_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/create_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/delete_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/edit_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/edit_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/edit_user_data_sources"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/keyrecovery"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_hardtoken"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_ALLOW, "/ra_master/invoke_api"),
            new ExpectedResourceState(STATE_ALLOW, "/ra_slave/manage"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit/auditor"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/export"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/select"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/verify"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit/log"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/log_custom_events"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/management/manage"),
            new ExpectedResourceState(STATE_ALLOW, "/services/edit"),
            new ExpectedResourceState(STATE_ALLOW, "/services/view"),
            new ExpectedResourceState(STATE_ALLOW, "/system_functionality"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/edit_administrator_privileges"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/"
                + "edit_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/edit_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_ALLOW, "/system_functionality/edit_systemconfiguration"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/view_administrator_privileges"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/"
                + "view_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/view_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_ALLOW, "/system_functionality/view_systemconfiguration"),
            new ExpectedResourceState(STATE_ALLOW, "/userdatasourcesrules"),
            new ExpectedResourceState(STATE_ALLOW, "/userdatasourcesrules/123"),
            new ExpectedResourceState(
                STATE_ALLOW, "/userdatasourcesrules/123/fetch_userdata"),
            new ExpectedResourceState(
                STATE_ALLOW, "/userdatasourcesrules/123/remove_userdata"),
            new ExpectedResourceState(STATE_ALLOW, "/userdatasourcesrules/456"),
            new ExpectedResourceState(
                STATE_ALLOW, "/userdatasourcesrules/456/fetch_userdata"),
            new ExpectedResourceState(
                STATE_ALLOW, "/userdatasourcesrules/456/remove_userdata"),
            new ExpectedResourceState(STATE_ALLOW, "/xcustomrule1"),
            new ExpectedResourceState(STATE_ALLOW, "/xcustomrule2"));
    testMigrationInternal(
        accessRulesMigratorSystemA,
        "SecurityOfficer",
        oldAccessRules,
        expectedNewAccessRules,
        expectedResourceAccesses);
    LOG.trace("<testMigrationSecurityOfficer()");
  }
  /**
   * Test.
   */
  @Test
  public void testMigrationAuditor() {
    LOG.trace(">testMigrationAuditor()");
    // Auditor role as it would look using old rule templating (2/3 CAs, 2/2
    // EEPs)
    final List<AccessRuleData> oldAccessRules =
        Arrays.asList(
            new AccessRuleData(
                "", "/administrator", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "", "/ca/12345", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "", "/ca/-1011", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "",
                "/ca_functionality/view_approval_profiles",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ca_functionality/view_ca",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ca_functionality/view_certificate",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ca_functionality/view_certificate_profiles",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ca_functionality/view_publisher",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "", "/cryptotoken/view", AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1/view_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1/view_end_entity_history",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/view_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/view_end_entity_history",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/internalkeybinding/view",
                AccessRuleState.RULE_ACCEPT,
                true),
            new AccessRuleData(
                "", "/peer/view", AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleData(
                "",
                "/ra_functionality/view_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/view_end_entity_history",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/view_end_entity_profiles",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/secureaudit/auditor/select",
                AccessRuleState.RULE_ACCEPT,
                true),
            new AccessRuleData(
                "", "/services/view", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "",
                "/system_functionality/view_administrator_privileges",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/system_functionality/"
                + "view_available_custom_certificate_extensions",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/system_functionality/view_available_extended_key_usages",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/system_functionality/view_systemconfiguration",
                AccessRuleState.RULE_ACCEPT,
                false));
    final List<ExpectedResourceState> expectedNewAccessRules =
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/administrator/"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/12345/"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/-1011/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_approval_profiles/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_ca/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_certificate/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_certificate_profiles/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_publisher/"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/view/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/edit_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/create_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/delete_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/revoke_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/approve_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/view_hardtoken/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/keyrecovery/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/edit_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/create_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/delete_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/revoke_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/approve_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/view_hardtoken/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/keyrecovery/"),
            new ExpectedResourceState(STATE_ALLOW, "/internalkeybinding/view/"),
            new ExpectedResourceState(STATE_ALLOW, "/peer/view/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_history/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_profiles/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/secureaudit/auditor/select/"),
            new ExpectedResourceState(STATE_ALLOW, "/services/view/"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/view_administrator_privileges/"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/"
                + "view_available_custom_certificate_extensions/"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/view_available_extended_key_usages/"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/view_systemconfiguration/"));
    final List<ExpectedResourceState> expectedResourceAccesses =
        Arrays.asList(
            new ExpectedResourceState(STATE_DENY, "/"),
            new ExpectedResourceState(STATE_ALLOW, "/administrator"),
            new ExpectedResourceState(STATE_DENY, "/ca"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/-1011"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/12345"),
            new ExpectedResourceState(STATE_DENY, "/ca/67890"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/approve_caaction"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/basic_functions"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/basic_functions/activate_ca"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/create_certificate"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/create_crl"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_approval_profiles"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality/edit_ca"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_certificate_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_publisher"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality/renew_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_approval_profiles"),
            new ExpectedResourceState(STATE_ALLOW, "/ca_functionality/view_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_certificate"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_certificate_profiles"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_publisher"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/activate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/activate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/activate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/deactivate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/deactivate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/deactivate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/delete"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/generate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/generate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/generate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/remove"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/remove/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/remove/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/test"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/test/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/test/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/modify"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use/12345"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/view"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/view/12345"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/view/67890"),
            new ExpectedResourceState(STATE_DENY, "/endentityprofilesrules"),
            new ExpectedResourceState(STATE_ALLOW, "/endentityprofilesrules/1"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/approve_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/create_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/delete_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/edit_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/keyrecovery"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/1/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/view_hardtoken"),
            new ExpectedResourceState(
                STATE_DENY,
                "/endentityprofilesrules/1/view_hardtoken/puk_data"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/approve_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/create_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/delete_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/edit_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/keyrecovery"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/2345/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/view_hardtoken"),
            new ExpectedResourceState(
                STATE_DENY,
                "/endentityprofilesrules/2345/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_DENY, "/hardtoken_functionality"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/edit_hardtoken_issuers"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/edit_hardtoken_profiles"),
            new ExpectedResourceState(
                STATE_DENY,
                "/hardtoken_functionality/issue_hardtoken_administrators"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/issue_hardtokens"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding/delete"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/delete/-12345"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/delete/67890"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding/modify"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/modify/-12345"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/modify/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/internalkeybinding/view"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/view/-12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/view/67890"),
            new ExpectedResourceState(STATE_DENY, "/peer"),
            new ExpectedResourceState(STATE_DENY, "/peer/manage"),
            new ExpectedResourceState(STATE_DENY, "/peer/modify"),
            new ExpectedResourceState(STATE_ALLOW, "/peer/view"),
            new ExpectedResourceState(STATE_DENY, "/peerincoming"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/readcert"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/writecert"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/writecrl"),
            new ExpectedResourceState(STATE_DENY, "/public_web_user"),
            new ExpectedResourceState(STATE_DENY, "/ra_functionality"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/approve_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/create_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/delete_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/edit_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/edit_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/edit_user_data_sources"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/keyrecovery"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_hardtoken"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_DENY, "/ra_master/invoke_api"),
            new ExpectedResourceState(STATE_DENY, "/ra_slave/manage"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit/auditor"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/export"),
            new ExpectedResourceState(
                STATE_ALLOW, "/secureaudit/auditor/select"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/verify"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit/log"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/log_custom_events"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/management/manage"),
            new ExpectedResourceState(STATE_DENY, "/services/edit"),
            new ExpectedResourceState(STATE_ALLOW, "/services/view"),
            new ExpectedResourceState(STATE_DENY, "/system_functionality"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/edit_administrator_privileges"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/"
                + "edit_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/edit_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_DENY, "/system_functionality/edit_systemconfiguration"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/view_administrator_privileges"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/"
                + "view_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/view_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_ALLOW, "/system_functionality/view_systemconfiguration"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules/123"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/123/fetch_userdata"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/123/remove_userdata"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules/456"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/456/fetch_userdata"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/456/remove_userdata"),
            new ExpectedResourceState(STATE_DENY, "/xcustomrule1"),
            new ExpectedResourceState(STATE_DENY, "/xcustomrule2"));
    testMigrationInternal(
        accessRulesMigratorSystemA,
        "Auditor",
        oldAccessRules,
        expectedNewAccessRules,
        expectedResourceAccesses);
    LOG.trace("<testMigrationAuditor()");
  }
  /**
   * Test.
   */
  @Test
  public void testMigrationSupervisor() {
    LOG.trace(">testMigrationSupervisor()");
    // Supervisor role as it would look using old rule templating (2/3 CAs, 2/2
    // EEPs)
    final List<AccessRuleData> oldAccessRules =
        Arrays.asList(
            new AccessRuleData(
                "", "/administrator", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "", "/ca/12345", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "", "/ca/-1011", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "",
                "/ca_functionality/view_certificate",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1/view_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1/view_end_entity_history",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1/view_hardtoken",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/view_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/view_end_entity_history",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/view_hardtoken",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/view_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/view_end_entity_history",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/view_hardtoken",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/secureaudit/auditor/select",
                AccessRuleState.RULE_ACCEPT,
                true));
    final List<ExpectedResourceState> expectedNewAccessRules =
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/administrator/"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/-1011/"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/12345/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_certificate/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/approve_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/create_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/delete_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/edit_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/keyrecovery/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/revoke_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY,
                "/endentityprofilesrules/1/view_hardtoken/puk_data/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/approve_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/create_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/delete_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/edit_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/keyrecovery/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/revoke_end_entity/"),
            new ExpectedResourceState(
                STATE_DENY,
                "/endentityprofilesrules/2345/view_hardtoken/puk_data/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_history/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_hardtoken/"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_hardtoken/puk_data/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/secureaudit/auditor/select/"));
    final List<ExpectedResourceState> expectedResourceAccesses =
        Arrays.asList(
            new ExpectedResourceState(STATE_DENY, "/"),
            new ExpectedResourceState(STATE_ALLOW, "/administrator"),
            new ExpectedResourceState(STATE_DENY, "/ca"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/-1011"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/12345"),
            new ExpectedResourceState(STATE_DENY, "/ca/67890"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/approve_caaction"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/basic_functions"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/basic_functions/activate_ca"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/create_certificate"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/create_crl"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_approval_profiles"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality/edit_ca"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_certificate_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_publisher"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality/renew_ca"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/view_approval_profiles"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality/view_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_certificate"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/view_certificate_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/view_publisher"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/activate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/activate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/activate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/deactivate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/deactivate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/deactivate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/delete"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/generate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/generate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/generate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/remove"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/remove/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/remove/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/test"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/test/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/test/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/modify"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use/12345"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/view"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/view/12345"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/view/67890"),
            new ExpectedResourceState(STATE_DENY, "/endentityprofilesrules"),
            new ExpectedResourceState(STATE_ALLOW, "/endentityprofilesrules/1"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/approve_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/create_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/delete_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/edit_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/keyrecovery"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/1/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/view_hardtoken"),
            new ExpectedResourceState(
                STATE_DENY,
                "/endentityprofilesrules/1/view_hardtoken/puk_data"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/approve_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/create_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/delete_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/edit_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/keyrecovery"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/2345/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/view_hardtoken"),
            new ExpectedResourceState(
                STATE_DENY,
                "/endentityprofilesrules/2345/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_DENY, "/hardtoken_functionality"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/edit_hardtoken_issuers"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/edit_hardtoken_profiles"),
            new ExpectedResourceState(
                STATE_DENY,
                "/hardtoken_functionality/issue_hardtoken_administrators"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/issue_hardtokens"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding/delete"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/delete/-12345"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/delete/67890"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding/modify"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/modify/-12345"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/modify/67890"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding/view"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/view/-12345"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/view/67890"),
            new ExpectedResourceState(STATE_DENY, "/peer"),
            new ExpectedResourceState(STATE_DENY, "/peer/manage"),
            new ExpectedResourceState(STATE_DENY, "/peer/modify"),
            new ExpectedResourceState(STATE_DENY, "/peer/view"),
            new ExpectedResourceState(STATE_DENY, "/peerincoming"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/readcert"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/writecert"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/writecrl"),
            new ExpectedResourceState(STATE_DENY, "/public_web_user"),
            new ExpectedResourceState(STATE_DENY, "/ra_functionality"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/approve_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/create_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/delete_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/edit_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/edit_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/edit_user_data_sources"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/keyrecovery"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_hardtoken"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_DENY, "/ra_master/invoke_api"),
            new ExpectedResourceState(STATE_DENY, "/ra_slave/manage"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit/auditor"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/export"),
            new ExpectedResourceState(
                STATE_ALLOW, "/secureaudit/auditor/select"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/verify"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit/log"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/log_custom_events"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/management/manage"),
            new ExpectedResourceState(STATE_DENY, "/services/edit"),
            new ExpectedResourceState(STATE_DENY, "/services/view"),
            new ExpectedResourceState(STATE_DENY, "/system_functionality"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/edit_administrator_privileges"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/"
                + "edit_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/edit_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_DENY, "/system_functionality/edit_systemconfiguration"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/view_administrator_privileges"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/"
                + "view_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/view_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_DENY, "/system_functionality/view_systemconfiguration"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules/123"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/123/fetch_userdata"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/123/remove_userdata"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules/456"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/456/fetch_userdata"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/456/remove_userdata"),
            new ExpectedResourceState(STATE_DENY, "/xcustomrule1"),
            new ExpectedResourceState(STATE_DENY, "/xcustomrule2"));
    testMigrationInternal(
        accessRulesMigratorSystemA,
        "Supervisor",
        oldAccessRules,
        expectedNewAccessRules,
        expectedResourceAccesses);
    LOG.trace("<testMigrationSupervisor()");
  }
  /**
   * Test.
   */
  @Test
  public void testMigrationRaAdministrator() {
    LOG.trace(">testMigrationRaAdministrator()");
    // RAAdministrator role as it would look using old rule templating (2/3 CAs,
    // 2/2 EEPs)
    final List<AccessRuleData> oldAccessRules =
        Arrays.asList(
            new AccessRuleData(
                "", "/administrator", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "", "/ca/12345", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "", "/ca/-1011", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "",
                "/ca_functionality/create_certificate",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ca_functionality/view_certificate",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1/approve_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1/create_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1/delete_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1/edit_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1/keyrecovery",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1/revoke_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1/view_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1/view_end_entity_history",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1/view_hardtoken",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/1/view_hardtoken/puk_data",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/approve_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/create_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/delete_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/edit_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/keyrecovery",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/revoke_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/view_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/view_end_entity_history",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/view_hardtoken",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/view_hardtoken/puk_data",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/approve_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/create_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/delete_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/edit_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/keyrecovery",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/revoke_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/view_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/view_end_entity_history",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/view_hardtoken",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/view_hardtoken/puk_data",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/secureaudit/auditor/select",
                AccessRuleState.RULE_ACCEPT,
                true));
    final List<ExpectedResourceState> expectedNewAccessRules =
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/administrator/"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/-1011/"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/12345/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/create_certificate/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_certificate/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/approve_end_entity/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/create_end_entity/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/delete_end_entity/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/edit_end_entity/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/keyrecovery/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/revoke_end_entity/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_history/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_hardtoken/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/secureaudit/auditor/select/"));
    final List<ExpectedResourceState> expectedResourceAccesses =
        Arrays.asList(
            new ExpectedResourceState(STATE_DENY, "/"),
            new ExpectedResourceState(STATE_ALLOW, "/administrator"),
            new ExpectedResourceState(STATE_DENY, "/ca"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/-1011"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/12345"),
            new ExpectedResourceState(STATE_DENY, "/ca/67890"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/approve_caaction"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/basic_functions"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/basic_functions/activate_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/create_certificate"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/create_crl"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_approval_profiles"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality/edit_ca"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_certificate_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_publisher"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality/renew_ca"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/view_approval_profiles"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality/view_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_certificate"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/view_certificate_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/view_publisher"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/activate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/activate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/activate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/deactivate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/deactivate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/deactivate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/delete"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/generate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/generate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/generate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/remove"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/remove/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/remove/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/test"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/test/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/test/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/modify"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use/12345"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/view"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/view/12345"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/view/67890"),
            new ExpectedResourceState(STATE_DENY, "/endentityprofilesrules"),
            new ExpectedResourceState(STATE_ALLOW, "/endentityprofilesrules/1"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/approve_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/create_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/delete_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/edit_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/keyrecovery"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/1/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/view_hardtoken"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/1/view_hardtoken/puk_data"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/approve_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/create_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/delete_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/edit_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/keyrecovery"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/2345/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/view_hardtoken"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/2345/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_DENY, "/hardtoken_functionality"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/edit_hardtoken_issuers"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/edit_hardtoken_profiles"),
            new ExpectedResourceState(
                STATE_DENY,
                "/hardtoken_functionality/issue_hardtoken_administrators"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/issue_hardtokens"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding/delete"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/delete/-12345"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/delete/67890"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding/modify"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/modify/-12345"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/modify/67890"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding/view"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/view/-12345"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/view/67890"),
            new ExpectedResourceState(STATE_DENY, "/peer"),
            new ExpectedResourceState(STATE_DENY, "/peer/manage"),
            new ExpectedResourceState(STATE_DENY, "/peer/modify"),
            new ExpectedResourceState(STATE_DENY, "/peer/view"),
            new ExpectedResourceState(STATE_DENY, "/peerincoming"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/readcert"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/writecert"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/writecrl"),
            new ExpectedResourceState(STATE_DENY, "/public_web_user"),
            new ExpectedResourceState(STATE_DENY, "/ra_functionality"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/approve_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/create_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/delete_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/edit_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/edit_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/edit_user_data_sources"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/keyrecovery"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_hardtoken"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_DENY, "/ra_master/invoke_api"),
            new ExpectedResourceState(STATE_DENY, "/ra_slave/manage"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit/auditor"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/export"),
            new ExpectedResourceState(
                STATE_ALLOW, "/secureaudit/auditor/select"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/verify"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit/log"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/log_custom_events"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/management/manage"),
            new ExpectedResourceState(STATE_DENY, "/services/edit"),
            new ExpectedResourceState(STATE_DENY, "/services/view"),
            new ExpectedResourceState(STATE_DENY, "/system_functionality"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/edit_administrator_privileges"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/"
                + "edit_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/edit_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_DENY, "/system_functionality/edit_systemconfiguration"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/view_administrator_privileges"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/"
                + "view_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/view_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_DENY, "/system_functionality/view_systemconfiguration"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules/123"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/123/fetch_userdata"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/123/remove_userdata"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules/456"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/456/fetch_userdata"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/456/remove_userdata"),
            new ExpectedResourceState(STATE_DENY, "/xcustomrule1"),
            new ExpectedResourceState(STATE_DENY, "/xcustomrule2"));
    testMigrationInternal(
        accessRulesMigratorSystemA,
        "RaAdministrator",
        oldAccessRules,
        expectedNewAccessRules,
        expectedResourceAccesses);
    LOG.trace("<testMigrationRaAdministrator()");
  }
  /**
   * Test.
   */
  @Test
  public void testMigrationCaAdministrator() {
    LOG.trace(">testMigrationCaAdministrator()");
    // CAAdministrator role as it would look using old rule templating (2/3 CAs)
    final List<AccessRuleData> oldAccessRules =
        Arrays.asList(
            new AccessRuleData(
                "", "/administrator", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "", "/ca/12345", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "", "/ca/-1011", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "", "/ca_functionality", AccessRuleState.RULE_ACCEPT, true),
            // The following 4 rules are redundant, but this is what using this
            // template would create
            new AccessRuleData(
                "",
                "/ca_functionality/edit_publisher",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ca_functionality/view_ca",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ca_functionality/view_certificate_profiles",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ca_functionality/view_publisher",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "", "/cryptotoken/view", AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleData(
                "",
                "/endentityprofilesrules",
                AccessRuleState.RULE_ACCEPT,
                true),
            new AccessRuleData(
                "",
                "/hardtoken_functionality/edit_hardtoken_issuers",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/hardtoken_functionality/edit_hardtoken_profiles",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/internalkeybinding/delete",
                AccessRuleState.RULE_ACCEPT,
                true),
            new AccessRuleData(
                "",
                "/internalkeybinding/modify",
                AccessRuleState.RULE_ACCEPT,
                true),
            new AccessRuleData(
                "",
                "/internalkeybinding/view",
                AccessRuleState.RULE_ACCEPT,
                true),
            new AccessRuleData(
                "", "/ra_functionality", AccessRuleState.RULE_ACCEPT, true),
            // The following rule is redundant, but this is what using this
            // template would create
            new AccessRuleData(
                "",
                "/ra_functionality/view_end_entity_profiles",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/secureaudit/auditor/select",
                AccessRuleState.RULE_ACCEPT,
                true),
            new AccessRuleData(
                "", "/secureaudit/log", AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleData(
                "",
                "/system_functionality/edit_administrator_privileges",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/system_functionality/view_administrator_privileges",
                AccessRuleState.RULE_ACCEPT,
                false));
    final List<ExpectedResourceState> expectedNewAccessRules =
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/administrator/"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/-1011/"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/12345/"),
            new ExpectedResourceState(STATE_ALLOW, "/ca_functionality/"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/view/"),
            new ExpectedResourceState(STATE_ALLOW, "/endentityprofilesrules/"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/hardtoken_functionality/edit_hardtoken_issuers/"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/hardtoken_functionality/edit_hardtoken_profiles/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/delete/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/modify/"),
            new ExpectedResourceState(STATE_ALLOW, "/internalkeybinding/view/"),
            new ExpectedResourceState(STATE_ALLOW, "/ra_functionality/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/secureaudit/auditor/select/"),
            new ExpectedResourceState(STATE_ALLOW, "/secureaudit/log/"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/edit_administrator_privileges/"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/view_administrator_privileges/"));
    final List<ExpectedResourceState> expectedResourceAccesses =
        Arrays.asList(
            new ExpectedResourceState(STATE_DENY, "/"),
            new ExpectedResourceState(STATE_ALLOW, "/administrator"),
            new ExpectedResourceState(STATE_DENY, "/ca"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/-1011"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/12345"),
            new ExpectedResourceState(STATE_DENY, "/ca/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/ca_functionality"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/approve_caaction"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/basic_functions"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/basic_functions/activate_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/create_certificate"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/create_crl"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/edit_approval_profiles"),
            new ExpectedResourceState(STATE_ALLOW, "/ca_functionality/edit_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/edit_certificate_profiles"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/edit_publisher"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/renew_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_approval_profiles"),
            new ExpectedResourceState(STATE_ALLOW, "/ca_functionality/view_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_certificate"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_certificate_profiles"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_publisher"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/activate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/activate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/activate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/deactivate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/deactivate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/deactivate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/delete"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/generate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/generate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/generate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/remove"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/remove/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/remove/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/test"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/test/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/test/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/modify"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use/12345"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/view"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/view/12345"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/view/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/endentityprofilesrules"),
            new ExpectedResourceState(STATE_ALLOW, "/endentityprofilesrules/1"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/approve_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/create_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/delete_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/edit_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/keyrecovery"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/1/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/1/view_hardtoken"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/1/view_hardtoken/puk_data"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/approve_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/create_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/delete_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/edit_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/keyrecovery"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/2345/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/view_hardtoken"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/2345/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_DENY, "/hardtoken_functionality"),
            new ExpectedResourceState(
                STATE_ALLOW, "/hardtoken_functionality/edit_hardtoken_issuers"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/hardtoken_functionality/edit_hardtoken_profiles"),
            new ExpectedResourceState(
                STATE_DENY,
                "/hardtoken_functionality/issue_hardtoken_administrators"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/issue_hardtokens"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/delete"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/delete/-12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/delete/67890"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/modify"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/modify/-12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/modify/67890"),
            new ExpectedResourceState(STATE_ALLOW, "/internalkeybinding/view"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/view/-12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/view/67890"),
            new ExpectedResourceState(STATE_DENY, "/peer"),
            new ExpectedResourceState(STATE_DENY, "/peer/manage"),
            new ExpectedResourceState(STATE_DENY, "/peer/modify"),
            new ExpectedResourceState(STATE_DENY, "/peer/view"),
            new ExpectedResourceState(STATE_DENY, "/peerincoming"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/readcert"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/writecert"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/writecrl"),
            new ExpectedResourceState(STATE_DENY, "/public_web_user"),
            new ExpectedResourceState(STATE_ALLOW, "/ra_functionality"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/approve_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/create_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/delete_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/edit_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/edit_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/edit_user_data_sources"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/keyrecovery"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_hardtoken"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_DENY, "/ra_master/invoke_api"),
            new ExpectedResourceState(STATE_DENY, "/ra_slave/manage"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit/auditor"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/export"),
            new ExpectedResourceState(
                STATE_ALLOW, "/secureaudit/auditor/select"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/verify"),
            new ExpectedResourceState(STATE_ALLOW, "/secureaudit/log"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/log_custom_events"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/management/manage"),
            new ExpectedResourceState(STATE_DENY, "/services/edit"),
            new ExpectedResourceState(STATE_DENY, "/services/view"),
            new ExpectedResourceState(STATE_DENY, "/system_functionality"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/edit_administrator_privileges"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/"
                + "edit_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/edit_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_DENY, "/system_functionality/edit_systemconfiguration"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/system_functionality/view_administrator_privileges"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/"
                + "view_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/view_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_DENY, "/system_functionality/view_systemconfiguration"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules/123"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/123/fetch_userdata"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/123/remove_userdata"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules/456"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/456/fetch_userdata"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/456/remove_userdata"),
            new ExpectedResourceState(STATE_DENY, "/xcustomrule1"),
            new ExpectedResourceState(STATE_DENY, "/xcustomrule2"));
    testMigrationInternal(
        accessRulesMigratorSystemA,
        "CaAdministrator",
        oldAccessRules,
        expectedNewAccessRules,
        expectedResourceAccesses);
    LOG.trace("<testMigrationCaAdministrator()");
  }
  /**
   * Test.
   */
  @Test
  public void testMigrationPeerRa() {
    LOG.trace(">testMigrationPeerRa()");
    // Peer RA role as it would look using old rule templating (1/3 CAs, 1/2
    // EEPs)
    final List<AccessRuleData> oldAccessRules =
        Arrays.asList(
            new AccessRuleData(
                "", "/ca/12345", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "",
                "/ca_functionality/create_certificate",
                AccessRuleState.RULE_ACCEPT,
                false),
            // The next one is a legacy rule that is not in use (and should
            // disappear during conversion)
            new AccessRuleData(
                "",
                "/ca_functionality/store_certificate",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ca_functionality/view_ca",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ca_functionality/view_certificate",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/approve_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/create_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/delete_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/edit_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/keyrecovery",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/revoke_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/view_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/endentityprofilesrules/2345/view_end_entity_history",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/approve_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/create_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/delete_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/edit_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/keyrecovery",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/revoke_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/view_end_entity",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/view_end_entity_history",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_functionality/view_end_entity_profiles",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/ra_master/invoke_api",
                AccessRuleState.RULE_ACCEPT,
                false));
    final List<ExpectedResourceState> expectedNewAccessRules =
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/ca/12345/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/create_certificate/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_ca/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_certificate/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/view_hardtoken/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/approve_end_entity/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/create_end_entity/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/delete_end_entity/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/edit_end_entity/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/keyrecovery/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/revoke_end_entity/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_history/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_profiles/"),
            new ExpectedResourceState(STATE_ALLOW, "/ra_master/invoke_api/"));
    final List<ExpectedResourceState> expectedResourceAccesses =
        Arrays.asList(
            new ExpectedResourceState(STATE_DENY, "/"),
            new ExpectedResourceState(STATE_DENY, "/administrator"),
            new ExpectedResourceState(STATE_DENY, "/ca"),
            new ExpectedResourceState(STATE_DENY, "/ca/-1011"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/12345"),
            new ExpectedResourceState(STATE_DENY, "/ca/67890"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/approve_caaction"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/basic_functions"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/basic_functions/activate_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/create_certificate"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/create_crl"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_approval_profiles"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality/edit_ca"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_certificate_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_publisher"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality/renew_ca"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/view_approval_profiles"),
            new ExpectedResourceState(STATE_ALLOW, "/ca_functionality/view_ca"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ca_functionality/view_certificate"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/view_certificate_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/view_publisher"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/activate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/activate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/activate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/deactivate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/deactivate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/deactivate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/delete"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/generate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/generate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/generate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/remove"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/remove/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/remove/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/test"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/test/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/test/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/modify"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use/12345"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/view"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/view/12345"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/view/67890"),
            new ExpectedResourceState(STATE_DENY, "/endentityprofilesrules"),
            new ExpectedResourceState(STATE_DENY, "/endentityprofilesrules/1"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/approve_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/create_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/delete_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/edit_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/keyrecovery"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/view_end_entity"),
            new ExpectedResourceState(
                STATE_DENY,
                "/endentityprofilesrules/1/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/view_hardtoken"),
            new ExpectedResourceState(
                STATE_DENY,
                "/endentityprofilesrules/1/view_hardtoken/puk_data"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/approve_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/create_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/delete_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/edit_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/keyrecovery"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/endentityprofilesrules/2345/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW,
                "/endentityprofilesrules/2345/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/view_hardtoken"),
            new ExpectedResourceState(
                STATE_DENY,
                "/endentityprofilesrules/2345/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_DENY, "/hardtoken_functionality"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/edit_hardtoken_issuers"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/edit_hardtoken_profiles"),
            new ExpectedResourceState(
                STATE_DENY,
                "/hardtoken_functionality/issue_hardtoken_administrators"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/issue_hardtokens"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding/delete"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/delete/-12345"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/delete/67890"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding/modify"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/modify/-12345"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/modify/67890"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding/view"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/view/-12345"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/view/67890"),
            new ExpectedResourceState(STATE_DENY, "/peer"),
            new ExpectedResourceState(STATE_DENY, "/peer/manage"),
            new ExpectedResourceState(STATE_DENY, "/peer/modify"),
            new ExpectedResourceState(STATE_DENY, "/peer/view"),
            new ExpectedResourceState(STATE_DENY, "/peerincoming"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/readcert"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/writecert"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish/writecrl"),
            new ExpectedResourceState(STATE_DENY, "/public_web_user"),
            new ExpectedResourceState(STATE_DENY, "/ra_functionality"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/approve_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/create_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/delete_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/edit_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/edit_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/edit_user_data_sources"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/keyrecovery"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_ALLOW, "/ra_functionality/view_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_hardtoken"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_ALLOW, "/ra_master/invoke_api"),
            new ExpectedResourceState(STATE_DENY, "/ra_slave/manage"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit/auditor"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/export"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/select"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/verify"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit/log"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/log_custom_events"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/management/manage"),
            new ExpectedResourceState(STATE_DENY, "/services/edit"),
            new ExpectedResourceState(STATE_DENY, "/services/view"),
            new ExpectedResourceState(STATE_DENY, "/system_functionality"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/edit_administrator_privileges"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/"
                + "edit_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/edit_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_DENY, "/system_functionality/edit_systemconfiguration"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/view_administrator_privileges"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/"
                + "view_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/view_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_DENY, "/system_functionality/view_systemconfiguration"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules/123"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/123/fetch_userdata"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/123/remove_userdata"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules/456"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/456/fetch_userdata"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/456/remove_userdata"),
            new ExpectedResourceState(STATE_DENY, "/xcustomrule1"),
            new ExpectedResourceState(STATE_DENY, "/xcustomrule2"));
    testMigrationInternal(
        accessRulesMigratorSystemA,
        "PeerRa",
        oldAccessRules,
        expectedNewAccessRules,
        expectedResourceAccesses);
    LOG.trace("<testMigrationPeerRa()");
  }
  /**
   * Test.
   */
  @Test
  public void testMigrationPeerCa() {
    LOG.trace(">testMigrationPeerCa()");
    // Peer CA role as it would look using old rule templating allowed to
    // publish certs+crls, renew OCSP signer and poll for RA messages
    // (1 external CA, 1 OcspKeyBinding with keys in 1 CryptoToken)
    final List<AccessRuleData> oldAccessRules =
        Arrays.asList(
            new AccessRuleData(
                "", "/ca/67890", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "",
                "/cryptotoken/view/67890",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/cryptotoken/use/67890",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/cryptotoken/keys/generate/67890",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/internalkeybinding/modify/-12345",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/internalkeybinding/view/-12345",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "", "/peerincoming", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "",
                "/peerpublish/readcert",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/peerpublish/writecert",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "",
                "/peerpublish/writecrl",
                AccessRuleState.RULE_ACCEPT,
                false),
            new AccessRuleData(
                "", "/ra_slave/manage", AccessRuleState.RULE_ACCEPT, false));
    final List<ExpectedResourceState> expectedNewAccessRules =
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/ca/67890/"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/view/67890/"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/use/67890/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/keys/generate/67890/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/modify/-12345/"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/view/-12345/"),
            new ExpectedResourceState(STATE_ALLOW, "/peerincoming/"),
            new ExpectedResourceState(STATE_ALLOW, "/peerpublish/readcert/"),
            new ExpectedResourceState(STATE_ALLOW, "/peerpublish/writecert/"),
            new ExpectedResourceState(STATE_ALLOW, "/peerpublish/writecrl/"),
            new ExpectedResourceState(STATE_ALLOW, "/ra_slave/manage/"));
    final List<ExpectedResourceState> expectedResourceAccesses =
        Arrays.asList(
            new ExpectedResourceState(STATE_DENY, "/"),
            new ExpectedResourceState(STATE_DENY, "/administrator"),
            new ExpectedResourceState(STATE_DENY, "/ca"),
            new ExpectedResourceState(STATE_DENY, "/ca/-1011"),
            new ExpectedResourceState(STATE_DENY, "/ca/12345"),
            new ExpectedResourceState(STATE_ALLOW, "/ca/67890"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/approve_caaction"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/basic_functions"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/basic_functions/activate_ca"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/create_certificate"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/create_crl"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_approval_profiles"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality/edit_ca"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_certificate_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/edit_publisher"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality/renew_ca"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/view_approval_profiles"),
            new ExpectedResourceState(STATE_DENY, "/ca_functionality/view_ca"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/view_certificate"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/view_certificate_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ca_functionality/view_publisher"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/activate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/activate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/activate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/deactivate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/deactivate/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/deactivate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/delete"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/generate"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/generate/12345"),
            new ExpectedResourceState(
                STATE_ALLOW, "/cryptotoken/keys/generate/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/remove"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/remove/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/remove/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/keys/test"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/test/12345"),
            new ExpectedResourceState(
                STATE_DENY, "/cryptotoken/keys/test/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/modify"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/use/12345"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/use/67890"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/view"),
            new ExpectedResourceState(STATE_DENY, "/cryptotoken/view/12345"),
            new ExpectedResourceState(STATE_ALLOW, "/cryptotoken/view/67890"),
            new ExpectedResourceState(STATE_DENY, "/endentityprofilesrules"),
            new ExpectedResourceState(STATE_DENY, "/endentityprofilesrules/1"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/approve_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/create_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/delete_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/edit_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/keyrecovery"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/view_end_entity"),
            new ExpectedResourceState(
                STATE_DENY,
                "/endentityprofilesrules/1/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/1/view_hardtoken"),
            new ExpectedResourceState(
                STATE_DENY,
                "/endentityprofilesrules/1/view_hardtoken/puk_data"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/approve_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/create_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/delete_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/edit_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/keyrecovery"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/view_end_entity"),
            new ExpectedResourceState(
                STATE_DENY,
                "/endentityprofilesrules/2345/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_DENY, "/endentityprofilesrules/2345/view_hardtoken"),
            new ExpectedResourceState(
                STATE_DENY,
                "/endentityprofilesrules/2345/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_DENY, "/hardtoken_functionality"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/edit_hardtoken_issuers"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/edit_hardtoken_profiles"),
            new ExpectedResourceState(
                STATE_DENY,
                "/hardtoken_functionality/issue_hardtoken_administrators"),
            new ExpectedResourceState(
                STATE_DENY, "/hardtoken_functionality/issue_hardtokens"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding/delete"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/delete/-12345"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/delete/67890"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding/modify"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/modify/-12345"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/modify/67890"),
            new ExpectedResourceState(STATE_DENY, "/internalkeybinding/view"),
            new ExpectedResourceState(
                STATE_ALLOW, "/internalkeybinding/view/-12345"),
            new ExpectedResourceState(
                STATE_DENY, "/internalkeybinding/view/67890"),
            new ExpectedResourceState(STATE_DENY, "/peer"),
            new ExpectedResourceState(STATE_DENY, "/peer/manage"),
            new ExpectedResourceState(STATE_DENY, "/peer/modify"),
            new ExpectedResourceState(STATE_DENY, "/peer/view"),
            new ExpectedResourceState(STATE_ALLOW, "/peerincoming"),
            new ExpectedResourceState(STATE_DENY, "/peerpublish"),
            new ExpectedResourceState(STATE_ALLOW, "/peerpublish/readcert"),
            new ExpectedResourceState(STATE_ALLOW, "/peerpublish/writecert"),
            new ExpectedResourceState(STATE_ALLOW, "/peerpublish/writecrl"),
            new ExpectedResourceState(STATE_DENY, "/public_web_user"),
            new ExpectedResourceState(STATE_DENY, "/ra_functionality"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/approve_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/create_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/delete_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/edit_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/edit_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/edit_user_data_sources"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/keyrecovery"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/revoke_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_end_entity"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_end_entity_history"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_end_entity_profiles"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_hardtoken"),
            new ExpectedResourceState(
                STATE_DENY, "/ra_functionality/view_hardtoken/puk_data"),
            new ExpectedResourceState(STATE_DENY, "/ra_master/invoke_api"),
            new ExpectedResourceState(STATE_ALLOW, "/ra_slave/manage"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit/auditor"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/export"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/select"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/auditor/verify"),
            new ExpectedResourceState(STATE_DENY, "/secureaudit/log"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/log_custom_events"),
            new ExpectedResourceState(
                STATE_DENY, "/secureaudit/management/manage"),
            new ExpectedResourceState(STATE_DENY, "/services/edit"),
            new ExpectedResourceState(STATE_DENY, "/services/view"),
            new ExpectedResourceState(STATE_DENY, "/system_functionality"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/edit_administrator_privileges"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/"
                + "edit_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/edit_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_DENY, "/system_functionality/edit_systemconfiguration"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/view_administrator_privileges"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/"
                + "view_available_custom_certificate_extensions"),
            new ExpectedResourceState(
                STATE_DENY,
                "/system_functionality/view_available_extended_key_usages"),
            new ExpectedResourceState(
                STATE_DENY, "/system_functionality/view_systemconfiguration"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules/123"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/123/fetch_userdata"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/123/remove_userdata"),
            new ExpectedResourceState(STATE_DENY, "/userdatasourcesrules/456"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/456/fetch_userdata"),
            new ExpectedResourceState(
                STATE_DENY, "/userdatasourcesrules/456/remove_userdata"),
            new ExpectedResourceState(STATE_DENY, "/xcustomrule1"),
            new ExpectedResourceState(STATE_DENY, "/xcustomrule2"));
    testMigrationInternal(
        accessRulesMigratorSystemA,
        "PeerCa",
        oldAccessRules,
        expectedNewAccessRules,
        expectedResourceAccesses);
    LOG.trace("<testMigrationPeerCa()");
  }

  /**
   * Test that sub-resource comparisons checks everything between slashes and
   * not other sibling resources.
   */
  @Test
  public void testStartsWithSame() {
    LOG.trace(">testStartsWithSame()");
    final AccessRulesMigrator accessRulesMigrator =
        new AccessRulesMigrator(Arrays.asList("/", "/a", "/a/test", "/abc"));
    testMigrationInternal(
        accessRulesMigrator,
        "StartsWithSame 1",
        Arrays.asList(
            new AccessRuleData("", "/a", AccessRuleState.RULE_ACCEPT, true)),
        Arrays.asList(new ExpectedResourceState(STATE_ALLOW, "/a/")),
        new ArrayList<ExpectedResourceState>());
    testMigrationInternal(
        accessRulesMigrator,
        "StartsWithSame 2",
        Arrays.asList(
            new AccessRuleData("", "/a", AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleData("", "/abc", AccessRuleState.RULE_ACCEPT, true)),
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/a/"),
            new ExpectedResourceState(STATE_ALLOW, "/abc/")),
        new ArrayList<ExpectedResourceState>());
    testMigrationInternal(
        accessRulesMigrator,
        "StartsWithSame 3",
        Arrays.asList(
            new AccessRuleData("", "/a", AccessRuleState.RULE_ACCEPT, false)),
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/a/"),
            new ExpectedResourceState(STATE_DENY, "/a/test/")),
        new ArrayList<ExpectedResourceState>());
    testMigrationInternal(
        accessRulesMigrator,
        "StartsWithSame 4",
        Arrays.asList(
            new AccessRuleData("", "/a", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData("", "/abc", AccessRuleState.RULE_ACCEPT, false)),
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/a/"),
            new ExpectedResourceState(STATE_DENY, "/a/test/"),
            new ExpectedResourceState(STATE_ALLOW, "/abc/")),
        new ArrayList<ExpectedResourceState>());
    testMigrationInternal(
        accessRulesMigrator,
        "StartsWithSame 5",
        Arrays.asList(
            new AccessRuleData("", "/a", AccessRuleState.RULE_DECLINE, false),
            new AccessRuleData("", "/abc", AccessRuleState.RULE_ACCEPT, false)),
        Arrays.asList(new ExpectedResourceState(STATE_ALLOW, "/abc/")),
        new ArrayList<ExpectedResourceState>());
    testMigrationInternal(
        accessRulesMigrator,
        "StartsWithSame 6",
        Arrays.asList(
            new AccessRuleData("", "/abc", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData("", "/a", AccessRuleState.RULE_DECLINE, false)),
        Arrays.asList(new ExpectedResourceState(STATE_ALLOW, "/abc/")),
        new ArrayList<ExpectedResourceState>());
    LOG.trace("<testStartsWithSame()");
  }

  /**
   * Test that even if positive access rules exists for sub-resources, they are
   * ignored after the conversion.
   */
  @Test
  public void testOldDeclineIsIrreversable() {
    LOG.trace(">testOldDeclineIsIrreversable()");
    final AccessRulesMigrator accessRulesMigrator =
        new AccessRulesMigrator(Arrays.asList("/", "/a", "/a/b", "/a/b/c"));
    testMigrationInternal(
        accessRulesMigrator,
        "OldDeclineIsIrreversable 1",
        Arrays.asList(
            new AccessRuleData("", "/", AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleData("", "/a", AccessRuleState.RULE_DECLINE, true),
            new AccessRuleData("", "/a/b", AccessRuleState.RULE_ACCEPT, true)),
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/"),
            new ExpectedResourceState(STATE_DENY, "/a/")),
        new ArrayList<ExpectedResourceState>());
    testMigrationInternal(
        accessRulesMigrator,
        "OldDeclineIsIrreversable 2",
        Arrays.asList(
            new AccessRuleData("", "/a", AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleData("", "/a/b", AccessRuleState.RULE_DECLINE, true),
            new AccessRuleData(
                "", "/a/b/c", AccessRuleState.RULE_ACCEPT, true)),
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/a/"),
            new ExpectedResourceState(STATE_DENY, "/a/b/")),
        new ArrayList<ExpectedResourceState>());
    testMigrationInternal(
        accessRulesMigrator,
        "OldDeclineIsIrreversable 3",
        Arrays.asList(
            new AccessRuleData("", "/", AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleData("", "/a", AccessRuleState.RULE_DECLINE, false),
            new AccessRuleData("", "/a/b", AccessRuleState.RULE_ACCEPT, false)),
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/"),
            new ExpectedResourceState(STATE_DENY, "/a/")),
        new ArrayList<ExpectedResourceState>());
    testMigrationInternal(
        accessRulesMigrator,
        "OldDeclineIsIrreversable 4",
        Arrays.asList(
            new AccessRuleData("", "/", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData("", "/a", AccessRuleState.RULE_DECLINE, false),
            new AccessRuleData("", "/a/b", AccessRuleState.RULE_ACCEPT, false)),
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/"),
            new ExpectedResourceState(STATE_DENY, "/a/")),
        new ArrayList<ExpectedResourceState>());
    testMigrationInternal(
        accessRulesMigrator,
        "OldDeclineIsIrreversable 4",
        Arrays.asList(
            new AccessRuleData("", "/", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData("", "/a", AccessRuleState.RULE_DECLINE, false),
            new AccessRuleData(
                "", "/a/b/c", AccessRuleState.RULE_ACCEPT, false)),
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/"),
            new ExpectedResourceState(STATE_DENY, "/a/")),
        new ArrayList<ExpectedResourceState>());
    LOG.trace("<testOldDeclineIsIrreversable()");
  }

  /**
   * Test that recursive accept rules are not overwritten by DENY of sub
   * resources.
   */
  @Test
  public void testKeepAcceptRecursiveForSubResources() {
    LOG.trace(">testKeepAcceptRecursiveForSubResources()");
    final AccessRulesMigrator accessRulesMigrator =
        new AccessRulesMigrator(
            Arrays.asList("/", "/a", "/a/b", "/a/b/1", "/a/b/2", "/a/c"));
    testMigrationInternal(
        accessRulesMigrator,
        "KeepAcceptRecursiveForSubResources 1",
        Arrays.asList(
            new AccessRuleData("", "/a", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData("", "/a/b", AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleData(
                "", "/a/c", AccessRuleState.RULE_DECLINE, false)),
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/a/"),
            new ExpectedResourceState(STATE_DENY, "/a/c/")),
        new ArrayList<ExpectedResourceState>());
    testMigrationInternal(
        accessRulesMigrator,
        "KeepAcceptRecursiveForSubResources 2",
        Arrays.asList(
            new AccessRuleData("", "/a", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData("", "/a/b", AccessRuleState.RULE_ACCEPT, true)),
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/a/"),
            new ExpectedResourceState(STATE_DENY, "/a/c/")),
        new ArrayList<ExpectedResourceState>());
    testMigrationInternal(
        accessRulesMigrator,
        "KeepAcceptRecursiveForSubResources 3",
        Arrays.asList(
            new AccessRuleData("", "/a", AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleData(
                "", "/a/b/2", AccessRuleState.RULE_DECLINE, false)),
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/a/"),
            new ExpectedResourceState(STATE_DENY, "/a/b/2/")),
        new ArrayList<ExpectedResourceState>());
    testMigrationInternal(
        accessRulesMigrator,
        "KeepAcceptRecursiveForSubResources 4",
        Arrays.asList(
            new AccessRuleData("", "/a", AccessRuleState.RULE_ACCEPT, true),
            new AccessRuleData(
                "", "/a/b/2", AccessRuleState.RULE_ACCEPT, false)),
        Arrays.asList(new ExpectedResourceState(STATE_ALLOW, "/a/")),
        new ArrayList<ExpectedResourceState>());
    testMigrationInternal(
        accessRulesMigrator,
        "KeepAcceptRecursiveForSubResources 5",
        Arrays.asList(
            new AccessRuleData("", "/a", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "", "/a/b/2", AccessRuleState.RULE_DECLINE, false)),
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/a/"),
            new ExpectedResourceState(STATE_DENY, "/a/b/"),
            new ExpectedResourceState(STATE_DENY, "/a/c/")),
        new ArrayList<ExpectedResourceState>());
    testMigrationInternal(
        accessRulesMigrator,
        "KeepAcceptRecursiveForSubResources 6",
        Arrays.asList(
            new AccessRuleData("", "/a", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData("", "/a/b/", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "", "/a/b/2", AccessRuleState.RULE_DECLINE, false)),
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/a/"),
            new ExpectedResourceState(STATE_DENY, "/a/b/1/"),
            new ExpectedResourceState(STATE_DENY, "/a/b/2/"),
            new ExpectedResourceState(STATE_DENY, "/a/c/")),
        new ArrayList<ExpectedResourceState>());
    testMigrationInternal(
        accessRulesMigrator,
        "KeepAcceptRecursiveForSubResources 7",
        Arrays.asList(
            new AccessRuleData("", "/a", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "", "/a/b/1", AccessRuleState.RULE_ACCEPT, false),
            new AccessRuleData(
                "", "/a/b/2", AccessRuleState.RULE_DECLINE, false)),
        Arrays.asList(
            new ExpectedResourceState(STATE_ALLOW, "/a/"),
            new ExpectedResourceState(STATE_DENY, "/a/b/"),
            new ExpectedResourceState(STATE_ALLOW, "/a/b/1/"),
            new ExpectedResourceState(STATE_DENY, "/a/c/")),
        new ArrayList<ExpectedResourceState>());
    LOG.trace("<testKeepAcceptRecursiveForSubResources()");
  }

  /** Helper class for keeping a String and boolean. */
  private class ExpectedResourceState {
      /** param. */
    private final boolean state;
    /** param. */
    private final String resource;

    ExpectedResourceState(final boolean aState, final String aResource) {
      this.state = aState;
      this.resource = aResource;
    }
  }

  /**
   * Perform migration and validate the result.
   *
   * @param accessRulesMigrator the migrator, complete with all existing access
   *     rules on the "system"
   * @param roleName for logging
   * @param oldAccessRules old format of access rules for role
   * @param expectedAccessRules exact list of new access rules this migration
   *     should lead to
   * @param expectedResourceAccesses access
   */
  private void testMigrationInternal(
      final AccessRulesMigrator accessRulesMigrator,
      final String roleName,
      final List<AccessRuleData> oldAccessRules,
      final List<ExpectedResourceState> expectedAccessRules,
      final List<ExpectedResourceState> expectedResourceAccesses) {
    LOG.debug("testMigrationInternal from role '" + roleName + "'.");
    final HashMap<String, Boolean> newAccessRules =
        accessRulesMigrator.toNewAccessRules(oldAccessRules, roleName);
    LOG.debug("newAccessRules role '" + roleName + "':");
    debugLogAccessRules(newAccessRules);
    // Verify that new rules are the expected
    final HashMap<String, Boolean> uncheckedAccessRules =
        new HashMap<>(newAccessRules);
    for (final ExpectedResourceState expectedAccessRule : expectedAccessRules) {
      assertEquals(
          "Rule '"
              + expectedAccessRule.resource
              + "' was not present with the correct state.",
          expectedAccessRule.state,
          uncheckedAccessRules.remove(expectedAccessRule.resource));
    }
    LOG.debug("uncheckedAccessRules role '" + roleName + "':");
    debugLogAccessRules(uncheckedAccessRules);
    assertEquals(
        "Unexpected access rules were present. See debug output for a list.",
        0,
        uncheckedAccessRules.size());
    // Verify that new rules grant/deny the provided resources as expected
    for (final ExpectedResourceState expectedResourceAccess
        : expectedResourceAccesses) {
      final String errorMessage =
          expectedResourceAccess.state
              ? ERRMSG_DENIED_TO_ALLOWED
              : ERRMSG_ALLOWED_TO_DENIED;
      assertEquals(
          errorMessage + ": " + expectedResourceAccess.resource,
          expectedResourceAccess.state,
          AccessRulesHelper.hasAccessToResource(
              newAccessRules, expectedResourceAccess.resource));
    }
  }

  private void debugLogAccessRules(final HashMap<String, Boolean> accessRules) {
    final List<Entry<String, Boolean>> accessRulesList =
        AccessRulesHelper.getAsListSortedByKey(accessRules);
    for (final Entry<String, Boolean> entry : accessRulesList) {
      LOG.debug(
          " "
              + entry.getKey()
              + ":"
              + (entry.getValue().booleanValue() ? "allow" : "deny"));
    }
  }
}
