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
package org.cesecore;

import java.io.Serializable;

/**
 * The error code describes the cause of an EjbcaException. Usage:
 *
 * <pre>
 * (caught EjbcaException e)
 * If (e.equals(ErrorCode.SIGNATURE_ERROR) {
 *     System.out.println("Error verifying signature (popp) of request");
 * }
 * </pre>
 *
 * @version $Id: ErrorCode.java 30470 2018-11-12 11:02:11Z samuellb $
 */
public final class ErrorCode implements Serializable {

  private static final long serialVersionUID = -5727877733175038546L;

  /** Internal error code. */
  private String internalErrorCode = S_NOT_SPECIFIED;
  /** CA does not exist. */
  private static final String S_CA_NOT_EXISTS =
      "CA_NOT_EXISTS";
  /** CA already exists. */
  private static final String S_CA_ALREADY_EXISTS =
      "CA_ALREADY_EXISTS";
  /** CA ID can't be equal to zero. */
  private static final String S_CA_ID_EQUALS_ZERO =
      "CA_ID_EQUALS_ZERO";
  /** End Entity profile does not exist. */
  private static final String S_EE_PROFILE_NOT_EXISTS =
      "EE_PROFILE_NOT_EXISTS";
  /** Certificate profile does not exist. */
  private static final String S_CERT_PROFILE_NOT_EXISTS =
      "CERT_PROFILE_NOT_EXISTS";
  /** Hard token issuer doens't exists. */
  private static final String S_HARD_TOKEN_ISSUER_NOT_EXISTS =
      "HARD_TOKEN_ISSUER_NOT_EXISTS";
  /** Hard token does not exist. */
  private static final String S_HARD_TOKEN_NOT_EXISTS =
      "HARD_TOKEN_NOT_EXISTS";
  /** Unknown token type. */
  private static final String S_UNKOWN_TOKEN_TYPE =
      "UNKOWN_TOKEN_TYPE";
  /** Client authentication certificate not received. */
  private static final String S_AUTH_CERT_NOT_RECEIVED =
      "AUTH_CERT_NOT_RECEIVED";
  /** User doesn't exist. */
  private static final String S_USER_NOT_FOUND =
      "USER_NOT_FOUND";
  /** Wrong token type for user. */
  private static final String S_BAD_USER_TOKEN_TYPE =
      "BAD_USER_TOKEN_TYPE";
  /** Generated certificate is invalid
   * (usually validated with external command). */
  private static final String S_INVALID_CERTIFICATE =
      "INVALID_CERTIFICATE";
  /** Provided key is invalid. */
  private static final String S_INVALID_KEY =
      "INVALID_KEY";
  /**  User key is illegal (key length too small). */
  private static final String S_ILLEGAL_KEY =
      "ILLEGAL_KEY";
  /** User wrong status. */
  private static final String S_USER_WRONG_STATUS =
      "USER_WRONG_STATUS";
  /** User already exists. */
  private static final String S_USER_ALREADY_EXISTS =
      "USER_ALREADY_EXISTS";
  /** Login error. */
  private static final String S_LOGIN_ERROR = "LOGIN_ERROR";
  /** Error in signature. */
  private static final String S_SIGNATURE_ERROR =
      "SIGNATURE_ERROR";
  /** Invalid key specification. */
  private static final String S_INVALID_KEY_SPEC =
      "INVALID_KEY_SPEC";
  /** Certificate wrong status. */
  private static final String S_CERT_WRONG_STATUS =
      "CERT_WRONG_STATUS";
  /** Key recovery feature not enabled. */
  private static final String S_KEY_RECOVERY_NOT_AVAILABLE =
      "KEY_RECOVERY_NOT_AVAILABLE";
  /** Validity format badly formatted (must be defined in days). */
  private static final String S_BAD_VALIDITY_FORMAT =
      "BAD_VALIDITY_FORMAT";
  /** Key store type not supported. */
  private static final String S_NOT_SUPPORTED_KEY_STORE =
      "NOT_SUPPORTED_KEY_STORE";
  /** Not supported request type. */
  private static final String S_NOT_SUPPORTED_REQUEST_TYPE =
      "NOT_SUPPORTED_REQUEST_TYPE";
  /** Not supported PIN type. */
  private static final String S_NOT_SUPPORTED_PIN_TYPE =
      "NOT_SUPPORTED_PIN_TYPE";
  /** Not supported token type. */
  private static final String S_NOT_SUPPORTED_TOKEN_TYPE =
      "NOT_SUPPORTED_TOKEN_TYPE";
  /** Authorization denied. */
  private static final String S_NOT_AUTHORIZED =
      "NOT_AUTHORIZED";
  /** Wrong status of approval. */
  private static final String S_APPROVAL_WRONG_STATUS =
      "APPROVAL_WRONG_STATUS";
  /** Already enough approval for this request. */
  private static final String S_ENOUGH_APPROVAL =
      "ENOUGH_APPROVAL";
  /** Approval already exists. */
  private static final String S_APPROVAL_ALREADY_EXISTS =
      "APPROVAL_ALREADY_EXISTS";
  /** Approval request with specified ID does not exist. */
  private static final String S_APPROVAL_REQUEST_ID_NOT_EXIST =
      "APPROVAL_REQUEST_ID_NOT_EXIST";
  /**  Invalid custom log level. */
  private static final String S_INVALID_LOG_LEVEL =
      "INVALID_LOG_LEVEL";
  /**  Technical problem. */
  private static final String S_INTERNAL_ERROR =
      "INTERNAL_ERROR";
  /** No error code specified. */
  private static final String S_NOT_SPECIFIED =
      "NOT_SPECIFIED";
  /** CA is offline. */
  private static final String S_CA_OFFLINE = "CA_OFFLINE";
  /** an invalid CA token PIN was given. */
  private static final String S_CA_INVALID_TOKEN_PIN =
      "CA INVALID TOKEN PIN";
  /** End entity is already revoked. */
  private static final String S_ALREADY_REVOKED =
      "ALREADY_REVOKED";
  /** A certificate path was invalid/could not be constructed. */
  private static final String S_CERT_PATH_INVALID =
      "CERT_PATH_INVALID";
  /** Certificates in a PEM or DER file could not be parsed. */
  private static final String S_CERT_COULD_NOT_BE_PARSED =
      "CERT_COULD_NOT_BE_PARSED";
  /** Certificate with this key already exists for a different user. */
  private static final String
      S_CERTIFICATE_FOR_THIS_KEY_ALREADY_EXISTS_FOR_ANOTHER_USER =
          "CERTIFICATE_FOR_THIS_KEY_ALREADY_EXISTS_FOR_ANOTHER_USER";
  /** Certificate with this DN already exists for a different user. */
  private static final String
      S_CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER =
          "CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER";
  /** A cerificate already exosts with this SN. */
  private static final String S_SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS =
      "SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS";
  /** Invalid field. */
  private static final String S_FIELD_VALUE_NOT_VALID =
          "_FIELD_VALUE_NOT_VALID";
  /** Backdating is disallowed. */
  private static final String S_REVOKE_BACKDATE_NOT_ALLOWED =
      "REVOKE_BACKDATE_NOT_ALLOWED";
  /** A date is invalid. */
  private static final String S_DATE_NOT_VALID = "DATE_NOT_VALID";
  /** A CryptoToken with the name already exists. */
  private static final String S_CRYPTOTOKEN_NAME_IN_USE =
      "CRYPTOTOKEN_NAME_IN_USE";
  /** An InternalKeyBinding with the name already exists. */
  private static final String S_INTERNAL_KEY_BINDING_NAME_IN_USE =
      "INTERNAL_KEY_BINDING_NAME_IN_USE";
  /** Failure during import of a certificate. */
  private static final String S_CERTIFICATE_IMPORT =
      "CERTIFICATE_IMPORT";
  /** End-entity does not satisfy name constraints of CA. */
  private static final String S_NAMECONSTRAINT_VIOLATION =
      "NAMECONSTRAINT_VIOLATION";
  /** The profile type is neither end entity profile nor
   * certificate profile. */
  private static final String S_UNKNOWN_PROFILE_TYPE =
      "UNKNOWN_PROFILE_TYPE";
  /** Typically used to block access to enterprise-only features. */
  private static final String S_UNSUPPORTED_METHOD =
      "UNSUPPORTED_METHOD";
  /** when trying to create a new CA signed by an external CA using the WS. */
  private static final String S_SIGNED_BY_EXTERNAL_CA_NOT_SUPPORTED =
      "SIGNED_BY_EXTERNAL_CA_NOT_SUPPORTED";
  /** when using a cert/endentity profile of the wrong type. */
  private static final String S_BAD_CERTIFICATE_PROFILE_TYPE =
      "BAD_CERTIFICATE_PROFILE_TYPE";
  /** When trying to find a role that does not exist. */
  private static final String S_ROLE_DOES_NOT_EXIST =
      "ROLE_DOES_NOT_EXIST";
  /** Failure to verify request signature. */
  private static final String S_BAD_REQUEST_SIGNATURE =
      "BAD_REQUEST_SIGNATURE";
  /** CA Name Change Renewal could not be completed. */
  private static final String S_CA_NAME_CHANGE_RENEWAL_ERROR =
      "CA_NAME_CHANGE_RENEWAL_ERROR";
  /** User could not be added cause it doesn't fulfill end entity profile. */
  private static final String S_USER_DOESNT_FULFILL_END_ENTITY_PROFILE =
      "USER_DOESNT_FULFILL_END_ENTITY_PROFILE";
  /** Custom error. */
  private static final String S_CUSTOM_CERTIFICATE_EXTENSION_ERROR =
      "CUSTOM_CERTIFICATE_EXTENSION_ERROR";
  /** References to item exist. */
  private static final String S_REFERENCES_TO_ITEM_EXIST =
      "REFERENCES_TO_ITEM_EXIST";
  /** CA does not exist. */
  public static final ErrorCode CA_NOT_EXISTS = new ErrorCode(S_CA_NOT_EXISTS);
  /** CA already exists. */
  public static final ErrorCode CA_ALREADY_EXISTS =
      new ErrorCode(S_CA_ALREADY_EXISTS);
  /** CA ID can't be equal to zero. */
  public static final ErrorCode CA_ID_EQUALS_ZERO =
      new ErrorCode(S_CA_ID_EQUALS_ZERO);
  /** End Entity profile does not exist. */
  public static final ErrorCode EE_PROFILE_NOT_EXISTS =
      new ErrorCode(S_EE_PROFILE_NOT_EXISTS);
  /** Certificate profile does not exist. */
  public static final ErrorCode CERT_PROFILE_NOT_EXISTS =
      new ErrorCode(S_CERT_PROFILE_NOT_EXISTS);
  /** Hard token issuer doens't exists. */
  public static final ErrorCode HARD_TOKEN_ISSUER_NOT_EXISTS =
      new ErrorCode(S_HARD_TOKEN_ISSUER_NOT_EXISTS);
  /** Hard token issuer exists. */
  public static final ErrorCode HARD_TOKEN_NOT_EXISTS =
      new ErrorCode(S_HARD_TOKEN_NOT_EXISTS);
  /** Unknown token type. */
  public static final ErrorCode UNKOWN_TOKEN_TYPE =
      new ErrorCode(S_UNKOWN_TOKEN_TYPE);
  /** Client authentication certificate not received. */
  public static final ErrorCode AUTH_CERT_NOT_RECEIVED =
      new ErrorCode(S_AUTH_CERT_NOT_RECEIVED);
  /** User doesn't exist. */
  public static final ErrorCode USER_NOT_FOUND =
          new ErrorCode(S_USER_NOT_FOUND);
  /** Wrong token type for user. */
  public static final ErrorCode BAD_USER_TOKEN_TYPE =
      new ErrorCode(S_BAD_USER_TOKEN_TYPE);
  /** Generated certificate is invalid. */
  public static final ErrorCode INVALID_CERTIFICATE =
      new ErrorCode(S_INVALID_CERTIFICATE);
  /** Provided key is invalid. */
  public static final ErrorCode INVALID_KEY = new ErrorCode(S_INVALID_KEY);
  /** User key is illegal (key length too small). */
  public static final ErrorCode ILLEGAL_KEY = new ErrorCode(S_ILLEGAL_KEY);
  /** User wrong status. */
  public static final ErrorCode USER_WRONG_STATUS =
      new ErrorCode(S_USER_WRONG_STATUS);
  /** User already exists. */
  public static final ErrorCode USER_ALREADY_EXISTS =
      new ErrorCode(S_USER_ALREADY_EXISTS);
  /** Login error. */
  public static final ErrorCode LOGIN_ERROR = new ErrorCode(S_LOGIN_ERROR);
  /** Error in signature. */
  public static final ErrorCode SIGNATURE_ERROR =
      new ErrorCode(S_SIGNATURE_ERROR);
  /** Invalid key specification. */
  public static final ErrorCode INVALID_KEY_SPEC =
      new ErrorCode(S_INVALID_KEY_SPEC);
  /** Certificate wrong status. */
  public static final ErrorCode CERT_WRONG_STATUS =
      new ErrorCode(S_CERT_WRONG_STATUS);
  /** Key recovery feature not enabled. */
  public static final ErrorCode KEY_RECOVERY_NOT_AVAILABLE =
      new ErrorCode(S_KEY_RECOVERY_NOT_AVAILABLE);
  /** Validity format badly formatted (must be defined in days). */
  public static final ErrorCode BAD_VALIDITY_FORMAT =
      new ErrorCode(S_BAD_VALIDITY_FORMAT);
  /** Key store type not supported. */
  public static final ErrorCode NOT_SUPPORTED_KEY_STORE =
      new ErrorCode(S_NOT_SUPPORTED_KEY_STORE);
  /** Not supported request type. */
  public static final ErrorCode NOT_SUPPORTED_REQUEST_TYPE =
      new ErrorCode(S_NOT_SUPPORTED_REQUEST_TYPE);
  /** Not supported PIN type. */
  public static final ErrorCode NOT_SUPPORTED_PIN_TYPE =
      new ErrorCode(S_NOT_SUPPORTED_PIN_TYPE);
  /** Not supported token type. */
  public static final ErrorCode NOT_SUPPORTED_TOKEN_TYPE =
      new ErrorCode(S_NOT_SUPPORTED_TOKEN_TYPE);
  /** Authorization denied. */
  public static final ErrorCode NOT_AUTHORIZED =
          new ErrorCode(S_NOT_AUTHORIZED);
  /** Wrong status of approval. */
  public static final ErrorCode APPROVAL_WRONG_STATUS =
      new ErrorCode(S_APPROVAL_WRONG_STATUS);
  /** Already enough approval for this request. */
  public static final ErrorCode ENOUGH_APPROVAL =
      new ErrorCode(S_ENOUGH_APPROVAL);
  /** Approval already exists. */
  public static final ErrorCode APPROVAL_ALREADY_EXISTS =
      new ErrorCode(S_APPROVAL_ALREADY_EXISTS);
  /** Approval request with specified ID does not exist. */
  public static final ErrorCode APPROVAL_REQUEST_ID_NOT_EXIST =
      new ErrorCode(S_APPROVAL_REQUEST_ID_NOT_EXIST);
  /** Invalid custom log level. */
  public static final ErrorCode INVALID_LOG_LEVEL =
      new ErrorCode(S_INVALID_LOG_LEVEL);
  /** Technical problem. */
  public static final ErrorCode INTERNAL_ERROR =
          new ErrorCode(S_INTERNAL_ERROR);
  /** No error code specified. */
  public static final ErrorCode NOT_SPECIFIED = new ErrorCode(S_NOT_SPECIFIED);
  /** CA is offline. */
  public static final ErrorCode CA_OFFLINE = new ErrorCode(S_CA_OFFLINE);
  /** CA token PIN is invalid. */
  public static final ErrorCode CA_INVALID_TOKEN_PIN =
      new ErrorCode(S_CA_INVALID_TOKEN_PIN);
  /** End entity is already revoked. */
  public static final ErrorCode ALREADY_REVOKED =
      new ErrorCode(S_ALREADY_REVOKED);
  /** A certificate path was invalid/could not be constructed. */
  public static final ErrorCode CERT_PATH_INVALID =
      new ErrorCode(S_CERT_PATH_INVALID);

  /** Instance. */
  public static final ErrorCode CERT_COULD_NOT_BE_PARSED =
      new ErrorCode(S_CERT_COULD_NOT_BE_PARSED);
  /** Instance. */
  public static final ErrorCode
      CERTIFICATE_FOR_THIS_KEY_ALLREADY_EXISTS_FOR_ANOTHER_USER =
          new ErrorCode(
              S_CERTIFICATE_FOR_THIS_KEY_ALREADY_EXISTS_FOR_ANOTHER_USER);
  /** Instance. */
  public static final ErrorCode
      CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER =
          new ErrorCode(
            S_CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER);
  /** Instance. */
  public static final ErrorCode SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS =
      new ErrorCode(S_SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS);
  /** Instance. */
  public static final ErrorCode FIELD_VALUE_NOT_VALID =
      new ErrorCode(S_FIELD_VALUE_NOT_VALID);
  /** Instance. */
  public static final ErrorCode REVOKE_BACKDATE_NOT_ALLOWED =
      new ErrorCode(S_REVOKE_BACKDATE_NOT_ALLOWED);
  /** Istance. */
  public static final ErrorCode DATE_NOT_VALID =
          new ErrorCode(S_DATE_NOT_VALID);
  /** Instance. */
  public static final ErrorCode CRYPTOTOKEN_NAME_IN_USE =
      new ErrorCode(S_CRYPTOTOKEN_NAME_IN_USE);
  /** Instance. */
  public static final ErrorCode INTERNAL_KEY_BINDING_NAME_IN_USE =
      new ErrorCode(S_INTERNAL_KEY_BINDING_NAME_IN_USE);
  /** Instance. */
  public static final ErrorCode CERTIFICATE_IMPORT =
      new ErrorCode(S_CERTIFICATE_IMPORT);
  /** Instance. */
  public static final ErrorCode NAMECONSTRAINT_VIOLATION =
      new ErrorCode(S_NAMECONSTRAINT_VIOLATION);
  /** Instance. */
  public static final ErrorCode UNKNOWN_PROFILE_TYPE =
      new ErrorCode(S_UNKNOWN_PROFILE_TYPE);
  /** Instance. */
  public static final ErrorCode UNSUPPORTED_METHOD =
      new ErrorCode(S_UNSUPPORTED_METHOD);
  /** Instance. */
  public static final ErrorCode SIGNED_BY_EXTERNAL_CA_NOT_SUPPORTED =
      new ErrorCode(S_SIGNED_BY_EXTERNAL_CA_NOT_SUPPORTED);
  /** Instance. */
  public static final ErrorCode BAD_CERTIFICATE_PROFILE_TYPE =
      new ErrorCode(S_BAD_CERTIFICATE_PROFILE_TYPE);
  /** Instance. */
  public static final ErrorCode ROLE_DOES_NOT_EXIST =
      new ErrorCode(S_ROLE_DOES_NOT_EXIST);
  /** Failure to verify request signature. */
  public static final ErrorCode BAD_REQUEST_SIGNATURE =
      new ErrorCode(S_BAD_REQUEST_SIGNATURE);
  /** Instance. */
  public static final ErrorCode CA_NAME_CHANGE_RENEWAL_ERROR =
      new ErrorCode(S_CA_NAME_CHANGE_RENEWAL_ERROR);
  /** Instance. */
  public static final ErrorCode USER_DOESNT_FULFILL_END_ENTITY_PROFILE =
      new ErrorCode(S_USER_DOESNT_FULFILL_END_ENTITY_PROFILE);
  /** Instance. */
  public static final ErrorCode CUSTOM_CERTIFICATE_EXTENSION_ERROR =
      new ErrorCode(S_CUSTOM_CERTIFICATE_EXTENSION_ERROR);
  /**
   * Trying to delete an item when references exist. For example, a deleting
   * publisher when it's used by profiles.
   */
  public static final ErrorCode REFERENCES_TO_ITEM_EXIST =
      new ErrorCode(S_REFERENCES_TO_ITEM_EXIST);

  /** Default constructor. */
  private ErrorCode() { }

  /**
   * Constructor.
   *
   * @param aInternalErrorCode error code.
   */
  private ErrorCode(final String aInternalErrorCode) {
    this.internalErrorCode = aInternalErrorCode;
  }

  /**
   * Get the internal error code.
   *
   * @return Error code
   */
  public String getInternalErrorCode() {
    return internalErrorCode;
  }

  /**
   * Set the internal error code.
   *
   * @param ainternalErrorCode Error code
   */
  public void setInternalErrorCode(final String ainternalErrorCode) {
    this.internalErrorCode = ainternalErrorCode;
  }

  @Override
  public boolean equals(final Object obj) {
    if (obj != null && obj instanceof ErrorCode) {
      ErrorCode other = (ErrorCode) obj;
      return this.internalErrorCode.equals(other.internalErrorCode);
    } else {
      return false;
    }
  }

  @Override
  public String toString() {
    return "Internal EJBCA error code: " + this.internalErrorCode;
  }

  @Override
  public int hashCode() {
    if (internalErrorCode != null) {
      return internalErrorCode.hashCode();
    } else {
      return 0;
    }
  }
}
