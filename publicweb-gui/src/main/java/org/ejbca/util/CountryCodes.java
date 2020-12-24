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
package org.ejbca.util;

/**
 * A list of 2-character ISO country codes. See
 * https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2
 *
 * @version $Id: CountryCodes.java 19902 2014-09-30 14:32:24Z anatom $
 */
public final class CountryCodes {

  public static final class Country {
        /** Param. */
    private final String code;
    /** Param. */
    private final String name;

    private Country(final String aname, final String acode) {
      this.name = aname;
      this.code = acode;
    }

    /** @return Code */
    public String getCode() {
      return code;
    }

    /**
     * @return Name
     */
    public String getName() {
      return name;
    }
  }

  /** Country codes. */
  private static final Country[] COUNTRIES = {
    new Country("Afghanistan", "AF"),
    new Country("Albania", "AL"),
    new Country("Algeria", "DZ"),
    new Country("American Samoa", "AS"),
    new Country("Andorra", "AD"),
    new Country("Angola", "AO"),
    new Country("Anguilla", "AI"),
    new Country("Antarctica", "AQ"),
    new Country("Antigua and Barbuda", "AG"),
    new Country("Argentina", "AR"),
    new Country("Armenia", "AM"),
    new Country("Aruba", "AW"),
    new Country("Australia", "AU"),
    new Country("Austria", "AT"),
    new Country("Azerbaijan", "AZ"),
    new Country("Bahamas", "BS"),
    new Country("Bahrain", "BH"),
    new Country("Bangladesh", "BD"),
    new Country("Barbados", "BB"),
    new Country("Belarus", "BY"),
    new Country("Belgium", "BE"),
    new Country("Belize", "BZ"),
    new Country("Benin", "BJ"),
    new Country("Bermuda", "BM"),
    new Country("Bhutan", "BT"),
    new Country("Bolivia, Plurinational State of", "BO"),
    new Country("Bonaire, Sint Eustatius and Saba", "BQ"),
    new Country("Bosnia and Herzegovina", "BA"),
    new Country("Botswana", "BW"),
    new Country("Bouvet Island", "BV"),
    new Country("Brazil", "BR"),
    new Country("British Indian Ocean Territory", "IO"),
    new Country("Brunei Darussalam", "BN"),
    new Country("Bulgaria", "BG"),
    new Country("Burkina Faso", "BF"),
    new Country("Burundi", "BI"),
    new Country("Cambodia", "KH"),
    new Country("Cameroon", "CM"),
    new Country("Canada", "CA"),
    new Country("Cape Verde", "CV"),
    new Country("Cayman Islands", "KY"),
    new Country("Central African Republic", "CF"),
    new Country("Chad", "TD"),
    new Country("Chile", "CL"),
    new Country("China", "CN"),
    new Country("Christmas Island", "CX"),
    new Country("Cocos (Keeling) Islands", "CC"),
    new Country("Colombia", "CO"),
    new Country("Comoros", "KM"),
    new Country("Congo", "CG"),
    new Country("Congo, the Democratic Republic of the", "CD"),
    new Country("Cook Islands", "CK"),
    new Country("Costa Rica", "CR"),
    new Country("Côte d'Ivoire", "CI"),
    new Country("Croatia", "HR"),
    new Country("Cuba", "CU"),
    new Country("Curaçao", "CW"),
    new Country("Cyprus", "CY"),
    new Country("Czech Republic", "CZ"),
    new Country("Denmark", "DK"),
    new Country("Djibouti", "DJ"),
    new Country("Dominica", "DM"),
    new Country("Dominican Republic", "DO"),
    new Country("Ecuador", "EC"),
    new Country("Egypt", "EG"),
    new Country("El Salvador", "SV"),
    new Country("Equatorial Guinea", "GQ"),
    new Country("Eritrea", "ER"),
    new Country("Estonia", "EE"),
    new Country("Ethiopia", "ET"),
    new Country("Falkland Islands (Malvinas)", "FK"),
    new Country("Faroe Islands", "FO"),
    new Country("Fiji", "FJ"),
    new Country("Finland", "FI"),
    new Country("France", "FR"),
    new Country("French Guiana", "GF"),
    new Country("French Polynesia", "PF"),
    new Country("French Southern Territories", "TF"),
    new Country("Gabon", "GA"),
    new Country("Gambia", "GM"),
    new Country("Georgia", "GE"),
    new Country("Germany", "DE"),
    new Country("Ghana", "GH"),
    new Country("Gibraltar", "GI"),
    new Country("Greece", "GR"),
    new Country("Greenland", "GL"),
    new Country("Grenada", "GD"),
    new Country("Guadeloupe", "GP"),
    new Country("Guam", "GU"),
    new Country("Guatemala", "GT"),
    new Country("Guernsey", "GG"),
    new Country("Guinea", "GN"),
    new Country("Guinea-Bissau", "GW"),
    new Country("Guyana", "GY"),
    new Country("Haiti", "HT"),
    new Country("Heard Island and McDonald Islands", "HM"),
    new Country("Holy See (Vatican City State)", "VA"),
    new Country("Honduras", "HN"),
    new Country("Hong Kong", "HK"),
    new Country("Hungary", "HU"),
    new Country("Iceland", "IS"),
    new Country("India", "IN"),
    new Country("Indonesia", "ID"),
    new Country("Iran, Islamic Republic of", "IR"),
    new Country("Iraq", "IQ"),
    new Country("Ireland", "IE"),
    new Country("Isle of Man", "IM"),
    new Country("Israel", "IL"),
    new Country("Italy", "IT"),
    new Country("Jamaica", "JM"),
    new Country("Japan", "JP"),
    new Country("Jersey", "JE"),
    new Country("Jordan", "JO"),
    new Country("Kazakhstan", "KZ"),
    new Country("Kenya", "KE"),
    new Country("Kiribati", "KI"),
    new Country("Korea, Democratic People's Republic of", "KP"),
    new Country("Korea, Republic of", "KR"),
    new Country("Kuwait", "KW"),
    new Country("Kyrgyzstan", "KG"),
    new Country("Lao People's Democratic Republic", "LA"),
    new Country("Latvia", "LV"),
    new Country("Lebanon", "LB"),
    new Country("Lesotho", "LS"),
    new Country("Liberia", "LR"),
    new Country("Libya", "LY"),
    new Country("Liechtenstein", "LI"),
    new Country("Lithuania", "LT"),
    new Country("Luxembourg", "LU"),
    new Country("Macao", "MO"),
    new Country("Macedonia, the former Yugoslav Republic of", "MK"),
    new Country("Madagascar", "MG"),
    new Country("Malawi", "MW"),
    new Country("Malaysia", "MY"),
    new Country("Maldives", "MV"),
    new Country("Mali", "ML"),
    new Country("Malta", "MT"),
    new Country("Marshall Islands", "MH"),
    new Country("Martinique", "MQ"),
    new Country("Mauritania", "MR"),
    new Country("Mauritius", "MU"),
    new Country("Mayotte", "YT"),
    new Country("Mexico", "MX"),
    new Country("Micronesia, Federated States of", "FM"),
    new Country("Moldova, Republic of", "MD"),
    new Country("Monaco", "MC"),
    new Country("Mongolia", "MN"),
    new Country("Montenegro", "ME"),
    new Country("Montserrat", "MS"),
    new Country("Morocco", "MA"),
    new Country("Mozambique", "MZ"),
    new Country("Myanmar", "MM"),
    new Country("Namibia", "NA"),
    new Country("Nauru", "NR"),
    new Country("Nepal", "NP"),
    new Country("Netherlands", "NL"),
    new Country("New Caledonia", "NC"),
    new Country("New Zealand", "NZ"),
    new Country("Nicaragua", "NI"),
    new Country("Niger", "NE"),
    new Country("Nigeria", "NG"),
    new Country("Niue", "NU"),
    new Country("Norfolk Island", "NF"),
    new Country("Northern Mariana Islands", "MP"),
    new Country("Norway", "NO"),
    new Country("Oman", "OM"),
    new Country("Pakistan", "PK"),
    new Country("Palau", "PW"),
    new Country("Palestinian Territory, Occupied", "PS"),
    new Country("Panama", "PA"),
    new Country("Papua New Guinea", "PG"),
    new Country("Paraguay", "PY"),
    new Country("Peru", "PE"),
    new Country("Philippines", "PH"),
    new Country("Pitcairn", "PN"),
    new Country("Poland", "PL"),
    new Country("Portugal", "PT"),
    new Country("Puerto Rico", "PR"),
    new Country("Qatar", "QA"),
    new Country("Réunion", "RE"),
    new Country("Romania", "RO"),
    new Country("Russian Federation", "RU"),
    new Country("Rwanda", "RW"),
    new Country("Saint Barthélemy", "BL"),
    new Country("Saint Helena, Ascension and Tristan da Cunha", "SH"),
    new Country("Saint Kitts and Nevis", "KN"),
    new Country("Saint Lucia", "LC"),
    new Country("Saint Martin (French part)", "MF"),
    new Country("Saint Pierre and Miquelon", "PM"),
    new Country("Saint Vincent and the Grenadines", "VC"),
    new Country("Samoa", "WS"),
    new Country("San Marino", "SM"),
    new Country("Sao Tome and Principe", "ST"),
    new Country("Saudi Arabia", "SA"),
    new Country("Senegal", "SN"),
    new Country("Serbia", "RS"),
    new Country("Seychelles", "SC"),
    new Country("Sierra Leone", "SL"),
    new Country("Singapore", "SG"),
    new Country("Sint Maarten (Dutch part)", "SX"),
    new Country("Slovakia", "SK"),
    new Country("Slovenia", "SI"),
    new Country("Solomon Islands", "SB"),
    new Country("Somalia", "SO"),
    new Country("South Africa", "ZA"),
    new Country("South Georgia and the South Sandwich Islands", "GS"),
    new Country("South Sudan", "SS"),
    new Country("Spain", "ES"),
    new Country("Sri Lanka", "LK"),
    new Country("Sudan", "SD"),
    new Country("Suriname", "SR"),
    new Country("Svalbard and Jan Mayen", "SJ"),
    new Country("Swaziland", "SZ"),
    new Country("Sweden", "SE"),
    new Country("Switzerland", "CH"),
    new Country("Syrian Arab Republic", "SY"),
    new Country("Taiwan, Province of China", "TW"),
    new Country("Tajikistan", "TJ"),
    new Country("Tanzania, United Republic of", "TZ"),
    new Country("Thailand", "TH"),
    new Country("Timor-Leste", "TL"),
    new Country("Togo", "TG"),
    new Country("Tokelau", "TK"),
    new Country("Tonga", "TO"),
    new Country("Trinidad and Tobago", "TT"),
    new Country("Tunisia", "TN"),
    new Country("Turkey", "TR"),
    new Country("Turkmenistan", "TM"),
    new Country("Turks and Caicos Islands", "TC"),
    new Country("Tuvalu", "TV"),
    new Country("Uganda", "UG"),
    new Country("Ukraine", "UA"),
    new Country("United Arab Emirates", "AE"),
    new Country("United Kingdom", "GB"),
    new Country("United States", "US"),
    new Country("United States Minor Outlying Islands", "UM"),
    new Country("Uruguay", "UY"),
    new Country("Uzbekistan", "UZ"),
    new Country("Vanuatu", "VU"),
    new Country("Venezuela, Bolivarian Republic of", "VE"),
    new Country("Viet Nam", "VN"),
    new Country("Virgin Islands, British", "VG"),
    new Country("Virgin Islands, U.S.", "VI"),
    new Country("Wallis and Futuna", "WF"),
    new Country("Western Sahara", "EH"),
    new Country("Yemen", "YE"),
    new Country("Zambia", "ZM"),
    new Country("Zimbabwe", "ZW"),
    new Country("Åland Islands", "AX"),
  };

  /**
   * @return countries
   */
  public static Country[] getCountries() {
    return COUNTRIES.clone();
  }

  /**
   * @return countries
   */
  public Country[] getCountriesFromBean() {
    return COUNTRIES.clone();
  }
}
