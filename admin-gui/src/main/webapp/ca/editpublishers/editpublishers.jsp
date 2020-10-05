<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project/Owasp.CsrfGuard.tld" prefix="csrf" %>
<%@ page pageEncoding="ISO-8859-1"%>
<% response.setContentType("text/html; charset="+org.ejbca.config.WebConfiguration.getWebContentEncoding()); %>
<%@page errorPage="/errorpage.jsp" import="java.util.*, org.ejbca.ui.web.admin.configuration.EjbcaWebBean,org.ejbca.config.GlobalConfiguration, org.ejbca.core.model.SecConst, 
              org.cesecore.authorization.AuthorizationDeniedException, org.ejbca.core.model.authorization.AccessRulesConstants,
               org.ejbca.ui.web.admin.cainterface.CAInterfaceBean, org.ejbca.core.model.ca.publisher.*, org.ejbca.core.model.ca.publisher.LdapPublisher.ConnectionSecurity,
               org.ejbca.ui.web.admin.cainterface.EditPublisherJSPHelper, 
               org.ejbca.core.model.ca.publisher.PublisherExistsException, org.cesecore.certificates.util.DNFieldExtractor, org.cesecore.certificates.util.DnComponents, org.cesecore.authorization.control.StandardRules"%>

<html>
<jsp:useBean id="ejbcawebbean" scope="session" class="org.ejbca.ui.web.admin.configuration.EjbcaWebBean" />
<jsp:useBean id="cabean" scope="session" class="org.ejbca.ui.web.admin.cainterface.CAInterfaceBean" />
<jsp:useBean id="publisherhelper" scope="session" class="org.ejbca.ui.web.admin.cainterface.EditPublisherJSPHelper" />

<% 

  // Initialize environment
  String includefile = "publisherspage.jspf"; 


  GlobalConfiguration globalconfiguration = ejbcawebbean.initialize(request, AccessRulesConstants.REGULAR_VIEWPUBLISHER); 
                                            cabean.initialize(ejbcawebbean); 
                                            publisherhelper.initialize(request,ejbcawebbean, cabean);
  String THIS_FILENAME            =  globalconfiguration.getCaPath()  + "/editpublishers/editpublishers.jsp";
  
%>
 
<head>
  <title><c:out value="<%= globalconfiguration.getEjbcaTitle() %>" /></title>
  <base href="<%= ejbcawebbean.getBaseUrl() %>" />
  <link rel="stylesheet" type="text/css" href="<c:out value='<%=ejbcawebbean.getCssFile() %>' />" />
  <link rel="shortcut icon" href="<%=ejbcawebbean.getImagefileInfix("favicon.png")%>" type="image/png" />
  <script type="text/javascript" src="<%= globalconfiguration .getAdminWebPath() %>ejbcajslib.js"></script>
</head>

<body>
<jsp:include page="../../adminmenu.jsp" />

<div class="main-wrapper">
<div class="container">

<%  // Determine action 

  includefile = publisherhelper.parseRequest(request);

 // Include page
  if( includefile.equals("publisherpage.jspf")){ 
%>
   <%@ include file="publisherpage.jspf" %>
<%}
  if( includefile.equals("publisherspage.jspf")){ %>
   <%@ include file="publisherspage.jspf" %> 
<%} %>

</div> <!-- Container -->

<%
   // Include Footer 
   String footurl =   globalconfiguration.getFootBanner(); %>
   
  <jsp:include page="<%= footurl %>" />

</div> <!-- main-wrapper -->
</body>
</html>
