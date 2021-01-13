<%@ include file="header.jsp" %>
<h1 class="title">Fetch latest certificate</h1>

<p>
	Give subject DN to fetch users latest certificate.
</p><p>
	Note that the order or case of element descriptors in the DN (C, O, CN, etc.) is unimportant.
	The case of elements themselves, on the other hand, <em>IS</em> important.
</p><p> 
    For example, <code>cn=foo</code> is considered equal to <code>CN=foo</code> but different from <code>cn=FOO</code>.
</p>

<form action="../publicweb/webdist/certdist" enctype="x-www-form-encoded" method="post">
  <fieldset>
    <legend>Name</legend>
    <input type="hidden" name="hidemenu" value="<c:out value="${hidemenu}" />" />
    <input type="hidden" name="cmd" value="lastcert" />
    <label for="subject">Subject DN</label>
    <input name="subject" id="subject" type="text" size="60" accesskey="s" />
    <br />
    <label for="ok"></label>
    <input type="submit" id="ok" value="OK" />
  </fieldset>
</form>

<div class="message">
  <div class="label">Note</div>
  <div class="content">
    <p>If you receive a <em>404-Not found</em> response, it means that
       the subject does not have a certificate in the database. Check your entry to make sure 
       you have specified all the DN components.
    </p>
  </div>
</div>

<%@ include file="footer.inc" %>
