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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * JAX-WS Support. Utility for supporting JavaDoc creation of JAX-WS objects as
 * well as supporting an option for securely reusing server-objects on the
 * client to achieve a more uniform system.
 *
 * @author Anders Rundgren
 * @version $Id: JAXWSDocAndConvTools.java 28766 2018-04-24 11:18:17Z
 *     tarmo_r_helmes $
 */
public class JAXWSDocAndConvTools {

      /** Param. */
  private CompilationUnit server;
  /** Param. */
  private CompilationUnit client;

  enum Types {
      /** Token. */
    COMMENT,
      /** Token. */
    IDENTIFIER,
      /** Token. */
    SEMICOLON,
      /** Token. */
    STRING,
      /** Token. */
    CHARLITERAL,
      /** Token. */
    COMMA,
      /** Token. */
    NUMBER,
      /** Token. */
    LEFTPAR,
      /** Token. */
    RIGHTPAR,
      /** Token. */
    LEFTBRACK,
      /** Token. */
    RIGHTBRACK,
      /** Token. */
    LEFTARRAY,
      /** Token. */
    RIGHTARRAY,
      /** Token. */
    BINOP,
      /** Token. */
    EQUALOP,
      /** Token. */
    LEFTCURL,
      /** Token. */
    RIGHTCURL;
  }

  class Token {
      /** Param. */
    private int start = cStart;
    /** Param. */
    private int stop = cIndex;
    /** Param. */
    private Types type;

    Token(final Types atype) {
      this.type = atype;
      curr = this;
    }

    Types getType() {
      return type;
    }

    String getText() {
      return lines.substring(start, stop);
    }

    boolean equals(final String value) {
      return value.equals(getText());
    }
  }

  class Method {
      /** Param. */
    private String javaDoc;
    /** Param. */
    private String methodName;
    /** Param. */
    private String returnType;
    /** Param. */
    private List<String> declarators = new ArrayList<String>();
    /** Param. */
    private List<String> argumentNames = new ArrayList<String>();
    /** Param. */
    private List<String> exceptions = new ArrayList<String>();

    String signature() {
      final StringBuilder sig = new StringBuilder();
      sig.append(methodName).append(':').append(returnType);
      for (String decl : declarators) {
        sig.append('/').append(decl);
      }
      return sig.toString();
    }
  }

  class CompilationUnit {
      /** Param. */
    private String packageName;
    /** Param. */
    private String className;
    /** Param. */
    private String classJavaDoc;
    /** Param. */
    private List<String> imports = new ArrayList<String>();
    /** Param. */
    private LinkedHashMap<String, String> exceptions =
        new LinkedHashMap<String, String>();
    /** Param. */
    private LinkedHashMap<String, Method> methods =
            new LinkedHashMap<String, Method>();
  }

  /** Param. */
  private int cIndex;
  /** Param. */
  private int cStart;
  /** Param. */
  private StringBuilder lines;
  /** Param. */
  private boolean wsGen;
  /** Param. */
  private Token curr;

  /**
   * @param error error
   * @throws Exception fail
   */
  void bad(final String error) throws Exception {
    throw new Exception(error);
  }

  /**
   * @return nest token
   * @throws Exception fail
   */
  Token scan() throws Exception {
    while (true) {
      if (cIndex >= lines.length()) {
        return null;
      }

      cStart = cIndex;
      int c = lines.charAt(cIndex++);
      if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
        while (((c = lines.charAt(cIndex)) >= 'a' && c <= 'z')
            || (c >= 'A' && c <= 'Z')
            || (c >= '0' && c <= '9')
            || c == '_'
            || c == '.') {
          cIndex++;
        }
        return new Token(Types.IDENTIFIER);
      }
      if (c == '@') {
        if (scan().getType() != Types.IDENTIFIER) {
          bad("@ should be followed by an identifier");
        }
        Token nxt = scan();
        if (nxt.getType() == Types.LEFTPAR) {
          while (scan().getType()
              != Types.RIGHTPAR) {
              // NOPMD just loop
          }
          continue;
        }
        return nxt;
      }
      if (c == '/') {
        if (lines.charAt(cIndex) == '*') {
          cIndex++;
          while (true) {
            if (lines.charAt(cIndex++) == '*') {
              if (lines.charAt(cIndex) == '/') {
                cIndex++;
                return new Token(Types.COMMENT);
              }
            }
          }
        }
        if (lines.charAt(cIndex) == '/') {
          cIndex++;
          while (lines.charAt(cIndex++) != '\n') { // NOPMD, just loop through
          }
          continue;
        }
      }
      if (c <= ' ') {
        continue;
      }

      if (c == ';') {
        return new Token(Types.SEMICOLON);
      }

      if (c == '(') {
        return new Token(Types.LEFTPAR);
      }
      if (c == ')') {
        return new Token(Types.RIGHTPAR);
      }
      if (c == '[') {
        return new Token(Types.LEFTARRAY);
      }
      if (c == ']') {
        return new Token(Types.RIGHTARRAY);
      }
      if (c == '<') {
        return new Token(Types.LEFTBRACK);
      }
      if (c == '>') {
        return new Token(Types.RIGHTBRACK);
      }
      if (c == '{') {
        return new Token(Types.LEFTCURL);
      }
      if (c == '}') {
        return new Token(Types.RIGHTCURL);
      }
      if (c == ',') {
        return new Token(Types.COMMA);
      }
      if (c == '&') {
        if (lines.charAt(cIndex) == '&') {
          cIndex++;
        }
        return new Token(Types.BINOP);
      }
      if (c == '|') {
        if (lines.charAt(cIndex) == '|') {
          cIndex++;
        }
        return new Token(Types.BINOP);
      }
      if (c == '.' || c == '!' || c == '~' || c == '?' || c == ':') {
        return new Token(Types.BINOP);
      }
      if (c == '=') {
        if ((c = lines.charAt(cIndex)) == '=') {
          cIndex++;
          return new Token(Types.BINOP);
        }
        return new Token(Types.EQUALOP);
      }
      if (c == '+' || c == '-' || c == '*' || c == '%' || c == '&' || c == '|'
          || c == '^') {
        if ((c = lines.charAt(cIndex)) == '=') {
          cIndex++;
        }
        return new Token(Types.BINOP);
      }
      if (c >= '0' && c <= '9') {
        while (((c = lines.charAt(cIndex)) >= '0' && c <= '9')
            || c == 'x'
            || c == 'l'
            || c == 'X'
            || c == 'L') {
          cIndex++;
        }
        return new Token(Types.NUMBER);
      }
      if (c == '"') {
        while ((c = lines.charAt(cIndex++)) != '"') {
          if (c == '\\') {
            cIndex++;
          }
        }
        return new Token(Types.STRING);
      }
      if (c == '\'') {
        while ((c = lines.charAt(cIndex++)) != '\'') {
          if (c == '\\') {
            cIndex++;
          }
        }
        return new Token(Types.CHARLITERAL);
      }
      bad("Parser did not get it: " + (char) c);
    }
  }

  /**
   * @throws Exception fail
   */
  void readSemicolon() throws Exception {
    if (scan().getType() != Types.SEMICOLON) {
      bad("Semicolon expected");
    }
  }

  /**
   * @param ostart start
   * @return token
   * @throws Exception fail
   */
  Token removeModifiers(final Token ostart) throws Exception {
    Token start = ostart;
    boolean changed = false;
    do {
      changed = false;
      if (start.equals("public")) {
        start = scan();
        changed = true;
      }
      if (start.equals("static")) {
        start = scan();
        changed = true;
      }
      if (start.equals("final")) {
        start = scan();
        changed = true;
      }
      if (start.equals("abstract")) {
        start = scan();
        changed = true;
      }
    } while (changed);
    if (start.getType() != Types.IDENTIFIER) {
      bad("Identifier expected:" + start.getType());
    }
    return start;
  }

  /**
   * @param token token
   * @return bool
   */
  boolean isInterfaceOrClass(final Token token) {
    return token.equals("class") || token.equals("interface");
  }

  /**
   * @param token token
   * @throws Exception fail
   */
  void implementsOrExtends(final Token token) throws Exception {
    if (!token.equals("implements") && !token.equals("extends")) {
      bad("Expected implements/extend");
    }
  }

  /**
   * @throws Exception fail
   */
  void checkSource() throws Exception {
    if (wsGen) {
      bad("Unexpected element for generated file:" + curr.getText());
    }
  }

  /**
   * @param oid ID
   * @return Kest
   * @throws Exception Fail
   */
  Token nameList(final Token oid) throws Exception {
    Token id = oid;
    while (true) {
      if (id.getType() != Types.IDENTIFIER) {
        bad("Missing identifier in extend/impl");
      }
      Token nxt = scan();
      if (nxt.getType() != Types.COMMA) {
        return nxt;
      }
      id = scan();
    }
  }

  /**
   * @param start token
   * @return decl
   * @throws Exception fail
   */
  String getTypeDeclaration(final Token start) throws Exception {
    final StringBuilder typeDecl = new StringBuilder();
    typeDecl.append(start.getText());
    Token nxt = scan();
    if (nxt.getType() == Types.LEFTBRACK) {
      do {
        typeDecl.append(nxt.getText());
        if (scan().getType() != Types.IDENTIFIER) {
          bad("Missing <ID");
        }
        typeDecl.append(getTypeDeclaration(curr));
      } while ((nxt = curr).getType() == Types.COMMA);
      if (nxt.getType() != Types.RIGHTBRACK) {
        bad("> expected");
      }
      typeDecl.append(nxt.getText());
      scan();
    }
    if (nxt.getType() == Types.LEFTARRAY) {
      boolean byteArray = typeDecl.toString().equals("byte");
      if (wsGen && !byteArray) {
        bad("did not expect [] in WS-gen");
      }
      while ((nxt = scan()).getType()
          != Types.RIGHTARRAY) { // NOPMD, just loop through
      }
      if (byteArray) {
        typeDecl.append("[]");
      } else {
        typeDecl.insert(0, "List<").append('>');
      }
      scan();
    }
    return typeDecl.toString();
  }

  /**
   * @param ostart token
   * @param compilation AST
   * @throws Exception fail
   */
  void decodeDeclaration(final Token ostart, final CompilationUnit compilation)
      throws Exception {
    Token start = removeModifiers(ostart);
    if (!isInterfaceOrClass(start)) {
      bad("Expected class/interface declaration");
    }
    Token id;
    if ((id = scan()).getType() != Types.IDENTIFIER) {
      bad("class/interface identifier missing");
    }
    compilation.className = id.getText();
    //        System.out.println ("Class:" + id.getText());
    Token nxt;
    if ((nxt = scan()).getType() == Types.IDENTIFIER) {
      checkSource();
      implementsOrExtends(nxt);
      nxt = nameList(scan());
    }
    if (nxt.getType() != Types.LEFTCURL) {
      bad("Missing {");
    }
    String jdoc = null;
    while (true) {
      nxt = scan();
      if (nxt.getType() == Types.RIGHTCURL) {
        break;
      } else if (nxt.getType() == Types.COMMENT) {
        jdoc = nxt.getText();
        //                System.out.println ("Comment");
      } else {
        nxt = removeModifiers(nxt);
        if (isInterfaceOrClass(nxt)) {
          bad("Nested classes not implemented yet");
        }
        String returnType = null;
        String methodName = null;
        if (compilation.className.equals(nxt.getText())) {
          returnType = "";
          methodName = nxt.getText();
        } else {
          returnType = getTypeDeclaration(nxt);
          methodName = curr.getText();
        }
        scan();
        if (curr.getType() == Types.LEFTPAR) {
          //   System.out.println ("Return type: '" + return_type + "' method:
          // '" + method_name + "'");
          Method method = new Method();
          method.returnType = returnType;
          method.methodName = methodName;
          method.javaDoc = jdoc;
          scan();
          do {
            if (curr.getType() == Types.IDENTIFIER) {
              String argType = getTypeDeclaration(curr);
              //    System.out.println ("Argtype:" + arg_type);
              //    System.out.println ("Argname:" +     curr.getText ());
              method.declarators.add(argType);
              method.argumentNames.add(curr.getText());
              if (scan().getType() == Types.COMMA) {
                scan();
              }
            }
          } while (curr.getType() != Types.RIGHTPAR);
          scan();
          if (curr.equals("throws")) {
            while (true) {
              scan();
              if (curr.getType() != Types.IDENTIFIER) {
                bad("exception id missing");
              }
              compilation.exceptions.put(curr.getText(), "YES");
              method.exceptions.add(curr.getText());
              if (scan().getType() != Types.COMMA) {
                break;
              }
            }
          }
          if (compilation.methods.put(method.signature(), method) != null) {
            bad("Collision");
          }
          //                    bad ("Done");
        }
        while (curr.getType() != Types.SEMICOLON
            && curr.getType() != Types.LEFTCURL) {
          scan();
        }
        jdoc = null;
        if (curr.getType() == Types.LEFTCURL) {
          int i = 0;
          while (true) {
            scan();
            if (curr.getType() == Types.LEFTCURL) {
              i++;
            }
            if (curr.getType() == Types.RIGHTCURL) {
              if (i-- == 0) {
                break;
              }
            }
          }
        }
      }
    }
  }

  /**
   * @param fileName file
   * @return AST
   * @throws Exception fail
   */
  CompilationUnit parse(final String fileName) throws Exception {
    System.out.println("File to parse: " + fileName);
    CompilationUnit compilation = new CompilationUnit();
    lines = new StringBuilder();
    BufferedReader in = new BufferedReader(new FileReader(fileName));
    try {
      String line;
      while ((line = in.readLine()) != null) {
        lines.append(line).append('\n');
      }
    } finally {
      in.close();
    }
    cIndex = 0;
    curr = null;
    boolean packfound = false;
    String classJdoc = null;
    while (scan() != null) {
      switch (curr.getType()) {
        case COMMENT:
          classJdoc = curr.getText();
          break;

        case IDENTIFIER:
          if (packfound) {
            if (curr.equals("import")) {
              Token imp = scan();
              if (imp.getType() != Types.IDENTIFIER) {
                bad("Misformed import");
              }
              readSemicolon();
              compilation.imports.add(imp.getText());
              classJdoc = null;
            } else {
              compilation.classJavaDoc = classJdoc;
              decodeDeclaration(curr, compilation);
            }
          } else {
            if (!curr.equals("package")) {
              bad("No package key-word found");
            }
            Token pack = scan();
            if (pack.getType() != Types.IDENTIFIER) {
              bad("Package missing");
            }
            compilation.packageName = pack.getText();
            readSemicolon();
            packfound = true;
            classJdoc = null;
          }
          break;
        default:
          break;
      }
    }
    return compilation;
  }

  /**
   * @param genDirectory dir
   * @throws Exception fail
   */
  void generateJDocFriendlyFile(final String genDirectory) throws Exception {

    /*
            for (String s : client.methods.keySet()){
                System.out.print ("method=" + (server.methods.get(s)
                == null) + "=" + s + "\nthrows:");
                for (String e : client.methods.get(s).exceptions){
                    System.out.print(" " + e);
                }
                System.out.println ();
            }
    */
    final StringBuilder ofile = new StringBuilder();
    ofile.append(genDirectory).append("/");
    for (int i = 0; i < client.packageName.length(); i++) {
      if (client.packageName.charAt(i) == '.') {
        ofile.append('/');
      } else {
        ofile.append(client.packageName.charAt(i));
      }
    }
    String outPath = ofile.toString();
    String[] cf = new File(outPath).list();
    final int suf = 5;
    for (String f : cf) {
      if (f.toUpperCase().endsWith("EXCEPTION.JAVA")) {
        if (client.exceptions.get(f.substring(0, f.length() - suf)) == null) {
          /*
                          if (!new File (outPath + "/" + f).delete()){
                              bad ("Couldn't delete " + f);
                          }
          */
        }
      }
    }
    ofile.append('/').append(client.className).append(".java");
    //        System.out.println ("f=" + ofile.toString());
    FileWriter out = new FileWriter(ofile.toString());
    out.write("package " + client.packageName + ";\n\n");
    for (String imp : client.imports) {
      out.write("import " + imp + ";\n");
    }
    if (server.classJavaDoc != null) {
      out.write("\n" + server.classJavaDoc);
    }
    out.write("\npublic interface " + client.className + "\n{\n");
    for (String s : client.methods.keySet()) {
      Method clientMethod = client.methods.get(s);
      for (String f : cf) {
        if (f.equalsIgnoreCase(clientMethod.methodName + ".java")
            || f.equalsIgnoreCase(
                clientMethod.methodName + "response.java")) {
          if (!new File(outPath + "/" + f).delete()) {
            bad("Couldn't delete:" + f);
          }
        }
      }
      String jdoc = server.methods.get(s).javaDoc;
      if (jdoc == null) {
        bad("missing javadoc for " + s);
      }
      for (String e : clientMethod.exceptions) {
        int i = jdoc.indexOf("@throws " + e.substring(0, e.length() - 10));
        if (i > 0) {
          jdoc =
              jdoc.substring(0, i)
                  + "@throws "
                  + e
                  + jdoc.substring(i + e.length() - 2);
        } else {
          bad(
              "You need to declare @throws for '"
                  + e.substring(0, e.length() - 10)
                  + "' in method:"
                  + clientMethod.methodName);
        }
      }
      out.write("\n" + jdoc + "\n");
      out.write(
          " public "
              + clientMethod.returnType
              + " "
              + clientMethod.methodName
              + "(");
      boolean comma = false;
      List<String> argNames = server.methods.get(s).argumentNames;
      int q = 0;
      for (String arg : clientMethod.declarators) {
        if (comma) {
          out.write(", ");
        }
        comma = true;
        out.write(arg + " " + argNames.get(q++));
      }
      out.write(")");
      if (!clientMethod.exceptions.isEmpty()) {
        out.write(" throws ");
        comma = false;
        for (String e : clientMethod.exceptions) {
          if (comma) {
            out.write(", ");
          }
          comma = true;
          out.write(e);
        }
      }
      out.write(";\n");
    }
    out.write("}\n");
    out.close();
  }

  /**
   * @throws Exception fail
   */
  void compareGeneratedWithWritten() throws Exception {
    for (String s : client.methods.keySet()) {
      Method m = server.methods.get(s);
      if (m == null) {
        for (String o : server.methods.keySet()) {
          System.out.println(server.methods.get(o).signature());
        }
        bad("Method mismatch: " + s);
      }
    }
  }

  /**
   * @param serverInterface serv
   * @param clientInterface client
   * @param genDirectory dir
   * @throws Exception fail
   */
  JAXWSDocAndConvTools(
      final String serverInterface,
      final String clientInterface,
      final String genDirectory)
      throws Exception {
    server = parse(serverInterface);
    wsGen = (genDirectory != null);
    client = parse(clientInterface);
    if (genDirectory == null) {
      compareGeneratedWithWritten();
    } else {
      generateJDocFriendlyFile(genDirectory);
    }
  }

  /**
   * @param args Entry point
   * @throws Exception Fail
   */
  public static void main(final String[] args) throws Exception {
    final int maxArgs = 3;
    if (args.length != maxArgs && args.length != 2) {
      System.out.println(
          JAXWSDocAndConvTools.class.getName()
              + " WS-server-interface-file  WS-generated-client-interface-file"
              + " jdoc-\"gen\"-dir\n"
              + JAXWSDocAndConvTools.class.getName()
              + " WS-hand-written-file WS-generated-file\n\n"
              + "Generate JDoc\nCompare Declarations\n");
      System.exit(2); // NOPMD this is a cli command
    }
    new JAXWSDocAndConvTools(
        args[0], args[1], args.length == maxArgs ? args[2] : null);
  }
}
