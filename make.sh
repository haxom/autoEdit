#!/bin/bash
rm burp/BurpExtender*.class
javac -Xlint:unchecked burp/BurpExtender.java
jar -cfv autoEdit.jar burp/BurpExtender*
