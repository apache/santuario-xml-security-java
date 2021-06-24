<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet  version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:xbinding="https://jakarta.ee/xml/ns/jaxb">

    <xsl:template match="xbinding:bindings">
        <xsl:copy>
            <xsl:attribute name="if-exists">true</xsl:attribute>
            <xsl:apply-templates select="@*|node()" />
        </xsl:copy>
    </xsl:template>

    <xsl:template match="@*|node()">
        <xsl:copy>
            <xsl:apply-templates select="@*|node()" />
        </xsl:copy>
    </xsl:template>
</xsl:stylesheet>