package com.thirdparty;

import com.fortify.plugin.spi.VulnerabilityAttribute.AttrType;

/**
 * (c) Copyright [2018] Micro Focus or one of its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


/**
 * <P>All custom vulnerability attributes must be defined in this class and must implement {@link com.fortify.plugin.spi.VulnerabilityAttribute} interface .
 * <BR>For all other attributes than custom ones which this parser needs see {@link VulnAttribute}
 */
public enum CustomVulnAttribute implements com.fortify.plugin.spi.VulnerabilityAttribute {

    // Custom attributes must have their types defined:
    UNIQUE_ID(VulnAttribute.UNIQUE_ID.attrName(), AttrType.STRING),
	ENGINE_VERSION(VulnAttribute.ENGINE_VERSION.attrName(), AttrType.STRING),
//	PROJECT_NAME(VulnAttribute.PROJECT_NAME.attrName(), AttrType.STRING),
	SCANDATE(VulnAttribute.SCANDATE.attrName(), AttrType.DATE),
	REPORTSCHEMA(VulnAttribute.REPORTSCHEMA.attrName(), AttrType.STRING),
	SCANINFO(VulnAttribute.SCANINFO.attrName(),AttrType.STRING),
	FILE_NAME(VulnAttribute.FILE_NAME.attrName(), AttrType.STRING),
	FILE_PATH(VulnAttribute.FILE_PATH.attrName(), AttrType.LONG_STRING),
	SHA1(VulnAttribute.SHA1.attrName(), AttrType.STRING),
	DESCRIPTION(VulnAttribute.DESCRIPTION.attrName(), AttrType.LONG_STRING),
//	LICENSE(VulnAttribute.LICENSE.attrName(), AttrType.STRING),
	NAME(VulnAttribute.NAME.attrName(), AttrType.STRING),
//	URL(VulnAttribute.URL.attrName(), AttrType.STRING),
	VUL_NAME(VulnAttribute.VUL_NAME.attrName(), AttrType.STRING),
	CVSS_SCORE(VulnAttribute.CVSS_SCORE.attrName(), AttrType.DECIMAL),
	CVSS_CON_IMPACT(VulnAttribute.CVSS_CON_IMPACT.attrName(), AttrType.STRING),
	CVSS_INT_IMPACT(VulnAttribute.CVSS_INT_IMPACT.attrName(), AttrType.STRING),
	CVSS_AVAIL_IMPACT(VulnAttribute.CVSS_AVAIL_IMPACT.attrName(), AttrType.STRING),
	SEVERITY(VulnAttribute.SEVERITY.attrName(),AttrType.STRING),
	CWE(VulnAttribute.CWE.attrName(), AttrType.STRING),
	CWE_DESCRIPTION(VulnAttribute.DESCRIPTION.attrName(), AttrType.LONG_STRING),
	CVSS_ACCESS_VECTOR(VulnAttribute.CVSS_ACCESS_VECTOR.attrName(),AttrType.STRING),
	CVSS_ACCESS_COMPLEXITY(VulnAttribute.CVSS_ACCESS_COMPLEXITY.attrName(),AttrType.STRING)
    ;

    private final AttrType attributeType;
    private final String attributeName;

    CustomVulnAttribute(final String attributeName, final AttrType attributeType) {
        this.attributeType = attributeType;
        this.attributeName = attributeName;
    }

    @Override
    public String attributeName() {
        return attributeName;
    }

    @Override
    public AttrType attributeType() {
        return attributeType;
    }
}
