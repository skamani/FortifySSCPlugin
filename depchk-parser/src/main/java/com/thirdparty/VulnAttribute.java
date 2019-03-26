package com.thirdparty;

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
 * 
 */


import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

/**
 * <P>All attributes used by parser should be defined in this class.
 * <BR>We don't define attribute types here because we don't want this class to be dependent on plugin-api.
 * <BR>Mandatory custom issue attribute types should be defined in the class implementing VulnAttribute interface.
 */
enum VulnAttribute {

	//Top level Attributes
    ENGINE_VERSION("engineVersion"),
    PROJECT_NAME("name"),
    SCANDATE("reportDate"),
    REPORTSCHEMA("reportSchema"),
    SCANINFO("scanInfo"),
    
    // Dependency Level Attributes:
    FILE_NAME("fileName"),
    FILE_PATH("filePath"),
    SHA1("sha1"),
    DESCRIPTION("description"),
    LICENSE("license"),

    // Dependency Check attribute names:
    NAME("name"),
    URL("url"),
    
    // Vulnerability attribute names:
    VULNERABILITIES("vulnerabilities"),
    UNIQUE_ID("uniqueId"),
    VUL_NAME("name"),
    CVSS_SCORE("cvssScore"),
    CVSS_ACCESS_VECTOR("cvssAccessVector"),
    CVSS_ACCESS_COMPLEXITY("cvssAccessComplexity"),
    CVSS_CON_IMPACT("cvssConfidentialImpact"),
    CVSS_INT_IMPACT("cvssIntegrityImpact"),
    CVSS_AVAIL_IMPACT("cvssAvailabilityImpact"),
    SEVERITY("severity"),
    CWE("cwe"),
    CWE_DESCRIPTION("description")
   ;

    private final String attrName;
    private static final Map<String, VulnAttribute> lookup =
            new HashMap<>();

    static {
        for(VulnAttribute s : EnumSet.allOf(VulnAttribute.class))
            lookup.put(s.attrName(), s);
    }

    VulnAttribute(final String attrName) {
        this.attrName = attrName;
    }

    public String attrName() {
        return attrName;
    }

    public static VulnAttribute get(String attrName) {
        try {
            return lookup.get(attrName);
        } catch (Exception e) {
            return null;
        }
    }
}