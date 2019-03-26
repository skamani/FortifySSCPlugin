package com.thirdparty.scan;

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

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
//import static com.thirdparty.ScanGenerator.GenPriority;
//import static com.thirdparty.ScanGenerator.CustomStatus;
import java.util.Date;

@JsonSerialize
public class DepVuln {

	
	   public enum GenPriority {
	        Critical, High, Medium, Low;
	        final static int LENGTH = values().length;
	    };
    // mandatory attributes
    private String uniqueId;
    private String name;

    // builtin attributes
    private String category;
    private String fileName;
    private String vulnerabilityAbstract;
    private Float confidence;
    private Float impact;
    private GenPriority priority;

    // custom attributes
    private String categoryId;

    private String description;
    private String comment;
    private String cwe;
    private Date lastChangeDate;
    private Date artifactBuildDate;
    //CVSS Attributes
    private String cvssScore;
    private String cvssAccessVector;
    private String cvssAccessComplexity;
    private String cvssConfidentialImpact;
    private String cvssIntegrityImpact;
    private String cvssAvailabilityImpact;
    
 


    public String getUniqueId() {
        return uniqueId;
    }

    public String getName() {
        return name;
    }   
    
    public String getCategory() {
        return category;
    }

    public void setCategory(final String category) {
        this.category = category;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(final String fileName) {
        this.fileName = fileName;
    }

    public void setName(final String name) {
        this.name = name;
    } 
    
    public String getVulnerabilityAbstract() {
        return vulnerabilityAbstract;
    }

    public void setVulnerabilityAbstract(final String vulnerabilityAbstract) {
        this.vulnerabilityAbstract = vulnerabilityAbstract;
    }


    public Float getConfidence() {
        return confidence;
    }

    public void setConfidence(final Float confidence) { this.confidence = confidence; }

    public Float getImpact() {
        return impact;
    }

    public void setImpact(final Float impact) { this.impact = impact; }

    public void setUniqueId(final String uniqueId) {
        this.uniqueId = uniqueId;
    }

    public GenPriority getPriority() { return priority; }

    public void setPriority(final GenPriority priority) { this.priority = priority; }

    public String getCategoryId() { return categoryId; }

    public void setCategoryId(final String categoryId) { this.categoryId = categoryId; }

    public String getDescription() { return description; }

    public void setDescription(final String description) { this.description = description; }

    public String getComment() { return comment; }

    public void setComment(final String comment) { this.comment = comment; }

    public String getCWE() {
        return cwe;
    }

    public void setCWE(final String cwe) {
    	if (cwe != "") {
	    	String array1[]= cwe.split(" ");
	    	String cwetemp = array1[0];
	    	array1 = cwetemp.split("-");
	        this.cwe = "CWE ID "+ array1[1]; 
    	}
        else
        	this.cwe = cwe;
    }

    @JsonSerialize(converter = DateSerializer.class)
    public Date getLastChangeDate() {
        return lastChangeDate;
    }

    @JsonDeserialize(converter = DateDeserializer.class)
    public void setLastChangeDate(final Date lastChangeDate) {
        this.lastChangeDate = lastChangeDate;
    }

    @JsonSerialize(converter = DateSerializer.class)
    public Date getArtifactBuildDate() {
        return artifactBuildDate;
    }

    @JsonDeserialize(converter = DateDeserializer.class)
    public void setArtifactBuildDate(final Date artifactBuildDate) {
        this.artifactBuildDate = artifactBuildDate;
    }


    public String getInstanceId() {
    	return (this.uniqueId + "-" +this.name);
    
    }
    
    public String getcvssScore() {
    	return cvssScore;
    };
    public void setcvssScore(String cvssScore) {
    	this.cvssScore = cvssScore;
    }; 
    

    public String getcvssAccessVector() {
    	return cvssAccessVector;
    };
    public void setcvssAccessVector(String cvssAccessVector) {
    	this.cvssAccessVector = cvssAccessVector;
    }; 

    public String getcvssAccessComplexity() {
    	return cvssAccessComplexity;
    };
    public void setcvssAccessComplexity(String cvssAccessComplexity) {
    	this.cvssAccessComplexity = cvssAccessComplexity;
    }; 

    public String getcvssConfidentialImpact() {
    	return cvssConfidentialImpact;
    };
    public void setcvssConfidentialImpact(String cvssConfidentialImpact) {
    	this.cvssConfidentialImpact = cvssConfidentialImpact;
    }; 
    public String getcvssIntegrityImpact() {
    	return cvssIntegrityImpact;
    };
    public void setcvssIntegrityImpact(String cvssIntegrityImpact) {
    	this.cvssIntegrityImpact = cvssIntegrityImpact;
    }; 
    public String getcvssAvailabilityImpact() {
    	return cvssAvailabilityImpact;
    };
    public void setcvssAvailabilityImpact(String cvssAvailabilityImpact) {
    	this.cvssAvailabilityImpact = cvssAvailabilityImpact;
    };     
}
