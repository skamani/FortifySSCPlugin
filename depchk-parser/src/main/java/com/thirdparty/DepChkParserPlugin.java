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

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fortify.plugin.api.BasicVulnerabilityBuilder;
import com.fortify.plugin.api.ScanBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.ScanParsingException;
import com.fortify.plugin.api.StaticVulnerabilityBuilder;
import com.fortify.plugin.api.VulnerabilityHandler;
import com.fortify.plugin.spi.ParserPlugin;
import com.thirdparty.scan.DateDeserializer;
import com.thirdparty.scan.DepVuln;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;

import static com.fasterxml.jackson.core.JsonToken.START_OBJECT;
import static com.thirdparty.CustomVulnAttribute.*;

public class DepChkParserPlugin implements ParserPlugin<CustomVulnAttribute> {
	private static final Logger LOG = LoggerFactory.getLogger(DepChkParserPlugin.class);

	private static final JsonFactory JSON_FACTORY;
	private static final DateDeserializer DATE_DESERIALIZER = new DateDeserializer();

	static {
		JSON_FACTORY = new JsonFactory();
		JSON_FACTORY.disable(JsonParser.Feature.AUTO_CLOSE_SOURCE);
	}

	@Override
	public void start() throws Exception {
		LOG.info("DepChkParserPlugin plugin is starting");
	}

	@Override
	public void stop() throws Exception {
		LOG.info("DepChkParserPlugin plugin is stopping");
	}

	@Override
	public Class<CustomVulnAttribute> getVulnerabilityAttributesClass() {
		return CustomVulnAttribute.class;
	}

	@Override
	public void parseScan(final ScanData scanData, final ScanBuilder scanBuilder)
			throws ScanParsingException, IOException {
		parseJson(scanData, scanBuilder, this::parseScanInternal);
		// complete scan building
		scanBuilder.completeScan();
	}

	private void parseScanInternal(final ScanData scanData, final ScanBuilder scanBuilder, final JsonParser jsonParser)
			throws IOException, ScanParsingException {
		// load data from top-level object fields
		while (jsonParser.nextToken() != JsonToken.END_OBJECT) {
			final VulnAttribute vulnAttr = VulnAttribute.get(jsonParser.getCurrentName());
			jsonParser.nextToken();
			if (vulnAttr == null) {
				skipChildren(jsonParser);
				continue;
			}

			switch (vulnAttr) {
			case REPORTSCHEMA:
				scanBuilder.setHostName(jsonParser.getText());
				break;
			case SCANINFO:
				scanBuilder.setEngineVersion(getEngineVersion(jsonParser));
				break;
			case SCANDATE:
				scanBuilder.setScanDate(DATE_DESERIALIZER.convert(jsonParser.getText()));
				break;

			// Skip unneeded fields
			default:
				skipChildren(jsonParser);
				break;
			}
		}
	}

	private static <T> void parseJson(final ScanData scanData, final T object, final Callback<T> fn)
			throws ScanParsingException, IOException {
		try (final InputStream content = scanData.getInputStream(x -> x.endsWith(".json"));
				final JsonParser jsonParser = JSON_FACTORY.createParser(content)) {
			jsonParser.nextToken();
			assertStartObject(jsonParser);
			fn.apply(scanData, object, jsonParser);
		}
	}

	private static void assertStartObject(final JsonParser jsonParser) throws ScanParsingException {
		if (jsonParser.currentToken() != START_OBJECT) {
			throw new ScanParsingException(String.format("Expected object start at %s", jsonParser.getTokenLocation()));
		}
	}

	private String getEngineVersion(final JsonParser jsonParser) throws IOException {
		String ev = null;
		while (jsonParser.nextToken() != JsonToken.END_OBJECT) {
			final VulnAttribute vulnAttr = VulnAttribute.get(jsonParser.getCurrentName());
			jsonParser.nextToken();
			if (vulnAttr == null) {
				skipChildren(jsonParser);
				continue;
			}
			switch (vulnAttr) {
			case ENGINE_VERSION:
				ev = jsonParser.getText();
				break;
			// Skip unneeded fields
			default:
				skipChildren(jsonParser);
				break;
			}
		}
		return ev;
	}

	private void skipChildren(final JsonParser jsonParser) throws IOException {
		switch (jsonParser.getCurrentToken()) {
		case START_ARRAY:
		case START_OBJECT:
			jsonParser.skipChildren();
			break;
		}
	}

	private interface Callback<T> {
		void apply(final ScanData scanData, final T object, final JsonParser jsonParser)
				throws ScanParsingException, IOException;
	}

	@Override
	public void parseVulnerabilities(final ScanData scanData, final VulnerabilityHandler vh)
			throws ScanParsingException, IOException {
		parseJson(scanData, vh, this::parseVulnerabilitiesInternal);
	}

	private void parseVulnerabilitiesInternal(final ScanData scanData, final VulnerabilityHandler vh,
			final JsonParser jsonParser) throws ScanParsingException, IOException {
		int debugCounter = 0;
		while (jsonParser.nextToken() != JsonToken.END_OBJECT) {
			final String fieldName = jsonParser.getCurrentName();
			jsonParser.nextToken();
			if (fieldName.equals("dependencies")) {
				if (jsonParser.currentToken() != JsonToken.START_ARRAY) {
					throw new ScanParsingException(String.format("Expected array as a value for findings at %s",
							jsonParser.getTokenLocation()));
				}
				while (jsonParser.nextToken() != JsonToken.END_ARRAY) {
					LOG.info(String.format("json Token" + jsonParser.getCurrentToken().toString()));

					assertStartObject(jsonParser);
					final String uniqueId = parseVulnerability(scanData, vh, jsonParser);
					if (LOG.isDebugEnabled()) {
						LOG.debug(String.format("Parsed vulnerability %06d/%s in session %s", ++debugCounter, uniqueId,
								scanData.getSessionId()));
					}
				}
			} else {
				skipChildren(jsonParser);
			}
		}
	}

	private String parseVulnerability(final ScanData scanData, final VulnerabilityHandler vh,
			final JsonParser jsonParser) throws IOException, ScanParsingException {
		final DepVuln fn = new DepVuln();
		loadDependency(jsonParser, fn, vh); // Load data from one scan json vulnerability to the Finding object

		return fn.getUniqueId();
	}

	private void loadDependency(final JsonParser jsonParser, DepVuln fn, final VulnerabilityHandler vh)
			throws IOException, ScanParsingException {

		while (jsonParser.nextToken() != JsonToken.END_OBJECT) {
			VulnAttribute vulnAttr = VulnAttribute.get(jsonParser.getCurrentName());
			final String fieldName = jsonParser.getCurrentName();

			LOG.info(String.format("Field Name in Load Dependency = " + fieldName));

			jsonParser.nextToken();
			LOG.info(String.format("current token %s", jsonParser.getCurrentToken().name()));

			if (fieldName.equals("vulnerabilities")) {
				if (jsonParser.currentToken() != JsonToken.START_ARRAY) {
					throw new ScanParsingException(String.format("Expected array as a value for findings at %s",
							jsonParser.getTokenLocation()));
				}
				while (jsonParser.nextToken() != JsonToken.END_ARRAY) {
					LOG.info(String.format("json Token" + jsonParser.getCurrentToken().toString()));

					assertStartObject(jsonParser);
					processFindings(jsonParser, fn, vh);
					LOG.info(String.format("Parsed vulnerability " + fn.getUniqueId()));

				}
			} else {
				skipChildren(jsonParser);
			}
			if (vulnAttr == null) {
				skipChildren(jsonParser);
				continue;
			}

			switch (vulnAttr) {

			// Custom attributes:

			case SHA1:
				fn.setUniqueId(jsonParser.getText());
				LOG.info(String.format("SHA1= %s", jsonParser.getText()));

				break;

			case FILE_NAME:
				fn.setFileName(jsonParser.getText());
				LOG.info(String.format("FileName= %s", jsonParser.getText()));

				break;
			case FILE_PATH:
				fn.setFileName(jsonParser.getText());

				break;
			case DESCRIPTION:
				fn.setComment(jsonParser.getText());
				break;

			// Skip unneeded fields:
			default:
				LOG.info(String.format("Field Name in loadDependency %s", fieldName));

				skipChildren(jsonParser);
				break;
			}
		}
	}

	private void processFindings(final JsonParser jsonParser, DepVuln fn, VulnerabilityHandler vh) throws IOException {
		loadFinding(jsonParser, fn);
		LOG.info(String.format("Unique ID in parseVulnerability %s", fn.getUniqueId()));
		LOG.info(String.format("Unique ID in parseVulnerability %s", fn.getInstanceId()));
		if (fn.getName() != null) {
			final StaticVulnerabilityBuilder vb = vh.startStaticVulnerability(fn.getInstanceId()); // Start new
																									// vulnerability
																									// building
			populateVulnerability(vb, fn);
			vb.completeVulnerability(); // Complete vulnerability building
		}
	}

	private void loadFinding(final JsonParser jsonParser, DepVuln fn) throws IOException {

		LOG.info(String.format("Uniqueid = %s", fn.getUniqueId()));

		while (jsonParser.nextToken() != JsonToken.END_OBJECT) {
			VulnAttribute vulnAttr = VulnAttribute.get(jsonParser.getCurrentName());
			jsonParser.nextToken();
			if (vulnAttr == null) {
				skipChildren(jsonParser);
				continue;
			}
			LOG.info(String.format("jSON TEXT = %s", jsonParser.getCurrentName()));

			switch (vulnAttr) {

			// Custom mandatory attributes:

			case VUL_NAME:
				fn.setName(jsonParser.getText());
				break;

			case CWE:
				fn.setCWE(jsonParser.getText());
				break;

			case CWE_DESCRIPTION:
				fn.setVulnerabilityAbstract(jsonParser.getText());
				break;

			case CVSS_SCORE:
				fn.setImpact(Float.parseFloat(jsonParser.getText()));
				break;
			case CVSS_ACCESS_VECTOR:
				fn.setcvssAccessVector(jsonParser.getText());
				break;
			case CVSS_ACCESS_COMPLEXITY:
				fn.setcvssAccessComplexity(jsonParser.getText());
				break;
			case CVSS_CON_IMPACT:
				fn.setcvssConfidentialImpact(jsonParser.getText());
				break;
			case CVSS_INT_IMPACT:
				fn.setcvssIntegrityImpact(jsonParser.getText());
				break;
			case CVSS_AVAIL_IMPACT:
				fn.setcvssAvailabilityImpact(jsonParser.getText());
				break;

			case SEVERITY:
				try {
					fn.setPriority(com.thirdparty.scan.DepVuln.GenPriority.valueOf(jsonParser.getText()));
				} catch (IllegalArgumentException e) {
					fn.setPriority(com.thirdparty.scan.DepVuln.GenPriority.Medium);
				}
				LOG.info(String.format("Parser Priority = %s", jsonParser.getText()));
				LOG.info(String.format("Priority = %s", fn.getPriority().name()));
				break;

			// Custom attributes

			/*
			 * case CATEGORY_ID: fn.setCategoryId(jsonParser.getText()); break;
			 */

			// Skip unneeded fields:
			default:
				skipChildren(jsonParser);
				break;
			}
		}
	}

	private void populateVulnerability(final StaticVulnerabilityBuilder vb, final DepVuln fn) {

		// Set builtin attributes
		vb.setKingdom("Environment");
		// vb.setMappedCategory()
		vb.setAnalyzer("Configuration");
		vb.setCategory("Insecure Deployment");
		vb.setSubCategory("Unpatched Application");
		if (fn.getCWE() != null) {
			vb.setMappedCategory(fn.getCWE());
			vb.setStringCustomAttributeValue(CWE, fn.getCWE());

		}
		//vb.setCategory(fn.getName()); // REST -> issueName
		vb.setFileName(fn.getFileName()); // REST -> fullFileName or shortFileName
		vb.setVulnerabilityAbstract(fn.getVulnerabilityAbstract()); // REST -> brief
		vb.setImpact(fn.getImpact()); // REST -> impact

		try {
			vb.setPriority(BasicVulnerabilityBuilder.Priority.valueOf(fn.getPriority().name()));
			// REST -> friority, UI
		} catch (IllegalArgumentException e) { // Leave priority unset if the value from scan is unknown
			// Do Nothing.
		}

		// Set string custom attributes
		if (fn.getUniqueId() != null) {
			vb.setStringCustomAttributeValue(UNIQUE_ID, fn.getUniqueId());
		}

		if (fn.getcvssAccessComplexity() != null) {
			vb.setStringCustomAttributeValue(CVSS_ACCESS_COMPLEXITY, fn.getcvssAccessComplexity());
		}
		if (fn.getcvssAccessVector() != null) {
			vb.setStringCustomAttributeValue(CVSS_ACCESS_VECTOR, fn.getcvssAccessVector());
		}
		if (fn.getcvssAvailabilityImpact() != null) {
			vb.setStringCustomAttributeValue(CVSS_AVAIL_IMPACT, fn.getcvssAvailabilityImpact());
		}
		if (fn.getcvssConfidentialImpact() != null) {
			vb.setStringCustomAttributeValue(CVSS_CON_IMPACT, fn.getcvssConfidentialImpact());
		}

		if (fn.getcvssIntegrityImpact() != null) {
			vb.setStringCustomAttributeValue(CVSS_INT_IMPACT, fn.getcvssIntegrityImpact());
		}

		// set long string custom attributes
		if (fn.getDescription() != null) {
			vb.setStringCustomAttributeValue(DESCRIPTION, fn.getDescription());
		}

	}

}
