# Dependency Check parser plugin
## Plugin that can parse non-Fortify OWASP Dependency Check scan results and import them into Fortify Software Security Center.

## Java plugin API
- All types of plugins are developed against plugin-api (current version is plugin-api-1.0.1.jar)
- Plugin API version 1.0 supports only parser plugins (`com.fortify.plugin.spi.ParserPlugin`).
- The SPI that a plugin can implement is in package `com.fortify.plugin.spi` of plugin-api library
- The API that a plugin can use is in `com.fortify.plugin.api` of plugin-api library
- Dependency parser plugin implements `com.fortify.plugin.spi.ParserPlugin`

## Plugin requirements
- Plugin has to be a single Java library (JAR)
- All plugin dependencies have to be extracted and packed inside Plugin JAR as individual classes. Software Security Center (SSC) does not support the inclusion of other JARs inside of the plugin JAR file.
- The plugin must implement one, and only one, service provider interface in plugin-api/com.fortify.plugin.spi.
  - The plugin must declare SPI implementation in `META-INF/services`. For parser plugin implementation, it would be a `com.fortify.plugin.spi.ParserPlugin` file containing declaration of a class that implements the `com.fortify.plugin.spi.ParserPlugin` interface.
- Plugin JAR must contain the plugin.xml manifest in root of the JAR file. See the description of the plugin manifest attributes below.

## Plugin library build
- A plugin must be built with all dependencies contained in the plugin library.
 - All dependencies must be extracted and included in the plugin JAR as individual packages and classes. The plugin class loader cannot access JARs within the JAR file. It is implemented in the Gradle build script provided with the sample plugin.
- Example Gradle build `build.gradle` is provided with the plugin.
    Tasks supported by build script:
    - `gradle clean` Cleans up previous build results
    - `gradle build` Builds plugin binary. The plugin library artifact is created as `build/libs/sample-parser-[version].jar`
    - `gradle cleanIdea` IntelliJ Idea IDE users can use this to clean up the IDE work folder.
    - `gradle idea` IntelliJ Idea IDE users can use this to generate IDE project files.
- Sources includes a Gradle wrapper that can be used to build the project. The wrapper downloads the Gradle distribution on first run. The build must also have access to the Maven Central repository for downloading some project dependencies. Depending on your platform, use either the `gradlew.bat` or the `gradlew` script.

## Setting up the plugin framework working directory location (SSC 17.20 or later)
- The JVM system property `fortify.plugins.home` provides the plugin installation directory.
- `fortify.plugins.home` is set by default to `<fortify.home>/plugin-framework/` or `<fortify.home>/<app-context>/plugin-framework/` if the plugin framework runs inside Software Security Center web application.
 - The default location of the plugin directory is `<fortify.plugins.home>/plugins`.

## Installing and enabling the plugin (for SSC 17.20 or later)
- SSC version 17.20 supports plugin installation through the plugin management UI (Administration > Plugins).
- In this version, plugins are modeled in SSC with three primary states: "installed/disabled", "enabled", and "uninstalled/not present".  (It also models some transient and failure states, but these can be ignored for now.)
- In subsequent text, the terms "family of plugins" and "plugin family" refer to a set of plugins with small code variations that may differ in pluginVersion and/or dataVersion but are identified by the same pluginId. SSC 17.20 allows installation of multiple plugins belonging to the same family (with some restrictions).
 Use the `Add` button to install a new plugin in SSC.
- All installed plugins are disabled after installation, in that the plugins are defined in SSC, but cannot do any work or accept any requests from SSC.
- To enable a plugin, select the plugin row in the Plugins list, and then click `Enable`.
- The plugin container log `<fortify.plugins.home>/log` should contain an INFO record about the plugin's successful installation or enablement (start). For example:
`org.apache.felix.fileinstall - 3.5.4 | Started bundle: file:<fortify.plugins.home>/plugins/com.example.parser.jar`
- SSC performs several validation steps when plugins are being installed or enabled. SSC can block plugin installation and  enablement if conditions such as the following exist:
      - Installing a plugin is not allowed if a plugin from the same family but later version is already installed in SSC. Because plugins are developed by 3rd-party developers, SSC has no access to details about the logic implemented in plugins.
        In this case, SSC assumes that later versions of some plugins can produce data that is incompatible with an earlier version of the plugins, resulting in SSC system instability.
        If you absolutely must install an earlier version of a plugin (for example, to roll back from a defective later version), remove the later version of the plugin, and then install the earlier version.
      - You cannot install an earlier __data version__ of a plugin in SSC.
      - To maintain consistency of information displayed in the Administration UI with the underlying pluginIds, SSC ensures that plugins in the same family have the same name and other identifying attributes (such as engineType).
      - Only one plugin of a plugin family (sharing the same pluginId and name) can be enabled at a given time.


## Disabling/Uninstalling from SSC (for SSC 17.20 or later)
- You can remove plugin installed in SSC if the plugin is in the "disabled" state.
  - To disable a plugin, select it in the Plugins list, and then click `Disable`.
  - To remove a plugin in the "disabled" state, view the plugin details, and then click `Remove`.
- When a parser plugin is disabled or uninstalled, SSC can no longer process new result files from the engine type that was supported by that plugin.
- However, all the data previously parsed by the disabled or uninstalled plugin is preserved in the database and vulnerabilities that have been parsed by the plugin can still be viewed in the audit page listing.
  - Further, if the plugin has been just __disabled__, the details of previously-parsed issues are still visible.
  - However, if the plugin has also been __uninstalled__, the details of these vulnerabilities are not visible or available since the view template is also gone.
- If a plugin is uninstalled by mistake, you can install it again without data loss.

## Scan artifact uploading requirements
- The scan result file must be accompanied by `scan.info` metadata and packed together into a ZIP file.
  - The ZIP must contain at least two entries:
    - /scan.info
    - /raw.scan - name and location depend on parser implementation and how it retrieves entry from `com.fortify.plugin.api.ScanData` (for example, `scanData.getInputStream(x -> x.endsWith(".json"))` retrieves files that end with the `.json` extension)
- Optionally, you can upload 3rd-party scans as raw scans (not packed in ZIP with `scan.info`), but only through SSC REST API, where call to REST API has to provide the engine type as a call parameter. Example:
  - retrieve file upload token; using for example admin user and password `curl --noproxy localhost -X POST -H "Content-Type: application/json" -u admin:password -T "uploadFileToken.json" http://localhost:8080/ssc/api/v1/fileTokens` where content of `uploadFileToken.json` is `{"fileTokenType": "UPLOAD"}`
  - upload scan with engine type parameter; using token retrieved in previous operation `curl --noproxy localhost -X POST --form files=@"security.csv" "http://localhost:8080/ssc/upload/resultFileUpload.html?mat=TOKEN_FROM_PREV_OPERATION&entityId=APPLICATION_VERSION_ID&engineType=SAMPLE"` where engine type parameter matches engine type registered by the parser plugin (`plugin.xml/plugin/issue-parser/engine-type`)

## `scan.info` metadata contract
- `scan.info` is a property file
  - SSC can retrieve two properties from the file: `engineType` (STRING) and `scanDate` (STRING)
- The `scan.info` file must provide at least engineType property, designating scan producer, which will match engine type registered by parser plugin (`plugin.xml/plugin/issue-parser/engine-type`).
- The `scan.info` file can also provide the `scanDate` property value in ISO-8601 format.
  - If `scanDate` is not provided, the parser plugin is responsible for providing a meaningful scan date value for SSC operations.

## Generating scan with fixed or random data
The sample plugin library can also be used as a generator for scans that can be parsed by the plugin itself.

Two types of scans can be generated. A fixed scan with more realistic but small data and a random scan with artificial data but with configurable size.
The fixed scan will be automatically generated to the `build/scan/fixed-sample-scan.zip` as a part of a project's build.

The usage for the fixed scan generator is as follows:
- `java -cp path/to/sample-parser-[version].jar com.thirdparty.ScanGenerator fixed <FIXED_OUTPUT_SCAN_ZIP_NAME>`
  - For example, in the project root: `java -cp build/libs/* com.thirdparty.ScanGenerator fixed fixed_sample_scan.zip`

The usage for the random scan generator is as follows:
- `java -cp path/to/sample-parser-[version].jar com.thirdparty.ScanGenerator random <RANDOM_OUTPUT_SCAN_ZIP_NAME> <ISSUE_COUNT> <CATEGORY_COUNT> <LONG_TEXT_SIZE>`
  - For example, in the project root: `java -cp build/libs/* com.thirdparty.ScanGenerator random random_sample_scan.zip 50 10 500`

## Debugging
- A developer can follow `ssc.log` and `plugin-framework.log` to monitor what is happening in SSC and the plugin container.
  - `ssc.log` is, by default, located in the application server log directory or can be configured by the  `com.fortify.ssc.logPath` JVM system property.
  - The plugin container log is stored by default in the `<fortify.plugins.home>/log` directory and can be configured in `org.ops4j.pax.logging.cfg` (`WEB-INF/plugin-framework/etc`).

## FAQ
1) What is a scan?
   - A scan is a file in analyser-specific format that contains analysis results and can be parsed by a scan parser plugin.

2) What is the vulnerability ID and what are the basic rules that a plugin must follow to provide it?
   - SSC uses the vulnerability ID intensively to track vulnerability status. For example, the ID is used to determine whether some vulnerability was **fixed** (it is not present in the latest scan), **reintroduced** (the previous scan did not contain the vulnerability, but the latest scan does), **updated** (both the latest and the previous scans contain some vulnerability) or **new** if the vulnerability was found for the first time.
   - __ID must be unique__ among vulnerability IDs in a specific scan. The scan file is considered incorrect and is not processed if the plugin provides multiple vulnerabilities with the same ID.
   - If the same vulnerability exists in different scans, the ID of this vulnerability must be the same in the different scans. If IDs are not consistent for the same vulnerability in different scans, vulnerability status is not calculated correctly and SSC users cannot see how many new issues are produced or how many old issues are fixed after processing of the latest scan.
   - Some security analysers produce IDs that the plugin can pass to SSC without additional processing.
   - If analysers do not provide vulnerability identifiers in scan result files, the parser plugin is responsible for generating this ID using some other set of vulnerability attributes if they are unique for issues in one scan and the same for the same issues in different scans.

3) How to release new version of the plugin *if no changes have been made in custom vulnerability attributes definitions*?
   - Make any necessary changes to the plugin code.
   - Increase __plugin version__ in the plugin.xml descriptor.
   - Since the plugin's output format __was not changed__ and new version of the plugins produces custom attributes in exactly the same way as in the previous version of the plugin, __data version__ of the plugin __must not be changed__
   - The plugin can be built and distributed to users.

4) How to release new version of the plugin *if some changes have to be made to the custom vulnerability attribute definitions or to the vulnerability view template*? (changes in number, names or types of the attributes).
   - Enum class that implements the `com.fortify.plugin.spi.VulnerabilityAttribute` interface and contains custom attributes definitions must be updated if any changes to custom attributes definitions are required.
     New attributes must be added there or existing attributes definitions must be modified.
   - If changes to the vulnerability template are required to modify the way vulnerabilities are represented in the SSC UI, the file location is defined by issue-parser -> view-template section must be edited.
   - If necessary, plugin localization files whose locations are defined plugin-info -> resources -> localization sections must be modified.
   - Increase __plugin version__ in plugin.xml descriptor.
   - Increase __data version__ in plugin.xml descriptor. It will indicate to SSC that a new version of the plugin provides data in a new format.
   - The plugin can be built and distributed to users.

5) There is no parser to process a scan.
   - The engine type provided with the scan is different from the engine type provided by the parser plugin, or there is no installed/enabled plugin of the specified engine type in SSC.
   - Parser plugin registration failed - check the plugin container logs and SSC logs for errors.

6) Will my parser plugin developed for SSC/PluginFramework 17.10 work automatically with SSC/PluginFramework 17.20?
   - No. There is a change in XML namespace for plugin.xml. So the minimal change needed for 17.20 support is plugin.xml update. After that, there is a high probability that your plugin will be compatible with 17.20. However, due to significant improvements and validations added in SSC 17.20, be prepared to test your plugin with SSC/PluginFramework 17.20 and update your plugin for compatibility, if needed.
