
Penetration test reports are very important and provide you with the structured detailed of the pentest after the engagement has completed.

Usually we have those sections in this sequence:

- **Executive summary**: High-level overview of the whole engagement
- **Engagement methodology**: Explains the our phased approach of doing the exercice
- **Attack narrative**: Step-by-step walk-through of your attack path from beginning to end
- **Technical observations**: issues that allowed action on objectives
- **Appendix: severity definitions**: Objective definitions in order to remove personal bias from rating findings
- **Appendix: hosts and services**: Open ports and services discovered during the discovery phase
- **Appendix: tool list**: List of tools you used during the exercice, usually with hyperlinks for more information.

### Executive summary

This serves as a serves **high-level view** of both risk and business impact.
The purpose is to be **concise** and **clear**. It should be something that **non-technical readers can review and gain insight** into the security concerns highlighted in the report.

Within Executive Summary, you should always find the following:

- **Goals and objectives**:

  - What was the purpose of the engagement ?
  - What were the penetration testers attempting to accomplish ?
  - Why the penetration testers those actions ?

- **Dates and Times**:

  - When did the engagement take place ?
  - When did the testing begin ?
  - when did the testing end ?

- **Scope**:

  - What system or groups of systems were tested during this engagement?
  - Were any systems excluded or not allowed to be tested?
  - High-level results:
    - What happened ?
    - Was the test successful/unsuccess ?

### Engagement methodology

Describing the testing methodology up front and in as much detail as possible can helps to set expectations and make sure that you and the reader of the report are communicating with similar language.

- How did you go about the testing ? What was the approach ?
- What types of attacks did you tested ? How did you test them ?

You need to highlight your expertise and why this amount of money has been spent.

**It needs to describe what have been done during the time allocated for this exercice.**
You should describe the type of attacker or attacks that was emulated during the test.

*Note that this is a very important section, specially if you have a to deliver with almost 0 findings*

### Attack narrative

Summarizing exactly what has been done in specific details.
Describe in a linear fashion how you went from almost nothing towards the different "flags".

### Technical observations (Findings)

Findings should include the following:

- **Severity rating**: The severity rating assigned to that particular finding
- **Descriptive title**: A title that describes the finding.
- **Observation**: A more detailed explanation of what has been observed.
- **References**: Some findings can be link to standards like the OWASP Top 10, MITRE ATT&CK, OWASP Security Testing Guide.
- **Impact Statement**: A description of the potential impact on the business.
- **Evidence**: A screenshot, code listing, or command output that shows proof that you were able to use the finding to compromise a target in some way.
- **Assets affected**: The IP address or hostname of the assets affected.
- **Recommendation**: Actionable steps that your client can take to resolve the issue.

Note that for the recommendations:

- You should not say that they should stop using an solution.
For instance, if they are using a CMS which is know to have regularly vulnerabiliites, explain that they should patch the system more frequently, as you were able to leverage that due to a vulnerability that was not patched. Or maybe have additional security controls like a Web Application Firewall and/or a Dynamic Application Security Testing that are aware of this application.
- If possible, link it to standards such as CIS 20 Controls, CIS Benchmarks, ...
- Provide multiple solutions, there are use-cases when their is a business justification. Everybody is aware that they need to update their asset as soon at it is possible. But for example not disclose the version, perform virtual patching or use intrusion prevention system, even if all of them are not silver bullet.

### Apendices

#### Severity definitions

The problem is that words like medium, high, and critical are arbitrary and mean
something different to me than they do to you and something different to someone
else.

Here are the levels:

- **Critical**: A finding that impacts directly a business-critical function within the organization. Exploitation of a critical finding could result in a significant impact to the business’s ability to operate normally as well as compliance breach or high reputational damage.
Examples include:
  - Trivial exploit difficulty.
  - Business-critical data compromised.
  - Bypass of multiple security controls.
  - Direct violation of communicatied security objectives.
  - Large scale vulnerability exposure.

- **High**: This finding directly resulted in unauthorized access to otherwise
restricted areas of the scoped network environment. Exploitation of a high
finding is typically limited to a single system or application.
Examples include:
  - Execution of malicious code
  - Compromised the underlying system such
  - Breach of either the confidentiality or integrity of sensitive business data

- **Medium**: This finding does not directly result in the exposure of sensitive business and/or customer data or credentials. However, this issue together with other, or through an undected threat over times, this can be leverage through time
Examples include:
  - Brute-force possibilities
  - Outdated cryptographic requirements which still requires a long time to be cracked.
  - Having an security control that has his security capabilities decreased when being under attack.

- **Low**: This finding may result in a limited exposure of result in the exposure of sensitive business and/or customer data or credentials.
Examples includes:
  - Disclosure of system version information

#### Tools list

Note that depending on the client, they may ask that any tools you create specifically for this engagement become their intellectual property.
The best would be to have all those elements:

- Software name: The name of the software you used
- Link: A link where that software (It may be a Github link)
- Software version: Some tools have other behaviors, new ways of working depending on the version.

&rarr; It prevent you from writing a blog post saying that you just made a cool new tool that helped you hack.

Here is a good resource of public pentesting reports : <https://github.com/juliocesarfort/public-pentesting-reports>