# Summary
Some HTTP security headers are either misconfigured or missing.

# Background
Note that the content here is from the MDN Web Docs:
<a href="https://developer.mozilla.org/en-US/docs/MDN/Writing_guidelines/Attrib_copyright_license">Attributions and copyright licensing</a> by <a href="https://developer.mozilla.org/en-US/docs/MDN/Community/Roles_teams#contributor">Mozilla Contributors</a> is licensed under <a href="https://creativecommons.org/licenses/by-sa/2.5/">CC-BY-SA 2.5</a>.

Websites contain several different types of information. Some of it is non-sensitive, for example the copy shown on the public pages. Some of it is sensitive, for example customer usernames, passwords, and banking information, or internal algorithms and private product information.

Modern browsers already have several features to protect users' security on the web, but developers also need to employ best practices and code carefully to ensure that their websites are secure. Even simple bugs in your code can result in vulnerabilities that bad people can exploit to steal data and gain control over services for which they don't have authorization.

The following security headers were identified as being either missing or misconfigured. 

## HTTP Strict Transport Security (HSTS)
The HTTP Strict-Transport-Security response header (often abbreviated as HSTS) informs browsers that the site should only be accessed using HTTPS, and that any future attempts to access it using HTTP should automatically be converted to HTTPS. This is more secure than simply configuring a HTTP to HTTPS (301) redirect on your server, where the initial HTTP connection is still vulnerable to a man-in-the-middle attack.

The following HTTP response header can be used to enforce HTTPS for a max-age of 1 year. This blocks access to pages or subdomains that can only be served over HTTP:

`Strict-Transport-Security: max-age=31536000; includeSubDomains`

Although a max-age of 1 year is acceptable for a domain, two years is the recommended value as explained on https://hstspreload.org.

In the following example, max-age is set to 2 years, and is suffixed with preload, which is necessary for inclusion in all major web browsers' HSTS preload lists, like Chromium, Edge, and Firefox.

`Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`

## Content Security Policy (CSP)

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft, to site defacement, to malware distribution.

CSP is designed to be fully backward compatible (except CSP version 2 where there are some explicitly-mentioned inconsistencies in backward compatibility). Browsers that don't support it still work with servers that implement it, and vice versa: browsers that don't support CSP ignore it, functioning as usual, defaulting to the standard same-origin policy for web content. If the site doesn't offer the CSP header, browsers likewise use the standard same-origin policy. 

To enable CSP, you need to configure your web server to return the Content-Security-Policy HTTP header. (Sometimes you may see mentions of the `X-Content-Security-Policy` header, but that's an older version and you don't need to specify it anymore.)

You can use the Content-Security-Policy HTTP header to specify your policy, like this:

`Content-Security-Policy: policy`

The policy is a string containing the policy directives describing your Content Security Policy.

## Clickjacking

The X-Frame-Options HTTP response header can be used to indicate whether a browser should be allowed to render a page in a `&lt;frame\&gt;`, `&lt;iframe&gt;`, `&lt;embed&gt;` or `&lt;object&gt;`. Sites can use this to avoid click-jacking attacks, by ensuring that their content is not embedded into other sites.
The following HTTP response header can be used to prevent the application from being framed in undesirable locations:

The added security is provided only if the user accessing the document is using a browser that supports X-Frame-Options. Note that the Content-Security-Policy HTTP header has a `frame-ancestors` directive which obsoletes this header for supporting browsers.

There are two possible directives for X-Frame-Options:

`X-Frame-Options: DENY`

`X-Frame-Options: SAMEORIGIN`

If you specify `DENY`, not only will the browser attempt to load the page in a frame fail when loaded from other sites, attempts to do so will fail when loaded from the same site. On the other hand, if you specify `SAMEORIGIN`, you can still use the page in a frame as long as the site including it in a frame is the same as the one serving the page.

This feature is no longer recommended. Though some browsers might still support it, it may have already been removed from the relevant web standards, may be in the process of being dropped, or may only be kept for compatibility purposes. Instead of this header, use the frame-ancestors directive in a Content-Security-Policy header.

## Content Sniffing

The `X-Content-Type-Options` response HTTP header is a marker used by the server to indicate that the MIME types advertised in the `Content-Type` headers should be followed and not be changed. The header allows you to avoid MIME type sniffing by saying that the MIME types are deliberately configured.

This header was introduced by Microsoft in IE 8 as a way for webmasters to block content sniffing that was happening and could transform non-executable MIME types into executable MIME types. Since then, other browsers have introduced it, even if their MIME sniffing algorithms were less aggressive.

Starting with Firefox 72, top-level documents also avoid MIME sniffing (if `Content-type` is provided). This can cause HTML web pages to be downloaded instead of being rendered when they are served with a MIME type other than text/html. Make sure to set both headers correctly.

Site security testers usually expect this header to be set.

`X-Content-Type-Options: nosniff`

## Cacheable HTTPS Response

The `Cache-Control` HTTP header field holds directives (instructions) — in both requests and responses — that control caching in browsers and shared caches (e.g. Proxies, CDNs).

If you don't want a response stored in caches, use the no-store directive.

`Cache-Control: no-store`

## Referrer Policy

The `Referrer-Policy` HTTP header controls how much referrer information (sent with the `Referer` header) should be included with requests.

## Permissions Policy

The HTTP `Permissions-Policy` header provides a mechanism to allow and deny the use of browser features in a document or within any `&lt;iframe&gt;` elements in the document.

## X-XSS-Protection

The HTTP `X-XSS-Protection` response header is a feature of Internet Explorer, Chrome and Safari that stops pages from loading when they detect reflected cross-site scripting (XSS) attacks. These protections are largely unnecessary in modern browsers when sites implement a strong `Content-Security-Policy` that disables the use of inline JavaScript (`'unsafe-inline'`).

Warning: Even though this feature can protect users of older web browsers that don't yet support CSP, in some cases, XSS protection can create XSS vulnerabilities in otherwise safe websites. See the section below for more information.

# Recommendations

Employ best practices and code carefully to ensure web application security

# Further Reading
 - OWASP HTTP Security Response Headers Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
 - Security on the web - https://developer.mozilla.org/en-US/docs/Web/Security
 - Strict-Transport-Security - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
 - HSTS Preload List - https://hstspreload.org/
 - Content Security Policy (CSP) - https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
 - X-Frame-Options - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
 - X-Content-Type-Options - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
 - Cache-Control - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control
 - Referrer-Policy - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
 - Permissions-Policy - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
 - X-XSS-Protection - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection