# YASHA - Yet Another Security Header Analyser

**Note that this is still in development. Please use the logs option and compare output to ensure accuracy.**

**Warning: don't use this with untrusted data. See https://docs.python.org/3/library/xml.html#xml-vulnerabilities.**

# What file does YASHA take?
Yasha uses Burp Suite history. Ideally, first narrow traffic to in-scope items.

![Narrowing to in-scope](/readme_imgs/first.png)

Then save items to a file.

![Save items from history](/readme_imgs/second.png)

# Usage tips
 - YASHA writes a copy-and-paste-ready output into a file that should work for copy-and-pasting for a number of editors.
 - If something doesn't seem right, the detailed output for URLs and headers are available using `--log`. Use your browser's builtin JSON viewing and filtering or a tool like `jq` to analyse it.
 - Yasha needs you to identify if the right (usually sensitive) endpoints have caching headers. It helps by showing you a list so that you can make a judgement: if there are a few URLs, it will do so in the terminal, and else it will output a HTML file.
 - It also needs you to look at the CSP headers yourself. It will help by outputting a HTML file with links that can open that CSP header in Google's CSP Evaluator.

# If using YASHA as a library
YASHA is quite talkative: it will need to mention what it is analysing, and ask the user for input. It will also write `cache_report.htm` and (often) `csp_report.htm`.

The only function you need is `yasha()`. It requires the path to the Burp output file, and optionally takes a `log` Boolean argument that will output the results.
The function will return a `parcel`: a dictionary that contains `output` (a dictionary of the results), `report` which is a HTML page in string form with the VKB for adding to the editor of your choice, and optionally `log` which is a JSON of the original results of the analysis before anything was done to them.

Barebones example:

```python
from yasha import yasha

filename = input('What is the filename? > ')
try:
    for_editor = yasha(filename)['report']
except FileNotFoundError:
    print("Couldn't find the file.")

print("Here is the output.\n\n")
print(for_editor)
```

# Editing the vkb.md File
Currently the VKB file has been populated with information from the MDN Web Docs, which has its own copyright and attribution requirements.

If you would like to replace it with your own custom writeup, ideally you should leave the headings alone and simply edit the bodies under them. Use backticks for code.

The references in further reading are matched up to the first word or first three words, so editing the links should be fine. If you do want to edit the whole thing, edit `rec_translation` in the `report()` function.