// LLM Firewall - Proxy Auto-Configuration (PAC) File
// Deploy via GPO, MDM, or DHCP Option 252
// This routes LLM API traffic through the firewall proxy while allowing other traffic direct.

function FindProxyForURL(url, host) {
    // LLM provider domains to intercept
    var llmDomains = [
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
        "api.cohere.ai",
        "api.mistral.ai",
        "api.together.xyz"
    ];

    // Azure OpenAI patterns
    var azurePatterns = [
        "*.openai.azure.com",
        "*.api.cognitive.microsoft.com"
    ];

    // Check exact domain matches
    for (var i = 0; i < llmDomains.length; i++) {
        if (dnsDomainIs(host, llmDomains[i])) {
            return "PROXY domestique.internal.company.com:8080; DIRECT";
        }
    }

    // Check wildcard patterns for Azure
    for (var j = 0; j < azurePatterns.length; j++) {
        var pattern = azurePatterns[j];
        var domain = pattern.substring(2); // Remove "*."
        if (dnsDomainIs(host, domain)) {
            return "PROXY domestique.internal.company.com:8080; DIRECT";
        }
    }

    // Everything else goes direct
    return "DIRECT";
}
