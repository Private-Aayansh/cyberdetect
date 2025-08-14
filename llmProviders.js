export default [
    {
        id: "gemini",
        name: "Google Gemini",
        description: "Google's Gemini AI model",
        requiresApiKey: true,
        apiKeyLink: "https://makersuite.google.com/app/apikey"
    },
    {
        id: "openai",
        name: "OpenAI GPT",
        description: "OpenAI's GPT models",
        requiresApiKey: true,
        apiKeyLink: "https://platform.openai.com/api-keys"
    },
    {
        id: "anthropic",
        name: "Anthropic Claude",
        description: "Anthropic's Claude models",
        requiresApiKey: true,
        apiKeyLink: "https://console.anthropic.com/account/keys"
    },
    {
        id: "aipipe",
        name: "AIPipe",
        description: "AIPipe.org API service",
        requiresApiKey: true,
        customEndpoint: true,
        defaultEndpoint: "https://aipipe.org/openrouter/v1/chat/completions",
        apiKeyLink: "https://aipipe.org/"
    },
    {
        id: "custom",
        name: "Custom Endpoint",
        description: "Custom OpenAI-compatible API endpoint",
        requiresApiKey: true,
        customEndpoint: true
    }
];
